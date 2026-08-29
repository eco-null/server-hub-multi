#!/usr/bin/env python3
"""server.py — single-file static server + login + stats for Server Hub.

Zero third-party dependencies (Python 3 stdlib only).

Auth: Supabase Auth (email + password, multi-user). Falls back to the classic
single-user HUB_USER/HUB_PASSWORD env auth when SUPABASE_URL is not set.

Env vars:
  SUPABASE_URL         e.g. https://xxxx.supabase.co (enables multi-user)
  SUPABASE_ANON_KEY    publishable anon key
  HUB_USER             default: admin (legacy single-user fallback)
  HUB_PASSWORD         required if SUPABASE_URL unset
  HUB_PORT             default: 8642
  HUB_HOST             default: 0.0.0.0
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_ROOT = os.path.dirname(os.path.abspath(__file__))
SESSION_TTL = 30 * 24 * 60 * 60  # 30 days
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
MAX_LOGIN_BODY = 64 * 1024  # reject larger login POST bodies before reading them
PUBLIC_PATHS = {"/login", "/login.html", "/register", "/register.html"}

MAX_API_BODY = 64 * 1024  # reject larger API JSON bodies before reading them
SERVICES_FILE = os.path.join(WEB_ROOT, "services.json")

KNOWN_ICONS = {
    "chart", "pulse", "database", "shield", "shield-check", "key", "lock",
    "lock-key", "cloud", "note", "file", "film", "music", "headphones", "git",
    "branch", "terminal", "globe", "home", "broadcast", "cog", "box",
    "shopping", "flask", "sparkles", "camera", "image", "book", "gamepad",
    "wallet", "map-pin", "activity", "cpu", "server", "wifi", "zap", "mail",
    "message", "calendar", "clock", "download", "upload", "sliders", "user",
    "users", "bookmark", "star", "heart", "link", "external-link", "folder",
    "archive", "package", "layers", "refresh", "bell", "bug", "code", "command",
}
KNOWN_CATEGORIES = {
    "Monitoring", "Security", "Network", "Media", "Productivity", "Files",
    "Dev", "Communication", "Home", "Finance", "AI", "Search", "Database",
    "Other", "Gaming", "Books", "Money", "Travel", "Health",
}

# Supabase column mapping: API (camelCase) <-> DB (snake_case)
_SERVICE_TO_DB = {"desc": "description", "categoryOverride": "category_override"}
_DB_TO_SERVICE = {v: k for k, v in _SERVICE_TO_DB.items()}


def _to_db_service(fields):
    """Map API service fields (desc, categoryOverride) to DB columns."""
    return {_SERVICE_TO_DB.get(k, k): v for k, v in fields.items()}


def _from_db_service(row):
    """Map DB service row (description, category_override) to API shape."""
    if not isinstance(row, dict):
        return row
    out = {}
    for k, v in row.items():
        out[_DB_TO_SERVICE.get(k, k)] = v
    # Normalize expected API keys
    if "description" in row:
        out["desc"] = row.get("description") or ""
        out.pop("description", None)
    if "category_override" in row:
        out["categoryOverride"] = row.get("category_override")
        out.pop("category_override", None)
    # Ensure desc always present as string for frontend
    if "desc" not in out:
        out["desc"] = row.get("description") or row.get("desc") or ""
    if "categoryOverride" not in out:
        out["categoryOverride"] = row.get("category_override") if "category_override" in row else row.get("categoryOverride")
    return out


def validate_service(data, partial=False):
    """Validate a service object. Returns (fields, None) or (None, error)."""
    if not isinstance(data, dict):
        return None, "body must be a JSON object"
    fields = {}
    if "name" in data or not partial:
        name = str(data.get("name") or "").strip()
        if not name:
            return None, "name is required"
        if len(name) > 200:
            return None, "name too long"
        fields["name"] = name
    if "url" in data or not partial:
        url = str(data.get("url") or "").strip()
        if not url:
            return None, "url is required"
        if len(url) > 2000:
            return None, "url too long"
        if " " in url:
            return None, "url must not contain spaces"
        if not re.match(r"^https?://", url):
            return None, "url must start with http:// or https://"
        try:
            if not urllib.parse.urlparse(url).netloc:
                return None, "url must be a valid http(s) URL"
        except ValueError:
            return None, "url must be a valid http(s) URL"
        fields["url"] = url
    if "desc" in data or not partial:
        desc = str(data.get("desc") or "").strip()
        if len(desc) > 500:
            return None, "desc too long"
        fields["desc"] = desc
    if "icon" in data or not partial:
        icon = str(data.get("icon") or "box")
        fields["icon"] = icon if icon in KNOWN_ICONS else "box"
    if "ping" in data or not partial:
        fields["ping"] = bool(data.get("ping", True))
    if "categoryOverride" in data or not partial:
        cat = data.get("categoryOverride") or None
        if cat is not None and cat not in KNOWN_CATEGORIES:
            return None, "unknown category: " + str(cat)
        fields["categoryOverride"] = cat
    return fields, None


def validate_bookmark(data, partial=False):
    """Validate a bookmark object. Returns (fields, None) or (None, error)."""
    if not isinstance(data, dict):
        return None, "body must be a JSON object"
    fields = {}
    if "name" in data or not partial:
        name = str(data.get("name") or "").strip()
        if not name:
            return None, "name is required"
        if len(name) > 200:
            return None, "name too long"
        fields["name"] = name
    if "url" in data or not partial:
        url = str(data.get("url") or "").strip()
        if not url:
            return None, "url is required"
        if len(url) > 2000:
            return None, "url too long"
        if " " in url:
            return None, "url must not contain spaces"
        if not re.match(r"^https?://", url):
            return None, "url must start with http:// or https://"
        try:
            if not urllib.parse.urlparse(url).netloc:
                return None, "url must be a valid http(s) URL"
        except ValueError:
            return None, "url must be a valid http(s) URL"
        fields["url"] = url
    if "icon" in data or not partial:
        icon = str(data.get("icon") or "link").strip()
        fields["icon"] = icon if icon in KNOWN_ICONS else "link"
    if "color" in data or not partial:
        color = str(data.get("color") or "").strip()
        if color:
            if re.match(r"^#[0-9a-fA-F]{6}$", color):
                fields["color"] = color
    return fields, None


class ServiceStore:
    """Thread-safe JSON-backed service list. Atomic writes (tmp + os.replace)."""

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        self._services = self._load()
        self._bookmarks = self._load("bookmarks")

    def _load(self, key="services"):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            items = data.get(key, [])
            if not isinstance(items, list):
                return []
            return [s for s in items if isinstance(s, dict) and s.get("id")]
        except (OSError, ValueError):
            return []

    def _save(self):
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"services": self._services, "bookmarks": self._bookmarks}, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, self._path)

    def list(self):
        with self._lock:
            return [dict(s) for s in self._services]

    def add(self, entry):
        entry = dict(entry)
        entry["id"] = secrets.token_urlsafe(12)
        with self._lock:
            self._services.append(entry)
            self._save()
        return dict(entry)

    def update(self, sid, fields):
        with self._lock:
            for i, s in enumerate(self._services):
                if s["id"] == sid:
                    self._services[i] = {**s, **fields, "id": sid}
                    self._save()
                    return dict(self._services[i])
        return None

    def delete(self, sid):
        with self._lock:
            before = len(self._services)
            self._services = [s for s in self._services if s["id"] != sid]
            if len(self._services) != before:
                self._save()
                return True
        return False

    def list_bookmarks(self):
        with self._lock:
            return [dict(b) for b in self._bookmarks]

    def add_bookmark(self, entry):
        entry = dict(entry)
        entry["id"] = secrets.token_urlsafe(12)
        with self._lock:
            self._bookmarks.append(entry)
            self._save()
        return dict(entry)

    def update_bookmark(self, bid, fields):
        with self._lock:
            for i, b in enumerate(self._bookmarks):
                if b["id"] == bid:
                    self._bookmarks[i] = {**b, **fields, "id": bid}
                    self._save()
                    return dict(self._bookmarks[i])
        return None

    def delete_bookmark(self, bid):
        with self._lock:
            before = len(self._bookmarks)
            self._bookmarks = [b for b in self._bookmarks if b["id"] != bid]
            if len(self._bookmarks) != before:
                self._save()
                return True
        return False

MIME = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
}


def read_env(name, default=None):
    return os.environ.get(name) or default


class Sessions:
    """Session store.

    Legacy mode (no SUPABASE_URL): classic in-memory token store, used by the
    single threaded server. Fine for local/single-instance hosting.

    Supabase mode: stateless signed cookies (HMAC-SHA256). The cookie carries
    the user payload (user_id, email, supabase_token, username) and a
    signature; each request verifies it locally. This survives serverless
    (Vercel) cold starts where multiple instances share no memory — every
    request lands on any instance and still authenticates. SESSION_SECRET
    env var must be stable across instances; a secret is generated on first
    start otherwise (single-instance local use only).
    """

    def __init__(self, secret=None):
        self._tokens = {}
        self._lock = threading.Lock()
        env_secret = secret or os.environ.get("SESSION_SECRET")
        if not env_secret and os.environ.get("VERCEL"):
            raise RuntimeError("SESSION_SECRET must be set on Vercel (fleet needs stable HMAC key) — see MED-06")
        self._secret = env_secret or secrets.token_hex(32)

    # ---- legacy in-memory API ----
    def create(self, user):
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = (time.time() + SESSION_TTL, user)
        return token

    def get(self, token):
        if not token:
            return None
        # Stateless first: does it parse as a signed payload?
        user = self.verify_signed(token)
        if user is not None:
            return user
        with self._lock:
            entry = self._tokens.get(token)
        if not entry:
            return None
        expiry, user = entry
        if time.time() > expiry:
            with self._lock:
                self._tokens.pop(token, None)
            return None
        return user

    def delete(self, token):
        if not token:
            return
        with self._lock:
            self._tokens.pop(token, None)

    # ---- stateless signed-cookie API (serverless-safe) ----
    def sign(self, user):
        """Return a signed cookie value for the user payload."""
        payload = {
            "user_id": user.get("user_id", ""),
            "email": user.get("email", ""),
            "username": user.get("username", ""),
            "supabase_token": user.get("supabase_token", ""),
            "refresh_token": user.get("refresh_token", ""),
            "token_exp": int(user.get("token_exp", 0) or 0),
            "exp": int(time.time()) + SESSION_TTL,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        sig = hmac.new(self._secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
        return b64 + "." + sig

    def verify_signed(self, token):
        """Verify a signed cookie value -> user dict or None."""
        if not token or "." not in token:
            return None
        b64, sig = token.rsplit(".", 1)
        try:
            expected = hmac.new(self._secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        if int(payload.get("exp", 0)) < time.time():
            return None
        return {
            "user_id": payload.get("user_id", ""),
            "email": payload.get("email", ""),
            "username": payload.get("username", ""),
            "supabase_token": payload.get("supabase_token", ""),
            "refresh_token": payload.get("refresh_token", ""),
            "token_exp": int(payload.get("token_exp", 0) or 0),
        }


class LoginGuard:
    """Brute-force protection: N failed attempts per IP -> lockout."""

    def __init__(self, max_attempts=MAX_ATTEMPTS, lockout_seconds=LOCKOUT_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._state = {}
        self._lock = threading.Lock()

    def is_locked(self, ip):
        with self._lock:
            entry = self._state.get(ip)
            if not entry:
                return False
            fails, locked_until = entry
            if locked_until and time.time() < locked_until:
                return True
            if locked_until:
                self._state[ip] = (0, 0)
            return False

    def record_failure(self, ip):
        with self._lock:
            fails, locked_until = self._state.get(ip, (0, 0))
            fails += 1
            if fails >= self.max_attempts:
                fails = 0
                locked_until = time.time() + self.lockout_seconds
            self._state[ip] = (fails, locked_until)

    def reset(self, ip):
        with self._lock:
            self._state.pop(ip, None)


guard = LoginGuard()

class RegisterGuard:
    """Bulk-prevention: max N registrations per IP per window (e.g. 3 per 15 min)."""

    def __init__(self, max_per_window=3, window_seconds=15 * 60):
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self._state = {}
        self._lock = threading.Lock()

    def is_limited(self, ip):
        with self._lock:
            now = time.time()
            lst = self._state.get(ip, [])
            lst = [t for t in lst if now - t < self.window_seconds]
            self._state[ip] = lst
            return len(lst) >= self.max_per_window

    def record(self, ip):
        with self._lock:
            now = time.time()
            lst = self._state.get(ip, [])
            lst = [t for t in lst if now - t < self.window_seconds]
            lst.append(now)
            self._state[ip] = lst

    def reset(self, ip):
        with self._lock:
            self._state.pop(ip, None)


register_guard = RegisterGuard(max_per_window=3, window_seconds=15 * 60)


# ---- system stats (Linux /proc; returns None when unavailable) ----
# Cached CPU reading to avoid blocking the request handler with sleep(0.1)
_cpu_cache = {"prev": None, "val": None, "ts": 0}
_cpu_lock = threading.Lock()

def _read_cpu():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("cpu "):
                    nums = [int(x) for x in line.split()[1:]]
                    if len(nums) < 4:
                        return None
                    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
                    return sum(nums), idle
    except (OSError, ValueError):
        return None
    return None

def cpu_percent():
    """Overall CPU usage percent (0-100) from two /proc/stat samples, non-blocking via cache."""
    now = time.time()
    with _cpu_lock:
        # If cache is fresh (<1.5s), return it without blocking
        if _cpu_cache["val"] is not None and now - _cpu_cache["ts"] < 1.5:
            return _cpu_cache["val"]
        cur = _read_cpu()
        if not cur:
            return None
        prev = _cpu_cache["prev"]
        _cpu_cache["prev"] = cur
        if prev is None:
            _cpu_cache["ts"] = now
            return None
        total_delta = cur[0] - prev[0]
        idle_delta = cur[1] - prev[1]
        if total_delta <= 0:
            _cpu_cache["val"] = None
        else:
            _cpu_cache["val"] = round(100 * (1 - idle_delta / total_delta))
        _cpu_cache["ts"] = now
        return _cpu_cache["val"]


def mem_percent():
    try:
        data = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if parts:
                    data[parts[0].rstrip(":")] = int(parts[1])
        total = data.get("MemTotal")
        available = data.get("MemAvailable")
        if not total or available is None:
            return None
        return round(100 * (total - available) / total)
    except (OSError, ValueError):
        return None


def disk_percent(path="/"):
    try:
        st = os.statvfs(path)
    except (OSError, AttributeError):
        return None
    total = st.f_blocks
    used = st.f_blocks - st.f_bfree
    if total <= 0:
        return None
    return round(100 * used / total)


_host_cache = {"host": None, "ts": 0}

def _get_host():
    now = time.time()
    if _host_cache["host"] is not None and now - _host_cache["ts"] < 300:
        return _host_cache["host"]
    try:
        with open("/etc/hostname") as f:
            host = f.read().strip() or socket.gethostname()
    except OSError:
        host = socket.gethostname()
    _host_cache["host"] = host
    _host_cache["ts"] = now
    return host

def stats_payload():
    return {"host": _get_host(), "cpu": cpu_percent(), "mem": mem_percent(), "disk": disk_percent()}


# ---- Beszel multi-server stats proxy ----

BESZEL_CACHE_TTL = 10.0
_beszel_cache = {}
_beszel_cache_lock = threading.Lock()


def clear_beszel_cache():
    with _beszel_cache_lock:
        _beszel_cache.clear()


# ---- 2FA / TOTP (RFC 6238, zero-dependency) ----

def totp_generate_secret():
    """Random base32 secret (160 bits) for authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret_b32, for_time=None):
    """Compute a 6-digit TOTP code for the given time (default: now)."""
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int(for_time if for_time is not None else time.time()) // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return "%06d" % code


def totp_verify(secret_b32, code, window=1):
    """Verify a 6-digit code against the secret, tolerating ±window steps."""
    if not code or not secret_b32:
        return False
    code = str(code).strip()
    if len(code) != 6 or not code.isdigit():
        return False
    now = int(time.time())
    for i in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret_b32, now + i * 30), code):
            return True
    return False


def totp_uri(secret_b32, email):
    """otpauth:// URI for authenticator apps (Google Authenticator, Aegis…)."""
    label = "ServerHub:%s" % email
    return "otpauth://totp/%s?secret=%s&issuer=ServerHub&algorithm=SHA1&digits=6&period=30" % (
        urllib.parse.quote(label, safe=":"), secret_b32)


def twofa_enabled_for(user_settings_row):
    """True when the user's settings carry an enabled 2FA secret."""
    try:
        s = (user_settings_row or {}).get("settings") or {}
        t = s.get("twofa") or {}
        return bool(t.get("enabled")) and bool(t.get("secret"))
    except Exception:
        return False


def read_beszel_env():
    url = read_env("BESZEL_URL", "").rstrip("/")
    if not url:
        return None
    return {
        "url": url,
        "user": read_env("BESZEL_USER", ""),
        "password": read_env("BESZEL_PASSWORD", ""),
    }


def normalize_beszel_system(rec):
    """Map a Beszel systems-collection record to the dashboard shape.

    The live system stats live inside the record's `info` object, stored as
    either a JSON object or a JSON string. Beszel abbreviations (verified
    against the Beszel source): `cpu` (%), `mp` (memory %), `dp` (disk %),
    `u` (usage/uptime).
    """
    info = rec.get("info") or {}
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except Exception:
            info = {}
    if not isinstance(info, dict):
        info = {}
    return {
        "name": rec.get("name"),
        "status": rec.get("status", "unknown"),
        "host": rec.get("host"),
        "uptime": info.get("u"),
        "cpu": info.get("cpu"),
        "mem": info.get("mp"),
        "disk": info.get("dp"),
    }


def _beszel_urlopen(req):
    try:
        # Kısa timeout: serverless fonksiyon limitleri + hızlı "unreachable"
        # dönüşü, kullanıcı test butonuna bastığında uzun beklemek yerine.
        return urllib.request.urlopen(req, timeout=6)
    except urllib.error.HTTPError as e:
        e.close()
        raise


def _beszel_login(cfg):
    url = cfg["url"].rstrip("/") + "/api/collections/users/auth-with-password"
    payload = json.dumps({
        "identity": cfg["user"],
        "password": cfg["password"],
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with _beszel_urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("token")  # PocketBase-issued JWT


def _beszel_systems(cfg=None):
    """Fetch + normalize Beszel systems, cached in-process for 10s.

    cfg: optional {url, user, password} dict (per-user settings). Falls back
    to env vars (BESZEL_URL/USER/PASSWORD) when no cfg is given, so the
    single-admin legacy mode keeps working unchanged.

    Returns a list of {name, cpu, mem, disk, status} dicts, or None when
    Beszel is unconfigured. Raises on connection/auth/fetch failure. Failures
    are negative-cached for BESZEL_CACHE_TTL so a down/unreachable Beszel is
    not hammered on every poll.
    """
    if cfg is None:
        cfg = read_beszel_env()
    if not cfg or not cfg.get("url"):
        return None
    # Treat placeholder/example URL as not configured (prevents 500 on settings test)
    try:
        host = urllib.parse.urlparse(cfg["url"]).netloc.lower().split(":")[0]
        if host == "example.com" or host.endswith(".example.com") or host == "beszel.example.com" or host.endswith(".beszel.example.com"):
            return None
    except:
        pass
    now = time.time()
    cache_key = json.dumps(cfg, sort_keys=True)
    with _beszel_cache_lock:
        cached = _beszel_cache.get(cache_key)
        if cached and now - cached[0] < BESZEL_CACHE_TTL:
            entry = cached[1]
            if isinstance(entry, Exception):
                raise entry
            return entry

    try:
        # Always obtain a fresh JWT via the login flow (token-based API keys
        # can be misconfigured/expired; user/password is the reliable path).
        token = _beszel_login(cfg)
        if not token:
            raise RuntimeError("beszel unreachable")

        req = urllib.request.Request(
            cfg["url"].rstrip("/") + "/api/collections/systems/records?perPage=100",
            headers={
                # PocketBase accepts both "Bearer <token>" and bare "<token>".
                "Authorization": f"Bearer {token}",
            },
        )
        with _beszel_urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        systems = [normalize_beszel_system(rec) for rec in data.get("items", [])]
    except Exception as e:
        with _beszel_cache_lock:
            _beszel_cache[cache_key] = (time.time(), e)
        raise

    with _beszel_cache_lock:
        _beszel_cache[cache_key] = (time.time(), systems)
    return systems


# ---- HTTP handler ----

class HubHandler(BaseHTTPRequestHandler):
    server_version = "ServerHub/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.client_address[0], fmt % args))

    def client_ip(self):
        # HIGH-05: real IP behind Vercel / reverse proxy
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        xri = self.headers.get("X-Real-IP", "")
        if xri:
            return xri.strip()
        return self.client_address[0]

    def send_bytes(self, body, status=200, ctype="text/html; charset=utf-8", extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # ---- Security headers (her yanıtta) ----
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data: https:; "
                         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
                         "font-src 'self' https://fonts.gstatic.com; "
                         "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
                         "connect-src 'self'; frame-ancestors 'self'")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        # Token refresh sırasında yeni imzalı cookie bu yanıta eklenir.
        pending = getattr(self, "_pending_cookie", None)
        if pending:
            self.send_header("Set-Cookie", pending)
            self._pending_cookie = None
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        pending = getattr(self, "_pending_cookie", None)
        if pending:
            self.send_header("Set-Cookie", pending)
            self._pending_cookie = None
        self.end_headers()

    def read_cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            if k.strip() == name:
                return v.strip()
        return None

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return None, "bad content-length"
        if length < 0:
            return None, "bad content-length"
        if length > MAX_API_BODY:
            return None, "payload too large"
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            return json.loads(raw), None
        except ValueError:
            return None, "invalid JSON"

    def session_user(self):
        user = self.server.sessions.get(self.read_cookie("hub_session"))
        # Transparent token refresh: Supabase access tokens live ~1h; the
        # signed cookie lives 30d. If the cookie's token_exp has passed,
        # exchange refresh_token and issue a fresh signed cookie on this
        # response (pending_cookie is attached by send_bytes).
        if user and user.get("supabase_token") and user.get("refresh_token"):
            now = int(time.time())
            tok_exp = int(user.get("token_exp") or 0)
            if 0 < tok_exp < now + 300 and getattr(self.server, "supabase", None) is not None:
                try:
                    new_session = self.server.supabase.refresh(user["refresh_token"])
                    fresh = self._supabase_user_from_session(new_session)
                    fresh_cookie = self.session_cookie(self.server.sessions.sign(fresh))
                    self._pending_cookie = fresh_cookie  # attached by send_bytes
                    return fresh
                except Exception:
                    return None  # refresh failed -> re-login
        return user

    def session_cookie(self, token):
        # Secure flag yalnızca HTTPS'te (X-Forwarded-Proto=https) — reverse proxy
        # arkasında da doğru davranır; HTTP'de Secure flag cookie'yi kırar.
        secure = ""
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            secure = "; Secure"
        return "hub_session=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d%s" % (token, SESSION_TTL, secure)

    def clear_cookie(self):
        return {"Set-Cookie": "hub_session=; Path=/; Max-Age=0"}

    # ---- services API helpers ----

    def _supa(self):
        """Return (supabase_client, user) or (None, user) in legacy mode."""
        if self.server.supabase is None:
            return None, self.session_user()
        return self.server.supabase, self.session_user()

    def _api_services(self):
        supa, user = self._supa()
        if supa is not None:
            try:
                rows = supa.list_services(user["supabase_token"])
                return [_from_db_service(r) for r in rows] if isinstance(rows, list) else rows
            except Exception:
                return None
        return self.server.services.list()

    def _api_bookmarks(self):
        supa, user = self._supa()
        if supa is not None:
            try:
                return supa.list_bookmarks(user["supabase_token"])
            except Exception:
                return None
        return self.server.services.list_bookmarks()

    def _services_response(self, services):
        return self.send_bytes(json.dumps({"services": services}), 200, "application/json; charset=utf-8")

    def _bookmarks_response(self, bookmarks):
        return self.send_bytes(json.dumps({"bookmarks": bookmarks}), 200, "application/json; charset=utf-8")

    def _api_error(self, status, message):
        return self.send_bytes(json.dumps({"error": message}), status, "application/json; charset=utf-8")

    def _log_user_error(self, source, message, details=None):
        """Kullanıcıya özel hata/çakışma logu (Supabase user_logs). Hata bastırılır."""
        supa, user = self._supa()
        if supa is None or not user:
            return
        supa.log(user["supabase_token"], "ERROR", source, message, details, user_id=user.get("user_id"))

    # ---- per-user data endpoints ----

    def _handle_me(self):
        supa, user = self._supa()
        if supa is not None:
            # username profiles'dan okunabilir; session'da da var
            return self.send_bytes(
                json.dumps({"email": user["email"], "username": user["username"], "user_id": user["user_id"]}),
                200, "application/json; charset=utf-8")
        return self.send_bytes(json.dumps({"email": user if isinstance(user, str) else user.get("username", "")}), 200, "application/json; charset=utf-8")

    def _handle_settings_get(self):
        supa, user = self._supa()
        if supa is None:
            return self._api_error(404, "settings only available in multi-user mode")
        try:
            row = supa.get_settings(user["supabase_token"])
            # Gizli alanları client'a dönmeyiz (Beszel password + 2FA secret).
            if isinstance(row, dict) and isinstance(row.get("settings"), dict):
                b = row["settings"].get("beszel")
                if isinstance(b, dict) and "password" in b:
                    b = dict(b)
                    b["password"] = ""
                    row["settings"]["beszel"] = b
                t = row["settings"].get("twofa")
                if isinstance(t, dict):
                    t = dict(t)
                    t["secret"] = ""
                    t["enabled"] = bool(t.get("enabled"))
                    row["settings"]["twofa"] = t
            return self.send_bytes(json.dumps(row), 200, "application/json; charset=utf-8")
        except Exception as e:
            self._log_user_error("settings", "get_settings hatası: %s" % e)
            return self._api_error(500, "settings read failed")

    # ---- 2FA endpoints ----
    def _handle_2fa_setup(self):
        """Generate a fresh TOTP secret (not yet enabled) + QR URI."""
        supa, user = self._supa()
        if supa is None:
            return self._api_error(404, "multi-user mode required")
        secret = totp_generate_secret()
        email = user.get("email", "")
        return self.send_bytes(json.dumps({
            "secret": secret,
            "uri": totp_uri(secret, email),
        }), 200, "application/json; charset=utf-8")

    def _handle_2fa_enable(self):
        """Enable 2FA after verifying the proposed secret with a real code."""
        supa, user = self._supa()
        if supa is None:
            return self._api_error(404, "multi-user mode required")
        data, err = self.read_json_body()
        if err:
            return self._api_error(400, err)
        secret = str((data or {}).get("secret", "")).strip().upper()
        code = str((data or {}).get("code", "")).strip()
        if not secret or not totp_verify(secret, code):
            return self._api_error(400, "invalid authenticator code")
        # Persist enabled 2FA under the user's settings.
        cur = {}
        try:
            cur = supa.get_settings(user["supabase_token"]) or {}
        except Exception:
            pass
        s = dict((cur.get("settings") or {}))
        twofa = dict((s.get("twofa") or {}))
        twofa["enabled"] = True
        twofa["secret"] = secret
        twofa["confirmed"] = True
        s["twofa"] = twofa
        try:
            supa.save_settings(user["supabase_token"], settings=s, layout=cur.get("layout"), user_id=user["user_id"])
            return self.send_bytes(json.dumps({"ok": True, "enabled": True}), 200, "application/json; charset=utf-8")
        except Exception as e:
            self._log_user_error("2fa", "enable hatası: %s" % e)
            return self._api_error(500, "save failed")

    def _handle_2fa_disable(self):
        """Disable 2FA — requires a valid TOTP code (or recovery via session)."""
        supa, user = self._supa()
        if supa is None:
            return self._api_error(404, "multi-user mode required")
        data, err = self.read_json_body()
        if err:
            return self._api_error(400, err)
        code = str((data or {}).get("code", "")).strip()
        cur = {}
        try:
            cur = supa.get_settings(user["supabase_token"]) or {}
        except Exception:
            pass
        s = dict((cur.get("settings") or {}))
        twofa = dict((s.get("twofa") or {}))
        secret = twofa.get("secret", "")
        if not secret or not totp_verify(secret, code):
            return self._api_error(400, "invalid authenticator code")
        twofa = {"enabled": False, "secret": "", "confirmed": False}
        s["twofa"] = twofa
        try:
            supa.save_settings(user["supabase_token"], settings=s, layout=cur.get("layout"), user_id=user["user_id"])
            return self.send_bytes(json.dumps({"ok": True, "enabled": False}), 200, "application/json; charset=utf-8")
        except Exception as e:
            self._log_user_error("2fa", "disable hatası: %s" % e)
            return self._api_error(500, "save failed")

    def _handle_settings_put(self):
        supa, user = self._supa()
        if supa is None:
            return self._api_error(404, "settings only available in multi-user mode")
        data, err = self.read_json_body()
        if err:
            return self._api_error(400, err)
        incoming_settings = data.get("settings") if isinstance(data, dict) else None
        layout = data.get("layout") if isinstance(data, dict) else None
        # ---- Merge (veri kaybını önle) ----
        # Frontend tam settings object yerine partial gönderebilir (özellikle
        # localStorage cold-start'ta boşsa). Mevcut Supabase kaydıyla
        # derin-merge yapılır; eksik anahtarlar korunur. Beszel password boş
        # gelirse mevcut değer de korunur.
        try:
            cur = supa.get_settings(user["supabase_token"]) or {}
            cur_settings = dict((cur.get("settings") or {}))
            cur_layout = dict((cur.get("layout") or {}))
        except Exception:
            cur_settings, cur_layout = {}, {}
        settings = None
        if isinstance(incoming_settings, dict):
            settings = dict(cur_settings)
            for k, v in incoming_settings.items():
                # MED-03: null must not wipe dict with None
                if v is None:
                    continue
                # Reject non-dict for known dict sections to avoid type corruption
                if k in ("beszel", "twofa") and not isinstance(v, dict):
                    continue
                if k == "beszel" and isinstance(v, dict):
                    merged = dict(cur_settings.get("beszel") or {})
                    for bk, bv in v.items():
                        if bk == "password" and not bv:
                            continue  # boş password → mevcut korunur
                        if bv is None:
                            continue
                        merged[bk] = bv
                    settings["beszel"] = merged
                elif isinstance(v, dict) and isinstance(cur_settings.get(k), dict):
                    merged = dict(cur_settings[k])
                    for sk, sv in v.items():
                        if sv is None:
                            continue
                        if sv == "" and isinstance(sv, str) and sk in ("url", "user", "password"):
                            continue
                        merged[sk] = sv
                    settings[k] = merged
                else:
                    settings[k] = v
        if isinstance(layout, dict):
            merged_layout = dict(cur_layout)
            merged_layout.update(layout)
            layout = merged_layout
        try:
            supa.save_settings(user["supabase_token"], settings=settings, layout=layout, user_id=user["user_id"])
            return self.send_bytes(json.dumps({"ok": True}), 200, "application/json; charset=utf-8")
        except Exception as e:
            self._log_user_error("settings", "save_settings hatası: %s" % e)
            return self._api_error(500, "settings save failed")

    def _handle_logs_get(self):
        supa, user = self._supa()
        if supa is None:
            return self.send_bytes(json.dumps({"logs": []}), 200, "application/json; charset=utf-8")
        try:
            logs = supa.list_logs(user["supabase_token"])
            return self.send_bytes(json.dumps({"logs": logs}), 200, "application/json; charset=utf-8")
        except Exception as e:
            return self._api_error(500, "logs read failed")

    def _handle_logs_post(self):
        """Tarayıcı hatalarını kullanıcıya özel kaydet (frontend window.onerror)."""
        supa, user = self._supa()
        if supa is None:
            return self.send_bytes(json.dumps({"ok": True}), 200, "application/json; charset=utf-8")
        data, err = self.read_json_body()
        if err:
            return self._api_error(400, err)
        if not isinstance(data, dict):
            return self._api_error(400, "body must be a JSON object")
        level = str(data.get("level", "ERROR")).upper()
        message = str(data.get("message") or "")[:2000]
        source = str(data.get("source") or "frontend")[:100]
        details = data.get("details")
        if not message:
            return self._api_error(400, "message is required")
        supa.log(user["supabase_token"], level if level in ("ERROR", "WARN", "CONFLICT") else "ERROR",
                 source, message, details, user_id=user.get("user_id"))
        return self.send_bytes(json.dumps({"ok": True}), 200, "application/json; charset=utf-8")

    def _handle_services_create(self):
        supa, user = self._supa()
        data, err = self.read_json_body()
        if err:
            if err == "payload too large":
                return self._api_error(413, err)
            return self._api_error(400, err)
        fields, err = validate_service(data, partial=False)
        if err:
            return self._api_error(400, err)
        if supa is not None:
            try:
                payload = _to_db_service(fields)
                payload["user_id"] = user["user_id"]
                supa.insert("user_services", user["supabase_token"], payload)
            except Exception as e:
                self._log_user_error("services", "servis ekleme hatası: %s" % e)
                return self._api_error(500, "save failed")
        else:
            self.server.services.add(fields)
        return self._services_response(self._api_services())

    def _handle_services_update(self, sid):
        supa, user = self._supa()
        data, err = self.read_json_body()
        if err:
            if err == "payload too large":
                return self._api_error(413, err)
            return self._api_error(400, err)
        fields, err = validate_service(data, partial=True)
        if err:
            return self._api_error(400, err)
        if supa is not None:
            try:
                db_fields = _to_db_service(fields)
                rows = supa.update("user_services", user["supabase_token"], db_fields, "?id=eq." + sid)
                if not rows:
                    return self._api_error(404, "service not found")
            except Exception as e:
                self._log_user_error("services", "servis güncelleme hatası: %s" % e)
                return self._api_error(500, "update failed")
        else:
            if self.server.services.update(sid, fields) is None:
                return self._api_error(404, "service not found")
        return self._services_response(self._api_services())

    def _handle_services_delete(self, sid):
        supa, user = self._supa()
        if supa is not None:
            try:
                rows = supa.delete("user_services", user["supabase_token"], "?id=eq." + sid)
                if not rows:
                    return self._api_error(404, "service not found")
            except Exception as e:
                self._log_user_error("services", "servis silme hatası: %s" % e)
                return self._api_error(500, "delete failed")
        else:
            if not self.server.services.delete(sid):
                return self._api_error(404, "service not found")
        return self._services_response(self._api_services())

    def _handle_bookmarks_create(self):
        supa, user = self._supa()
        data, err = self.read_json_body()
        if err:
            if err == "payload too large":
                return self._api_error(413, err)
            return self._api_error(400, err)
        fields, err = validate_bookmark(data, partial=False)
        if err:
            return self._api_error(400, err)
        if supa is not None:
            try:
                payload = dict(fields)
                payload["user_id"] = user["user_id"]
                supa.insert("user_bookmarks", user["supabase_token"], payload)
            except Exception as e:
                self._log_user_error("bookmarks", "bookmark ekleme hatası: %s" % e)
                return self._api_error(500, "save failed")
        else:
            self.server.services.add_bookmark(fields)
        return self._bookmarks_response(self._api_bookmarks())

    def _handle_bookmarks_update(self, bid):
        supa, user = self._supa()
        data, err = self.read_json_body()
        if err:
            if err == "payload too large":
                return self._api_error(413, err)
            return self._api_error(400, err)
        fields, err = validate_bookmark(data, partial=True)
        if err:
            return self._api_error(400, err)
        if supa is not None:
            try:
                rows = supa.update("user_bookmarks", user["supabase_token"], fields, "?id=eq." + bid)
                if not rows:
                    return self._api_error(404, "bookmark not found")
            except Exception as e:
                self._log_user_error("bookmarks", "bookmark güncelleme hatası: %s" % e)
                return self._api_error(500, "update failed")
        else:
            if self.server.services.update_bookmark(bid, fields) is None:
                return self._api_error(404, "bookmark not found")
        return self._bookmarks_response(self._api_bookmarks())

    def _handle_bookmarks_delete(self, bid):
        supa, user = self._supa()
        if supa is not None:
            try:
                rows = supa.delete("user_bookmarks", user["supabase_token"], "?id=eq." + bid)
                if not rows:
                    return self._api_error(404, "bookmark not found")
            except Exception as e:
                self._log_user_error("bookmarks", "bookmark silme hatası: %s" % e)
                return self._api_error(500, "delete failed")
        else:
            if not self.server.services.delete_bookmark(bid):
                return self._api_error(404, "bookmark not found")
        return self._bookmarks_response(self._api_bookmarks())

    # ---- Beszel API helpers ----

    def _handle_beszel(self):
        # Per-user Beszel credentials from settings (jsonb: {"beszel": {...}}).
        # Falls back to env vars for single-admin legacy mode.
        cfg = None
        supa, user = self._supa()
        if supa is not None and user:
            try:
                row = supa.get_settings(user["supabase_token"])
                beszel_cfg = (row or {}).get("settings", {}).get("beszel") or {}
                if beszel_cfg.get("url"):
                    cfg = {
                        "url": str(beszel_cfg["url"]).rstrip("/"),
                        "user": str(beszel_cfg.get("user", "")),
                        "password": str(beszel_cfg.get("password", "")),
                    }
            except Exception:
                cfg = None  # settings read failure -> fall back to env
        try:
            systems = _beszel_systems(cfg)
        except Exception:
            return self.send_bytes(
                json.dumps({"enabled": True, "error": "beszel unreachable"}), 200,
                "application/json; charset=utf-8")
        if systems is None:
            return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        return self.send_bytes(
            json.dumps({"enabled": True, "systems": systems}), 200,
            "application/json; charset=utf-8")

    def _handle_beszel_test(self):
        """Test connection with credentials from the request body (not saved)."""
        data, err = self.read_json_body()
        if err:
            return self._api_error(400, err)
        cfg = {
            "url": str((data or {}).get("url", "")).rstrip("/"),
            "user": str((data or {}).get("user", "")),
            "password": str((data or {}).get("password", "")),
        }
        if not cfg["url"]:
            return self.send_bytes(
                json.dumps({"enabled": False}), 200,
                "application/json; charset=utf-8")
        # Placeholder/example URL is not a real Beszel — treat as not configured
        try:
            _host = urllib.parse.urlparse(cfg["url"]).netloc.lower().split(":")[0]
            if _host == "example.com" or _host.endswith(".example.com") or _host == "beszel.example.com" or _host.endswith(".beszel.example.com"):
                return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        except:
            pass
        try:
            systems = _beszel_systems(cfg)
        except Exception:
            return self.send_bytes(
                json.dumps({"enabled": True, "error": "beszel unreachable"}), 200,
                "application/json; charset=utf-8")
        if systems is None:
            return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        return self.send_bytes(
            json.dumps({"enabled": True, "systems": systems}), 200,
            "application/json; charset=utf-8")

    def serve_file(self, rel):
        if not rel:
            return self.send_bytes("Not found", 404)
        full = os.path.normpath(os.path.join(WEB_ROOT, rel))
        if full != WEB_ROOT and not full.startswith(WEB_ROOT + os.sep):
            return self.send_bytes("Forbidden", 403)
        if not os.path.isfile(full):
            return self.send_bytes("Not found", 404)
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME.get(ext, "application/octet-stream")
        with open(full, "rb") as f:
            body = f.read()
        return self.send_bytes(body, 200, ctype, {"Cache-Control": "no-cache"})

    # ---- routes ----

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in PUBLIC_PATHS:
            user = self.session_user()
            if user:
                return self.redirect("/")
            # Single auth page: login + signup tabs. /register opens the
            # signup panel (login.html ?show=signup). Legacy register.html
            # redirects to the new combined page.
            if path in ("/register", "/register.html"):
                return self.send_bytes(
                    "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=/login?show=signup\"></head><body></body></html>",
                    200, "text/html; charset=utf-8")
            return self.serve_file("login.html")
        if path == "/logout":
            user = self.session_user()
            if self.server.supabase is not None and user and user.get("supabase_token"):
                # Supabase tarafında refresh token'ları iptal et (best effort)
                try:
                    self.server.supabase.sign_out(user["supabase_token"])
                except Exception:
                    pass
            self.server.sessions.delete(self.read_cookie("hub_session"))
            return self.redirect("/login", self.clear_cookie())
        user = self.session_user()
        if path == "/api/stats":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self.send_bytes(json.dumps(stats_payload()), 200, "application/json; charset=utf-8")
        if path == "/api/services":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._services_response(self._api_services())
        if path == "/api/beszel":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_beszel()
        if path == "/api/bookmarks":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._bookmarks_response(self._api_bookmarks())
        if path == "/api/me":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_me()
        if path == "/api/settings":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_settings_get()
        if path == "/api/2fa/setup":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_2fa_setup()
        if path == "/api/logs":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_logs_get()
        # Public static assets (favicon, logo, JS, CSS) — not sensitive, and
        # required for the login page's favicon/logo to render without a session.
        ext = os.path.splitext(path)[1].lower()
        if ext in (".png", ".svg", ".ico", ".gif", ".jpg", ".jpeg", ".webp", ".js", ".css", ".woff", ".woff2"):
            return self.serve_file(path.lstrip("/"))
        if not user:
            return self.redirect("/login")
        if path == "/":
            return self.serve_file("index.html")
        return self.serve_file(path.lstrip("/"))

    def _csrf_blocked(self):
        """CSRF koruması: tüm mutating istekler same-origin olmalı.

        Origin header'ı yoksa (curl, eski istemci) allow — SameSite=Lax cookie
        zaten tarayıcı tabanlı CSRF'yi büyük ölçüde engeller; Origin farklıysa
        (cross-site form/JS) reddet. Sec-Fetch-Site: cross-site de reddet.
        Also checks X-Forwarded-Host behind proxy (LOW-02).
        """
        origin = self.headers.get("Origin")
        if origin:
            ref = self.headers.get("Host", "")
            xfh = self.headers.get("X-Forwarded-Host", "")
            try:
                from urllib.parse import urlparse
                o_host = urlparse(origin).netloc
            except ValueError:
                return True
            if o_host and o_host != ref and o_host != xfh:
                return True
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site == "cross-site":
            return True
        return False

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if self._csrf_blocked():
            return self.send_bytes(json.dumps({"error": "forbidden"}), 403, "application/json; charset=utf-8")
        if path == "/api/services":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_services_create()
        if path == "/api/bookmarks":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_bookmarks_create()
        if path == "/api/logs":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_logs_post()
        if path == "/api/2fa/enable":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_2fa_enable()
        if path == "/api/2fa/disable":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_2fa_disable()
        if path == "/api/beszel":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_beszel_test()
        if path not in ("/login", "/register"):
            return self.send_bytes("Not found", 404)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return self.send_bytes("Bad request", 400, "text/plain; charset=utf-8")
        if length < 0:
            return self.send_bytes("Bad request", 400, "text/plain; charset=utf-8")
        if length > MAX_LOGIN_BODY:
            return self.send_bytes("Payload too large", 413, "text/plain; charset=utf-8")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(raw)
        # Support new 3-field registration (email, username, password) and old 2-field (username as email)
        email = (form.get("email") or [""])[0].strip()
        username = (form.get("username") or [""])[0].strip()
        password = (form.get("password") or [""])[0]
        website_url = (form.get("website_url") or [""])[0].strip()  # honeypot
        form_ts = (form.get("form_ts") or [""])[0].strip()
        ip = self.client_ip()
        if guard.is_locked(ip):
            return self.redirect("/login?error=locked")

        # ---- Supabase multi-user (primary) ----
        if self.server.supabase is not None:
            if path == "/register":
                # Bulk prevention: honeypot must be empty, timestamp must be 1.5s-1h old, rate limit 3 per 15m
                if website_url:
                    return self.redirect("/login?show=signup&error=honeypot")
                try:
                    ts = int(form_ts) if form_ts else 0
                    now_ms = int(time.time() * 1000)
                    if not ts or now_ms - ts < 1500 or now_ms - ts > 3600000 or ts > now_ms + 30000:
                        return self.redirect("/login?show=signup&error=honeypot")
                except:
                    return self.redirect("/login?show=signup&error=honeypot")
                if register_guard.is_limited(ip):
                    return self.redirect("/login?show=signup&error=rate")
                # Normalize email/username: support old form where username is email
                if not email and "@" in username:
                    email = username
                    username = email.split("@")[0]
                elif not email:
                    email = username
                # Username fallback from email if not provided separately
                if not username or "@" in username:
                    username = (email.split("@")[0] if "@" in email else username) or "user"
                # Validate email, username, password
                if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=1")
                # Username: 3-20 chars, alphanumeric + underscore, not an email
                if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=1")
                if len(password) < 8:
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=1")
                # Check username not already taken (use SECURITY DEFINER RPC to bypass RLS)
                try:
                    if self.server.supabase.username_exists(username):
                        guard.record_failure(ip)
                        return self.redirect("/login?show=signup&error=1")
                except:
                    pass
                session = None
                signup_err = None
                try:
                    session = self.server.supabase.sign_up(email, password, username)
                except Exception as e:
                    signup_err = e
                    session = None
                # Normal signup may return user without access_token when email confirmation is required
                # or hit rate limit (429). In those cases try admin_create_user (service_role, auto-confirmed) first,
                # then fallback to bypass RPC.
                if not session or not session.get("access_token"):
                    try:
                        # Prefer admin_create_user via service_role (most reliable, bypasses rate limit)
                        if hasattr(self.server.supabase, 'admin_create_user') and self.server.supabase.service_role_key != self.server.supabase.anon_key:
                            try:
                                admin_res = None
                                try:
                                    admin_res = self.server.supabase.admin_create_user(email, password, username)
                                except Exception as e:
                                    if "429" in str(e) or "rate" in str(e).lower():
                                        admin_res = None
                                    else:
                                        admin_res = None
                                if admin_res and admin_res.get("id"):
                                    try:
                                        session = self.server.supabase.sign_in(email, password)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                        # Fallback: bypass RPC that creates user directly with email_confirmed_at = now()
                        if (not session or not session.get("access_token")):
                            try:
                                bypass_res = None
                                try:
                                    bypass_res = self.server.supabase.signup_bypass(email, password, username)
                                except Exception:
                                    bypass_res = None
                                if bypass_res and not bypass_res.get("error"):
                                    try:
                                        session = self.server.supabase.sign_in(email, password)
                                    except Exception:
                                        session = None
                            except Exception:
                                pass
                        # If normal signup had no session but user exists (confirmation pending), try sign-in directly
                        if (not session or not session.get("access_token")) and signup_err is None:
                            try:
                                session = self.server.supabase.sign_in(email, password)
                            except Exception:
                                pass
                    except Exception:
                        pass
                if not session or not session.get("access_token"):
                    guard.record_failure(ip)
                    # 422 = email taken / weak password / username taken; show generic error
                    return self.redirect("/login?show=signup&error=1")
                guard.reset(ip)
                register_guard.record(ip)
                user = self._supabase_user_from_session(session)
                token = self.server.sessions.sign(user)
                return self.redirect("/", {"Set-Cookie": self.session_cookie(token)})

            # ---- 2FA second step: username + TOTP code ----
            totp_code_val = (form.get("totp") or [""])[0]
            if totp_code_val:
                pending = self.read_cookie("2fa_pending")
                if not pending:
                    return self.redirect("/login?error=expired")
                pend_user = self.server.sessions.verify_signed(pending)
                if not pend_user or not pend_user.get("email"):
                    return self.redirect("/login?error=expired")
                # Fetch that user's settings and check the stored secret.
                try:
                    row = self.server.supabase.get_settings(pend_user.get("supabase_token", ""))
                except Exception:
                    row = None
                secret = None
                try:
                    s = (row or {}).get("settings") or {}
                    t = s.get("twofa") or {}
                    if t.get("enabled"):
                        secret = t.get("secret")
                except Exception:
                    secret = None
                if secret and totp_verify(secret, totp_code_val):
                    guard.reset(ip)
                    token = self.server.sessions.sign(pend_user)
                    # hub_session kur (Set-Cookie), 2fa_pending'i ayrı header ile sil
                    self._pending_cookie = "2fa_pending=; Path=/; Max-Age=0"
                    return self.redirect("/", {"Set-Cookie": self.session_cookie(token)})
                # Wrong or expired — keep pending but show error.
                guard.record_failure(ip)
                return self.redirect("/login?2fa=1&error=totp")

            # ---- login first step (password) - supports email or username ----
            login_id = (form.get("username") or [""])[0].strip() if form.get("username") else username.strip()
            # username variable from earlier is already stripped, but for login form it's the same field
            # If login_id is username (no @), resolve to email via RPC
            email_for_login = login_id or username
            if email_for_login and "@" not in email_for_login:
                try:
                    resolved = self.server.supabase.get_email_by_username(email_for_login)
                    # RPC returns text or json, handle both
                    if isinstance(resolved, str) and "@" in resolved:
                        email_for_login = resolved
                    elif isinstance(resolved, dict) and resolved.get("email") and "@" in resolved["email"]:
                        email_for_login = resolved["email"]
                except:
                    pass
            try:
                session = self.server.supabase.sign_in(email_for_login or "", password)
            except Exception:
                session = None
            if not session or not session.get("access_token"):
                guard.record_failure(ip)
                return self.redirect("/login?error=1")
            guard.reset(ip)
            user = self._supabase_user_from_session(session)
            # 2FA check: if the user enabled it, require a TOTP code next.
            try:
                row = self.server.supabase.get_settings(user["supabase_token"])
                need_2fa = twofa_enabled_for(row)
            except Exception:
                need_2fa = False
            if need_2fa:
                pending = self.server.sessions.sign(user)
                return self.redirect("/login?2fa=1", {"Set-Cookie": self._pending_cookie_value(pending)})
            token = self.server.sessions.sign(user)
            return self.redirect("/", {"Set-Cookie": self.session_cookie(token)})

        # ---- Legacy single-user fallback ----
        if secrets.compare_digest(username, self.server.hub_user) and secrets.compare_digest(
            password, self.server.hub_password
        ):
            guard.reset(ip)
            token = self.server.sessions.create({"username": username})
            return self.redirect("/", {"Set-Cookie": self.session_cookie(token)})
        guard.record_failure(ip)
        return self.redirect("/login?error=1")

    def _pending_cookie_value(self, token):
        """Short-lived cookie for the pending-2FA login step (5 min)."""
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        return "2fa_pending=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=300%s" % (token, secure)

    def _supabase_user_from_session(self, session):
        """Build the user dict stored in the local session from a Supabase session."""
        access_token = session.get("access_token", "")
        user_obj = session.get("user") or {}
        email = user_obj.get("email") or ""
        user_id = user_obj.get("id") or (user_obj.get("sub") or "")
        meta = user_obj.get("user_metadata") or {}
        # token_exp: JWT exp claim (seconds) — for transparent refresh
        token_exp = 0
        try:
            parts = access_token.split(".")
            if len(parts) == 3:
                pad = "=" * (-len(parts[1]) % 4)
                claims = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
                token_exp = int(claims.get("exp", 0))
        except Exception:
            pass
        return {
            "user_id": user_id,
            "email": email,
            "supabase_token": access_token,
            "refresh_token": session.get("refresh_token", ""),
            "token_exp": token_exp,
            "username": meta.get("username") or email.split("@")[0] or "user",
        }

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if self._csrf_blocked():
            return self.send_bytes(json.dumps({"error": "forbidden"}), 403, "application/json; charset=utf-8")
        m = re.match(r"^/api/services/([^/]+)$", path)
        if m:
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_services_update(m.group(1))
        m = re.match(r"^/api/bookmarks/([^/]+)$", path)
        if m:
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_bookmarks_update(m.group(1))
        if path == "/api/settings":
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_settings_put()
        return self.send_bytes("Not found", 404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if self._csrf_blocked():
            return self.send_bytes(json.dumps({"error": "forbidden"}), 403, "application/json; charset=utf-8")
        m = re.match(r"^/api/services/([^/]+)$", path)
        if m:
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_services_delete(m.group(1))
        m = re.match(r"^/api/bookmarks/([^/]+)$", path)
        if m:
            user = self.session_user()
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_bookmarks_delete(m.group(1))
        return self.send_bytes("Not found", 404)


class HubServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, hub_user, hub_password, services_path=None, supabase=None):
        super().__init__(addr, handler)
        self.hub_user = hub_user
        self.hub_password = hub_password
        self.supabase = supabase
        self.sessions = Sessions()
        self.services = ServiceStore(services_path or SERVICES_FILE)


def create_server(host="0.0.0.0", port=8642, user=None, password=None, services_path=None, supabase=None):
    user = user or read_env("HUB_USER", "admin")
    password = password or read_env("HUB_PASSWORD")
    if not password and not supabase:
        raise SystemExit("HUB_PASSWORD must be set (and not empty) when SUPABASE_URL is not configured.")
    return HubServer((host, port), HubHandler, user, password, services_path, supabase)


def main():
    host = read_env("HUB_HOST", "0.0.0.0")
    port = int(read_env("HUB_PORT", "8642"))
    supa_url = read_env("SUPABASE_URL", "")
    supa_key = read_env("SUPABASE_ANON_KEY", "")
    supa_service = read_env("SUPABASE_SERVICE_ROLE_KEY", "") or read_env("SUPABASE_SERVICE_KEY", "")
    supabase = None
    if supa_url and supa_key:
        import auth
        supabase = auth.SupabaseClient(supa_url, supa_key, supa_service or None)
        print("Auth: Supabase multi-user at %s" % supa_url)
    else:
        print("Auth: legacy single-user (HUB_USER/HUB_PASSWORD)")
    httpd = create_server(host, port, supabase=supabase)
    httpd.socket.settimeout(30)
    print("Server Hub listening on http://%s:%d" % (host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBye")
        httpd.server_close()


if __name__ == "__main__":
    main()
