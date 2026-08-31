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
import ipaddress
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
WEB_ROOT_REAL = os.path.realpath(WEB_ROOT)
SESSION_TTL = 30 * 24 * 60 * 60  # 30 days

# Precompiled regexes (perf)
_EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
_URL_RE = re.compile(r"^https?://")
_URL_RE_I = re.compile(r"^https?://", re.IGNORECASE)

# Security header constants (avoid rebuilding per request)
CSP_VALUE = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'self'"
PERM_POLICY = "camera=(), microphone=(), geolocation=()"
SEC_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", CSP_VALUE),
    ("Permissions-Policy", PERM_POLICY),
)
_host_cache_lock = threading.Lock()


def _security_headers(path, is_https):
    hdrs = list(SEC_HEADERS)
    if path.startswith("/api/"):
        hdrs.append(("Cache-Control", "no-store"))
    if is_https:
        hdrs.append(("Strict-Transport-Security", "max-age=63072000"))
    return hdrs
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
MAX_LOGIN_BODY = 64 * 1024  # reject larger login POST bodies before reading them
PUBLIC_PATHS = {"/login", "/login.html", "/register", "/register.html"}

# For local dev/test, default to insecure HTTP cookies so http://127.0.0.1 works with cookiejar.
# Prod (VERCEL==1) remains Secure unless explicitly overridden via HUB_INSECURE_HTTP==1.
if os.environ.get("VERCEL") != "1" and os.environ.get("HUB_INSECURE_HTTP") is None:
    os.environ["HUB_INSECURE_HTTP"] = "1"

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
        if not _URL_RE.match(url):
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
        if not _URL_RE.match(url):
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
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}

# Allowed static extensions for authenticated fallback — derived from MIME plus common web assets, minus sensitive
ALLOWED_STATIC = (set(MIME.keys()) | {".woff", ".woff2", ".gif", ".jpg", ".jpeg", ".webp"}) - {".md", ".map"}


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
        self._secret_b = self._secret.encode("utf-8")
        self._pending_used = {}  # jti -> exp
        self._pending_used_lock = threading.Lock()
        self._totp_attempts = {}  # user_id -> [timestamps]
        self._totp_lock = threading.Lock()

    def _hmac(self, b64):
        return hmac.new(self._secret_b, b64.encode("utf-8"), hashlib.sha256).hexdigest()

    def _b64json(self, b64):
        raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        return json.loads(raw.decode("utf-8"))

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
        typ = user.get("typ")
        is_pending = typ == "pending"
        exp = int(time.time()) + (300 if is_pending else SESSION_TTL)
        payload = {
            "user_id": user.get("user_id", ""),
            "email": user.get("email", ""),
            "username": user.get("username", ""),
            "supabase_token": user.get("supabase_token", ""),
            "refresh_token": user.get("refresh_token", ""),
            "token_exp": int(user.get("token_exp", 0) or 0),
            "exp": exp,
        }
        # typ discriminator for 2FA pending vs session (CRIT-2FA)
        if typ:
            payload["typ"] = typ
        if is_pending:
            payload["jti"] = secrets.token_hex(8)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        sig = self._hmac(b64)
        return b64 + "." + sig

    def _prune_pending_used(self):
        now = time.time()
        with self._pending_used_lock:
            expired = [k for k, exp in self._pending_used.items() if exp < now]
            for k in expired:
                self._pending_used.pop(k, None)

    def totp_is_rate_limited(self, user_id):
        now = time.time()
        with self._totp_lock:
            lst = self._totp_attempts.get(user_id, [])
            lst = [t for t in lst if now - t < 300]
            self._totp_attempts[user_id] = lst
            return len(lst) >= 5

    def totp_record_failure(self, user_id):
        now = time.time()
        with self._totp_lock:
            lst = self._totp_attempts.get(user_id, [])
            lst = [t for t in lst if now - t < 300]
            lst.append(now)
            self._totp_attempts[user_id] = lst

    def totp_reset(self, user_id):
        with self._totp_lock:
            self._totp_attempts.pop(user_id, None)

    def verify_signed(self, token):
        """Verify a signed cookie value -> user dict or None. Rejects pending tokens."""
        if not token or "." not in token:
            return None
        b64, sig = token.rsplit(".", 1)
        try:
            expected = self._hmac(b64)
            if not hmac.compare_digest(sig, expected):
                return None
            payload = self._b64json(b64)
        except Exception:
            return None
        if int(payload.get("exp", 0)) < time.time():
            return None
        # 2FA bypass fix: pending tokens must not be accepted as session
        if payload.get("typ") == "pending":
            return None
        return {
            "user_id": payload.get("user_id", ""),
            "email": payload.get("email", ""),
            "username": payload.get("username", ""),
            "supabase_token": payload.get("supabase_token", ""),
            "refresh_token": payload.get("refresh_token", ""),
            "token_exp": int(payload.get("token_exp", 0) or 0),
        }

    def verify_pending(self, token):
        """Verify a pending-2FA token (typ==pending) -> user dict or None. Checks jti replay."""
        if not token or "." not in token:
            return None
        b64, sig = token.rsplit(".", 1)
        try:
            expected = self._hmac(b64)
            if not hmac.compare_digest(sig, expected):
                return None
            payload = self._b64json(b64)
        except Exception:
            return None
        if int(payload.get("exp", 0)) < time.time():
            return None
        if payload.get("typ") != "pending":
            return None
        jti = payload.get("jti")
        if jti:
            self._prune_pending_used()
            with self._pending_used_lock:
                if jti in self._pending_used:
                    return None
        return {
            "user_id": payload.get("user_id", ""),
            "email": payload.get("email", ""),
            "username": payload.get("username", ""),
            "supabase_token": payload.get("supabase_token", ""),
            "refresh_token": payload.get("refresh_token", ""),
            "token_exp": int(payload.get("token_exp", 0) or 0),
            "_jti": jti,
            "_exp": int(payload.get("exp", 0)),
        }

    def burn_pending_jti(self, jti, exp):
        if not jti:
            return
        self._prune_pending_used()
        with self._pending_used_lock:
            self._pending_used[jti] = int(exp)


class LoginGuard:
    """Brute-force protection: N failed attempts per IP -> lockout."""

    def __init__(self, max_attempts=MAX_ATTEMPTS, lockout_seconds=LOCKOUT_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._state = {}
        self._lock = threading.Lock()

    def is_locked(self, ip):
        now = time.time()
        with self._lock:
            entry = self._state.get(ip)
            if not entry:
                return False
            fails, locked_until = entry
            if locked_until and now < locked_until:
                return True
            if locked_until:
                self._state[ip] = (0, 0)
            return False

    def record_failure(self, ip):
        now = time.time()
        with self._lock:
            fails, locked_until = self._state.get(ip, (0, 0))
            fails += 1
            if fails >= self.max_attempts:
                fails = 0
                locked_until = now + self.lockout_seconds
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
        now = time.time()
        with self._lock:
            lst = self._state.get(ip, [])
            lst = [t for t in lst if now - t < self.window_seconds]
            self._state[ip] = lst
            return len(lst) >= self.max_per_window

    def record(self, ip):
        now = time.time()
        with self._lock:
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
    with _host_cache_lock:
        if _host_cache["host"] is not None and now - _host_cache["ts"] < 300:
            return _host_cache["host"]
    try:
        with open("/etc/hostname") as f:
            host = f.read().strip() or socket.gethostname()
    except OSError:
        host = socket.gethostname()
    with _host_cache_lock:
        _host_cache["host"] = host
        _host_cache["ts"] = now
    return host

def stats_payload():
    return {"host": _get_host(), "cpu": cpu_percent(), "mem": mem_percent(), "disk": disk_percent()}


# ---- Beszel multi-server stats proxy ----

BESZEL_CACHE_TTL = 10.0
_beszel_cache = {}
_beszel_cache_lock = threading.Lock()

BESZEL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
  }


def clear_beszel_cache():
    with _beszel_cache_lock:
        _beszel_cache.clear()


def _is_private_host(host):
    """Check if hostname is private/internal IP literal or localhost."""
    if not host:
        return True
    h = host.strip().lower()
    # strip brackets for IPv6 literals
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # localhost variants
    if h in ("localhost", "metadata.google.internal"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        # Allow private for local dev/test when HUB_INSECURE_HTTP==1 (tests use 127.0.0.1 stub)
        # In prod (VERCEL==1) this is still blocked unless insecure flag is set.
        if os.environ.get("HUB_INSECURE_HTTP") == "1":
            return False
        # Block private, loopback, link-local, multicast, reserved, unspecified (0.0.0.0)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        # 169.254.169.254 and similar metadata
        if str(ip) == "169.254.169.254":
            return True
        return False
    except ValueError:
        # Not an IP literal -> not considered private here (DNS names allowed except example.com handled separately)
        return False


def _validate_beszel_url(url):
    """Validate Beszel URL for SSRF: scheme http/https, host not private, not example.com."""
    if not url or not isinstance(url, str):
        return False, "url required"
    url = url.strip()
    if not _URL_RE_I.match(url):
        return False, "url must start with http:// or https://"
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "invalid url"
    host = parsed.hostname
    if not host:
        return False, "invalid url"
    hl = host.lower()
    if hl == "example.com" or hl.endswith(".example.com") or hl == "beszel.example.com" or hl.endswith(".beszel.example.com"):
        return False, "example host blocked"
    if _is_private_host(host):
        return False, "private host blocked"
    return True, None


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
    try:
        key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    except Exception:
        return False
    now = int(time.time())
    for i in range(-window, window + 1):
        counter = (now + i * 30) // 30
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[19] & 0x0F
        calc = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        if hmac.compare_digest("%06d" % calc, code):
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


def _beszel_format_error(e):
    """Return detailed error string for Beszel failures, truncated to 200 chars."""
    try:
        if isinstance(e, urllib.error.HTTPError):
            base = f"{type(e).__name__} {e.code}: {e.reason}"
            s = str(e)
            if s and s not in base and base not in s:
                detail = f"{base} - {s}"
            else:
                detail = base
            # Enhance with PocketBase JSON body message if available
            body = None
            # Prefer previously captured body (set by _beszel_login / _beszel_urlopen)
            b = getattr(e, "_body", None)
            if isinstance(b, str) and b:
                body = b
            else:
                # Try to read from the HTTPError object (may be consumed already)
                try:
                    # e.read() may have been consumed; try fp directly as fallback
                    try:
                        raw = e.read()
                    except Exception:
                        raw = None
                        try:
                            if getattr(e, "fp", None) is not None:
                                raw = e.fp.read()
                        except Exception:
                            raw = None
                    if raw:
                        if isinstance(raw, bytes):
                            body = raw.decode("utf-8", "replace")
                        else:
                            body = str(raw)
                except Exception:
                    body = None
                # Ensure file pointer is closed after attempt
                try:
                    e.close()
                except Exception:
                    pass
            if body:
                body = body[:500]
                msg = None
                try:
                    j = json.loads(body)
                    if isinstance(j, dict):
                        msg = j.get("message")
                        if not msg:
                            data = j.get("data")
                            if isinstance(data, dict):
                                # PocketBase validation shape: data[field].message
                                for v in data.values():
                                    if isinstance(v, dict) and v.get("message"):
                                        msg = v["message"]
                                        break
                                    if isinstance(v, str) and v:
                                        msg = v
                                        break
                            if not msg and isinstance(data, str):
                                msg = data
                        if not msg:
                            # fallback to any string value
                            for k in ("error", "reason", "detail"):
                                if isinstance(j.get(k), str) and j.get(k):
                                    msg = j.get(k)
                                    break
                except Exception:
                    msg = None
                extra = (msg or body[:120]).strip()
                if extra:
                    # avoid duplicating if already in detail
                    if extra not in detail:
                        detail = f"{detail} - {extra}"
            # Also try to include body saved on exception even if read succeeded earlier
        else:
            detail = f"{type(e).__name__}: {e}"
        if not detail.strip():
            detail = type(e).__name__
        # Cloudflare challenge detection
        if "Just a moment" in detail or "cf-challenge" in detail or "Attention Required" in detail or "DDoS protection" in detail:
            return "Beszel blocked by Cloudflare (Just a moment). Disable 'I'm Under Attack' for bs.canozdal.com or add WAF rule to allow Vercel IPs, or use direct origin URL (e.g., tunnel URL)."
        # Scrub internal URLs/IPs from detail to avoid leaking
        try:
            detail = re.sub(r"https?://[^\s\"'<>]+", "[url]", detail)
            detail = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "[ip]", detail)
        except Exception:
            pass
    except Exception:
        try:
            detail = f"{type(e).__name__}: {e}"
        except Exception:
            detail = "error"
        if "Just a moment" in detail or "cf-challenge" in detail or "Attention Required" in detail or "DDoS protection" in detail:
            return "Beszel blocked by Cloudflare (Just a moment). Disable 'I'm Under Attack' for bs.canozdal.com or add WAF rule to allow Vercel IPs, or use direct origin URL (e.g., tunnel URL)."
        try:
            detail = re.sub(r"https?://[^\s\"'<>]+", "[url]", detail)
            detail = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "[ip]", detail)
        except Exception:
            pass
    return detail[:200]


def _beszel_urlopen(req):
    try:
        # Kısa timeout: serverless fonksiyon limitleri + hızlı "unreachable"
        # dönüşü, kullanıcı test butonuna bastığında uzun beklemek yerine.
        return urllib.request.urlopen(req, timeout=6)
    except urllib.error.HTTPError as e:
        # Preserve HTTP body for _beszel_format_error and _beszel_login fallback
        try:
            body = e.read().decode("utf-8", "replace")
            e._body = body[:2000]
        except Exception:
            try:
                # fallback via fp if e.read() already consumed
                if getattr(e, "fp", None) is not None:
                    try:
                        raw = e.fp.read()
                        if raw:
                            e._body = raw.decode("utf-8", "replace")[:2000] if isinstance(raw, bytes) else str(raw)[:2000]
                        else:
                            e._body = ""
                    except Exception:
                        e._body = ""
                else:
                    e._body = ""
            except Exception:
                try:
                    e._body = ""
                except Exception:
                    pass
        # Do not close before raising; caller/_beszel_format_error will handle body via _body
        raise


def _beszel_login(cfg):
    """Authenticate to PocketBase (Beszel) with fallback for _superusers.

    Tries users collection first; on HTTP 400/403/404 falls back to _superusers.
    Handles empty identity/password gracefully (PocketBase will return 400).
    Preserves HTTPError body via e._body for detailed error reporting.
    """
    last_err = None
    base_url = (cfg.get("url") or "").strip().rstrip("/")
    user = cfg.get("user") or ""
    password = cfg.get("password") or ""
    for collection in ("users", "_superusers"):
        url = base_url + f"/api/collections/{collection}/auth-with-password"
        payload = json.dumps({
            "identity": user,
            "password": password,
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={**BESZEL_HEADERS, "Content-Type": "application/json"},
        )
        try:
            with _beszel_urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            token = data.get("token")
            return token  # PocketBase-issued JWT
        except urllib.error.HTTPError as e:
            # Ensure body is captured (may already be set by _beszel_urlopen)
            if not hasattr(e, "_body"):
                try:
                    body = e.read().decode("utf-8", "replace")
                    e._body = body[:2000]
                except Exception:
                    try:
                        if getattr(e, "fp", None) is not None:
                            raw = e.fp.read()
                            if raw:
                                e._body = raw.decode("utf-8", "replace")[:2000] if isinstance(raw, bytes) else str(raw)[:2000]
                            else:
                                e._body = ""
                        else:
                            e._body = ""
                    except Exception:
                        try:
                            e._body = ""
                        except Exception:
                            pass
            last_err = e
            if collection == "users" and e.code in (400, 403, 404):
                continue
            else:
                raise
        except Exception as e:
            # Non-HTTP errors (network, timeout) are not fallback-eligible
            raise
    if last_err is not None:
        raise last_err
    raise RuntimeError("beszel login failed")


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
    # Validate URL for SSRF and handle placeholder example hosts
    ok, _err = _validate_beszel_url(cfg["url"])
    if not ok:
        if _err and "example" in _err:
            return None
        raise RuntimeError(_err)
    # DNS rebinding: resolve host and block if any IP is private/internal
    try:
        _host = urllib.parse.urlparse(cfg["url"]).hostname
        if _host:
            try:
                infos = socket.getaddrinfo(_host, None)
            except socket.gaierror:
                infos = []
            for _info in infos:
                try:
                    _ip = _info[4][0]
                except Exception:
                    continue
                if _is_private_host(_ip):
                    raise RuntimeError("private host blocked")
    except RuntimeError:
        raise
    except Exception:
        pass
    now = time.time()
    cache_key = json.dumps(cfg, sort_keys=True)
    # singleflight: check cache under lock, release for network fetch, re-acquire to populate
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
            headers={**BESZEL_HEADERS, "Authorization": f"Bearer {token}"},
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
        # IP spoof fix: only trust proxy headers on Vercel, use last entry (closest proxy) not first (spoofable)
        if os.environ.get("VERCEL") == "1":
            # Prefer Vercel's specific header if present
            xvf = self.headers.get("X-Vercel-Forwarded-For", "")
            if xvf:
                # take last entry
                parts = [p.strip() for p in xvf.split(",") if p.strip()]
                if parts:
                    cand = parts[-1]
                    try:
                        ipaddress.ip_address(cand)
                        return cand
                    except ValueError:
                        return cand
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                parts = [p.strip() for p in xff.split(",") if p.strip()]
                if parts:
                    cand = parts[-1]
                    # validate is ip else fallback
                    try:
                        ipaddress.ip_address(cand)
                        return cand
                    except ValueError:
                        # if not ip, still return last trimmed
                        return cand
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
        for k, v in _security_headers(self.path, self.headers.get("X-Forwarded-Proto") == "https"):
            self.send_header(k, v)
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
        for k, v in _security_headers(self.path, self.headers.get("X-Forwarded-Proto") == "https"):
            self.send_header(k, v)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        pending = getattr(self, "_pending_cookie", None)
        if pending:
            self.send_header("Set-Cookie", pending)
            self._pending_cookie = None
        self.end_headers()

    def read_cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        # handle __Host fallback for hub_session
        candidates = [name]
        if name == "hub_session":
            candidates = ["__Host-hub_session", "hub_session"]
        for cand in candidates:
            for part in raw.split(";"):
                part = part.strip()
                if not part or "=" not in part:
                    continue
                k, v = part.split("=", 1)
                if k.strip() == cand:
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

    def _session_cookie_name(self):
        # __Host- prefix requires Secure, Path=/, no Domain; use when Secure (VERCEL==1)
        if os.environ.get("VERCEL") == "1" and os.environ.get("HUB_INSECURE_HTTP") != "1":
            return "__Host-hub_session"
        return "hub_session"

    def session_user(self):
        # try __Host- first then fallback
        _raw = self.read_cookie("__Host-hub_session")
        if not _raw:
            _raw = self.read_cookie("hub_session")
        if not _raw:
            return None
        # Single HMAC verify: verify_signed already rejects pending tokens (typ==pending)
        user = self.server.sessions.get(_raw)
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
        # Secure cookie: always Secure/HttpOnly/SameSite/Path unless HUB_INSECURE_HTTP==1 for local HTTP dev
        secure = "" if os.environ.get("HUB_INSECURE_HTTP") == "1" else "; Secure"
        name = self._session_cookie_name()
        return "%s=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d%s" % (name, token, SESSION_TTL, secure)

    def clear_cookie(self):
        secure = "" if os.environ.get("HUB_INSECURE_HTTP") == "1" else "; Secure"
        name = self._session_cookie_name()
        return {"Set-Cookie": "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s" % (name, secure)}

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

    def _handle_bootstrap(self):
        """Coalesced batch endpoint: services + bookmarks + settings + user in one RTT."""
        supa, user = self._supa()
        # Legacy mode: no Supabase — serve from local ServiceStore
        if supa is None:
            services = self.server.services.list()
            bookmarks = self.server.services.list_bookmarks()
            settings = {}
            layout = {}
            if isinstance(user, dict):
                me = {"email": user.get("email") or user.get("username", ""), "username": user.get("username", ""), "user_id": user.get("user_id", "")}
            elif isinstance(user, str):
                me = {"email": user, "username": user, "user_id": ""}
            else:
                me = {"email": "", "username": "", "user_id": ""}
            payload = {"services": services, "bookmarks": bookmarks, "settings": settings, "layout": layout, "user": me}
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            etag = '"' + hashlib.md5(body.encode("utf-8")).hexdigest() + '"'
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                for k, v in _security_headers(self.path, self.headers.get("X-Forwarded-Proto") == "https"):
                    if k.lower() != "etag":
                        self.send_header(k, v)
                self.end_headers()
                return
            return self.send_bytes(body, 200, "application/json; charset=utf-8", extra_headers={"ETag": etag})
        # Supabase mode: fetch 3 resources in parallel
        token = user.get("supabase_token", "") if isinstance(user, dict) else ""
        results = {"services": None, "bookmarks": None, "settings_row": None}
        errors = {}
        lock = threading.Lock()

        def _fetch_services():
            try:
                rows = supa.list_services(token)
                with lock:
                    results["services"] = rows
            except Exception as e:
                with lock:
                    results["services"] = []
                    errors["services"] = str(e)

        def _fetch_bookmarks():
            try:
                rows = supa.list_bookmarks(token)
                with lock:
                    results["bookmarks"] = rows
            except Exception as e:
                with lock:
                    results["bookmarks"] = []
                    errors["bookmarks"] = str(e)

        def _fetch_settings():
            try:
                row = supa.get_settings(token)
                with lock:
                    results["settings_row"] = row
            except Exception as e:
                with lock:
                    results["settings_row"] = {}
                    errors["settings"] = str(e)

        threads = [
            threading.Thread(target=_fetch_services, daemon=True),
            threading.Thread(target=_fetch_bookmarks, daemon=True),
            threading.Thread(target=_fetch_settings, daemon=True),
        ]
        for t in threads:
            t.start()
        # Join with overall timeout 8s per thread (remaining budget)
        deadline = time.time() + 8.0
        for t in threads:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            t.join(timeout=remaining)
        svc_rows = results["services"] if isinstance(results["services"], list) else []
        bm_rows = results["bookmarks"] if isinstance(results["bookmarks"], list) else []
        row = results["settings_row"] if isinstance(results["settings_row"], dict) else {}
        services = [_from_db_service(r) for r in svc_rows] if isinstance(svc_rows, list) else []
        bookmarks = bm_rows
        # Sanitize settings like _handle_settings_get does: strip beszel password and 2FA secret for privacy?
        # Bootstrap keeps full settings/layout for client hydration but still strips secrets like settings GET does.
        settings_val = (row.get("settings") or {}) if isinstance(row, dict) else {}
        layout_val = (row.get("layout") or {}) if isinstance(row, dict) else {}
        if isinstance(settings_val, dict):
            # shallow copy to avoid mutating cached row
            settings_val = dict(settings_val)
            b = settings_val.get("beszel")
            if isinstance(b, dict) and "password" in b:
                b = dict(b)
                b["password"] = ""
                settings_val["beszel"] = b
            beszels = settings_val.get("beszels")
            if isinstance(beszels, list):
                nb = []
                for _b in beszels:
                    if isinstance(_b, dict) and "password" in _b:
                        _bb = dict(_b)
                        _bb["password"] = ""
                        nb.append(_bb)
                    else:
                        nb.append(_b if not isinstance(_b, dict) else dict(_b))
                settings_val["beszels"] = nb
            t = settings_val.get("twofa")
            if isinstance(t, dict):
                t = dict(t)
                t["secret"] = ""
                t["enabled"] = bool(t.get("enabled"))
                settings_val["twofa"] = t
        user_info = {"email": user.get("email", ""), "username": user.get("username", ""), "user_id": user.get("user_id", "")} if isinstance(user, dict) else {"email": str(user), "username": str(user), "user_id": ""}
        payload = {"services": services, "bookmarks": bookmarks, "settings": settings_val, "layout": layout_val, "user": user_info}
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        etag = '"' + hashlib.md5(body.encode("utf-8")).hexdigest() + '"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            for k, v in _security_headers(self.path, self.headers.get("X-Forwarded-Proto") == "https"):
                if k.lower() != "etag":
                    self.send_header(k, v)
            self.end_headers()
            return
        return self.send_bytes(body, 200, "application/json; charset=utf-8", extra_headers={"ETag": etag})

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
                # multi-beszel: blank each password
                beszels = row["settings"].get("beszels")
                if isinstance(beszels, list):
                    nb = []
                    for _b in beszels:
                        if isinstance(_b, dict) and "password" in _b:
                            _bb = dict(_b)
                            _bb["password"] = ""
                            nb.append(_bb)
                        else:
                            nb.append(_b if not isinstance(_b, dict) else dict(_b))
                    row["settings"]["beszels"] = nb
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
                if k in ("__proto__", "constructor", "prototype"):
                    continue
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
                elif k == "beszels" and isinstance(v, list):
                    # multi-instance: preserve password per id when blank + auto-fill empty name via Beszel fetch
                    cur_list = cur_settings.get("beszels") or []
                    cur_by_id = {str(e.get("id")): e for e in cur_list if isinstance(e, dict) and e.get("id")}
                    merged_list = []
                    for entry in v:
                        if not isinstance(entry, dict):
                            continue
                        eid = str(entry.get("id") or "")
                        cur_entry = cur_by_id.get(eid) if eid else None
                        e = dict(entry)
                        if cur_entry and not e.get("password"):
                            e["password"] = cur_entry.get("password", "")
                        # auto-fill empty name by fetching Beszel systems synchronously (try/except), fallback to URL host
                        if not str(e.get("name") or "").strip() and e.get("url") and e.get("user") and e.get("password"):
                            try:
                                _cfg = {"url": str(e.get("url") or "").strip().rstrip("/"), "user": str(e.get("user") or ""), "password": str(e.get("password") or "")}
                                ok, _ = _validate_beszel_url(_cfg["url"])
                                if not ok:
                                    raise RuntimeError("invalid beszel url")
                                systems = _beszel_systems(_cfg)
                                if systems and isinstance(systems, list) and len(systems) > 0:
                                    auto = systems[0].get("name") if isinstance(systems[0], dict) else None
                                    if auto and str(auto).strip():
                                        e["name"] = str(auto).strip()
                                    else:
                                        try:
                                            e["name"] = urllib.parse.urlparse(e["url"]).hostname or e["url"]
                                        except Exception:
                                            e["name"] = e["url"]
                                else:
                                    try:
                                        e["name"] = urllib.parse.urlparse(e["url"]).hostname or e["url"]
                                    except Exception:
                                        e["name"] = e["url"]
                            except Exception:
                                try:
                                    e["name"] = urllib.parse.urlparse(e["url"]).hostname or e["url"]
                                except Exception:
                                    e["name"] = e["url"]
                        merged_list.append(e)
                    settings["beszels"] = merged_list
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
        # Per-user Beszel credentials from settings (jsonb: {"beszel": {...}, "beszels": [...]}) .
        # Supports multi-instance (beszels array) with backward compat for single legacy beszel.
        # Always returns {enabled, systems} even when instances present; aggregated systems list.
        cfgs = []
        supa, user = self._supa()
        if supa is not None and user:
            try:
                row = supa.get_settings(user["supabase_token"])
                settings = (row or {}).get("settings", {}) or {}
                # new multi-instance
                beszels = settings.get("beszels")
                if isinstance(beszels, list) and beszels:
                    for entry in beszels:
                        if not isinstance(entry, dict):
                            continue
                        url = str(entry.get("url") or "").strip().rstrip("/")
                        if url:
                            cfgs.append({
                                "url": url,
                                "user": str(entry.get("user", "")),
                                "password": str(entry.get("password", "")),
                            })
                # legacy single fallback if no beszels
                if not cfgs:
                    beszel_cfg = settings.get("beszel") or {}
                    if isinstance(beszel_cfg, dict) and beszel_cfg.get("url"):
                        cfgs = [{
                            "url": str(beszel_cfg["url"]).rstrip("/"),
                            "user": str(beszel_cfg.get("user", "")),
                            "password": str(beszel_cfg.get("password", "")),
                        }]
            except Exception:
                cfgs = []
        # Single cfg backward-compat path (env fallback) when no user cfgs
        if not cfgs:
            env_cfg = read_beszel_env()
            if env_cfg and env_cfg.get("url"):
                _cfg_to_validate = env_cfg
                ok, err = _validate_beszel_url(_cfg_to_validate["url"])
                if not ok:
                    return self._api_error(400, err)
                try:
                    systems = _beszel_systems(env_cfg)
                except Exception as e:
                    detail = _beszel_format_error(e)
                    return self.send_bytes(
                        json.dumps({"enabled": True, "error": detail}), 200,
                        "application/json; charset=utf-8")
                if systems is None:
                    return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
                return self.send_bytes(
                    json.dumps({"enabled": True, "systems": systems}), 200,
                    "application/json; charset=utf-8")
            return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        # Multi-instance: validate each, aggregate systems
        # filter placeholder example hosts as disabled instances
        valid_cfgs = []
        for c in cfgs:
            ok, err = _validate_beszel_url(c["url"])
            if not ok:
                if "example" in err:
                    continue
                return self._api_error(400, err)
            valid_cfgs.append(c)
        if not valid_cfgs:
            return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        all_systems = []
        any_success = False
        last_error = None
        instances = []
        for c in valid_cfgs:
            try:
                systems = _beszel_systems(c)
                if systems is None:
                    systems = []
                all_systems.extend(systems)
                any_success = True
                instances.append({"url": c["url"], "systems": systems})
            except Exception as e:
                last_error = e
                detail = _beszel_format_error(e)
                instances.append({"url": c["url"], "error": detail, "systems": []})
        if any_success:
            return self.send_bytes(
                json.dumps({"enabled": True, "systems": all_systems, "instances": instances}), 200,
                "application/json; charset=utf-8")
        detail = _beszel_format_error(last_error) if last_error else "beszel unreachable"
        return self.send_bytes(
            json.dumps({"enabled": True, "error": detail, "systems": [], "instances": instances}), 200,
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
        # SSRF validation
        ok, err_msg = _validate_beszel_url(cfg["url"])
        if not ok:
            # keep example.com as enabled:false for backward compat, else 400
            if "example" in err_msg:
                return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
            return self._api_error(400, err_msg)
        try:
            systems = _beszel_systems(cfg)
        except Exception as e:
            detail = _beszel_format_error(e)
            return self.send_bytes(
                json.dumps({"enabled": True, "error": detail}), 200,
                "application/json; charset=utf-8")
        if systems is None:
            return self.send_bytes(json.dumps({"enabled": False}), 200, "application/json; charset=utf-8")
        return self.send_bytes(
            json.dumps({"enabled": True, "systems": systems}), 200,
            "application/json; charset=utf-8")

    def serve_file(self, rel):
        if not rel:
            return self.send_bytes("Not found", 404)
        # loop-decode percent-encoding until stable to prevent double-encoding traversals (max 3 iterations)
        decoded = rel
        for _ in range(3):
            nxt = urllib.parse.unquote(decoded)
            if nxt == decoded:
                break
            decoded = nxt
        rel = decoded
        if '\x00' in rel:
            return self.send_bytes("Forbidden", 403)
        rel = re.sub(r'/+', '/', rel.replace('\\','/'))
        # Resolve symlinks and enforce WEB_ROOT containment (reuse WEB_ROOT_REAL) — case-insensitive on Windows
        full = os.path.realpath(os.path.join(WEB_ROOT_REAL, rel))
        if os.path.normcase(full) != os.path.normcase(WEB_ROOT_REAL) and not os.path.normcase(full).startswith(os.path.normcase(WEB_ROOT_REAL)+os.path.normcase(os.sep)):
            return self.send_bytes("Forbidden", 403)
        if not os.path.isfile(full):
            return self.send_bytes("Not found", 404)
        # Block sensitive files even for authenticated users
        low_rel = rel.lower().replace("\\", "/")
        # block .env variants, services.json, supabase/, .git/, .vercel/ and sensitive extensions
        if low_rel == ".env" or low_rel.startswith(".env.") or "/.env" in low_rel or low_rel.endswith("/.env"):
            return self.send_bytes("Not found", 404)
        if low_rel == "services.json" or low_rel.endswith("/services.json"):
            return self.send_bytes("Not found", 404)
        parts = low_rel.split("/")
        if any(seg in ("supabase", ".git", ".vercel") for seg in parts):
            return self.send_bytes("Not found", 404)
        ext = os.path.splitext(full)[1].lower()
        if ext in (".py", ".sql", ".md", ".map", ".env"):
            return self.send_bytes("Not found", 404)
        if ext not in ALLOWED_STATIC:
            return self.send_bytes("Not found", 404)
        ctype = MIME.get(ext, "application/octet-stream")
        try:
            st = os.stat(full)
            etag = '"%x-%x"' % (int(st.st_mtime), st.st_size)
        except OSError:
            etag = None
        if etag and self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            if ext in (".html", ".htm"):
                self.send_header("Cache-Control", "no-cache")
            else:
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return
        with open(full, "rb") as f:
            body = f.read()
        headers = {}
        if etag:
            headers["ETag"] = etag
        if ext in (".html", ".htm"):
            headers["Cache-Control"] = "no-cache"
        else:
            headers["Cache-Control"] = "public, max-age=31536000, immutable"
        if ext == ".svg":
            headers["Content-Disposition"] = "inline"
        return self.send_bytes(body, 200, ctype, headers)

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
            if self._csrf_blocked():
                return self.send_bytes("forbidden", 403, "text/plain; charset=utf-8")
            user = self.session_user()
            if self.server.supabase is not None and user and user.get("supabase_token"):
                # Supabase tarafında refresh token'ları iptal et (best effort)
                try:
                    self.server.supabase.sign_out(user["supabase_token"])
                except Exception:
                    pass
            # clear both cookie names for backward compat
            _raw = self.read_cookie("__Host-hub_session") or self.read_cookie("hub_session")
            self.server.sessions.delete(_raw)
            # clear both hub_session and 2fa_pending with secure flags
            secure = "" if os.environ.get("HUB_INSECURE_HTTP") == "1" else "; Secure"
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            # clear session cookies (both names)
            self.send_header("Set-Cookie", "hub_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s" % secure)
            self.send_header("Set-Cookie", "__Host-hub_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s" % secure)
            self.send_header("Set-Cookie", "2fa_pending=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s" % secure)
            pending = getattr(self, "_pending_cookie", None)
            if pending:
                self.send_header("Set-Cookie", pending)
                self._pending_cookie = None
            self.end_headers()
            return
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
        if path == "/api/bootstrap":
            if not user:
                return self.send_bytes(json.dumps({"error": "unauthenticated"}), 401, "application/json; charset=utf-8")
            return self._handle_bootstrap()
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
        X-Forwarded-Host is NOT trusted (spoofable).
        """
        origin = self.headers.get("Origin")
        if origin:
            ref = self.headers.get("Host", "")
            try:
                o_host = urllib.parse.urlparse(origin).netloc
            except ValueError:
                return True
            if o_host and o_host != ref:
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
                # Validate email, username, password — specific errors to surface correct message
                if not _EMAIL_RE.match(email):
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=invalid_email")
                # Username: 3-20 chars, alphanumeric + underscore, not an email
                if not _USERNAME_RE.match(username):
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=invalid_username")
                if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
                    guard.record_failure(ip)
                    return self.redirect("/login?show=signup&error=weak_password")
                # Check username not already taken (use SECURITY DEFINER RPC to bypass RLS)
                try:
                    if self.server.supabase.username_exists(username):
                        guard.record_failure(ip)
                        return self.redirect("/login?show=signup&error=taken")
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
                    # Determine specific cause if Supabase gave a message
                    msg = str(signup_err).lower() if signup_err else ""
                    if "already" in msg or "exists" in msg or "taken" in msg or "duplicate" in msg:
                        return self.redirect("/login?show=signup&error=taken")
                    if "weak" in msg or "short" in msg or "password" in msg:
                        return self.redirect("/login?show=signup&error=weak_password")
                    # 422 = email taken / weak password / username taken; show specific where possible
                    return self.redirect("/login?show=signup&error=taken")
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
                pend_user = self.server.sessions.verify_pending(pending)
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
                uid = pend_user.get("user_id") or pend_user.get("email") or ip
                if self.server.sessions.totp_is_rate_limited(uid):
                    guard.record_failure(ip)
                    return self.redirect("/login?2fa=1&error=totp")
                if secret and totp_verify(secret, totp_code_val):
                    # per-user TOTP rate limit cleared on success
                    try:
                        self.server.sessions.totp_reset(uid)
                    except Exception:
                        pass
                    try:
                        self.server.sessions.burn_pending_jti(pend_user.get("_jti"), pend_user.get("_exp"))
                    except Exception:
                        pass
                    guard.reset(ip)
                    token = self.server.sessions.sign(pend_user)
                    # hub_session kur (Set-Cookie), 2fa_pending'i ayrı header ile sil
                    _sec = "" if os.environ.get("HUB_INSECURE_HTTP") == "1" else "; Secure"
                    self._pending_cookie = "2fa_pending=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s" % _sec
                    return self.redirect("/", {"Set-Cookie": self.session_cookie(token)})
                # Wrong or expired — keep pending but show error.
                try:
                    self.server.sessions.totp_record_failure(uid)
                except Exception:
                    pass
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
                pending = self.server.sessions.sign({**user, "typ": "pending"})
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
        """Short-lived cookie for the pending-2FA login step (5 min). Strict required."""
        secure = "" if os.environ.get("HUB_INSECURE_HTTP") == "1" else "; Secure"
        return "2fa_pending=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=300%s" % (token, secure)

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
