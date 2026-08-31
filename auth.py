"""auth.py — Supabase Auth + Data REST bridge for Server Hub.

Zero third-party dependencies: pure urllib. Replaces the single-user
HUB_USER/HUB_PASSWORD auth with Supabase Auth (email + password, multi-user).

Env vars:
  SUPABASE_URL        e.g. https://xxxx.supabase.co
  SUPABASE_ANON_KEY   publishable anon key (RLS-scoped)

Architecture:
  Browser -> Server Hub (session cookie) -> Supabase Auth/Data REST
  The server holds the user's Supabase JWT in its session and proxies every
  data request with it, so PostgREST RLS (auth.uid()) applies per user.
"""

import json
import time
import urllib.error
import urllib.request

MAX_BODY = 64 * 1024


class SupabaseError(Exception):
    """Raised when Supabase returns an error. .status holds HTTP code."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class SupabaseClient:
    """Minimal Supabase Auth + PostgREST client (stdlib only)."""

    def __init__(self, url, anon_key, service_role_key=None):
        self.auth_url = url.rstrip("/") + "/auth/v1"
        self.rest_url = url.rstrip("/") + "/rest/v1"
        self.anon_key = anon_key
        self.service_role_key = service_role_key if service_role_key else None
        self._connect_timeout = 10

    # ---- HTTP helpers ----

    def _request(self, url, method="GET", body=None, token=None, headers=None):
        hdrs = {
            "apikey": self.anon_key,
            "Accept": "application/json",
        }
        if token:
            hdrs["Authorization"] = "Bearer " + token
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._connect_timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode("utf-8", "replace"))
            except Exception:
                detail = {"message": str(e)}
            finally:
                try:
                    e.close()
                except Exception:
                    pass
            raise SupabaseError(e.code, detail.get("message") or detail.get("error_description") or str(e)) from e
        except urllib.error.URLError as e:
            raise SupabaseError(502, str(e)) from e

    # ---- Auth ----

    def sign_in(self, email, password):
        """Email+password login. Returns session dict or raises SupabaseError."""
        return self._request(
            self.auth_url + "/token?grant_type=password",
            method="POST",
            body={"email": email, "password": password},
        )

    def refresh(self, refresh_token):
        """Exchange refresh_token for a fresh access token (serverless-safe)."""
        return self._request(
            self.auth_url + "/token?grant_type=refresh_token",
            method="POST",
            body={"refresh_token": refresh_token},
        )

    def sign_up(self, email, password, username=None):
        """Create account. Returns session dict (auto-confirmed or pending)."""
        body = {"email": email, "password": password}
        if username:
            body["data"] = {"username": username}
        return self._request(self.auth_url + "/signup", method="POST", body=body)

    def signup_bypass(self, email, password, username=None):
        """Bypass email rate limit: create user directly via SECURITY DEFINER RPC (auto-confirmed).
        Requires service_role key (anon revoked). No fallback to anon."""
        if not self.service_role_key:
            raise SupabaseError(500, "service_role_key not configured")
        try:
            res = self._request(
                self.rest_url + "/rpc/signup_bypass",
                method="POST",
                body={"email": email, "password": password, "username": username or ""},
                token=self.service_role_key,
                headers={"apikey": self.service_role_key},
            )
            # RPC returns json like {"id": "...", "email": "..."} or {"error": "..."}
            if isinstance(res, dict) and res.get("error"):
                raise SupabaseError(400, res["error"])
            return res
        except SupabaseError:
            raise
        except Exception as e:
            raise SupabaseError(500, str(e)) from e

    def admin_create_user(self, email, password, username=None):
        """Create user via service_role admin API (bypasses rate limit, auto-confirmed)."""
        if not self.service_role_key:
            raise SupabaseError(500, "service_role_key not configured")
        body = {"email": email, "password": password, "email_confirm": True}
        if username:
            body["user_metadata"] = {"username": username}
        return self._request(
            self.auth_url + "/admin/users",
            method="POST",
            body=body,
            token=self.service_role_key,
            headers={"apikey": self.service_role_key},
        )

    def get_email_by_username(self, username):
        """Resolve username -> email via SECURITY DEFINER RPC (for login with username).
        Uses service_role when available (anon revoked in DB), else anon."""
        try:
            _key = self.service_role_key if self.service_role_key else self.anon_key
            _token = self.service_role_key if self.service_role_key else None
            res = self._request(self.rest_url + "/rpc/get_email_by_username", method="POST", body={"uname": username}, token=_token, headers={"apikey": _key})
            if isinstance(res, str):
                return res
            if isinstance(res, dict) and "get_email_by_username" in res:
                return res["get_email_by_username"]
            return res
        except Exception:
            return None

    def username_exists(self, username):
        """Check if username exists (bypasses RLS). Uses service_role when available."""
        try:
            _key = self.service_role_key if self.service_role_key else self.anon_key
            _token = self.service_role_key if self.service_role_key else None
            res = self._request(self.rest_url + "/rpc/username_exists", method="POST", body={"uname": username}, token=_token, headers={"apikey": _key})
            if isinstance(res, bool):
                return res
            if isinstance(res, dict) and "username_exists" in res:
                return bool(res["username_exists"])
            return bool(res)
        except Exception:
            return False

    def list_users(self, page=1, per_page=50):
        """List users via admin API (requires service_role)."""
        return self._request(
            self.auth_url + f"/admin/users?page={page}&per_page={per_page}",
            method="GET",
            token=self.service_role_key,
            headers={"apikey": self.service_role_key},
        )

    def delete_user(self, user_id):
        """Delete user via admin API (requires service_role)."""
        return self._request(
            self.auth_url + f"/admin/users/{user_id}",
            method="DELETE",
            token=self.service_role_key,
            headers={"apikey": self.service_role_key},
        )

    def sign_out(self, token):
        """Invalidate the refresh token server-side (best effort)."""
        try:
            return self._request(
                self.auth_url + "/logout",
                method="POST",
                token=token,
                body={},
            )
        except SupabaseError:
            return None

    def get_user(self, token):
        """Fetch user object for a JWT access token."""
        return self._request(self.auth_url + "/user", token=token)

    # ---- Data (PostgREST, RLS enforced via user JWT) ----

    def select(self, table, token, query=""):
        return self._request(self.rest_url + "/" + table + (query or ""), method="GET", token=token)

    def insert(self, table, token, payload):
        return self._request(
            self.rest_url + "/" + table,
            method="POST",
            body=payload,
            token=token,
            headers={"Prefer": "return=representation"},
        )

    def update(self, table, token, payload, query=""):
        return self._request(
            self.rest_url + "/" + table + (query or ""),
            method="PATCH",
            body=payload,
            token=token,
            headers={"Prefer": "return=representation"},
        )

    def delete(self, table, token, query=""):
        return self._request(
            self.rest_url + "/" + table + (query or ""),
            method="DELETE",
            token=token,
            headers={"Prefer": "return=representation"},
        )

    # ---- domain helpers (server-hub) ----

    def list_services(self, token):
        return self.select("user_services", token, "?select=*&order=created_at")

    def list_bookmarks(self, token):
        return self.select("user_bookmarks", token, "?select=*&order=created_at")

    def get_settings(self, token):
        rows = self.select("user_settings", token, "?select=*&limit=1")
        if rows:
            return rows[0]
        return {"settings": {}, "layout": {}}

    def save_settings(self, token, settings=None, layout=None, user_id=None):
        payload = {"updated_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())}
        if settings is not None:
            payload["settings"] = settings
        if layout is not None:
            payload["layout"] = layout
        try:
            # PostgREST "UPDATE requires a WHERE clause" koruması: kendi satırını
            # id'yle hedefle. RLS zaten auth.uid()==user_id zorlar (güvenlik).
            where = ("?user_id=eq." + user_id) if user_id else ""
            rows = self.update("user_settings", token, payload, where)
            if rows:
                return rows
            # satır yok -> insert (trigger oluşturmadıysa; user_id biliniyorsa ekle)
            ins = dict(payload)
            if user_id:
                ins["user_id"] = user_id
            return self.insert("user_settings", token, ins)
        except SupabaseError as e:
            if e.status in (404, 406):
                # no row yet -> insert
                ins = dict(payload)
                if user_id:
                    ins["user_id"] = user_id
                return self.insert("user_settings", token, ins)
            raise

    def log(self, token, level, source, message, details=None, user_id=None):
        """Kullanıcıya özel hata/çakışma logu (sadece ERROR/WARN/CONFLICT).

        user_id payload'a eklenmeli: RLS insert policy
        ``with check (auth.uid() = user_id)`` yüzünden eksikse insert sessizce
        reddedilir.
        """
        if level not in ("ERROR", "WARN", "CONFLICT"):
            return None
        payload = {"level": level, "source": source, "message": message}
        if user_id:
            payload["user_id"] = user_id
        if details is not None:
            payload["details"] = details
        try:
            return self.insert("user_logs", token, payload)
        except SupabaseError:
            return None  # logging must never break the request

    def list_logs(self, token, limit=50):
        """Kullanıcının kendi loglarını listele (RLS filtreli)."""
        try:
            return self.select("user_logs", token, "?select=level,source,message,details,created_at&order=created_at.desc&limit=%d" % limit)
        except SupabaseError:
            return []