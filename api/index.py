"""api/index.py — Vercel Python runtime bridge for Server Hub.

Vercel Python Functions serve WSGI applications. Server Hub's core is a
stdlib http.server handler (HubHandler); this module adapts it to WSGI so the
*entire* existing server logic (auth, Supabase proxy, services, bookmarks,
settings, logs, stats, Beszel) runs unchanged on Vercel's serverless runtime.

Approach: monkey-patch the handler's HTTP response primitives
(send_response/send_header/end_headers) to capture status + headers into a
plain WSGI response, instead of trying to parse raw HTTP bytes.
"""

import io
import os
import sys
import threading

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import server as hub_server  # noqa: E402

_supa = None
_supa_url = os.environ.get("SUPABASE_URL", "")
_supa_key = os.environ.get("SUPABASE_ANON_KEY", "")
_supa_service = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "") or os.environ.get("SUPABASE_SERVICE_KEY", "")
if _supa_url and _supa_key:
    import auth  # noqa: E402
    _supa = auth.SupabaseClient(_supa_url, _supa_key, _supa_service or None)

# CRIT-05: catch SystemExit when HUB_PASSWORD empty and no Supabase URL
# (Vercel cold start would 500 on every request otherwise)
_shared = None
_shared_error = None
try:
    _shared = hub_server.create_server(
        "127.0.0.1", int(os.environ.get("HUB_PORT", "8642")),
        user=os.environ.get("HUB_USER", "admin"),
        password=os.environ.get("HUB_PASSWORD", ""),
        supabase=_supa,
    )
except SystemExit as e:
    _shared_error = str(e)
    _shared = None
except Exception as e:
    _shared_error = str(e)
    _shared = None


class _WrappedHandler(hub_server.HubHandler):
    """HubHandler pinned to the shared server instance."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("server", _shared)
        super().__init__(*args, **kwargs)


# CRIT-02: thread-safe capture via thread-local (was module-global dict)
_local = threading.local()

def _get_capture():
    return getattr(_local, "capture", None)

def _capture_send_response(status, message=None):
    cap = _get_capture()
    if cap is not None:
        cap["status"] = status


def _capture_send_header(keyword, value):
    cap = _get_capture()
    if cap is not None:
        cap["headers"].append((keyword, str(value)))


def _capture_end_headers():
    pass


class _CaptureBody(io.BytesIO):
    """Writes body bytes into thread-local capture."""

    def write(self, data):
        cap = _get_capture()
        if cap is not None:
            cap["body"] += data
        return len(data) if hasattr(data, "__len__") else 0


def _build_handler(environ, body):
    method = environ.get("REQUEST_METHOD", "GET")
    path_qs = environ.get("PATH_INFO", "/")
    qs = environ.get("QUERY_STRING", "")
    if qs:
        path_qs += "?" + qs

    headers = {"Host": environ.get("HTTP_HOST", "localhost")}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers[key[5:].replace("_", "-").title()] = value
    if "CONTENT_TYPE" in environ:
        headers["Content-Type"] = environ["CONTENT_TYPE"]
    # CRIT-01: forward Content-Length so HubHandler.do_POST reads body correctly
    # WSGI provides CONTENT_LENGTH separately; without this header handler reads 0 bytes.
    clen = environ.get("CONTENT_LENGTH")
    if clen is not None and str(clen).strip() != "":
        headers["Content-Length"] = str(clen)
    elif body:
        headers["Content-Length"] = str(len(body))
    else:
        headers["Content-Length"] = "0"

    # XFF spoof fix: same logic as HubHandler.client_ip
    _remote = environ.get("REMOTE_ADDR", "127.0.0.1")
    _client_ip = _remote
    if os.environ.get("VERCEL") == "1":
        # Prefer X-Vercel-Forwarded-For
        _xvf = headers.get("X-Vercel-Forwarded-For", "") or environ.get("HTTP_X_VERCEL_FORWARDED_FOR", "")
        if _xvf:
            _parts = [p.strip() for p in _xvf.split(",") if p.strip()]
            if _parts:
                _client_ip = _parts[-1]
        else:
            _xff = headers.get("X-Forwarded-For", "") or environ.get("HTTP_X_FORWARDED_FOR", "")
            if _xff:
                _parts = [p.strip() for p in _xff.split(",") if p.strip()]
                if _parts:
                    _client_ip = _parts[-1]
            else:
                _xri = headers.get("X-Real-Ip", "") or headers.get("X-Real-IP", "") or environ.get("HTTP_X_REAL_IP", "")
                if _xri:
                    _client_ip = _xri.strip()
    else:
        _client_ip = _remote
    handler = _WrappedHandler.__new__(_WrappedHandler)
    handler.client_address = (_client_ip, 0)
    handler.command = method
    handler.path = path_qs
    handler.request_version = "HTTP/1.1"
    handler.requestline = "%s %s HTTP/1.1" % (method, path_qs)
    handler.close_connection = True
    handler.headers = type("H", (), {
        "get": lambda self, k, d=None: headers.get(k, d),
        "items": lambda self: headers.items(),
    })()
    handler.rfile = io.BytesIO(body)
    handler.wfile = _CaptureBody()
    handler.server = _shared
    handler.connection = None
    handler.request = None
    return handler


def application(environ, start_response):
    # CRIT-05: if shared failed to init, return generic 500 config error (no leak)
    if _shared is None:
        body = b'{"error":"configuration error"}'
        start_response("500 Internal Server Error", [("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "SAMEORIGIN"), ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'self'"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()")])
        return [body]

    # CRIT-02: per-request capture (thread-local) + per-request retry flag
    _local.capture = {"status": 200, "headers": [], "body": b""}
    capture = _local.capture
    retried = False

    try:
        content_length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        content_length = 0
    # Body size DoS protection: cap before reading wsgi.input
    max_body = getattr(hub_server, "MAX_API_BODY", 64*1024)
    # login/register uses MAX_LOGIN_BODY (same size)
    try:
        max_login = getattr(hub_server, "MAX_LOGIN_BODY", 64*1024)
        max_body = max(max_body, max_login)
    except Exception:
        pass
    if content_length < 0:
        content_length = 0
    if content_length > max_body:
        body_err = b'{"error":"payload too large"}'
        start_response("413 Payload Too Large", [("Content-Type", "application/json"), ("Content-Length", str(len(body_err)))])
        return [body_err]
    # Also guard against missing CONTENT_LENGTH but huge chunked body: read exactly content_length
    if content_length > 0:
        body = environ["wsgi.input"].read(content_length)
        if len(body) > max_body:
            body_err = b'{"error":"payload too large"}'
            start_response("413 Payload Too Large", [("Content-Type", "application/json"), ("Content-Length", str(len(body_err)))])
            return [body_err]
    else:
        body = b""
    handler = _build_handler(environ, body)

    # Pin capture primitives onto this handler instance only.
    handler.send_response = _capture_send_response
    handler.send_header = _capture_send_header
    handler.end_headers = _capture_end_headers

    try:
        do_method = "do_" + environ.get("REQUEST_METHOD", "GET").upper()
        getattr(handler, do_method)()
    except Exception as e:
        import traceback
        sys.stderr.write("WSGI_EXC [%s %s]: %r\n" % (environ.get("REQUEST_METHOD"), environ.get("PATH_INFO"), e))
        traceback.print_exc(file=sys.stderr)
        # One automatic retry for transient serverless cold-start failures.
        # First request in a fresh container can hit Supabase before the
        # connection pool is warm — retrying once inside the same invocation
        # avoids a user-visible 500. Only for safe GET/HEAD paths, per-request.
        if environ.get("REQUEST_METHOD") in ("GET", "HEAD") and not retried:
            retried = True
            _local.capture = {"status": 200, "headers": [], "body": b""}
            capture = _local.capture
            try:
                handler2 = _build_handler(environ, body)
                handler2.send_response = _capture_send_response
                handler2.send_header = _capture_send_header
                handler2.end_headers = _capture_end_headers
                getattr(handler2, do_method)()
                capture = _local.capture
            except Exception as e2:
                sys.stderr.write("WSGI_EXC2 [%s]: %r\n" % (environ.get("PATH_INFO"), e2))
                traceback.print_exc(file=sys.stderr)
        cap = _get_capture()
        if cap and cap["status"] == 200 and not cap["body"]:
            cap["status"] = 500
            cap["body"] = b'{"error":"internal"}'
            capture = cap

    # Static fallback: only serve if authenticated (reuse HubHandler auth), else 302 to /login. Public assets allowed without session.
    capture = _get_capture()
    if capture and capture["status"] == 200 and not capture["body"] and environ.get("REQUEST_METHOD") == "GET":
        _path_info = environ.get("PATH_INFO", "/") or "/"
        _ext_pub = os.path.splitext(_path_info)[1].lower()
        _is_public = _ext_pub in (".png", ".svg", ".ico", ".gif", ".jpg", ".jpeg", ".webp", ".js", ".css", ".woff", ".woff2")
        _auth_user = handler.session_user() if _shared is not None else None
        if not _auth_user and not _is_public:
            _local.capture = {"status": 302, "headers": [("Location", "/login")], "body": b""}
        else:
            rel = _path_info.lstrip("/")
            if rel == "":
                rel = "index.html"
            if os.path.isfile(os.path.join(hub_server.WEB_ROOT, rel)):
                try:
                    handler.path = "/" + rel
                    handler.wfile = _CaptureBody()
                    handler.send_response = _capture_send_response
                    handler.send_header = _capture_send_header
                    handler.end_headers = _capture_end_headers
                    handler.serve_file(rel)
                    capture = _get_capture()
                except Exception:
                    cap = _get_capture()
                    if cap and cap["status"] == 200 and not cap["body"]:
                        cap["status"] = 404
                        cap["body"] = b"Not found"
                cap = _get_capture()
                if cap and cap["status"] == 200 and not cap["body"]:
                    cap["status"] = 404
                    cap["body"] = b"Not found"

    capture = _get_capture() or {"status": 500, "headers": [], "body": b'{"error":"internal"}'}
    status_text = {
        200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
        403: "Forbidden", 404: "Not Found", 413: "Payload Too Large",
        500: "Internal Server Error",
    }.get(capture["status"], "Server Error")

    headers = capture["headers"]
    header_keys = [k.lower() for k, _ in headers]
    if "content-length" not in header_keys:
        headers.append(("Content-Length", str(len(capture["body"]))))
    if "content-type" not in header_keys:
        headers.append(("Content-Type", "text/html; charset=utf-8"))
    for k, v in [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'self'"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ]:
        if k.lower() not in header_keys:
            headers.append((k, v))
    # Cache-Control no-store for /api/*
    _p = environ.get("PATH_INFO", "") or ""
    if _p.startswith("/api/") and "cache-control" not in header_keys:
        headers.append(("Cache-Control", "no-store"))
    # HSTS when behind https proxy
    if environ.get("HTTP_X_FORWARDED_PROTO") == "https" and "strict-transport-security" not in header_keys:
        headers.append(("Strict-Transport-Security", "max-age=63072000"))

    start_response("%d %s" % (capture["status"], status_text), headers)
    return [capture["body"]]
