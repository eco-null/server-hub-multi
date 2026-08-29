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

_shared = hub_server.create_server(
    "127.0.0.1", int(os.environ.get("HUB_PORT", "8642")),
    user=os.environ.get("HUB_USER", "admin"),
    password=os.environ.get("HUB_PASSWORD", ""),
    supabase=_supa,
)


class _WrappedHandler(hub_server.HubHandler):
    """HubHandler pinned to the shared server instance."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("server", _shared)
        super().__init__(*args, **kwargs)


# Per-request capture state (set inside application()).
_capture = {"status": 200, "headers": [], "body": b""}

# Cold-start retry counter (per container, not per request).
_retried = {"once": False}


def _capture_send_response(status, message=None):
    _capture["status"] = status


def _capture_send_header(keyword, value):
    _capture["headers"].append((keyword, str(value)))


def _capture_end_headers():
    pass


class _CaptureBody(io.BytesIO):
    """Writes body bytes into _capture as well."""

    def write(self, data):
        _capture["body"] += data
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

    handler = _WrappedHandler.__new__(_WrappedHandler)
    handler.client_address = (environ.get("REMOTE_ADDR", "127.0.0.1"), 0)
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
    _capture["status"] = 200
    _capture["headers"] = []
    _capture["body"] = b""

    content_length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(content_length) if content_length > 0 else b""
    handler = _build_handler(environ, body)

    # Pin capture primitives onto this handler instance only.
    handler.send_response = _capture_send_response
    handler.send_header = _capture_send_header
    handler.end_headers = _capture_end_headers

    try:
        do_method = "do_" + environ.get("REQUEST_METHOD", "GET").upper()
        getattr(handler, do_method)()
    except Exception as e:
        # send_bytes already captured a status for handled errors; if the
        # process died before writing anything, report 500.
        import traceback
        sys.stderr.write("WSGI_EXC [%s %s]: %r\n" % (environ.get("REQUEST_METHOD"), environ.get("PATH_INFO"), e))
        traceback.print_exc(file=sys.stderr)
        # One automatic retry for transient serverless cold-start failures.
        # First request in a fresh container can hit Supabase before the
        # connection pool is warm — retrying once inside the same invocation
        # avoids a user-visible 500. Only for safe GET/HEAD paths.
        if environ.get("REQUEST_METHOD") in ("GET", "HEAD") and not _retried.get("once", False):
            _retried["once"] = True
            _capture["status"] = 200; _capture["headers"] = []; _capture["body"] = b""
            try:
                handler2 = _build_handler(environ, body)
                handler2.send_response = _capture_send_response
                handler2.send_header = _capture_send_header
                handler2.end_headers = _capture_end_headers
                getattr(handler2, do_method)()
            except Exception as e2:
                sys.stderr.write("WSGI_EXC2 [%s]: %r\n" % (environ.get("PATH_INFO"), e2))
                traceback.print_exc(file=sys.stderr)
        if _capture["status"] == 200 and not _capture["body"]:
            _capture["status"] = 500
            _capture["body"] = b'{"error":"internal"}'

    # Static fallback: Vercel static build'leri devre dışıysa (legacy builds
    # config'i) statik dosyaları WSGI üzerinden server.serve_file ile ver.
    # send_bytes zaten security headers içerir — yani CSP/nosniff/X-Frame
    # statik yanıtlarda da mevcut olur.
    if _capture["status"] == 200 and not _capture["body"] and environ.get("REQUEST_METHOD") == "GET":
        rel = (environ.get("PATH_INFO", "/") or "/").lstrip("/")
        if rel == "":
            rel = "index.html"
        # Sadece bilinen statik dosyalar (path traversal önleme server'da var)
        if os.path.isfile(os.path.join(hub_server.WEB_ROOT, rel)):
            try:
                handler.path = "/" + rel
                handler.wfile = _CaptureBody()
                handler.send_response = _capture_send_response
                handler.send_header = _capture_send_header
                handler.end_headers = _capture_end_headers
                handler.serve_file(rel)
            except Exception:
                if _capture["status"] == 200 and not _capture["body"]:
                    _capture["status"] = 404
                    _capture["body"] = b"Not found"
            if _capture["status"] == 200 and not _capture["body"]:
                _capture["status"] = 404
                _capture["body"] = b"Not found"

    # Logout/redirect set a Set-Cookie via extra_headers — captured. Static
    # file responses carry the body in handler.wfile (our capture) already.
    status_text = {
        200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
        403: "Forbidden", 404: "Not Found", 413: "Payload Too Large",
        500: "Internal Server Error",
    }.get(_capture["status"], "Server Error")

    headers = _capture["headers"]
    # Ensure a content-type and content-length (WSGI requires no framing, but
    # browsers do; send_bytes already set Content-Type/Length for API, and
    # for file bodies we add them here).
    header_keys = [k.lower() for k, _ in headers]
    if "content-length" not in header_keys:
        headers.append(("Content-Length", str(len(_capture["body"]))))
    if "content-type" not in header_keys:
        headers.append(("Content-Type", "text/html; charset=utf-8"))
    # Security headers (same as send_bytes).
    for k, v in [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Referrer-Policy", "no-referrer"),
    ]:
        if k.lower() not in header_keys:
            headers.append((k, v))

    start_response("%d %s" % (_capture["status"], status_text), headers)
    return [_capture["body"]]