"""Read-only HTTP + SSE server for the Monitor v2 dashboard (Phase E2).

Every request passes through the same gate, in this exact order:

    1. socket peer address -> IP whitelist  (``/recovery`` is the ONLY exempt
       path pair, added by the recovery module)
    2. admin session cookie  (static shell + a tiny session-info endpoint are
       the only session-free responses, and they carry no traffic data)
    3. the route itself

Only the socket peer address is trusted; ``X-Forwarded-For`` / ``X-Real-IP``
are never read. The server is strictly read-only: there is no endpoint that
mutates sing-box state, creates/deletes clients, touches credentials or
reloads anything. All responses carry strict security headers and the
frontend is served from local static assets only (CSP ``default-src
'self'``, no CDN, no external fonts).
"""

from __future__ import annotations

import json
import sys
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MONITOR_WEB_VERSION = "0.1.0-e2"
SESSION_COOKIE = "monitor_session"
MAX_BODY_BYTES = 65536

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}

STATIC_ROUTES = {
    "/": "index.html",
    "/static/style.css": "style.css",
    "/static/app.js": "app.js",
    "/favicon.svg": "favicon.svg",
}

SECURITY_HEADERS = (
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
)


def normalize_path(raw_path):
    path = urlsplit(raw_path).path
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


class MonitorWebApp:
    """Wiring shared by all requests: broker + access policy + auth."""

    def __init__(self, broker, access, static_dir, auth=None,
                 remote_mode=False, version=MONITOR_WEB_VERSION):
        self.broker = broker
        self.access = access
        self.auth = auth
        self.static_dir = static_dir
        self.remote_mode = remote_mode
        self.version = version
        self._static_cache = {}

    def static_file(self, name):
        cached = self._static_cache.get(name)
        if cached is None:
            full = "%s/%s" % (self.static_dir, name) if self.static_dir else name
            try:
                with open(full, "rb") as handle:
                    cached = handle.read()
            except OSError:
                return None
            self._static_cache[name] = cached
        return cached

    def recovery_configured(self):
        # Replaced by the recovery module wiring (Phase E4 access flow).
        return False

    def session_from_token(self, token):
        if not self.auth or not token:
            return None
        return self.auth.sessions.resolve(token)


class MonitorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MonitorRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "singbox-monitor-web/" + MONITOR_WEB_VERSION

    # -- plumbing ------------------------------------------------------------

    @property
    def app(self):
        return self.server.app

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # Request line + status only: never headers, never bodies, so
        # passwords / session tokens / recovery keys cannot reach the log.
        sys.stderr.write("[monitor-web] %s %s\n"
                         % (self.client_address[0], format % args))

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        try:
            self._route(method)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - last-resort guard
            traceback.print_exc()
            try:
                self._send_json(500, {"error": "internal error"})
            except OSError:
                self.close_connection = True

    # -- routing ---------------------------------------------------------------

    def _route(self, method):
        path = normalize_path(self.path)
        remote = self.client_address[0]

        # Phase E4 exemption hook: the recovery flow is the single whitelist
        # exception (added by web/recovery.py wiring; empty in this commit).
        if self._recovery_route(method, path, remote):
            return

        if not self.app.access.is_allowed(remote):
            self._send_json(
                403, {"error": "forbidden: source address is not whitelisted"})
            return

        if method == "GET":
            self._route_get(path, remote)
            return
        if method == "POST":
            self._route_post(path, remote)
            return
        # PUT / DELETE: the dashboard has no mutation endpoints at all.
        self._send_json(404, {"error": "not found"})

    def _recovery_route(self, method, path, remote):
        return False  # replaced by the recovery module wiring

    def _route_get(self, path, remote):
        if path in STATIC_ROUTES:
            self._serve_static(STATIC_ROUTES[path])
            return
        if path == "/api/v1/session":
            self._handle_session_info(remote)
            return
        if path == "/api/v1/snapshot":
            self._require_session(self._handle_snapshot)
            return
        if path == "/api/v1/stream":
            self._require_session(self._handle_stream)
            return
        self._send_json(404, {"error": "not found"})

    def _route_post(self, path, remote):
        self._send_json(404, {"error": "not found"})

    # -- gates -----------------------------------------------------------------

    def _session_token(self):
        header = self.headers.get("Cookie")
        if not header:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:  # noqa: BLE001 - malformed cookie header
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _require_session(self, handler, *args):
        session = self.app.session_from_token(self._session_token())
        if session is None:
            self._send_json(401, {"error": "login required"})
            return
        handler(session, *args)

    # -- responses ---------------------------------------------------------------

    def _common_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        for name, value in (extra_headers or ()):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, name):
        body = self.app.static_file(name)
        if body is None:
            self._send_json(404, {"error": "not found"})
            return
        suffix = "." + name.rsplit(".", 1)[-1]
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES.get(suffix,
                                                          "text/plain"))
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

    # -- unauthenticated endpoints ---------------------------------------------

    def _handle_session_info(self, remote):
        session = self.app.session_from_token(self._session_token())
        self._send_json(200, {
            "authenticated": session is not None,
            "current_ip": remote,
            "whitelist_allowed": True,  # the request already passed the gate
            "password_configured": self.app.auth is not None
            and self.app.auth.password_configured(),
            "recovery_configured": self.app.recovery_configured(),
            "remote_mode": self.app.remote_mode,
            "version": self.app.version,
        })

    # -- session-gated endpoints -------------------------------------------------

    def _handle_snapshot(self, session):
        version, payload = self.app.broker.snapshot_json()
        if payload is None:
            self._send_json(503, {"error": "snapshot not ready"})
            return
        body = payload.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

    def _handle_stream(self, session):
        version, payload = self.app.broker.snapshot_json()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self._common_headers()
        self.end_headers()
        self.wfile.write(b"retry: 3000\n\n")
        self.wfile.flush()
        try:
            for _version, payload in self.app.broker.subscribe(
                    after_version=version):
                chunk = ("event: snapshot\ndata: %s\n\n" % payload).encode(
                    "utf-8")
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # browser went away; the collector never notices
        finally:
            self.close_connection = True


def build_server(app, host, port, tls_context=None):
    server = MonitorHTTPServer((host, port), MonitorRequestHandler)
    server.app = app
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server
