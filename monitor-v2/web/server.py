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

import hmac
import json
import sys
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from web.access import host_entry_for_ip
from web.recovery import (RECOVERY_SUCCESS_MESSAGE, RecoveryGlobalGuard,
                          RecoveryRateLimiter, generate_key)

MONITOR_WEB_VERSION = "0.1.0-e2"
SESSION_COOKIE = "monitor_session"
MAX_BODY_BYTES = 65536
SUPPORTED_METHODS = "GET, POST"

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
                 remote_mode=False, version=MONITOR_WEB_VERSION,
                 recovery_guard=None):
        self.broker = broker
        self.access = access
        self.auth = auth
        self.static_dir = static_dir
        self.remote_mode = remote_mode
        self.version = version
        self.recovery_limiter = RecoveryRateLimiter()
        self.recovery_guard = recovery_guard or RecoveryGlobalGuard()
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
        return self.auth is not None and self.auth.recovery_configured()

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

    # The dashboard implements exactly GET and POST. Everything else --
    # including methods a future phase might want (E3 DELETE) -- is
    # uniformly rejected NOW instead of drifting into accidental surface.
    def do_PUT(self):
        self._method_not_allowed()

    do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = do_PUT

    def _method_not_allowed(self):
        # Uniform surface: 405 + Allow, and never reuse a connection whose
        # method semantics (or body framing) we did not interpret.
        self.close_connection = True
        body = json.dumps({"error": "method not allowed"}).encode("utf-8")
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.send_header("Allow", SUPPORTED_METHODS)
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

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
        """The recovery flow is the SINGLE whitelist exception.

        It is an EXACT allowlist (never a wildcard): the recovery shell plus
        the minimal asset set that shell needs to render and submit, and the
        recovery API itself. These static files are the public app shell --
        they contain no snapshot data, no whitelist content, no session and
        no credentials. Everything else stays behind the whitelist gate:
        GET / and /api/v1/* still answer 403 to a locked-out caller.
        """
        if method == "GET" and path in (
                "/recovery", "/static/style.css", "/static/app.js",
                "/favicon.svg"):
            self._serve_static(STATIC_ROUTES.get(path, "index.html"))
            return True
        if method == "POST" and path == "/api/v1/recovery":
            self._handle_recovery(remote)
            return True
        return False

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
        if path == "/api/v1/whitelist":
            self._require_session(self._handle_whitelist_get, remote)
            return
        self._send_json(404, {"error": "not found"})

    def _body_header_error(self):
        """(status, message) when request body headers are unacceptable.

        A malformed Content-Length is a 400, never a silent 0; an oversized
        body is a 413; chunked bodies are unsupported. In all three cases
        the connection is closed afterwards -- the body length is not
        trusted for skipping.
        """
        if self.headers.get("Transfer-Encoding"):
            return 400, "Transfer-Encoding is not supported"
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            length = int(raw)
        except (TypeError, ValueError):
            return 400, "malformed Content-Length"
        if length < 0:
            return 400, "malformed Content-Length"
        if length > MAX_BODY_BYTES:
            return 413, "request body too large"
        return None

    def _route_post(self, path, remote):
        error = self._body_header_error()
        if error is not None:
            self.close_connection = True  # body length untrusted: no reuse
            self._send_json(error[0], {"error": error[1]})
            return
        if self._cross_origin():
            self._send_json(403, {"error": "cross-origin request rejected"})
            return
        if path == "/api/v1/login":
            self._handle_login(remote)
            return
        if path == "/api/v1/logout":
            self._require_session(self._handle_logout, csrf=True)
            return
        if path == "/api/v1/password":
            self._require_session(self._handle_password, remote, csrf=True)
            return
        if path == "/api/v1/whitelist":
            self._require_session(self._handle_whitelist_add, remote,
                                  csrf=True)
            return
        if path == "/api/v1/whitelist/remove":
            self._require_session(self._handle_whitelist_remove, remote,
                                  csrf=True)
            return
        if path == "/api/v1/recovery/rotate":
            self._require_session(self._handle_recovery_rotate, csrf=True)
            return
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

    def _body_length(self):
        try:
            return int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return 0

    def _drain_body(self):
        """Consume any unread request body so it is never mistaken for a
        pipelined request (an early 403/401 must not leave bytes behind).

        A request whose body had to be DRAINED rather than parsed also
        loses its keep-alive: we never reuse a connection after bytes we
        did not explicitly interpret. This deterministically rules out
        request-smuggling through leftover body fragments -- a locked-out
        caller's connection is worth nothing, the next request simply
        opens a new one."""
        if self.command not in ("POST", "PUT", "DELETE"):
            return
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True  # chunked bodies are not supported
            return
        length = self._body_length()
        remaining = length - getattr(self, "_consumed", 0)
        if remaining <= 0:
            return
        self.close_connection = True  # drained, not parsed: no reuse
        if remaining > MAX_BODY_BYTES:
            return  # absurd body: close without buffering it
        try:
            self.rfile.read(remaining)
        except OSError:
            pass
        self._consumed = length

    def _json_body(self):
        """Read a bounded JSON object body; None on anything malformed."""
        length = self._body_length()
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        finally:
            self._consumed = length
        return data if isinstance(data, dict) else None

    def _require_session(self, handler, *args, csrf=False):
        """Resolve the session; for mutations also enforce the session-bound
        CSRF token (primary defence) and the same-origin check (second
        layer). The session cookie stays HttpOnly; the CSRF token is the
        only one of the pair the browser scripting context may hold."""
        session = self.app.session_from_token(self._session_token())
        if session is None:
            self._send_json(401, {"error": "login required"})
            return
        if csrf:
            supplied = self.headers.get("X-CSRF-Token")
            expected = session.get("csrf_token", "")
            if not isinstance(supplied, str) or \
                    not hmac.compare_digest(supplied, expected):
                self._send_json(403,
                                {"error": "missing or invalid CSRF token"})
                return
        handler(session, *args)

    def _cross_origin(self):
        """True when the browser declared a foreign Origin (second CSRF
        layer). Tools that send no Origin are NOT affected here -- they
        still face the CSRF-token contract above."""
        origin = self.headers.get("Origin")
        if not origin:
            return False
        host = self.headers.get("Host", "")
        scheme = getattr(self.server, "scheme", "http")
        return origin.rstrip("/") != ("%s://%s" % (scheme, host)).rstrip("/")

    # -- responses ---------------------------------------------------------------

    def _common_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, status, payload, extra_headers=None):
        self._drain_body()
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
        payload = {
            "authenticated": session is not None,
            "current_ip": remote,
            "whitelist_allowed": True,  # the request already passed the gate
            "password_configured": self.app.auth is not None
            and self.app.auth.password_configured(),
            "recovery_configured": self.app.recovery_configured(),
            "remote_mode": self.app.remote_mode,
            "version": self.app.version,
        }
        if session is not None:
            # The CSRF half of the session: safe to expose to the page's own
            # scripting context, unlike the HttpOnly session cookie.
            payload["csrf_token"] = session.get("csrf_token")
        self._send_json(200, payload)

    def _handle_login(self, remote):
        """POST /api/v1/login {password} -> session cookie.

        Rate limited per source IP; the password itself is never logged and
        never echoed back anywhere.
        """
        auth = self.app.auth
        if auth is None or not auth.password_configured():
            self._send_json(503, {"error": "authentication not configured"})
            return
        body = self._json_body()
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str):
            self._send_json(400, {"error": "password required"})
            return
        allowed, retry_after = auth.login_limiter.check(remote)
        if not allowed:
            self._send_json(
                429,
                {"error": "too many failed attempts; try again later",
                 "retry_after": retry_after},
                extra_headers=[("Retry-After", str(retry_after))])
            return
        if not auth.verify_password(password):
            auth.login_limiter.record_failure(remote)
            self._send_json(401, {"error": "invalid password"})
            return
        auth.login_limiter.record_success(remote)
        token = auth.sessions.create()
        self._send_json(200, {"status": "ok"},
                        extra_headers=[("Set-Cookie",
                                        self._session_cookie(
                                            token, int(auth.sessions.ttl)))])

    def _session_cookie(self, value, max_age):
        """Session cookie header with the mode-appropriate Secure flag.

        Remote mode (and any TLS listener) is HTTPS-only, so Secure is
        mandatory there. On a loopback HTTP listener Secure is deliberately
        omitted: browsers differ in whether they accept Secure cookies over
        plain http://localhost, the loopback canary must work in all of
        them, and a loopback-only listener never touches a network.
        """
        parts = ["%s=%s" % (SESSION_COOKIE, value), "Path=/",
                 "Max-Age=%d" % max_age, "HttpOnly", "SameSite=Strict"]
        if self.app.remote_mode or \
                getattr(self.server, "scheme", "http") == "https":
            parts.append("Secure")
        return "; ".join(parts)

    # -- recovery flow -----------------------------------------------------------

    def _handle_recovery(self, remote):
        """POST /api/v1/recovery {key} -> add the CALLER's IP, nothing more.

        No session is created; the dashboard and the whitelist stay
        invisible; the target of the whitelist add is always the real
        socket peer address, never a client-supplied value.
        """
        auth = self.app.auth
        if auth is None or not auth.recovery_configured():
            # Uniform generic refusal: never reveal whether recovery is
            # configured, and never distinguish hash states on failure.
            self._send_json(403, {"error": "invalid recovery key"})
            return
        body = self._json_body()
        key = body.get("key") if isinstance(body, dict) else None
        if not isinstance(key, str) or not key:
            self._send_json(400, {"error": "recovery key required"})
            return
        limiter = self.app.recovery_limiter
        allowed, retry_after = limiter.check(remote)
        if not allowed:
            self._send_json(
                429, {"error": "too many failed recovery attempts; try "
                               "again later", "retry_after": retry_after},
                extra_headers=[("Retry-After", str(retry_after))])
            return
        # Global budget (all source addresses): rolling-window attempt cap
        # plus scrypt concurrency cap. A rejected caller consumes NO scrypt
        # work -- the guard is checked before any verification happens.
        acquired, guard_retry = self.app.recovery_guard.try_acquire()
        if not acquired:
            self._send_json(
                429, {"error": "recovery verification is busy; try again "
                               "later", "retry_after": guard_retry},
                extra_headers=[("Retry-After", str(guard_retry))])
            return
        try:
            if not auth.verify_recovery_key(key):
                limiter.record_failure(remote)
                self._send_json(403, {"error": "invalid recovery key"})
                return
            limiter.record_success(remote)
            entry = host_entry_for_ip(remote)
            self.app.access.add(entry)
            self._send_json(
                200, {"status": "ok", "ip": remote, "entry": entry,
                      "message": RECOVERY_SUCCESS_MESSAGE})
        finally:
            self.app.recovery_guard.release()

    def _handle_recovery_rotate(self, session):
        """POST /api/v1/recovery/rotate {current_password} -> new key once."""
        auth = self.app.auth
        body = self._json_body()
        current = body.get("current_password") \
            if isinstance(body, dict) else None
        if not isinstance(current, str):
            self._send_json(400, {"error": "current_password required"})
            return
        remote = self.client_address[0]
        allowed, retry_after = auth.login_limiter.check(remote)
        if not allowed:
            self._send_json(429, {"error": "try again later"})
            return
        if not auth.verify_password(current):
            auth.login_limiter.record_failure(remote)
            self._send_json(403, {"error": "current password is wrong"})
            return
        auth.login_limiter.record_success(remote)
        key = generate_key()
        auth.set_recovery_key(key)
        # shown exactly once, in this response; only a hash is stored
        self._send_json(200, {"status": "ok", "recovery_key": key})

    # -- session-gated endpoints -------------------------------------------------

    def _handle_logout(self, session):
        token = self._session_token()
        if self.app.auth is not None and token:
            self.app.auth.sessions.drop(token)
        self._send_json(200, {"status": "ok"},
                        extra_headers=[("Set-Cookie",
                                        self._session_cookie("", 0))])

    def _handle_password(self, session, remote):
        """POST /api/v1/password {current_password, new_password}."""
        auth = self.app.auth
        body = self._json_body()
        if not isinstance(body, dict):
            self._send_json(400, {"error": "invalid request body"})
            return
        current = body.get("current_password")
        new = body.get("new_password")
        if not isinstance(current, str) or not isinstance(new, str):
            self._send_json(400, {"error": "current_password and "
                                           "new_password required"})
            return
        allowed, retry_after = auth.login_limiter.check(remote)
        if not allowed:
            self._send_json(429, {"error": "try again later"})
            return
        if not auth.verify_password(current):
            auth.login_limiter.record_failure(remote)
            self._send_json(403, {"error": "current password is wrong"})
            return
        auth.login_limiter.record_success(remote)
        try:
            auth.set_password(new, keep_session=self._session_token())
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, {"status": "ok"})

    def _handle_whitelist_get(self, session, remote):
        self._send_json(200, {
            "whitelist": list(self.app.access.entries()),
            "current_ip": remote,
        })

    def _handle_whitelist_add(self, session, remote):
        body = self._json_body()
        entry = body.get("entry") if isinstance(body, dict) else None
        if not isinstance(entry, str):
            self._send_json(400, {"error": "entry required"})
            return
        try:
            canonical = self.app.access.add(entry)
        except ValueError:
            self._send_json(400, {"error": "invalid IP or CIDR entry"})
            return
        self._send_json(200, {"status": "ok", "entry": canonical,
                              "whitelist": list(self.app.access.entries())})

    def _handle_whitelist_remove(self, session, remote):
        body = self._json_body()
        entry = body.get("entry") if isinstance(body, dict) else None
        if not isinstance(entry, str):
            self._send_json(400, {"error": "entry required"})
            return
        if self.app.access.covers(entry, remote) and body.get("confirm") is not True:
            self._send_json(
                409,
                {"error": "confirm required: removing your current IP will "
                          "lock this browser out; the recovery key will be "
                          "required"})
            return
        if not self.app.access.remove(entry):
            self._send_json(404, {"error": "entry not found"})
            return
        self._send_json(200, {"status": "ok",
                              "whitelist": list(self.app.access.entries())})

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
    server.scheme = "https" if tls_context is not None else "http"
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server
