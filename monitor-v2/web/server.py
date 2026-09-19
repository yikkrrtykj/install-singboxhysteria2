"""Read-only HTTP + SSE server for the Monitor v2 dashboard (Phase E2).

Every request passes through the same gate, in this exact order:

    1. socket peer address -> IP whitelist  (``/recovery`` is the ONLY exempt
       path pair, added by the recovery module)
    2. admin session cookie  (static shell + a tiny session-info endpoint are
       the only session-free responses, and they carry no traffic data)
    3. the route itself

Only the socket peer address is trusted; ``X-Forwarded-For`` / ``X-Real-IP``
are never read. The server is strictly read-only with respect to sing-box:
there is no endpoint that mutates sing-box state, creates/deletes clients,
touches credentials or reloads anything. All responses carry strict security
headers and the frontend is served from local static assets only (CSP
``default-src 'self'``, no CDN, no external fonts).

M0.5 adds the **step-up authorization boundary** (rev5 §5, G3): four
privileged mutation routes exist so the gate can be exercised, but the
privileged backend itself is a later milestone (M1/M2). Each of them is
therefore terminated with an explicit 501 AFTER the full authorization
chain (session -> CSRF -> step-up) has been satisfied. No marker, no config,
no sing-box state is ever touched by this module.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import re
import sys
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from web.access import host_entry_for_ip
from web.e3_broker import BrokerUnavailable
from web.e3rpc import RpcTransportError
from web.recovery import (RECOVERY_SUCCESS_MESSAGE, RecoveryGlobalGuard,
                          RecoveryRateLimiter, generate_key)

MONITOR_WEB_VERSION = "0.1.0-m0.5"
SESSION_COOKIE = "monitor_session"
MAX_BODY_BYTES = 65536
SUPPORTED_METHODS = "GET, POST"

# The four privileged mutation routes of rev5 §7. M0.5 delivered them as a
# 501 boundary; M2 wires them to the sbox-cm RPC adapter (below). The
# authentication boundary above them is UNCHANGED: session -> CSRF -> step-up,
# and a 401 reauth_required still precedes everything else.
MUTATION_ROUTES = {
    "/api/v1/management/activate": "management.activate",
    "/api/v1/management/deactivate": "management.deactivate",
    "/api/v1/clients/add": "client.add",
    "/api/v1/clients/delete": "client.delete",
}

# ---------------------------------------------------------------- M2 adapter --
# Validation mirrors the helper's own schema (sbox-cm OPS table): the web
# layer is the FIRST of the two defences, the helper re-validates in-lock.
E3_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
E3_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
E3_RESERVED_NAME = "legacy"
IDEMPOTENCY_HEADER = "Idempotency-Key"

# Helper error code -> HTTP status (rev5 §2.6, the authoritative table). The
# code, stage and retriable flag pass through; error.backup NEVER does (it is
# a root-side backup path inside the proxy tree, exactly like lock.path).
E3_ERROR_HTTP = {
    "E_SCHEMA": 400, "E_OP_UNKNOWN": 400, "E_PEER_AUTH": 403,
    "E_RESERVED_NAME": 403, "E_LOCK": 423, "E_DUPLICATE_NAME": 409,
    "E_NOT_FOUND": 404, "E_CONFIG_INCONSISTENT": 409,
    "E_IDEMPOTENCY_CONFLICT": 409, "E_RECONCILE_CONFLICT": 409,
    "E_LEDGER_UNAVAILABLE": 503, "E_STATE_UNCERTAIN": 503,
    "E_CANDIDATE_REJECTED": 500, "E_COMMIT_FAILED": 500,
    "E_ROLLED_BACK": 503, "E_MANUAL_INTERVENTION": 500,
    "E_ACTIVATION_STATE": 409, "E_TIMEOUT": 504, "E_INTERNAL": 500,
}

# Deny-by-default response whitelist (design §9). Helper fields not listed
# here never reach the browser -- including any field the helper grows later.
E3_DATA_WHITELIST = {
    "management.status": ("management_state", "management_active",
                          "helper", "lock", "last_transaction"),
    "client.list": ("clients", "truncated"),
    "client.add": ("name", "protocols", "mutable", "source",
                   "yaml_available", "credential_delivery", "warnings"),
    "client.delete": ("deleted", "derived_cleanup", "warnings"),
    "management.activate": ("management_state", "no_op"),
    "management.deactivate": ("management_state", "no_op"),
}
E3_STATUS_HELPER_KEYS = ("degraded", "reconcile")
E3_STATUS_LOCK_KEYS = ("acquirable",)
E3_LAST_TX_KEYS = ("generation", "op", "outcome", "ended_at")
E3_CLIENT_KEYS = ("name", "protocols", "reserved", "mutable", "source")

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


def iso_utc(epoch):
    """Epoch seconds -> ISO-8601 UTC (``...Z``); None stays None."""
    if epoch is None:
        return None
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_e3_data(op, data):
    """Deny-by-default whitelist of a helper ``data`` payload (M2 §9)."""
    allowed = E3_DATA_WHITELIST.get(op, ())
    if not isinstance(data, dict):
        return {}
    out = {}
    for key in allowed:
        if key not in data:
            continue
        value = data[key]
        if key == "helper" and isinstance(value, dict):
            value = {k: value[k] for k in E3_STATUS_HELPER_KEYS
                     if k in value}
        elif key == "lock" and isinstance(value, dict):
            # lock.path names a root-side lock file inside the proxy tree:
            # it must never leave this process
            value = {k: value[k] for k in E3_STATUS_LOCK_KEYS
                     if k in value}
        elif key == "last_transaction" and isinstance(value, dict):
            value = {k: value[k] for k in E3_LAST_TX_KEYS if k in value}
        elif key == "clients" and isinstance(value, list):
            value = [{k: c[k] for k in E3_CLIENT_KEYS if k in c}
                     for c in value if isinstance(c, dict)]
        out[key] = value
    return out


def sanitize_e3_idempotency(idem):
    if not isinstance(idem, dict):
        return None
    out = {}
    for key in ("key_fp", "replayed", "generation"):
        if key in idem:
            out[key] = idem[key]
    return out or None


def sanitize_e3_error(verdict):
    """{code, stage, retriable, detail} from a failed helper verdict.
    ``backup`` is deliberately dropped (a root-side backup path)."""
    err = verdict.get("error") if isinstance(verdict.get("error"), dict) \
        else {}
    return {"code": err.get("code") or "E_INTERNAL",
            "stage": err.get("stage"),
            "retriable": bool(err.get("retriable")),
            "error": err.get("detail") or err.get("code") or "E_INTERNAL"}


class MonitorWebApp:
    """Wiring shared by all requests: broker + access policy + auth."""

    def __init__(self, broker, access, static_dir, auth=None,
                 remote_mode=False, version=MONITOR_WEB_VERSION,
                 recovery_guard=None, management_active=None, e3_broker=None):
        self.broker = broker
        self.access = access
        self.auth = auth
        self.static_dir = static_dir
        self.remote_mode = remote_mode
        self.version = version
        self.recovery_limiter = RecoveryRateLimiter()
        self.recovery_guard = recovery_guard or RecoveryGlobalGuard()
        # ``management_active`` is an ORTHOGONAL boolean to ``monitor_running``
        # (rev5 §4.5): the monitor being up says nothing about whether the
        # privileged mutation plane is armed.
        #
        # M2 (D-5 closure): with an ``e3_broker`` wired, the ONLY source is
        # the broker's fresh-only derivation from management.status RPC --
        # this module still never stats/opens/reads the activation marker,
        # and a stale "active" is never trusted. The injectable provider hook
        # remains ONLY for the M0.5 test harness (and answers False when no
        # broker and no provider exist, which stays the fail-closed default).
        self._management_active = management_active
        self.e3_broker = e3_broker
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

    def step_up_active(self, token):
        """Is a live step-up window attached to this session right now?"""
        if not self.auth or not token:
            return False
        return self.auth.sessions.step_up_active(token)

    def monitor_running(self):
        """``monitor_running``: the E1 collector + E2 web are both alive."""
        run = getattr(self.broker, "running", None)
        return bool(run()) if callable(run) else False

    def management_active(self):
        """``management_active``: the privileged mutation plane is armed.

        M2: with an E3 broker wired, the answer is the broker's fresh-only
        derivation of management.status (``stale active=true`` is NEVER
        trusted; helper unreachable answers False). Without a broker, the
        M0.5 injectable provider path applies and still fails closed.
        There is no filesystem read anywhere on either path.
        """
        if self.e3_broker is not None:
            try:
                return bool(self.e3_broker.management_active())
            except Exception:  # noqa: BLE001 - unknown state is NOT "active"
                return False
        provider = self._management_active
        if provider is None:
            return False
        try:
            return bool(provider())
        except Exception:  # noqa: BLE001 - unknown state is NOT "active"
            return False

    def session_fingerprint(self, token):
        """sha256(session token)[:16] -- the RPC actor's ``session_fp``.

        One-way: the session token itself never leaves this process. """
        if not token:
            return None
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

    # (B2) the step-up fingerprint is no longer read separately anywhere:
    # the gate captures it atomically with the liveness check via
    # auth.step_up_credentials, freezes it into the request's actor, and
    # the handler never re-reads it.


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

        # POST body framing is validated BEFORE every other gate: the
        # recovery exemption, the whitelist and the session checks all
        # run after we know the declared body is sane and bounded. No
        # early-return path can be reached with a malformed
        # Content-Length, an unbounded body or chunked framing.
        if method == "POST":
            error = self._body_header_error()
            if error is not None:
                self.close_connection = True  # framing untrusted: no reuse
                self._send_json(error[0], {"error": error[1]})
                return

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
        # M2: the E3 adapter read surface (session-gated; read-level).
        if path == "/api/v1/management/status":
            self._require_session(self._handle_e3_management_status)
            return
        if path == "/api/v1/clients":
            self._require_session(self._handle_e3_clients_list)
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
        # Body framing was already validated in _route() before every gate.
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
        if path == "/api/v1/step-up":
            self._require_session(self._handle_step_up, csrf=True)
            return
        op = MUTATION_ROUTES.get(path)
        if op is not None:
            # M2: the full gate chain (session -> CSRF -> step-up) is
            # unchanged; the gate ALSO freezes the audit actor atomically
            # with the step-up liveness check (B2), so a revocation that
            # lands after the gate can never strip the actor from an
            # already-authorized dispatch.
            self._require_step_up(self._handle_e3_mutation, op)
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

    def _require_step_up(self, handler, *args):
        """Gate for privileged mutations (M0.5 / rev5 §5).

        Chain, in order: session -> session-bound CSRF token -> live step-up.
        A missing/expired step-up is a 401 ``reauth_required``, which is the
        ONLY signal the web UI acts on (it pops the password box and replays
        the identical request). The step-up credential itself never leaves
        this process: the backend would only ever receive an actor
        fingerprint, never the password.

        REVOCATION CONCURRENCY SEMANTICS (contract, aligned with M1's
        "a transaction is uncancellable once its durable intent is written"):

        * the check above is evaluated PER REQUEST, at the moment the request
          reaches the gate. Logout / password change / recovery reset-rotate
          therefore strip the step-up from every request that has NOT yet
          passed the gate -- immediately, not after the 300s window;
        * a request that has ALREADY passed the gate is not reconsidered. Its
          step-up was valid when authorization happened, and it must not be
          aborted mid-flight by a revocation that lands afterwards;
        * M0.5 performs no dispatch, so no half-finished transaction can exist
          here at all. The rule is stated now because M1 inherits it: once a
          durable ledger intent exists, the sbox-cm side drives the mutation
          to a terminal state regardless of what the web session does.
        """
        token = self._session_token()
        session = self.app.session_from_token(token)
        if session is None:
            self._send_json(401, {"error": "login required"})
            return
        supplied = self.headers.get("X-CSRF-Token")
        expected = session.get("csrf_token", "")
        if not isinstance(supplied, str) or \
                not hmac.compare_digest(supplied, expected):
            self._send_json(403, {"error": "missing or invalid CSRF token"})
            return
        # B2: the step-up liveness check and the audit fingerprint are read
        # in ONE atomic step (auth.step_up_credentials). The frozen actor
        # travels with the request: a revocation that lands after this point
        # refuses every LATER request but does not strip the actor from an
        # already-authorized dispatch -- the helper's audit keeps the
        # gate-time fingerprints.
        creds = self.app.auth.sessions.step_up_credentials(token)
        if not creds["active"]:
            self._send_json(401, {"error": "reauth_required"})
            return
        actor = {}
        sfp = self.app.session_fingerprint(token)
        if sfp:
            actor["session_fp"] = sfp
        if creds["fp"]:
            actor["stepup_fp"] = creds["fp"]
        handler(session, *args, actor)

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
            # M0.5 orthogonal status model (rev5 §4.5). These two are
            # independent on purpose: a running monitor with the mutation
            # plane DISARMED is the normal, safe production default.
            "monitor_running": self.app.monitor_running(),
            "management_active": self.app.management_active(),
            # The step-up state of THIS session, so the page can show whether
            # a re-authentication is still live. It is an opaque boolean --
            # no password, no token, no expiry value is disclosed.
            "step_up_active": session is not None
            and self.app.step_up_active(self._session_token()),
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

    def _handle_step_up(self, session):
        """POST /api/v1/step-up {password} -> open a 300s mutation window.

        Gate order for THIS endpoint, enforced by the caller plus this body:
        session -> CSRF -> rate-limit -> verify_password -> grant_step_up.

        It requires a logged-in session AND that session's CSRF token, but of
        course not an existing step-up (that would be circular). The CSRF
        requirement is not cosmetic: without it, a cross-site request could
        not guess the password, but it COULD submit deliberate wrong ones and
        burn the shared login-rate-limiter budget, locking the real admin out
        (a CSRF-triggered lockout DoS). CSRF is therefore checked BEFORE any
        password work or counter mutation -- a rejected cross-origin attempt
        consumes no rate-limit budget and performs no scrypt work.

        The password is verified with the SAME ``AuthStore.verify_password``
        used by login, and failures are counted by the SAME
        ``LoginRateLimiter`` keyed on the socket peer address. Step-up is
        therefore not a second, unlimited password-guessing surface: the
        lockout budget is shared, so neither endpoint can be used to brute
        force the other's limiter away.
        """
        auth = self.app.auth
        if auth is None:
            self._send_json(401, {"error": "login required"})
            return
        body = self._json_body()
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str):
            self._send_json(400, {"error": "password required"})
            return
        remote = self.client_address[0]
        allowed, retry_after = auth.login_limiter.check(remote)
        if not allowed:
            self._send_json(
                429,
                {"error": "rate_limited", "retry_after": retry_after},
                extra_headers=[("Retry-After", str(retry_after))])
            return
        if not auth.verify_password(password):
            auth.login_limiter.record_failure(remote)
            self._send_json(401, {"error": "invalid_credentials"})
            return
        auth.login_limiter.record_success(remote)
        token = self._session_token()
        # The window length comes from the session store (production default
        # 300s, rev5 §5.1); the same value is reported back so the page and
        # the test harness never have to assume it.
        ttl = auth.sessions.step_up_ttl
        if auth.sessions.grant_step_up(token, ttl) is None:
            # The session vanished between the gate and the grant: never
            # claim a window was opened.
            self._send_json(401, {"error": "login required"})
            return
        self._send_json(200, {"status": "ok", "expires_in": ttl})

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
            # Dropping the session also drops its step-up: revocation on
            # logout is immediate, not "whenever the 300s window lapses".
            self.app.auth.sessions.drop(token)
        self._send_json(200, {"status": "ok"},
                        extra_headers=[("Set-Cookie",
                                        self._session_cookie("", 0))])

    # -- M2: sbox-cm RPC adapter -------------------------------------------------

    def _e3_unavailable(self, detail="the privileged execution plane is "
                                     "unreachable"):
        self._send_json(503, {"ok": False, "code": "e3_unavailable",
                              "error": detail, "retriable": True})

    def _e3_verdict_error(self, result):
        """B1: a helper ``ok:false`` verdict on a WORKING transport maps
        through the authoritative error table -- never disguised as a
        snapshot, never as e3_unavailable, and the breaker was not touched."""
        err = result["verdict_error"]
        mapped = {"ok": False, "code": err["code"], "stage": err["stage"],
                  "error": err["detail"], "retriable": err["retriable"],
                  "request_id": err.get("request_id")}
        self._send_json(E3_ERROR_HTTP.get(err["code"], 500), mapped)

    def _handle_e3_management_status(self, session):
        """GET /api/v1/management/status -> the whitelisted status snapshot.

        transport (fresh|stale|unavailable) and as_of describe the WEB-side
        freshness of the snapshot; helper.degraded inside data is only ever
        what a real management.status response said (the two are never
        conflated, design §7.5). monitor_running is web-supplied (frozen
        ruling): this process IS the monitor. An unavailable helper with no
        snapshot is a 503 -- nothing is synthesized. A helper semantic
        verdict (ok:false) maps through E3_ERROR_HTTP (B1)."""
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable("the E3 adapter is not wired in this build")
            return
        result = broker.status()
        if result.get("verdict_error"):
            self._e3_verdict_error(result)
            return
        if result["payload"] is None:
            self._e3_unavailable("sbox-cm is unreachable (no snapshot)")
            return
        payload = result["payload"]
        data = payload.get("data") if isinstance(payload, dict) else {}
        self._send_json(200, {
            "ok": True,
            "transport": result["transport"],
            "as_of": iso_utc(result["as_of"]),
            "monitor_running": self.app.monitor_running(),
            "management_active": self.app.management_active(),
            "data": sanitize_e3_data("management.status", data or {}),
        })

    def _handle_e3_clients_list(self, session):
        """GET /api/v1/clients -> the whitelisted client.list snapshot.

        A stale snapshot is served for DISPLAY with its as_of; the delete
        flow never trusts it (it prefetches a fresh list server-side)."""
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable("the E3 adapter is not wired in this build")
            return
        result = broker.list_clients()
        if result.get("verdict_error"):
            self._e3_verdict_error(result)
            return
        if result["payload"] is None:
            self._e3_unavailable("sbox-cm is unreachable (no snapshot)")
            return
        payload = result["payload"]
        data = payload.get("data") if isinstance(payload, dict) else {}
        self._send_json(200, {
            "ok": True,
            "transport": result["transport"],
            "as_of": iso_utc(result["as_of"]),
            "data": sanitize_e3_data("client.list", data or {}),
        })

    def _handle_e3_mutation(self, session, op, actor):
        """POST mutation -> dispatch to sbox-cm via the broker.

        Reached only after session -> CSRF -> step-up, and the ``actor`` was
        FROZEN at the gate (B2): the fingerprints are the gate-time values,
        so a revocation racing the dispatch changes the authorization of
        FUTURE requests, never the attribution of this one.

        Contract highlights (design §8-§11):

        * client.add/delete take the Idempotency-Key HTTP header (16..128 of
          [A-Za-z0-9._:-]), validated here and forwarded verbatim; the body
          must NOT carry a second key. The browser keeps the header across a
          401 replay and an explicit post-uncertain retry;
        * client.delete runs a FRESH (cache-bypassing) list preflight and a
          server-side confirm==name check before anything is dispatched;
        * a connect failure is a definitive non-dispatch (503
          e3_unavailable); a post-send budget exhaustion is 504
          result_unknown with uncertain=true -- the transaction keeps running
          inside the helper, so no automatic retry ever happens here;
        * helper verdicts pass through the deny-by-default whitelist; the
          code/stage/retriable mapping is rev5 §2.6.
        """
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable("the E3 adapter is not wired in this build")
            return

        body = self._json_body() or {}
        payload = {}
        key = None
        name = None

        if op in ("client.add", "client.delete"):
            if "idempotency_key" in body:
                self._send_json(400, {
                    "ok": False, "code": "invalid_idempotency_key",
                    "error": "the Idempotency-Key must be sent as the "
                             "request header, never in the body",
                    "retriable": False})
                return
            key = self.headers.get(IDEMPOTENCY_HEADER)
            if not isinstance(key, str) or not E3_KEY_RE.match(key):
                self._send_json(400, {
                    "ok": False, "code": "invalid_idempotency_key",
                    "error": "Idempotency-Key header missing or invalid "
                             "(16..128 characters of [A-Za-z0-9._:-])",
                    "retriable": False})
                return
            payload["idempotency_key"] = key
            name = body.get("name")
            if not isinstance(name, str) or not E3_NAME_RE.match(name):
                self._send_json(400, {
                    "ok": False, "code": "invalid_name",
                    "error": "name missing or invalid (<=32 chars, "
                             "[A-Za-z0-9][A-Za-z0-9._-]*)",
                    "retriable": False})
                return
            if name == E3_RESERVED_NAME:
                # First of the two defences; the helper re-validates in-lock.
                self._send_json(403, {
                    "ok": False, "code": "E_RESERVED_NAME",
                    "error": "legacy is a reserved name", "retriable": False})
                return
            payload["name"] = name

        if op == "client.delete":
            # Server-side type-to-confirm: the echoed value must equal the
            # name exactly (U-2). Then the fresh-list preflight: without a
            # provably FRESH list (this exact request's own successful RPC,
            # never a stale fallback) nothing destructive is dispatched (the
            # helper's in-lock revalidation stays the correctness boundary).
            if body.get("confirm") != name:
                self._send_json(400, {
                    "ok": False, "code": "confirm_mismatch",
                    "error": "confirm must be present and equal the client "
                             "name exactly",
                    "retriable": False})
                return
            try:
                fresh = broker.list_clients(force=True)
            except BrokerUnavailable:
                fresh = {"payload": None, "transport": "unavailable",
                         "verdict_error": None}
            # B1: a helper semantic verdict on the preflight keeps its own
            # semantics (E_LOCK -> 423, E_CONFIG_INCONSISTENT -> 409, ...);
            # it is never disguised as E_NOT_FOUND and the delete is never
            # dispatched past a failed preflight.
            if fresh.get("verdict_error"):
                self._e3_verdict_error(fresh)
                return
            fresh_ok = fresh.get("payload") is not None \
                and fresh.get("transport") == "fresh"
            names = set()
            if fresh_ok:
                data = fresh["payload"].get("data")
                if isinstance(data, dict):
                    names = {c.get("name")
                             for c in data.get("clients", [])
                             if isinstance(c, dict)}
            if not fresh_ok:
                self._send_json(503, {
                    "ok": False, "code": "list_unavailable",
                    "error": "no fresh client list is available; the delete "
                             "was NOT dispatched",
                    "retriable": True})
                return
            if name not in names:
                self._send_json(404, {
                    "ok": False, "code": "E_NOT_FOUND",
                    "error": "the client is not in the fresh list; nothing "
                             "was deleted",
                    "retriable": False})
                return

        # the actor arrived FROZEN from the gate (B2) -- never re-read here
        try:
            verdict = broker.mutate(op, payload=payload, actor=actor or None)
        except BrokerUnavailable:
            self._e3_unavailable("the helper breaker is open; the mutation "
                                 "was NOT dispatched")
            return
        except RpcTransportError as exc:
            if exc.stage == "connect":
                # Definitively not dispatched: no transaction can have begun.
                self._e3_unavailable("sbox-cm is unreachable; the mutation "
                                     "was NOT dispatched")
                return
            # Post-send: the outcome is unknown by design (the helper never
            # aborts a dispatched transaction). No automatic retry here.
            response = {
                "ok": False, "code": "result_unknown",
                "error": "the caller budget expired after dispatch; the "
                         "transaction keeps running inside sbox-cm",
                "retriable": True, "uncertain": True,
            }
            if op in ("management.activate", "management.deactivate"):
                # No Idempotency-Key exists for these ops by design: recovery
                # is status-first, then an explicit new confirmation.
                response["recovery"] = (
                    "check GET /api/v1/management/status (management_state) "
                    "before doing anything; if a new attempt is still needed, "
                    "confirm it explicitly")
            else:
                response["recovery"] = (
                    "check GET /api/v1/management/status and GET /api/v1/"
                    "clients first; retry ONLY with the SAME Idempotency-Key "
                    "if a retry is still needed")
            self._send_json(504, response)
            return

        if verdict.get("ok"):
            self._send_json(200, {
                "ok": True, "op": op,
                "request_id": verdict.get("request_id"),
                "idempotency": sanitize_e3_idempotency(
                    verdict.get("idempotency")),
                "data": sanitize_e3_data(op, verdict.get("data")),
                "warnings": verdict.get("warnings") or [],
            })
            return
        mapped = sanitize_e3_error(verdict)
        mapped.update({"ok": False,
                       "request_id": verdict.get("request_id")})
        self._send_json(E3_ERROR_HTTP.get(mapped["code"], 500), mapped)

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
        # The session was valid at connection time; it must stay valid for
        # the whole stream. Revalidate the ORIGINAL token before every
        # push: TTL expiry, logout or a password change (which revokes
        # other sessions) each stop an open stream within one publish
        # tick (~1s). No special auth-expired event: the browser's
        # EventSource reconnects, the new request hits 401, the UI shows
        # the login view.
        token = self._session_token()
        try:
            for _version, payload in self.app.broker.subscribe(
                    after_version=version):
                if self.app.session_from_token(token) is None:
                    break  # session expired or revoked mid-stream
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
