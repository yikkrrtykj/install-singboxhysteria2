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
import math
import re
import sys
import threading
import time
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from web.access import host_entry_for_ip
from web.e3_broker import BrokerUnavailable
from web.e3rpc import RpcTransportError
from p6_artifact import ArtifactError, read_artifact
from p6_distribution import DistributionError, open_release
from web.p6_bundle import BundleError, assemble as assemble_p6_bundle
from web.p6_windows_bundle import WindowsClientPackage, require_client_package
from web import incident_presenter as incident_presenter
from web.incident_remote import incident_remote
from web import incident_history as ih_outcomes
from web.incident_history import (MARKER_KINDS, QUERY_LIMIT_DEFAULT,
                                  QUERY_LIMIT_MAX, RETENTION_SECONDS)

ih_outcome_ok = ih_outcomes.OUTCOME_OK
ih_outcome_missing = ih_outcomes.OUTCOME_MISSING
ih_outcome_store_unavailable = ih_outcomes.OUTCOME_STORE_UNAVAILABLE
ih_outcome_rejected = ih_outcomes.OUTCOME_REJECTED
ih_outcome_rearmed = ih_outcomes.OUTCOME_REARMED
ih_outcome_recorded = ih_outcomes.OUTCOME_RECORDED
from web.remote_ingest import (INGEST_HEADERS, INGEST_MAX_BODY,
                               ERR_BAD_FRAMING, ERR_PAYLOAD_TOO_LARGE,
                               ERR_CONTENT_TYPE, REMOTE_INGEST_PATH)
from web.recovery import (RECOVERY_SUCCESS_MESSAGE, RecoveryGlobalGuard,
                          RecoveryRateLimiter, generate_key)

MONITOR_WEB_VERSION = "0.9.0"
SESSION_COOKIE = "monitor_session"
MAX_BODY_BYTES = 65536
SUPPORTED_METHODS = "GET, POST"

# Issue #33 PR-3B: the closed probe-scheduler status vocabulary re-emitted by
# /api/v1/diagnostics/timeline. web/ never imports diagnostics/, so this is a
# deliberate duplicate; tests/test-monitor-v2-probe-ingest.sh is the static
# gate that keeps the two in lockstep (a scheduler key that is not listed
# here is invisible to the surface, which is the fail-closed direction).
PROBE_STATUS_KEYS = (
    "enabled", "running", "target_source", "startup_error",
    "cadence_seconds", "cycles_completed", "cycles_rejected",
    "runtime_failures", "last_cycle_epoch", "last_store_epoch",
)
PROBE_STATUS_BOOL_KEYS = frozenset({"enabled", "running"})
PROBE_STATUS_SOURCE_KEYS = frozenset({"target_source"})
PROBE_STATUS_TOKEN_KEYS = frozenset({"startup_error"})
# Mirror of the scheduler's closed startup vocabulary (the same no-import,
# duplicate-shapes discipline the history module uses for the probe
# result codes): an arbitrary string from a buggy scheduler is refused,
# so this field can never carry a path, an endpoint or exception text.
PROBE_STARTUP_TOKENS = frozenset({
    "target_file_not_configured", "target_file_absent",
    "target_injection_invalid"})
PROBE_STATUS_REAL_KEYS = frozenset({"cadence_seconds", "last_cycle_epoch",
                                    "last_store_epoch"})
PROBE_STATUS_INT_KEYS = frozenset({"cycles_completed", "cycles_rejected",
                                   "runtime_failures"})
PROBE_TARGET_SOURCES = frozenset({"production", "injected", "dark"})
# Every projected value is EXACTLY typed before it is judged. Numbers get a
# finiteness, nonnegativity and JSON-safe range check (a NaN or an infinity
# would serialize as the bare words ``NaN``/``Infinity`` -- not valid JSON, so
# one lying scheduler would break this read for every consumer). Booleans get
# an EXACT-type check (``bool(value)`` would otherwise turn ``"yes"`` or ``1``
# into "enabled"). Tokens get one too, and it runs BEFORE the membership test:
# a frozenset asks its candidate to hash, so a list or a dict used to raise
# ``TypeError`` straight out of the projection, and an object that forges a
# token's ``__hash__`` while ``__eq__`` always answers True used to be
# ADOPTED as that token and then emitted verbatim into the response.
PROBE_STATUS_MAX_NUMBER = 9007199254740991  # 2**53 - 1


def closed_probe_bool(value):
    """One projected flag, or the deny answer. ONLY an EXACT bool is a flag
    this surface may repeat; ``"yes"``, ``1``, ``[]`` or a subclass with a
    private ``__bool__`` is a producer defect, and since this field has no
    "unknown" shape it can take without changing its JSON type, the defect
    answers ``False`` -- the direction that can never make the probe plane
    look enabled or running when it is not."""
    return value if type(value) is bool else False


def closed_probe_source(value):
    """One projected target source, or ``"dark"``. The exact-type check runs
    first so membership never hashes a list/dict (that raised) and never
    adopts a hash-forging impostor (that leaked a live object into the
    response); a string outside the closed vocabulary -- an endpoint, a
    hostname, a path -- is refused."""
    if type(value) is str and value in PROBE_TARGET_SOURCES:
        return value
    return "dark"


def closed_probe_startup(value):
    """One projected startup token, or None. Same discipline as the source:
    EXACTLY a str, then EXACTLY a member of the closed startup vocabulary, so
    an unhashable or impersonating object can neither raise nor be repeated,
    and exception text can never be presented as a token."""
    if value is None:
        return None
    if type(value) is str and value in PROBE_STARTUP_TOKENS:
        return value
    return None


def closed_probe_seconds(value):
    """One projected real, or None. EXACTLY a plain int or float (not a
    bool, not a subclass with a private ``__float__``), finite,
    nonnegative and representable without JSON precision loss. Anything
    else -- ``"fast"``, ``NaN``, ``Infinity``, ``-1``, ``True`` -- is not a
    number this surface may repeat, so it answers None (unknown) instead
    of a coerced guess."""
    if type(value) not in (int, float):
        return None
    if value < 0 or value > PROBE_STATUS_MAX_NUMBER:
        return None
    if not math.isfinite(value):
        return None
    return 0 if value == 0 else value


def closed_probe_counter(value):
    """One projected integer count, or 0. EXACTLY a plain int (a float
    claim like ``2.5`` is a defect, not a count), nonnegative and
    JSON-safe -- so a counter can never read as a fractional, negative or
    precision-losing number."""
    if type(value) is not int:
        return 0
    if value < 0 or value > PROBE_STATUS_MAX_NUMBER:
        return 0
    return value

# 0.5.0 (#33 PR-4B): the closed IncidentScanner status vocabulary re-emitted
# by /api/v1/diagnostics/timeline. web/ never imports the runtime module, so
# this is a deliberate duplicate of its §12 contract (a scanner key that is
# not listed here is invisible to the surface, which is the fail-closed
# direction). The bool/int/real domains below reuse the exact-typing
# primitives above: identical semantics, shared discipline.
INCIDENT_RUNTIME_STATUS_KEYS = (
    "enabled", "running", "phase", "cycles_completed", "runtime_failures",
    "last_error_code", "last_evaluated_end_epoch", "open_incident",
)
INCIDENT_RUNTIME_BOOL_KEYS = frozenset(
    {"enabled", "running", "open_incident"})
INCIDENT_RUNTIME_PHASE_KEYS = frozenset(
    {"warmup", "idle", "open", "rearm", "degraded"})
INCIDENT_RUNTIME_ERROR_TOKENS = frozenset({
    "evidence_read_failed", "classify_failed", "persist_failed",
    "runtime_state_corrupt"})
INCIDENT_RUNTIME_INT_KEYS = frozenset(
    {"cycles_completed", "runtime_failures"})
INCIDENT_RUNTIME_REAL_KEYS = frozenset({"last_evaluated_end_epoch"})


def closed_incident_phase(value):
    """One projected scanner phase, or ``"warmup"``. EXACTLY a str, then
    EXACTLY a member of the closed phase vocabulary -- warmup is the deny
    answer because it is the scanner's dark phase (a lying phase can never
    make the plane look more live than it is)."""
    if type(value) is str and value in INCIDENT_RUNTIME_PHASE_KEYS:
        return value
    return "warmup"


def closed_incident_error(value):
    """One projected scanner error token, or None. Same discipline as the
    probe startup token: EXACTLY a str, then EXACTLY a member of the
    closed four-token vocabulary, so exception text or a path can never be
    presented as an error code."""
    if type(value) is str and value in INCIDENT_RUNTIME_ERROR_TOKENS:
        return value
    return None

# The four privileged mutation routes of rev5 §7. M0.5 delivered them as a
# 501 boundary; M2 wires them to the sbox-cm RPC adapter (below).
# Product UX contract: client.add is session + CSRF only after login;
# delete/activate/deactivate retain session + CSRF + step-up.
MUTATION_ROUTES = {
    "/api/v1/management/activate": "management.activate",
    "/api/v1/management/deactivate": "management.deactivate",
    "/api/v1/clients/add": "client.add",
    "/api/v1/clients/delete": "client.delete",
}

P6_ROUTES = {
    '/api/v1/clients/probes/list': 'probe.list',
    '/api/v1/clients/probes/enroll': 'probe.enroll',
    '/api/v1/clients/probes/revoke': 'probe.revoke',
    '/api/v1/clients/probes/resume': 'probe.resume',
    '/api/v1/clients/bundle': 'client.bundle',
    '/api/v1/clients/windows': 'windows.download',
    '/api/v1/clients/windows-bundle': 'windows.bundle',
}
P6_ERROR_HTTP = {
    'E_P6_SCHEMA': 400, 'E_P6_NOT_ENROLLED': 404, 'E_P6_REVOKED': 409,
    'E_P6_BINDING': 409, 'E_P6_BINDING_CHANGED': 409, 'E_P6_DEVICE_EXISTS': 409,
    'E_P6_IDEMPOTENCY_CONFLICT': 409, 'E_P6_KEY_CHANGED': 409,
    'E_P6_REGISTRY_CHANGED': 409, 'E_P6_LIVE_UNCONFIRMED': 503,
    'E_P6_CONFIRM_PENDING': 503, 'E_P6_CAPACITY': 507, 'E_P6_BUSY': 423,
    'E_P6_AUTHORITY': 503, 'E_P6_STATE': 503, 'E_P6_REGISTRY': 503,
    'E_P6_ARTIFACT': 503, 'E_P6_UNAVAILABLE': 503, 'E_AUDIT_UNAVAILABLE': 503,
    'E_P6_BUNDLE': 502, 'E_P6_WINDOWS_UNAVAILABLE': 503,
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


# -- P5 incidents surface (issue #33 Phase 5, #63 R2 §4/§8/§10) -----------------

INCIDENT_LIST_LIMIT_DEFAULT = 100
INCIDENT_LIST_LIMIT_MAX = 500
MARKER_LIST_LIMIT_DEFAULT = 200
MARKER_LIST_LIMIT_MAX = 500
# The marker evidence context (#63 R2 §8): a marker-bound evidence window
# is exactly the +/-900 s span around the operator-declared epoch.
MARKER_CONTEXT_SPAN_SECONDS = 900.0
INCIDENT_LIST_STATES = ("open", "closed")
# The closed evidence section vocabulary: exactly the classifier's
# LIST_SECTIONS. web/ never imports the classifier, so this is the same
# deliberate duplicate-shapes discipline as every other mirrored enum;
# the incidents lane equality-gates it against the live module.
EVIDENCE_SECTION_NAMES = ("samples", "device_states", "probe_rows",
                          "journal_events", "audit")
INCIDENT_LIST_ROW_KEYS = (
    "incident_id", "classifier_version", "state", "category",
    "analysis_start_epoch", "first_signal_epoch", "last_signal_epoch",
    "last_classified_end_epoch", "closed_epoch", "closure_reason",
    "buckets",
)


# Bounded positive-ID parsing for the P5 route family: EXACTLY ASCII
# 0-9, at most nine digits (any rowid this surface can produce is far
# smaller), positive -- and TOTAL: no exception can escape, because
# malformed user input must never reach the internal-error path.
MAX_ROUTE_ID_DIGITS = 9
ASCII_DIGITS = frozenset("0123456789")


def parse_positive_id(raw):
    """The bounded ASCII-decimal positive ID, or None. ``str.isdigit``
    accepts non-ASCII digit characters (e.g. "²") that ``int`` then
    refuses, and an unbounded digit string is unbounded conversion work --
    so the parser is character-closed and length-bounded BEFORE ``int``
    ever runs."""
    if (not isinstance(raw, str) or not raw
            or len(raw) > MAX_ROUTE_ID_DIGITS
            or not all(ch in ASCII_DIGITS for ch in raw)):
        return None
    value = int(raw)
    return value if value >= 1 else None


def incident_list_params(query):
    """Validate the ONLY accepted incident-list params:
    (error, state, limit). Unknown query keys are IGNORED -- never
    interpreted as filters (the timeline discipline). An invalid or
    <1 limit is a 400; a too-large limit is clamped (#63 R2 §4)."""
    state = None
    if "state" in query:
        state = query["state"][0]
        if state not in INCIDENT_LIST_STATES:
            return "invalid_state", None, None
    limit = INCIDENT_LIST_LIMIT_DEFAULT
    if "limit" in query:
        try:
            limit = int(query["limit"][0])
        except (TypeError, ValueError):
            return "invalid_limit", None, None
        if limit < 1:
            return "invalid_limit", None, None
        limit = min(limit, INCIDENT_LIST_LIMIT_MAX)
    return None, state, limit


def marker_list_params(query):
    """Validate the ONLY accepted marker-list params: (error, limit).
    Same discipline as the incident list."""
    limit = MARKER_LIST_LIMIT_DEFAULT
    if "limit" in query:
        try:
            limit = int(query["limit"][0])
        except (TypeError, ValueError):
            return "invalid_limit", None, None
        if limit < 1:
            return "invalid_limit", None, None
        limit = min(limit, MARKER_LIST_LIMIT_MAX)
    return None, limit


def timeline_query_params(query):
    """Validate the ONLY accepted timeline params: (error, since, limit).

    Unknown query keys are IGNORED -- never interpreted as filters, so no
    arbitrary filter, field or SQL surface can be expressed through the
    URL. limit is hard-capped; since must be a finite non-negative epoch.
    """
    since = None
    if "since" in query:
        try:
            since = float(query["since"][0])
        except (TypeError, ValueError):
            return "since must be a numeric epoch", None, None
        if not math.isfinite(since) or since < 0:
            return "since must be a finite non-negative epoch", None, None
    limit = QUERY_LIMIT_DEFAULT
    if "limit" in query:
        raw = query["limit"][0]
        try:
            limit = int(raw)
        except (TypeError, ValueError):
            return "limit must be an integer", None, None
        if limit < 1:
            return "limit must be at least 1", None, None
        limit = min(limit, QUERY_LIMIT_MAX)
    return None, since, limit


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
                 recovery_guard=None, management_active=None, e3_broker=None,
                 incident_history=None, probe_scheduler=None,
                 incident_scanner=None, remote_plane=None, bundle_artifact=None, windows_distribution=None, host_evidence=None):
        self.broker = broker
        self.access = access
        self.auth = auth
        self.static_dir = static_dir
        self.remote_mode = remote_mode
        self.version = version
        # Issue #33 P1: the bounded incident timeline. Injectable; None
        # (standalone harnesses) keeps the read endpoint a clean 503.
        self.incident_history = incident_history
        self.host_evidence = host_evidence
        # Issue #33 PR-3B: the probe scheduler's closed status object is the
        # ONLY thing this surface can show about probing -- no endpoints, no
        # probe results, no paths, no free text.
        self.probe_scheduler = probe_scheduler
        # Issue #33 PR-4B: the incident scanner's closed 8-key status object
        # is the ONLY thing this surface can show about the automatic
        # incident lifecycle -- no incident rows, no evidence bits, no
        # window coordinates beyond the one bounded epoch.
        self.incident_scanner = incident_scanner
        # Issue #67 PR-6B: the machine ingest plane is OPTIONAL. None
        # (standalone harnesses) keeps the exact ingest route a plain 404;
        # a wired plane answers only after framing -> whitelist -> HMAC.
        self.remote_plane = remote_plane
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
        self.bundle_artifact = bundle_artifact or read_artifact
        self.windows_distribution = windows_distribution or open_release
        self.bundle_slots = threading.BoundedSemaphore(2)
        self._static_cache = {}

    def probe_status(self):
        """Closed scheduler status for the diagnostics surface.

        Deny-by-default: only the frozen ``PROBE_STATUS_KEYS`` are
        re-emitted, each value forced back into its own closed domain --
        every field EXACTLY typed first (bool, str, plain int/float), then
        tokens by membership in the closed vocabularies, then numbers by
        finiteness, nonnegativity and a JSON-safe range -- so an endpoint, a
        path or exception text can never reach a response, neither can a
        ``NaN``/``Infinity`` literal (invalid JSON that would break the
        whole read for every consumer), and neither can an unhashable or
        ``__eq__``-forging candidate raise out of the projection or be adopted
        as a token. A missing, broken or lying scheduler answers ``None``; a
        lying value answers its closed minimum, never a guess.
        """
        getter = getattr(self.probe_scheduler, "status", None)
        if not callable(getter):
            return None
        try:
            raw = getter()
        except Exception:  # noqa: BLE001 -- a status read never propagates
            return None
        if type(raw) is not dict:
            # EXACTLY a dict: a subclass can override ``get`` to answer a
            # different value per key, which is not a status container this
            # surface may project.
            return None
        status = {}
        for key in PROBE_STATUS_KEYS:
            value = raw.get(key)
            if key in PROBE_STATUS_BOOL_KEYS:
                status[key] = closed_probe_bool(value)
            elif key in PROBE_STATUS_SOURCE_KEYS:
                status[key] = closed_probe_source(value)
            elif key in PROBE_STATUS_TOKEN_KEYS:
                status[key] = closed_probe_startup(value)
            elif key in PROBE_STATUS_REAL_KEYS:
                status[key] = closed_probe_seconds(value)
            elif key in PROBE_STATUS_INT_KEYS:
                status[key] = closed_probe_counter(value)
            else:
                # An unclassified key cannot exist: the probe suite asserts
                # that the five class sets cover PROBE_STATUS_KEYS exactly.
                # Should the mirror ever drift, the surface answers the
                # closed minimum for a count rather than repeating whatever
                # an unknown shape held.
                status[key] = 0
        return status

    def incident_runtime_status(self):
        """Closed scanner status for the diagnostics surface.

        Deny-by-default mirror of ``probe_status()`` for the PR-4B
        IncidentScanner: only the frozen ``INCIDENT_RUNTIME_STATUS_KEYS``
        are re-emitted, each value forced back into its own closed domain
        (bool by exact type, phase/error by closed-token membership,
        counters by plain-int nonnegativity, the one epoch by plain-real
        finiteness/nonnegativity). A missing, broken or lying scanner
        answers ``None``; a lying value answers its closed minimum, never
        a guess -- a lying phase answers ``"warmup"`` (the scanner's dark
        phase), a lying error token answers None.
        """
        getter = getattr(self.incident_scanner, "status", None)
        if not callable(getter):
            return None
        try:
            raw = getter()
        except Exception:  # noqa: BLE001 -- a status read never propagates
            return None
        if type(raw) is not dict:
            return None
        status = {}
        for key in INCIDENT_RUNTIME_STATUS_KEYS:
            value = raw.get(key)
            if key in INCIDENT_RUNTIME_BOOL_KEYS:
                status[key] = closed_probe_bool(value)
            elif key == "phase":
                status[key] = closed_incident_phase(value)
            elif key == "last_error_code":
                status[key] = closed_incident_error(value)
            elif key in INCIDENT_RUNTIME_INT_KEYS:
                status[key] = closed_probe_counter(value)
            elif key in INCIDENT_RUNTIME_REAL_KEYS:
                status[key] = closed_probe_seconds(value)
            else:
                # An unclassified key cannot exist: the runtime suite
                # asserts that the class sets cover
                # INCIDENT_RUNTIME_STATUS_KEYS exactly. Should the mirror
                # ever drift, the surface answers the closed minimum for a
                # count rather than repeating an unknown shape.
                status[key] = 0
        return status

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

    # The ONLY exceptions suppressed at this boundary (issue #65). Both are
    # raised by the CLIENT going away, never by the Monitor: a client that
    # resets or half-closes a keep-alive connection while
    # ``BaseHTTPRequestHandler.handle()`` waits for the next request line
    # produces them AFTER a complete, successfully answered request --
    # outside ``MonitorRequestHandler._dispatch()``, which is why the
    # request-level disconnect handling there cannot see them.
    #
    # Deliberately NOT ``ConnectionError`` (their common parent), not
    # ``OSError``, not ``TimeoutError`` and not ``Exception``: those would
    # hide real server defects in the same traceback channel that exists to
    # report them. An independently reviewed need would be required to
    # widen this tuple.
    BENIGN_CLIENT_DISCONNECTS = (BrokenPipeError, ConnectionResetError)

    def handle_error(self, request, client_address):
        """Suppress the stdlib traceback for benign client disconnects only.

        Every other exception is delegated unchanged to
        ``super().handle_error()``, so genuine faults keep their normal
        stderr traceback. Nothing else is touched: the socket is still
        released by ``socketserver``'s own shutdown path after this
        method returns.
        """
        if isinstance(sys.exc_info()[1], self.BENIGN_CLIENT_DISCONNECTS):
            return
        super().handle_error(request, client_address)


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

    def _method_not_allowed(self, allowed=SUPPORTED_METHODS):
        # Uniform surface: 405 + Allow, and never reuse a connection whose
        # method semantics (or body framing) we did not interpret.
        self.close_connection = True
        body = json.dumps({"error": "method not allowed"}).encode("utf-8")
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.send_header("Allow", allowed)
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
        # 0.1.4: the one-shot post-mutation convergence read (session-gated,
        # read-only -- it dispatches no mutation and changes nothing).
        if path == "/api/v1/clients/convergence":
            self._require_session(self._handle_e3_convergence)
            return
        # 0.2.0 (#33 P1): the incident-timeline read (session-gated, GET-only,
        # bounded since/limit -- no arbitrary SQL, no arbitrary filters).
        if path == "/api/v1/diagnostics/timeline":
            self._require_session(self._handle_diagnostics_timeline)
            return
        # 0.6.0 (#33 PR-5, #63 R2 §4): the closed incidents read family.
        if path == "/api/v1/incidents":
            self._require_session(self._handle_incidents)
            return
        if path.startswith("/api/v1/incidents/"):
            suffix = path[len("/api/v1/incidents/"):]
            if suffix == "rearm":
                # rearm is POST-only by contract: a GET here is a method
                # error on a known route, never a silent 404.
                self._method_not_allowed(allowed="POST")
                return
            if suffix.endswith('/host-evidence'):
                id_text = suffix[:-len('/host-evidence')]
                incident_id = parse_positive_id(id_text)
                if incident_id is not None and id_text == str(incident_id):
                    self._require_session(self._handle_incident_host, incident_id)
                else:
                    self._send_json(404, {"error": "incident_not_found"})
                return
            if suffix.endswith('/remote-probes'):
                id_text = suffix[:-len('/remote-probes')]
                incident_id = parse_positive_id(id_text)
                if incident_id is not None and id_text == str(incident_id):
                    self._require_session(self._handle_incident_remote, incident_id)
                else:
                    self._send_json(404, {"error": "incident_not_found"})
                return
            incident_id = parse_positive_id(suffix)
            if incident_id is not None:
                self._require_session(self._handle_incident_detail,
                                      incident_id)
                return
            # invalid SYNTAX and a valid-but-missing id share the same
            # closed 404 -- the route never confirms an arbitrary number
            self._send_json(404, {"error": "incident_not_found"})
            return
        if path == "/api/v1/evidence":
            self._require_session(self._handle_evidence)
            return
        if path == "/api/v1/markers":
            self._require_session(self._handle_markers_get)
            return
        # M4: the export endpoint exists but is POST-only. A GET there is a
        # method error on a known route, not a static miss -- answering 404
        # would make the endpoint look absent to anything probing the
        # surface. Allow names only POST; the connection is never reused.
        if path == "/api/v1/clients/export":
            self._method_not_allowed(allowed="POST")
            return
        if path == "/api/v1/session/activity":
            self._method_not_allowed(allowed="POST")
            return
        if path in P6_ROUTES:
            self._method_not_allowed(allowed="POST")
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
        # Issue #67 PR-6B: the EXACT machine-ingest route dispatches here,
        # after the global POST framing gate and the source whitelist
        # (both already ran in _route()) but BEFORE the browser
        # _cross_origin / session / CSRF spine. This is the only POST
        # route with the machine-auth exception; the recovery flow stays
        # the single WHITELIST exception.
        if path == REMOTE_INGEST_PATH:
            self._handle_remote_ingest(remote)
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
        if path == "/api/v1/session/activity":
            self._require_session(self._handle_session_activity, csrf=True)
            return
        if path == "/api/v1/step-up":
            self._require_session(self._handle_step_up, csrf=True)
            return
        op = MUTATION_ROUTES.get(path)
        if op is not None:
            if op == "client.add":
                # Add is non-step-up by product contract: the authenticated
                # session plus CSRF is sufficient. Freeze session_fp for the
                # helper audit; stepup_fp is intentionally absent.
                self._require_csrf_actor(self._handle_e3_mutation, op)
            else:
                # Destructive / control-plane mutations keep full step-up.
                self._require_step_up(self._handle_e3_mutation, op)
            return
        if path == "/api/v1/clients/export":
            # M4: the read-only sensitive delivery. POST-only by contract --
            # a GET would put the client name into URLs, access logs and
            # Referer chains. Same gate spine as the mutations (session ->
            # CSRF -> step-up with the frozen actor), then the broker's
            # FRESH management gate refuses dispatch unless the helper plane
            # is provably healthy at that moment.
            self._require_step_up(self._handle_e3_export)
            return
        if path in P6_ROUTES:
            op = P6_ROUTES[path]
            if op == 'probe.list':
                self._require_csrf_actor(self._handle_p6_request, op)
            else:
                self._require_step_up(self._handle_p6_request, op)
            return
        if path == "/api/v1/clients/convergence":
            # 0.1.4: GET-only. A POST on this route is a method error, not a
            # silent 404 -- the convergence read is a pure read and must
            # never acquire mutation-looking semantics.
            self._method_not_allowed(allowed="GET")
            return
        if path == "/api/v1/diagnostics/timeline":
            # 0.2.0: same GET-only semantics as the convergence route.
            self._method_not_allowed(allowed="GET")
            return
        # 0.6.0 (#33 PR-5, #63 R2 §4/§10/§11): the two operator mutations,
        # both behind the full step-up chain, and the method-closure
        # answers for the read family (a POST on a GET-only route is a
        # method error, never a silent 404).
        if path == "/api/v1/markers":
            self._require_step_up(self._handle_marker_post)
            return
        if path == "/api/v1/incidents/rearm":
            self._require_step_up(self._handle_rearm)
            return
        if path == "/api/v1/incidents" or \
                path.startswith("/api/v1/incidents/"):
            self._method_not_allowed(allowed="GET")
            return
        if path == "/api/v1/evidence":
            self._method_not_allowed(allowed="GET")
            return
        self._send_json(404, {"error": "not found"})

    # -- machine ingest (issue #67 PR-6B) ---------------------------------------

    def _ingest_framing_error(self):
        """Route-specific framing beyond the global POST gate.

        The global gate already refused Transfer-Encoding/chunked and the
        64 KiB ceiling. The ingest route additionally requires an EXPLICIT
        Content-Length of 1..16 KiB (checked before anything is read or
        parsed) and exactly the ``application/json`` content type.
        """
        if self.request_version != "HTTP/1.1":
            return 400, ERR_BAD_FRAMING
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 400, ERR_BAD_FRAMING
        try:
            length = int(raw)
        except (TypeError, ValueError):
            return 400, ERR_BAD_FRAMING
        if length <= 0 or length > INGEST_MAX_BODY:
            return 413, ERR_PAYLOAD_TOO_LARGE
        content_type = (self.headers.get("Content-Type") or "").strip().lower()
        if content_type != "application/json":
            return 400, ERR_CONTENT_TYPE
        return None

    def _ingest_headers(self):
        """The five exact wire headers as plain strings (missing -> None;
        the plane treats every malformed value as an authentication
        failure). No header value is ever logged or echoed."""
        return {name: self.headers.get(name) for name in INGEST_HEADERS}

    def _handle_remote_ingest(self, remote):
        """POST /api/v1/remote-probes/ingest -- machine authentication.

        Reached ONLY through the exact-path dispatch at the top of
        ``_route_post`` (after framing + whitelist, before _cross_origin/
        session/CSRF). The plane is optional: an app without one -- or with
        a DARK (not_configured) registry -- answers the same plain 404 as
        any other unknown path, so an unconfigured Monitor gains no
        surface. Every plane outcome is a closed status; the raw body is
        hashed, never logged, and never echoed.
        """
        plane = getattr(self.app, "remote_plane", None)
        if plane is None or not plane.configured():
            self._send_json(404, {"error": "not found"})
            return
        error = self._ingest_framing_error()
        if error is not None:
            if error[0] == 413:
                self.close_connection = True   # body length untrusted
            self._send_json(error[0], {"error": error[1]})
            return
        length = self._body_length()
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except OSError:
            self.close_connection = True
            return
        self._consumed = length       # exactly the declared bytes were read
        status, payload, extra = plane.handle(raw, self._ingest_headers())
        self._send_json(status, payload, extra_headers=extra)

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

    def _require_csrf_actor(self, handler, *args):
        """Session + CSRF gate with a frozen session-only audit actor.

        Used only for client.add so an authenticated user is not prompted for
        the admin password again. CSRF remains mandatory and stepup_fp is
        deliberately absent.
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
        actor = {}
        sfp = self.app.session_fingerprint(token)
        if sfp:
            actor["session_fp"] = sfp
        handler(session, *args, actor)

    def _require_step_up(self, handler, *args):
        """Session administrative authorization (Issue #67, 2026-10-03).

        Chain: live session -> session-bound CSRF -> password-login authorization.
        Password login grants this authorization atomically with the session.
        Background reads do not renew the 900s idle deadline. The legacy
        step-up fields retain the existing frozen helper audit actor format.
        Missing authorization is refused; the new UI returns to login and
        never prompts for an operation password or automatically replays it.
        Only anonymous event fingerprints cross the helper boundary.


        REVOCATION CONCURRENCY SEMANTICS (contract, aligned with M1's
        "a transaction is uncancellable once its durable intent is written"):

        * the check above is evaluated PER REQUEST, at the moment the request
          reaches the gate. Logout / password change / recovery reset-rotate
          therefore strip the step-up from every request that has NOT yet
          passed the gate -- immediately, without waiting for a deadline;
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

    def _handle_diagnostics_timeline(self, session):
        """GET /api/v1/diagnostics/timeline[?since=<epoch>&limit=<int>]

        0.2.0 (#33 P1): session-gated, read-only view of the bounded
        incident timeline. The response shape is a deny-by-default
        whitelist: exactly the sanitized columns that were PERSISTED,
        plus the category-level history health. Connection ids, source /
        destination addresses and any credential can never appear here
        for the same reason they can never appear in the database.

        0.4.0 (#33 PR-3B): the SAME bounded request also carries the v3
        probe rows (``probe_rows``, whitelisted columns, the same
        ``since``/``limit``) and the closed scheduler status
        (``probes``, projected through ``PROBE_STATUS_KEYS``). One read
        surface, one bound, no new endpoint and no new query parameter.

        0.5.0 (#33 PR-4B): the same bounded request also carries the
        incident scanner's closed 8-key status (``incident_runtime``,
        projected through ``INCIDENT_RUNTIME_STATUS_KEYS``) -- still one
        read surface, still no new endpoint and no incident rows.
        """
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        error, since, limit = timeline_query_params(
            parse_qs(urlsplit(self.path).query))
        if error is not None:
            self._send_json(400, {"error": error})
            return
        result = history.query_timeline(since=since, limit=limit)
        self._send_json(200, {
            "history": history.health(),
            "samples": result["samples"],
            "device_states": result["device_states"],
            "probe_rows": result["probe_rows"],
            "probes": self.app.probe_status(),
            "incident_runtime": self.app.incident_runtime_status(),
            "truncated": result["truncated"],
            "limit": result["limit"],
        })

    # -- P5 handlers (#33 PR-5, #63 R2 §4/§8/§10) -----------------------------
    #
    # Every response below is a deny-by-default closed projection: exactly
    # the reviewed keys, categories only from the six emittable ones,
    # evidence only over the subject-derived window, and no
    # run_id / cycle_id / fp / identity material anywhere. Timeline stays
    # byte-frozen: the incidents family never widens it.

    def _handle_incidents(self, session):
        """GET /api/v1/incidents[?state=open|closed&limit=<int>]

        The bounded incident list (#63 R2 §4): rows over the closed
        12-key projection (marker_count is a read-time join over the
        analysis window), the CURRENT closed 8-key runtime projection,
        and the CURRENT sanitized history health -- the UI must label
        that as diagnostics health, never as incident-time health."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        error, state, limit = incident_list_params(
            parse_qs(urlsplit(self.path).query))
        if error is not None:
            self._send_json(400, {"error": error})
            return
        outcome, result = history.query_incidents(state=state, limit=limit)
        if outcome != ih_outcome_ok:
            # a storage failure is never presented as a healthy empty list
            self._send_json(503, {"error": "incident history unavailable"})
            return
        rows = []
        for row in result["incidents"]:
            item = {key: row[key] for key in INCIDENT_LIST_ROW_KEYS}
            c_outcome, count = history.marker_count(
                row["analysis_start_epoch"],
                row["last_classified_end_epoch"])
            if c_outcome != ih_outcome_ok:
                # zero MEANS "no joined markers"; an unreadable marker
                # table must never masquerade as a fabricated zero on a
                # 200 list (the failure is recorded in health by the store)
                self._send_json(503,
                                {"error": "incident history unavailable"})
                return
            item["marker_count"] = count
            rows.append(item)
        self._send_json(200, {
            "incidents": rows,
            "runtime": self.app.incident_runtime_status(),
            "history": history.health(),
            "truncated": result["truncated"],
            "limit": result["limit"],
        })

    def _handle_incident_detail(self, session, incident_id):
        """GET /api/v1/incidents/<id>

        The closed detail projection (#63 R2 §4): the 12 list fields plus
        created/updated epochs, the raw bitsets, the DECODED
        evidence/unknowns as [{token, text}] (decoding authority is the
        presenter, never the browser), the deterministic 10-key L1
        summary, and the in-window markers with their closed labels. A
        missing or non-integer id is incident_not_found -- the route
        family never confirms that an arbitrary number exists."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        outcome, detail = history.incident_detail(incident_id)
        if outcome == ih_outcome_missing:
            self._send_json(404, {"error": "incident_not_found"})
            return
        if outcome != ih_outcome_ok:
            # a storage failure is never presented as a missing row
            self._send_json(503, {"error": "incident history unavailable"})
            return
        evidence_tokens = incident_presenter.bits_to_evidence(
            detail["evidence_bits"])
        unknown_tokens = incident_presenter.bits_to_unknown(
            detail["unknown_bits"])
        if evidence_tokens is None or unknown_tokens is None:
            # unreachable through the CHECK-bounded columns; a decode
            # failure is a closed 500, never a fabricated empty verdict
            self._send_json(500, {"error": "internal error"})
            return
        row = {key: detail[key] for key in INCIDENT_LIST_ROW_KEYS}
        row["marker_count"] = len(detail["markers"])
        row["created_epoch"] = detail["created_epoch"]
        row["updated_epoch"] = detail["updated_epoch"]
        row["evidence_bits"] = detail["evidence_bits"]
        row["unknown_bits"] = detail["unknown_bits"]
        row["evidence"] = incident_presenter.evidence_texts(evidence_tokens)
        row["unknowns"] = incident_presenter.unknown_texts(unknown_tokens)
        row["summary"] = incident_presenter.summarize(detail, unknown_tokens)
        row["markers"] = [dict(marker, label=incident_presenter.marker_label(
            marker["kind"])) for marker in detail["markers"]]
        self._send_json(200, row)

    def _handle_incident_host(self, session, incident_id):
        """Server-derived window only; separate supporting facts, no P5 keys."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        outcome, detail = history.incident_detail(incident_id)
        if outcome == ih_outcome_missing:
            self._send_json(404, {"error": "incident_not_found"})
            return
        if outcome != ih_outcome_ok:
            self._send_json(503, {"error": "incident history unavailable"})
            return
        plane = self.app.host_evidence
        if plane is None:
            self._send_json(503, {"error": "host evidence unavailable"})
            return
        try:
            result = plane.incident(incident_id, detail["analysis_start_epoch"],
                                    detail["last_classified_end_epoch"])
        except Exception:
            self._send_json(503, {"error": "host evidence unavailable"})
            return
        self._send_json(200, result)

    def _handle_incident_remote(self, session, incident_id):
        """P6C: separate GET-only supporting evidence, never P5 row enrichment."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        outcome, detail = history.incident_detail(incident_id)
        if outcome == ih_outcome_missing:
            self._send_json(404, {"error": "incident_not_found"})
            return
        if outcome != ih_outcome_ok:
            self._send_json(503, {"error": "incident history unavailable"})
            return
        # URL bounds/filters cannot widen or narrow the stored analysis span.
        result = incident_remote(self.app.remote_plane, incident_id,
                                 detail['analysis_start_epoch'],
                                 detail['last_classified_end_epoch'])
        self._send_json(200, result)

    def _handle_evidence(self, session):
        """GET /api/v1/evidence?section=...&incident_id=<n>|marker_id=<n>

        The SUBJECT-BOUND evidence read (#63 R2 §8): exactly one of
        incident_id / marker_id, the window derived by the SERVER (the
        incident's analysis window, or the marker's +/-900 s span) --
        arbitrary start/end browsing is structurally absent. The response
        carries the retention cutoff so the UI can say evidence may have
        aged out, and deliberately NO health field: current health must
        never be mistaken for incident-time health."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        query = parse_qs(urlsplit(self.path).query)
        section = query.get("section", [None])[0]
        if section is None or section not in EVIDENCE_SECTION_NAMES:
            self._send_json(400, {"error": "invalid_section"})
            return
        subjects = []
        if "incident_id" in query:
            subjects.append(("incident", query["incident_id"][0]))
        if "marker_id" in query:
            subjects.append(("marker", query["marker_id"][0]))
        if len(subjects) != 1:
            self._send_json(400, {"error": "invalid_subject"})
            return
        subject_type, raw_id = subjects[0]
        subject_id = parse_positive_id(raw_id)
        if subject_id is None:
            self._send_json(400, {"error": "invalid_subject"})
            return
        if subject_type == "incident":
            d_outcome, detail = history.incident_detail(subject_id)
            if d_outcome == ih_outcome_missing:
                self._send_json(404, {"error": "incident_not_found"})
                return
            if d_outcome != ih_outcome_ok:
                self._send_json(503,
                                {"error": "incident history unavailable"})
                return
            start = detail["analysis_start_epoch"]
            end = detail["last_classified_end_epoch"]
        else:
            m_outcome, marker = history.marker_get(subject_id)
            if m_outcome == ih_outcome_missing:
                self._send_json(404, {"error": "marker_not_found"})
                return
            if m_outcome != ih_outcome_ok:
                self._send_json(503,
                                {"error": "incident history unavailable"})
                return
            start = max(0.0, marker["epoch"] - MARKER_CONTEXT_SPAN_SECONDS)
            end = marker["epoch"] + MARKER_CONTEXT_SPAN_SECONDS
        e_outcome, result = history.evidence_section(section, start, end)
        if e_outcome == ih_outcome_store_unavailable:
            # a storage failure is never presented as an empty section
            self._send_json(503, {"error": "evidence unavailable"})
            return
        if e_outcome != ih_outcome_ok:
            # the window is server-derived and validated above; a shape
            # refusal reaching this point is a closed 400 regardless
            self._send_json(400, {"error": "invalid_window"})
            return
        self._send_json(200, {
            "subject": {"type": subject_type, "id": subject_id},
            "section": section,
            "window": {"start_epoch": start, "end_epoch": end},
            "rows": result["rows"],
            "truncated": result["truncated"],
            "retention_cutoff_epoch": result["retention_cutoff_epoch"],
        })

    def _handle_markers_get(self, session):
        """GET /api/v1/markers[?limit=<int>]

        The bounded marker list (#63 R2 §3), newest epoch first, each row
        the closed 5-key shape with the frozen kind label."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        error, limit = marker_list_params(
            parse_qs(urlsplit(self.path).query))
        if error is not None:
            self._send_json(400, {"error": error})
            return
        m_outcome, result = history.query_markers(limit)
        if m_outcome != ih_outcome_ok:
            # a storage failure is never presented as an empty marker list
            self._send_json(503, {"error": "incident history unavailable"})
            return
        markers = [dict(marker, label=incident_presenter.marker_label(
            marker["kind"])) for marker in result["markers"]]
        self._send_json(200, {
            "markers": markers,
            "truncated": result["truncated"],
            "limit": result["limit"],
        })

    def _handle_marker_post(self, session, actor):
        """POST /api/v1/markers {kind, epoch?}

        Append one closed-enum operator marker (#63 R2 §3). The body is
        EXACTLY {"kind": ...} or {"kind": ..., "epoch": ...} -- any other
        key is a 400, so no free-text field can ever be smuggled in. An
        explicit epoch must be a finite non-negative number within
        [now - RETENTION_SECONDS, now]: future-dated and
        older-than-retention markers are refused, never clamped. Step-up
        already happened at the gate; no Idempotency-Key exists by
        design (a local single-transaction append; a double submit
        yields two markers, which is semantically two events)."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        body = self._json_body()
        if not isinstance(body, dict) or "kind" not in body \
                or set(body) - {"kind", "epoch"}:
            self._send_json(400, {"error": "invalid_request_body"})
            return
        kind = body["kind"]
        if kind not in MARKER_KINDS:
            self._send_json(400, {"error": "invalid_marker_kind"})
            return
        if "epoch" in body:
            # PRESENCE is the contract: omission means "now"; an explicit
            # epoch -- JSON null included -- must be EXACTLY a finite,
            # non-negative, non-bool number inside the retention window.
            epoch = body["epoch"]
            # EXACT typing first: a bool is an int subclass that would
            # otherwise pass as a timestamp; a string would compare.
            if type(epoch) not in (int, float) or isinstance(epoch, bool) \
                    or not math.isfinite(epoch) or epoch < 0:
                self._send_json(400, {"error": "invalid_marker_epoch"})
                return
            now = time.time()
            if epoch > now or epoch < now - RETENTION_SECONDS:
                self._send_json(400, {"error": "invalid_marker_epoch"})
                return
        else:
            epoch = None
        m_outcome, row = history.record_marker(kind, epoch)
        if m_outcome == ih_outcome_rejected:
            # the body passed the HTTP time check but crossed the
            # retention/future boundary by the time the store checked it:
            # an honest closed 400 epoch refusal, never a persistence
            # failure and never a fabricated success
            self._send_json(400, {"error": "invalid_marker_epoch"})
            return
        if m_outcome != ih_outcome_recorded:
            # a persistence failure is a closed 503, never a fabricated
            # success and never exception text
            self._send_json(503, {"error": "marker persistence failed"})
            return
        row["label"] = incident_presenter.marker_label(row["kind"])
        self._send_json(200, row)

    def _handle_rearm(self, session, actor):
        """POST /api/v1/incidents/rearm

        The operator re-arm (#63 R2 §10). The web layer checks the
        CURRENT projected runtime (enabled AND running AND phase ==
        "rearm"); the store then re-checks the SAME preconditions
        atomically at the SQL level, so a stale web view can never re-arm
        a gate that has already moved. Success means ONLY that the
        durable gate was re-armed: the in-memory phase may stay ``rearm``
        until the next scan cadence, and the UI says exactly that."""
        history = self.app.incident_history
        if history is None:
            self._send_json(503, {"error": "incident history not enabled"})
            return
        runtime = self.app.incident_runtime_status()
        if not isinstance(runtime, dict) or not runtime.get("enabled") \
                or not runtime.get("running") \
                or runtime.get("phase") != "rearm":
            self._send_json(409, {"error": "incident_runtime_not_rearmable"})
            return
        r_outcome = history.incident_rearm()
        if r_outcome == ih_outcome_store_unavailable:
            # a persistence failure is a closed 503, never a fake 409
            self._send_json(503, {"error": "incident history unavailable"})
            return
        if r_outcome != ih_outcome_rearmed:
            self._send_json(409, {"error": "incident_runtime_not_rearmable"})
            return
        self._send_json(200, {"status": "ok"})

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
            # Existing boolean/actor vocabulary is retained; its current
            # grant originates at password login. No credential is disclosed.
            "step_up_active": session is not None
            and self.app.step_up_active(self._session_token()),
        }
        if session is not None:
            # The CSRF half of the session: safe to expose to the page's own
            # scripting context, unlike the HttpOnly session cookie.
            payload["csrf_token"] = session.get("csrf_token")
            payload["idle_remaining_seconds"] = self.app.auth.sessions.remaining(self._session_token())
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
        token = auth.login(password)
        if token is None:
            auth.login_limiter.record_failure(remote)
            self._send_json(401, {"error": "invalid password"})
            return
        auth.login_limiter.record_success(remote)
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

    def _handle_session_activity(self, session):
        # Origin/peer/session/CSRF checks precede this closed, bounded body.
        # Reads/SSE never call activity; expiry is rechecked under the mutex.
        if self._json_body() != {}:
            self._send_json(400, {"error": "invalid activity body"})
            return
        remaining = self.app.auth.sessions.activity(self._session_token())
        if remaining is None:
            self._send_json(401, {"error": "login required"})
            return
        self._send_json(200, {"status": "ok", "idle_remaining_seconds": remaining})

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

    def _handle_e3_convergence(self, session):
        """GET /api/v1/clients/convergence -> the one-shot post-mutation
        read (0.1.4).

        Session-gated and READ-ONLY: no step-up, no idempotency key, it
        changes nothing. Both reads use force=True, which defeats the TTL
        and the attempt throttle -- never the single-flight, the breaker
        or the 0.1.3 epoch rules -- so the browser learns the post-
        mutation truth in ONE response instead of racing the 2s/5s cache
        windows. Success is ALL-OR-NOTHING: ok only when BOTH the status
        and the list are FRESH; anything else answers 503 (or the helper
        verdict table) and the caller keeps its closed view -- a stale
        half-answer is exactly what the fail-closed UI must never see.
        Both payloads go through the same whitelists as the ordinary GETs
        (management.status / client.list sanitization, lock.path stripped)
        and are applied by the frontend atomically."""
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable("the E3 adapter is not wired in this build")
            return
        status = broker.status(force=True)
        if status.get("verdict_error"):
            self._e3_verdict_error(status)
            return
        if status["payload"] is None or status["transport"] != "fresh":
            self._e3_unavailable(
                "no fresh management.status is available; the view stays "
                "closed")
            return
        clients = broker.list_clients(force=True)
        if clients.get("verdict_error"):
            self._e3_verdict_error(clients)
            return
        if clients["payload"] is None or clients["transport"] != "fresh":
            self._e3_unavailable(
                "no fresh client list is available; the view stays closed")
            return
        spayload = status["payload"]
        sdata = spayload.get("data") if isinstance(spayload, dict) else {}
        cpayload = clients["payload"]
        cdata = cpayload.get("data") if isinstance(cpayload, dict) else {}
        self._send_json(200, {
            "ok": True,
            "status": {
                "ok": True,
                "transport": status["transport"],
                "as_of": iso_utc(status["as_of"]),
                "monitor_running": self.app.monitor_running(),
                "management_active": self.app.management_active(),
                "data": sanitize_e3_data("management.status", sdata or {}),
            },
            "clients": {
                "ok": True,
                "transport": clients["transport"],
                "as_of": iso_utc(clients["as_of"]),
                "data": sanitize_e3_data("client.list", cdata or {}),
            },
        })

    def _handle_e3_mutation(self, session, op, actor):
        """POST mutation -> dispatch to sbox-cm via the broker.

        Reached after an operation-specific authorization gate. client.add
        uses session + CSRF with a session-only actor; delete and the other
        privileged mutations use session + CSRF + step-up. In either case the
        actor is frozen at the gate, so later revocation cannot change the
        attribution of an already-authorized dispatch.

        Contract highlights (design §8-§11):

        * client.add/delete take the Idempotency-Key HTTP header (16..128 of
          [A-Za-z0-9._:-]), validated here and forwarded verbatim; the body
          must NOT carry a second key. The browser keeps the header across a
          401 replay and an explicit post-uncertain retry;
        * client.delete runs a FRESH (cache-bypassing) list preflight and a
          server-side confirm==name target-binding echo check before
          anything is dispatched;
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
            # Target-binding echo / defence in depth (renamed semantics in
            # 0.1.5, was "type-to-confirm"): since #36 the frontend binds
            # the confirmation to the selected row and echoes
            # confirm == name itself -- no user re-typing is involved. The
            # equality check still rejects hand-assembled or substituted
            # targets. Then the fresh-list preflight: without a
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
            if op in ("client.add", "client.delete"):
                # 0.1.3 post-mutation convergence: the helper returned a
                # CONFIRMED terminal success, so expire the status/list
                # caches BEFORE the browser learns about it -- the
                # convergence reads that follow must perform fresh helper
                # RPCs, never TTL or the watchdog. Failed, refused,
                # uncertain (504/result_unknown) and replayed-error
                # outcomes never reach this line; an idempotent replay of
                # a confirmed success invalidates again, which is
                # harmless by design.
                broker.invalidate_after_client_mutation()
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

    # -- P6B2 device lifecycle and the separate sensitive bundle read ----------

    def _p6_failure(self, code):
        # Never echo arbitrary helper detail/data on this credential surface.
        if code not in P6_ERROR_HTTP and code not in E3_ERROR_HTTP:
            code = 'E_P6_UNAVAILABLE'
        self._send_json(P6_ERROR_HTTP.get(code, E3_ERROR_HTTP.get(code, 503)),
                        {'ok': False, 'code': code, 'error': 'P6 operation unavailable',
                         'retriable': code in ('E_P6_LIVE_UNCONFIRMED', 'E_P6_UNAVAILABLE',
                                               'E_P6_CONFIRM_PENDING', 'E_P6_BUSY', 'E_LOCK')})

    def _p6_public_device(self, row):
        if type(row) is not dict:
            raise BundleError()
        public = {}
        for field, pattern in (('name', E3_NAME_RE), ('device', E3_NAME_RE),
                ('probe_id', re.compile(r'[a-z0-9-]{1,64}')),
                ('server_id', re.compile(r'[0-9a-f]{32}')),
                ('certificate_sha256', re.compile(r'[0-9a-f]{64}'))):
            value = row.get(field)
            if type(value) is not str or not pattern.fullmatch(value):
                raise BundleError()
            public[field] = value
        if row.get('desired') not in ('active', 'revoked') or row.get('verified') not in ('pending', 'active', 'revoked'):
            raise BundleError()
        epoch = row.get('verified_epoch')
        if epoch is not None and (type(epoch) is not int or epoch < 0):
            raise BundleError()
        endpoint = row.get('ingest_url')
        if type(endpoint) is not str or len(endpoint) > 256 or not re.fullmatch(
                r'https://(?:[0-9.]+|\[[0-9a-fA-F:]+\]):[0-9]+/api/v1/remote-probes/ingest', endpoint):
            raise BundleError()
        for field in ('site_label', 'path_label'):
            label=row.get(field,'')
            if type(label) is not str or not re.fullmatch(r'[ -~]{0,64}',label):
                raise BundleError()
            public[field]=label
        public.update(desired=row['desired'], verified=row['verified'], verified_epoch=epoch, ingest_url=endpoint)
        return public

    def _handle_p6_request(self, session, op, actor):
        if op == 'windows.bundle':
            self._handle_windows_client_bundle(actor)
            return
        if op == 'windows.download':
            self._handle_windows_download()
            return
        body = self._json_body()
        keys = {'name', 'device'} if op in ('probe.revoke', 'probe.resume', 'client.bundle') else \
               {'name', 'device', 'site_label', 'path_label'} if op == 'probe.enroll' else {'name'}
        if op == 'probe.revoke':
            keys |= {'probe_id'}
        allowed = keys | ({'cursor'} if op == 'probe.list' else set())
        if type(body) is not dict or not keys <= set(body) or not set(body) <= allowed:
            self._p6_failure('E_P6_SCHEMA')
            return
        for field in ('name', 'device'):
            if field in body and (type(body[field]) is not str or not E3_NAME_RE.fullmatch(body[field])):
                self._p6_failure('E_P6_SCHEMA')
                return
        if op == 'probe.revoke' and (type(body['probe_id']) is not str or
                not re.fullmatch(r'[a-z0-9-]{1,64}', body['probe_id'])):
            self._p6_failure('E_P6_SCHEMA')
            return
        if body['name'] == E3_RESERVED_NAME:
            self._p6_failure('E_RESERVED_NAME')
            return
        key = self.headers.get(IDEMPOTENCY_HEADER)
        if op == 'probe.enroll':
            if type(key) is not str or not E3_KEY_RE.fullmatch(key) or any(
                    type(body[field]) is not str or not re.fullmatch(r'[ -~]{1,64}', body[field])
                    for field in ('site_label', 'path_label')):
                self._p6_failure('E_P6_SCHEMA')
                return
            body['idempotency_key'] = key
        elif key is not None:
            self._p6_failure('E_P6_SCHEMA')
            return
        if 'cursor' in body and (type(body['cursor']) is not str or not re.fullmatch(r'[a-z0-9-]{1,64}', body['cursor'])):
            self._p6_failure('E_P6_SCHEMA')
            return
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable()
            return
        slot = op == 'client.bundle'
        if slot and not self.app.bundle_slots.acquire(blocking=False):
            self._send_json(429, {'ok': False, 'code': 'bundle_busy', 'error': 'try again later'})
            return
        try:
            generic = None
            if slot:
                # No artifact I/O or credential RPC occurs before the HTTP
                # auth spine and the broker's fresh management proof.
                broker.require_export_ready()
                _, generic = self.app.bundle_artifact()
            verdict = broker.p6_request(op, body, actor=actor)
            if verdict.get('ok') is not True:
                error = verdict.get('error')
                self._p6_failure(error.get('code') if type(error) is dict else 'E_P6_UNAVAILABLE')
                return
            data = verdict.get('data')
            if slot:
                content = assemble_p6_bundle(body['name'], body['device'], data, generic)
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="%s-%s-client-bundle.zip"' %
                                 (body['name'], body['device']))
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                for hname, hvalue in SECURITY_HEADERS:
                    self.send_header(hname, hvalue)
                self.end_headers()
                self.connection.settimeout(10)
                self.wfile.write(content)
                return
            if type(data) is not dict:
                raise BundleError()
            if op == 'probe.list':
                rows = data.get('devices')
                cursor = data.get('next_cursor')
                if type(rows) is not list or len(rows) > 64 or (cursor is not None and
                        (type(cursor) is not str or not re.fullmatch(r'[a-z0-9-]{1,64}', cursor))):
                    raise BundleError()
                result = {'devices': [self._p6_public_device(row) for row in rows], 'next_cursor': cursor}
            elif op in ('probe.enroll', 'probe.resume'):
                result = self._p6_public_device(data)
            else:
                if data.get('revoked') is not True or type(data.get('count')) is not int or not 0 <= data['count'] <= 4096:
                    raise BundleError()
                result = {'revoked': True, 'count': data['count']}
            self._send_json(200, {'ok': True, 'data': result})
        except BrokerUnavailable:
            self._e3_unavailable('fresh management gate not satisfied; P6 was not dispatched')
        except RpcTransportError as exc:
            if exc.stage == 'connect':
                self._e3_unavailable()
            else:
                self._send_json(504, {'ok': False, 'code': 'result_unknown',
                                    'error': 'retry explicitly', 'uncertain': True, 'retriable': True})
        except ArtifactError:
            self._p6_failure('E_P6_ARTIFACT')
        except BundleError:
            self._p6_failure('E_P6_BUNDLE')
        finally:
            if slot:
                self.app.bundle_slots.release()

    def _handle_windows_client_bundle(self, actor):
        # Same session/CSRF/origin spine as other private exports. Software
        # must pass authority/integrity/compatibility before credential dispatch.
        body = self._json_body()
        if type(body) is not dict or set(body) != {'name', 'device'} or any(
                type(body[k]) is not str or not E3_NAME_RE.fullmatch(body[k]) for k in ('name', 'device')) \
                or body['name'] == E3_RESERVED_NAME or self.headers.get(IDEMPOTENCY_HEADER) is not None:
            self._p6_failure('E_P6_SCHEMA')
            return
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable()
            return
        if not self.app.bundle_slots.acquire(blocking=False):
            self._send_json(429, {'ok': False, 'code': 'bundle_busy', 'error': 'try again later'})
            return
        started = False
        package = None
        deadline = time.monotonic()+60
        try:
            broker.require_export_ready()
            artifact, generic = self.app.bundle_artifact()
            with self.app.windows_distribution(artifact) as (manifest, stream):
                require_client_package(stream, manifest)
                verdict = broker.p6_request('client.bundle', body, actor=actor)
                if verdict.get('ok') is not True:
                    error = verdict.get('error')
                    self._p6_failure(error.get('code') if type(error) is dict else 'E_P6_UNAVAILABLE')
                    return
                parts = verdict.get('data')
                bundle = assemble_p6_bundle(body['name'], body['device'], parts, generic)
                package = WindowsClientPackage(stream, manifest, bundle,
                    body['name']+'-mihomo.yaml', parts['yaml'].encode('utf-8'))
                if time.monotonic()>=deadline:
                    raise DistributionError()
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="%s-%s-windows-client.zip"' % (body['name'], body['device']))
                self.send_header('Content-Length', str(package.size))
                self.send_header('X-P6-Distribution-Scope', manifest['scope'])
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                for name,value in SECURITY_HEADERS:
                    self.send_header(name,value)
                self.connection.settimeout(10)
                self.end_headers()
                started = True
                for chunk in package.chunks():
                    if time.monotonic()>=deadline:
                        raise TimeoutError()
                    self.wfile.write(chunk)
        except BrokerUnavailable:
            self._e3_unavailable('fresh management gate not satisfied; private package not dispatched')
        except RpcTransportError as exc:
            if exc.stage=='connect':
                self._e3_unavailable()
            else:
                self._send_json(504, {'ok': False, 'code': 'result_unknown', 'error': 'retry explicitly', 'uncertain': True, 'retriable': True})
        except (ArtifactError, BundleError, DistributionError, ValueError, TypeError, KeyError):
            if started:
                self.close_connection = True
            else:
                self._p6_failure('E_P6_WINDOWS_UNAVAILABLE')
        except OSError:
            self.close_connection = True
        finally:
            try:
                if package is not None:
                    package.close()
            finally:
                self.app.bundle_slots.release()

    def _handle_windows_download(self):
        # Reached through the existing whitelist/origin/session/CSRF/step-up
        # spine. Neither caller paths nor credential RPCs enter this read.
        body = self._json_body()
        if type(body) is not dict or body or self.headers.get(IDEMPOTENCY_HEADER) is not None:
            self._p6_failure('E_P6_SCHEMA')
            return
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable()
            return
        if not self.app.bundle_slots.acquire(blocking=False):
            self._send_json(429, {'ok': False, 'code': 'bundle_busy', 'error': 'try again later'})
            return
        started = False
        try:
            broker.require_export_ready()
            artifact, _ = self.app.bundle_artifact()
            with self.app.windows_distribution(artifact) as (manifest, stream):
                size = manifest['archive']['size']
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="p6-windows-%s.zip"' % manifest['scope'])
                self.send_header('Content-Length', str(size))
                self.send_header('X-P6-Distribution-Scope', manifest['scope'])
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                for name, value in SECURITY_HEADERS:
                    self.send_header(name, value)
                self.connection.settimeout(10)
                self.end_headers()
                started = True
                deadline = time.monotonic() + 60
                remaining = size
                while remaining:
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise DistributionError()
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except BrokerUnavailable:
            self._e3_unavailable('fresh management gate not satisfied; software was not read')
        except (ArtifactError, DistributionError):
            if started:
                self.close_connection = True
            else:
                self._p6_failure('E_P6_WINDOWS_UNAVAILABLE')
        except OSError:
            self.close_connection = True
        finally:
            self.app.bundle_slots.release()

    # -- M4 export: canonical YAML delivery remains unchanged ------------------

    EXPORT_MAX_BYTES = 49152   # 48 KiB; mirrors the worker cap (defence in
                               # depth -- a larger body is refused, never
                               # truncated, never forwarded to the browser)

    def _handle_e3_export(self, session, actor):
        """POST /api/v1/clients/export -> file download of the canonical
        Mihomo YAML (M4).

        Contract highlights (docs/e3-m4-client-export-design.md §7):

        * reached only after session -> CSRF -> step-up; the actor is the
          gate-frozen one (B2), exactly like the mutations;
        * the body must be EXACTLY {"name": "..."} -- any other JSON (array,
          scalar, malformed, empty) or any extra/missing/other key is a 400
          answered BEFORE the broker, so it can never dispatch an RPC;
        * NO Idempotency-Key exists for a read: header or body key is a
          400 -- the export re-renders live on every dispatch;
        * `legacy` is exportable BY DESIGN (lifecycle closure); the body
          gate is only the shape regex, existence/consistency are the
          helper's in-lock fail-closed preconditions;
        * the broker refuses (ZERO RPC) unless the breaker is closed AND a
          FRESH management.status proves active + not degraded + reconcile
          clean + lock acquirable;
        * success is served as an attachment with no-store semantics and
          bypasses the JSON deny-by-default whitelist -- the YAML is the
          intended payload, and it is written to the socket EXACTLY once,
          from this response only. Nothing about it is logged, cached,
          stored or echoed into any error body;
        * the filename is derived from the regex-validated name (never
          from helper-supplied text), so Content-Disposition cannot be
          injected.
        """
        broker = self.app.e3_broker
        if broker is None:
            self._e3_unavailable("the E3 adapter is not wired in this build")
            return

        body = self._json_body()
        if self.headers.get(IDEMPOTENCY_HEADER) is not None:
            self._send_json(400, {
                "ok": False, "code": "invalid_idempotency_key",
                "error": "client.export is read-only and accepts no "
                         "Idempotency-Key",
                "retriable": False})
            return
        if not isinstance(body, dict):
            self._send_json(400, {
                "ok": False, "code": "invalid_request_body",
                "error": 'the export body must be a JSON object exactly '
                         '{"name": "..."}',
                "retriable": False})
            return
        if "idempotency_key" in body:
            self._send_json(400, {
                "ok": False, "code": "invalid_idempotency_key",
                "error": "client.export is read-only and accepts no "
                         "Idempotency-Key",
                "retriable": False})
            return
        if set(body) != {"name"}:
            # R5: one accepted key, no extras -- an unexpected field is a
            # schema error, not something to ignore on a credential route.
            self._send_json(400, {
                "ok": False, "code": "invalid_request_body",
                "error": 'the export body must contain exactly the key '
                         '"name" and nothing else',
                "retriable": False})
            return
        name = body["name"]
        if not isinstance(name, str) or not E3_NAME_RE.match(name):
            self._send_json(400, {
                "ok": False, "code": "invalid_name",
                "error": "name missing or invalid (<=32 chars, "
                         "[A-Za-z0-9][A-Za-z0-9._-]*)",
                "retriable": False})
            return

        try:
            verdict = broker.export_client(name, actor=actor or None)
        except BrokerUnavailable:
            self._e3_unavailable(
                "the fresh management gate is not satisfied; the export "
                "was NOT dispatched")
            return
        except RpcTransportError as exc:
            if exc.stage == "connect":
                self._e3_unavailable(
                    "sbox-cm is unreachable; the export was NOT dispatched")
                return
            # A read leaves no transaction to resolve, but the frozen
            # single-dispatch rule still holds: no automatic retry.
            self._send_json(504, {
                "ok": False, "code": "result_unknown",
                "error": "the caller budget expired after dispatch; retry "
                         "explicitly",
                "retriable": True, "uncertain": True})
            return

        if not verdict.get("ok"):
            mapped = sanitize_e3_error(verdict)
            mapped.update({"ok": False,
                           "request_id": verdict.get("request_id")})
            self._send_json(E3_ERROR_HTTP.get(mapped["code"], 500), mapped)
            return

        data = verdict.get("data")
        data = data if isinstance(data, dict) else {}
        content = data.get("content")
        if data.get("format") != "mihomo-yaml" \
                or not isinstance(content, str) or not content:
            self._send_json(502, {
                "ok": False, "code": "E_INTERNAL",
                "error": "the helper returned an unexpected export payload",
                "retriable": False})
            return
        yaml_bytes = content.encode("utf-8")
        if len(yaml_bytes) > self.EXPORT_MAX_BYTES:
            self._send_json(502, {
                "ok": False, "code": "E_INTERNAL",
                "error": "the export exceeded the frozen size cap",
                "retriable": False})
            return

        filename = "%s-mihomo.yaml" % name
        self.send_response(200)
        self.send_header("Content-Type", "application/x-yaml; charset=utf-8")
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % filename)
        self.send_header("Content-Length", str(len(yaml_bytes)))
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # SECURITY_HEADERS already carries the required nosniff/CSP values;
        # only the standard no-store Cache-Control is replaced above.
        for hname, hvalue in SECURITY_HEADERS:
            self.send_header(hname, hvalue)
        self.end_headers()
        self.wfile.write(yaml_bytes)

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
            auth.set_password(new)
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
