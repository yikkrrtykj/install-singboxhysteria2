"""P6 office remote-probe agent -- issue #67 PR-6A (DARK support code).

This package is the OPTIONAL office/client-side evidence collector defined by
the frozen P6 contract (issue #67). PR-6A ships it DARK: there is no server
ingest route, no server database, no History change, no classifier change, no
UI change and no deployment surface. The agent produces canonical signed
samples and spools them durably; upload is performed only against the frozen
wire contract, and in this phase only fixtures/mock endpoints are used.

Hard boundaries (all enforced structurally, see the individual modules):

* **Reuse, never fork.** The audited E4 pieces are imported, not copied:
  ``parse_controller_url`` (loopback-only, fail-closed), ``HttpTransport``
  (structurally GET-only: ``get(path)`` is the whole request surface),
  ``check_secret_mode`` / ``_read_secret_file`` (the 0600 secret-file
  discipline) and ``parse_proxies`` (the ``/proxies`` payload semantics).
  ``monitor-v2/mihomo/`` is NOT modified: its transport is already exactly the
  narrow surface P6 needs, and adding an active-delay call to it would
  contradict that module's own documented read-only contract.
* **Active probing lives only here.** ``mihomo_probe.P6Mihomo`` exposes a
  closed set of named operations (``version``, ``proxies``, one delay test)
  over the shared transport. There is no generic method/request API, so no
  PUT/POST/PATCH/DELETE can be issued -- selection, connections, config,
  restart and upgrade are unreachable by construction.
* **No mutation of anything but our own spool.** A failing probe never
  restarts, gates or mutates Mihomo, sing-box, sbox-cm or the Monitor.
* **Bounded everywhere.** Per-request, per-slot, per-cycle and per-spool
  budgets are constants, and every unbounded input (a header, a body, a label,
  a response) is closed by grammar or length before use.
"""

from __future__ import annotations

# Payload / signature protocol version (frozen by issue #67 §6).
P6_PROTOCOL = "p6-v1"
INGEST_METHOD = "POST"
INGEST_PATH = "/api/v1/remote-probes/ingest"

# Agent-side schema version of the canonical body (PR-6A freezes body v1).
BODY_VERSION = 1

# Identity grammars (issue #67 §3/§5/§6/§13).
PROBE_ID_PATTERN = r"[a-z0-9-]{1,64}"
RUN_PATTERN = r"[0-9a-f]{32}"
SEQ_MIN = 1
SEQ_MAX = 2 ** 63 - 1

# Cadence / deadline bounds (issue #67 §4).
CADENCE_DEFAULT_SECONDS = 60.0
CADENCE_MIN_SECONDS = 30.0
CYCLE_DEADLINE_SECONDS = 20.0
DELAY_TIMEOUT_SECONDS = 5.0

# Wire body bound (issue #67 §6): route-specific, enforced before any parse.
MAX_BODY_BYTES = 16 * 1024

# Transport-freshness window for the signed sent_epoch (issue #67 §8).
SENT_EPOCH_SKEW_SECONDS = 300.0

# Closed active-probe outcome vocabulary (issue #67 §4).
OUTCOME_OK = "ok"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_INVALID = "invalid"
ACTIVE_OUTCOMES = (OUTCOME_OK, OUTCOME_TIMEOUT, OUTCOME_UNAVAILABLE,
                   OUTCOME_INVALID)

# Closed role vocabulary. Roles are ALWAYS operator-configured; a node display
# name is never parsed, matched or mapped onto a role.
ROLE_REALITY = "reality"
ROLE_HY2 = "hy2"
ROLES = (ROLE_REALITY, ROLE_HY2)

# The one dedicated, frozen P6 diagnostic destination (§2/§4). It is a
# compiled constant, never operator- or payload-supplied: arbitrary
# diagnostic URLs are an explicit P6 non-goal.
P6_DIAGNOSTIC_URL = "https://www.cloudflare.com/cdn-cgi/trace"
P6_DIAGNOSTIC_ID = "p6-dedicated"

__all__ = [
    "ACTIVE_OUTCOMES", "BODY_VERSION", "CADENCE_DEFAULT_SECONDS",
    "CADENCE_MIN_SECONDS", "CYCLE_DEADLINE_SECONDS", "DELAY_TIMEOUT_SECONDS",
    "INGEST_METHOD", "INGEST_PATH", "MAX_BODY_BYTES", "OUTCOME_INVALID",
    "OUTCOME_OK", "OUTCOME_TIMEOUT", "OUTCOME_UNAVAILABLE",
    "P6_DIAGNOSTIC_ID", "P6_DIAGNOSTIC_URL", "P6_PROTOCOL",
    "PROBE_ID_PATTERN", "ROLES", "ROLE_HY2", "ROLE_REALITY", "RUN_PATTERN",
    "SENT_EPOCH_SKEW_SECONDS", "SEQ_MAX", "SEQ_MIN",
]
