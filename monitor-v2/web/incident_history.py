"""Incident history -- bounded persistent timeline (issue #33 Phase 1).

Answers the PRIMARY question the monitor exists for: what did the system
look like during an incident that has already recovered? This module is a
pure WRITE-ALONGSIDE of the SnapshotBroker publication boundary: it never
feeds back into traffic accounting, never mutates sing-box, and never
touches the E1 lifecycle model.

Safety contract (all enforced, all tested):

* Storage: ``<data-root>/diagnostics/`` must be a REAL directory at 0700
  and ``history.sqlite3`` absent-or-REGULAR at 0600 -- a symlink (or any
  non-directory / non-regular type) is REFUSED, never followed. SQLite
  runs ``journal_mode=DELETE`` (no stray -wal/-shm files),
  ``synchronous=FULL``, ``foreign_keys=ON`` and a bounded busy timeout.
  Schema handling is strict: a genuinely fresh DB is created at v5; an
  existing DB opens only with an exactly-declared v5 on EXACTLY the
  eleven v5 tables, or with EXACTLY the ten v4 tables (migrated FORWARD
  to v5 in one transaction), or with EXACTLY the eight v3 tables
  (migrated FORWARD all the way to v5 in one transaction), or with
  EXACTLY the seven v2 tables (migrated FORWARD all the way to v5 in one
  transaction), or with EXACTLY the three v1 tables (migrated FORWARD
  all the way to v5 in one transaction), with every pre-existing row
  preserved. Any extra unrelated table, any other declared version
  (newer, negative, malformed, hybrid) or metadata-less SQLite file is
  refused fail-closed and never mutated -- migrations are explicit and
  forward-only. A database at v5 opened by a pre-v5 build refuses on
  exactly this gate, which is what the deploy-side rollback
  compatibility gate mirrors BEFORE any mutation.
* Threading: ONE reentrant lock serializes the whole of ``open`` /
  ``on_publish`` (write + retention) / ``health`` / ``query_timeline`` /
  ``close`` against each other -- exactly one thread may touch the shared
  SQLite connection at any moment.
* Privacy: only a whitelisted projection of the decorated snapshot is
  persisted -- counters, timestamps, rates, DEVICE (API USER) names and
  INBOUND tags. Connection ids, source/destination addresses, UUIDs,
  passwords, keys, secrets, raw errors and raw snapshots NEVER enter a
  row, a parameter or a log line.
* Resilience: every public entry point swallows its own failures and
  records a sanitized health state (``enabled`` / ``degraded`` /
  ``last_error_code`` -- a code category, never exception text, paths or
  payload). A dead disk must degrade the dashboard's health chip, never
  kill the publisher thread, a reader thread or the web server. Journal
  ingest carries its OWN degraded state, composed into ``health()``:
  an ingest failure survives a successful ordinary sample write in the
  same publication and clears only when a later ingest pass completes
  with nothing blocked. NO journal-path exception ever escapes into
  the publisher path (structural refusals included): the P1 timeline
  write never acquires a dependency on journal ingest, and a missing
  continuity row is failed closed, never recreated.
* Retention: rows older than the retention horizon are deleted at
  startup and at most hourly; if the database crosses the size ceiling
  the OLDEST rows are pruned in batches until below the target size --
  ALL tables are pruned as ONE globally epoch-ordered timeline, so a
  newer row is never sacrificed while a strictly older row still exists
  in another table.
* Probe ingest (issue #33 Phase 3, PR-3B): the v3 ``network_probe_samples``
  table is the ONE network-probe surface -- one row per accepted probe
  cycle, carrying ONLY the closed engine result re-validated AT THIS
  BOUNDARY (status/error_code through the frozen 9-member vocabulary,
  latency only with ok, the canonical GLOBAL UNICAST egress IP or NULL,
  the NOT NULL exact lowercase 32-hex cycle id, UNIQUE -- one row per
  cycle). Free text, resolved
  addresses and over-long values are unconstructible: the boundary
  rejects the whole result (zero bytes written) and the CHECK
  constraints reject even a buggy direct INSERT. Egress-change
  semantics are DERIVED AT THIS BOUNDARY for all three tokens
  (``changed``/``unchanged``/``unknown``) from the reviewer-frozen
  ``classify_egress_change`` judgement recomputed against the LAST
  SUCCESSFUL PERSISTED public egress IP, and a producer claim that
  disagrees with the derivation is refused. Probe persistence carries its
  OWN degraded state (like journal ingest): a probe rejection or DB
  failure can never be swallowed by a successful sample write, and --
  critically -- a probe cycle full of ordinary NETWORK failures is
  DATA, not degradation: network-failure evidence never touches the
  probe health plane, and probe-plane degradation never claims the
  network is down.

Journal ingest (issue #33 P2, PR-2B activation):

* The Monitor NEVER reads the log source itself. It consumes only the
  reader's sanitized exchange artifacts (``ev-<seq>.jsonl``) through the
  frozen PR-2A contract in ``journal_reader/ingest_contract.py`` --
  strict filename grammar, regular-file-only, the 256 KiB hard cap,
  closed record schema re-validation, and sanitized disposition codes.
  When ``journal_reader`` is not importable (the packaged 0.2.x monitor
  release does not ship it yet) the ingest surface is inert, not broken.
* Continuity: ``journal_ingest_state.terminal_seq`` is the SOLE
  authority (v3-B4); settlement is strictly ascending from
  terminal+1 -- a terminally rejected file or a discovered gap advances
  terminal exactly ONCE, a failed apply settles NOTHING and blocks
  higher seqs for the pass. Every settlement (valid apply, rejected,
  gap) is ONE SQLite transaction that carries the terminal advance with
  it: a crash can never double-count an event batch nor leave a
  partially applied file.
* Only contract fields persist: sequence identity, the closed-class
  error records (class/proto/port-class/dest-class/fingerprint/count),
  header aggregates, reader run id and ingest timestamps. Raw journal
  lines, addresses, credentials and free text have nowhere to go --
  the record grammar rejects them at the boundary.

Incident plane (issue #33 Phase 4, PR-4B):

* The v4 ``incident_windows`` / ``incident_runtime_state`` tables are the
  persistence side of the deterministic incident lifecycle. Verdicts,
  categories and bitsets are stored ONLY in their closed CHECK-bound
  forms: six emittable categories, two closure reasons, positional
  bitsets whose 45/28 widths are pinned by the classifier's closed
  vocabularies, and the partial unique index that makes TWO OPEN
  INCIDENTS unrepresentable. No raw logs, identities, addresses or free
  text have a column to land in.
* The internal ``classifier_bundle`` reader is the ONLY evidence read
  the runtime scanner ever gets: bounded per-section row budgets, the
  already-persisted column projections, and a caller-supplied reader
  freshness token. It NEVER widens ``query_timeline`` and never feeds
  anything but the classifier.
* Incident persistence carries its OWN degraded state (fourth
  subsystem, same discipline as journal and probe): a failed window
  write can never be swallowed by a successful ordinary sample write,
  and the runtime's open-incident pointer is updated in the SAME
  transaction as the window row it mirrors, so a crash can never leave
  the runtime pointing at a row that does not exist.

Operator markers + the P5 read surface (issue #33 Phase 5, PR-5):

* The v5 ``operator_markers`` table holds CLOSED-ENUM event markers only
  (``tt_live_studio_login_failed`` / ``operator_event``): there is no
  free-text column, no edit and no delete -- a marker is an append-only
  fact with a timestamp, never a note pad. A marker older than the
  retention horizon or in the future is refused at the boundary, and the
  table participates in BOTH time and size retention like every other
  evidence table: markers are bounded history, not a permanent record.
* Markers never enter ``classifier_bundle()``: they are operator
  annotations, not classification input, and no bundle section reads
  them.
* The operator re-arm (``incident_rearm``) flips the durable gate the
  P4B window-limit close raised, under the SAME closed preconditions at
  the SQL level (activated, no open incident, no discovery floor,
  rearm demanded) and the SAME one-minute bucket grid the activation
  floor uses. It moves NOTHING else: activation floor, evaluated end,
  reader continuity and incident rows are untouched.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time

try:  # PR-2B activation surface: contract + schema ONLY, never the reader
    from journal_reader import ingest_contract as _journal_contract
    from journal_reader import schema as _journal_schema
    JOURNAL_CONTRACT_AVAILABLE = True
except ImportError:  # packaged monitor release does not (yet) ship the lib
    _journal_contract = None
    _journal_schema = None
    JOURNAL_CONTRACT_AVAILABLE = False

SCHEMA_VERSION = 5

DB_NAME = "history.sqlite3"

# Sampling cadence (code defaults; monitor.conf is deliberately NOT touched
# in P1 -- see issue #33 spec §9).
SAMPLE_INTERVAL_SECONDS = 5.0
DEVICE_HEARTBEAT_SECONDS = 60.0

# Retention budget: 7 days, soft target 48 MiB, hard ceiling 64 MiB.
RETENTION_SECONDS = 7 * 86400.0
RETENTION_TARGET_BYTES = 48 * 1024 * 1024
RETENTION_CEILING_BYTES = 64 * 1024 * 1024
CLEANUP_INTERVAL_SECONDS = 3600.0
PRUNE_BATCH_ROWS = 512
# One timeline, ALL tables: size pruning orders these epochs GLOBALLY
# (samples first only to settle exact ties at the cut epoch). The v2
# journal tables participate through their Monitor-clock ingest epochs;
# journal_events rides along via ON DELETE CASCADE with journal_runs.
# PR-5: operator markers join the SAME accounting (bounded history, not a
# permanent record -- #63 R2 §3).
_PRUNE_SOURCES = (
    ("timeline_samples", "epoch"),
    ("device_protocol_states", "epoch"),
    ("network_probe_samples", "epoch"),
    ("journal_runs", "ingested_epoch"),
    ("journal_ingest_audit", "epoch"),
    ("operator_markers", "epoch"),
)

# Read surface bounds (spec §8): bounded, no arbitrary filters.
QUERY_LIMIT_DEFAULT = 500
QUERY_LIMIT_MAX = 2000

BUSY_TIMEOUT_MS = 2000

# Sanitized failure codes: the ONLY error detail that ever leaves this
# module (health object / logs stay category-level, never exception text).
CODE_DIR_UNSAFE = "history_dir_unsafe"
CODE_DB_UNSAFE = "history_db_unsafe"
CODE_OPEN_FAILED = "history_open_failed"
CODE_SCHEMA_UNSUPPORTED = "history_schema_unsupported"
CODE_WRITE_FAILED = "history_write_failed"
CODE_RETENTION_FAILED = "history_retention_failed"
CODE_READ_FAILED = "history_read_failed"
CODE_INGEST_APPLY_FAILED = "history_ingest_apply_failed"
# PR-3B probe plane: CODE_PROBE_PERSIST_FAILED is the storage-side
# refusal (the row could not be written at all); CODE_PROBE_RESULT_REJECTED
# is the boundary-side refusal (a result that is not a closed engine
# object -- zero bytes written). Neither is EVER a network-failure code:
# failed probes persist as data; only refusal to persist degrades here.
CODE_PROBE_PERSIST_FAILED = "history_probe_persist_failed"
CODE_PROBE_RESULT_REJECTED = "history_probe_result_rejected"
# B7-B: the journal exchange directory could not be enumerated AT ALL
# (missing, not searchable for this identity, not a directory). Distinct
# from an empty directory on purpose: "I could not look" is a storage
# failure, "I looked and found nothing" is a clean pass.
CODE_EXCHANGE_UNREADABLE = "history_journal_exchange_unreadable"
# PR-4B incident plane: the storage-side refusal for an incident window
# or runtime-state write. Like the probe plane this is persistence-side
# only -- a refused evidence bundle or a quiet analysis window is DATA
# and never degrades here.
CODE_HISTORY_INCIDENT_PERSIST_FAILED = "history_incident_persist_failed"

# -- journal ingest surface (issue #33 P2, PR-2B) -----------------------------

# Reader-owned exchange dir; pass None to disable the ingest path.
JOURNAL_DEFAULT_EXCHANGE_DIR = "/var/lib/sbox-journal/out"
# One pass per reader poll window (the reader writes a file at most once
# per WINDOW_SECONDS -- faster polling proves nothing).
JOURNAL_INGEST_INTERVAL_SECONDS = 10.0
# PR-2A frozen heartbeat semantics: reader staleness is Monitor-derived
# from this file's age and nothing else. NEVER re-tune the number here.
JOURNAL_HB_NAME = "hb"
JOURNAL_HB_STALE_SECONDS = 180.0
JOURNAL_HB_MAX_BYTES = 4096

# Mirrors of the PR-2A closed enums (journal_reader.schema). They MUST
# equal the live contract -- asserted by the ingest suite -- because the
# v2 CHECK constraints must be creatable even in a packaged release that
# does not ship journal_reader.
JOURNAL_BOUNDARIES = ("NONE", "COLD_START", "SOURCE_GAP")
JOURNAL_CLASSES = ("dns", "dial_timeout", "reset", "net_unreachable",
                   "tls_handshake", "quic_error", "eof_cancel", "other")
JOURNAL_PROTOS = ("Reality", "Hysteria2", "OTHER")
# 'NONE' is the reviewed DB sentinel for a wire-null dcls (v2-R1);
# port uses the integer sentinel 0.
JOURNAL_DCLS = ("NONE", "https443", "http80", "quic", "dns53", "dot853",
                "smtpish", "other")
JOURNAL_AUDIT_KINDS = ("gap", "rejected")
# Closed vocabulary for journal_ingest_audit.code: the sanitized
# disposition codes the frozen PR-2A contract can EVER return
# (ingest_contract.read_and_validate + schema.parse_exchange_text) plus
# the Monitor-derived gap marker. Anything outside this set -- a future
# contract code, let alone free text -- is refused by the DB CHECK, so
# the audit table cannot store a credential-like string even if a
# caller is buggy. The ingest suite asserts this tuple equals the code
# literals present in the contract sources, so the mirror cannot rot.
JOURNAL_AUDIT_CODES = ("sequence_gap", "exchange_bad_json",
                       "exchange_bad_name", "exchange_bad_shape",
                       "exchange_empty", "exchange_event_invalid",
                       "exchange_header_invalid",
                       "exchange_header_position", "exchange_no_header",
                       "exchange_not_regular", "exchange_seq_mismatch",
                       "exchange_too_large", "exchange_unreadable")

_V1_TABLES = frozenset({"timeline_samples", "device_protocol_states"})
_JOURNAL_TABLES = frozenset({"journal_runs", "journal_events",
                             "journal_ingest_audit",
                             "journal_ingest_state"})
_PROBE_TABLES = frozenset({"network_probe_samples"})
_INCIDENT_TABLES = frozenset({"incident_windows",
                              "incident_runtime_state"})
# PR-5 (#63 R2 §2): the ONE v5 table. The gate stays table-set EQUALITY --
# an extra or missing table under any declaration is refused fail-closed.
_MARKER_TABLES = frozenset({"operator_markers"})
# EXACT shapes -- the schema gate is table-set EQUALITY, not a subset:
# an unrelated extra table is a shape this module never created, so an
# open that claims v1/v2/v3/v4 while carrying one is refused fail-closed
# (zero bytes mutated), never "adopted apart from the stranger".
_META_TABLE = "meta"
_ALLOWED_V1_SHAPE = _V1_TABLES | {_META_TABLE}
_ALLOWED_V2_SHAPE = _ALLOWED_V1_SHAPE | _JOURNAL_TABLES
_ALLOWED_V3_SHAPE = _ALLOWED_V2_SHAPE | _PROBE_TABLES
_ALLOWED_V4_SHAPE = _ALLOWED_V3_SHAPE | _INCIDENT_TABLES
_ALLOWED_V5_SHAPE = _ALLOWED_V4_SHAPE | _MARKER_TABLES

# -- probe ingest surface (issue #33 Phase 3, PR-3B) ---------------------------

# Mirror of the PR-3A closed vocabulary (network_probes.ERROR_CODES).
# They MUST equal the engine's live set -- the probe suite asserts the
# mirror against the engine source, exactly like JOURNAL_AUDIT_CODES is
# asserted against the journal contract -- because the v3 CHECK
# constraints must be creatable from this module alone.
PROBE_ERROR_CODES = ("NONE", "timeout", "dns_failed", "connect_failed",
                     "tls_failed", "bad_response", "protocol_failed",
                     "parse_failed", "unavailable")
PROBE_STATUSES = ("ok", "failed")
PROBE_CHANGE_VALUES = ("unchanged", "changed", "unknown")
# Result-schema version this boundary accepts (engine RESULT_VERSION).
PROBE_RESULT_VERSION = 1
# Latency budget ceiling: strictly below the engine's own bound space
# (per-spec timeouts are < 3600 s, cycle deadlines far lower). A value
# this large can only come from a broken producer, never from a probe.
PROBE_LATENCY_MAX_MS = 120000
# Egress freshness window (seconds) for the DURABLE change baseline:
# "last successful persisted public IP" only carries change-detection
# meaning while it is plausibly the same egress session; older than the
# window (default retention horizon) it is history, not a baseline.
PROBE_EGRESS_BASELINE_WINDOW_SECONDS = RETENTION_SECONDS

# -- incident plane (issue #33 Phase 4, PR-4B) ---------------------------------

# The v4 incident tables are the FROZEN PR-4B contract (docs/
# monitor-v2-incident-runtime-p4b.md §5). The evidence/unknown columns
# are POSITIONAL bitsets: bit i of the sorted closed classifier
# vocabulary is bit i of the integer. The widths below are therefore
# PINNED by the classifier's closed vocabularies (45 evidence tokens,
# 28 unknown tokens): a future vocabulary growth overflows the DB CHECK
# and fails the write CLOSED, which is exactly what forces a schema v5
# review instead of silently shifting the meaning of stored bits.
INCIDENT_CLASSIFIER_VERSION = 1
INCIDENT_EVIDENCE_BITS_MAX = 35184372088831   # 2**45 - 1
INCIDENT_UNKNOWN_BITS_MAX = 268435455         # 2**28 - 1
# The six categories the classifier can actually emit. destination_specific
# is structurally unemittable (PR-4A) and therefore has no CHECK slot
# here either: a buggy caller cannot store what the engine cannot say.
INCIDENT_WINDOW_CATEGORIES = (
    "common_inbound_client_office", "hysteria2_udp_path",
    "insufficient_evidence", "reality_tcp_path", "vps_outbound",
    "vps_process_or_api")
INCIDENT_CLOSURE_CLEAN_BUCKETS = "clean_buckets"
INCIDENT_CLOSURE_WINDOW_LIMIT = "window_limit"
INCIDENT_CLOSURE_REASONS = (INCIDENT_CLOSURE_CLEAN_BUCKETS,
                             INCIDENT_CLOSURE_WINDOW_LIMIT)
# Window bucket-count bound: MUST equal the classifier's MAX_BUCKETS (60).
# Stated locally on purpose -- this module never imports the classifier
# (task #9's single-consumer gate) -- and mirror-checked by the lane.
INCIDENT_BUDGET_MAX = 60
# The internal bundle reader's per-section budget: one analysis window
# can carry at most this many rows from EACH evidence section (§7), the
# same bound class as QUERY_LIMIT_MAX.
CLASSIFIER_BUNDLE_ROW_BUDGET = 2000
# Closed reader freshness tokens the bundle reader accepts from its
# caller (the runtime scanner derives "fresh"/"stale"; §9). The other
# heartbeat-name tokens stay the journal reader's vocabulary -- the
# classifier consumes "stale" for ANY non-fresh runtime derivation.
CLASSIFIER_READER_STATUSES = ("fresh", "stale")

# -- operator markers + re-arm (issue #33 Phase 5, PR-5, #63 R2 §3/§10) ---------

# The closed marker kinds. There is NO free-text column: a marker is an
# append-only fact with a timestamp and a reviewed label, never a note pad.
MARKER_KINDS = ("tt_live_studio_login_failed", "operator_event")
# Exact projected columns of a marker row (deny-by-default like every
# other projection here); the label is presentation (incident_presenter),
# never storage.
MARKER_COLUMNS = ("marker_id", "epoch", "kind", "created_epoch")
# The re-arm floor uses the SAME one-minute bucket grid as the P4B
# activation floor. Stated locally on purpose -- this module never imports
# the classifier or the runtime -- and equality-gated against BOTH by the
# lanes (the classifier's BUCKET_SECONDS and the runtime's referenced
# constant are the same reviewed 60).
INCIDENT_BUCKET_SECONDS = 60

# Internal outcome tokens for the P5 operator surface (review round, #63
# R2 §6): "the row is not there", "the store could not answer" and "the
# write landed" are EXPLICIT outcomes, never inferred from a pre-existing
# global degraded flag and never collapsed into one None/False. The web
# layer maps them to 404 / 503 / 200 / 409; every token stays inside this
# module and never reaches a response body.
OUTCOME_OK = "ok"
OUTCOME_MISSING = "missing"
OUTCOME_STORE_UNAVAILABLE = "store_unavailable"
OUTCOME_REARMED = "rearmed"
OUTCOME_NOT_REARMABLE = "not_rearmable"
OUTCOME_RECORDED = "recorded"
OUTCOME_REJECTED = "rejected"


def _encode_incident_bits(tokens, maximum):
    """Boundary gate for a bitset about to be persisted: EXACTLY a plain
    non-negative int within the frozen width. The positional mapping
    itself is the classifier's property (``evidence_to_bits`` and its
    siblings), so this module validates the RESULT, not the vocabulary --
    deny-by-default on the stored integer, exactly like every other
    column here."""
    if type(tokens) is not int or isinstance(tokens, bool):
        return None
    if tokens < 0 or tokens > maximum:
        return None
    return tokens


def classify_protocol(inbound, inbound_type=""):
    """Map a connection's (INBOUND tag, inbound_type) to a protocol class.

    Deliberately an explicit, reviewed mapping -- the SAME table the UI
    uses (app.js PROTOCOL_LABELS) -- not a substring guess. The inbound
    TAG is authoritative for this deployment (vless-in carries the Reality
    clients); ``inbound_type`` is the fallback for tags not in the table.
    Anything unrecognized is counted as OTHER, never silently dropped and
    never guessed into Reality/Hysteria2.
    """
    tag_class = _INBOUND_TAG_CLASSES.get(inbound)
    if tag_class is not None:
        return tag_class
    return _INBOUND_TYPE_CLASSES.get((inbound_type or "").lower(),
                                     PROTOCOL_OTHER)


PROTOCOL_REALITY = "Reality"
PROTOCOL_HYSTERIA2 = "Hysteria2"
PROTOCOL_OTHER = "OTHER"

_INBOUND_TAG_CLASSES = {
    "vless-in": PROTOCOL_REALITY,
    "hy2-in": PROTOCOL_HYSTERIA2,
}
_INBOUND_TYPE_CLASSES = {
    "reality": PROTOCOL_REALITY,
    "vless": PROTOCOL_REALITY,      # sing-box opens Reality ON TOP of VLESS
    "hy2": PROTOCOL_HYSTERIA2,
    "hysteria2": PROTOCOL_HYSTERIA2,
}

# Exact persisted column sets (deny-by-default): a snapshot field NOT in
# this projection cannot reach the database, and a row lacking one of them
# is filled with None -- never with an arbitrary extra key.
SAMPLE_COLUMNS = (
    "epoch", "iso_utc", "run_id",
    "monitor_uptime_seconds", "snapshot_version", "snapshot_generated_at",
    "last_success_at", "collector_stale", "api_status",
    "total_active_connections", "reality_active_connections",
    "hysteria2_active_connections", "other_active_connections",
    "uplink_rate", "downlink_rate",
    "skipped_events", "duplicate_events", "identity_conflicts",
    "abandoned_on_reset",
)

DEVICE_STATE_COLUMNS = (
    "epoch", "iso_utc", "run_id", "device", "inbound",
    "active_connections", "device_status",
    "uplink_rate", "downlink_rate", "uplink_total", "downlink_total",
    "reason",
)

REASON_CHANGE = "change"
REASON_HEARTBEAT = "heartbeat"

# Exact persisted probe columns (deny-by-default like every other
# projection here): the closed v1 engine result flattened into ONE
# row, plus the derived durable egress-change token and ingest identity.
PROBE_COLUMNS = (
    "epoch", "iso_utc", "run_id", "cycle_id", "result_version",
    "dns_status", "dns_latency_ms", "dns_error_code",
    "https_status", "https_latency_ms", "https_error_code",
    "udp_status", "udp_latency_ms", "udp_error_code",
    "egress_status", "egress_latency_ms", "egress_error_code", "egress_ip",
    "egress_change",
)


def _iso(timestamp):
    return datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc).isoformat()


def _as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def project_sample(snapshot, run_id, version, now):
    """Whitelist projection of one DECORATED snapshot -> sample row.

    Reads ONLY aggregate counters / health fields. The per-connection
    lists (``connections``, ``devices[*].recent_sources``,
    ``recent_connections``, ``closed_ids``) are never traversed, so no
    connection id, source or destination can leak through this path even
    by accident.
    """
    if not isinstance(snapshot, dict):
        return None
    devices = snapshot.get("devices")
    devices = devices if isinstance(devices, dict) else {}
    reality = hy2 = other = total = 0
    up_rate = down_rate = 0.0
    for device in devices.values():
        if not isinstance(device, dict):
            continue
        protocols = device.get("protocols")
        protocols = protocols if isinstance(protocols, dict) else {}
        for inbound, proto in protocols.items():
            if not isinstance(proto, dict):
                continue
            count = _as_int(proto.get("active_connections"))
            total += count
            cls = classify_protocol(inbound, proto.get("inbound_type"))
            if cls == PROTOCOL_REALITY:
                reality += count
            elif cls == PROTOCOL_HYSTERIA2:
                hy2 += count
            else:
                other += count
        up_rate += _as_float(device.get("uplink_rate"))
        down_rate += _as_float(device.get("downlink_rate"))
    row = {
        "epoch": float(now),
        "iso_utc": _iso(now),
        "run_id": run_id,
        "monitor_uptime_seconds": snapshot.get("collector_uptime_seconds"),
        "snapshot_version": _as_int(version, -1),
        "snapshot_generated_at": snapshot.get("snapshot_generated_at")
        or snapshot.get("generated_at"),
        "last_success_at": snapshot.get("last_success_at"),
        "collector_stale": 1 if snapshot.get("stale") else 0,
        "api_status": snapshot.get("api_status"),
        "total_active_connections": _as_int(
            snapshot.get("active_connections"), total) or total,
        "reality_active_connections": reality,
        "hysteria2_active_connections": hy2,
        "other_active_connections": other,
        "uplink_rate": round(up_rate, 3),
        "downlink_rate": round(down_rate, 3),
        "skipped_events": _as_int(snapshot.get("skipped_events")),
        "duplicate_events": _as_int(snapshot.get("duplicate_events")),
        "identity_conflicts": _as_int(snapshot.get("identity_conflicts")),
        "abandoned_on_reset": _as_int(snapshot.get("abandoned_on_reset")),
    }
    return {column: row[column] for column in SAMPLE_COLUMNS}


def project_device_rows(snapshot, run_id, now):
    """Whitelist projection -> compact (device, inbound) rows.

    Only names, tags, counts, status and traffic numbers are read; the
    forbidden per-connection arrays are never touched.
    """
    rows = []
    devices = snapshot.get("devices") if isinstance(snapshot, dict) else None
    if not isinstance(devices, dict):
        return rows
    for name, device in devices.items():
        if not isinstance(name, str) or not isinstance(device, dict):
            continue
        protocols = device.get("protocols")
        protocols = protocols if isinstance(protocols, dict) else {}
        for inbound, proto in protocols.items():
            if not isinstance(inbound, str) or not isinstance(proto, dict):
                continue
            row = {
                "epoch": float(now),
                "iso_utc": _iso(now),
                "run_id": run_id,
                "device": name,
                "inbound": inbound,
                "active_connections": _as_int(proto.get("active_connections")),
                "device_status": device.get("status"),
                "uplink_rate": _as_float(proto.get("uplink_rate")),
                "downlink_rate": _as_float(proto.get("downlink_rate")),
                "uplink_total": _as_float(proto.get("uplink_total")),
                "downlink_total": _as_float(proto.get("downlink_total")),
            }
            rows.append(row)
    return rows


class IncidentHistory:
    """Bounded SQLite timeline writer + read-only query surface.

    ONE reentrant lock serializes every public critical section --
    ``open``, the whole ``on_publish`` write/retention pass, ``health``,
    ``query_timeline`` and ``close`` -- so exactly one thread ever touches
    the shared ``check_same_thread=False`` connection. Writes are rare
    (>= 5s apart) so contention is a non-issue; a reader may wait out one
    retention VACUUM (bounded by the 64 MiB ceiling), never a torn
    transaction. The lock is reentrant because internal failure
    bookkeeping re-enters it; no path acquires it twice in a way that
    could deadlock (no blocking I/O happens under ``_record_failure``).
    """

    def __init__(self, diagnostics_dir, run_id, clock=time.time,
                 monitor_version="", sample_interval=SAMPLE_INTERVAL_SECONDS,
                 heartbeat_interval=DEVICE_HEARTBEAT_SECONDS,
                 retention_seconds=RETENTION_SECONDS,
                 target_bytes=RETENTION_TARGET_BYTES,
                 ceiling_bytes=RETENTION_CEILING_BYTES,
                 cleanup_interval=CLEANUP_INTERVAL_SECONDS,
                 journal_exchange_dir=JOURNAL_DEFAULT_EXCHANGE_DIR,
                 journal_ingest_interval=JOURNAL_INGEST_INTERVAL_SECONDS):
        self._dir = diagnostics_dir
        self._db_path = os.path.join(diagnostics_dir, DB_NAME)
        self._run_id = str(run_id)
        self._clock = clock
        self._monitor_version = monitor_version
        self._sample_interval = float(sample_interval)
        self._heartbeat_interval = float(heartbeat_interval)
        self._retention_seconds = float(retention_seconds)
        self._target_bytes = float(target_bytes)
        self._ceiling_bytes = float(ceiling_bytes)
        self._cleanup_interval = float(cleanup_interval)

        self._lock = threading.RLock()
        self._conn = None
        self._enabled = False
        self._degraded = True
        self._last_error_code = None
        # Journal ingest health is a SEPARATE subsystem state: a journal
        # failure is reported through health() but a successful ordinary
        # sample write must never clear it (and vice versa) -- health()
        # composes the two. Recovery is a later ingest pass that
        # completes with nothing blocked.
        self._journal_degraded = False
        self._journal_last_error_code = None
        self._failure_count = 0
        self._last_success_ts = None
        self._last_sample_ts = None
        self._last_cleanup_ts = None
        # (device, inbound) -> {"active": n, "status": s, "written_at": t}
        self._device_state = {}
        self._pending = None  # buffered (sample, rows) after a failed write
        self._journal_exchange_dir = journal_exchange_dir
        self._journal_ingest_interval = float(journal_ingest_interval)
        self._last_journal_ingest_ts = None
        self._journal_blocked_at = None
        self._journal_last_pass = None
        # Probe ingest (PR-3B) is a THIRD independent health subsystem
        # (same discipline as journal): never cleared by the ordinary
        # write path, never confused with network-failure evidence.
        self._probe_degraded = False
        self._probe_last_error_code = None
        self._probe_persisted_total = 0
        self._probe_rejected_total = 0
        # Incident plane (PR-4B) is a FOURTH independent health
        # subsystem (same discipline): a failed incident-window or
        # runtime-state write is recorded here and can never be
        # swallowed by a successful ordinary sample write.
        self._incident_degraded = False
        self._incident_last_error_code = None
        self._incident_persisted_total = 0
        self._incident_rejected_total = 0

    # -- public surface (NONE of these ever raise) -----------------------------

    def open(self):
        """Validate storage and create/migrate the schema. Fail-soft:
        a refusal flips the health state, it never raises to the caller."""
        try:
            with self._lock:
                self._open_locked()
        except _HistoryError as exc:
            self._record_failure(exc.code)
        except (sqlite3.Error, OSError):
            self._record_failure(CODE_OPEN_FAILED)

    def on_publish(self, snapshot, version):
        """Publication-boundary hook (publisher thread).

        Takes the SAME lock as every reader and ``close``: the whole
        write/retention pass is one serialized critical section on the
        shared connection.

        Never raises: a history failure must be invisible to the broker
        loop apart from the health state, so one bad disk cannot stop the
        dashboard from serving fresh snapshots.
        """
        try:
            with self._lock:
                self._on_publish_locked(snapshot, version)
        except _HistoryError as exc:
            self._record_failure(exc.code)
        except (sqlite3.Error, OSError):
            self._record_failure(CODE_WRITE_FAILED)

    def health(self):
        with self._lock:
            # Composed surface: the ordinary write path, the journal
            # ingest path and the probe ingest path carry INDEPENDENT
            # degraded states; any one of them makes the whole history
            # degraded. The code precedence is write > journal > probe
            # (the primary data path wins), but a lower-plane code is
            # NEVER swallowed by a successful higher-plane write in the
            # same publication. Probe degradation is persistence-side
            # only -- ordinary network-failure evidence never enters it.
            degraded, code = self._evidence_health_locked()
            return {
                "enabled": bool(self._enabled),
                "degraded": degraded,
                "last_success_at": _iso(self._last_success_ts)
                if self._last_success_ts else None,
                "failure_count": int(self._failure_count),
                "last_error_code": code,
                "run_id": self._run_id,
            }

    def _evidence_health_locked(self):
        """The composed health of the three planes the CLASSIFIER reads
        (ordinary samples / journal / probe). Shared by ``health()`` and
        the bundle reader so the two surfaces cannot drift.
        ``_incident_degraded`` is deliberately NOT part of it: the
        incident persistence plane is this bundle's only consumer, so
        feeding its own degradation back into the evidence would let one
        refused close poison the next classification's health judgement
        (§7, PR-4B R2)."""
        degraded = bool(self._degraded or self._journal_degraded
                        or self._probe_degraded)
        code = self._last_error_code
        if code is None and self._journal_degraded:
            code = self._journal_last_error_code
        if code is None and self._probe_degraded:
            code = self._probe_last_error_code
        return degraded, code

    def query_timeline(self, since=None, limit=QUERY_LIMIT_DEFAULT):
        """Bounded, sanitized read of the persisted timeline.

        Returns ``{"samples": [...], "device_states": [...],
        "probe_rows": [...], "truncated": bool}`` with EXACTLY the
        whitelisted columns, or empty lists if the history is
        unreadable (health carries the reason -- reads never raise).
        The v3 probe rows ride the SAME ``since``/``limit`` bounds:
        one bounded read surface, three projections, no arbitrary
        filters.
        """
        limit = max(1, min(_as_int(limit, QUERY_LIMIT_DEFAULT),
                           QUERY_LIMIT_MAX))
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return {"samples": [], "device_states": [],
                            "probe_rows": [],
                            "truncated": False, "limit": limit}
                sample_rows = self._query_table("timeline_samples",
                                                SAMPLE_COLUMNS, since, limit)
                state_rows = self._query_table("device_protocol_states",
                                               DEVICE_STATE_COLUMNS,
                                               since, limit)
                probe_rows = self._query_table("network_probe_samples",
                                               PROBE_COLUMNS, since, limit)
        except (sqlite3.Error, OSError, ValueError):
            self._record_failure(CODE_READ_FAILED)
            return {"samples": [], "device_states": [], "probe_rows": [],
                    "truncated": False, "limit": limit}
        truncated = (len(sample_rows) > limit or len(state_rows) > limit
                     or len(probe_rows) > limit)
        samples = [_project_rows(r, SAMPLE_COLUMNS) for r in sample_rows[:limit]]
        states = [_project_rows(r, DEVICE_STATE_COLUMNS)
                  for r in state_rows[:limit]]
        probes = [_project_rows(r, PROBE_COLUMNS) for r in probe_rows[:limit]]
        samples.reverse()   # chronological order for the reader
        states.reverse()
        probes.reverse()
        return {"samples": samples, "device_states": states,
                "probe_rows": probes,
                "truncated": truncated, "limit": limit}

    def _query_table(self, table, columns, since, limit):
        select = "SELECT %s FROM %s" % (", ".join(columns), table)
        if since is None:
            return self._conn.execute(select + " ORDER BY epoch DESC"
                                      " LIMIT ?", (limit + 1,)).fetchall()
        return self._conn.execute(select + " WHERE epoch >= ?"
                                  " ORDER BY epoch DESC LIMIT ?",
                                  (float(since), limit + 1)).fetchall()

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def ingest_journal_events(self):
        """ONE cadence-independent journal ingest pass (test/operator
        entry point -- the publication path drives it via
        ``on_publish``).

        Expected operational and storage failures are fail-soft: they are
        contained here, recorded as a sanitized status/degradation code and
        reported as ``None``. A deliberately injected unexpected exception
        (for instance the crash-consistency ``RuntimeError`` a test or
        operator raises from inside the contract) is NOT swallowed by this
        direct entry point -- it propagates to the caller, which is exactly
        what lets the test prove that nothing settled on the way out. The
        publication path never sees it: ``_journal_ingest_publish_gate``
        contains every Exception of any kind one level up, so a journal
        failure can never break a P1 timeline write."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return None
                return self._journal_ingest_gate(self._clock(), force=True)
        except _HistoryError as exc:
            self._record_failure(exc.code)
            return None
        except (sqlite3.Error, OSError):
            self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
            return None

    def journal_status(self):
        """Sanitized read surface for journal ingest + reader
        availability (heartbeat age). Never raises; never echoes file
        content, paths or exception text."""
        status = {
            "enabled": False,
            "contract_available": JOURNAL_CONTRACT_AVAILABLE,
            "exchange_dir_configured": self._journal_exchange_dir is not None,
            # sanitized BOOLEAN only: distinguishes "this host never
            # activated the reader" from "provisioned storage that is
            # currently unreadable" without echoing a path.
            "exchange_dir_provisioned": self._journal_exchange_provisioned(),
            "terminal_seq": None,
            "last_consumed_seq": None,
            "gaps_total": None,
            "rejected_total": None,
            "blocked_at": self._journal_blocked_at,
            "last_pass": self._journal_last_pass,
            "reader": self._journal_reader_hb_status(),
        }
        try:
            with self._lock:
                if self._enabled and self._conn is not None:
                    row = self._conn.execute(
                        "SELECT terminal_seq, last_consumed_seq,"
                        " gaps_total, rejected_total"
                        " FROM journal_ingest_state WHERE id = 1").fetchone()
                    if row is not None:
                        status["enabled"] = True
                        status["terminal_seq"] = row[0]
                        status["last_consumed_seq"] = row[1]
                        status["gaps_total"] = row[2]
                        status["rejected_total"] = row[3]
        except (sqlite3.Error, OSError):
            self._record_failure(CODE_READ_FAILED)
        return status

    # -- probe ingest surface (issue #33 Phase 3, PR-3B) ----------------------

    def record_probe_result(self, result, egress_change=None):
        """ONE bounded probe-cycle persist (scheduler-thread entry).

        Returns True iff the row landed. Like journal ingest this is an
        INDEPENDENT health subsystem: an ordinary probe cycle full of
        network failures is DATA and returns True; only a boundary
        rejection (a result that is not a closed engine object) or a
        storage failure degrades the probe plane -- and a successful
        ordinary sample write can never swallow either. NEVER raises on
        expected conditions; the containment wrapper below is the
        publication-parity belt-and-braces line so a probe defect can
        not be heard anywhere but as a sanitized counter/code.
        """
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return False
                return self._probe_record_locked(result, egress_change,
                                                 self._clock())
        except _HistoryError as exc:
            self._record_probe_failure(exc.code)
            return False
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_probe_failure(CODE_PROBE_PERSIST_FAILED)
            return False
        except Exception:  # noqa: BLE001 -- probe plane containment
            self._rollback_quiet()
            self._record_probe_failure(CODE_PROBE_PERSIST_FAILED)
            return False

    def last_persisted_egress_ip(self):
        """The DURABLE change baseline: the egress IP of the most
        recent ACCEPTED, SUCCESSFUL probe row inside the baseline
        window, or None ("no baseline" -- restart, retention, fresh
        DB). Never raises; a read failure reports no baseline (change
        then adjudicates ``unknown``, never a fabricated event)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return None
                return self._last_persisted_egress_ip_locked()
        except (sqlite3.Error, OSError, ValueError):
            self._record_probe_failure(CODE_PROBE_PERSIST_FAILED)
            return None

    def probe_status(self):
        """Closed, sanitized probe-plane status (no endpoints, no
        results, no paths, no exception text)."""
        with self._lock:
            return {
                "enabled": bool(self._enabled),
                "degraded": bool(self._probe_degraded),
                "last_error_code": self._probe_last_error_code,
                "persisted_total": int(self._probe_persisted_total),
                "rejected_total": int(self._probe_rejected_total),
            }

    # -- incident plane surface (issue #33 Phase 4, PR-4B) ----------------------

    # Exact persisted incident-window columns (deny-by-default like every
    # other projection here).
    INCIDENT_WINDOW_COLUMNS = (
        "incident_id", "classifier_version", "state", "category",
        "analysis_start_epoch", "first_signal_epoch", "last_signal_epoch",
        "last_classified_end_epoch", "closed_epoch", "closure_reason",
        "buckets", "evidence_bits", "unknown_bits", "created_epoch",
        "updated_epoch")

    def classifier_bundle(self, window_start, window_end, reader_status):
        """THE internal evidence read the incident runtime gets (§7).

        Projects ONLY the already-persisted columns of the six evidence
        sections -- timeline_samples, device_protocol_states,
        network_probe_samples, journal_events, journal_ingest_audit and
        the health triple -- into the closed classifier bundle shape,
        bounded by CLASSIFIER_BUNDLE_ROW_BUDGET per section over
        ``window_start <= epoch < window_end``. A section that cannot
        fit its rows inside the budget REFUSES THE WHOLE BUNDLE: partial
        evidence must never be classified as if it were complete. This
        path NEVER widens ``query_timeline`` (it is a separate, narrower
        read) and its result feeds ONLY the classifier. Returns None on
        any refusal or storage failure (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return None
                return self._classifier_bundle_locked(window_start,
                                                      window_end,
                                                      reader_status)
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None

    def incident_runtime_snapshot(self):
        """Sanitized read of the runtime-state row plus the open incident
        row (None when absent). This is the webapp status object's ONLY
        incident source and the scanner's crash-recovery source. Never
        raises."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return {"state": None, "open_incident": None}
                return self._incident_runtime_snapshot_locked()
        except (sqlite3.Error, OSError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return {"state": None, "open_incident": None}

    def incident_activate(self, activation_floor_epoch):
        """One-way activation floor (§4): the first call pins WHERE
        runtime analysis may begin (no v3-era backfill); a later call
        with a DIFFERENT value is a no-op that still reports True --
        re-activation can never rewind or move the floor, so a scanner
        restart is idempotent. Returns False only on a shape/storage
        refusal (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return False
                return self._incident_activate_locked(
                    activation_floor_epoch)
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False

    def incident_open_window(self, category, analysis_start_epoch,
                             first_signal_epoch, last_signal_epoch,
                             last_classified_end_epoch, buckets,
                             evidence_bits, unknown_bits):
        """Open ONE incident window AND point the runtime state at it in
        the SAME transaction: the partial unique index refuses a second
        open, and the pointer can never outlive a crash that lost the
        row. Returns the new incident_id, or None on any refusal (never
        raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return None
                return self._incident_open_window_locked(
                    category, analysis_start_epoch, first_signal_epoch,
                    last_signal_epoch, last_classified_end_epoch, buckets,
                    evidence_bits, unknown_bits, self._clock())
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None

    def incident_update_window(self, incident_id, category,
                               last_signal_epoch,
                               last_classified_end_epoch, buckets,
                               evidence_bits, unknown_bits):
        """Refresh the SAME open row in place (§6/§8.1). The six written
        columns are ONE snapshot of ONE classification: this boundary
        does not know and does not care which category is "more specific"
        -- it enforces only the durable facts (the target row exists, is
        open, and the new values satisfy the closed CHECKs), so no
        cross-generation stitching is possible here. A non-open or
        missing target is a refusal, never a silent no-op. Returns True
        iff the row landed (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return False
                return self._incident_update_window_locked(
                    incident_id, category, last_signal_epoch,
                    last_classified_end_epoch, buckets, evidence_bits,
                    unknown_bits, self._clock())
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False

    def incident_close_window(self, incident_id, category, last_signal_epoch,
                              last_classified_end_epoch, buckets,
                              evidence_bits, unknown_bits, closure_reason):
        """Close the open row AND move the runtime gate in the SAME
        transaction (§6/§8.3): the pointer clears either way, a
        clean_buckets close re-arms discovery AT this row's signal end,
        and a window_limit close drops the discovery floor and raises
        ``rearm_required`` so automatic discovery stops fail-closed until
        an operator re-arms it. closure_reason is the frozen closed enum
        (clean_buckets / window_limit). Returns True iff the row landed
        (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return False
                return self._incident_close_window_locked(
                    incident_id, category, last_signal_epoch,
                    last_classified_end_epoch, buckets, evidence_bits,
                    unknown_bits, closure_reason, self._clock())
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False

    def incident_runtime_mark(self, last_evaluated_end_epoch,
                              reader_fresh_since_epoch):
        """Per-cycle runtime-state advance (§6/§9): how far the scanner
        has evaluated and where reader continuity currently begins. The
        open_incident_id pointer is deliberately NOT a parameter -- it
        only moves inside the open/close transactions, so a plain mark
        can never desync it. Returns True iff the mark landed (never
        raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return False
                return self._incident_runtime_mark_locked(
                    last_evaluated_end_epoch, reader_fresh_since_epoch)
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False

    def incident_status(self):
        """Closed, sanitized incident-plane status (parity with
        ``probe_status``): no categories, no windows, no exception
        text -- counters and the one code only."""
        with self._lock:
            return {
                "enabled": bool(self._enabled),
                "degraded": bool(self._incident_degraded),
                "last_error_code": self._incident_last_error_code,
                "persisted_total": int(self._incident_persisted_total),
                "rejected_total": int(self._incident_rejected_total),
            }

    # -- operator surface (issue #33 Phase 5, PR-5) ------------------------------
    #
    # The P5 read/write surface rides the SAME incident-plane health
    # subsystem (same counters, same one code): an operator write that
    # fails is the same class of persistence refusal as an incident-window
    # write, and it can never swallow or be swallowed by the ordinary
    # evidence planes.

    def record_marker(self, kind, epoch=None):
        """Append ONE closed-enum operator marker (#63 R2 §3).

        ``kind`` MUST be a member of the frozen two-token vocabulary;
        ``epoch`` (the operator-declared event time) defaults to now and
        is refused when it is not a finite non-negative epoch, lies in
        the future, or is older than the retention horizon -- a marker
        that would instantly be retention-pruned is not accepted as
        history. There is no edit and no delete: a wrong marker is
        corrected by appending another one. Returns
        ``(OUTCOME_RECORDED, row)`` with the stored 4-key row, or an
        explicit failure outcome: ``(OUTCOME_REJECTED, None)`` when the
        boundary refuses the candidate, ``(OUTCOME_STORE_UNAVAILABLE,
        None)`` when the store is disabled or the write could not land
        -- a persistence failure is never disguised as a rejection and
        never raises."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, None
                return self._record_marker_locked(kind, epoch, self._clock())
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
    def query_markers(self, limit):
        """Bounded, sanitized marker read, newest epoch first.

        Returns ``(OUTCOME_OK, {"markers", "truncated", "limit"})`` over
        the exact MARKER_COLUMNS, or
        ``(OUTCOME_STORE_UNAVAILABLE, empty)`` -- a read failure is
        distinguishable from a healthy empty marker list (never
        raises)."""
        limit = max(1, min(_as_int(limit, 1), QUERY_LIMIT_MAX))
        empty = {"markers": [], "truncated": False, "limit": limit}
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, empty
                rows = self._conn.execute(
                    "SELECT %s FROM operator_markers"
                    " ORDER BY epoch DESC, marker_id DESC LIMIT ?"
                    % ", ".join(MARKER_COLUMNS), (limit + 1,)).fetchall()
        except (sqlite3.Error, OSError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, empty
        return (OUTCOME_OK,
                {"markers": [_project_rows(row, MARKER_COLUMNS)
                             for row in rows[:limit]],
                 "truncated": len(rows) > limit, "limit": limit})
    def marker_get(self, marker_id):
        """ONE marker row over the closed columns. Returns
        ``(OUTCOME_OK, row)``, ``(OUTCOME_MISSING, None)`` when the id
        does not exist, or ``(OUTCOME_STORE_UNAVAILABLE, None)`` on a
        storage failure -- never a bare None for two different meanings
        (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, None
                if type(marker_id) is not int or isinstance(marker_id, bool) or marker_id < 1:
                    return OUTCOME_MISSING, None
                row = self._conn.execute(
                    "SELECT %s FROM operator_markers WHERE marker_id = ?"
                    % ", ".join(MARKER_COLUMNS), (marker_id,)).fetchone()
                if row is None:
                    return OUTCOME_MISSING, None
                return OUTCOME_OK, _project_rows(row, MARKER_COLUMNS)
        except (sqlite3.Error, OSError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
    def query_incidents(self, state=None, limit=QUERY_LIMIT_DEFAULT):
        """Bounded incident read, newest incident first (#63 R2 §4).

        ``state`` is None (both) or exactly 'open'/'closed'. Returns
        ``(OUTCOME_OK, {"incidents", "truncated", "limit"})`` or
        ``(OUTCOME_STORE_UNAVAILABLE, empty)`` -- a read failure is
        distinguishable from a healthy empty history (never raises)."""
        limit = max(1, min(_as_int(limit, QUERY_LIMIT_DEFAULT),
                           QUERY_LIMIT_MAX))
        empty = {"incidents": [], "truncated": False, "limit": limit}
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, empty
                if state is None:
                    rows = self._conn.execute(
                        "SELECT %s FROM incident_windows"
                        " ORDER BY incident_id DESC LIMIT ?"
                        % ", ".join(self.INCIDENT_WINDOW_COLUMNS),
                        (limit + 1,)).fetchall()
                elif state in ("open", "closed"):
                    rows = self._conn.execute(
                        "SELECT %s FROM incident_windows WHERE state = ?"
                        " ORDER BY incident_id DESC LIMIT ?"
                        % ", ".join(self.INCIDENT_WINDOW_COLUMNS),
                        (state, limit + 1)).fetchall()
                else:
                    return OUTCOME_OK, empty
        except (sqlite3.Error, OSError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, empty
        return (OUTCOME_OK,
                {"incidents": [_project_rows(row,
                                             self.INCIDENT_WINDOW_COLUMNS)
                               for row in rows[:limit]],
                 "truncated": len(rows) > limit, "limit": limit})
    def incident_detail(self, incident_id):
        """ONE incident row over the closed columns plus the markers whose
        epoch falls inside its analysis window
        (analysis_start <= epoch <= last_classified_end, the #63 R2 §4
        read join). Returns ``(OUTCOME_OK, row)``,
        ``(OUTCOME_MISSING, None)`` when the id does not exist, or
        ``(OUTCOME_STORE_UNAVAILABLE, None)`` when the store could not
        answer -- a read failure is never presented as a missing row
        (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, None
                if type(incident_id) is not int or isinstance(incident_id, bool) or incident_id < 1:
                    return OUTCOME_MISSING, None
                row = self._conn.execute(
                    "SELECT %s FROM incident_windows WHERE incident_id = ?"
                    % ", ".join(self.INCIDENT_WINDOW_COLUMNS),
                    (incident_id,)).fetchone()
                if row is None:
                    return OUTCOME_MISSING, None
                detail = _project_rows(row, self.INCIDENT_WINDOW_COLUMNS)
                markers = self._conn.execute(
                    "SELECT %s FROM operator_markers"
                    " WHERE epoch >= ? AND epoch <= ?"
                    " ORDER BY epoch ASC, marker_id ASC"
                    % ", ".join(MARKER_COLUMNS),
                    (detail["analysis_start_epoch"],
                     detail["last_classified_end_epoch"])).fetchall()
                detail["markers"] = [_project_rows(m, MARKER_COLUMNS)
                                     for m in markers]
                return OUTCOME_OK, detail
        except (sqlite3.Error, OSError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
    def marker_count(self, analysis_start_epoch, last_classified_end_epoch):
        """The list-row marker_count: a read-time count over
        ``analysis_start <= epoch <= last_classified_end`` (#63 R2 §4).
        Returns ``(OUTCOME_OK, count)`` -- where 0 MEANS "no joined
        markers" -- or ``(OUTCOME_STORE_UNAVAILABLE, None)`` when the
        marker table could not be read: a read failure is never presented
        as a fabricated zero (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, None
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM operator_markers"
                    " WHERE epoch >= ? AND epoch <= ?",
                    (analysis_start_epoch, last_classified_end_epoch)
                ).fetchone()
                return OUTCOME_OK, int(row[0])
        except (sqlite3.Error, OSError, ValueError, TypeError):
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None

    # Exact EVIDENCE wire whitelists (#63 R2 §8): subsets of the persisted
    # columns with the reader/probe identity stripped -- run_id, cycle_id,
    # result_version and the reader HMAC fp have no presentation meaning
    # and never leave the store. egress_ip is deliberately visible (#33
    # requires public-egress correlation).
    EVIDENCE_SAMPLE_COLUMNS = (
        "epoch", "iso_utc", "collector_stale", "api_status",
        "total_active_connections", "reality_active_connections",
        "hysteria2_active_connections", "other_active_connections",
        "uplink_rate", "downlink_rate",
        "skipped_events", "duplicate_events", "identity_conflicts",
        "abandoned_on_reset",
    )
    EVIDENCE_DEVICE_COLUMNS = (
        "epoch", "iso_utc", "device", "inbound", "active_connections",
        "device_status", "uplink_rate", "downlink_rate",
        "uplink_total", "downlink_total", "reason",
    )
    EVIDENCE_PROBE_COLUMNS = (
        "epoch", "iso_utc",
        "dns_status", "dns_latency_ms", "dns_error_code",
        "https_status", "https_latency_ms", "https_error_code",
        "udp_status", "udp_latency_ms", "udp_error_code",
        "egress_status", "egress_latency_ms", "egress_error_code",
        "egress_ip", "egress_change",
    )
    EVIDENCE_JOURNAL_COLUMNS = ("seq", "ts", "cls", "proto", "port",
                                "dcls", "n")
    EVIDENCE_AUDIT_COLUMNS = ("epoch", "kind", "seq", "code")

    EVIDENCE_SECTIONS_MAP = (
        ("samples", "timeline_samples", "epoch", EVIDENCE_SAMPLE_COLUMNS),
        ("device_states", "device_protocol_states", "epoch",
         EVIDENCE_DEVICE_COLUMNS),
        ("probe_rows", "network_probe_samples", "epoch",
         EVIDENCE_PROBE_COLUMNS),
        ("journal_events", "journal_events", "ts", EVIDENCE_JOURNAL_COLUMNS),
        ("audit", "journal_ingest_audit", "epoch", EVIDENCE_AUDIT_COLUMNS),
    )

    def evidence_section(self, section, start, end):
        """ONE subject-bound evidence section (#63 R2 §8).

        The window is SERVER-DERIVED (the incident's analysis window or
        the marker's +/-900 s span) -- never caller-chosen -- and this
        method re-validates it anyway: exactly a finite, ordered,
        non-negative epoch pair. Rows come back over the section's closed
        whitelist, chronological, at most CLASSIFIER_BUNDLE_ROW_BUDGET of
        them with an explicit ``truncated`` flag (honest truncation, never
        a silent drop and never the classifier's whole-bundle refusal --
        presentation may be cut, classification may not). The response
        carries ``retention_cutoff_epoch`` so the UI can say "some
        evidence may have aged out" WITHOUT a health field: current
        health must never be mistaken for incident-time health. Returns
        ``(OUTCOME_OK, result)``, ``(OUTCOME_REJECTED, None)`` when the
        window/section shape is refused here, or
        ``(OUTCOME_STORE_UNAVAILABLE, None)`` when the store could not
        answer -- a read failure is never presented as an empty section
        (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE, None
                spec = None
                for name, table, column, columns in self.EVIDENCE_SECTIONS_MAP:
                    if name == section:
                        spec = (table, column, columns)
                        break
                start_v = self._incident_epoch(start)
                end_v = self._incident_epoch(end)
                if (spec is None or start_v is None or end_v is None
                        or end_v <= start_v):
                    self._incident_rejected_total += 1
                    self._record_incident_failure(
                        CODE_HISTORY_INCIDENT_PERSIST_FAILED)
                    return OUTCOME_REJECTED, None
                table, column, columns = spec
                rows = self._conn.execute(
                    "SELECT %s FROM %s WHERE %s >= ? AND %s < ?"
                    " ORDER BY %s ASC LIMIT ?"
                    % (", ".join(columns), table, column, column, column),
                    (start_v, end_v,
                     CLASSIFIER_BUNDLE_ROW_BUDGET + 1)).fetchall()
                return (OUTCOME_OK, {
                    "rows": [_project_rows(row, columns)
                             for row in rows[:CLASSIFIER_BUNDLE_ROW_BUDGET]],
                    "truncated": len(rows) > CLASSIFIER_BUNDLE_ROW_BUDGET,
                    "retention_cutoff_epoch":
                        self._clock() - self._retention_seconds,
                })
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE, None
    def incident_rearm(self):
        """The operator re-arm (#63 R2 §10): flip the durable window-limit
        gate back to discovery, on the SAME one-minute bucket grid the
        activation floor uses, under the SAME closed preconditions at the
        SQL level. One transaction moves EXACTLY two values --
        ``rearm_required = 0`` and ``discovery_floor_epoch = floor`` --
        and touches nothing else (activation floor, evaluated end, reader
        continuity, incident rows, counters). The WHERE clause restates
        every precondition the web layer checked, so a stale web view can
        never re-arm a gate that has already moved. Returns
        ``OUTCOME_REARMED`` iff the gate was re-armed,
        ``OUTCOME_NOT_REARMABLE`` when the preconditions did not hold,
        ``OUTCOME_STORE_UNAVAILABLE`` when the store could not answer --
        a persistence failure never masquerades as a precondition
        refusal (never raises)."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return OUTCOME_STORE_UNAVAILABLE
                return self._incident_rearm_locked(self._clock())
        except _HistoryError:
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE
        except Exception:  # noqa: BLE001 -- incident plane containment
            self._rollback_quiet()
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_STORE_UNAVAILABLE

    # -- incident plane internals ------------------------------------------------

    @staticmethod
    def _incident_epoch(value):
        """EXACTLY a plain int/float epoch: finite, non-negative, not a
        bool (the probe boundary's timestamp rule, reused)."""
        if type(value) not in (int, float) or not math.isfinite(value):
            return None
        if value < 0:
            return None
        return float(value)

    def _classifier_bundle_locked(self, window_start, window_end,
                                  reader_status):
        start = self._incident_epoch(window_start)
        end = self._incident_epoch(window_end)
        if (start is None or end is None or end <= start
                or type(reader_status) is not str
                or reader_status not in CLASSIFIER_READER_STATUSES):
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        sections = (
            ("samples", "timeline_samples", "epoch", SAMPLE_COLUMNS),
            ("device_states", "device_protocol_states", "epoch",
             DEVICE_STATE_COLUMNS),
            ("probe_rows", "network_probe_samples", "epoch",
             PROBE_COLUMNS),
            ("journal_events", "journal_events", "ts",
             ("seq", "ts", "cls", "proto", "port", "dcls", "fp", "n")),
            ("audit", "journal_ingest_audit", "epoch",
             ("epoch", "kind", "seq", "code")),
        )
        evidence_degraded, evidence_code = self._evidence_health_locked()
        bundle = {
            "window": {"start_epoch": start, "end_epoch": end},
            "health": {
                "enabled": bool(self._enabled),
                "degraded": evidence_degraded,
                "last_error_code": evidence_code,
            },
            "reader": {"status": reader_status},
        }
        for name, table, column, columns in sections:
            rows = self._conn.execute(
                "SELECT %s FROM %s WHERE %s >= ? AND %s < ?"
                " ORDER BY %s ASC LIMIT ?"
                % (", ".join(columns), table, column, column, column),
                (start, end, CLASSIFIER_BUNDLE_ROW_BUDGET + 1)
            ).fetchall()
            if len(rows) > CLASSIFIER_BUNDLE_ROW_BUDGET:
                # over-budget evidence would be a silently TRUNCATED
                # view classified as if complete -- refuse the whole
                # bundle instead (§7)
                self._incident_rejected_total += 1
                self._record_incident_failure(
                    CODE_HISTORY_INCIDENT_PERSIST_FAILED)
                return None
            bundle[name] = [_project_rows(row, columns) for row in rows]
        return bundle

    def _incident_runtime_snapshot_locked(self):
        state_row = self._conn.execute(
            "SELECT runtime_version, activation_floor_epoch,"
            " last_evaluated_end_epoch, reader_fresh_since_epoch,"
            " open_incident_id, discovery_floor_epoch, rearm_required"
            " FROM incident_runtime_state"
            " WHERE id = 1").fetchone()
        state = None
        if state_row is not None:
            state = {
                "runtime_version": state_row[0],
                "activation_floor_epoch": state_row[1],
                "last_evaluated_end_epoch": state_row[2],
                "reader_fresh_since_epoch": state_row[3],
                "open_incident_id": state_row[4],
                "discovery_floor_epoch": state_row[5],
                "rearm_required": state_row[6],
            }
        open_row = None
        if state is not None and state["open_incident_id"] is not None:
            row = self._conn.execute(
                "SELECT %s FROM incident_windows WHERE incident_id = ?"
                % ", ".join(self.INCIDENT_WINDOW_COLUMNS),
                (state["open_incident_id"],)).fetchone()
            if row is not None:
                open_row = _project_rows(row, self.INCIDENT_WINDOW_COLUMNS)
        return {"state": state, "open_incident": open_row}

    def _incident_runtime_row_present_locked(self):
        if self._conn.execute(
                "SELECT id FROM incident_runtime_state"
                " WHERE id = 1").fetchone() is None:
            # a missing continuity row is NEVER silently recreated
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)

    def _incident_activate_locked(self, activation_floor_epoch):
        floor = self._incident_epoch(activation_floor_epoch)
        if floor is None:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        self._incident_runtime_row_present_locked()
        row = self._conn.execute(
            "SELECT activation_floor_epoch FROM incident_runtime_state"
            " WHERE id = 1").fetchone()
        current = float(row[0])
        if current > 0.0:
            return True  # one-way: first activation wins, restart-safe
        # The first activation owns three columns in ONE statement, so a
        # crash can never leave a floor without its discovery gate (§5).
        # activation_floor_epoch stays the one-way / no-backfill authority;
        # discovery starts where activation starts and nothing is armed
        # yet, so a fresh floor never inherits a stale rearm demand.
        self._conn.execute(
            "UPDATE incident_runtime_state SET activation_floor_epoch = ?,"
            " discovery_floor_epoch = ?, rearm_required = 0"
            " WHERE id = 1 AND activation_floor_epoch = 0.0",
            (floor, floor))
        self._conn.commit()
        return True

    def _incident_values_locked(self, category, last_signal_epoch,
                                last_classified_end_epoch, buckets,
                                evidence_bits, unknown_bits):
        """The shared closed-shape validation for every window write.
        Returns the validated tuple or None (one rejection counter, the
        raw candidate never reaches SQL)."""
        if type(category) is not str \
                or category not in INCIDENT_WINDOW_CATEGORIES:
            return None
        last_signal = self._incident_epoch(last_signal_epoch)
        classified_end = self._incident_epoch(last_classified_end_epoch)
        if last_signal is None or classified_end is None \
                or classified_end < last_signal:
            return None
        if type(buckets) is not int or isinstance(buckets, bool) \
                or buckets < 1 or buckets > INCIDENT_BUDGET_MAX:
            return None
        evidence = _encode_incident_bits(evidence_bits,
                                         INCIDENT_EVIDENCE_BITS_MAX)
        unknown = _encode_incident_bits(unknown_bits,
                                        INCIDENT_UNKNOWN_BITS_MAX)
        if evidence is None or unknown is None:
            return None
        return (category, last_signal, classified_end, buckets,
                evidence, unknown)

    def _incident_open_window_locked(self, category, analysis_start_epoch,
                                     first_signal_epoch, last_signal_epoch,
                                     last_classified_end_epoch, buckets,
                                     evidence_bits, unknown_bits, now):
        analysis_start = self._incident_epoch(analysis_start_epoch)
        first_signal = self._incident_epoch(first_signal_epoch)
        values = self._incident_values_locked(
            category, last_signal_epoch, last_classified_end_epoch,
            buckets, evidence_bits, unknown_bits)
        now = self._incident_epoch(now)
        if (analysis_start is None or first_signal is None or now is None
                or first_signal < analysis_start or values is None):
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return None
        category, last_signal, classified_end, buckets, evidence, \
            unknown = values
        self._incident_runtime_row_present_locked()
        cursor = self._conn.execute(
            "INSERT INTO incident_windows (classifier_version, state,"
            " category, analysis_start_epoch, first_signal_epoch,"
            " last_signal_epoch, last_classified_end_epoch,"
            " closed_epoch, closure_reason, buckets, evidence_bits,"
            " unknown_bits, created_epoch, updated_epoch)"
            " VALUES (?, 'open', ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?,"
            " ?, ?)",
            (INCIDENT_CLASSIFIER_VERSION, category, analysis_start,
             first_signal, last_signal, classified_end, buckets, evidence,
             unknown, now, now))
        incident_id = int(cursor.lastrowid)
        # the pointer rides the SAME transaction: both or neither
        self._conn.execute(
            "UPDATE incident_runtime_state SET open_incident_id = ?"
            " WHERE id = 1", (incident_id,))
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return incident_id

    def _incident_update_window_locked(self, incident_id, category,
                                       last_signal_epoch,
                                       last_classified_end_epoch, buckets,
                                       evidence_bits, unknown_bits, now):
        if type(incident_id) is not int or isinstance(incident_id, bool) \
                or incident_id < 1:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        values = self._incident_values_locked(
            category, last_signal_epoch, last_classified_end_epoch,
            buckets, evidence_bits, unknown_bits)
        now = self._incident_epoch(now)
        if values is None or now is None:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        category, last_signal, classified_end, buckets, evidence, \
            unknown = values
        cursor = self._conn.execute(
            "UPDATE incident_windows SET category = ?,"
            " last_signal_epoch = ?, last_classified_end_epoch = ?,"
            " buckets = ?, evidence_bits = ?, unknown_bits = ?,"
            " updated_epoch = ?"
            " WHERE incident_id = ? AND state = 'open'",
            (category, last_signal, classified_end, buckets, evidence,
             unknown, now, incident_id))
        if cursor.rowcount != 1:
            self._rollback_quiet()
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return True

    def _incident_close_window_locked(self, incident_id, category,
                                      last_signal_epoch,
                                      last_classified_end_epoch, buckets,
                                      evidence_bits, unknown_bits,
                                      closure_reason, now):
        if type(incident_id) is not int or isinstance(incident_id, bool) \
                or incident_id < 1:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        if type(closure_reason) is not str \
                or closure_reason not in INCIDENT_CLOSURE_REASONS:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        values = self._incident_values_locked(
            category, last_signal_epoch, last_classified_end_epoch,
            buckets, evidence_bits, unknown_bits)
        now = self._incident_epoch(now)
        if values is None or now is None or now < values[1]:
            # closed_epoch must not precede the signal it closes over
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        category, last_signal, classified_end, buckets, evidence, \
            unknown = values
        cursor = self._conn.execute(
            "UPDATE incident_windows SET state = 'closed', category = ?,"
            " last_signal_epoch = ?, last_classified_end_epoch = ?,"
            " buckets = ?, evidence_bits = ?, unknown_bits = ?,"
            " closed_epoch = ?, closure_reason = ?, updated_epoch = ?"
            " WHERE incident_id = ? AND state = 'open'",
            (category, last_signal, classified_end, buckets, evidence,
             unknown, now, closure_reason, now, incident_id))
        if cursor.rowcount != 1:
            self._rollback_quiet()
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        # The pointer clears in the SAME transaction as the close, and so
        # does the discovery gate (§8.3): one statement, so no crash and no
        # CHECK-visible intermediate can leave an incident closed with a
        # stale gate. A clean close re-arms discovery AT the signal end,
        # making its three clean buckets the next segment's baseline; a
        # window-limit close disarms automatic discovery entirely until an
        # operator re-arms it, and refuses to let outage rows become a new
        # baseline by dropping the floor to NULL.
        if closure_reason == INCIDENT_CLOSURE_CLEAN_BUCKETS:
            gate = (" open_incident_id = NULL, discovery_floor_epoch = ?,"
                    " rearm_required = 0")
            gate_values: tuple = (last_signal,)
        else:
            gate = (" open_incident_id = NULL, discovery_floor_epoch = NULL,"
                    " rearm_required = 1")
            gate_values = ()
        self._conn.execute(
            "UPDATE incident_runtime_state SET" + gate + " WHERE id = 1",
            gate_values)
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return True

    def _incident_runtime_mark_locked(self, last_evaluated_end_epoch,
                                      reader_fresh_since_epoch):
        evaluated = self._incident_epoch(last_evaluated_end_epoch)
        fresh = self._incident_epoch(reader_fresh_since_epoch) \
            if reader_fresh_since_epoch is not None else None
        if reader_fresh_since_epoch is not None and fresh is None:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        if evaluated is None:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return False
        self._incident_runtime_row_present_locked()
        self._conn.execute(
            "UPDATE incident_runtime_state SET"
            " last_evaluated_end_epoch = ?, reader_fresh_since_epoch = ?"
            " WHERE id = 1", (evaluated, fresh))
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return True

    def _record_marker_locked(self, kind, epoch, now):
        if type(kind) is not str or kind not in MARKER_KINDS:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_REJECTED, None
        if epoch is None:
            epoch = now
        marker_epoch = self._incident_epoch(epoch)
        current = self._incident_epoch(now)
        if (marker_epoch is None or current is None
                or marker_epoch > current
                or marker_epoch < current - self._retention_seconds):
            # future-dated or already-older-than-retention: both are
            # shapes this surface never accepts (#63 R2 §3)
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_REJECTED, None
        cursor = self._conn.execute(
            "INSERT INTO operator_markers (epoch, kind, created_epoch)"
            " VALUES (?, ?, ?)", (marker_epoch, kind, current))
        marker_id = int(cursor.lastrowid)
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return (OUTCOME_RECORDED,
                {"marker_id": marker_id, "epoch": marker_epoch,
                 "kind": kind, "created_epoch": current})
    def _incident_rearm_locked(self, now):
        current = self._incident_epoch(now)
        if current is None:
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_NOT_REARMABLE
        # The SAME bucket grid as the P4B activation floor: the re-arm
        # floor is the next whole minute boundary at/after now.
        floor = math.ceil(current / INCIDENT_BUCKET_SECONDS)             * INCIDENT_BUCKET_SECONDS
        self._incident_runtime_row_present_locked()
        cursor = self._conn.execute(
            "UPDATE incident_runtime_state SET rearm_required = 0,"
            " discovery_floor_epoch = ?"
            " WHERE id = 1 AND activation_floor_epoch > 0"
            " AND open_incident_id IS NULL AND discovery_floor_epoch IS NULL"
            " AND rearm_required = 1", (floor,))
        if cursor.rowcount != 1:
            self._rollback_quiet()
            self._incident_rejected_total += 1
            self._record_incident_failure(
                CODE_HISTORY_INCIDENT_PERSIST_FAILED)
            return OUTCOME_NOT_REARMABLE
        self._conn.commit()
        self._incident_persisted_total += 1
        self._incident_degraded = False
        self._incident_last_error_code = None
        return OUTCOME_REARMED
    def _record_incident_failure(self, code):
        # Incident plane is INDEPENDENT: never touches _degraded /
        # _journal_* / _probe_*; only a later accepted incident write
        # clears it. Pure field bookkeeping under the RLock.
        with self._lock:
            self._failure_count += 1
            self._incident_degraded = True
            self._incident_last_error_code = code

    # -- probe ingest internals ------------------------------------------------

    def _last_persisted_egress_ip_locked(self):
        row = self._conn.execute(
            "SELECT egress_ip FROM network_probe_samples"
            " WHERE egress_status = 'ok' AND egress_ip IS NOT NULL"
            " AND epoch >= ? ORDER BY epoch DESC, rowid DESC LIMIT 1",
            (self._clock() - PROBE_EGRESS_BASELINE_WINDOW_SECONDS,)
        ).fetchone()
        if row is None:
            return None
        # defense-in-depth: the stored value already passed the CHECK
        # and the boundary gate; re-canonicalize before it can inform
        # a change judgement anyway.
        return _canonical_global_ip(row[0])

    def _probe_cycle_is_new_locked(self, cycle_id):
        """Replay rule (the documented cycle identity): ONE row per
        ``cycle_id``, so a re-delivered cycle can never double-count a
        probe sample or move the baseline twice. The UNIQUE index is the
        durable wall; this read is what turns a replay into a closed
        REJECTION (a producer-side defect) instead of a storage failure.
        Bounded by retention like everything else here: an id whose row
        has aged out of the timeline is no longer a replay."""
        return self._conn.execute(
            "SELECT 1 FROM network_probe_samples WHERE cycle_id = ? LIMIT 1",
            (cycle_id,)
        ).fetchone() is None

    def _probe_boundary_validate_locked(self, result, egress_change, now):
        """Re-validate the CLOSED engine result at the DB boundary.

        The engine already enforces every one of these invariants on
        correct code; this gate exists because the DB is the last place
        a trust assumption can be checked for free. Accepts ONLY a
        strictly-typed, exact-key closed result whose three timed slots
        and egress slot each satisfy the closed transition matrix, whose
        egress IP is byte-identical to the canonical GLOBAL UNICAST form
        (the raw text is never stored, and a loopback/private/reserved/
        multicast address is rejected even if the engine above were
        buggy), whose ``cycle_id`` is the exact 32-hex token the engine
        always emits AND has not been persisted yet, and whose
        egress-change token EQUALS the one derived here from the DURABLE
        baseline -- the last successfully persisted public IP -- so a
        Monitor restart can neither fabricate nor suppress nor misdirect
        a change event. Any violation returns None (one sanitized
        rejection counter, one plane code, the raw candidate never
        reaches the table)."""
        if not _result_is_closed(result, _PROBE_RESULT_KEYS):
            return None
        if type(result["v"]) is not int or result["v"] != PROBE_RESULT_VERSION:
            return None
        epoch = result["epoch"]
        # EXACTLY a plain int/float: a bool is an int subclass that would
        # otherwise pass as a timestamp, and a subclass can carry a private
        # __float__ answering a different number each read.
        if type(epoch) not in (int, float) \
                or not math.isfinite(epoch) or epoch < 0 \
                or abs(now - epoch) > PROBE_CYCLE_FRESHNESS_SECONDS:
            return None
        cycle_id = result["cycle_id"]
        # The engine ALWAYS emits an exact lowercase 32-hex id, so NULL is
        # not a shape this boundary may adopt: an id-less row cannot be
        # traced back to a cycle and is invisible to the replay rule. A
        # non-string is a SHAPE defect refused here, with the boundary's
        # own rejection counter, never as an escaping TypeError. EXACTLY a
        # str: a subclass could answer fullmatch one way and comparison
        # another.
        if type(cycle_id) is not str \
                or _CYCLE_ID_RE.fullmatch(cycle_id) is None:
            return None
        if not self._probe_cycle_is_new_locked(cycle_id):
            return None
        row = {
            "epoch": float(epoch),
            "iso_utc": _iso(epoch),
            "run_id": self._run_id,
            "cycle_id": cycle_id,
            "result_version": PROBE_RESULT_VERSION,
        }
        for slot in ("dns", "https", "udp"):
            if not _result_is_closed(result[slot], _PROBE_CYCLE_KEYS):
                return None
            triple = _closed_code_slot(result[slot])
            if triple is None:
                return None
            row["%s_status" % slot], row["%s_latency_ms" % slot], \
                row["%s_error_code" % slot] = triple
        if not _result_is_closed(result["egress"], _PROBE_EGRESS_KEYS):
            return None
        egress = _closed_code_slot(result["egress"])
        if egress is None:
            return None
        status, latency, code = egress
        row["egress_status"] = status
        row["egress_latency_ms"] = latency
        row["egress_error_code"] = code

        raw_ip = result["egress"]["ip"]
        if status == "ok":
            if type(raw_ip) is not str:
                return None
            ip = _canonical_global_ip(raw_ip)
            # canonical-form gate: stored text must be byte-identical to
            # the canonical form (no leading zeros, no brackets, no
            # case play, no non-global address). The candidate is EXACTLY a
            # plain str by now, so this comparison cannot be answered by a
            # subclass's private __eq__ that claims identity with anything.
            if ip is None or ip != raw_ip:
                return None
        elif raw_ip is not None:
            return None
        else:
            ip = None
        row["egress_ip"] = ip

        # DERIVED HERE, NOT ACCEPTED FROM THE PRODUCER: the token is
        # recomputed from the two inputs the judgement can legitimately
        # use -- this row's canonical address and the durable baseline --
        # and a claim that disagrees is refused, for ALL THREE values. A
        # lost in-memory state, a restart or a stale view can therefore
        # neither FABRICATE an event (``changed`` with no baseline), nor
        # SUPPRESS one (``unknown`` where both addresses are valid), nor
        # invent a direction (``unchanged`` across different addresses).
        previous = self._last_persisted_egress_ip_locked()
        # EXACTLY a plain str before the vocabulary test: ``in`` over a tuple
        # compares with __eq__, so an object that always claims equality would
        # be adopted as a change token and stored.
        if type(egress_change) is not str \
                or egress_change not in PROBE_CHANGE_VALUES:
            return None
        if egress_change != _derive_egress_change(previous, ip):
            return None
        row["egress_change"] = egress_change
        return {column: row[column] for column in PROBE_COLUMNS}

    def _probe_record_locked(self, result, egress_change, now):
        row = self._probe_boundary_validate_locked(result, egress_change,
                                                   now)
        if row is None:
            self._probe_rejected_total += 1
            self._record_probe_failure(CODE_PROBE_RESULT_REJECTED)
            return False
        columns = ", ".join(PROBE_COLUMNS)
        marks = ", ".join("?" for _ in PROBE_COLUMNS)
        try:
            self._conn.execute(
                "INSERT INTO network_probe_samples (%s) VALUES (%s)"
                % (columns, marks),
                [row[c] for c in PROBE_COLUMNS])
            self._conn.commit()
        except (sqlite3.Error, OSError):
            # a failed commit settles NOTHING (single statement in
            # sqlite3 legacy mode auto-commits or rolls back whole)
            self._rollback_quiet()
            raise
        self._probe_persisted_total += 1
        # explicit recovery condition: a probe row that lands clears
        # the probe plane (same discipline as a clean journal pass).
        self._probe_degraded = False
        self._probe_last_error_code = None
        return True

    def _record_probe_failure(self, code):
        # Probe plane is INDEPENDENT: never touches _degraded /
        # _last_error_code / _journal_*; only a later accepted probe row
        # clears it. Pure field bookkeeping under the RLock.
        with self._lock:
            self._failure_count += 1
            self._probe_degraded = True
            self._probe_last_error_code = code

    # -- open / schema -----------------------------------------------------------

    def _open_locked(self):
        self._validate_dir()
        self._validate_db_file()
        # Decide BEFORE connecting whether a file already carries bytes:
        # a non-empty pre-existing SQLite file with no schema metadata is
        # an unrelated (or stripped) database and must never be claimed.
        try:
            pre_existing = os.path.getsize(self._db_path) > 0
        except OSError:
            pre_existing = False
        conn = sqlite3.connect(self._db_path, timeout=BUSY_TIMEOUT_MS / 1000.0,
                               check_same_thread=False)
        try:
            self._enforce_schema(conn, pre_existing)
            conn.commit()
        except BaseException:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            raise
        self._conn = conn
        self._enabled = True
        if os.name == "posix":
            os.chmod(self._db_path, 0o600)
        self._last_success_ts = self._clock()
        self._degraded = False
        self._last_error_code = None
        self._journal_degraded = False
        self._journal_last_error_code = None
        self._probe_degraded = False
        self._probe_last_error_code = None
        self._incident_degraded = False
        self._incident_last_error_code = None
        # startup cleanup: retention first, before any new row is added
        self._cleanup("startup")
        self._last_cleanup_ts = self._clock()

    def _validate_dir(self):
        path = self._dir
        if os.path.islink(path) or (os.path.exists(path)
                                    and not os.path.isdir(path)):
            raise _HistoryError(CODE_DIR_UNSAFE)
        if not os.path.isdir(path):
            try:
                os.makedirs(path, mode=0o700, exist_ok=True)
            except OSError:
                raise _HistoryError(CODE_DIR_UNSAFE)
        if os.name == "posix":
            try:
                os.chmod(path, 0o700)
                mode = stat.S_IMODE(os.stat(path).st_mode)
            except OSError:
                raise _HistoryError(CODE_DIR_UNSAFE)
            if mode != 0o700:
                raise _HistoryError(CODE_DIR_UNSAFE)

    def _validate_db_file(self):
        path = self._db_path
        if not os.path.exists(path):
            return
        if os.path.islink(path) or not stat.S_ISREG(os.stat(path).st_mode):
            raise _HistoryError(CODE_DB_UNSAFE)
        if os.name == "posix":
            try:
                os.chmod(path, 0o600)
                mode = stat.S_IMODE(os.stat(path).st_mode)
            except OSError:
                raise _HistoryError(CODE_DB_UNSAFE)
            if mode != 0o600:
                raise _HistoryError(CODE_DB_UNSAFE)

    def _enforce_schema(self, conn, pre_existing):
        """STRICT schema gate -- the whole DB is opened read-only-first.

        Accepted shapes are exactly six: a genuinely fresh database
        (absent or zero-byte file, no tables) which is created at the
        current version, an existing database that DECLARES the current
        schema_version and whose tables are EXACTLY the eleven v5 tables,
        an existing database that declares v4 whose tables are EXACTLY
        the ten v4 tables (migrated FORWARD to v5 in ONE transaction,
        zero v4 rows touched), an existing database that declares v3
        whose tables are EXACTLY the eight v3 tables (migrated FORWARD
        all the way to v5 in ONE transaction, zero v3 rows touched), an
        existing database that declares v2 whose tables are EXACTLY the
        seven v2 tables (migrated FORWARD all the way to v5 in ONE
        transaction, zero v2 rows touched), and an existing database that
        declares v1 whose tables are EXACTLY the three v1 tables
        (migrated FORWARD all the way to v5 in ONE transaction, zero v1
        rows touched). Any extra unrelated table (under any declaration),
        any newer, zero, negative, malformed or meta-less claim, a
        stripped or hybrid shape -- all are refused with
        CODE_SCHEMA_UNSUPPORTED before any pragma, DDL or write can touch
        the file. In particular no lower version is ever silently
        rewritten: migration is the explicit v1->v5 / v2->v5 / v3->v5 /
        v4->v5 path below and nothing else -- and a v5 file opened by a
        PRE-v5 build is refused by the SAME gate, which is the runtime
        half of the rollback compatibility contract.
        """
        conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables:
            if pre_existing:
                # a NON-empty pre-existing SQLite file without our schema
                # metadata: unrelated or stripped -- never claimed fresh
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._create_schema(conn)
            return
        row = None
        if "meta" in tables:
            row = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
        raw = row[0]
        if not isinstance(raw, str) or not re.fullmatch(r"-?\d{1,9}", raw):
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
        version = int(raw)
        if version == SCHEMA_VERSION:
            if tables != _ALLOWED_V5_SHAPE:
                # meta CLAIMS v5 but the shape is not EXACTLY the eleven
                # v5 tables -- stripped, hybrid, or carrying an
                # unrelated extra table this module never created:
                # unknown shape, refuse rather than adopt
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            if conn.execute("SELECT terminal_seq FROM journal_ingest_state"
                            " WHERE id = 1").fetchone() is None:
                # state row missing under a complete table set is an
                # unknown shape too -- never a repair
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            if conn.execute("SELECT id FROM incident_runtime_state"
                            " WHERE id = 1").fetchone() is None:
                # the incident runtime state row is the same class of
                # single-row continuity: present under every complete
                # v5 shape, never recreated when missing
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            return
        if version == 4:
            # EXACT v4 only: the ten v4 tables -- no marker table yet
            # (hybrid) and no unrelated extra table either.
            if tables != _ALLOWED_V4_SHAPE:
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._migrate_v4_to_v5(conn)
            return
        if version == 3:
            # EXACT v3 only: the eight v3 tables -- no incident tables
            # yet (hybrid) and no unrelated extra table either.
            if tables != _ALLOWED_V3_SHAPE:
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._migrate_v3_to_v5(conn)
            return
        if version == 2:
            # EXACT v2 only: the seven v2 tables -- no probe table yet
            # (hybrid) and no unrelated extra table either.
            if tables != _ALLOWED_V2_SHAPE:
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._migrate_v2_to_v5(conn)
            return
        if version == 1:
            # EXACT v1 only: precisely the three v1 tables -- no journal
            # tables (hybrid) and no unrelated extra table either (a
            # stranger table means this is not the file the migration
            # was written for)
            if tables != _ALLOWED_V1_SHAPE:
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._migrate_v1_to_v5(conn)
            return
        # NEWER, ZERO, NEGATIVE or otherwise unknown declared version:
        # refuse; an explicit forward-only migration is the ONLY way a
        # future release may adopt it.
        raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)

    def _apply_pragmas(self, conn):
        conn.execute("PRAGMA journal_mode=DELETE").fetchall()
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        # only WRITE the header when the mode actually differs: re-setting
        # an unchanged auto_vacuum still bumps the change counter, and an
        # accepted re-open of an exact v1 DB must mutate zero bytes
        if conn.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")

    def _create_schema(self, conn):
        """Fresh database: the full v5 shape in ONE explicit
        transaction (DDL auto-commits under sqlite3 legacy mode, so an
        unbounded CREATE chain could otherwise strand a half-created
        file that no later gate would adopt)."""
        now = self._clock()
        try:
            conn.execute("BEGIN")
            self._create_meta(conn, SCHEMA_VERSION, now)
            self._create_v1_tables(conn)
            self._create_journal_tables(conn)
            self._create_journal_state_row(conn, now)
            self._create_probe_table(conn)
            self._create_incident_tables(conn)
            self._create_incident_state_row(conn, now)
            self._create_marker_table(conn)
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    def _create_meta(self, conn, version, now):
        conn.execute(
            "CREATE TABLE meta ("
            " key TEXT NOT NULL PRIMARY KEY,"
            " value TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?)",
            [("schema_version", str(version)),
             ("created_at", _iso(now)),
             ("created_by_version", str(self._monitor_version))])

    @staticmethod
    def _create_v1_tables(conn):
        conn.execute(
            "CREATE TABLE timeline_samples ("
            " epoch REAL NOT NULL,"
            " iso_utc TEXT NOT NULL,"
            " run_id TEXT NOT NULL,"
            " monitor_uptime_seconds REAL,"
            " snapshot_version INTEGER,"
            " snapshot_generated_at TEXT,"
            " last_success_at TEXT,"
            " collector_stale INTEGER NOT NULL,"
            " api_status TEXT,"
            " total_active_connections INTEGER NOT NULL,"
            " reality_active_connections INTEGER NOT NULL,"
            " hysteria2_active_connections INTEGER NOT NULL,"
            " other_active_connections INTEGER NOT NULL,"
            " uplink_rate REAL NOT NULL,"
            " downlink_rate REAL NOT NULL,"
            " skipped_events INTEGER NOT NULL,"
            " duplicate_events INTEGER NOT NULL,"
            " identity_conflicts INTEGER NOT NULL,"
            " abandoned_on_reset INTEGER NOT NULL)")
        conn.execute(
            "CREATE INDEX idx_samples_epoch ON timeline_samples(epoch)")
        conn.execute(
            "CREATE TABLE device_protocol_states ("
            " epoch REAL NOT NULL,"
            " iso_utc TEXT NOT NULL,"
            " run_id TEXT NOT NULL,"
            " device TEXT NOT NULL,"
            " inbound TEXT NOT NULL,"
            " active_connections INTEGER NOT NULL,"
            " device_status TEXT,"
            " uplink_rate REAL NOT NULL,"
            " downlink_rate REAL NOT NULL,"
            " uplink_total REAL NOT NULL,"
            " downlink_total REAL NOT NULL,"
            " reason TEXT NOT NULL CHECK (reason IN ('change','heartbeat')))")
        conn.execute(
            "CREATE INDEX idx_states_epoch"
            " ON device_protocol_states(epoch)")
        conn.execute(
            "CREATE INDEX idx_states_device"
            " ON device_protocol_states(device, inbound, epoch)")

    @staticmethod
    def _in_list(values):
        return ", ".join("'%s'" % value for value in values)

    @classmethod
    def _create_journal_tables(cls, conn):
        """v2 journal tables: closed CHECKs mirror the PR-2A record
        grammar, so a raw line / address / free text CANNOT be stored
        even by a buggy caller (deny-by-default at the column level)."""
        conn.execute(
            "CREATE TABLE journal_runs ("
            " seq INTEGER NOT NULL PRIMARY KEY,"
            " run TEXT NOT NULL CHECK (length(run) = 32),"
            " source_epoch INTEGER NOT NULL CHECK (source_epoch >= 1),"
            " boundary TEXT NOT NULL"
            f" CHECK (boundary IN ({cls._in_list(JOURNAL_BOUNDARIES)})),"
            " lines INTEGER NOT NULL CHECK (lines >= 0),"
            " eligible INTEGER NOT NULL CHECK (eligible >= 0),"
            " info_dropped INTEGER NOT NULL CHECK (info_dropped >= 0),"
            " nomatch_dropped INTEGER NOT NULL"
            " CHECK (nomatch_dropped >= 0),"
            " priority_unusable INTEGER NOT NULL CHECK (priority_unusable >= 0),"
            " pfail INTEGER NOT NULL CHECK (pfail >= 0),"
            " limited INTEGER NOT NULL CHECK (limited >= 0),"
            " first_ts REAL,"
            " last_ts REAL,"
            " record_count INTEGER NOT NULL CHECK (record_count >= 0),"
            " event_count INTEGER NOT NULL CHECK (event_count >= 0),"
            " ingested_epoch REAL NOT NULL,"
            " ingested_at TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE journal_events ("
            " seq INTEGER NOT NULL"
            " REFERENCES journal_runs(seq) ON DELETE CASCADE,"
            " ts REAL NOT NULL CHECK (ts >= 0),"
            " cls TEXT NOT NULL"
            f" CHECK (cls IN ({cls._in_list(JOURNAL_CLASSES)})),"
            " proto TEXT NOT NULL"
            f" CHECK (proto IN ({cls._in_list(JOURNAL_PROTOS)})),"
            " port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),"
            " dcls TEXT NOT NULL"
            f" CHECK (dcls IN ({cls._in_list(JOURNAL_DCLS)})),"
            " fp TEXT CHECK (fp IS NULL OR (length(fp) = 16"
            " AND fp NOT GLOB '*[^0-9a-f]*')),"
            " n INTEGER NOT NULL CHECK (n >= 1),"
            # cross-field determinism, mirroring schema.validate_event
            # and the v2-R1 sentinels: fp only with 'other', dcls only
            # with a real port (0 == wire null).
            " CHECK (fp IS NULL OR cls = 'other'),"
            " CHECK (dcls = 'NONE' OR port > 0))")
        conn.execute(
            "CREATE INDEX idx_journal_events_seq"
            " ON journal_events(seq)")
        conn.execute(
            "CREATE TABLE journal_ingest_audit ("
            " epoch REAL NOT NULL,"
            " kind TEXT NOT NULL"
            f" CHECK (kind IN ({cls._in_list(JOURNAL_AUDIT_KINDS)})),"
            " seq INTEGER NOT NULL,"
            # closed vocabulary, NOT a length cap: even a buggy caller
            # cannot store free text / credential-like material here
            f" code TEXT NOT NULL CHECK (code IN"
            f" ({cls._in_list(JOURNAL_AUDIT_CODES)})))")
        conn.execute(
            "CREATE INDEX idx_journal_audit_epoch"
            " ON journal_ingest_audit(epoch)")
        conn.execute(
            "CREATE TABLE journal_ingest_state ("
            " id INTEGER PRIMARY KEY CHECK (id = 1),"
            " terminal_seq INTEGER NOT NULL CHECK (terminal_seq >= 0),"
            " last_consumed_seq INTEGER,"
            " gaps_total INTEGER NOT NULL CHECK (gaps_total >= 0),"
            " rejected_total INTEGER NOT NULL CHECK (rejected_total >= 0),"
            " updated_epoch REAL NOT NULL)")

    @staticmethod
    def _create_journal_state_row(conn, now):
        conn.execute(
            "INSERT INTO journal_ingest_state (id, terminal_seq,"
            " last_consumed_seq, gaps_total, rejected_total,"
            " updated_epoch) VALUES (1, 0, NULL, 0, 0, ?)", (now,))

    @classmethod
    def _create_probe_table(cls, conn):
        """v3 network probe table: the closed CHECKs mirror the PR-3A
        engine contract (status/error_code vocabulary, ok-iff-NONE,
        latency only with ok, egress ip = canonical GLOBAL UNICAST
        literal or NULL, cycle_id = NOT NULL exact lowercase 32-hex with
        a UNIQUE index), so free text, a resolved address or a credential
        CANNOT be stored even by a
        buggy caller -- the same deny-by-default column discipline as
        the v2 journal tables. ONE table only: the per-slot columns are
        the closed result, not rows.

        SQLite grammar: every table-level CHECK must come AFTER all
        column definitions, so the cross-field invariants are collected
        separately and appended last."""
        columns = [
            " epoch REAL NOT NULL",
            " iso_utc TEXT NOT NULL",
            " run_id TEXT NOT NULL",
            # The engine NEVER emits a cycle without an id, so the column
            # is NOT NULL and the exact lowercase 32-hex shape is the only
            # one the table can hold; the UNIQUE index below is the
            # documented cycle identity (one row per cycle).
            " cycle_id TEXT NOT NULL CHECK (length(cycle_id) = 32"
            " AND cycle_id NOT GLOB '*[^0-9a-f]*')",
            " result_version INTEGER NOT NULL CHECK (result_version = 1)",
        ]
        checks = []
        for slot in ("dns", "https", "udp"):
            columns.extend(cls._probe_slot_columns(slot))
            checks.append(cls._probe_slot_check(slot))
        columns.extend([
            " egress_status TEXT NOT NULL CHECK (egress_status IN (%s))"
            % cls._in_list(PROBE_STATUSES),
            " egress_latency_ms INTEGER",
            " egress_error_code TEXT NOT NULL"
            " CHECK (egress_error_code IN (%s))"
            % cls._in_list(PROBE_ERROR_CODES),
            # the ONLY string an accepted result may carry besides the
            # vocabulary: a canonical GLOBAL IP literal. The two GLOBs
            # are the same negated-character-class shape the v2 journal
            # fp CHECK uses ('*[^…]*' matches only when at least one
            # character is OUTSIDE the class; '[!…]' would mean the
            # opposite and reject every legal address). Comma-free by
            # construction: IPv6 canonical always carries ':'.
            " egress_ip TEXT",
            " egress_change TEXT NOT NULL"
            " CHECK (egress_change IN (%s))"
            % cls._in_list(PROBE_CHANGE_VALUES),
        ])
        checks.extend([
            " CHECK ((egress_status = 'ok' AND egress_error_code = 'NONE'"
            " AND egress_latency_ms IS NOT NULL AND egress_latency_ms >="
            " 0 AND egress_latency_ms <= %d)"
            " OR (egress_status = 'failed' AND egress_error_code <> 'NONE'"
            " AND egress_latency_ms IS NULL))" % PROBE_LATENCY_MAX_MS,
            " CHECK (egress_ip IS NULL OR ((egress_ip NOT GLOB '*,*')"
            " AND (egress_ip NOT GLOB '*[^0-9a-fA-F.:]*')))",
            " CHECK (egress_change <> 'changed' OR"
            " (egress_status = 'ok' AND egress_ip IS NOT NULL))",
            " CHECK (egress_change <> 'unchanged' OR"
            " (egress_status = 'ok' AND egress_ip IS NOT NULL))",
            # an ADDRESS IS ANSWERED ONLY BY A SUCCESSFUL EGRESS: a
            # failed lookup can never carry one, so a stored public IP
            # always names a probe that actually succeeded.
            " CHECK (egress_status <> 'failed' OR egress_ip IS NULL)",
        ])
        conn.execute("CREATE TABLE network_probe_samples (%s,%s)"
                     % (",".join(columns), ",".join(checks)))
        conn.execute(
            "CREATE INDEX idx_probe_samples_epoch"
            " ON network_probe_samples(epoch)")
        conn.execute(
            "CREATE INDEX idx_probe_samples_egress"
            " ON network_probe_samples(egress_status, epoch)")
        # THE DOCUMENTED CYCLE IDENTITY: one row per cycle_id. A replay of
        # an already-persisted cycle -- a redelivered result, a producer
        # bug, a hand-replayed file -- can never double-count a sample or
        # move the egress baseline twice.
        conn.execute(
            "CREATE UNIQUE INDEX idx_probe_samples_cycle"
            " ON network_probe_samples(cycle_id)")

    @classmethod
    def _probe_slot_columns(cls, slot):
        """The three column definitions of one timed slot; the closed
        cross-field invariant is a table-level CHECK (see
        ``_probe_slot_check``)."""
        return [
            " %s_status TEXT NOT NULL CHECK (%s_status IN (%s))"
            % (slot, slot, cls._in_list(PROBE_STATUSES)),
            " %s_latency_ms INTEGER" % slot,
            " %s_error_code TEXT NOT NULL"
            " CHECK (%s_error_code IN (%s))"
            % (slot, slot, cls._in_list(PROBE_ERROR_CODES)),
        ]

    @classmethod
    def _probe_slot_check(cls, slot):
        return (
            " CHECK ((%s_status = 'ok' AND %s_error_code = 'NONE'"
            " AND %s_latency_ms IS NOT NULL AND %s_latency_ms >="
            " 0 AND %s_latency_ms <= %d)"
            " OR (%s_status = 'failed' AND %s_error_code <> 'NONE'"
            " AND %s_latency_ms IS NULL))"
            % (slot, slot, slot, slot, slot, PROBE_LATENCY_MAX_MS, slot,
               slot, slot))

    @classmethod
    def _create_incident_tables(cls, conn):
        """v4 incident tables: the closed CHECKs mirror the FROZEN PR-4B
        contract (docs/monitor-v2-incident-runtime-p4b.md §5) -- six
        emittable categories (destination_specific is structurally
        unemittable and therefore has no CHECK slot), the two closure
        reasons, epoch ordering invariants, the positional-bitset upper
        bounds pinned by the classifier's closed vocabularies (45
        evidence / 28 unknown tokens), and the open-row CHECK pairing
        state with closed_epoch/closure_reason. The partial unique index
        is the durable ONE-OPEN-INCIDENT wall: a second concurrent open
        INSERT is a constraint violation, not a race to be managed."""
        conn.execute(
            "CREATE TABLE incident_windows ("
            " incident_id INTEGER PRIMARY KEY,"
            " classifier_version INTEGER NOT NULL"
            " CHECK (classifier_version = 1),"
            " state TEXT NOT NULL CHECK (state IN ('open','closed')),"
            " category TEXT NOT NULL CHECK (category IN (%s)),"
            " analysis_start_epoch REAL NOT NULL"
            " CHECK (analysis_start_epoch >= 0),"
            " first_signal_epoch REAL NOT NULL"
            " CHECK (first_signal_epoch >= analysis_start_epoch),"
            " last_signal_epoch REAL NOT NULL"
            " CHECK (last_signal_epoch >= first_signal_epoch),"
            " last_classified_end_epoch REAL NOT NULL"
            " CHECK (last_classified_end_epoch >= first_signal_epoch),"
            " closed_epoch REAL CHECK (closed_epoch IS NULL"
            " OR closed_epoch >= last_signal_epoch),"
            " closure_reason TEXT CHECK (closure_reason IS NULL"
            " OR closure_reason IN (%s)),"
            " buckets INTEGER NOT NULL CHECK (buckets >= 1"
            " AND buckets <= 60),"
            " evidence_bits INTEGER NOT NULL CHECK (evidence_bits"
            " BETWEEN 0 AND %d),"
            " unknown_bits INTEGER NOT NULL CHECK (unknown_bits"
            " BETWEEN 0 AND %d),"
            " created_epoch REAL NOT NULL,"
            " updated_epoch REAL NOT NULL"
            " CHECK (updated_epoch >= created_epoch),"
            " CHECK ((state = 'open' AND closed_epoch IS NULL"
            " AND closure_reason IS NULL)"
            " OR (state = 'closed' AND closed_epoch IS NOT NULL"
            " AND closure_reason IS NOT NULL)))"
            % (cls._in_list(INCIDENT_WINDOW_CATEGORIES),
               cls._in_list(INCIDENT_CLOSURE_REASONS),
               INCIDENT_EVIDENCE_BITS_MAX, INCIDENT_UNKNOWN_BITS_MAX))
        conn.execute(
            "CREATE UNIQUE INDEX ux_incident_windows_one_open"
            " ON incident_windows(state) WHERE state = 'open'")
        conn.execute(
            "CREATE TABLE incident_runtime_state ("
            " id INTEGER PRIMARY KEY CHECK (id = 1),"
            " runtime_version INTEGER NOT NULL CHECK (runtime_version = 1),"
            " activation_floor_epoch REAL NOT NULL"
            " CHECK (activation_floor_epoch >= 0),"
            " last_evaluated_end_epoch REAL NOT NULL"
            " CHECK (last_evaluated_end_epoch >= 0),"
            " reader_fresh_since_epoch REAL CHECK (reader_fresh_since_epoch"
            " IS NULL OR reader_fresh_since_epoch >= 0),"
            " open_incident_id INTEGER CHECK (open_incident_id IS NULL"
            " OR open_incident_id >= 1),"
            # PR-4B R2: the discovery gate and the rearm gate. Still v4,
            # still exactly ten tables -- the gate is durable state, not
            # scanner memory, because a restart must not un-learn that the
            # frozen window was outlived (§8.3).
            " discovery_floor_epoch REAL CHECK (discovery_floor_epoch IS"
            " NULL OR discovery_floor_epoch >= activation_floor_epoch),"
            " rearm_required INTEGER NOT NULL"
            " CHECK (rearm_required IN (0, 1)),"
            # R3 §5.1 closes the row's SHAPE from both sides: a raised rearm
            # gate owns a NULL floor and no pointer, and an ACTIVATED
            # runtime owns a discovery floor -- so an armed row can never
            # lose its floor and have the reader fall back to the wider
            # activation floor. Pre-activation (floor 0) stays exempt
            # because that is the row's birth shape: inert with a NULL
            # floor, and the first activation lands BOTH floors in one
            # statement, so no armed row is ever written without a gate.
            " CHECK ((rearm_required = 0"
            " OR (open_incident_id IS NULL"
            " AND discovery_floor_epoch IS NULL))"
            " AND (activation_floor_epoch <= 0 OR rearm_required = 1"
            " OR discovery_floor_epoch IS NOT NULL)))")

    @staticmethod
    def _create_incident_state_row(conn, now):
        """The single runtime-state row, born INERT: no activation floor
        (0.0 is pre-activation, not a real floor), nothing evaluated,
        no reader continuity, no open incident, no discovery floor and no
        rearm demand. The scanner raises the floor and starts evaluating;
        until then the runtime is warmup."""
        conn.execute(
            "INSERT INTO incident_runtime_state (id, runtime_version,"
            " activation_floor_epoch, last_evaluated_end_epoch,"
            " reader_fresh_since_epoch, open_incident_id,"
            " discovery_floor_epoch, rearm_required)"
            " VALUES (1, 1, 0.0, 0.0, NULL, NULL, NULL, 0)", ())

    @classmethod
    def _create_marker_table(cls, conn):
        """v5 operator markers (#63 R2 §3): closed two-kind vocabulary,
        no free text anywhere, epoch <= created_epoch in the CHECK so a
        future-dated marker is unrepresentable even by a buggy caller."""
        conn.execute(
            "CREATE TABLE operator_markers ("
            " marker_id INTEGER PRIMARY KEY,"
            " epoch REAL NOT NULL CHECK (epoch >= 0),"
            " kind TEXT NOT NULL"
            f" CHECK (kind IN ({cls._in_list(MARKER_KINDS)})),"
            " created_epoch REAL NOT NULL CHECK (created_epoch >= 0"
            " AND epoch <= created_epoch))")
        conn.execute(
            "CREATE INDEX ix_operator_markers_epoch"
            " ON operator_markers(epoch)")

    def _migrate_v1_to_v5(self, conn):
        """The v1 source jumps to v5 in ONE explicit transaction:
        journal tables + probe table + incident tables + the marker
        table + state rows + the schema_version flip. Zero v1 rows are
        read, moved or rewritten; any mid-migration failure rolls the
        whole thing back, leaving an untouched exact-v1 database, so
        startup after a crash simply re-runs the migration. (v1 was
        never meant to stop at v2 or v3: the intermediate migrations of
        the 0.3.x / 0.4.x / 0.5.x lines are subsumed here -- the end
        shape is identical to a v2->v5, v3->v5 or v4->v5 walk.)"""
        try:
            conn.execute("BEGIN")
            self._create_journal_tables(conn)
            self._create_journal_state_row(conn, self._clock())
            self._create_probe_table(conn)
            self._create_incident_tables(conn)
            self._create_incident_state_row(conn, self._clock())
            self._create_marker_table(conn)
            conn.execute("UPDATE meta SET value = ?"
                         " WHERE key = 'schema_version'",
                         (str(SCHEMA_VERSION),))
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    def _migrate_v2_to_v5(self, conn):
        """The v2 source adds EXACTLY the v3 probe table, the v4 incident
        tables and the v5 marker table and flips the version in a SINGLE
        explicit transaction -- zero v2 rows touched, no journal-shape
        rewrite, forward-only. A crash anywhere before the commit rolls
        back whole and the untouched exact-v2 file re-migrates on the
        next open."""
        try:
            conn.execute("BEGIN")
            self._create_probe_table(conn)
            self._create_incident_tables(conn)
            self._create_incident_state_row(conn, self._clock())
            self._create_marker_table(conn)
            conn.execute("UPDATE meta SET value = ?"
                         " WHERE key = 'schema_version'",
                         (str(SCHEMA_VERSION),))
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    def _migrate_v3_to_v5(self, conn):
        """The v3 source adds EXACTLY the two v4 incident tables, their
        state row and the v5 marker table and flips the version in a
        SINGLE explicit transaction -- zero v3 rows touched (every
        pre-existing sample/state/probe/journal row survives
        byte-for-byte), no probe-shape rewrite, forward-only. A crash
        anywhere before the commit rolls back whole and the untouched
        exact-v3 file re-migrates on the next open. The retained
        prestate snapshot the deploy layer takes BEFORE this runs is
        what makes a refused or rolled-back activation restorable."""
        try:
            conn.execute("BEGIN")
            self._create_incident_tables(conn)
            self._create_incident_state_row(conn, self._clock())
            self._create_marker_table(conn)
            conn.execute("UPDATE meta SET value = ?"
                         " WHERE key = 'schema_version'",
                         (str(SCHEMA_VERSION),))
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    def _migrate_v4_to_v5(self, conn):
        """The v4 source adds EXACTLY the v5 marker table and flips the
        version in a SINGLE explicit transaction -- zero v4 rows touched
        (incident rows, runtime state and every evidence row survive
        byte-for-byte), forward-only. A crash anywhere before the commit
        rolls back whole and the untouched exact-v4 file re-migrates on
        the next open."""
        try:
            conn.execute("BEGIN")
            self._create_marker_table(conn)
            conn.execute("UPDATE meta SET value = ?"
                         " WHERE key = 'schema_version'",
                         (str(SCHEMA_VERSION),))
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    # -- publish hook internals ----------------------------------------------------

    def _on_publish_locked(self, snapshot, version):
        if not self._enabled or self._conn is None:
            return
        now = self._clock()
        # Journal ingest rides the SAME publication cadence under the SAME
        # lock (before the write-nothing early return below, so a quiet
        # publish still drains the exchange dir). The publisher entry uses
        # the outer containment wrapper: NO ordinary Exception from the
        # journal path may ever break this publication's P1 write — it is
        # contained, rolled back, and recorded only as sanitized journal
        # degradation.
        self._journal_ingest_publish_gate(now)
        sample_due = (self._last_sample_ts is None or
                      (now - self._last_sample_ts) >= self._sample_interval)
        rows = project_device_rows(snapshot, self._run_id, now)
        changed = []
        for row in rows:
            key = (row["device"], row["inbound"])
            state = self._device_state.get(key)
            reason = None
            if state is None:
                reason = REASON_CHANGE           # first sighting: immediate
            elif (state["active"] != row["active_connections"]
                    or state["status"] != row["device_status"]):
                reason = REASON_CHANGE           # count / status change: now
            elif (now - state["written_at"]) >= self._heartbeat_interval:
                reason = REASON_HEARTBEAT        # otherwise: >= 60s apart
            if reason is not None:
                row["reason"] = reason
                changed.append(row)
        if not sample_due and not changed:
            return
        sample = project_sample(snapshot, self._run_id, version, now) \
            if sample_due else None
        self._write(sample, changed, now)
        for row in changed:
            self._device_state[(row["device"], row["inbound"])] = {
                "active": row["active_connections"],
                "status": row["device_status"],
                "written_at": now,
            }
        if sample_due:
            self._last_sample_ts = now
        if self._last_cleanup_ts is None:
            self._last_cleanup_ts = self._clock()
        elif (now - self._last_cleanup_ts) >= self._cleanup_interval:
            self._last_cleanup_ts = now
            self._cleanup("periodic")

    def _write(self, sample, rows, now):
        statements = []
        if sample is not None:
            columns = ", ".join(SAMPLE_COLUMNS)
            marks = ", ".join("?" for _ in SAMPLE_COLUMNS)
            statements.append((
                "INSERT INTO timeline_samples (%s) VALUES (%s)"
                % (columns, marks),
                [sample[c] for c in SAMPLE_COLUMNS]))
        if rows:
            columns = ", ".join(DEVICE_STATE_COLUMNS)
            marks = ", ".join("?" for _ in DEVICE_STATE_COLUMNS)
            statements.append((
                "INSERT INTO device_protocol_states (%s) VALUES (%s)"
                % (columns, marks),
                [[row[c] for c in DEVICE_STATE_COLUMNS] for row in rows]))
        if not statements:
            return
        try:
            for sql, params in statements:
                if isinstance(params[0], list):
                    self._conn.executemany(sql, params)
                else:
                    self._conn.execute(sql, params)
            self._conn.commit()
        except (sqlite3.Error, OSError):
            # A COMMIT that fails may still have landed: best-effort
            # rollback so the NEXT publish starts from a clean state.
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            raise
        self._last_success_ts = now
        self._degraded = False
        self._last_error_code = None

    # -- journal ingest internals (issue #33 P2, PR-2B) ------------------------
    #
    # The decision table is the FROZEN PR-2A ingest contract (v2-R6 /
    # v3-B4), settled per-file directly against SQLite: strictly
    # ascending from terminal+1, gap counted exactly once at discovery,
    # terminal rejection settles exactly once and never blocks higher
    # seqs, a failed apply settles NOTHING and blocks the rest of the
    # pass. Unlike the pure-contract `settle()` (whose injection point
    # documents this activation), every settlement -- valid, rejected
    # AND gap -- carries its terminal advance inside the SAME SQLite
    # transaction as its rows, so no crash window can re-count or
    # retract anything.

    def _journal_exchange_provisioned(self):
        """Is there a reader data root on this host at all?

        The configured exchange directory's PARENT is the reader-owned
        data root, so a parent that does not exist means the journal
        reader was never activated here: there is nothing to ingest and
        the subsystem stays quiet (NOT degraded). That is the single
        carve-out, and it is a wiring fact rather than a read result.
        Once the root exists, every unenumerable shape below it is a real
        storage failure and must degrade (B7-B) -- which is exactly the
        production shape this hotfix removes: root present and statable,
        ``out`` unreachable through it."""
        if self._journal_exchange_dir is None:
            return False
        try:
            return os.path.isdir(
                os.path.dirname(os.path.abspath(
                    self._journal_exchange_dir)))
        except OSError:
            return False

    def _journal_ingest_gate(self, now, force=False):
        if self._journal_exchange_dir is None:
            return None
        if not self._journal_exchange_provisioned():
            # never-activated host: quiet, no cadence stamp consumed, and
            # above all not the "clean pass" that would clear a real
            # journal degradation.
            return None
        if (not force and self._last_journal_ingest_ts is not None
                and (now - self._last_journal_ingest_ts)
                < self._journal_ingest_interval):
            return None
        self._last_journal_ingest_ts = now
        # Journal containment (frozen P2 failure invariant): structural
        # and storage errors fail-close ONLY the journal subsystem --
        # nothing settles, nothing is fabricated, and the ordinary P1
        # sample/device write of the same publication still executes on
        # its own storage path. A missing continuity row is NEVER
        # silently recreated. BaseException (process control) is
        # deliberately NOT caught, and an injected RuntimeError still
        # propagates out of the DIRECT ingest_journal_events() entry --
        # that is the pre-commit crash-consistency vehicle; the
        # publication path is fully isolated one level up in
        # ``_journal_ingest_publish_gate``.
        try:
            return self._journal_ingest_pass(now)
        except _HistoryError as exc:
            self._rollback_quiet()
            self._record_journal_failure(exc.code)
            return None
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
            return None

    def _journal_ingest_publish_gate(self, now):
        # PUBLICATION-ONLY outer containment: no journal Exception of
        # ANY kind (including the crash-sim RuntimeError a direct
        # ingest call lets propagate) may prevent the P1 timeline write
        # of the same publication. Contained, rolled back whole, and
        # recorded ONLY as sanitized journal degradation.
        try:
            return self._journal_ingest_gate(now)
        except Exception:  # noqa: BLE001 -- publisher isolation is total
            self._rollback_quiet()
            self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
            return None

    def _journal_ingest_pass(self, now):
        result = {"consumed": 0, "gaps": 0, "rejected": 0,
                  "blocked_at": None,
                  "contract_available": JOURNAL_CONTRACT_AVAILABLE}
        self._journal_last_pass = result
        # the blocked marker and the journal degraded state describe the
        # MOST RECENT pass: each new pass starts clean and re-proves
        # recovery (a later pass that completes with nothing blocked IS
        # the explicit recovery condition).
        self._journal_blocked_at = None
        if not JOURNAL_CONTRACT_AVAILABLE:
            return result
        state = self._conn.execute(
            "SELECT terminal_seq, last_consumed_seq, gaps_total,"
            " rejected_total FROM journal_ingest_state WHERE id = 1"
        ).fetchone()
        if state is None:
            # the open-time shape gate guarantees the row; its absence
            # mid-run is a hostile mutation -- fail closed, mutate zero
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
        terminal = state[0]
        try:
            files = _journal_contract.scan_exchange_dir(
                self._journal_exchange_dir)
        except _journal_contract.ExchangeDirUnreadable:
            # B7-B: storage the Monitor could not enumerate is NOT an
            # empty exchange directory. This leaves before the settlement
            # loop opens, so ZERO seq advances, no gap and no rejection is
            # counted, and nothing can leapfrog the unseen seq; and
            # because the pass never completes, the recovery branch at the
            # bottom cannot run and cannot clear a degradation the broken
            # storage never earned. The gate turns this into the
            # sanitized code and nothing else.
            raise _HistoryError(CODE_EXCHANGE_UNREADABLE)
        # Loop invariant: the DB terminal is always exactly seq-1 --
        # every settlement (applied, rejected, gap) advanced it to the
        # seq it consumed, every failure settled NOTHING.
        seq = terminal + 1
        while seq in files or any(s > seq for s in files):
            if seq not in files:
                nxt = min(s for s in files if s >= seq)
                if not self._journal_settle_gap(seq, nxt, now, result):
                    break
                seq = nxt
            payload, code = None, None
            try:
                payload, code = _journal_contract.read_and_validate(
                    self._journal_exchange_dir, files[seq], seq)
            except UnicodeDecodeError:
                # Undecodable bytes are the most malformed a file can
                # be: the contract's text-mode read raises before any
                # sanitized code can come back. Contained HERE (never
                # escapes the journal boundary) and classified with the
                # frozen closed-vocabulary disposition code -- no raw
                # byte is ever kept or echoed.
                payload, code = None, "exchange_unreadable"
            if code is not None:
                if not self._journal_settle_rejected(seq, code, now,
                                                     result):
                    break
                seq += 1
                continue
            body, records = payload
            header = json.loads(body.split("\n", 1)[0])
            try:
                self._journal_apply_locked(header, records, seq, now)
            except (sqlite3.Error, OSError):
                # NOT terminal: nothing settled (the transaction rolled
                # back whole), and higher seqs never leapfrog a file
                # that merely failed to settle -- retried next pass.
                # Journal-owned degraded state: a successful ordinary
                # sample write later in this same publication must NOT
                # clear it.
                self._rollback_quiet()
                self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
                result["blocked_at"] = self._journal_blocked_at = seq
                break
            result["consumed"] += 1
            seq += 1
        result["terminal_after"] = seq - 1
        if result["blocked_at"] is None:
            # explicit recovery condition: a pass that completed with
            # nothing blocked -- the journal degraded state clears here
            # and only here.
            self._journal_degraded = False
            self._journal_last_error_code = None
        return result

    def _journal_settle_gap(self, seq, nxt, now, result):
        """Missing-seq discovery (v3-B4): count the whole skipped
        interval exactly once and move terminal to nxt-1, atomically."""
        try:
            self._conn.executemany(
                "INSERT INTO journal_ingest_audit (epoch, kind, seq,"
                " code) VALUES (?, 'gap', ?, 'sequence_gap')",
                [[now, skipped] for skipped in range(seq, nxt)])
            self._conn.execute(
                "UPDATE journal_ingest_state SET terminal_seq = ?,"
                " gaps_total = gaps_total + ?, updated_epoch = ?"
                " WHERE id = 1", (nxt - 1, nxt - seq, now))
            self._conn.commit()
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
            result["blocked_at"] = self._journal_blocked_at = seq
            return False
        result["gaps"] += nxt - seq
        return True

    def _journal_settle_rejected(self, seq, code, now, result):
        """Terminally rejected file: settles ONCE (no forever-reject
        loop) and the next seq continues -- a later valid file around
        it records NO gap (frozen contract rule). `code` is stored
        UNMODIFIED: the DB CHECK already restricts it to the closed
        JOURNAL_AUDIT_CODES vocabulary, so a code outside that mirror
        (a future unknown contract code) FAILS the settlement
        fail-closed instead of being truncated into a lie."""
        try:
            self._conn.execute(
                "INSERT INTO journal_ingest_audit (epoch, kind, seq,"
                " code) VALUES (?, 'rejected', ?, ?)",
                (now, seq, code))
            self._conn.execute(
                "UPDATE journal_ingest_state SET terminal_seq = ?,"
                " rejected_total = rejected_total + 1, updated_epoch = ?"
                " WHERE id = 1", (seq, now))
            self._conn.commit()
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_journal_failure(CODE_INGEST_APPLY_FAILED)
            result["blocked_at"] = self._journal_blocked_at = seq
            return False
        result["rejected"] += 1
        return True

    def _journal_apply_locked(self, header, records, seq, now):
        """THE exactly-once boundary: event rows AND the terminal
        advance commit together (one implicit SQLite transaction,
        synchronous=FULL). A crash anywhere before the commit leaves
        zero rows and zero movement; a crash after it is settled
        history -- re-encountering seq <= terminal is a no-op."""
        timestamps = [record["ts"] for record in records]
        self._conn.execute(
            "INSERT INTO journal_runs (seq, run, source_epoch,"
            " boundary, lines, eligible, info_dropped,"
            " nomatch_dropped, priority_unusable, pfail, limited,"
            " first_ts, last_ts, record_count, event_count,"
            " ingested_epoch, ingested_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, header["run"], header["epoch"], header["boundary"],
             header["lines"], header["eligible"], header["info_dropped"],
             header["nomatch_dropped"], header["priority_unusable"],
             header["pfail"], header["limited"],
             min(timestamps) if timestamps else None,
             max(timestamps) if timestamps else None,
             len(records), sum(record["n"] for record in records),
             float(now), _iso(now)))
        self._conn.executemany(
            "INSERT INTO journal_events (seq, ts, cls, proto, port,"
            " dcls, fp, n) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [[seq, record["ts"], record["cls"], record["proto"],
              record["port"] or 0, record["dcls"] or "NONE",
              record["fp"], record["n"]] for record in records])
        self._conn.execute(
            "UPDATE journal_ingest_state SET terminal_seq = ?,"
            " last_consumed_seq = ?, updated_epoch = ? WHERE id = 1",
            (seq, seq, now))
        self._conn.commit()

    def _journal_reader_hb_status(self):
        """PR-2A frozen availability semantics: reader staleness is
        derived ONLY from the age of out/hb, never from anything the
        reader would have to say about itself."""
        status = {"status": "disabled", "seq": None, "age_seconds": None,
                  "stale_threshold_seconds": JOURNAL_HB_STALE_SECONDS}
        out_dir = self._journal_exchange_dir
        if out_dir is None:
            return status
        path = os.path.join(out_dir, JOURNAL_HB_NAME)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            status["status"] = "absent"
            return status
        except OSError:
            status["status"] = "unreadable"
            return status
        if not stat.S_ISREG(st.st_mode) or st.st_size > JOURNAL_HB_MAX_BYTES:
            status["status"] = "invalid"
            return status
        try:
            with open(path, "r") as handle:
                obj = json.loads(handle.read(JOURNAL_HB_MAX_BYTES + 1))
            seq, ts = obj["seq"], obj["ts"]
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise ValueError
            if (isinstance(ts, bool) or not isinstance(ts, (int, float))
                    or ts != ts):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError):
            status["status"] = "invalid"
            return status
        age = self._clock() - float(ts)
        status["seq"] = seq
        status["age_seconds"] = age
        status["status"] = "stale" if age > JOURNAL_HB_STALE_SECONDS \
            else "fresh"
        return status

    def _rollback_quiet(self):
        try:
            self._conn.rollback()
        except sqlite3.Error:
            pass

    # -- retention -----------------------------------------------------------------

    def _cleanup(self, phase):
        if self._conn is None:
            return
        try:
            horizon = self._clock() - self._retention_seconds
            self._conn.execute(
                "DELETE FROM timeline_samples WHERE epoch < ?", (horizon,))
            self._conn.execute(
                "DELETE FROM device_protocol_states WHERE epoch < ?",
                (horizon,))
            # v3 probe rows age out on the SAME horizon and ride the
            # same global size-prune order: the probe table can never
            # grow unbounded past the retention budget.
            self._conn.execute(
                "DELETE FROM network_probe_samples WHERE epoch < ?",
                (horizon,))
            # v2 journal rows join the SAME accounting: runs age out by
            # their ingest epoch and their events ride the FK cascade --
            # the new tables can never grow unbounded past the horizon.
            # journal_ingest_state is the terminal continuity authority:
            # it is a single bounded row and is NEVER retention-pruned.
            self._conn.execute(
                "DELETE FROM journal_runs WHERE ingested_epoch < ?",
                (horizon,))
            self._conn.execute(
                "DELETE FROM journal_ingest_audit WHERE epoch < ?",
                (horizon,))
            # v4 incident windows join the SAME 7-day contract (§10) with
            # their own rule: a CLOSED window ages out by its last signal
            # age; an OPEN window is live operational state and is NEVER
            # retention-pruned; incident_runtime_state is the continuity
            # authority (like journal_ingest_state) and never prunes at
            # all. Neither table is in _PRUNE_SOURCES: size pruning stays
            # a pure-evidence-timeline discipline.
            self._conn.execute(
                "DELETE FROM incident_windows WHERE state = 'closed'"
                " AND last_signal_epoch < ?", (horizon,))
            # v5 operator markers join the SAME 7-day contract (#63 R2
            # §3): bounded history, not a permanent record -- a marker
            # ages out by its operator-declared epoch exactly like the
            # evidence around it, and size pruning treats it as one more
            # source in the global epoch order.
            self._conn.execute(
                "DELETE FROM operator_markers WHERE epoch < ?", (horizon,))
            self._conn.commit()
            # Spec §5: time-based retention is the normal path; SIZE pruning
            # kicks in only when the HARD CEILING is crossed, and then
            # forgets the OLDEST rows in batches until back below the soft
            # TARGET -- newest rows are never sacrificed for old.
            if self._db_bytes() > self._ceiling_bytes:
                self._prune_to_target()
                self._vacuum()
            if os.name == "posix":
                os.chmod(self._db_path, 0o600)
        except (sqlite3.Error, OSError):
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            self._record_failure(CODE_RETENTION_FAILED)

    def _prune_to_target(self):
        """Delete globally OLDEST rows -- ALL pruned tables as ONE timeline.

        Contract: no row at time T2 may be deleted while a strictly
        older row at T1 still exists in ANY pruned table; the survivors
        are always a newest-suffix of the merged epoch order. Ties at
        the cut epoch are settled deterministically (source order,
        insertion order within a table). v2 journal_runs prunes cascade
        their events; journal_ingest_state is continuity, not history,
        and is never a pruning candidate. File size can ONLY be
        re-measured after a full VACUUM: incremental vacuum releases free
        pages at the END of the file, but oldest-first deletes free pages
        behind live newest rows -- without the rewrite the measured size
        never drops and the loop would drain the whole table.
        """
        while self._db_bytes() > self._target_bytes:
            bytes_now = self._db_bytes()
            counts = [self._conn.execute(
                "SELECT COUNT(*) FROM %s" % table).fetchone()[0]
                for table, _column in _PRUNE_SOURCES]
            total = sum(counts)
            if total <= 0:
                return
            # k globally-oldest rows, k >= a minimum batch and >= 10% of
            # the rows: guaranteed forward progress, never a newer time
            # before an older one.
            k = max(PRUNE_BATCH_ROWS,
                    int(total * max((bytes_now - self._target_bytes)
                                    / float(bytes_now), 0.10)) + 1)
            k = min(k, total)
            cut = self._conn.execute(
                "SELECT epoch FROM (" + " UNION ALL".join(
                    " SELECT %s AS epoch FROM %s" % (column, table)
                    for table, column in _PRUNE_SOURCES) + ")"
                " ORDER BY epoch ASC LIMIT 1 OFFSET ?",
                (k - 1,)).fetchone()[0]
            remaining = k
            # samples/states first: they settle exact ties at the cut
            # epoch in the historical source order
            for table, column in _PRUNE_SOURCES:  # strictly older than cut
                if remaining <= 0:
                    break
                cursor = self._conn.execute(
                    "DELETE FROM %s WHERE %s < ?" % (table, column),
                    (cut,))
                remaining -= max(cursor.rowcount, 0)
            for table, column in _PRUNE_SOURCES:  # top up AT the cut epoch
                if remaining <= 0:
                    break
                cursor = self._conn.execute(
                    "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s"
                    " WHERE %s = ? ORDER BY rowid ASC LIMIT ?)"
                    % (table, table, column), (cut, remaining))
                remaining -= max(cursor.rowcount, 0)
            self._conn.commit()
            self._conn.execute("VACUUM")
            self._conn.commit()

    def _vacuum(self):
        try:
            freelist = self._conn.execute(
                "PRAGMA freelist_count").fetchone()[0]
            if freelist:
                self._conn.execute("PRAGMA incremental_vacuum")
                self._conn.commit()
        except sqlite3.Error:
            pass  # reclaim is opportunistic; retention already happened

    def _db_bytes(self):
        try:
            pages = self._conn.execute("PRAGMA page_count").fetchone()[0]
            size = self._conn.execute("PRAGMA page_size").fetchone()[0]
            return int(pages) * int(size)
        except (sqlite3.Error, TypeError, ValueError):
            try:
                return os.path.getsize(self._db_path)
            except OSError:
                return 0

    # -- failure bookkeeping ----------------------------------------------------------

    def _record_failure(self, code):
        # RLock: safe to re-enter from a call site that already holds it;
        # pure field bookkeeping, no I/O, so it can never hold the lock
        # long enough to matter and can never deadlock.
        with self._lock:
            self._failure_count += 1
            self._degraded = True
            self._last_error_code = code
            if code in (CODE_DIR_UNSAFE, CODE_DB_UNSAFE, CODE_OPEN_FAILED,
                        CODE_SCHEMA_UNSUPPORTED):
                # a refused OPEN is fail-closed: the surface is NOT enabled
                # until a later open() succeeds (never a stale True)
                self._enabled = False

    def _record_journal_failure(self, code):
        # Journal ingest is an INDEPENDENT health subsystem: this never
        # touches the write-path _degraded/_last_error_code, and only a
        # later clean ingest pass (_journal_ingest_pass with nothing
        # blocked) clears it. A successful sample write can therefore
        # never swallow an ingest failure inside the same publication.
        with self._lock:
            self._failure_count += 1
            self._journal_degraded = True
            self._journal_last_error_code = code


class _HistoryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _project_rows(row, columns):
    values = dict(zip(columns, tuple(row)))
    return {column: values.get(column) for column in columns}


# -- probe boundary helpers (module-level, pure, closed) -----------------------

_PROBE_CYCLE_KEYS = frozenset({"status", "latency_ms", "error_code"})
_PROBE_EGRESS_KEYS = _PROBE_CYCLE_KEYS | {"ip"}
_PROBE_RESULT_KEYS = frozenset({"v", "epoch", "cycle_id", "dns", "https",
                                "udp", "egress"})
_CYCLE_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
# The engine's cycle wall-clock budget (12 s) plus scheduling slack: the
# largest producer->store skew a legitimate cycle can show.
PROBE_CYCLE_FRESHNESS_SECONDS = 30.0


def _canonical_global_ip(value):
    """Mirror of the engine's ``_canonical_ip`` gate: canonical form of a
    PUBLIC, GLOBAL UNICAST IP literal, else None. The v3 boundary and the
    durable baseline read both pass through this ONE function, so a
    loopback/private/reserved/document/multicast address can never be
    persisted or inform a change judgement even if the engine above were
    buggy (defense in depth; the probe suite AST-compares this gate with
    the engine's). ``ipaddress`` scopes 224.0.0.0/4 and ff00::/12 as
    GLOBAL, so globality alone would admit a multicast GROUP -- which is a
    destination, never a host's egress address."""
    if type(value) is not str:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global or address.is_multicast:
        return None
    return str(address)


def _derive_egress_change(previous, current):
    """Mirror of the engine's pure ``classify_egress_change``: the CLOSED
    judgement over two candidate egress answers, computed from the
    DURABLE baseline and this cycle's own address. Kept as a separate
    function -- not inlined into the boundary -- so the probe suite can
    assert it answers identically to the engine's over a table of
    addresses; the boundary then REFUSES any producer claim that
    disagrees with it, for all three tokens."""
    before = _canonical_global_ip(previous)
    after = _canonical_global_ip(current)
    if before is None or after is None:
        return "unknown"
    return "changed" if before != after else "unchanged"


def _result_is_closed(value, keys):
    """Strict dict of EXACTLY ``keys`` (no subclass, no extra/missing
    key, no hostile __getitem__ surface -- dict type is exact)."""
    return (type(value) is dict
            and frozenset(value.keys()) == frozenset(keys))


def _closed_code_slot(raw):
    """Map one result slot to its closed (status, latency, code) triple
    or reject it. The transition matrix is the engine's own invariant:
    ok <=> NONE, latency only on the ok path, EXACTLY a plain integer and
    bounded.

    Every primitive is type-checked BEFORE it is judged, because each
    judgement has a coercion or a raise behind it: ``in`` over the closed
    vocabularies compares with ``==``, so a status object whose ``__eq__``
    always answers True would be adopted as ``"ok"``; and a latency of
    ``True``, ``12.0`` or ``"12"`` satisfies a numeric-equality test
    (``12 == 12.0 == True``) while being a producer defect -- and in the
    string case SQLite's INTEGER affinity would convert it on the way in, so
    the table would store a coercion the engine never emitted."""
    code = raw["error_code"]
    status = raw["status"]
    latency = raw["latency_ms"]
    if type(status) is not str or type(code) is not str:
        return None
    if code not in PROBE_ERROR_CODES or status not in PROBE_STATUSES:
        return None
    if status == "ok":
        if code != "NONE":
            return None
        if type(latency) is not int \
                or not 0 <= latency <= PROBE_LATENCY_MAX_MS:
            return None
    else:
        if code == "NONE" or latency is not None:
            return None
    return status, latency, code
