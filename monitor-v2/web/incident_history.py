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
  Schema handling is strict: a genuinely fresh DB is created at v2; an
  existing DB opens only with an exactly-declared v2, or with the exact
  v1 shape, which is migrated FORWARD to v2 in one transaction with
  every v1 row preserved. Any other declared version (newer, negative,
  malformed, hybrid) or metadata-less SQLite file is refused fail-closed
  and never mutated -- migrations are explicit and forward-only.
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
  kill the publisher thread, a reader thread or the web server.
* Retention: rows older than the retention horizon are deleted at
  startup and at most hourly; if the database crosses the size ceiling
  the OLDEST rows are pruned in batches until below the target size --
  ALL tables are pruned as ONE globally epoch-ordered timeline, so a
  newer row is never sacrificed while a strictly older row still exists
  in another table.

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
"""

from __future__ import annotations

import datetime
import json
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

SCHEMA_VERSION = 2

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
_PRUNE_SOURCES = (
    ("timeline_samples", "epoch"),
    ("device_protocol_states", "epoch"),
    ("journal_runs", "ingested_epoch"),
    ("journal_ingest_audit", "epoch"),
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

_V1_TABLES = frozenset({"timeline_samples", "device_protocol_states"})
_JOURNAL_TABLES = frozenset({"journal_runs", "journal_events",
                             "journal_ingest_audit",
                             "journal_ingest_state"})


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

_SAMPLE_SELECT = "SELECT %s FROM" % ", ".join(SAMPLE_COLUMNS)
_STATE_SELECT = "SELECT %s FROM" % ", ".join(DEVICE_STATE_COLUMNS)


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
            return {
                "enabled": bool(self._enabled),
                "degraded": bool(self._degraded),
                "last_success_at": _iso(self._last_success_ts)
                if self._last_success_ts else None,
                "failure_count": int(self._failure_count),
                "last_error_code": self._last_error_code,
                "run_id": self._run_id,
            }

    def query_timeline(self, since=None, limit=QUERY_LIMIT_DEFAULT):
        """Bounded, sanitized read of the persisted timeline.

        Returns ``{"samples": [...], "device_states": [...],
        "truncated": bool}`` with EXACTLY the whitelisted columns, or
        empty lists if the history is unreadable (health carries the
        reason -- reads never raise).
        """
        limit = max(1, min(_as_int(limit, QUERY_LIMIT_DEFAULT),
                           QUERY_LIMIT_MAX))
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return {"samples": [], "device_states": [],
                            "truncated": False, "limit": limit}
                if since is None:
                    sample_rows = self._conn.execute(
                        _SAMPLE_SELECT + " timeline_samples ORDER BY epoch"
                        " DESC LIMIT ?", (limit + 1,)).fetchall()
                    state_rows = self._conn.execute(
                        _STATE_SELECT + " device_protocol_states ORDER BY"
                        " epoch DESC LIMIT ?", (limit + 1,)).fetchall()
                else:
                    sample_rows = self._conn.execute(
                        _SAMPLE_SELECT + " timeline_samples WHERE epoch >= ?"
                        " ORDER BY epoch DESC LIMIT ?",
                        (float(since), limit + 1)).fetchall()
                    state_rows = self._conn.execute(
                        _STATE_SELECT + " device_protocol_states WHERE epoch"
                        " >= ? ORDER BY epoch DESC LIMIT ?",
                        (float(since), limit + 1)).fetchall()
        except (sqlite3.Error, OSError, ValueError):
            self._record_failure(CODE_READ_FAILED)
            return {"samples": [], "device_states": [],
                    "truncated": False, "limit": limit}
        truncated = len(sample_rows) > limit or len(state_rows) > limit
        samples = [_project_rows(r, SAMPLE_COLUMNS) for r in sample_rows[:limit]]
        states = [_project_rows(r, DEVICE_STATE_COLUMNS)
                  for r in state_rows[:limit]]
        samples.reverse()   # chronological order for the reader
        states.reverse()
        return {"samples": samples, "device_states": states,
                "truncated": truncated, "limit": limit}

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
        ``on_publish``). Never raises; the returned dict is sanitized."""
        try:
            with self._lock:
                if not self._enabled or self._conn is None:
                    return None
                return self._journal_ingest_gate(self._clock(), force=True)
        except _HistoryError as exc:
            self._record_failure(exc.code)
            return None
        except (sqlite3.Error, OSError):
            self._record_failure(CODE_INGEST_APPLY_FAILED)
            return None

    def journal_status(self):
        """Sanitized read surface for journal ingest + reader
        availability (heartbeat age). Never raises; never echoes file
        content, paths or exception text."""
        status = {
            "enabled": False,
            "contract_available": JOURNAL_CONTRACT_AVAILABLE,
            "exchange_dir_configured": self._journal_exchange_dir is not None,
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

        Accepted shapes are exactly three: a genuinely fresh database
        (absent or zero-byte file, no tables) which is created at the
        current version, an existing database that DECLARES the current
        schema_version and carries the full v2 shape, and an existing
        database that declares exactly v1 and carries the EXACT v1 shape
        (v1 tables present, no journal tables) -- migrated forward to v2
        in ONE transaction with zero v1 rows touched. Everything else --
        newer, zero, negative, malformed, meta-less, a v1 claim with
        stripped tables, a v2 claim with stripped journal tables or any
        hybrid -- is refused with CODE_SCHEMA_UNSUPPORTED before any
        pragma, DDL or write can touch the file. In particular no lower
        version is ever silently rewritten: migration is the explicit
        v1->v2 path below and nothing else.
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
            if not (_V1_TABLES | _JOURNAL_TABLES) <= tables:
                # meta CLAIMS v2 but the v2 shape is not there: unknown
                # old/hybrid shape, refuse rather than adopt
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            if conn.execute("SELECT terminal_seq FROM journal_ingest_state"
                            " WHERE id = 1").fetchone() is None:
                # state row missing under a complete table set is an
                # unknown shape too -- never a repair
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            return
        if version == 1:
            # exact-v1 only: v1 tables AND no journal tables (a hybrid
            # is an unknown shape, never a migration candidate)
            if not _V1_TABLES <= tables or (tables & _JOURNAL_TABLES):
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._migrate_v1_to_v2(conn)
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
        """Fresh database: the full v2 shape in ONE explicit
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
            " code TEXT NOT NULL CHECK (length(code) <= 64))")
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

    def _migrate_v1_to_v2(self, conn):
        """The ONE forward migration: journal tables + state row + the
        schema_version flip in a SINGLE explicit transaction (the DDL is
        bound into it by the leading BEGIN -- under sqlite3 legacy mode
        a bare CREATE would auto-commit and strand a half-migrated
        hybrid that no later shape gate adopts). Zero v1 rows are read,
        moved or rewritten; any mid-migration failure rolls the whole
        thing back, leaving an untouched exact-v1 database, so startup
        after a crash simply re-runs the migration."""
        try:
            conn.execute("BEGIN")
            self._create_journal_tables(conn)
            self._create_journal_state_row(conn, self._clock())
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
        # publish still drains the exchange dir). It swallows its own
        # failures: it can never delay or break snapshot writes.
        self._journal_ingest_gate(now)
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

    def _journal_ingest_gate(self, now, force=False):
        if self._journal_exchange_dir is None:
            return None
        if (not force and self._last_journal_ingest_ts is not None
                and (now - self._last_journal_ingest_ts)
                < self._journal_ingest_interval):
            return None
        self._last_journal_ingest_ts = now
        return self._journal_ingest_pass(now)

    def _journal_ingest_pass(self, now):
        result = {"consumed": 0, "gaps": 0, "rejected": 0,
                  "blocked_at": None,
                  "contract_available": JOURNAL_CONTRACT_AVAILABLE}
        self._journal_last_pass = result
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
        files = _journal_contract.scan_exchange_dir(
            self._journal_exchange_dir)
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
            payload, code = _journal_contract.read_and_validate(
                self._journal_exchange_dir, files[seq], seq)
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
                self._rollback_quiet()
                self._record_failure(CODE_INGEST_APPLY_FAILED)
                result["blocked_at"] = self._journal_blocked_at = seq
                break
            result["consumed"] += 1
            seq += 1
        result["terminal_after"] = seq - 1
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
            self._record_failure(CODE_INGEST_APPLY_FAILED)
            result["blocked_at"] = self._journal_blocked_at = seq
            return False
        result["gaps"] += nxt - seq
        return True

    def _journal_settle_rejected(self, seq, code, now, result):
        """Terminally rejected file: settles ONCE (no forever-reject
        loop) and the next seq continues -- a later valid file around
        it records NO gap (frozen contract rule)."""
        try:
            self._conn.execute(
                "INSERT INTO journal_ingest_audit (epoch, kind, seq,"
                " code) VALUES (?, 'rejected', ?, ?)",
                (now, seq, code[:64]))
            self._conn.execute(
                "UPDATE journal_ingest_state SET terminal_seq = ?,"
                " rejected_total = rejected_total + 1, updated_epoch = ?"
                " WHERE id = 1", (seq, now))
            self._conn.commit()
        except (sqlite3.Error, OSError):
            self._rollback_quiet()
            self._record_failure(CODE_INGEST_APPLY_FAILED)
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


class _HistoryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _project_rows(row, columns):
    values = dict(zip(columns, tuple(row)))
    return {column: values.get(column) for column in columns}
