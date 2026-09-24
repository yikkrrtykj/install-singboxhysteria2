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
  Schema handling is strict: a genuinely fresh DB is created at v1; an
  existing DB opens ONLY with an exactly-declared v1; any other declared
  version (older, newer, malformed) or metadata-less SQLite file is
  refused fail-closed and never mutated.
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
  the two tables are pruned as ONE globally epoch-ordered timeline, so a
  newer row is never sacrificed while a strictly older row still exists
  in the other table.
"""

from __future__ import annotations

import datetime
import os
import re
import sqlite3
import stat
import threading
import time

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
# One timeline, two tables: size pruning orders these epochs GLOBALLY
# (samples first only to settle exact ties at the cut epoch).
_PRUNE_TABLES = ("timeline_samples", "device_protocol_states", "error_aggregates")

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
CODE_INGEST_DB_FAILED = "ingest_db_failed"
CODE_INGEST_GAP = "ingest_gap"
CODE_INGEST_REJECTED = "ingest_rejected"
CODE_INGEST_STALE_READER = "ingest_stale_reader"

JOURNAL_META_DEFAULTS = {
    "journal_terminal_seq": 0,
    "journal_last_consumed_seq": 0,
    "journal_gaps": 0,
    "journal_cold_starts": 0,
    "journal_source_gaps": 0,
    "journal_rejected_files": 0,
    "journal_reader_cv": 0,
    "journal_skew": 0,
}
ERROR_AGGREGATE_LIMIT_PER_BUCKET = 64
JOURNAL_SKEW_SECONDS = 86400.0


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
                 cleanup_interval=CLEANUP_INTERVAL_SECONDS):
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
        self._ingest_enabled = False
        self._ingest_degraded = False
        self._ingest_last_error_code = None
        self._ingest_failure_count = 0
        self._ingest_last_success_ts = None

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
                "journal_ingest": {
                    "enabled": bool(self._ingest_enabled),
                    "degraded": bool(self._ingest_degraded),
                    "last_success_at": _iso(self._ingest_last_success_ts)
                    if self._ingest_last_success_ts else None,
                    "failure_count": int(self._ingest_failure_count),
                    "last_error_code": self._ingest_last_error_code,
                    "terminal_seq": self._journal_terminal_locked()
                    if self._conn is not None and self._enabled else 0,
                },
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

    def journal_terminal_seq(self):
        with self._lock:
            return self._journal_terminal_locked()

    def apply_journal_records(self, header, records, seq):
        """Atomically apply one validated exchange file + terminal advance."""
        with self._lock:
            if not self._enabled or not self._ingest_enabled or self._conn is None:
                raise _HistoryError(CODE_INGEST_DB_FAILED)
            now = self._clock()
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                for event in records:
                    self._upsert_error_event_locked(header, event, now)
                self._set_meta_int_locked("journal_terminal_seq", int(seq))
                self._set_meta_int_locked("journal_last_consumed_seq", int(seq))
                self._set_meta_int_locked("journal_reader_cv", int(header["cv"]))
                if header.get("boundary") == "COLD_START":
                    self._inc_meta_locked("journal_cold_starts", 1)
                elif header.get("boundary") == "SOURCE_GAP":
                    self._inc_meta_locked("journal_source_gaps", 1)
                self._conn.commit()
            except (sqlite3.Error, OSError, ValueError, TypeError):
                try:
                    self._conn.rollback()
                except sqlite3.Error:
                    pass
                self._mark_ingest_failure_locked(CODE_INGEST_DB_FAILED)
                raise
            self._mark_ingest_success_locked(now)

    def apply_journal_settlement(self, kind, terminal, amount, code=None):
        """Atomically settle gap/rejected terminal movement + counters."""
        del code  # sanitized disposition code is intentionally not persisted
        with self._lock:
            if not self._enabled or not self._ingest_enabled or self._conn is None:
                raise _HistoryError(CODE_INGEST_DB_FAILED)
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._set_meta_int_locked("journal_terminal_seq", int(terminal))
                if kind == "gap":
                    self._inc_meta_locked("journal_gaps", int(amount))
                elif kind == "rejected":
                    self._inc_meta_locked("journal_rejected_files", int(amount))
                else:
                    raise ValueError("unknown settlement")
                self._conn.commit()
            except (sqlite3.Error, OSError, ValueError, TypeError):
                try:
                    self._conn.rollback()
                except sqlite3.Error:
                    pass
                self._mark_ingest_failure_locked(CODE_INGEST_DB_FAILED)
                raise
            if kind == "gap":
                self._mark_ingest_failure_locked(CODE_INGEST_GAP)
            elif kind == "rejected":
                self._mark_ingest_failure_locked(CODE_INGEST_REJECTED)

    def mark_journal_ingest_success(self):
        with self._lock:
            if self._ingest_enabled:
                self._mark_ingest_success_locked(self._clock())

    def mark_journal_ingest_failure(self, code):
        with self._lock:
            self._mark_ingest_failure_locked(code)

    def query_error_summary(self, since=None, until=None, limit=QUERY_LIMIT_DEFAULT):
        """Bounded Python-only P2 read surface; no new HTTP endpoint."""
        limit = max(1, min(_as_int(limit, QUERY_LIMIT_DEFAULT), QUERY_LIMIT_MAX))
        where = []
        params = []
        if since is not None:
            where.append("bucket_epoch >= ?")
            params.append(int(float(since)))
        if until is not None:
            where.append("bucket_epoch < ?")
            params.append(int(float(until)))
        sql = ("SELECT bucket_epoch,classifier_version,journal_epoch,"
               "error_class,protocol,dest_port,dest_class,fp,first_ts,last_ts,count "
               "FROM error_aggregates")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += (" ORDER BY bucket_epoch DESC,classifier_version,journal_epoch,"
                "error_class,protocol,dest_port,dest_class,fp LIMIT ?")
        params.append(limit + 1)
        try:
            with self._lock:
                if not self._enabled or not self._ingest_enabled or self._conn is None:
                    return {"rows": [], "truncated": False, "limit": limit}
                rows = self._conn.execute(sql, tuple(params)).fetchall()
        except (sqlite3.Error, OSError, ValueError, TypeError):
            self._mark_ingest_failure_locked(CODE_INGEST_DB_FAILED)
            return {"rows": [], "truncated": False, "limit": limit}
        cols = ("bucket_epoch", "classifier_version", "journal_epoch",
                "error_class", "protocol", "dest_port", "dest_class", "fp",
                "first_ts", "last_ts", "count")
        out = [_project_rows(row, cols) for row in rows[:limit]]
        out.reverse()
        return {"rows": out, "truncated": len(rows) > limit, "limit": limit}

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

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
        self._ingest_enabled = True
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
        """Strict forward-only schema gate: fresh/v1 -> v2, exact v2 reopen."""
        conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables:
            if pre_existing:
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            self._apply_pragmas(conn)
            self._create_schema_v1(conn)
            self._migrate_v1_to_v2(conn)
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
        p1 = {"timeline_samples", "device_protocol_states"}
        if not p1 <= tables:
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
        self._apply_pragmas(conn)
        if version == 1:
            self._migrate_v1_to_v2(conn)
            return
        if version == SCHEMA_VERSION and "error_aggregates" in tables:
            self._ensure_journal_meta(conn)
            return
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

    def _create_schema_v1(self, conn):
        now = self._clock()
        conn.execute(
            "CREATE TABLE meta ("
            " key TEXT NOT NULL PRIMARY KEY,"
            " value TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?)",
            [("schema_version", "1"),
             ("created_at", _iso(now)),
             ("created_by_version", str(self._monitor_version))])
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

    def _migrate_v1_to_v2(self, conn):
        """Forward-only v1 -> v2 migration; P1 tables/rows are untouched."""
        conn.execute(
            "CREATE TABLE error_aggregates ("
            " bucket_epoch INTEGER NOT NULL,"
            " classifier_version INTEGER NOT NULL,"
            " journal_epoch INTEGER NOT NULL,"
            " error_class TEXT NOT NULL,"
            " protocol TEXT NOT NULL,"
            " dest_port INTEGER NOT NULL,"
            " dest_class TEXT NOT NULL,"
            " fp TEXT NOT NULL,"
            " first_ts REAL NOT NULL,"
            " last_ts REAL NOT NULL,"
            " count INTEGER NOT NULL,"
            " PRIMARY KEY (bucket_epoch,classifier_version,journal_epoch,"
            " error_class,protocol,dest_port,dest_class,fp)"
            ") WITHOUT ROWID")
        self._ensure_journal_meta(conn)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (str(SCHEMA_VERSION),))
        conn.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)

    def _ensure_journal_meta(self, conn):
        conn.executemany(
            "INSERT OR IGNORE INTO meta (key,value) VALUES (?,?)",
            [(key, str(value)) for key, value in JOURNAL_META_DEFAULTS.items()])

    def _meta_int_locked(self, key, default=0):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return int(default)
        try:
            return int(row[0])
        except (TypeError, ValueError):
            raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)

    def _set_meta_int_locked(self, key, value):
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(int(value))))

    def _inc_meta_locked(self, key, amount):
        self._set_meta_int_locked(
            key, self._meta_int_locked(key, 0) + int(amount))

    def _journal_terminal_locked(self):
        if self._conn is None:
            return 0
        return self._meta_int_locked("journal_terminal_seq", 0)

    def _mark_ingest_failure_locked(self, code):
        self._ingest_failure_count += 1
        self._ingest_degraded = True
        self._ingest_last_error_code = str(code)

    def _mark_ingest_success_locked(self, now):
        self._ingest_last_success_ts = now
        self._ingest_degraded = False
        self._ingest_last_error_code = None

    def _upsert_error_event_locked(self, header, event, now):
        ts = float(event["ts"])
        low = now - JOURNAL_SKEW_SECONDS
        high = now + JOURNAL_SKEW_SECONDS
        if ts < low:
            ts = low
            self._inc_meta_locked("journal_skew", 1)
        elif ts > high:
            ts = high
            self._inc_meta_locked("journal_skew", 1)
        bucket = int(ts // 60) * 60
        cv = int(header["cv"])
        epoch = int(header["epoch"])
        cls = event["cls"]
        proto = event["proto"]
        port = int(event["port"]) if event.get("port") is not None else 0
        dcls = event["dcls"] if event.get("dcls") is not None else "NONE"
        fp = event["fp"] if event.get("fp") is not None else "NONE"
        if port == 0:
            dcls = "NONE"
        if cls != "other":
            fp = "NONE"

        exists = self._conn.execute(
            "SELECT 1 FROM error_aggregates WHERE "
            "bucket_epoch=? AND classifier_version=? AND journal_epoch=? "
            "AND error_class=? AND protocol=? AND dest_port=? "
            "AND dest_class=? AND fp=?",
            (bucket, cv, epoch, cls, proto, port, dcls, fp)).fetchone()
        if exists is None:
            count = self._conn.execute(
                "SELECT COUNT(*) FROM error_aggregates WHERE "
                "bucket_epoch=? AND classifier_version=? AND journal_epoch=?",
                (bucket, cv, epoch)).fetchone()[0]
            if count >= ERROR_AGGREGATE_LIMIT_PER_BUCKET:
                # Collapse every existing row for this class/protocol into
                # one sentinel row before adding more context. With only
                # 8 classes x 3 protocols this always frees capacity.
                prior = self._conn.execute(
                    "SELECT COALESCE(SUM(count),0),MIN(first_ts),MAX(last_ts) "
                    "FROM error_aggregates WHERE bucket_epoch=? AND "
                    "classifier_version=? AND journal_epoch=? AND "
                    "error_class=? AND protocol=?",
                    (bucket, cv, epoch, cls, proto)).fetchone()
                self._conn.execute(
                    "DELETE FROM error_aggregates WHERE bucket_epoch=? AND "
                    "classifier_version=? AND journal_epoch=? AND "
                    "error_class=? AND protocol=?",
                    (bucket, cv, epoch, cls, proto))
                if prior and int(prior[0] or 0) > 0:
                    self._conn.execute(
                        "INSERT INTO error_aggregates VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (bucket, cv, epoch, cls, proto, 0, "NONE", "NONE",
                         float(prior[1]), float(prior[2]), int(prior[0])))
                port, dcls, fp = 0, "NONE", "NONE"

        self._conn.execute(
            "INSERT INTO error_aggregates "
            "(bucket_epoch,classifier_version,journal_epoch,error_class,"
            "protocol,dest_port,dest_class,fp,first_ts,last_ts,count) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(bucket_epoch,classifier_version,journal_epoch,"
            "error_class,protocol,dest_port,dest_class,fp) DO UPDATE SET "
            "count=count+excluded.count,"
            "first_ts=min(first_ts,excluded.first_ts),"
            "last_ts=max(last_ts,excluded.last_ts)",
            (bucket, cv, epoch, cls, proto, port, dcls, fp,
             ts, ts, int(event["n"])))

    # -- publish hook internals ----------------------------------------------------

    def _on_publish_locked(self, snapshot, version):
        if not self._enabled or self._conn is None:
            return
        now = self._clock()
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
            self._conn.execute(
                "DELETE FROM error_aggregates WHERE bucket_epoch < ?",
                (int(horizon),))
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
        """Delete globally OLDEST rows -- both tables as ONE timeline.

        Contract: no row at time T2 may be deleted while a strictly
        older row at T1 still exists in EITHER table; the survivors are
        always a newest-suffix of the merged epoch order. Ties at the
        cut epoch are settled deterministically (samples before states,
        insertion order within a table). File size can ONLY be
        re-measured after a full VACUUM: incremental vacuum releases free
        pages at the END of the file, but oldest-first deletes free pages
        behind live newest rows -- without the rewrite the measured size
        never drops and the loop would drain the whole table.
        """
        while self._db_bytes() > self._target_bytes:
            bytes_now = self._db_bytes()
            counts = [self._conn.execute(
                "SELECT COUNT(*) FROM %s" % table).fetchone()[0]
                for table in _PRUNE_TABLES]
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
                "SELECT epoch FROM ("
                " SELECT epoch FROM timeline_samples"
                " UNION ALL SELECT epoch FROM device_protocol_states"
                " UNION ALL SELECT bucket_epoch AS epoch FROM error_aggregates)"
                " ORDER BY epoch ASC LIMIT 1 OFFSET ?",
                (k - 1,)).fetchone()[0]
            remaining = k
            for table in _PRUNE_TABLES:       # strictly older than the cut
                if remaining <= 0:
                    break
                epoch_col = "bucket_epoch" if table == "error_aggregates" else "epoch"
                cursor = self._conn.execute(
                    "DELETE FROM %s WHERE %s < ?" % (table, epoch_col), (cut,))
                remaining -= max(cursor.rowcount, 0)
            for table in _PRUNE_TABLES:       # top up AT the cut epoch only
                if remaining <= 0:
                    break
                if table != "error_aggregates":
                    cursor = self._conn.execute(
                        "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s"
                        " WHERE epoch = ? ORDER BY rowid ASC LIMIT ?)"
                        % (table, table), (cut, remaining))
                else:
                    cursor = self._conn.execute(
                        "DELETE FROM error_aggregates WHERE "
                        "(bucket_epoch,classifier_version,journal_epoch,error_class,"
                        "protocol,dest_port,dest_class,fp) IN ("
                        "SELECT bucket_epoch,classifier_version,journal_epoch,"
                        "error_class,protocol,dest_port,dest_class,fp "
                        "FROM error_aggregates WHERE bucket_epoch=? "
                        "ORDER BY classifier_version,journal_epoch,error_class,"
                        "protocol,dest_port,dest_class,fp LIMIT ?)",
                        (cut, remaining))
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
