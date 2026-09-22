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
  Schema version lives in ``meta``; migrations are forward-only.
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
  newest rows are never sacrificed for old.
"""

from __future__ import annotations

import datetime
import os
import sqlite3
import stat
import threading
import time

SCHEMA_VERSION = 1

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

    The publisher thread owns all writes via ``on_publish``; HTTP reader
    threads only call ``query_timeline`` / ``health``. One internal lock
    serializes both -- writes are rare (>= 5s apart) so contention is a
    non-issue, and correctness never depends on sqlite's own threading.
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

        self._lock = threading.Lock()
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

    # -- public surface (NONE of these ever raise) -----------------------------

    def open(self):
        """Validate storage and create/migrate the schema. Fail-soft:
        a refusal flips the health state, it never raises to the caller."""
        try:
            self._open_locked()
        except _HistoryError as exc:
            self._record_failure(exc.code)
        except (sqlite3.Error, OSError):
            self._record_failure(CODE_OPEN_FAILED)

    def on_publish(self, snapshot, version):
        """Publication-boundary hook (publisher thread ONLY).

        Never raises: a history failure must be invisible to the broker
        loop apart from the health state, so one bad disk cannot stop the
        dashboard from serving fresh snapshots.
        """
        try:
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

    # -- open / schema -----------------------------------------------------------

    def _open_locked(self):
        self._validate_dir()
        self._validate_db_file()
        conn = sqlite3.connect(self._db_path, timeout=BUSY_TIMEOUT_MS / 1000.0,
                               check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
            self._ensure_schema(conn)
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

    def _ensure_schema(self, conn):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta ("
            " key TEXT NOT NULL PRIMARY KEY,"
            " value TEXT NOT NULL)")
        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            now = self._clock()
            conn.executemany(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                [("schema_version", str(SCHEMA_VERSION)),
                 ("created_at", _iso(now)),
                 ("created_by_version", str(self._monitor_version))])
        else:
            version = _as_int(row[0], -1)
            if version > SCHEMA_VERSION:
                # written by a NEWER monitor: never downgrade in place
                raise _HistoryError(CODE_SCHEMA_UNSUPPORTED)
            # forward-only migrations land here (P1: version 1 is current)
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value)"
                " VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS timeline_samples ("
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
            "CREATE INDEX IF NOT EXISTS idx_samples_epoch"
            " ON timeline_samples(epoch)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS device_protocol_states ("
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
            "CREATE INDEX IF NOT EXISTS idx_states_epoch"
            " ON device_protocol_states(epoch)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_states_device"
            " ON device_protocol_states(device, inbound, epoch)")

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
        """Delete OLDEST rows in proportionate batches until below the target.

        Newest-first deletion is forbidden by contract: a retention run may
        only ever forget the past, never the present. File size can ONLY be
        re-measured after a full VACUUM: incremental vacuum releases free
        pages at the END of the file, but oldest-first deletes free pages
        behind live newest rows -- without the rewrite the measured size
        never drops and the loop would drain the whole table.
        """
        for _table in ("timeline_samples", "device_protocol_states"):
            while self._db_bytes() > self._target_bytes:
                total = self._conn.execute(
                    "SELECT COUNT(*) FROM %s" % _table).fetchone()[0]
                if total <= 0:
                    break
                bytes_now = self._db_bytes()
                # At least 10% and always a minimum batch: guarantees forward
                # progress without ever touching the newest suffix first.
                batch = max(PRUNE_BATCH_ROWS,
                            int(total * max((bytes_now - self._target_bytes)
                                            / float(bytes_now), 0.10)) + 1)
                self._conn.execute(
                    "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s"
                    " ORDER BY epoch ASC LIMIT ?)" % (_table, _table),
                    (batch,))
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
        self._failure_count += 1
        self._degraded = True
        self._last_error_code = code
        if code in (CODE_DIR_UNSAFE, CODE_DB_UNSAFE, CODE_OPEN_FAILED):
            self._enabled = False


class _HistoryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _project_rows(row, columns):
    values = dict(zip(columns, tuple(row)))
    return {column: values.get(column) for column in columns}
