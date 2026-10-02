"""Independent three-table remote plane, Issue #67 re-freeze 2026-10-02.

Disposable samples are evidence. Immutable receipts owned by continuity
runs authorize retries after pruning. High-water never proves receipt
existence. This module has no History or classifier dependency.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
import shutil
import sqlite3
import stat
import threading
import time

DB_DIR_NAME = "remote-probes"
DB_NAME = "remote-probes.sqlite3"
SCHEMA_USER_VERSION = 1
BUSY_TIMEOUT_MS = 5000
TABLE_SAMPLES = "remote_probe_samples"
TABLE_RUNS = "remote_probe_runs"
TABLE_RECEIPTS = "remote_probe_receipts"
EXPECTED_TABLES = frozenset({TABLE_SAMPLES, TABLE_RUNS, TABLE_RECEIPTS})
MAX_AGE_SECONDS = 7 * 86400.0
NEW_SAMPLE_MAX_AGE = MAX_AGE_SECONDS + 12 * 3600
SOFT_BUDGET_BYTES = 16 * 1024 * 1024
HARD_BUDGET_BYTES = 24 * 1024 * 1024
SAMPLE_ROW_CHARGE = RECEIPT_ROW_CHARGE = 256
RUN_ROW_CHARGE = 1024
MAX_RUNS_PER_PROBE = 64
MAX_RUNS_GLOBAL = 4096
MAX_RECEIPTS_PER_PROBE = 131072
MAX_RECEIPTS_GLOBAL = 1048576
RECEIPT_BUDGET_BYTES = 256 * 1024 * 1024
RUN_BUDGET_BYTES = 4 * 1024 * 1024
DB_BUDGET_BYTES = 320 * 1024 * 1024
WORKING_BUDGET_BYTES = 1024 * 1024 * 1024
RUN_LIFETIME_SECONDS = 30 * 86400.0
PRUNE_BATCH = READ_LIMIT = 256
STATUS_KEYS = ("budget_pruned", "budget_pruned_total", "retained_since_epoch",
               "sample_count", "sample_bytes", "receipt_count", "receipt_bytes",
               "run_count", "run_bytes", "db_live_bytes", "db_allocated_bytes",
               "capacity_code")

# DDL is also the v1 constraint gate: names alone establish no authority.
SCHEMA = (
    "CREATE TABLE remote_probe_runs (probe_id TEXT NOT NULL, run TEXT NOT NULL, "
    "max_seq INTEGER NOT NULL CHECK(max_seq >= 1), "
    "max_sample_epoch REAL NOT NULL CHECK(max_sample_epoch >= 0), "
    "created_epoch REAL NOT NULL, last_activity_epoch REAL NOT NULL, "
    "PRIMARY KEY(probe_id, run))",
    "CREATE TABLE remote_probe_receipts (probe_id TEXT NOT NULL, run TEXT NOT NULL, "
    "seq INTEGER NOT NULL CHECK(seq >= 1), body_hash BLOB NOT NULL "
    "CHECK(typeof(body_hash) = 'blob' AND length(body_hash) = 32), "
    "accepted_epoch REAL NOT NULL, PRIMARY KEY(probe_id, run, seq), "
    "FOREIGN KEY(probe_id, run) REFERENCES remote_probe_runs(probe_id, run) ON DELETE CASCADE)",
    "CREATE TABLE remote_probe_samples (probe_id TEXT NOT NULL, run TEXT NOT NULL, "
    "seq INTEGER NOT NULL, sample_epoch REAL NOT NULL CHECK(sample_epoch >= 0), "
    "received_epoch REAL NOT NULL, body_hash BLOB NOT NULL "
    "CHECK(typeof(body_hash) = 'blob' AND length(body_hash) = 32), body BLOB NOT NULL "
    "CHECK(typeof(body) = 'blob' AND length(body) BETWEEN 1 AND 16384), "
    "PRIMARY KEY(probe_id, run, seq), FOREIGN KEY(probe_id, run, seq) "
    "REFERENCES remote_probe_receipts(probe_id, run, seq) ON DELETE CASCADE)",
    "CREATE INDEX remote_probe_samples_age ON remote_probe_samples(sample_epoch, probe_id, run, seq)",
    "CREATE INDEX remote_probe_runs_activity ON remote_probe_runs(last_activity_epoch)",
)


class RemoteStoreError(Exception):
    """Sanitized remote-only failure."""
    code = "remote_store_unavailable"


class RunCapacityError(RemoteStoreError):
    code = "remote_run_capacity"


class ReceiptCapacityError(RemoteStoreError):
    code = "remote_receipt_capacity"


class StorageCapacityError(RemoteStoreError):
    code = "remote_storage_capacity"


class RemoteStore:
    def __init__(self, data_dir, clock=None):
        self.directory = os.path.join(data_dir, DB_DIR_NAME)
        self.db_path = os.path.join(self.directory, DB_NAME)
        self.clock = clock or time.time
        self._conn = None
        self._opened = False
        self._lock = threading.RLock()
        # Injectable bounds for deterministic tests, with no HTTP/config knobs.
        self.hard_budget, self.soft_budget = HARD_BUDGET_BYTES, SOFT_BUDGET_BYTES
        self.prune_batch = PRUNE_BATCH
        self.max_runs_per_probe, self.max_runs_global = MAX_RUNS_PER_PROBE, MAX_RUNS_GLOBAL
        self.max_receipts_per_probe = MAX_RECEIPTS_PER_PROBE
        self.max_receipts_global = MAX_RECEIPTS_GLOBAL
        self.receipt_budget, self.run_budget = RECEIPT_BUDGET_BYTES, RUN_BUDGET_BYTES
        self.db_budget, self.working_budget = DB_BUDGET_BYTES, WORKING_BUDGET_BYTES
        self._budget_pruned = False
        self._budget_pruned_total = 0

    def open(self):
        with self._lock:
            try:
                self._ensure_paths()
                self._conn = sqlite3.connect(self.db_path, timeout=BUSY_TIMEOUT_MS / 1000,
                                            isolation_level=None, check_same_thread=False)
                self._conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
                self._conn.execute("PRAGMA foreign_keys=ON")
                # Gate BEFORE journal/retention writes. Draft v1 stays intact.
                self._verify_schema()
                self._conn.execute("PRAGMA journal_mode=DELETE").fetchall()
                self._conn.execute("PRAGMA synchronous=FULL")
                self._set_page_ceiling()
                self._opened = True
                self.enforce_retention()
                return self
            except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, RemoteStoreError):
                self.close()
                raise RemoteStoreError("remote store open refused") from None

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
            self._conn, self._opened = None, False

    def _ensure_paths(self):
        if os.path.islink(self.directory):
            raise RemoteStoreError("unsafe directory")
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        st = os.lstat(self.directory)
        if not stat.S_ISDIR(st.st_mode) or (os.name == "posix" and
                (stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid())):
            raise RemoteStoreError("unsafe directory")
        if not os.path.lexists(self.db_path):
            fd = os.open(self.db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        before = os.lstat(self.db_path)
        if not stat.S_ISREG(before.st_mode):
            raise RemoteStoreError("unsafe DB")
        fd = os.open(self.db_path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) \
                    or (os.name == "posix" and
                        (stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_uid != os.geteuid())):
                raise RemoteStoreError("unsafe DB")
        finally:
            os.close(fd)

    @staticmethod
    def _normalized(sql):
        return " ".join(sql.lower().split())

    def _verify_schema(self):
        conn = self._conn
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        objects = conn.execute("SELECT type,name,sql FROM sqlite_master "
                               "WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if not objects and version == 0:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for sql in SCHEMA:
                    conn.execute(sql)
                conn.execute("PRAGMA user_version=1")
                conn.execute("COMMIT")
            except sqlite3.Error:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        elif version != 1 or len(objects) != len(SCHEMA) or \
                {self._normalized(row[2] or "") for row in objects} != \
                {self._normalized(sql) for sql in SCHEMA}:
            raise RemoteStoreError("incompatible schema")
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok" \
                or conn.execute("PRAGMA foreign_key_check").fetchone():
            raise RemoteStoreError("inconsistent store")
        if conn.execute(
                "SELECT 1 FROM remote_probe_runs r LEFT JOIN remote_probe_receipts p "
                "ON p.probe_id=r.probe_id AND p.run=r.run AND p.seq=r.max_seq "
                "WHERE p.seq IS NULL OR EXISTS (SELECT 1 FROM remote_probe_receipts q "
                "WHERE q.probe_id=r.probe_id AND q.run=r.run AND q.seq>r.max_seq) LIMIT 1").fetchone():
            raise RemoteStoreError("inconsistent progression")
        if conn.execute(
                "SELECT 1 FROM remote_probe_samples s JOIN remote_probe_receipts p "
                "USING(probe_id,run,seq) JOIN remote_probe_runs r USING(probe_id,run) "
                "WHERE s.body_hash != p.body_hash OR s.sample_epoch>r.max_sample_epoch "
                "OR (s.seq=r.max_seq AND s.sample_epoch != r.max_sample_epoch) LIMIT 1").fetchone():
            raise RemoteStoreError("inconsistent evidence")
        from remote_probe.payload import valid_probe_id, valid_run, validate_sample, canonical_bytes
        for probe, run, seq, epoch, created, activity in conn.execute("SELECT * FROM remote_probe_runs"):
            if not valid_probe_id(probe) or not valid_run(run) or type(seq) is not int \
                    or not 1 <= seq <= (1 << 63)-1 \
                    or not all(type(x) in (int, float) and math.isfinite(x) and x >= 0
                               for x in (epoch, created, activity)) or activity < created:
                raise RemoteStoreError("invalid run state")
        if conn.execute("SELECT 1 FROM remote_probe_receipts p JOIN remote_probe_runs r "
                "USING(probe_id,run) WHERE typeof(seq)!='integer' OR seq<1 "
                "OR typeof(accepted_epoch) NOT IN ('integer','real') OR accepted_epoch<0 "
                "OR accepted_epoch>r.last_activity_epoch LIMIT 1").fetchone():
            raise RemoteStoreError("invalid receipt state")
        for probe, run, seq, epoch, received, digest, body in conn.execute("SELECT * FROM remote_probe_samples"):
            sample = json.loads(body)
            if validate_sample(sample) or canonical_bytes(sample) != body \
                    or hashlib.sha256(body).digest() != digest \
                    or (sample['probe_id'],sample['run'],sample['seq'],sample['sample_epoch']) != (probe,run,seq,epoch) \
                    or type(received) not in (int,float) or not math.isfinite(received) or received < 0:
                raise RemoteStoreError("inconsistent evidence hash")

    @contextmanager
    def _transaction(self):
        with self._lock:
            if not self._opened or self._conn is None:
                raise RemoteStoreError("store closed")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield
                self._conn.execute("COMMIT")
            except BaseException as exc:
                if self._conn.in_transaction:
                    try:
                        self._conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                if isinstance(exc, sqlite3.Error):
                    # Python 3.10 (Ubuntu 22.04) lacks sqlite_errorcode and
                    # the newer module result constants. Compare only the
                    # fixed driver FULL message internally; never expose it.
                    code = getattr(exc, "sqlite_errorcode", None)
                    if code == 13 or (code is None and str(exc) == "database or disk is full"):
                        raise StorageCapacityError("DB page ceiling") from None
                    raise RemoteStoreError("store transaction failed") from None
                if isinstance(exc, OSError):
                    raise RemoteStoreError("store I/O failed") from None
                raise

    def _count(self, table, probe_id=None):
        sql, args = "SELECT COUNT(*) FROM " + table, ()
        if probe_id is not None:
            sql += " WHERE probe_id=?"
            args = (probe_id,)
        return self._conn.execute(sql, args).fetchone()[0]

    def _sample_bytes(self):
        return self._conn.execute("SELECT COALESCE(SUM(length(body)+?),0) "
                                  "FROM remote_probe_samples", (SAMPLE_ROW_CHARGE,)).fetchone()[0]

    def _page_bytes(self):
        size = self._conn.execute("PRAGMA page_size").fetchone()[0]
        count = self._conn.execute("PRAGMA page_count").fetchone()[0]
        free = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
        return (count - free) * size, count * size

    def _set_page_ceiling(self):
        size = self._conn.execute("PRAGMA page_size").fetchone()[0]
        self._conn.execute("PRAGMA max_page_count=%d" % max(1, self.db_budget // size))

    def _reserve_working_space(self):
        # Bound/reserve main DB + DELETE journal + VACUUM copy. Each original
        # page is journaled once; 8 MiB covers journal headers/rounding.
        overhead = 8 * 1024 * 1024
        footprint = journal_bytes = 0
        for item in os.scandir(self.directory):
            st = item.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise RemoteStoreError("unsafe store working object")
            footprint += st.st_size
            if item.name == DB_NAME + "-journal":
                journal_bytes = st.st_size
        # The current DELETE journal is already one of the reserved copies,
        # not unrelated directory data; do not double-charge large expiry.
        other = max(0, footprint - os.path.getsize(self.db_path) - journal_bytes)
        if 3 * self.db_budget + overhead + other > self.working_budget \
                or footprint > self.working_budget \
                or journal_bytes > self.db_budget + overhead \
                or shutil.disk_usage(self.directory).free < max(0,2*self.db_budget+overhead-journal_bytes):
            raise StorageCapacityError("working space capacity")

    def _physical_admission(self):
        self._set_page_ceiling()
        live, allocated = self._page_bytes()
        if live > self.db_budget or allocated > self.db_budget:
            raise StorageCapacityError("DB capacity")
        self._reserve_working_space()

    def _prune(self, now, prospective_sample_bytes=0):
        # Only legal run expiry cascades into receipts; sample pruning cannot.
        self._conn.execute("DELETE FROM remote_probe_runs WHERE last_activity_epoch < ?",
                           (now - RUN_LIFETIME_SECONDS,))
        self._conn.execute("DELETE FROM remote_probe_samples WHERE sample_epoch < ?",
                           (now - MAX_AGE_SECONDS,))
        pruned = 0
        if self._sample_bytes() + prospective_sample_bytes > self.hard_budget:
            while self._sample_bytes() + prospective_sample_bytes > self.soft_budget:
                removed = self._conn.execute("DELETE FROM remote_probe_samples WHERE rowid IN "
                    "(SELECT rowid FROM remote_probe_samples ORDER BY sample_epoch,probe_id,run,seq LIMIT ?)",
                    (self.prune_batch,)).rowcount
                if removed <= 0:
                    break
                pruned += removed
        return pruned

    def _note_pruned(self, count):
        if count:
            self._budget_pruned = True
            self._budget_pruned_total += 1

    def _activity(self, probe_id, run, now):
        self._conn.execute("UPDATE remote_probe_runs SET last_activity_epoch=MAX(last_activity_epoch,?) "
                           "WHERE probe_id=? AND run=?", (now, probe_id, run))

    def _capacity(self, probe_id, new_run):
        runs = self._count(TABLE_RUNS)
        if new_run and (self._count(TABLE_RUNS, probe_id) >= self.max_runs_per_probe
                        or runs >= self.max_runs_global or (runs+1)*RUN_ROW_CHARGE > self.run_budget):
            return RunCapacityError
        receipts = self._count(TABLE_RECEIPTS)
        if self._count(TABLE_RECEIPTS, probe_id) >= self.max_receipts_per_probe \
                or receipts >= self.max_receipts_global \
                or (receipts+1)*RECEIPT_ROW_CHARGE > self.receipt_budget:
            return ReceiptCapacityError
        return None

    def accept(self, probe_id, run, seq, sample_epoch, body, now=None):
        """Atomic receipt classification, new-tuple admission and durable write.

        Caller supplies authenticated canonical bytes. Hash is computed here.
        Return a closed verdict; capacity failures are typed exceptions.
        """
        now = float(self.clock() if now is None else now)
        with self._lock:
            try:
                return self._accept_locked(probe_id, run, seq, sample_epoch, body, now)
            except StorageCapacityError:
                # SQLITE_FULL may automatically roll back the entire SQLite
                # transaction, including activity. Refresh only a canonical,
                # progression-valid existing-run capacity retry in a fresh
                # bounded transaction; never manufacture accepted state.
                with self._transaction():
                    state = self._conn.execute("SELECT max_seq,max_sample_epoch,last_activity_epoch "
                        "FROM remote_probe_runs WHERE probe_id=? AND run=?", (probe_id,run)).fetchone()
                    if state and state[2] >= now-RUN_LIFETIME_SECONDS and seq > state[0] \
                            and sample_epoch > state[1] and now-NEW_SAMPLE_MAX_AGE <= sample_epoch <= now+300:
                        self._activity(probe_id,run,now)
                raise

    def _accept_locked(self, probe_id, run, seq, sample_epoch, body, now):
        digest = hashlib.sha256(body).digest()
        failure, verdict = None, None
        with self._transaction():
            pruned = self._prune(now)
            receipt = self._conn.execute("SELECT body_hash FROM remote_probe_receipts "
                "WHERE probe_id=? AND run=? AND seq=?", (probe_id, run, seq)).fetchone()
            if receipt is not None:
                verdict = "duplicate" if receipt[0] == digest else "equivocation"
                if verdict == "duplicate":
                    self._activity(probe_id, run, now)
            else:
                state = self._conn.execute("SELECT max_seq,max_sample_epoch FROM remote_probe_runs "
                    "WHERE probe_id=? AND run=?", (probe_id, run)).fetchone()
                if type(sample_epoch) not in (int, float) or not math.isfinite(sample_epoch) or sample_epoch < 0:
                    verdict = "sample_epoch_out_of_range"
                elif state is not None and seq <= state[0]:
                    verdict = "sequence_not_increasing"
                elif state is not None and sample_epoch <= state[1]:
                    verdict = "sample_epoch_not_increasing"
                elif sample_epoch > now+300 or sample_epoch < now-NEW_SAMPLE_MAX_AGE:
                    verdict = "sample_epoch_out_of_range"
                else:
                    failure = self._capacity(probe_id, state is None)
                    if failure is None:
                        self._conn.execute("SAVEPOINT admission")
                        try:
                            # Prune prospective sample pressure before insert,
                            # so page ceilings do not preempt legal retention.
                            new_pruned = self._prune(now, len(body)+SAMPLE_ROW_CHARGE)
                            self._physical_admission()
                            if state is None:
                                self._conn.execute("INSERT INTO remote_probe_runs VALUES(?,?,?,?,?,?)",
                                    (probe_id, run, seq, sample_epoch, now, now))
                            self._conn.execute("INSERT INTO remote_probe_receipts VALUES(?,?,?,?,?)",
                                (probe_id, run, seq, digest, now))
                            self._conn.execute("INSERT INTO remote_probe_samples VALUES(?,?,?,?,?,?,?)",
                                (probe_id, run, seq, sample_epoch, now, digest, body))
                            self._conn.execute("UPDATE remote_probe_runs SET max_seq=?,max_sample_epoch=?,"
                                "last_activity_epoch=MAX(last_activity_epoch,?) WHERE probe_id=? AND run=?",
                                (seq, sample_epoch, now, probe_id, run))
                            new_pruned += self._prune(now)
                            self._physical_admission()
                            self._conn.execute("RELEASE admission")
                            pruned += new_pruned
                            verdict = "accepted"
                        except StorageCapacityError:
                            self._conn.execute("ROLLBACK TO admission")
                            self._conn.execute("RELEASE admission")
                            failure = StorageCapacityError
                    if failure is not None and state is not None:
                        self._activity(probe_id, run, now)
        with self._lock:
            self._note_pruned(pruned)
        if failure:
            raise failure("remote admission capacity")
        return verdict

    def enforce_retention(self, now=None):
        now = float(self.clock() if now is None else now)
        with self._lock:
            with self._transaction():
                pruned = self._prune(now)
            self._note_pruned(pruned)
            return self._status_snapshot()

    def receipt_hash(self, probe_id, run, seq):
        with self._lock:
            self.enforce_retention()
            rows = self._query_rows("SELECT body_hash FROM remote_probe_receipts "
                "WHERE probe_id=? AND run=? AND seq=?", (probe_id, run, seq))
            return rows[0][0] if rows else None

    def _query_rows(self, sql, args=()):
        try:
            if not self._opened or self._conn is None:
                raise RemoteStoreError("store closed")
            return self._conn.execute(sql,args).fetchall()
        except sqlite3.Error:
            raise RemoteStoreError("remote query failed") from None

    def run_state(self, probe_id, run):
        with self._lock:
            self.enforce_retention()
            rows = self._query_rows("SELECT max_seq,max_sample_epoch,created_epoch,last_activity_epoch "
                "FROM remote_probe_runs WHERE probe_id=? AND run=?", (probe_id, run))
            return dict(zip(("max_seq", "max_sample_epoch", "created_epoch", "last_activity_epoch"), rows[0])) if rows else None

    def read_samples(self, start_epoch, end_epoch, probe_id=None, limit=READ_LIMIT):
        """Bounded retained evidence; no HTTP/incident route here."""
        if type(limit) is not int or not 1 <= limit <= READ_LIMIT \
                or not all(type(x) in (int, float) and math.isfinite(x) and x >= 0
                           for x in (start_epoch, end_epoch)) \
                or not 0 <= end_epoch-start_epoch <= MAX_AGE_SECONDS:
            raise ValueError("invalid remote read bounds")
        with self._lock:
            self.enforce_retention()
            sql = "SELECT body FROM remote_probe_samples WHERE sample_epoch BETWEEN ? AND ?"
            args = [start_epoch, end_epoch]
            if probe_id is not None:
                sql += " AND probe_id=?"
                args.append(probe_id)
            sql += " ORDER BY sample_epoch,probe_id,run,seq LIMIT ?"
            args.append(limit)
            try:
                return [json.loads(row[0]) for row in self._query_rows(sql, args)]
            except (sqlite3.Error, ValueError, UnicodeError):
                raise RemoteStoreError("remote read failed") from None

    def probe_sample_times(self):
        with self._lock:
            self.enforce_retention()
            return dict(self._query_rows("SELECT probe_id,MAX(sample_epoch) "
                                           "FROM remote_probe_samples GROUP BY probe_id"))

    def capacity_code(self, probe_id=None):
        with self._lock:
            try:
                live, allocated = self._page_bytes()
                if live >= self.db_budget or allocated > self.db_budget:
                    return StorageCapacityError.code
                self._reserve_working_space()
                if probe_id is not None:
                    failure = self._capacity(probe_id, True)
                    return failure.code if failure else None
                if self._count(TABLE_RECEIPTS) >= self.max_receipts_global \
                        or (self._count(TABLE_RECEIPTS)+1)*RECEIPT_ROW_CHARGE > self.receipt_budget:
                    return ReceiptCapacityError.code
                if self._count(TABLE_RUNS) >= self.max_runs_global \
                        or (self._count(TABLE_RUNS)+1)*RUN_ROW_CHARGE > self.run_budget:
                    return RunCapacityError.code
                return None
            except StorageCapacityError:
                return StorageCapacityError.code
            except (sqlite3.Error, OSError):
                raise RemoteStoreError("remote capacity status failed") from None

    def _status_snapshot(self):
        with self._lock:
            if not self._opened:
                return {key: None for key in STATUS_KEYS}
            try:
                oldest, count = self._conn.execute(
                    "SELECT MIN(sample_epoch),COUNT(*) FROM remote_probe_samples").fetchone()
                receipts, runs = self._count(TABLE_RECEIPTS), self._count(TABLE_RUNS)
                live, allocated = self._page_bytes()
                return dict(zip(STATUS_KEYS, (self._budget_pruned, self._budget_pruned_total,
                    oldest, count, self._sample_bytes(), receipts, receipts*RECEIPT_ROW_CHARGE,
                    runs, runs*RUN_ROW_CHARGE, live, allocated, self.capacity_code())))
            except (sqlite3.Error, OSError):
                raise RemoteStoreError("remote status failed") from None

    def status(self):
        return self.enforce_retention() if self._opened else self._status_snapshot()
