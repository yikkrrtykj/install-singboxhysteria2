"""Physically independent remote-probe store (issue #67 §11-§13, PR-6B).

The remote plane owns a SEPARATE SQLite database:

    <data_dir>/remote-probes/remote-probes.sqlite3   (0600, in a 0700 dir)

Core History stays exactly ``<data_dir>/diagnostics/history.sqlite3`` on
schema v5 with its current ``_PRUNE_SOURCES``; this store never touches it,
never enters History pruning, and can never make core History unavailable.

Schema v1 -- EXACTLY two application tables:

    remote_probe_samples  the retained evidence rows (the ONLY budget/age
                          pruning source);
    remote_probe_runs     continuity/idempotency state (never a pruning
                          source; lifetime 30 days after last activity).

`PRAGMA user_version = 1`, `journal_mode=DELETE`, `synchronous=FULL`, a
bounded busy timeout, exact table-set equality, and
unknown/newer/malformed schema -> the REMOTE plane fails closed (core
Monitor is untouched).

### The two-table idempotency proof (contract §7 gate)

The frozen semantics are: same ``(probe_id, run, seq)`` + same body hash ->
idempotent success (never a second evidence row); same tuple + different
hash -> equivocation reject; retained samples live up to 7 days subject to
the byte budget; run state lives 30 days after last activity. The exact
two-table model satisfies this because server acceptance enforces a STRICT
per-run progression: ``seq`` strictly increases with every accepted tuple
and ``sample_epoch`` strictly increases with every newly accepted one, and
the run row records the high-water of both. Therefore a tuple whose sample
row has aged out (or been budget-pruned) is provably one the server ALREADY
accepted -- its ``seq <= runs.max_seq`` -- and a replay is answered
idempotently (``duplicate``) without storing anything, exactly the §9
"idempotently accounted ... then age out" case. Equivocation detection is
defined over RETAINED evidence: while the sample row survives, its hash is
compared and a mismatch is an equivocation reject; once the evidence itself
has legitimately aged out there is no retained byte to contradict, and no
second evidence row can be created either way. No third table is needed and
none may be added.

A captured old HTTP request is rejected before any of this by the ±300 s
``sent_epoch`` freshness window -- aged-out run state never reopens replay.
"""

from __future__ import annotations

import os
import sqlite3
import stat as stat_module
import threading

DB_DIR_NAME = "remote-probes"
DB_NAME = "remote-probes.sqlite3"
SCHEMA_USER_VERSION = 1
BUSY_TIMEOUT_MS = 5000               # bounded

TABLE_SAMPLES = "remote_probe_samples"
TABLE_RUNS = "remote_probe_runs"
EXPECTED_TABLES = frozenset({TABLE_SAMPLES, TABLE_RUNS})

# §12 retention: up to 7 days, soft 16 MiB / hard 24 MiB on the STORE's own
# bytes (page_count * page_size). Never a History byte.
MAX_AGE_SECONDS = 7 * 86400.0
SOFT_BUDGET_BYTES = 16 * 1024 * 1024
HARD_BUDGET_BYTES = 24 * 1024 * 1024
PRUNE_BATCH = 256

# §13 continuity bounds.
MAX_RUNS_PER_PROBE = 64
MAX_RUNS_GLOBAL = 4096
RUN_LIFETIME_SECONDS = 30 * 86400.0

STATUS_KEYS = ("budget_pruned", "budget_pruned_total", "retained_since_epoch",
               "sample_count", "db_bytes", "run_count")


class RemoteStoreError(Exception):
    """The remote store is unusable right now (sanitized text only)."""


class RunCapacityError(RemoteStoreError):
    """A new run would exceed a frozen continuity bound with no legally
    expirable row. Live state is never deleted to make room."""


class RemoteStore:
    """One closed SQLite plane: samples + continuity runs."""

    def __init__(self, data_dir, clock=None):
        import time
        self.directory = os.path.join(data_dir, DB_DIR_NAME)
        self.db_path = os.path.join(self.directory, DB_NAME)
        self.clock = clock or (lambda: time.time())
        self._conn = None
        self._lock = threading.RLock()
        self._opened = False
        # Instance-level budget numbers: the defaults are the FROZEN
        # contract constants; deterministic tests may scale them and
        # exercise the exact product prune loop.
        self.hard_budget = HARD_BUDGET_BYTES
        self.soft_budget = SOFT_BUDGET_BYTES
        self.prune_batch = PRUNE_BATCH
        self._budget_pruned = False          # runtime-generation bool
        self._budget_pruned_total = 0        # runtime explanatory counter

    # -- lifecycle -----------------------------------------------------------

    def open(self):
        """Create/open the store. Every failure is a sanitized
        ``RemoteStoreError`` -- the caller degrades the REMOTE plane only."""
        self._ensure_directory()
        self._ensure_db_file()
        try:
            # The plane serialises every access with its own RLock (the
            # History store's pattern), so the connection may be used from
            # whatever thread the HTTP handler runs on.
            conn = sqlite3.connect(self.db_path,
                                   timeout=BUSY_TIMEOUT_MS / 1000.0,
                                   isolation_level=None,
                                   check_same_thread=False)
        except sqlite3.Error as exc:
            raise RemoteStoreError("store connect refused: %s"
                                   % type(exc).__name__) from None
        self._conn = conn
        try:
            conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
            conn.execute("PRAGMA journal_mode=DELETE").fetchall()
            conn.execute("PRAGMA synchronous=FULL")
            self._verify_schema(conn)
        except sqlite3.Error as exc:
            self.close()
            raise RemoteStoreError("store unusable: %s"
                                   % type(exc).__name__) from None
        except BaseException:
            self.close()
            raise
        self._opened = True
        return self

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None
            self._opened = False

    def _ensure_directory(self):
        if os.path.islink(self.directory):
            raise RemoteStoreError("store directory must not be a symlink")
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise RemoteStoreError("store directory unusable: %s"
                                   % type(exc).__name__) from None
        if not os.path.isdir(self.directory):
            raise RemoteStoreError("store path is not a directory")
        if os.name == "posix":
            try:
                os.chmod(self.directory, 0o700)
                mode = stat_module.S_IMODE(os.stat(self.directory).st_mode)
            except OSError:
                raise RemoteStoreError("store directory not statable") from None
            if mode != 0o700:
                raise RemoteStoreError("store directory mode must be 0700")

    def _ensure_db_file(self):
        """The DB file exists only as a regular 0600 file (never a symlink,
        never a special object, never created with a looser mode)."""
        if os.path.lexists(self.db_path):
            if os.path.islink(self.db_path):
                raise RemoteStoreError("store DB must not be a symlink")
            try:
                st = os.lstat(self.db_path)
            except OSError as exc:
                raise RemoteStoreError("store DB unstatable: %s"
                                       % type(exc).__name__) from None
            if not stat_module.S_ISREG(st.st_mode):
                raise RemoteStoreError("store DB must be a regular file")
            if os.name == "posix" \
                    and stat_module.S_IMODE(st.st_mode) != 0o600:
                raise RemoteStoreError("store DB mode must be 0600")
            return
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(self.db_path, flags, 0o600)
            os.close(fd)
        except OSError as exc:
            raise RemoteStoreError("store DB not creatable: %s"
                                   % type(exc).__name__) from None

    def _verify_schema(self, conn):
        """Exact schema gate: user_version == 1 and EXACTLY the two
        application tables. Unknown/newer/malformed fails the REMOTE plane
        closed; a foreign table is never auto-adopted. A fresh empty file
        (no tables, user_version 0) is created at v1; an empty table set
        with any OTHER user_version is malformed, not fresh."""
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()
        names = {row[0] for row in rows}
        if not names:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version in (0, SCHEMA_USER_VERSION):
                self._create_schema(conn)
                return
            raise RemoteStoreError("store schema user_version=%d" % version)
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_USER_VERSION:
            raise RemoteStoreError("store schema user_version=%d" % version)
        if names != EXPECTED_TABLES:
            raise RemoteStoreError("store table set mismatch")

    @staticmethod
    def _create_schema(conn):
        conn.execute(
            "CREATE TABLE %s ("
            " probe_id TEXT NOT NULL,"
            " run TEXT NOT NULL,"
            " seq INTEGER NOT NULL,"
            " sample_epoch REAL NOT NULL,"
            " received_epoch REAL NOT NULL,"
            " body_hash TEXT NOT NULL,"
            " body BLOB NOT NULL,"
            " PRIMARY KEY (probe_id, run, seq))" % TABLE_SAMPLES)
        conn.execute(
            "CREATE INDEX %s_age ON %s (probe_id, sample_epoch)"
            % (TABLE_SAMPLES, TABLE_SAMPLES))
        conn.execute(
            "CREATE TABLE %s ("
            " probe_id TEXT NOT NULL,"
            " run TEXT NOT NULL,"
            " max_seq INTEGER NOT NULL,"
            " max_sample_epoch REAL NOT NULL,"
            " created_epoch REAL NOT NULL,"
            " last_activity_epoch REAL NOT NULL,"
            " PRIMARY KEY (probe_id, run))" % TABLE_RUNS)
        conn.execute("PRAGMA user_version=%d" % SCHEMA_USER_VERSION)

    # -- continuity / idempotency primitives ---------------------------------

    def sample_hash(self, probe_id, run, seq):
        """The retained body hash for one identity tuple, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT body_hash FROM %s WHERE probe_id=? AND run=? AND seq=?"
                % TABLE_SAMPLES, (probe_id, run, int(seq))).fetchone()
        return row[0] if row else None

    def run_state(self, probe_id, run):
        """The continuity row for one (probe_id, run), or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT max_seq, max_sample_epoch, created_epoch, "
                "last_activity_epoch FROM %s WHERE probe_id=? AND run=?"
                % TABLE_RUNS, (probe_id, run)).fetchone()
        if not row:
            return None
        return {"max_seq": int(row[0]), "max_sample_epoch": float(row[1]),
                "created_epoch": float(row[2]),
                "last_activity_epoch": float(row[3])}

    def begin_run(self, probe_id, run, now):
        """Create the continuity row for a NEW run, honouring the frozen
        bounds. Expired rows are removed first (they are legally expirable);
        a full capacity with none expirable raises ``RunCapacityError`` --
        live idempotency state is NEVER deleted to make room."""
        with self._lock:
            self._expire_runs(now)
            probe_count = int(self._conn.execute(
                "SELECT COUNT(*) FROM %s WHERE probe_id=?"
                % TABLE_RUNS, (probe_id,)).fetchone()[0])
            if probe_count >= MAX_RUNS_PER_PROBE:
                raise RunCapacityError("probe run capacity")
            global_count = int(self._conn.execute(
                "SELECT COUNT(*) FROM %s" % TABLE_RUNS).fetchone()[0])
            if global_count >= MAX_RUNS_GLOBAL:
                raise RunCapacityError("global run capacity")
            self._conn.execute(
                "INSERT INTO %s (probe_id, run, max_seq, max_sample_epoch,"
                " created_epoch, last_activity_epoch)"
                " VALUES (?, ?, 0, -1.0, ?, ?)"
                % TABLE_RUNS, (probe_id, run, float(now), float(now)))

    def note_activity(self, probe_id, run, now):
        """Record that an authenticated request touched this run (accepted,
        idempotently accounted or retried): the 30-day lifetime counts from
        the LAST such activity."""
        with self._lock:
            self._conn.execute(
                "UPDATE %s SET last_activity_epoch=? WHERE probe_id=? AND run=?"
                % TABLE_RUNS, (float(now), probe_id, run))

    def record_accepted(self, probe_id, run, seq, sample_epoch, body_hash,
                        body, now):
        """Insert one evidence row and advance the run's progression in ONE
        transaction. The caller has already proven: identity authenticated,
        tuple not retained, seq > run.max_seq, sample_epoch > run.max_sample_epoch."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO %s (probe_id, run, seq, sample_epoch,"
                    " received_epoch, body_hash, body)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)" % TABLE_SAMPLES,
                    (probe_id, run, int(seq), float(sample_epoch),
                     float(now), body_hash, sqlite3.Binary(body)))
                self._conn.execute(
                    "UPDATE %s SET max_seq=?, max_sample_epoch=?,"
                    " last_activity_epoch=? WHERE probe_id=? AND run=?"
                    % TABLE_RUNS,
                    (int(seq), float(sample_epoch), float(now),
                     probe_id, run))
                self._conn.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise RemoteStoreError("sample not stored: %s"
                                       % type(exc).__name__) from None

    def _expire_runs(self, now):
        """Remove ONLY runs whose 30-day lifetime has passed."""
        horizon = float(now) - RUN_LIFETIME_SECONDS
        self._conn.execute(
            "DELETE FROM %s WHERE last_activity_epoch < ?" % TABLE_RUNS,
            (horizon,))

    # -- retention -----------------------------------------------------------

    def _db_bytes(self):
        """The store's LIVE data size in bytes.

        Freelist pages are excluded: deleted-but-not-yet-reclaimed pages
        are not evidence, and counting them would make the prune loop
        unable to see its own progress (it would keep deleting past the
        soft target -- all the way to an empty store). The final VACUUM
        reclaims the freelist so the file matches this number.
        """
        with self._lock:
            page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(self._conn.execute(
                "PRAGMA page_count").fetchone()[0])
            freelist = int(self._conn.execute(
                "PRAGMA freelist_count").fetchone()[0])
        return page_size * (page_count - freelist)

    def enforce_retention(self, now=None):
        """Age + budget retention over ``remote_probe_samples`` ONLY.

        Samples older than 7 days are removed. When the store's own byte
        size crosses the 24 MiB hard ceiling, the OLDEST samples are pruned
        until below the 16 MiB soft target, then space is reclaimed with
        VACUUM. ``remote_probe_runs`` is never a pruning source, and core
        History is unreachable from here by construction.
        """
        now = float(self.clock() if now is None else now)
        with self._lock:
            self._expire_runs(now)
            self._conn.execute(
                "DELETE FROM %s WHERE sample_epoch < ?" % TABLE_SAMPLES,
                (now - MAX_AGE_SECONDS,))
            pruned = 0
            if self._db_bytes() > self.hard_budget:
                self._budget_pruned = True
                while self._db_bytes() > self.soft_budget:
                    cursor = self._conn.execute(
                        "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s"
                        " ORDER BY sample_epoch ASC, seq ASC LIMIT ?)"
                        % (TABLE_SAMPLES, TABLE_SAMPLES),
                        (self.prune_batch,))
                    removed = cursor.rowcount if cursor.rowcount > 0 else 0
                    if removed <= 0:
                        break            # nothing left we may delete
                    pruned += removed
                self._conn.execute("VACUUM")   # reclaim the freelist
            if pruned:
                self._budget_pruned_total += 1
            return self.status()

    # -- closed status -------------------------------------------------------

    def status(self):
        """Closed, sanitized store status (§12 minimum fields plus the
        store's own byte size and the continuity row count)."""
        with self._lock:
            if not self._opened:
                return {key: None for key in STATUS_KEYS}
            row = self._conn.execute(
                "SELECT MIN(sample_epoch), COUNT(*) FROM %s"
                % TABLE_SAMPLES).fetchone()
            run_count = int(self._conn.execute(
                "SELECT COUNT(*) FROM %s" % TABLE_RUNS).fetchone()[0])
            return {
                "budget_pruned": bool(self._budget_pruned),
                "budget_pruned_total": int(self._budget_pruned_total),
                "retained_since_epoch": (float(row[0])
                                         if row and row[0] is not None
                                         else None),
                "sample_count": int(row[1]) if row else 0,
                "db_bytes": self._db_bytes(),
                "run_count": run_count,
            }
