"""Durable office-side spool -- spool-before-ack (issue #67 §5).

The spool exists for exactly one reason: a short server/network outage must not
erase office-side incident evidence. It is therefore append-only, fsynced
before a record is considered durable, and a record leaves the queue only in a
TERMINAL state (acknowledged, or resolved into the bounded quarantine ledger).

Crash-safety uses the same CLASS of primitives as the audited E4-Diag writer
(``monitor-v2/mihomo/diag.py``):

* directory: real, no symlink component, mode 0700 (tightened, matching
  History's ``_validate_dir`` and the E4-Diag writer);
* EVERY file this module owns -- the record chain, the state file, both temp
  files, the compaction temp and the lock -- is opened ``O_NOFOLLOW``,
  fstat-verified as a regular file and forced to mode 0600; a symlink, a
  special file or an unsafe target fails closed. The checks run on the OPEN
  descriptor, so there is no lstat-then-open TOCTOU window;
* one complete write loop per record, then ``fsync``;
* startup repairs AT MOST one incomplete trailing fragment;
* rotation with file fsync, rename, then directory fsync;
* startup ID reconciliation, so a crash between the record fsync and the state
  save can never make the next append reuse a record id;
* an advisory single-writer lock, so two agents over one directory cannot
  produce duplicate cursors or duplicate uploads;
* durable per-record retry counters, so a restart cannot reset a retry budget.

Ordering: records are delivered strictly in order. Every record ends in exactly
one terminal state, so the durable cursor advances through both acknowledged
and quarantined records -- a permanently-rejected record can never become a
poison head that blocks later samples.
"""

from __future__ import annotations

import base64
import binascii
import errno
import json
import os
import stat as stat_module

from . import MAX_BODY_BYTES
from .payload import canonical_bytes

RECORD_VERSION = 1
SPOOL_FILE = "spool.jsonl"
STATE_FILE = "spool.state.json"
LOCK_FILE = "spool.lock"
MAX_FILES = 4
FILE_BYTES = 8 * 1024 * 1024          # per-file rotation threshold
MAX_AGE_SECONDS = 7 * 86400.0         # <= 7 days (contract)
MAX_TOTAL_BYTES = 32 * 1024 * 1024    # <= 32 MiB (contract)
RETENTION_INTERVAL_SECONDS = 3600.0   # periodic enforcement while running
QUARANTINE_MAX_ENTRIES = 512
RECORD_MAX_BYTES = MAX_BODY_BYTES * 2  # base64 of a 16 KiB body, with slack
STATE_MAX_BYTES = 512 * 1024
MAX_TRACKED_RETRIES = 4096
NL = bytes([10])
# os.open defaults to TEXT mode on Windows, which would silently rewrite
# every LF as CRLF and break the exact-bytes invariant of a record line.
# The audited E4-Diag writer passes O_BINARY for the same reason.
BINARY = getattr(os, "O_BINARY", 0)

# Closed quarantine tokens (sanitized: never a server body or error string).
QUARANTINE_MALFORMED_2XX = "malformed_2xx"
QUARANTINE_REDIRECT = "redirect"
QUARANTINE_CLIENT_ERROR = "client_error"
QUARANTINE_OVERSIZE = "oversize"
QUARANTINE_UNKNOWN_RESPONSE = "unknown_response"
QUARANTINE_TOKENS = (QUARANTINE_MALFORMED_2XX, QUARANTINE_REDIRECT,
                     QUARANTINE_CLIENT_ERROR, QUARANTINE_OVERSIZE,
                     QUARANTINE_UNKNOWN_RESPONSE)

STATUS_KEYS = ("pending", "pending_bytes", "oldest_queued_epoch",
               "resolved_through", "acknowledged_total", "quarantined_total",
               "expired_total", "budget_dropped_total", "corrupt_total",
               "state_save_failures", "reconciled_ids", "tracked_attempts")


class SpoolError(Exception):
    """The spool could not be used safely (refused, never followed)."""


def _fsync_dir(path):
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SpoolError("short write")
        view = view[written:]


def _fsync(fd):
    """fsync that does NOT swallow its failure: an un-fsyncable file means the
    durability step cannot be claimed, so the caller fails closed."""
    os.fsync(fd)


def check_no_symlink_component(path):
    """Every component of ``path`` must be a real directory (or the final
    component a real file): a symlink anywhere is refused fail-closed."""
    current = os.path.abspath(path)
    parts = []
    while True:
        head, tail = os.path.split(current)
        if tail:
            parts.append(tail)
            current = head
            continue
        break
    probe = current
    for name in reversed(parts):
        probe = os.path.join(probe, name)
        try:
            st = os.lstat(probe)
        except FileNotFoundError:
            continue
        if stat_module.S_ISLNK(st.st_mode):
            raise SpoolError("symlink component refused: %s" % probe)


def open_restricted(path, flags, mode=0o600):
    """Open ONE spool file under the full storage discipline.

    ``O_NOFOLLOW`` refuses a symlink at the final component (a link at open
    time is ELOOP, never a followed target); ``fstat`` proves the object that
    was opened is a regular file (never a FIFO/device/dir); the mode is forced
    to 0600. The checks run on the OPEN descriptor.
    """
    open_flags = (flags | BINARY
                  | getattr(os, "O_NONBLOCK", 0)
                  | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, open_flags, mode)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise SpoolError("symlink refused: %s" % path) from exc
        if getattr(exc, "errno", None) == errno.ENXIO:
            raise SpoolError("special file refused: %s" % path) from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise SpoolError("not a regular file: %s" % path)
        if os.name == "posix":
            try:
                if stat_module.S_IMODE(st.st_mode) != 0o600:
                    os.fchmod(fd, 0o600)
            except OSError:
                raise SpoolError("mode not settable: %s" % path) from None
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_restricted(path, limit):
    """Read a bounded number of bytes from a regular, no-follow file."""
    fd = open_restricted(path, os.O_RDONLY)
    try:
        chunks = []
        remaining = int(limit)
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def assert_safe_regular(path, what="chain member"):
    """REFUSE an existing path that is not a regular, non-symlink file.

    The ONE choke point for "our own storage is what it claims to be": the
    record chain, the rotation targets and the agent's own baseline all call
    it, so no caller can invent a weaker check. ABSENT is not an error -- the
    caller decides whether a missing path is acceptable -- but an existing
    path that cannot even be stat'ed is fail-closed, never skipped.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SpoolError("%s unstatable: %s"
                         % (what, type(exc).__name__)) from None
    if stat_module.S_ISLNK(st.st_mode):
        raise SpoolError("%s must not be a symlink" % what)
    if not stat_module.S_ISREG(st.st_mode):
        raise SpoolError("%s must be a regular file" % what)


class _InstanceLock:
    """Advisory exclusive lock over one spool directory (single writer)."""

    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        fd = open_restricted(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except (OSError, ImportError):
            os.close(fd)
            raise SpoolError(
                "spool directory is locked by another writer") from None
        self.fd = fd

    def release(self):
        if self.fd is None:
            return
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        except (OSError, ImportError):
            pass
        os.close(self.fd)
        self.fd = None


class Spool:
    """One bounded, durable office-side queue over a dedicated directory."""

    def __init__(self, directory, clock=None, max_age=MAX_AGE_SECONDS,
                 max_bytes=MAX_TOTAL_BYTES, max_files=MAX_FILES,
                 file_bytes=FILE_BYTES, lock=True):
        self.directory = directory
        self.clock = clock or (lambda: __import__("time").time())
        self.max_age = float(max_age)
        self.max_bytes = int(max_bytes)
        self.max_files = int(max_files)
        self.file_bytes = int(file_bytes)
        self._lock_enabled = bool(lock)
        self._instance_lock = None
        self._state = {
            "next_record_id": 1,
            "resolved_through": 0,
            "acknowledged_total": 0,
            "quarantined_total": 0,
            "expired_total": 0,
            "budget_dropped_total": 0,
            "corrupt_total": 0,
            "state_save_failures": 0,
            "reconciled_ids": 0,
            "retry_attempts": {},
            "quarantine": [],
        }
        self._opened = False
        self._id_ceiling = 0      # highest durable id seen by a scan

    # -- lifecycle ----------------------------------------------------------

    def open(self):
        """Validate storage, take the writer lock, repair the tail, reconcile
        ids from the durable records and count unreadable lines once.

        Transaction-like: the object becomes OPEN only when every startup step
        succeeded. Any failure releases the writer lock and leaves the object
        closed, so a refusal inside open() cannot hand back a directory that is
        still held by an object the caller never got to use (the caller's own
        cleanup cannot cover this, because the failure happens before it has
        anything to clean up).
        """
        self._ensure_directory()
        if self._lock_enabled:
            lock = _InstanceLock(os.path.join(self.directory, LOCK_FILE))
            lock.acquire()
            self._instance_lock = lock
        try:
            self._reject_symlinked_record_path()
            self._load_state()
            self._repair_tail()
            self._reconcile_ids()
            self._count_corrupt_lines()
        except BaseException:
            self.close()          # release the writer lock, stay closed
            raise
        self._opened = True
        return self

    def close(self):
        if self._instance_lock is not None:
            self._instance_lock.release()
            self._instance_lock = None
        self._opened = False

    def _ensure_directory(self):
        if os.path.islink(self.directory):
            raise SpoolError("spool directory must not be a symlink")
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise SpoolError("spool directory unusable: %s"
                             % type(exc).__name__) from None
        check_no_symlink_component(self.directory)
        if not os.path.isdir(self.directory):
            raise SpoolError("spool path is not a directory")
        if os.name == "posix":
            try:
                os.chmod(self.directory, 0o700)
                mode = stat_module.S_IMODE(os.stat(self.directory).st_mode)
            except OSError:
                raise SpoolError("spool directory not statable") from None
            if mode != 0o700:
                raise SpoolError("spool directory mode must be 0700")

    def _record_paths(self):
        """Oldest-first: rotated files descending, then the current file."""
        paths = []
        for index in range(self.max_files, 0, -1):
            candidate = "%s.%d" % (os.path.join(self.directory, SPOOL_FILE),
                                   index)
            if os.path.lexists(candidate):
                self._assert_chain_member_safe(candidate)
                paths.append(candidate)
        current = os.path.join(self.directory, SPOOL_FILE)
        if os.path.lexists(current):
            self._assert_chain_member_safe(current)
        paths.append(current)
        return paths

    @staticmethod
    def _assert_chain_member_safe(path):
        """EVERY existing chain member must be a regular, non-symlink file: an
        unsafe rotated object is refused fail-closed, never skipped (a skip
        would make the queue look complete while records hide behind it)."""
        assert_safe_regular(path, "record chain member")

    def _read_chain_member(self, path):
        """Read one chain member.

        ABSENT is a normal state (the current file does not exist until the
        first append) and reads as empty; any OTHER failure is FATAL and must
        never be skipped -- a silent skip would make the queue look complete
        while an unreadable file hides records.
        """
        try:
            return read_restricted(path, self.file_bytes * 4)
        except FileNotFoundError:
            return b""

    def _state_path(self):
        return os.path.join(self.directory, STATE_FILE)

    # -- state --------------------------------------------------------------

    def _load_state(self):
        path = self._state_path()
        if not os.path.lexists(path):
            return
        try:
            raw = read_restricted(path, STATE_MAX_BYTES)
            loaded = json.loads(raw.decode("utf-8"))
        except (SpoolError, OSError, ValueError, UnicodeDecodeError):
            # A damaged cursor is fail-closed: refuse rather than replay
            # records we cannot prove were resolved.
            raise SpoolError("spool state unreadable") from None
        if not isinstance(loaded, dict):
            raise SpoolError("spool state malformed")
        for key in ("next_record_id", "resolved_through",
                    "acknowledged_total", "quarantined_total",
                    "expired_total", "budget_dropped_total", "corrupt_total",
                    "state_save_failures", "reconciled_ids"):
            value = loaded.get(key)
            if value is None:
                continue
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise SpoolError("spool state field %s" % key)
            self._state[key] = value
        quarantine = loaded.get("quarantine")
        if isinstance(quarantine, list):
            self._state["quarantine"] = [
                entry for entry in quarantine[-QUARANTINE_MAX_ENTRIES:]
                if isinstance(entry, dict) and entry.get("token")
                in QUARANTINE_TOKENS]
        attempts = loaded.get("retry_attempts")
        if isinstance(attempts, dict):
            clean = {}
            for key, value in attempts.items():
                if (isinstance(key, str) and key.isdigit()
                        and type(value) is int
                        and not isinstance(value, bool) and value > 0):
                    clean[key] = value
            self._state["retry_attempts"] = dict(
                list(clean.items())[-MAX_TRACKED_RETRIES:])

    def _save_state(self):
        payload = canonical_bytes(self._state)
        if len(payload) > STATE_MAX_BYTES:
            raise SpoolError("spool state oversized")
        tmp = self._state_path() + ".tmp"
        fd = open_restricted(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            _write_all(fd, payload)
            _fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._state_path())
        _fsync_dir(self.directory)

    def _save_state_soft(self):
        """Persist the cursor; a failure is COUNTED, never fatal.

        The in-memory cursor stays correct for this process, and a reopen
        reconciles ids from the durable records, so a failed state save can
        cost at worst a re-send (which the server answers idempotently) --
        never a reused id and never a lost record.
        """
        try:
            self._save_state()
        except (SpoolError, OSError):
            self._state["state_save_failures"] = int(
                self._state["state_save_failures"]) + 1

    # -- reconciliation -----------------------------------------------------

    def _scan_records(self):
        """Every readable record in chain order: ``[(record_id, record)]``.

        Also the id-integrity gate: a duplicate id, or an id that is not
        strictly increasing in chain order, is refused fail-closed rather than
        silently adopted.
        """
        found = []
        seen = set()
        last = 0
        for path in self._record_paths():
            # An EXISTING member that cannot be read is fail-closed, never
            # skipped: a skip makes the queue look complete while records
            # hide behind an unreadable file. ABSENT reads as empty.
            data = self._read_chain_member(path)
            for line in data.splitlines():
                if not line:
                    continue
                record = decode_record(line)
                if record is None:
                    # A COMPLETE line whose payload is unusable still occupies
                    # its record id: the id joins the durable high-water so a
                    # reconciled append can never hand it out again. An id that
                    # cannot be recovered fails the scan CLOSED -- guessing one
                    # would reopen exactly the reuse this prevents.
                    reserved = recover_record_id(line)
                    if reserved is None:
                        raise SpoolError(
                            "corrupt record without a recoverable id")
                    if reserved in seen:
                        raise SpoolError("duplicate record id: %d" % reserved)
                    if reserved <= last:
                        raise SpoolError("non-monotonic record id: %d"
                                         % reserved)
                    seen.add(reserved)
                    last = reserved
                    continue
                record_id = record["record_id"]
                if record_id in seen:
                    raise SpoolError("duplicate record id: %d" % record_id)
                if record_id <= last:
                    raise SpoolError("non-monotonic record id: %d"
                                     % record_id)
                seen.add(record_id)
                last = record_id
                found.append((record_id, record))
        # The id ceiling covers corrupt-but-recoverable records too, so the
        # cursor reconciled from it is strictly greater than EVERY durable id.
        self._id_ceiling = last
        return found

    def _reconcile_ids(self):
        """Startup ID reconciliation (the crash window between the record fsync
        and the state save).

        ``next_record_id`` must be strictly greater than every durable record
        id -- including the ids of corrupt-but-recoverable lines, which are
        still physically on disk -- so a record fsynced before the cursor was
        persisted can never have its id handed out a second time.
        """
        records = self._scan_records()
        highest = records[-1][0] if records else 0
        highest = max(highest, int(self._id_ceiling))
        wanted = highest + 1
        if wanted > int(self._state["next_record_id"]):
            self._state["reconciled_ids"] = int(
                self._state["reconciled_ids"]) + 1
            self._state["next_record_id"] = wanted
            self._save_state_soft()
        live = {str(record_id) for record_id, _record in records
                if record_id > int(self._state["resolved_through"])}
        self._state["retry_attempts"] = {
            key: value for key, value
            in self._state["retry_attempts"].items() if key in live}

    # -- torn tail ----------------------------------------------------------

    def _reject_symlinked_record_path(self):
        """A symlink at the record path is refused whether or not its target
        exists (``os.path.exists`` FOLLOWS a link, so a dangling one would
        otherwise look like "no file yet")."""
        path = os.path.join(self.directory, SPOOL_FILE)
        if os.path.islink(path):
            raise SpoolError("spool file must not be a symlink")
        if os.path.lexists(path) and not stat_module.S_ISREG(
                os.lstat(path).st_mode):
            raise SpoolError("spool file must be a regular file")

    def _repair_tail(self):
        """Truncate AT MOST one incomplete trailing fragment of the current
        file. A complete-but-unparseable line is counted, never rewritten."""
        path = os.path.join(self.directory, SPOOL_FILE)
        if not os.path.lexists(path):
            return 0
        # An EXISTING current file that cannot be read is NOT "nothing to
        # repair": a plain I/O failure here means the queue is unreadable and
        # the caller has to hear about it.
        data = self._read_chain_member(path)
        if not data:
            return 0
        last_newline = data.rfind(NL)
        if last_newline == len(data) - 1:
            return 0
        keep = data[:last_newline + 1] if last_newline >= 0 else b""
        fd = open_restricted(path, os.O_WRONLY)
        try:
            os.ftruncate(fd, len(keep))
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self.directory)
        return 1

    def _count_corrupt_lines(self):
        """Count complete lines whose body cannot be recovered, ONCE at open."""
        resolved = int(self._state["resolved_through"])
        counted = 0
        for path in self._record_paths():
            data = self._read_chain_member(path)
            for line in data.splitlines():
                if not line or _line_is_readable(line):
                    continue
                if record_id_unresolved(line, resolved):
                    counted += 1
        if counted:
            self._state["corrupt_total"] = int(
                self._state["corrupt_total"]) + counted
            self._save_state_soft()

    # -- append -------------------------------------------------------------

    def append(self, probe_id, run, seq, body, queued_epoch=None):
        """Durably append one record and return its ``record_id``."""
        if not self._opened:
            raise SpoolError("spool not open")
        if type(body) is not bytes or len(body) > MAX_BODY_BYTES:
            raise SpoolError("body bytes out of bounds")
        epoch = float(queued_epoch if queued_epoch is not None
                      else self.clock())
        record_id = int(self._state["next_record_id"])
        record = {
            "v": RECORD_VERSION,
            "record_id": record_id,
            "probe_id": probe_id,
            "run": run,
            "seq": int(seq),
            "queued_epoch": epoch,
            "body_b64": base64.b64encode(body).decode("ascii"),
        }
        line = canonical_bytes(record) + NL
        if len(line) > RECORD_MAX_BYTES:
            raise SpoolError("record exceeds spool record bound")
        self._append_line(line)
        self._state["next_record_id"] = record_id + 1
        self._save_state_soft()
        return record_id

    def _append_line(self, line):
        path = os.path.join(self.directory, SPOOL_FILE)
        self._reject_symlinked_record_path()
        if os.path.lexists(path):
            try:
                size = os.lstat(path).st_size
            except OSError:
                size = 0
            if size + len(line) > self.file_bytes:
                self._rotate()
        fd = open_restricted(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        try:
            _write_all(fd, line)
            os.fsync(fd)          # durable BEFORE the record counts as queued
        finally:
            os.close(fd)

    def _preflight_chain(self):
        """Validate EVERY existing chain member BEFORE the rotation mutates
        anything.

        Validating the source of one rename is not enough: the RENAMED-OVER
        target is also our storage, and discovering an unsafe target halfway
        through an oldest-outward shift would leave the chain half-mutated
        (some members already renamed, the unsafe one still in place). So the
        whole chain -- current and every rotated slot -- is checked first; any
        unsafe member fails the entire rotation with nothing touched.
        """
        base = os.path.join(self.directory, SPOOL_FILE)
        for index in range(self.max_files, 0, -1):
            self._assert_chain_member_safe("%s.%d" % (base, index))
        self._assert_chain_member_safe(base)

    def _rotate(self):
        """Shift the chain oldest-outward with fsync + rename + dir fsync."""
        self._preflight_chain()
        base = os.path.join(self.directory, SPOOL_FILE)
        for index in range(self.max_files - 1, 0, -1):
            source = "%s.%d" % (base, index)
            if os.path.lexists(source):
                self._rename_fsynced(source, "%s.%d" % (base, index + 1))
        oldest = "%s.%d" % (base, self.max_files)
        if os.path.lexists(oldest):
            self._state["budget_dropped_total"] = int(
                self._state["budget_dropped_total"]) + 1
            os.unlink(oldest)
            _fsync_dir(self.directory)
        self._rename_fsynced(base, "%s.1" % base)

    @staticmethod
    def _rename_fsynced(source, target):
        """Publish one rotation step: file fsync -> rename -> directory fsync.

        Every step is load-bearing and none is swallowed: an unsafe source
        (symlink/special) is REFUSED and never renamed, a failed file fsync
        raises (the rotation is not durable), and the rename is followed by
        a directory fsync so the new name is durable too.
        """
        fd = open_restricted(source, os.O_RDWR)
        try:
            _fsync(fd)
        finally:
            os.close(fd)
        os.replace(source, target)
        _fsync_dir(os.path.dirname(os.path.abspath(target)))

    # -- read / attempts / resolve ------------------------------------------

    def pending(self):
        """Yield pending records oldest-first, in record order."""
        resolved = int(self._state["resolved_through"])
        for record_id, record in self._scan_records():
            if record_id <= resolved:
                continue
            yield {"record_id": record_id,
                   "probe_id": record["probe_id"],
                   "run": record["run"],
                   "seq": record["seq"],
                   "queued_epoch": record["queued_epoch"],
                   "body": record["body"]}

    def attempts(self, record_id):
        """Durable retry count for one record (survives a restart)."""
        return int(self._state["retry_attempts"].get(str(int(record_id)), 0))

    def note_attempt(self, record_id):
        """Count one delivery attempt DURABLY, before delivery may proceed.

        ``next_record_id`` can be recovered by reconciling the durable
        records; a retry count cannot. A soft save that failed would let a
        restart start the same bounded budget from zero, so this save is HARD:
        on failure the in-memory count is rolled back and ``SpoolError`` is
        raised, leaving the last durable value as the only truth -- an attempt
        that was never persisted is never charged against the budget.
        """
        key = str(int(record_id))
        previous = self._state["retry_attempts"].get(key)
        previous_table = dict(self._state["retry_attempts"])
        value = int(previous or 0) + 1
        self._state["retry_attempts"][key] = value
        if len(self._state["retry_attempts"]) > MAX_TRACKED_RETRIES:
            self._state["retry_attempts"] = dict(
                list(self._state["retry_attempts"].items())
                [-MAX_TRACKED_RETRIES:])
        try:
            self._save_state()          # HARD: the count is durable or nothing
        except (SpoolError, OSError):
            # Roll the in-memory count back so the DURABLE value stays the
            # only truth, and refuse. An attempt that was never persisted must
            # not be charged against a bounded budget: the caller has to hear
            # that delivery cannot proceed rather than silently consume it.
            self._state["retry_attempts"] = previous_table
            self._state["state_save_failures"] = int(
                self._state["state_save_failures"]) + 1
            raise SpoolError("retry attempt count is not durable") from None
        return value

    def resolve(self, record_id, quarantine_token=None):
        """Mark a record terminal (acknowledged or quarantined)."""
        if type(record_id) is not int or record_id <= 0:
            raise SpoolError("record id")
        if record_id <= self._state["resolved_through"]:
            return False
        self._state["resolved_through"] = record_id
        self._state["retry_attempts"].pop(str(record_id), None)
        if quarantine_token is None:
            self._state["acknowledged_total"] = int(
                self._state["acknowledged_total"]) + 1
        else:
            if quarantine_token not in QUARANTINE_TOKENS:
                raise SpoolError("quarantine token must be closed")
            self._state["quarantined_total"] = int(
                self._state["quarantined_total"]) + 1
            ledger = self._state["quarantine"]
            ledger.append({"token": quarantine_token,
                           "record_id": record_id,
                           "epoch": float(self.clock())})
            del ledger[:-QUARANTINE_MAX_ENTRIES]
        self._save_state_soft()
        return True

    # -- bounds -------------------------------------------------------------

    def enforce_bounds(self):
        """Apply the 7-day / 32 MiB bounds and physically drop resolved records
        from EVERY file in the chain. Every drop is counted and visible."""
        self._compact_resolved()
        resolved = int(self._state["resolved_through"])
        now = float(self.clock())
        for record_id, record in self._scan_records():
            if record_id <= resolved:
                continue
            if now - float(record["queued_epoch"]) > self.max_age:
                self._state["resolved_through"] = record_id
                self._state["expired_total"] = int(
                    self._state["expired_total"]) + 1
        live = [(rid, rec) for rid, rec in self._scan_records()
                if rid > int(self._state["resolved_through"])]
        total = sum(len(rec["body"]) for _rid, rec in live)
        for record_id, record in live:
            if total <= self.max_bytes:
                break
            self._state["resolved_through"] = record_id
            self._state["budget_dropped_total"] = int(
                self._state["budget_dropped_total"]) + 1
            total -= len(record["body"])
        self._save_state_soft()
        self._compact_resolved()
        return self.status()

    def _compact_resolved(self):
        """Rewrite EVERY file in the chain without RESOLVED records, so
        acknowledged records cannot linger physically in the rotated files.

        A complete-but-corrupt line is NOT garbage. Its record id is part of
        the durable high-water, so it is dropped only when the durable cursor
        PROVES it terminal (``id <= resolved_through``); dropping an
        unresolved one would erase the only on-disk evidence of that id and
        reopen reuse (the crash window C3 closes). A corrupt line whose id
        cannot be recovered fails CLOSED with no rewrite published, and the
        ONE incomplete trailing fragment is repaired at open by
        ``_repair_tail`` -- never silently here. Each rewrite goes to a
        restricted temp file (fsynced), renames over the original, then
        fsyncs the directory."""
        resolved = int(self._state["resolved_through"])
        current = os.path.join(self.directory, SPOOL_FILE)
        for path in self._record_paths():
            if not os.path.lexists(path):
                continue
            data = self._read_chain_member(path)
            keep = []
            for line in data.splitlines():
                if not line:
                    continue
                record = decode_record(line)
                if record is None:
                    reserved = recover_record_id(line)
                    if reserved is None:
                        raise SpoolError(
                            "corrupt record without a recoverable id")
                    if reserved <= resolved:
                        continue           # the durable cursor proves it ended
                    keep.append(line)      # verbatim: it still owns its id
                    continue
                if record["record_id"] <= resolved:
                    continue
                keep.append(line)
            if not keep and path != current:
                # A fully-consumed rotated file is removed outright.
                os.unlink(path)
                _fsync_dir(self.directory)
                continue
            tmp = path + ".compact"
            fd = open_restricted(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            try:
                _write_all(fd, b"".join(line + NL for line in keep))
                _fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, path)
            _fsync_dir(self.directory)

    # -- status -------------------------------------------------------------

    def status(self):
        """Closed, sanitized local status (no bodies, no secrets)."""
        pending = list(self.pending())
        oldest = min((item["queued_epoch"] for item in pending), default=None)
        return {
            "pending": len(pending),
            "pending_bytes": sum(len(item["body"]) for item in pending),
            "oldest_queued_epoch": oldest,
            "resolved_through": int(self._state["resolved_through"]),
            "acknowledged_total": int(self._state["acknowledged_total"]),
            "quarantined_total": int(self._state["quarantined_total"]),
            "expired_total": int(self._state["expired_total"]),
            "budget_dropped_total": int(self._state["budget_dropped_total"]),
            "corrupt_total": int(self._state["corrupt_total"]),
            "state_save_failures": int(self._state["state_save_failures"]),
            "reconciled_ids": int(self._state["reconciled_ids"]),
            "tracked_attempts": len(self._state["retry_attempts"]),
        }


def decode_record(line):
    """One record line -> a closed dict, or None when unreadable."""
    try:
        record = json.loads(line.decode("utf-8"))
        base64.b64decode(record["body_b64"], validate=True)
        record_id = record["record_id"]
        if type(record_id) is not int or isinstance(record_id, bool) \
                or record_id < 1:
            return None
        seq = record["seq"]
        if type(seq) is not int or isinstance(seq, bool):
            return None
        epoch = record["queued_epoch"]
        if type(epoch) not in (int, float) or isinstance(epoch, bool):
            return None
        probe_id = record["probe_id"]
        run = record["run"]
        if type(probe_id) is not str or type(run) is not str:
            return None
        body = base64.b64decode(record["body_b64"], validate=True)
        return {"record_id": record_id, "probe_id": probe_id, "run": run,
                "seq": seq, "queued_epoch": float(epoch), "body": body}
    except (ValueError, KeyError, TypeError, binascii.Error,
            UnicodeDecodeError):
        return None


def _line_is_readable(line):
    return decode_record(line) is not None


def record_id_unresolved(line, resolved):
    """Best-effort: is this unreadable line one we have not resolved yet?"""
    try:
        record = json.loads(line.decode("utf-8"))
        return int(record.get("record_id", 0)) > resolved
    except (ValueError, TypeError, UnicodeDecodeError):
        return True


def recover_record_id(line):
    """Trustworthy ``record_id`` of a corrupt-but-complete line, or None.

    A line whose body (or any other field) is unusable can still name the id
    it DUPLICABLY occupied. That id is part of the durable high-water: a later
    reconciled append that reused it would collide with a record that is still
    physically on disk, so the id is reserved even though the record itself
    cannot be delivered. When no trustworthy positive integer id can be
    extracted the caller must FAIL CLOSED -- never guess one, and never keep
    allocating from a cursor that may already be behind.
    """
    try:
        record = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    record_id = record.get("record_id")
    if type(record_id) is not int or isinstance(record_id, bool) \
            or record_id < 1:
        return None
    return record_id
