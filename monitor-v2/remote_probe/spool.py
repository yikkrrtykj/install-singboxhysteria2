"""Durable office-side spool -- spool-before-ack (issue #67 §5).

The spool exists for exactly one reason: a short server/network outage must not
erase office-side incident evidence. It is therefore append-only, fsynced
before a record is considered durable, and a record leaves the queue only in a
TERMINAL state (acknowledged by the server, or resolved into the bounded
quarantine ledger).

Crash-safety uses the same CLASS of primitives as the audited E4-Diag writer
(``monitor-v2/mihomo/diag.py``), re-implemented here so the office agent stays
a stdlib-only, server-independent tree:

* directory: real, no symlink component, mode 0700;
* record files: regular, no-follow, mode 0600, ``O_APPEND``;
* one complete write loop per record, then ``fsync``;
* startup repair of AT MOST one incomplete trailing fragment;
* rotation with file fsync, rename, then directory fsync;
* unsafe/symlink/special objects FAIL CLOSED (never followed, never adopted).

Ordering note: records are delivered strictly in order. Every record ends in
exactly one terminal state, so the durable cursor advances through both
acknowledged and quarantined records -- a permanently-rejected record can
therefore never become a poison head that blocks later samples.
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
MAX_FILES = 4
FILE_BYTES = 8 * 1024 * 1024          # per-file rotation threshold
MAX_AGE_SECONDS = 7 * 86400.0         # <= 7 days (contract)
MAX_TOTAL_BYTES = 32 * 1024 * 1024    # <= 32 MiB (contract)
QUARANTINE_MAX_ENTRIES = 512
RECORD_MAX_BYTES = MAX_BODY_BYTES * 2  # base64 of a 16 KiB body, with slack

# Closed quarantine tokens (sanitized: never a server body or error string).
QUARANTINE_MALFORMED_2XX = "malformed_2xx"
QUARANTINE_REDIRECT = "redirect"
QUARANTINE_CLIENT_ERROR = "client_error"
QUARANTINE_OVERSIZE = "oversize"
QUARANTINE_UNKNOWN_RESPONSE = "unknown_response"
QUARANTINE_TOKENS = (QUARANTINE_MALFORMED_2XX, QUARANTINE_REDIRECT,
                     QUARANTINE_CLIENT_ERROR, QUARANTINE_OVERSIZE,
                     QUARANTINE_UNKNOWN_RESPONSE)


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


def check_no_symlink_component(path):
    """Every component of ``path`` must exist and be a real directory (or the
    final component a real file). A symlink anywhere is refused fail-closed."""
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


class Spool:
    """One bounded, durable office-side queue over a dedicated directory."""

    def __init__(self, directory, clock=None, max_age=MAX_AGE_SECONDS,
                 max_bytes=MAX_TOTAL_BYTES, max_files=MAX_FILES,
                 file_bytes=FILE_BYTES):
        self.directory = directory
        self.clock = clock or (lambda: __import__("time").time())
        self.max_age = float(max_age)
        self.max_bytes = int(max_bytes)
        self.max_files = int(max_files)
        self.file_bytes = int(file_bytes)
        self._state = {
            "next_record_id": 1,
            "resolved_through": 0,
            "acknowledged_total": 0,
            "quarantined_total": 0,
            "expired_total": 0,
            "budget_dropped_total": 0,
            "corrupt_total": 0,
            "quarantine": [],
        }
        self._opened = False

    # -- lifecycle ----------------------------------------------------------

    def open(self):
        """Validate storage, repair at most one torn tail, load the cursor,
        and count unreadable-but-complete lines exactly once."""
        self._ensure_directory()
        self._load_state()
        self._repair_tail()
        self._opened = True
        self._count_corrupt_lines()
        return self

    def _count_corrupt_lines(self):
        """Count complete lines whose body cannot be recovered. Done once at
        open so ``status()`` is stable (a counter that grew on every read
        would misreport evidence loss)."""
        resolved = int(self._state["resolved_through"])
        counted = 0
        for path in self._record_paths():
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            for line in data.splitlines():
                if not line:
                    continue
                if _line_is_readable(line):
                    continue
                if record_id_unresolved(line, resolved):
                    counted += 1
        if counted:
            self._state["corrupt_total"] = int(
                self._state["corrupt_total"]) + counted
            self._save_state()

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
            if os.path.exists(candidate):
                paths.append(candidate)
        paths.append(os.path.join(self.directory, SPOOL_FILE))
        return paths

    def _state_path(self):
        return os.path.join(self.directory, STATE_FILE)

    def _load_state(self):
        path = self._state_path()
        if not os.path.exists(path):
            return
        if os.path.islink(path):
            raise SpoolError("spool state must not be a symlink")
        try:
            with open(path, "rb") as handle:
                raw = handle.read(64 * 1024)
            loaded = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            # A damaged cursor is fail-closed: we refuse rather than replay
            # records we cannot prove were resolved.
            raise SpoolError("spool state unreadable") from None
        if not isinstance(loaded, dict):
            raise SpoolError("spool state malformed")
        for key in ("next_record_id", "resolved_through",
                    "acknowledged_total", "quarantined_total",
                    "expired_total", "budget_dropped_total", "corrupt_total"):
            value = loaded.get(key)
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise SpoolError("spool state field %s" % key)
            self._state[key] = value
        quarantine = loaded.get("quarantine")
        if isinstance(quarantine, list):
            self._state["quarantine"] = [
                entry for entry in quarantine[-QUARANTINE_MAX_ENTRIES:]
                if isinstance(entry, dict) and entry.get("token")
                in QUARANTINE_TOKENS]

    def _save_state(self):
        payload = canonical_bytes(self._state)
        tmp = self._state_path() + ".tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC \
            | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._state_path())
        _fsync_dir(self.directory)

    # -- torn tail ----------------------------------------------------------

    def _repair_tail(self):
        """Truncate AT MOST one incomplete trailing fragment of the current
        file. A complete-but-unparseable line is counted, never rewritten."""
        path = os.path.join(self.directory, SPOOL_FILE)
        if not os.path.exists(path):
            return 0
        st = os.lstat(path)
        if stat_module.S_ISLNK(st.st_mode) or not stat_module.S_ISREG(
                st.st_mode):
            raise SpoolError("spool file must be a regular file")
        with open(path, "rb") as handle:
            data = handle.read()
        if not data:
            return 0
        last_newline = data.rfind(b"\n")
        if last_newline == len(data) - 1:
            return 0
        keep = data[:last_newline + 1] if last_newline >= 0 else b""
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            os.ftruncate(fd, len(keep))
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self.directory)
        return 1

    # -- append -------------------------------------------------------------

    def append(self, probe_id, run, seq, body, queued_epoch=None):
        """Durably append one record and return its ``record_id``.

        The body bytes are stored EXACTLY as given (base64 inside the record
        line): the spool never holds a parsed object that would be
        re-serialized on retry.
        """
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
        line = canonical_bytes(record) + b"\n"
        if len(line) > RECORD_MAX_BYTES:
            raise SpoolError("record exceeds spool record bound")
        self._append_line(line)
        self._state["next_record_id"] = record_id + 1
        self._save_state()
        return record_id

    def _append_line(self, line):
        path = os.path.join(self.directory, SPOOL_FILE)
        if os.path.exists(path):
            st = os.lstat(path)
            if stat_module.S_ISLNK(st.st_mode):
                raise SpoolError("spool file must not be a symlink")
            if not stat_module.S_ISREG(st.st_mode):
                raise SpoolError("spool file must be a regular file")
            if st.st_size + len(line) > self.file_bytes:
                self._rotate()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND \
            | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise SpoolError("spool file must be a regular file")
            if os.name == "posix":
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    raise SpoolError("spool file mode not settable") from None
            _write_all(fd, line)
            os.fsync(fd)          # durable BEFORE the record counts as queued
        finally:
            os.close(fd)

    def _rotate(self):
        """Shift the chain oldest-outward with fsync + rename + dir fsync."""
        base = os.path.join(self.directory, SPOOL_FILE)
        for index in range(self.max_files - 1, 0, -1):
            source = "%s.%d" % (base, index)
            if not os.path.exists(source):
                continue
            target = "%s.%d" % (base, index + 1)
            self._rename_fsynced(source, target)
        oldest = "%s.%d" % (base, self.max_files)
        if os.path.exists(oldest):
            # Beyond the chain: dropped under the byte/age budget, counted.
            st = os.lstat(oldest)
            self._state["budget_dropped_total"] += 1
            os.unlink(oldest)
            _fsync_dir(self.directory)
            del st
        self._rename_fsynced(base, "%s.1" % base)

    @staticmethod
    def _rename_fsynced(source, target):
        if os.path.exists(source):
            # fsync needs a WRITE-capable handle (Windows refuses it on a
            # read-only one). Best-effort: the rename plus the directory fsync
            # that follows is what actually publishes the rotation.
            try:
                fd = os.open(source, os.O_RDWR)
            except OSError:
                fd = None
            if fd is not None:
                try:
                    os.fsync(fd)
                except OSError:
                    pass
                finally:
                    os.close(fd)
        os.replace(source, target)

    # -- read / resolve -----------------------------------------------------

    def pending(self):
        """Yield pending records oldest-file-first, in record order. A
        complete-but-unparseable line is counted and skipped (it can never be
        delivered: its body is unrecoverable)."""
        resolved = int(self._state["resolved_through"])
        for index, path in enumerate(self._record_paths()):
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except FileNotFoundError:
                continue
            is_current = index == len(self._record_paths()) - 1
            lines = data.split(b"\n")
            if is_current and lines and lines[-1] == b"":
                lines = lines[:-1]
            for line in lines:
                if not line:
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                    body = base64.b64decode(record["body_b64"], validate=True)
                    record_id = int(record["record_id"])
                    int(record["seq"])
                    float(record["queued_epoch"])
                    if type(record["probe_id"]) is not str \
                            or type(record["run"]) is not str:
                        raise ValueError("record shape")
                except (ValueError, KeyError, TypeError,
                        binascii.Error, UnicodeDecodeError):
                    continue          # counted once at open, never here
                if record_id <= resolved:
                    continue
                yield {"record_id": record_id,
                       "probe_id": record["probe_id"],
                       "run": record["run"],
                       "seq": int(record["seq"]),
                       "queued_epoch": float(record["queued_epoch"]),
                       "body": body}

    def resolve(self, record_id, quarantine_token=None):
        """Mark a record terminal (acknowledged or quarantined) and persist
        the cursor. A quarantined record is recorded in the bounded,
        sanitized ledger -- never with a response body or error text."""
        if type(record_id) is not int or record_id <= 0:
            raise SpoolError("record id")
        if record_id <= self._state["resolved_through"]:
            return False
        self._state["resolved_through"] = record_id
        if quarantine_token is None:
            self._state["acknowledged_total"] += 1
        else:
            if quarantine_token not in QUARANTINE_TOKENS:
                raise SpoolError("quarantine token must be closed")
            self._state["quarantined_total"] += 1
            ledger = self._state["quarantine"]
            ledger.append({"token": quarantine_token,
                           "record_id": record_id,
                           "epoch": float(self.clock())})
            del ledger[:-QUARANTINE_MAX_ENTRIES]
        self._save_state()
        return True

    # -- bounds -------------------------------------------------------------

    def enforce_bounds(self):
        """Apply the 7-day / 32 MiB bounds (and physically drop resolved
        records). Every drop is COUNTED and visible in ``status()``."""
        self._compact_resolved()
        now = float(self.clock())
        pending = list(self.pending())
        total = sum(len(item["body"]) for item in pending)
        for item in pending:
            if now - item["queued_epoch"] > self.max_age:
                self._state["resolved_through"] = item["record_id"]
                self._state["expired_total"] += 1
                total -= len(item["body"])
        remaining = [item for item in self.pending()]
        index = 0
        while total > self.max_bytes and index < len(remaining):
            item = remaining[index]
            self._state["resolved_through"] = item["record_id"]
            self._state["budget_dropped_total"] += 1
            total -= len(item["body"])
            index += 1
        self._save_state()
        self._compact_resolved()
        return self.status()

    def _compact_resolved(self):
        """Physically drop resolved records: rewrite the current file to a
        temp file (fsynced), rename over, then fsync the directory."""
        path = os.path.join(self.directory, SPOOL_FILE)
        if not os.path.exists(path):
            return
        resolved = int(self._state["resolved_through"])
        with open(path, "rb") as handle:
            data = handle.read()
        keep = []
        for line in data.split(b"\n"):
            if not line:
                continue
            try:
                record = json.loads(line.decode("utf-8"))
                record_id = int(record.get("record_id", 0))
            except (ValueError, TypeError, UnicodeDecodeError):
                continue
            if record_id > resolved:
                keep.append(line)
        if not keep and len(self._record_paths()) == 1:
            pass
        tmp = path + ".tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC \
            | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            _write_all(fd, b"".join(line + b"\n" for line in keep))
            os.fsync(fd)
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
        }


def _line_is_readable(line):
    """Can this record line be decoded into a deliverable record?"""
    try:
        record = json.loads(line.decode("utf-8"))
        base64.b64decode(record["body_b64"], validate=True)
        int(record["record_id"])
        int(record["seq"])
        float(record["queued_epoch"])
        return (type(record["probe_id"]) is str
                and type(record["run"]) is str)
    except (ValueError, KeyError, TypeError, binascii.Error,
            UnicodeDecodeError):
        return False


def record_id_unresolved(line, resolved):
    """Best-effort: is this unparseable line one we have not resolved yet?
    Used only to decide whether a corrupt line counts as evidence loss."""
    try:
        record = json.loads(line.decode("utf-8"))
        return int(record.get("record_id", 0)) > resolved
    except (ValueError, TypeError, UnicodeDecodeError):
        return True
