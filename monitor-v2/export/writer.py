"""Single-writer atomic publisher for the restricted traffic export (UM-LT).

Publication contract
--------------------

* ONE daemon writer thread per monitor process. The publisher (SnapshotBroker)
  hands over an already-sanitized traffic projection through a bounded queue
  that holds at most ONE pending item; when a newer projection arrives while
  the older one is still pending, the older one is dropped. The publisher's
  ``submit()`` is non-blocking and can never stall on disk I/O.
* A publish writes a temp file in the SAME directory as the final path,
  ``chmod 0640`` (before publication), ``fsync``s the file, then atomically
  ``os.replace()``s it over the final path. Consequences:
    - a reader NEVER sees a partial/torn JSON document (it sees either the
      previous complete document or the new complete one);
    - a failed write leaves the previous complete file in place;
    - the final path is never opened for writing (no symlink-follow hazard at
      publication time; the writer only replaces the directory entry).
* Durability tradeoff: the FILE is fsynced before the rename, so the published
  document contents survive a crash right after publication. The DIRECTORY is
  fsynced on a best-effort basis only (POSIX); a power loss in the narrow
  window between `rename` and the directory flush may lose the *latest*
  publication (the previous complete document remains, or the file is
  absent on a first publication). It can never expose partial JSON, and a
  monitor restart removes any leftover file before serving again.
* Write failures are contained: they never raise into the publisher, never
  stop the writer thread, never touch the collector, and are rate-limited on
  stderr (one line per ``ERROR_LOG_INTERVAL`` seconds, no payload/path).
* On ``prepare()`` (monitor startup, BEFORE serving) a leftover export file
  from a previous process is removed. If it cannot be removed safely the
  writer refuses to start (fail closed) so a stale file cannot look fresh.
  A NEW random 32-lowercase-hex ``source_epoch`` is created per writer.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import sys
import tempfile
import threading
import time

from .contract import (MAX_EXPORT_BYTES, SOURCE_EPOCH_HEX_BYTES,
                       TrafficExportConfigError, TrafficExportDocumentError,
                       build_document, validate_export_path)

# The writer thread wakes at least this often to notice a stop request.
THREAD_WAIT_SECONDS = 0.5
# One stderr line per interval when publication keeps failing.
ERROR_LOG_INTERVAL = 60.0
TEMP_PREFIX = ".traffic-export-"
TEMP_SUFFIX = ".tmp"
FINAL_FILE_MODE = 0o640


class TrafficExportWriter:
    """Bounded, sanitized, atomically published traffic export writer.

    Disabled usage is simply "do not construct one": no thread, queue, file
    or path access exists until an instance is created + prepared.
    """

    def __init__(self, path, inbounds, clock=time.time, source_epoch=None):
        self.path = validate_export_path(path)
        self.inbounds = tuple(inbounds)
        specs_seen = set()
        for spec in self.inbounds:
            tag = getattr(spec, "tag", None)
            kind = getattr(spec, "kind", None)
            if tag is None or kind is None:
                raise TrafficExportConfigError("invalid inbound specification")
            if tag in specs_seen:
                raise TrafficExportConfigError(
                    "duplicate inbound tag %r in the allow-list" % (tag,))
            specs_seen.add(tag)
        self._clock = clock
        if source_epoch is None:
            source_epoch = secrets.token_hex(SOURCE_EPOCH_HEX_BYTES)
        # Fail fast on a caller-supplied epoch that could never be published.
        build_document(
            _empty_projection(int(self._clock())),
            source_epoch=source_epoch, sequence=0,
            generated_at=int(self._clock()))
        self.source_epoch = source_epoch
        self.prepared = False
        self._queue = queue.Queue(maxsize=1)
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._sequence = 0
        self._last_error_log = None
        self.published_count = 0
        self.error_count = 0
        self.dropped_count = 0
        self.last_error_kind = None

    # -- lifecycle -----------------------------------------------------------

    def prepare(self):
        """Validate again, then remove a leftover file from a previous process.

        Called by the monitor BEFORE it starts serving. A stale export from an
        old process must never look like fresh data: the file is removed and
        the new writer gets a brand-new ``source_epoch``. If removal fails the
        writer refuses to start (fail closed) rather than serve alongside stale
        data.
        """
        self.path = validate_export_path(self.path)
        try:
            existing = os.lstat(self.path)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise TrafficExportConfigError(
                "cannot inspect the existing traffic export file") from None
        if existing is not None:
            try:
                os.unlink(self.path)
            except OSError:
                raise TrafficExportConfigError(
                    "cannot remove the stale traffic export file before "
                    "serving (fail closed)") from None
        self.prepared = True
        return self

    def start(self):
        if not self.prepared:
            raise RuntimeError("prepare() must run before start()")
        if self._thread is not None and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="monitor-traffic-export", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout=5.0):
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)
            return not thread.is_alive()
        return True

    def running(self):
        return self._thread is not None and self._thread.is_alive()

    # -- submission (publisher side; NEVER blocks) ---------------------------

    def submit(self, projection):
        """Hand the latest sanitized projection to the writer thread.

        Non-blocking. The queue holds at most one pending projection: a newer
        one replaces (drops) the older one. Returns False only when stopped.
        """
        if self._stop.is_set():
            return False
        try:
            self._queue.put_nowait(projection)
            return True
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            with self._lock:
                self.dropped_count += 1
            try:
                self._queue.put_nowait(projection)
                return True
            except queue.Full:  # pragma: no cover - constructible in theory
                return False

    # -- writer thread -------------------------------------------------------

    def _run(self):
        while not self._stop.is_set():
            try:
                projection = self._queue.get(timeout=THREAD_WAIT_SECONDS)
            except queue.Empty:
                continue
            try:
                self.publish(projection)
            except Exception as exc:  # noqa: BLE001 - export never kills Monitor
                self._record_error(exc)

    def _record_error(self, exc):
        kind = type(exc).__name__
        with self._lock:
            self.error_count += 1
            self.last_error_kind = kind
        now = self._clock()
        with self._lock:
            last = self._last_error_log
            if last is not None and (now - last) < ERROR_LOG_INTERVAL:
                return
            self._last_error_log = now
        # No payload, no path, no exception text: journal hygiene + the file
        # may be blocked by a transient condition that retries will fix.
        print("monitor traffic export: publish failed (%s); dashboard and "
              "collector unaffected" % kind, file=sys.stderr, flush=True)

    # -- synchronous publication (direct-call testable) ----------------------

    def publish(self, projection, now=None):
        """Build + atomically publish one document. Raises on any failure."""
        generated_at = int(self._clock() if now is None else now)
        with self._lock:
            sequence = self._sequence
        document = build_document(projection,
                                  source_epoch=self.source_epoch,
                                  sequence=sequence,
                                  generated_at=generated_at)
        payload = encode_document(document)
        self._atomic_write(payload)
        with self._lock:
            self._sequence = sequence + 1
            self.published_count += 1
        return document

    def _atomic_write(self, payload):
        directory = os.path.dirname(self.path)
        fd = None
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(
                dir=directory, prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX)
            _set_final_mode(fd, temporary)
            with os.fdopen(fd, "wb") as handle:
                fd = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
            self._fsync_directory(directory)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    @staticmethod
    def _fsync_directory(directory):
        """Best-effort directory fsync (rename durability tradeoff, see module).

        Only meaningful on POSIX; failures (e.g. filesystems that refuse
        directory fsync) are deliberately swallowed -- the file itself was
        already fsynced BEFORE the rename, so a reader can never observe a
        partial document either way.
        """
        if os.name != "posix":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            dir_fd = os.open(directory, flags)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _set_final_mode(fd, temporary):
    """Best-effort 0640 on the temp file BEFORE the atomic rename."""
    if hasattr(os, "fchmod"):
        try:
            os.fchmod(fd, FINAL_FILE_MODE)
            return
        except OSError:
            pass
    try:
        os.chmod(temporary, FINAL_FILE_MODE)
    except OSError:
        pass


def encode_document(document):
    """Serialize one document to bounded UTF-8 JSON bytes (with a newline)."""
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":"),
                          allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > MAX_EXPORT_BYTES:
        raise TrafficExportDocumentError(
            "serialized export document exceeds the %d-byte bound"
            % MAX_EXPORT_BYTES)
    return payload


def _empty_projection(now):
    """Minimal valid projection used only to validate a source epoch."""
    return {
        "observed_at": int(now),
        "monitor_stale": True,
        "monitor_last_success_at": None,
        "active_connections": 0,
        "rate_window_seconds": None,
        "inbounds": [],
    }
