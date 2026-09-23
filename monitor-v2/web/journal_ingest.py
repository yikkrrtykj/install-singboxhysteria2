"""Monitor-side journal exchange consumer loop (issue #33 P2 / PR-2B).

This module NEVER reads journald.  Its only input is the reviewed, group-readable
exchange directory produced by the dedicated sbox-jr process.  Raw MESSAGE text
cannot cross that boundary because the exchange schema has no free-text field.

The storage transaction itself lives in IncidentHistory.ingest_journal_once();
this module owns only scheduling and the reader-heartbeat health signal.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time

DEFAULT_OUT_DIR = "/var/lib/sbox-journal/out"
POLL_SECONDS = 10.0
READER_STALE_SECONDS = 180.0
MAX_HEARTBEAT_BYTES = 1024

CODE_INGEST_FAILED = "journal_ingest_failed"
CODE_HEARTBEAT_INVALID = "journal_heartbeat_invalid"


def read_heartbeat(out_dir, now=None):
    """Return a sanitized heartbeat view.

    Result keys are fixed and contain no path or free text:
      present, valid, seq, age_seconds, stale

    Symlinks, non-regular files, oversized/malformed JSON and wrong exact-key
    shapes are invalid.  A missing heartbeat is simply present=false/stale=true.
    """
    now = time.time() if now is None else float(now)
    path = os.path.join(out_dir, "hb")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"present": False, "valid": False, "seq": None,
                "age_seconds": None, "stale": True}
    except OSError:
        return {"present": True, "valid": False, "seq": None,
                "age_seconds": None, "stale": True}

    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or st.st_size < 2 or st.st_size > MAX_HEARTBEAT_BYTES):
        return {"present": True, "valid": False, "seq": None,
                "age_seconds": None, "stale": True}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read(MAX_HEARTBEAT_BYTES + 1)
        obj = json.loads(raw)
    except (OSError, ValueError):
        return {"present": True, "valid": False, "seq": None,
                "age_seconds": None, "stale": True}

    if (not isinstance(obj, dict) or set(obj) != {"seq", "ts"}
            or not isinstance(obj["seq"], int) or isinstance(obj["seq"], bool)
            or obj["seq"] < 0
            or not isinstance(obj["ts"], int) or isinstance(obj["ts"], bool)
            or obj["ts"] < 0):
        return {"present": True, "valid": False, "seq": None,
                "age_seconds": None, "stale": True}

    age = max(0.0, now - float(obj["ts"]))
    return {"present": True, "valid": True, "seq": obj["seq"],
            "age_seconds": age, "stale": age > READER_STALE_SECONDS}


class JournalIngestLoop:
    """Fail-soft scheduler around IncidentHistory journal ingestion."""

    def __init__(self, history, out_dir=DEFAULT_OUT_DIR,
                 poll_seconds=POLL_SECONDS, clock=time.time):
        self._history = history
        self._out_dir = out_dir
        self._poll = float(poll_seconds)
        self._clock = clock
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._last_success_at = None
        self._failure_count = 0
        self._last_error_code = None

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="journal-ingest", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(2.0, self._poll + 1.0))

    def run_once(self):
        try:
            self._history.ingest_journal_once(self._out_dir)
        except Exception:  # storage implementation must not kill Web serving
            with self._lock:
                self._failure_count += 1
                self._last_error_code = CODE_INGEST_FAILED
            return False
        with self._lock:
            self._last_success_at = self._clock()
            self._last_error_code = None
        return True

    def health(self):
        hb = read_heartbeat(self._out_dir, self._clock())
        with self._lock:
            thread_alive = bool(self._thread and self._thread.is_alive())
            return {
                "thread_alive": thread_alive,
                "reader_stale": bool(hb["stale"]),
                "heartbeat_valid": bool(hb["valid"]),
                "heartbeat_seq": hb["seq"],
                "last_success_at": self._last_success_at,
                "failure_count": int(self._failure_count),
                "last_error_code": self._last_error_code,
            }

    def _run(self):
        # Run immediately so an upgrade does not wait one full interval before
        # consuming already-durable exchange files.
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._poll)
