"""Monitor-side sanitized journal ingest loop (issue #33 P2 PR-2B).

Reads only the reviewed group-readable exchange directory. It never opens
journald, /var/log, reader-private state, or raw MESSAGE text.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time

from journal_reader.ingest_contract import settle
from .incident_history import (
    CODE_INGEST_DB_FAILED,
    CODE_INGEST_GAP,
    CODE_INGEST_REJECTED,
    CODE_INGEST_STALE_READER,
)

DEFAULT_OUT_DIR = "/var/lib/sbox-journal/out"
POLL_SECONDS = 10.0
HEARTBEAT_STALE_SECONDS = 180.0
HB_NAME = "hb"


class JournalIngestWorker:
    """One bounded background consumer; all storage is delegated to history."""

    def __init__(self, history, out_dir=DEFAULT_OUT_DIR, poll=POLL_SECONDS,
                 clock=time.time):
        self._history = history
        self._out_dir = out_dir
        self._poll = float(poll)
        self._clock = clock
        self._stop = threading.Event()
        self._thread = None

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
        self._thread = None

    def run_once(self):
        """One deterministic ingest pass; never raises to the caller."""
        try:
            terminal = self._history.journal_terminal_seq()
            result = settle(
                self._out_dir, terminal,
                self._history.apply_journal_records,
                self._history.apply_journal_settlement)
            if result.get("blocked_at") is not None:
                self._history.mark_journal_ingest_failure(
                    CODE_INGEST_DB_FAILED)
                return result
            if result.get("rejected", 0):
                self._history.mark_journal_ingest_failure(
                    CODE_INGEST_REJECTED)
                return result
            if result.get("gaps", 0):
                self._history.mark_journal_ingest_failure(CODE_INGEST_GAP)
                return result
            if not self._heartbeat_fresh():
                self._history.mark_journal_ingest_failure(
                    CODE_INGEST_STALE_READER)
                return result
            self._history.mark_journal_ingest_success()
            return result
        except Exception:
            # Category only; never exception text/path/payload.
            self._history.mark_journal_ingest_failure(CODE_INGEST_DB_FAILED)
            return {"terminal": self._history.journal_terminal_seq(),
                    "blocked_at": self._history.journal_terminal_seq() + 1,
                    "gaps": 0, "rejected": 0, "consumed": 0}

    def _heartbeat_fresh(self):
        path = os.path.join(self._out_dir, HB_NAME)
        try:
            st = os.lstat(path)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return False
        if st.st_size > 4096:
            return False
        try:
            with open(path, "r", encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, ValueError, TypeError):
            return False
        if not isinstance(obj, dict) or set(obj) != {"seq", "ts"}:
            return False
        seq = obj.get("seq")
        ts = obj.get("ts")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            return False
        if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
            return False
        age = self._clock() - float(ts)
        return 0.0 <= age <= HEARTBEAT_STALE_SECONDS

    def _run(self):
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._poll)
