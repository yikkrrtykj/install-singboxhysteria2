"""Shared test harness for the sbox-journal-reader suite (PR-2A).

Test-side ONLY: nothing under monitor-v2/journal_reader/ may import this
file or anything from tests/ (statically asserted). Provides a fake
journalctl child (Popen-compatible: communicate()/wait() set .returncode
exactly like subprocess.Popen) and tmp-tree helpers.
"""

import io
import json
import os
import shutil
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "monitor-v2"))

from journal_reader import reader as reader_mod  # noqa: E402
from journal_reader import state as state_mod  # noqa: E402

CURSOR_TAIL = "a" * 37


class FakeChild:
    def __init__(self, stdout_bytes, rc):
        self.stdout = io.BytesIO(stdout_bytes)
        self._rc = rc
        self.returncode = None
        self.terminated = False
        self.killed = False

    def communicate(self, timeout=None):
        out = self.stdout.read()
        self.returncode = self._rc
        return (out, b"")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._rc
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakePopen:
    """Scripts journalctl invocations by argv shape: the single
    --show-cursor call answers with `show_cursor`/`cursor_rc`; poll calls
    consume `responses` in order ((stdout_bytes, rc) tuples)."""

    def __init__(self, responses=None, show_cursor=None, cursor_rc=0,
                 spawn_error=False):
        self.responses = list(responses or [])
        self.show_cursor = (b"cursor: " + CURSOR_TAIL.encode() + b"\n"
                            if show_cursor is None else show_cursor)
        self.cursor_rc = cursor_rc
        self.spawn_error = spawn_error
        self.calls = []
        self.poll_calls = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if self.spawn_error:
            raise OSError("journalctl: not found")
        self.calls.append(argv)
        if "--show-cursor" in argv:
            return FakeChild(self.show_cursor, self.cursor_rc)
        self.poll_calls.append(argv)
        if not self.responses:
            return FakeChild(b"", 0)
        out, rc = self.responses.pop(0)
        return FakeChild(out, rc)


def entry(cursor, message, priority="3", ts=1760000000, field=None):
    """One journalctl -o json line. ts is SECONDS (encoded as
    microseconds); field selects the timestamp field name."""
    row = {"__CURSOR": cursor, "PRIORITY": priority,
           "SYSLOG_IDENTIFIER": "sing-box"}
    key = field or "__REALTIME_TIMESTAMP"
    row[key] = str(int(ts * 1_000_000))
    if message is not None:
        row["MESSAGE"] = message
    return (json.dumps(row, sort_keys=True) + "\n").encode()


def entries(items):
    """items: list of (cursor, message, ts_seconds[, priority])."""
    out = b""
    for item in items:
        prio = item[3] if len(item) > 3 else "3"
        out += entry(item[0], item[1], prio, item[2])
    return out


def cursor_at(i, fill="w"):
    """Deterministic distinct valid cursors (opaque 37-char lookalikes)."""
    return "%s%036d" % (fill, i)


class Tree:
    """Throwaway state/out tree with fixture journalctl injection."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="sbjr-t-")
        self.state_dir = os.path.join(self.root, "state")
        self.out_dir = os.path.join(self.root, "out")
        os.makedirs(self.state_dir)
        os.makedirs(self.out_dir)

    def reader(self, popen, faults=(), **kw):
        return reader_mod.Reader(state_dir=self.state_dir,
                                 out_dir=self.out_dir, popen=popen,
                                 unit=kw.pop("unit", "sing-box.service"),
                                 faults=set(faults), **kw)

    def committed(self):
        obj, ok = state_mod.load_committed(self.state_dir)
        return obj if ok else "INVALID"

    def pending(self):
        obj, ok = state_mod.load_pending(self.state_dir)
        return obj if ok else "INVALID"

    def seqs(self):
        return sorted(state_mod.durable_ev_seqs(self.out_dir))

    def body(self, seq):
        with open(os.path.join(self.out_dir,
                               state_mod.ev_filename(seq))) as handle:
            return handle.read()

    def header(self, seq):
        return json.loads(self.body(seq).split("\n", 1)[0])

    def records(self, seq):
        lines = self.body(seq).strip().split("\n")
        return [json.loads(x) for x in lines[1:]]

    def hb(self):
        path = os.path.join(self.out_dir, reader_mod.HB_NAME)
        if not os.path.isfile(path):
            return None
        with open(path) as handle:
            return json.load(handle)

    def files(self, directory):
        return sorted(os.listdir(directory))

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class JournalPopen(FakePopen):
    """A STATEFUL fake journal: each poll honors --after-cursor by
    returning only the scripted rows strictly after the given cursor, so
    backlog/truncation semantics are exercised for real (a replaying
    fake would double-count every entry)."""

    def __init__(self, rows, show_cursor=None, cursor_rc=0):
        # rows: list of (cursor, message, ts_seconds[, priority])
        fake = FakePopen([], show_cursor=show_cursor, cursor_rc=cursor_rc)
        super().__init__([], show_cursor=fake.show_cursor, cursor_rc=cursor_rc)
        self.rows = list(rows)

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        if "--show-cursor" in argv:
            return FakeChild(self.show_cursor, self.cursor_rc)
        self.poll_calls.append(argv)
        after = None
        if "--after-cursor" in argv:
            after = argv[argv.index("--after-cursor") + 1]
        body = b""
        for row in self.rows:
            if after is not None and row[0] <= after:
                continue
            prio = row[3] if len(row) > 3 else "3"
            body += entry(row[0], row[1], prio, row[2])
        return FakeChild(body, 0)
