"""Reader durable state: committed/pending atomic state machine
(issue #33 P2, v4-C1/C2 + v5-D2/D3/D5).

state/ holds exactly the authoritative `committed`, the in-flight
`pending`, the R4 `hmac.key`, and transient `*.tmp-<run>` scratch that
recovery cleans first. `committed` is the SOLE settled authority:

  {"v":1,"seq":int,"epoch":int,
   "boundary":"NONE"|"COLD_START"|"SOURCE_GAP",
   "source":{"mode":"cursor"|"since","value":"<opaque, D5-validated>"}}

  {"v":1,"run":"<32hex uuid4>","seq":int,"epoch":int,"boundary":enum,
   "source_end":{"mode":"cursor","value":"<D5-validated>"}}

Every state write uses ONE recipe: write `X.tmp-<run>` -> flush+fsync ->
os.replace -> fsync(state dir). Boundary clearing to NONE and the
since->cursor conversion happen ONLY inside the step-4 committed
replacement (v5-D2/D3), so both are exactly-once across crashes: the
sign-off frozen invariant -- recovery row 2 replays the SAME logical
step-4 (committed.seq=pending.seq, epoch=pending.epoch,
source=pending.source_end, boundary=NONE) and only then durably removes
pending.
"""

import datetime
import json
import os
import re

from . import cursor as cursor_mod
from .schema import RUN_RE, validate_header

COMMITTED_NAME = "committed"
PENDING_NAME = "pending"
SCRATCH_INFIX = ".tmp-"

SINCE_FORM_RE = re.compile(r"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\Z")

_BOUNDS = ("NONE", "COLD_START", "SOURCE_GAP")


def fsync_dir(path):
    """Directory fsync per C1. Production targets are Linux; on non-POSIX
    dev-only platforms os.open on a directory is not possible and there is
    no ext4-style directory-entry journaling to flush, so the durability
    step is defined as a no-op there. CI enforces the real behavior on the
    three Ubuntu baselines (T28 crash matrix runs on Linux)."""
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _silent_unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _durable_write_json(state_dir, name, obj, run_tag, gate=None):
    # `gate(point)` is a TEST HOOK only (crash-matrix T28): production
    # passes None. When set it is called immediately BEFORE each durability
    # boundary so a test can die exactly there; raising from it simulates
    # power loss at pre-fsync / pre-rename / pre-dir-fsync.
    payload = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    tmp = os.path.join(state_dir, name + SCRATCH_INFIX + run_tag)
    final = os.path.join(state_dir, name)
    if gate:
        gate("tmp_open")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
            handle.flush()
            if gate:
                gate("fsync")
            os.fsync(handle.fileno())
    except OSError:
        _silent_unlink(tmp)
        raise OSError("state_write_failed")
    if gate:
        gate("rename")
    try:
        os.replace(tmp, final)
    except OSError:
        _silent_unlink(tmp)
        raise OSError("state_write_failed")
    if gate:
        gate("dir_fsync")
    try:
        fsync_dir(state_dir)
    except OSError:
        raise OSError("state_write_failed")


def write_committed(state_dir, committed, run_tag, gate=None):
    """Atomic committed replacement via the C1 recipe."""
    if not validate_committed(committed):
        raise ValueError("committed_invalid")
    _durable_write_json(state_dir, COMMITTED_NAME, committed, run_tag, gate)


def write_pending(state_dir, pending, gate=None):
    """Atomic pending write via the C1 recipe (step 2 of the cycle: fully
    durable, state dir fsynced, BEFORE any exchange-file write begins)."""
    if not validate_pending(pending):
        raise ValueError("pending_invalid")
    _durable_write_json(state_dir, PENDING_NAME, pending, pending["run"],
                        gate)


def remove_pending(state_dir, gate=None):
    """Unlink pending + dir fsync (C1 step 5)."""
    if gate:
        gate("unlink")
    try:
        os.unlink(os.path.join(state_dir, PENDING_NAME))
    except FileNotFoundError:
        return
    except OSError:
        raise OSError("state_write_failed")
    if gate:
        gate("dir_fsync")
    fsync_dir(state_dir)


def load_json(path):
    """Returns (obj_or_None, ok). Absent -> (None, True). Anything that
    exists but cannot be read/parsed -> (None, False) = fail-closed."""
    try:
        with open(path, "r") as handle:
            obj = json.loads(handle.read())
    except FileNotFoundError:
        return None, True
    except (OSError, ValueError):
        return None, False
    return obj, isinstance(obj, dict)


def load_committed(state_dir):
    obj, ok = load_json(os.path.join(state_dir, COMMITTED_NAME))
    if not ok:
        return None, False
    if obj is None:
        return None, True  # genuinely absent
    return (obj, True) if validate_committed(obj) else (None, False)


def load_pending(state_dir):
    obj, ok = load_json(os.path.join(state_dir, PENDING_NAME))
    if not ok:
        return None, False
    if obj is None:
        return None, True
    return (obj, True) if validate_pending(obj) else (None, False)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_source(source, cursor_mode_only=False):
    if not isinstance(source, dict) or set(source) != {"mode", "value"}:
        return False
    mode, value = source["mode"], source["value"]
    if mode == "cursor":
        return cursor_mod.validate_cursor(value)
    if cursor_mode_only:
        return False
    if mode == "since":
        if not isinstance(value, str) or not SINCE_FORM_RE.match(value):
            return False
        try:
            datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False
        return True
    return False


def validate_committed(obj):
    """Full D2/D3 grammar (v5): v==1, ints >= 0 (epoch >= 1), enum boundary,
    tagged source with mode-matched value grammar. Any deviation is
    journal_state_corruption at load, never a repair."""
    if not isinstance(obj, dict) or set(obj) != {"v", "seq", "epoch",
                                                 "boundary", "source"}:
        return False
    if obj["v"] != 1 or not _is_int(obj["seq"]) or obj["seq"] < 0:
        return False
    if not _is_int(obj["epoch"]) or obj["epoch"] < 1:
        return False
    if obj["boundary"] not in _BOUNDS:
        return False
    return validate_source(obj["source"])


def validate_pending(obj):
    if not isinstance(obj, dict) or set(obj) != {"v", "run", "seq", "epoch",
                                                 "boundary", "source_end"}:
        return False
    if obj["v"] != 1:
        return False
    if not isinstance(obj["run"], str) or not RUN_RE.match(obj["run"]):
        return False
    if not _is_int(obj["seq"]) or obj["seq"] < 1:
        return False
    if not _is_int(obj["epoch"]) or obj["epoch"] < 1:
        return False
    if obj["boundary"] not in _BOUNDS:
        return False
    return validate_source(obj["source_end"], cursor_mode_only=True)


def make_committed(seq, epoch, boundary, source):
    return {"v": 1, "seq": seq, "epoch": epoch, "boundary": boundary,
            "source": dict(source)}


def make_pending(run, seq, epoch, boundary, end_cursor):
    return {"v": 1, "run": run, "seq": seq, "epoch": epoch,
            "boundary": boundary,
            "source_end": {"mode": "cursor", "value": end_cursor}}


def step4_committed(pending):
    """The ONE logical step-4 projection (original cycle AND recovery row
    2 -- sign-off frozen invariant): settle the batch, clear boundary to
    NONE, and convert since->cursor by taking source from source_end."""
    return make_committed(pending["seq"], pending["epoch"], "NONE",
                          dict(pending["source_end"]))


def clean_scratch(state_dir, out_dir):
    """Remove abandoned scratch artifacts (state `*.tmp-*`, out
    `*.tmp-*` and `*.part`) before recovery evaluates: non-terminal by
    construction, never the object of a trust decision. Returns number
    removed."""
    removed = 0
    for directory in (state_dir, out_dir):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        dirty = False
        for name in names:
            if SCRATCH_INFIX in name or name.endswith(".part"):
                _silent_unlink(os.path.join(directory, name))
                removed += 1
                dirty = True
        if dirty:
            fsync_dir(directory)
    return removed


def ev_filename(seq):
    return "ev-%d.jsonl" % seq


def durable_ev_seqs(out_dir):
    """Set of seqs backed by durable exchange files matching the strict
    filename grammar (`.part` scratch excluded by shape)."""
    seqs = set()
    try:
        names = os.listdir(out_dir)
    except OSError:
        return seqs
    for name in names:
        match = re.fullmatch(r"ev-([0-9]{1,20})\.jsonl", name)
        if match:
            path = os.path.join(out_dir, name)
            try:
                if os.path.isfile(path) and not os.path.islink(path):
                    seqs.add(int(match.group(1)))
            except OSError:
                pass
    return seqs


def header_matches(out_dir, seq, expect_run, expect_seq):
    """Recovery row-2 identity check: the durable file's header must itself
    validate AND carry pending.run / pending.seq (C2: mutual agreement,
    never equality with the CURRENT process run)."""
    try:
        with open(os.path.join(out_dir, ev_filename(seq)), "r") as handle:
            first = handle.readline()
    except OSError:
        return False
    try:
        obj = json.loads(first)
    except ValueError:
        return False
    if not validate_header(obj):
        return False
    return obj["seq"] == expect_seq and obj["run"] == expect_run


def evaluate_recovery(committed, pending, durable_seqs, out_dir):
    """C2 startup table (v4 rows, as amended by v5-D2/D3).

    Returns (row:int, action:str) with action in
      "start" / "finish_commit" / "repoll" / "fail_closed" /
      "first_activation".
    Row 4 (stale pending) is reported as "repoll": the caller unlinks
    pending via the recipe, then proceeds as row 1.
    """
    if committed is None:
        if pending is None and not durable_seqs:
            return 7, "first_activation"
        return 8, "fail_closed"

    cs = committed["seq"]
    ev_next = (cs + 1) in durable_seqs

    if pending is None:
        if ev_next:
            return 6, "fail_closed"
        if any(seq > cs + 1 for seq in durable_seqs):
            # Visible ev above committed.seq+1 is unreachable except via a
            # lost committed replacement -- corrupt by definition.
            return 8, "fail_closed"
        return 1, "start"

    if pending["seq"] <= cs:
        return 4, "repoll"
    if pending["seq"] > cs + 1:
        return 5, "fail_closed"
    if any(seq > cs + 1 for seq in durable_seqs):
        return 8, "fail_closed"
    if not ev_next:
        return 3, "repoll"
    if header_matches(out_dir, cs + 1, pending["run"], pending["seq"]):
        return 2, "finish_commit"
    return 6, "fail_closed"
