"""Monitor-side ingest CONTRACT (issue #33 P2, v2-R6 + v3-B4).

Pure, storage-agnostic and INERT in PR-2A: nothing in the Monitor process
imports this module yet (schema-v2 ingest activation is PR-2B). It exists
in 2A because the frozen acceptance contracts it implements are exactly
what PR-2B will wire to SQLite, and the reviewer-required terminal-seq
continuity cases (T24/T25/T27a/b/c) must be provable green before any
activation code merges.

Policies implemented here (frozen):
  * journal_terminal_seq is the SOLE continuity authority (v3-B4);
    journal_last_consumed_seq is informational only.
  * Files settle STRICTLY ascending from terminal+1 -- no leapfrogging:
    a failed apply settles nothing and blocks higher seqs for the cycle.
  * A terminally REJECTED (schema-invalid) file advances terminal exactly
    once and bumps the rejected counter once (no 10 s forever-reject
    loop); a later valid file around it records NO gap
    (valid4/rejected5/valid6 => rejected=1, gaps=0).
  * A missing file that a higher arrival leaps over counts the gap exactly
    once at discovery (valid4/missing5/valid6 => gaps=1); a late-arriving
    skipped seq is then ignored by the seq<=terminal rule and never
    re-counted or retracted.
  * A valid file applies within ONE storage transaction that also carries
    the terminal advance: partial application settles nothing (PR-2B's
    SQLite transaction boundary; `apply` here is the injection point).
  * Header rules: exactly one header line, FIRST; header.seq == filename
    seq; any violation rejects the WHOLE file with a sanitized code only.
"""

import json
import os
import re
import stat as _stat

from .schema import FILENAME_RE, parse_exchange_text

MAX_FILE_BYTES = 256 * 1024  # §7.2 hard validation bound

# Disposition categories (all sanitized; never the raw reason payload).
DISPOSITION_EMPTY = "empty"          # nothing to do (seq <= terminal)
DISPOSITION_VALID = "valid"
DISPOSITION_REJECTED = "rejected"
DISPOSITION_APPLY_FAILED = "apply_failed"  # NOT terminal, retried, blocks


def scan_exchange_dir(out_dir):
    """Strict filename grammar; symlinks/non-regular are excluded here and
    re-checked at open (regular-file-only per §7.2)."""
    found = {}
    try:
        names = os.listdir(out_dir)
    except OSError:
        return found
    for name in sorted(names):
        match = FILENAME_RE.match(name)
        if not match:
            continue
        found[int(match.group(1))] = name
    return found


def read_and_validate(out_dir, name, filename_seq):
    """Fail-closed per file: returns (records, None) or (None, code)."""
    path = os.path.join(out_dir, name)
    try:
        st = os.lstat(path)
    except OSError:
        return None, "exchange_unreadable"
    if not re.fullmatch(r"ev-[0-9]{1,20}\.jsonl", name):
        return None, "exchange_bad_name"
    if not _stat.S_ISREG(st.st_mode):
        return None, "exchange_not_regular"
    if st.st_size > MAX_FILE_BYTES:
        return None, "exchange_too_large"
    try:
        with open(path, "r") as handle:
            body = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None, "exchange_unreadable"
    if len(body.encode("utf-8")) > MAX_FILE_BYTES:
        return None, "exchange_too_large"
    code = parse_exchange_text(body, filename_seq)
    if code is not None:
        return None, code
    records = []
    for line in body.split("\n"):
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("t") == "e":
            records.append(obj)
    return (body, records), None


def settle(out_dir, terminal_seq, apply_fn, settle_fn=None):
    """Run one ingest pass over `out_dir` given the stored
    `journal_terminal_seq`; returns a result dict:

      {"terminal": int, "gaps": int, "rejected": int, "consumed": int,
       "last_consumed": int|None, "blocked_at": int|None,
       "rejected_codes": {seq: code}}

    `apply_fn(header, records, seq)` must persist aggregates AND the
    terminal advance as ONE atomic storage transaction. Optional
    `settle_fn(kind, terminal, amount, code)` is the PR-2B storage hook for
    gap/rejected dispositions; it must persist their terminal advance and
    counter increment atomically before scanning continues. Returning
    normally means committed; raising means nothing settled and blocks the
    cycle at that seq."""
    files = scan_exchange_dir(out_dir)
    result = {"terminal": terminal_seq, "gaps": 0, "rejected": 0,
              "consumed": 0, "last_consumed": None, "blocked_at": None,
              "rejected_codes": {}}
    seq = terminal_seq + 1
    while seq in files or any(s > seq for s in files):
        if seq not in files:
            # Discovery-time gap settlement (v3-B4): count the whole
            # skipped interval ONCE, move terminal to seq-1, continue.
            present = sorted(s for s in files if s >= seq)
            if not present:
                break
            nxt = present[0]
            amount = nxt - seq
            new_terminal = nxt - 1
            if settle_fn is not None:
                try:
                    settle_fn("gap", new_terminal, amount, None)
                except Exception:
                    result["blocked_at"] = seq
                    break
            result["gaps"] += amount
            result["terminal"] = new_terminal
            seq = nxt
        payload, code = read_and_validate(out_dir, files[seq], seq)
        if code is not None:
            # Terminally rejected: settles once, never re-read again, and
            # later seqs continue (no forever-reject loop, no gap).
            if settle_fn is not None:
                try:
                    settle_fn("rejected", seq, 1, code)
                except Exception:
                    result["blocked_at"] = seq
                    break
            result["terminal"] = seq
            result["rejected"] += 1
            result["rejected_codes"][seq] = code
            seq += 1
            continue
        body, records = payload
        header = json.loads(body.split("\n", 1)[0])
        try:
            apply_fn(header, records, seq)
        except Exception:
            # NOT terminal: no counters, no advance; higher seqs do NOT
            # leapfrog a file that merely failed to settle (in-order
            # settlement is the reviewed policy).
            result["blocked_at"] = seq
            break
        result["terminal"] = seq
        result["last_consumed"] = seq
        result["consumed"] += 1
        seq += 1
    return result
