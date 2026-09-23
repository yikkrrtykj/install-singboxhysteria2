#!/usr/bin/env bash
# PR-2B monitor-side journal ingest scheduler regression.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH="$ROOT/monitor-v2" python3 - <<'PY'
import json
import os
import tempfile

from web.journal_ingest import JournalIngestLoop, READER_STALE_SECONDS, read_heartbeat

passed = 0
failed = 0

def ck(label, cond):
    global passed, failed
    if cond:
        passed += 1
        print("PASS", label)
    else:
        failed += 1
        print("FAIL", label)

class History:
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail
    def ingest_journal_once(self, _out):
        self.calls += 1
        if self.fail:
            raise RuntimeError("sentinel raw failure must not escape")

with tempfile.TemporaryDirectory() as d:
    h = read_heartbeat(d, now=1000)
    ck("missing hb is stale but not valid", not h["present"] and h["stale"] and not h["valid"])

    p = os.path.join(d, "hb")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"seq": 7, "ts": 900}, f)
    os.chmod(p, 0o640)
    h = read_heartbeat(d, now=1000)
    ck("valid hb carries only seq/age health", h["valid"] and h["seq"] == 7 and h["age_seconds"] == 100)
    ck("fresh hb below 180 seconds", not h["stale"])

    h = read_heartbeat(d, now=900 + READER_STALE_SECONDS + 1)
    ck("hb older than 180 seconds is stale", h["stale"])

    with open(p, "w", encoding="utf-8") as f:
        json.dump({"seq": True, "ts": 900}, f)
    ck("bool seq rejected", not read_heartbeat(d, now=1000)["valid"])

    os.unlink(p)
    os.symlink("elsewhere", p)
    ck("symlink hb rejected", not read_heartbeat(d, now=1000)["valid"])
    os.unlink(p)

    with open(p, "w", encoding="utf-8") as f:
        json.dump({"seq": 1, "ts": 1000, "extra": "x"}, f)
    ck("extra heartbeat key rejected", not read_heartbeat(d, now=1000)["valid"])

    good = History()
    loop = JournalIngestLoop(good, out_dir=d, clock=lambda: 1234.0)
    ck("run_once invokes storage consumer", loop.run_once() and good.calls == 1)
    ck("successful run exposes no raw error", loop.health()["last_error_code"] is None)

    bad = History(fail=True)
    loop2 = JournalIngestLoop(bad, out_dir=d, clock=lambda: 1234.0)
    ck("storage failure is fail-soft", loop2.run_once() is False and bad.calls == 1)
    health = loop2.health()
    ck("failure health is sanitized code only", health["last_error_code"] == "journal_ingest_failed" and health["failure_count"] == 1)

print("pass=%d fail=%d" % (passed, failed))
raise SystemExit(0 if failed == 0 else 1)
PY
