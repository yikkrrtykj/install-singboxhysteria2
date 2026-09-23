#!/usr/bin/env bash
# PR-2B Monitor-side ingest regression: schema-v2 migration + atomic settle.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

PASS=0
FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
check(){ if [ "$1" = "True" ]; then pass "$2"; else fail "$2"; fi; }

OUT="$TMP/result.json"
PYTHONPATH="$ROOT/monitor-v2" "$PY" - "$TMP" >"$OUT" <<'PY'
import json
import os
import sqlite3
import sys

from web.incident_history import IncidentHistory, SAMPLE_COLUMNS, SCHEMA_VERSION
from web.journal_ingest import JournalIngestWorker

root = sys.argv[1]
clock_now = [1_700_000_000.0]
def clock():
    return clock_now[0]

diag = os.path.join(root, "diag")
out = os.path.join(root, "out")
os.makedirs(out, mode=0o750)

# Build a genuine v1 database with the production P1 DDL, then reopen under
# PR-2B and prove forward-only migration preserves existing P1 metadata.
h0 = IncidentHistory(diag, "0"*32, clock=clock, monitor_version="0.2.0")
os.makedirs(diag, mode=0o700, exist_ok=True)
db = os.path.join(diag, "history.sqlite3")
con = sqlite3.connect(db)
h0._apply_pragmas(con)
h0._create_schema_v1(con)
con.execute("INSERT INTO meta(key,value) VALUES('p1_sentinel','keep-me')")
con.commit(); con.close()

history = IncidentHistory(diag, "1"*32, clock=clock, monitor_version="0.3.0")
history.open()
con = sqlite3.connect(db)
schema = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
sentinel = con.execute("SELECT value FROM meta WHERE key='p1_sentinel'").fetchone()[0]
tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
meta = dict(con.execute("SELECT key,value FROM meta"))
con.close()

def header(seq, epoch=1, boundary="NONE"):
    return {"t":"h","v":1,"cv":1,"seq":seq,"run":"2"*32,
            "epoch":epoch,"boundary":boundary,"lines":1,"eligible":1,
            "info_dropped":0,"nomatch_dropped":0,"priority_unusable":0,
            "pfail":0,"limited":0}

def event(ts=None):
    return {"t":"e","ts":clock() if ts is None else ts,
            "cls":"dial_timeout","proto":"Reality","port":443,
            "dcls":"https443","fp":None,"n":2}

def write_ev(seq, hdr, ev=None, raw=None):
    path = os.path.join(out, "ev-%d.jsonl" % seq)
    with open(path, "w", encoding="utf-8") as f:
        if raw is not None:
            f.write(raw)
        else:
            f.write(json.dumps(hdr,separators=(",",":"))+"\n")
            if ev is not None:
                f.write(json.dumps(ev,separators=(",",":"))+"\n")

def heartbeat():
    with open(os.path.join(out,"hb"),"w",encoding="utf-8") as f:
        json.dump({"seq":0,"ts":int(clock())},f)

heartbeat()
write_ev(1, header(1,1,"COLD_START"), event())
worker = JournalIngestWorker(history, out_dir=out, poll=10, clock=clock)
r1 = worker.run_once()

con = sqlite3.connect(db)
row1 = con.execute("SELECT journal_epoch,error_class,protocol,dest_port,dest_class,fp,count FROM error_aggregates").fetchall()
m1 = dict(con.execute("SELECT key,value FROM meta"))
con.close()

# Missing seq 2 then valid 3: one gap, terminal advances atomically through 3.
write_ev(3, header(3,1,"NONE"), event())
r3 = worker.run_once()
con = sqlite3.connect(db)
m3 = dict(con.execute("SELECT key,value FROM meta"))
con.close()

# Invalid seq 4 is terminal exactly once.
write_ev(4, None, raw='{"t":"e","bad":"raw-secret-SENTINEL"}\n')
r4a = worker.run_once()
r4b = worker.run_once()
con = sqlite3.connect(db)
m4 = dict(con.execute("SELECT key,value FROM meta"))
raw_db = open(db,"rb").read()
con.close()

# Same minute/context but a new completeness epoch must NOT merge.
write_ev(5, header(5,2,"SOURCE_GAP"), event())
heartbeat()
r5 = worker.run_once()
con = sqlite3.connect(db)
epochs = con.execute("SELECT journal_epoch,SUM(count) FROM error_aggregates GROUP BY journal_epoch ORDER BY journal_epoch").fetchall()
m5 = dict(con.execute("SELECT key,value FROM meta"))
con.close()

summary = history.query_error_summary(limit=20)
health = history.health()
history.close()

result = {
  "schema2": schema == str(SCHEMA_VERSION) == "2",
  "p1_meta_preserved": sentinel == "keep-me",
  "v2_table_present": "error_aggregates" in tables,
  "meta_initialized": all(k in meta for k in (
      "journal_terminal_seq","journal_gaps","journal_cold_starts",
      "journal_source_gaps","journal_rejected_files","journal_reader_cv")),
  "first_consumed": r1["terminal"] == 1 and r1["consumed"] == 1,
  "first_row_safe": row1 == [(1,"dial_timeout","Reality",443,"https443","NONE",2)],
  "cold_start_once": m1["journal_cold_starts"] == "1",
  "gap_once": r3["gaps"] == 1 and m3["journal_gaps"] == "1" and m3["journal_terminal_seq"] == "3",
  "reject_once": r4a["rejected"] == 1 and r4b["rejected"] == 0 and m4["journal_rejected_files"] == "1" and m4["journal_terminal_seq"] == "4",
  "invalid_raw_not_persisted": b"raw-secret-SENTINEL" not in raw_db,
  "epoch_split": epochs == [(1,4),(2,2)],
  "source_gap_once": m5["journal_source_gaps"] == "1",
  "terminal5": m5["journal_terminal_seq"] == "5",
  "query_bounded": len(summary["rows"]) == 2 and summary["truncated"] is False,
  "health_ingest_enabled": health["journal_ingest"]["enabled"] is True,
}
print(json.dumps(result,sort_keys=True))
PY

if ! "$PY" -m py_compile     "$ROOT/monitor-v2/web/incident_history.py"     "$ROOT/monitor-v2/web/journal_ingest.py"     "$ROOT/monitor-v2/journal_reader/ingest_contract.py"; then
    fail "python sources compile"
else
    pass "python sources compile"
fi

for key in schema2 p1_meta_preserved v2_table_present meta_initialized            first_consumed first_row_safe cold_start_once gap_once reject_once            invalid_raw_not_persisted epoch_split source_gap_once terminal5            query_bounded health_ingest_enabled; do
    val="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$OUT" "$key")"
    check "$val" "$key"
done

printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
