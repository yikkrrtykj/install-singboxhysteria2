#!/usr/bin/env bash
# Monitor v2 0.2.0 -- incident history (issue #33 Phase 1) regression suite.
#
# Discriminating gates required by the P1 spec §10: storage safety (modes,
# symlink/non-regular rejection, journal_mode=DELETE), privacy (sentinel
# values that must NEVER reach a row, the file, or the HTTP surface),
# cadence (5s aggregate / change-triggered device rows / <=1 heartbeat per
# 60s / no row for rate-only change), restart (new run_id, no fabricated
# backfill), retention (time + size, the two tables pruned as ONE globally
# epoch-ordered timeline), failure (never raises to the broker, degraded
# health, dashboard keeps serving) and the session-gated bounded read
# endpoint. Review fixes on PR #44 add their own discriminating gates:
# B1 (one RLock serializes writer/readers/close, proven by a REAL threaded
# stress group H9), B2 (interleaved mixed-table epochs prune to a global
# newest suffix), B3 (strict schema: any non-exact-v1 shape fails closed
# with zero bytes mutated).
#
# POSIX-specific permission/symlink assertions run for real on Linux (the
# CI gate) and vacuously pass on platforms without symlink/permission
# support -- the same pattern the packaging suite uses for SYMLINKS_OK.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export WEBAPP="$ROOT/monitor-v2/webapp.py"

PASS=0
FAIL=0
EXPECTED_PASS=215
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -gt 0 ]; then pass "$3"; else fail "$3 (missing: $1)"; fi; }

if [ -z "$PY" ]; then
    printf '  SKIP python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$FAIL"
    exit 1  # fail closed: no Python means the gate cannot be proven
fi

section "S0: static gates"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
if "$PY" -m py_compile "$HIST_PY" "$ROOT/monitor-v2/web/broker.py" \
    "$ROOT/monitor-v2/web/server.py" "$ROOT/monitor-v2/webapp.py" \
    2>"$TMP/py.err"; then
    pass "py_compile incident_history + broker + server + webapp"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi
IMPORTS="$("$PY" - "$HIST_PY" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
mods = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        mods.update(a.name.split(".")[0] for a in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        mods.add(node.module.split(".")[0])
print(",".join(sorted(mods)))
EOF
)"
if printf '%s' "$IMPORTS" | grep -qE 'requests|aiohttp|httpx|redis|peewee|sqlalchemy|pandas|numpy'; then
    fail "non-stdlib dependency in incident_history: $IMPORTS"
else
    case "$IMPORTS" in
        *datetime*,*os*,*sqlite3*,*stat*,*threading*,*time*)
            pass "incident_history imports are stdlib-only (no new dependency)" ;;
        *) fail "unexpected import set in incident_history: $IMPORTS" ;;
    esac
fi
if grep -Eq 'print\(|logging\.' "$HIST_PY"; then
    fail "incident_history must never print/log (payload hygiene)"
else
    pass "incident_history has zero print/logging calls (DB contents never logged)"
fi
if grep -q 'incident_history' "$ROOT/monitor-v2/collector.py"; then
    fail "collector.py references incident_history (E1 boundary violated)"
else
    pass "collector.py (E1 accounting) is untouched by the history subsystem"
fi
if "$PY" - "$ROOT/monitor-v2/web/broker.py" <<'EOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
loop = src.split("def _publish_loop", 1)[1].split("def _export_health_file", 1)[0]
assert "self._decorate(snapshot)" in loop
assert loop.index("self._decorate(snapshot)") < loop.index("self._record_history(snapshot, version)")
hook = src.split("def _record_history", 1)[1].split("def _decorate", 1)[0]
assert "except Exception" in hook
EOF
then
    pass "broker hook: AFTER _decorate, publisher-guarded"
else
    fail "broker publication hook ordering/guard contract broken"
fi
assert_eq '0.2.0' "$(cat "$ROOT/monitor-v2/VERSION")" "VERSION file is 0.2.0"
assert_contains 'MONITOR_WEB_VERSION = "0.2.0"' \
    "$(cat "$ROOT/monitor-v2/web/server.py")" "MONITOR_WEB_VERSION is 0.2.0"
assert_eq "0" "$(grep -c 'diagnostics/timeline' "$ROOT/monitor-v2/web/static/app.js" "$ROOT/monitor-v2/web/static/index.html" | awk -F: '{s+=$2} END {print s+0}')" \
    "no Incidents UI in P1 (static frontend untouched by the read surface)"
if grep -Eq 'ReadWritePaths|supplementaryGroups|AmbientCapabilities|journald|sudoers' "$HIST_PY"; then
    fail "history module asks for new privileges/log access (spec §1/§12)"
else
    pass "history module requests no new systemd privilege or journald access"
fi
if "$PY" - "$HIST_PY" <<'EOF'
import ast, re, sys
src = open(sys.argv[1], encoding="utf-8").read()
assert not re.search(r"threading\.Lock\(\)", src), \
    "bare Lock would deadlock the reentrant failure path"
tree = ast.parse(src)
fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
for name in ("open", "on_publish", "close", "_record_failure"):
    withs = [n for n in ast.walk(fns[name]) if isinstance(n, ast.With)]
    assert withs, "%s has no with-block" % name
    assert any("_lock" in ast.dump(w) for w in withs), \
        "%s does not enter self._lock" % name
import re as _re
assert re.search(r"self\._lock = threading\.RLock\(\)", src), \
    "lock must be a reentrant RLock"
EOF
then
    pass "B1 lock discipline: RLock + writer/readers/close/_record_failure all serialize"
else
    fail "B1 lock discipline broken (public section escapes the shared lock)"
fi

# -- shared python harness ---------------------------------------------------
cat > "$TMP/hist_harness.py" <<'HARNESS_EOF'
#!/usr/bin/env python3
"""Incident-history harness: real SQLite files, injected clocks,
real loopback HTTP server for the read surface."""
import http.client
import json
import locale
import os
import re
import sqlite3
import stat
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])

from web.access import AccessPolicy
from web.auth import AuthStore
from web.broker import SnapshotBroker
from web.incident_history import (CODE_DIR_UNSAFE, CODE_DB_UNSAFE,
                                  CODE_OPEN_FAILED,
                                  CODE_RETENTION_FAILED,
                                  CODE_SCHEMA_UNSUPPORTED, CODE_WRITE_FAILED,
                                  DEVICE_STATE_COLUMNS, QUERY_LIMIT_MAX,
                                  SAMPLE_COLUMNS, IncidentHistory,
                                  classify_protocol)
from web.server import MonitorWebApp, build_server

PASSWORD = "hist-test-password-0"
RUN = "run-a-fixture"
T0 = 1_700_000_000.0

# Sentinel values that MUST NEVER appear in the database or any read result.
S_CONN = "b6ff1e2c-SENTINEL-CONNID-9f3a"
S_SRC = "203.0.113.77"
S_DST = "sentinel-dest-host.example.invalid"
S_PW = "SENTINEL-HY2-PASSWORD-do-not-store"
S_KEY = "SENTINEL-PRIVATE-KEY-do-not-store"
S_SEC = "SENTINEL-API-SECRET-do-not-store"
SENTINELS = [S_CONN, S_SRC, S_DST, S_PW, S_KEY, S_SEC]


def snap(active_vless=2, active_hy2=1, status="ACTIVE", rate=1.0, extra=None):
    """A DECORATED snapshot shaped like the broker's, with forbidden
    payload everywhere the real snapshot has it."""
    devices = {
        "vmix-01": {
            "name": "vmix-01", "status": status,
            "protocols": {
                "vless-in": {"device_name": "vmix-01", "inbound": "vless-in",
                             "active_connections": active_vless,
                             "uplink_rate": rate, "downlink_rate": rate,
                             "uplink_total": 100.0, "downlink_total": 200.0},
                "hy2-in": {"device_name": "vmix-01", "inbound": "hy2-in",
                           "active_connections": active_hy2,
                           "uplink_rate": rate, "downlink_rate": rate,
                           "uplink_total": 10.0, "downlink_total": 20.0}},
            "active_connections": active_vless + active_hy2,
            "uplink_rate": rate, "downlink_rate": rate,
            "uplink_total": 110.0, "downlink_total": 220.0,
            "recent_sources": [S_SRC],
            "last_activity": "2026-01-01T00:00:00+00:00",
            "recent_connections": [{"id": S_CONN, "inbound": "vless-in",
                                    "source": S_SRC, "destination": S_DST,
                                    "uplink_total": 1.0, "downlink_total": 1.0,
                                    "closed_at": None}],
            "closed_ids": [{"id": S_CONN, "inbound": "vless-in",
                            "closed_at": None}],
        }}
    if extra:
        devices.update(extra)
    return {
        "batch_count": 7, "skipped_events": 1, "duplicate_events": 2,
        "identity_conflicts": 0, "abandoned_on_reset": 0,
        "active_connections": active_vless + active_hy2,
        "recently_closed": 1,
        "connections": [{"id": S_CONN, "user": "vmix-01",
                         "inbound": "vless-in", "inbound_type": "vless",
                         "network": "tcp", "source": S_SRC,
                         "destination": S_DST, "password": S_PW,
                         "state": "ACTIVE"}],
        "devices": devices,
        "stale": False, "last_error": "RuntimeError: %s %s" % (S_SEC, S_KEY),
        "last_success_at": "2026-01-01T00:00:00+00:00",
        "generated_at": "2026-01-01T00:00:01+00:00",
        "monitor_started_at": "2026-01-01T00:00:00+00:00",
        "snapshot_generated_at": "2026-01-01T00:00:01+00:00",
        "api_status": "CONNECTED", "collector_uptime_seconds": 42.0,
    }


def tmp_history(run_id=RUN, **kw):
    d = tempfile.mkdtemp()
    kw.setdefault("clock", lambda: T0)
    kw.setdefault("monitor_version", "0.2.0")
    h = IncidentHistory(os.path.join(d, "diagnostics"), run_id, **kw)
    h._tmpdir = d
    return h


def raw_db_bytes(h):
    path = os.path.join(h._tmpdir, "diagnostics", "history.sqlite3")
    if not os.path.exists(path):
        return b""
    with open(path, "rb") as handle:
        return handle.read()


def posix_symlink_ok():
    if os.name != "posix":
        return False
    probe = tempfile.mkdtemp()
    try:
        os.symlink(probe, probe + "-link")
        return True
    except OSError:
        return False
    finally:
        try:
            os.unlink(probe + "-link")
        except OSError:
            pass


SYMLINK = posix_symlink_ok()


def rows_of(h):
    r = h.query_timeline(limit=QUERY_LIMIT_MAX)
    return r["samples"], r["device_states"]


# -- P2B journal ingest helpers ----------------------------------------------
from journal_reader import schema as JR  # noqa: E402 (harness-side fixture)
from journal_reader import ingest_contract as JC  # noqa: E402
from web.incident_history import (CODE_INGEST_APPLY_FAILED,  # noqa: E402
                                  JOURNAL_AUDIT_CODES, JOURNAL_BOUNDARIES,
                                  JOURNAL_CLASSES, JOURNAL_DCLS,
                                  JOURNAL_PROTOS)

JR_RUN = "0123456789abcdef0123456789abcdef"


def ev_header(seq, **over):
    header = {"t": "h", "v": JR.FORMAT_VERSION, "cv": JR.CLASSIFIER_VERSION,
              "seq": seq, "run": JR_RUN, "epoch": 1, "boundary": "NONE",
              "lines": 10, "eligible": 3, "info_dropped": 2,
              "nomatch_dropped": 5, "priority_unusable": 0, "pfail": 0,
              "limited": 0}
    header.update(over)
    return header


def ev_record(ts=1_700_000_000.0, **over):
    record = {"t": "e", "ts": ts, "cls": "dns", "proto": "OTHER",
              "port": None, "dcls": None, "fp": None, "n": 1}
    record.update(over)
    return record


def write_ev(h, seq, records=None, header=None, raw=None):
    """Write a contract-shaped ev file into h._out (valid unless
    records/header/raw say otherwise)."""
    if raw is not None:
        body = raw
    else:
        lines = [json.dumps(header if header is not None
                            else ev_header(seq), sort_keys=True)]
        for record in (records if records is not None
                       else [ev_record()]):
            lines.append(json.dumps(record, sort_keys=True))
        body = "\n".join(lines) + "\n"
    path = os.path.join(h._out, "ev-%d.jsonl" % seq)
    with open(path, "w", newline="\n") as handle:
        handle.write(body)
    return path


def ingest_history():
    d = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    t = [T0]
    h = IncidentHistory(os.path.join(d, "diagnostics"), "ing-run",
                        clock=lambda: t[0], journal_exchange_dir=out)
    h._tmpdir = d
    h._out = out
    h._t = t
    h.open()
    return h


def journal_dump(h):
    conn = h._conn
    runs = conn.execute(
        "SELECT seq, run, source_epoch, boundary, lines, eligible,"
        " info_dropped, nomatch_dropped, priority_unusable, pfail,"
        " limited, first_ts, last_ts, record_count, event_count"
        " FROM journal_runs ORDER BY seq").fetchall()
    events = conn.execute(
        "SELECT seq, ts, cls, proto, port, dcls, fp, n FROM journal_events"
        " ORDER BY seq, ts, cls").fetchall()
    state = conn.execute(
        "SELECT terminal_seq, last_consumed_seq, gaps_total,"
        " rejected_total FROM journal_ingest_state WHERE id = 1").fetchone()
    audit = conn.execute(
        "SELECT kind, seq, code FROM journal_ingest_audit"
        " ORDER BY seq").fetchall()
    return runs, events, state, audit


# Exact v1 DDL as shipped by Monitor 0.2.0 (schema_version "1"): the
# migration fixture, kept verbatim -- the WHOLE POINT is that the old
# shape is what production currently carries on disk.
V1_DDL = """
CREATE TABLE meta ( key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta (key, value) VALUES ('schema_version','1'),
 ('created_at','2026-01-01T00:00:00+00:00'),('created_by_version','0.2.0');
CREATE TABLE timeline_samples ( epoch REAL NOT NULL, iso_utc TEXT NOT NULL,
 run_id TEXT NOT NULL, monitor_uptime_seconds REAL, snapshot_version INTEGER,
 snapshot_generated_at TEXT, last_success_at TEXT, collector_stale INTEGER NOT
 NULL, api_status TEXT, total_active_connections INTEGER NOT NULL,
 reality_active_connections INTEGER NOT NULL,
 hysteria2_active_connections INTEGER NOT NULL,
 other_active_connections INTEGER NOT NULL, uplink_rate REAL NOT NULL,
 downlink_rate REAL NOT NULL, skipped_events INTEGER NOT NULL,
 duplicate_events INTEGER NOT NULL, identity_conflicts INTEGER NOT NULL,
 abandoned_on_reset INTEGER NOT NULL);
CREATE INDEX idx_samples_epoch ON timeline_samples(epoch);
CREATE TABLE device_protocol_states ( epoch REAL NOT NULL,
 iso_utc TEXT NOT NULL, run_id TEXT NOT NULL, device TEXT NOT NULL,
 inbound TEXT NOT NULL, active_connections INTEGER NOT NULL,
 device_status TEXT, uplink_rate REAL NOT NULL, downlink_rate REAL NOT NULL,
 uplink_total REAL NOT NULL, downlink_total REAL NOT NULL, reason TEXT NOT
 NULL CHECK (reason IN ('change','heartbeat')));
CREATE INDEX idx_states_epoch ON device_protocol_states(epoch);
CREATE INDEX idx_states_device ON device_protocol_states(device, inbound,
 epoch);
"""


def make_v1_db(seed_epoch):
    """A real 0.2.0 v1 database with one sample row + one device row."""
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "diagnostics"))
    conn = sqlite3.connect(os.path.join(d, "diagnostics", "history.sqlite3"))
    conn.executescript(V1_DDL)
    conn.execute(
        "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
        " collector_stale, total_active_connections,"
        " reality_active_connections, hysteria2_active_connections,"
        " other_active_connections, uplink_rate, downlink_rate,"
        " skipped_events, duplicate_events, identity_conflicts,"
        " abandoned_on_reset) VALUES (?, 'x', 'v1-run', 0, 3, 2, 1, 0,"
        " 1.5, 2.5, 0, 0, 0, 0)", (seed_epoch,))
    conn.execute(
        "INSERT INTO device_protocol_states (epoch, iso_utc, run_id, device,"
        " inbound, active_connections, device_status, uplink_rate,"
        " downlink_rate, uplink_total, downlink_total, reason)"
        " VALUES (?, 'x', 'v1-run', 'dev-a', 'vless-in', 2, 'ACTIVE',"
        " 1.0, 2.0, 3.0, 4.0, 'change')", (seed_epoch,))
    conn.commit()
    conn.close()
    return d


def v1_dump(d):
    conn = sqlite3.connect(os.path.join(d, "diagnostics", "history.sqlite3"))
    rows = (conn.execute("SELECT * FROM timeline_samples ORDER BY epoch"
                         ).fetchall(),
            conn.execute("SELECT * FROM device_protocol_states ORDER BY epoch"
                         ).fetchall())
    conn.close()
    return rows


def db_bytes(d):
    with open(os.path.join(d, "diagnostics", "history.sqlite3"), "rb") as f:
        return f.read()


# ---------------------------------------------------------------- groups ----
def group_storage():
    out = {}
    h = tmp_history()
    h.open()
    h.on_publish(snap(), 1)
    tables = {r[0] for r in h._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    out["schema_created"] = {"meta", "timeline_samples",
                             "device_protocol_states",
                             "journal_runs", "journal_events",
                             "journal_ingest_audit",
                             "journal_ingest_state"}.issubset(tables)
    meta = dict(h._conn.execute("SELECT key, value FROM meta"))
    out["meta_schema_version_2"] = meta.get("schema_version") == "2"
    out["meta_creation_only"] = set(meta) == {"schema_version", "created_at",
                                              "created_by_version"}
    jm = h._conn.execute("PRAGMA journal_mode").fetchone()[0]
    out["journal_mode_delete"] = str(jm).lower() == "delete"
    out["synchronous_full"] = h._conn.execute(
        "PRAGMA synchronous").fetchone()[0] in (2, 3)
    out["foreign_keys_on"] = h._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    diag = os.path.join(h._tmpdir, "diagnostics")
    if os.name == "posix":
        out["dir_mode_0700"] = stat.S_IMODE(os.stat(diag).st_mode) == 0o700
        out["db_mode_0600"] = stat.S_IMODE(
            os.stat(os.path.join(diag, "history.sqlite3")).st_mode) == 0o600
    else:
        out["dir_mode_0700"] = True
        out["db_mode_0600"] = True
    out["no_wal_shm_files"] = set(os.listdir(diag)) == {"history.sqlite3"}
    # reopen: data persists, prior run_id stays readable
    h.close()
    h2 = IncidentHistory(diag, "run-b", clock=lambda: T0 + 60.0)
    h2.open()
    samples, _states = rows_of(h2)
    out["reopen_persistence"] = (len(samples) == 1
                                 and samples[0]["run_id"] == RUN)
    h2.close()
    # a pre-existing WRONG-MODE dir is tightened, never refused-open
    d3 = tempfile.mkdtemp()
    p3 = os.path.join(d3, "diagnostics")
    os.makedirs(p3)
    if os.name == "posix":
        os.chmod(p3, 0o755)
    h3 = IncidentHistory(p3, "run-c", clock=lambda: T0)
    h3.open()
    out["dir_mode_tightened"] = (os.name != "posix"
                                 or stat.S_IMODE(os.stat(p3).st_mode) == 0o700)
    h3.close()
    # refusal: regular file where the directory must be
    d4 = tempfile.mkdtemp()
    with open(os.path.join(d4, "diagnostics"), "w") as handle:
        handle.write("x")
    h4 = IncidentHistory(os.path.join(d4, "diagnostics"), "run-d")
    h4.open()
    out["file_as_dir_refused"] = (h4.health()["degraded"]
                                  and h4.health()["last_error_code"] == CODE_DIR_UNSAFE
                                  and not h4.health()["enabled"])
    # refusal: symlinked diagnostics dir -- and NOTHING written through it
    if SYMLINK:
        d5 = tempfile.mkdtemp()
        victim = os.path.join(d5, "victim")
        os.makedirs(victim)
        with open(os.path.join(victim, "keep.txt"), "w") as handle:
            handle.write("keep")
        os.symlink(victim, os.path.join(d5, "diagnostics"))
        h5 = IncidentHistory(os.path.join(d5, "diagnostics"), "run-e")
        h5.open()
        out["symlink_dir_refused"] = h5.health()["last_error_code"] == CODE_DIR_UNSAFE
        out["symlink_dir_no_write"] = set(os.listdir(victim)) == {"keep.txt"}
    else:
        out["symlink_dir_refused"] = True
        out["symlink_dir_no_write"] = True
    # refusal: symlinked db file -- the victim is never opened or rewritten
    d6 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d6, "diagnostics"))
    victim6 = os.path.join(d6, "victim.txt")
    with open(victim6, "w") as handle:
        handle.write("do-not-touch")
    if SYMLINK:
        os.symlink(victim6, os.path.join(d6, "diagnostics", "history.sqlite3"))
        h6 = IncidentHistory(os.path.join(d6, "diagnostics"), "run-f")
        h6.open()
        out["symlink_db_refused"] = h6.health()["last_error_code"] == CODE_DB_UNSAFE
        with open(victim6) as handle:
            out["symlink_db_target_intact"] = handle.read() == "do-not-touch"
    else:
        out["symlink_db_refused"] = True
        out["symlink_db_target_intact"] = True
    # refusal: directory where the regular db file must be
    d7 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d7, "diagnostics", "history.sqlite3"))
    h7 = IncidentHistory(os.path.join(d7, "diagnostics"), "run-g")
    h7.open()
    out["nonregular_db_refused"] = h7.health()["last_error_code"] == CODE_DB_UNSAFE
    # a NEWER on-disk schema is never downgraded in place
    h8 = tmp_history()
    h8.open()
    h8.close()
    conn = sqlite3.connect(os.path.join(h8._tmpdir, "diagnostics",
                                        "history.sqlite3"))
    conn.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    h9 = IncidentHistory(os.path.join(h8._tmpdir, "diagnostics"), "run-h")
    h9.open()
    out["no_downgrade"] = h9.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
    # ---- B3 (review), P2B-revISED: the gate is STRICT in BOTH
    # directions around schema v2 ---- every non-exact-v2 DECLARATION
    # except the exact-v1 migration source is refused fail-closed, and
    # the refusal must not touch a single byte of the existing DB.
    b = tmp_history()
    b.open()
    b.on_publish(snap(), 1)
    b.close()
    db = os.path.join(b._tmpdir, "diagnostics", "history.sqlite3")
    refused_all = intact_all = preserved = True
    for raw in ("0", "-1", "3", "abc", "1.0", ""):
        conn = sqlite3.connect(db)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (raw,))
        conn.commit()
        conn.close()
        before = raw_db_bytes(b)
        hx = IncidentHistory(os.path.join(b._tmpdir, "diagnostics"), "b3")
        hx.open()
        hb = hx.health()
        hx.close()
        refused_all = (refused_all and not hb["enabled"]
                       and hb["last_error_code"] == CODE_SCHEMA_UNSUPPORTED)
        intact_all = intact_all and raw_db_bytes(b) == before
        conn = sqlite3.connect(db)
        v = conn.execute("SELECT value FROM meta WHERE key='schema_version'"
                         ).fetchone()[0]
        conn.close()
        preserved = preserved and v == raw
    out["b3_noncurrent_all_refused"] = refused_all
    out["b3_refusal_zero_bytes"] = intact_all and preserved
    # a v1 CLAIM on a full v2 database is a hybrid: refused, never
    # "down-migrated" and never a silent accept (journal tables under
    # version 1 is not a shape the migration recognizes)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    before = raw_db_bytes(b)
    bh = IncidentHistory(os.path.join(b._tmpdir, "diagnostics"), "b3h")
    bh.open()
    out["b3_hybrid_v1_claim_refused"] = (
        not bh.health()["enabled"]
        and bh.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and raw_db_bytes(b) == before)
    bh.close()
    # restore the exact-v2 shape, THEN prove an accepted re-open is pure
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    # an ACCEPTED exact-v2 re-open also mutates zero bytes (read-only gate)
    b2 = IncidentHistory(os.path.join(b._tmpdir, "diagnostics"), "b3ok",
                         clock=lambda: T0 + 60.0)
    before = raw_db_bytes(b)
    b2.open()
    out["b3_exact_v2_reopen_readonly"] = (b2.health()["enabled"]
                                          and raw_db_bytes(b) == before)
    b2.close()
    # meta CLAIMS v2 but the tables are gone: refuse, never adopt via
    # CREATE-IF-NOT-EXISTS (and the shape must stay exactly as found)
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE timeline_samples")
    conn.execute("DROP TABLE device_protocol_states")
    conn.execute("DROP TABLE journal_runs")
    conn.execute("DROP TABLE journal_events")
    conn.execute("DROP TABLE journal_ingest_audit")
    conn.execute("DROP TABLE journal_ingest_state")
    conn.commit()
    conn.close()
    before = raw_db_bytes(b)
    b3 = IncidentHistory(os.path.join(b._tmpdir, "diagnostics"), "b3x")
    b3.open()
    out["b3_metaless_orphan_refused"] = (
        not b3.health()["enabled"]
        and b3.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and raw_db_bytes(b) == before)
    b3.close()
    # an unrelated tables-only DB (no meta) is never claimed as v1
    d10 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d10, "diagnostics"))
    conn = sqlite3.connect(os.path.join(d10, "diagnostics",
                                        "history.sqlite3"))
    conn.execute("CREATE TABLE foo (x INTEGER)")
    conn.commit()
    conn.close()
    b4 = IncidentHistory(os.path.join(d10, "diagnostics"), "b4")
    b4.open()
    out["b3_unrelated_db_refused"] = (
        not b4.health()["enabled"]
        and b4.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED)
    b4.close()
    # zero tables but NON-empty pre-existing file: never claimed fresh
    d11 = tempfile.mkdtemp()
    with open(os.path.join(d11, "history.sqlite3"), "wb") as handle:
        handle.write(b"SQLite format 3\x00" + b"\x00" * 4096)
    b5 = IncidentHistory(d11, "b5")
    b5.open()
    out["b3_zero_tables_claim_refused"] = not b5.health()["enabled"]
    b5.close()
    # a real garbage file fails softly (sanitized code, no raise, bytes kept)
    d12 = tempfile.mkdtemp()
    with open(os.path.join(d12, "history.sqlite3"), "wb") as handle:
        handle.write(b"definitely not sqlite" * 300)
    b6 = IncidentHistory(d12, "b6")
    b6.open()
    out["b3_garbage_soft"] = (not b6.health()["enabled"]
                              and b6.health()["last_error_code"]
                              in (CODE_SCHEMA_UNSUPPORTED, CODE_OPEN_FAILED))
    b6.close()
    # a zero-byte pre-existing file IS genuinely fresh: must be claimed v1
    d13 = tempfile.mkdtemp()
    open(os.path.join(d13, "history.sqlite3"), "wb").close()
    b7 = IncidentHistory(d13, "b7")
    b7.open()
    out["b3_zero_byte_claimed"] = b7.health()["enabled"]
    b7.close()
    return out


def group_privacy():
    out = {}
    h = tmp_history()
    h.open()
    for v in range(1, 5):
        h._clock = (lambda v=v: T0 + v * 5.0)
        h.on_publish(snap(), v)
    samples, states = rows_of(h)
    blob = json.dumps([samples, states, h.health()])
    out["no_sentinel_in_reads"] = not any(s in blob for s in SENTINELS)
    raw = raw_db_bytes(h)
    out["no_sentinel_in_db_bytes"] = not any(s.encode() in raw for s in SENTINELS)
    out["sample_keys_exact"] = (len(samples) == 4
                                and all(set(r) == set(SAMPLE_COLUMNS)
                                        for r in samples))
    out["state_keys_exact"] = (len(states) == 2
                                and all(set(r) == set(DEVICE_STATE_COLUMNS)
                                        for r in states))
    out["no_id_source_dest_any_row"] = not any(
        k in row for row in list(samples) + list(states)
        for k in ("id", "source", "destination", "recent_sources",
                  "closed_ids", "connections", "last_error"))
    # device names / inbound tags are OPERATIONAL metadata: kept on purpose
    out["device_protocol_kept"] = any(
        r["device"] == "vmix-01" and r["inbound"] == "vless-in" for r in states)
    # protocol classification (spec §3): reviewed tag map, inbound_type
    # fallback, unknown -> OTHER (counted, never guessed, never dropped)
    out["cls_tag_reality"] = classify_protocol("vless-in") == "Reality"
    out["cls_tag_hy2"] = classify_protocol("hy2-in") == "Hysteria2"
    out["cls_type_reality"] = classify_protocol("other-in", "reality") == "Reality"
    out["cls_type_vless"] = classify_protocol("other-in", "vless") == "Reality"
    out["cls_type_hy2"] = classify_protocol("other-in", "hysteria2") == "Hysteria2"
    out["cls_unknown"] = classify_protocol("other-in", "trojan") == "OTHER"
    out["cls_tag_wins"] = classify_protocol("hy2-in", "vless") == "Hysteria2"
    last = samples[-1]
    out["aggregate_counts"] = (last["reality_active_connections"] == 2
                               and last["hysteria2_active_connections"] == 1
                               and last["other_active_connections"] == 0
                               and last["total_active_connections"] == 3)
    # an unknown protocol tag is counted as OTHER, not silently dropped
    h2 = tmp_history()
    h2.open()
    extra = {"dev-x": {
        "name": "dev-x", "status": "ACTIVE",
        "protocols": {"tun-in": {"device_name": "dev-x", "inbound": "tun-in",
                                 "active_connections": 4, "uplink_rate": 0.0,
                                 "downlink_rate": 0.0, "uplink_total": 0.0,
                                 "downlink_total": 0.0}},
        "active_connections": 4, "uplink_rate": 0.0, "downlink_rate": 0.0,
        "uplink_total": 0.0, "downlink_total": 0.0, "recent_sources": [],
        "last_activity": None, "recent_connections": [], "closed_ids": []}}
    h2._clock = lambda: T0 + 5.0
    h2.on_publish(snap(extra=extra), 1)
    s2, _ = rows_of(h2)
    out["other_counted"] = s2[0]["other_active_connections"] == 4
    return out


def group_cadence():
    out = {}
    t = [T0]
    h = tmp_history(clock=lambda: t[0])
    h.open()
    h.on_publish(snap(), 1)
    s, st = rows_of(h)
    out["first_publish_samples_and_states"] = len(s) == 1 and len(st) == 2
    # sub-interval, rate-only publishes: NO extra sample AND no device rows
    for i in range(2, 10):
        t[0] = T0 + i * 0.5
        h.on_publish(snap(rate=float(i)), i)
    s, st = rows_of(h)
    out["sub_interval_no_extra_sample"] = len(s) == 1
    out["rate_only_no_state_row"] = len(st) == 2
    # 5s aggregate boundary
    t[0] = T0 + 5.0
    h.on_publish(snap(), 10)
    s, _ = rows_of(h)
    out["sample_at_5s"] = len(s) == 2
    # dense publishing across 10s: exactly the 10s and 15s boundaries land
    for i in range(20):
        t[0] = T0 + 5.0 + i * 0.5
        h.on_publish(snap(), 20 + i)
    s, _ = rows_of(h)
    out["no_excessive_sampling"] = len(s) == 3
    # device row IMMEDIATELY on active-count change (mid-window)
    t[0] = T0 + 15.2
    h.on_publish(snap(active_vless=3), 99)
    _, st = rows_of(h)
    out["row_on_active_change"] = any(
        r["reason"] == "change" and r["active_connections"] == 3 for r in st)
    # device row IMMEDIATELY on status change (active count unchanged)
    t[0] = T0 + 15.4
    h.on_publish(snap(active_vless=3, status="RECENT ACTIVITY"), 100)
    _, st = rows_of(h)
    out["row_on_status_change"] = any(
        r["device_status"] == "RECENT ACTIVITY" for r in st)
    # heartbeat: strictly >60s since the last write for that (device,inbound)
    base_rows = len(rows_of(h)[1])
    t[0] = T0 + 15.4 + 59.0
    h.on_publish(snap(active_vless=3, status="RECENT ACTIVITY", rate=7.0), 101)
    mid_rows = len(rows_of(h)[1])
    out["heartbeat_never_before_60s"] = mid_rows == base_rows
    t[0] = T0 + 15.4 + 61.0
    h.on_publish(snap(active_vless=3, status="RECENT ACTIVITY", rate=7.0), 102)
    after, _states = rows_of(h)
    out["heartbeat_after_60s_only"] = len(_states) - mid_rows == 2
    out["heartbeat_reason"] = all(
        r["reason"] == "heartbeat" for r in _states[mid_rows:])
    out["reason_values_closed"] = all(
        r["reason"] in ("change", "heartbeat") for r in _states)
    return out


def group_restart():
    out = {}
    t = [T0]
    d = tempfile.mkdtemp()
    h1 = IncidentHistory(os.path.join(d, "diagnostics"), "run-one",
                         clock=lambda: t[0])
    h1.open()
    for i in (1, 2, 3):
        t[0] = T0 + i * 5.0
        h1.on_publish(snap(), i)
    h1.close()
    # the process is DOWN between T0+15 and T0+900:
    t[0] = T0 + 900.0
    h2 = IncidentHistory(os.path.join(d, "diagnostics"), "run-two",
                         clock=lambda: t[0])
    h2.open()
    h2.on_publish(snap(), 1)
    samples, _ = rows_of(h2)
    out["run_ids_differ_and_persist"] = sorted(
        {s["run_id"] for s in samples}) == ["run-one", "run-two"]
    gap = [s for s in samples if s["run_id"] == "run-two"
           and T0 + 15.0 < s["epoch"] < T0 + 900.0]
    out["no_fabricated_gap_rows"] = gap == []
    r1 = [s["epoch"] for s in samples if s["run_id"] == "run-one"]
    r2 = [s["epoch"] for s in samples if s["run_id"] == "run-two"]
    out["gap_is_real_only"] = (max(r1) <= T0 + 15.0
                               and min(r2) >= T0 + 900.0)
    return out


def group_retention():
    out = {}
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "diagnostics"))
    seed = IncidentHistory(os.path.join(d, "diagnostics"), "seed",
                           clock=lambda: 300.0)
    seed._tmpdir = d
    seed.open()
    for epoch in range(0, 301, 10):
        seed._conn.execute(
            "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
            " collector_stale, total_active_connections,"
            " reality_active_connections, hysteria2_active_connections,"
            " other_active_connections, uplink_rate, downlink_rate,"
            " skipped_events, duplicate_events, identity_conflicts,"
            " abandoned_on_reset) VALUES (?, '', 'seed', 0,0,0,0,0,0,0,0,0,0,0)",
            (float(epoch),))
        seed._conn.execute(
            "INSERT INTO device_protocol_states (epoch, iso_utc, run_id,"
            " device, inbound, active_connections, device_status,"
            " uplink_rate, downlink_rate, uplink_total, downlink_total,"
            " reason) VALUES (?, '', 'seed', 'd', 'i', 0, 'ACTIVE',"
            " 0, 0, 0, 0, 'heartbeat')", (float(epoch),))
    seed._conn.commit()
    seed.close()
    # REOPEN with a 100s horizon at t=350: startup cleanup prunes epoch<250
    h = IncidentHistory(os.path.join(d, "diagnostics"), "reopen",
                        clock=lambda: 350.0, retention_seconds=100.0)
    h._tmpdir = d
    h.open()
    samples, states = rows_of(h)
    out["time_prune_oldest_gone"] = all(
        r["epoch"] >= 250.0 for r in samples + states) and len(samples) > 0
    out["time_prune_newest_kept"] = max(r["epoch"] for r in samples) == 300.0
    out["time_prune_actually_pruned"] = len(samples) < 31
    h.close()
    # cleanup cadence: once at startup, then bounded by cleanup_interval
    calls = []

    class Counting(IncidentHistory):
        def _cleanup(self, phase):
            calls.append(phase)
            return IncidentHistory._cleanup(self, phase)
    t = [T0]
    h2 = Counting(os.path.join(tempfile.mkdtemp(), "diagnostics"), "cad",
                  clock=lambda: t[0], cleanup_interval=10.0)
    h2.open()
    startup = len(calls)
    h2.on_publish(snap(), 1)              # writes nothing -> no cleanup
    no_write = len(calls)
    for i in range(1, 4):                 # samples at t=5,10,15
        t[0] = T0 + i * 5.0
        h2.on_publish(snap(), i)
    at_15 = len(calls)
    t[0] = T0 + 20.0
    h2.on_publish(snap(), 9)
    at_20 = len(calls)
    before_cleanup_rows = len(rows_of(h2)[0])
    h2._cleanup("manual-below-ceiling")   # size far below ceiling: keep all
    out["cleanup_at_startup"] = startup == 1
    out["no_write_no_cleanup"] = no_write == startup
    out["cleanup_bounded_hourly"] = (at_15 - startup) == 1 \
        and (at_20 - at_15) == 1
    out["below_ceiling_no_prune"] = len(rows_of(h2)[0]) == before_cleanup_rows
    # size pruning: fires ONLY over the ceiling, deletes oldest-first down to
    # the target; the newest rows always survive
    h3 = tmp_history(retention_seconds=10_000_000.0)
    h3.open()
    # Fresh-but-ordered epochs: 1970-style seeds would be TIME-pruned by the
    # startup/horizon DELETE before the SIZE path under test ever runs.
    for k in range(4000):
        h3._conn.execute(
            "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
            " collector_stale, total_active_connections,"
            " reality_active_connections, hysteria2_active_connections,"
            " other_active_connections, uplink_rate, downlink_rate,"
            " skipped_events, duplicate_events, identity_conflicts,"
            " abandoned_on_reset, snapshot_generated_at)"
            " VALUES (?, '', 'size', 0,0,0,0,0,0,0,0,0,0,0,?)",
            (T0 - 4000 + k, "x" * 16))
    h3._conn.commit()
    before = h3._db_bytes()
    h3._ceiling_bytes = before - 1        # force exactly the ceiling path
    h3._target_bytes = before // 2
    epochs_before = [r[0] for r in h3._conn.execute(
        "SELECT epoch FROM timeline_samples ORDER BY epoch")]
    h3._cleanup("size-test")
    epochs_after = [r[0] for r in h3._conn.execute(
        "SELECT epoch FROM timeline_samples ORDER BY epoch")]
    out["size_prune_keeps_newest_suffix"] = bool(epochs_after) and epochs_after == \
        epochs_before[len(epochs_before) - len(epochs_after):]
    out["size_prune_below_target"] = h3._db_bytes() <= h3._target_bytes
    out["size_prune_max_survives"] = max(epochs_after) == max(epochs_before)
    # B2 (review): the two tables are ONE globally epoch-ordered timeline.
    # Interleaved seeds discriminate the old per-table scheme, which could
    # delete a NEWER sample while an OLDER device row survived (and vice
    # versa) -- survivors must be the newest suffix of the MERGED order.
    h4 = tmp_history(retention_seconds=10_000_000.0)
    h4.open()
    base4 = T0 - 100000
    for k in range(1200):
        h4._conn.execute(
            "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
            " collector_stale, total_active_connections,"
            " reality_active_connections, hysteria2_active_connections,"
            " other_active_connections, uplink_rate, downlink_rate,"
            " skipped_events, duplicate_events, identity_conflicts,"
            " abandoned_on_reset, snapshot_generated_at)"
            " VALUES (?, '', ?, 0,0,0,0,0,0,0,0,0,0,0,?)",
            (base4 + 2 * k, "z" * 48, "y" * 16))
        h4._conn.execute(
            "INSERT INTO device_protocol_states (epoch, iso_utc, run_id,"
            " device, inbound, active_connections, device_status,"
            " uplink_rate, downlink_rate, uplink_total, downlink_total,"
            " reason) VALUES (?, '', ?, 'd', 'i', 0, 'ACTIVE',"
            " 0, 0, 0, 0, 'heartbeat')", (base4 + 2 * k + 1, "z" * 48))
    h4._conn.commit()
    before4 = h4._db_bytes()
    h4._ceiling_bytes = before4 - 1
    h4._target_bytes = before4 // 2
    merged_before = [r[0] for r in h4._conn.execute(
        "SELECT epoch FROM timeline_samples"
        " UNION ALL SELECT epoch FROM device_protocol_states"
        " ORDER BY epoch")]
    h4._cleanup("b2-mixed")
    s4 = [r[0] for r in h4._conn.execute(
        "SELECT epoch FROM timeline_samples ORDER BY epoch")]
    st4 = [r[0] for r in h4._conn.execute(
        "SELECT epoch FROM device_protocol_states ORDER BY epoch")]
    merged_after = sorted(s4 + st4)
    n4 = len(merged_after)
    out["b2_mixed_global_suffix"] = bool(merged_after) and \
        merged_after == merged_before[len(merged_before) - n4:]
    out["b2_mixed_both_pruned"] = (0 < len(s4) < 1200
                                   and 0 < len(st4) < 1200)
    out["b2_mixed_newest_survives"] = merged_before[-1] in merged_after
    out["b2_mixed_below_target"] = h4._db_bytes() <= h4._target_bytes
    h4.close()
    # a retention failure records its code and never raises
    h3._conn.close()
    h3._cleanup("after-close")
    out["retention_failure_code"] = h3.health()["last_error_code"] == CODE_RETENTION_FAILED
    return out


def group_failure():
    out = {}
    t = [T0]
    h = tmp_history(clock=lambda: t[0])
    h.open()
    h.on_publish(snap(), 1)
    good_success_ts = h.health()["last_success_at"]
    # break the schema under it: the NEXT write fails -- softly
    h._conn.execute("DROP TABLE timeline_samples")
    h._conn.commit()
    t[0] = T0 + 10.0
    raised = False
    try:
        h.on_publish(snap(), 2)
    except Exception:  # noqa: BLE001
        raised = True
    out["write_failure_never_raises"] = not raised
    out["write_failure_degrades"] = (h.health()["degraded"]
                                     and h.health()["last_error_code"] == CODE_WRITE_FAILED
                                     and h.health()["failure_count"] >= 1
                                     and h.health()["enabled"])
    out["last_success_time_kept"] = h.health()["last_success_at"] == good_success_ts
    # reads against the broken DB: empty + sanitized code, never a raise
    r = h.query_timeline()
    out["read_failure_empty"] = r["samples"] == [] and r["truncated"] is False
    # under the STRICT schema gate (review B3) a live DB whose tables were
    # stripped is NOT silently re-adopted on reopen: open() fails closed
    # WITHOUT mutating the corrupt file, and recovery happens only when
    # the operator removes it (fresh v1 re-created).
    h.close()
    db = os.path.join(h._tmpdir, "diagnostics", "history.sqlite3")
    corrupt_bytes = raw_db_bytes(h)
    h.open()
    out["stripped_table_reopen_refused"] = (
        not h.health()["enabled"]
        and h.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED)
    out["stripped_refusal_zero_bytes"] = (
        raw_db_bytes(h) == corrupt_bytes)
    os.remove(db)
    h.open()
    t[0] = T0 + 20.0
    h.on_publish(snap(), 3)
    out["recovers_after_reopen"] = (not h.health()["degraded"]
                                    and h.health()["last_error_code"] is None)
    # shutdown race (closed connection under on_publish): still soft
    h._conn.close()
    try:
        t[0] = T0 + 30.0
        h.on_publish(snap(), 4)
        out["closed_db_soft"] = True
    except Exception:  # noqa: BLE001
        out["closed_db_soft"] = False
    # open() itself never raises on hostile storage
    d = tempfile.mkdtemp()
    open(os.path.join(d, "diagnostics"), "w").close()
    try:
        IncidentHistory(os.path.join(d, "diagnostics"), "x").open()
        out["open_never_raises"] = True
    except Exception:  # noqa: BLE001
        out["open_never_raises"] = False

    # broker survival: an EXPLODING writer cannot kill the publisher thread
    class FakeTracker:
        def apply_batch(self, batch, now):
            return None

        def snapshot(self, now):
            return snap()

    class FakeCollector:
        def __init__(self):
            self.tracker = FakeTracker()

        def consume(self, duration=None):
            time.sleep(0.02)

        def snapshot(self):
            return snap()

    class Boom:
        def on_publish(self, snapshot, version):
            raise RuntimeError("SENTINEL-BOOM-from-history")

    broker = SnapshotBroker(FakeCollector(), poll_seconds=0.02,
                            incident_history=Boom())
    broker.start()
    got = broker.wait_for_snapshot(timeout=5.0)
    time.sleep(0.3)
    version_seen = broker._version
    time.sleep(0.3)
    kept = (broker._version > version_seen and broker.running())
    broker.stop()
    out["broker_survives_history_explosion"] = got and kept
    # the hook really fires, on DECORATED snapshots, with monotonic versions
    class Counting:
        def __init__(self):
            self.calls = []

        def on_publish(self, snapshot, version):
            self.calls.append((snapshot.get("api_status"), version))

    counter = Counting()
    broker2 = SnapshotBroker(FakeCollector(), poll_seconds=0.02,
                             incident_history=counter)
    broker2.start()
    broker2.wait_for_snapshot(timeout=5.0)
    time.sleep(0.25)
    broker2.stop()
    out["hook_receives_decorated_versioned"] = (
        len(counter.calls) >= 2
        and all(status == "CONNECTED" for status, _ in counter.calls)
        and [v for _, v in counter.calls]
        == sorted(set(v for _, v in counter.calls)))
    # standalone default: no history wired == behavior unchanged
    broker3 = SnapshotBroker(FakeCollector(), poll_seconds=0.02)
    broker3.start()
    ok3 = broker3.wait_for_snapshot(timeout=5.0)
    broker3.stop()
    out["standalone_broker_no_history"] = ok3 \
        and broker3._incident_history is None
    return out


def group_http():
    out = {}
    d = tempfile.mkdtemp()
    t = [T0]
    access = AccessPolicy(d)
    auth = AuthStore(d, session_ttl=3600.0)
    auth.set_password(PASSWORD)

    class FakeBroker:
        def snapshot(self):
            return snap()

        def snapshot_json(self):
            return 1, json.dumps(snap())

        def running(self):
            return True

        def wait_for_snapshot(self, timeout=10.0):
            return True

        def subscribe(self, after_version=0):
            return iter(())

    history = IncidentHistory(os.path.join(d, "diagnostics"), "http-run",
                              clock=lambda: t[0])
    history.open()
    history.on_publish(snap(), 1)
    t[0] = T0 + 10.0
    history.on_publish(snap(active_vless=5), 2)
    app = MonitorWebApp(broker=FakeBroker(), access=access, static_dir=None,
                        auth=auth, incident_history=history)
    server = build_server(app, "127.0.0.1", 0, None)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def request(method, path, cookie=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        payload = response.read().decode("utf-8")
        cookies = response.getheader("Set-Cookie") or ""
        conn.close()
        return response.status, payload, cookies

    status, _, _ = request("GET", "/api/v1/diagnostics/timeline")
    out["requires_session_401"] = status == 401
    status, _, cookies = request("POST", "/api/v1/login",
                                 body={"password": PASSWORD})
    session = cookies.split(";")[0] if status == 200 else ""
    out["login_ok"] = status == 200 and bool(session)
    status, body, _ = request("GET", "/api/v1/diagnostics/timeline",
                              cookie=session)
    data = json.loads(body)
    out["timeline_200"] = status == 200
    out["top_level_keys"] = set(data) == {"history", "samples",
                                          "device_states", "truncated",
                                          "limit"}
    out["history_health"] = set(data["history"]) == {"enabled", "degraded",
                                                     "last_success_at",
                                                     "failure_count",
                                                     "last_error_code",
                                                     "run_id"}
    out["run_id_exposed"] = data["history"]["run_id"] == "http-run"
    out["rows_present"] = len(data["samples"]) == 2 and \
        len(data["device_states"]) >= 3
    out["columns_whitelisted"] = all(set(r) == set(SAMPLE_COLUMNS)
                                     for r in data["samples"])
    out["no_forbidden_key"] = not any(
        k in r for r in data["samples"] + data["device_states"]
        for k in ("id", "source", "destination", "password", "secret"))
    out["no_sentinel_in_body"] = not any(s in body for s in SENTINELS)
    status, _, _ = request("POST", "/api/v1/diagnostics/timeline",
                           cookie=session, body={})
    out["post_405"] = status == 405
    out["bad_param_400"] = True
    for bad in ("?since=abc", "?since=-1", "?since=nan", "?since=inf",
                "?limit=0", "?limit=-3", "?limit=1.5", "?limit=two"):
        status, _, _ = request("GET", "/api/v1/diagnostics/timeline" + bad,
                               cookie=session)
        if status != 400:
            out["bad_param_400"] = False
            break
    status, body, _ = request("GET", "/api/v1/diagnostics/timeline?limit=99999",
                              cookie=session)
    out["limit_hard_capped"] = json.loads(body)["limit"] == QUERY_LIMIT_MAX
    status, body, _ = request("GET", "/api/v1/diagnostics/timeline?since=%d"
                              % (T0 + 5.0), cookie=session)
    out["since_filters"] = [r["epoch"] for r in
                            json.loads(body)["samples"]] == [T0 + 10.0]
    status, body, _ = request("GET", "/api/v1/diagnostics/timeline?limit=1",
                              cookie=session)
    data = json.loads(body)
    out["truncated_flag"] = data["truncated"] is True and \
        len(data["samples"]) == 1
    status, _, _ = request("GET", "/api/v1/diagnostics/timeline/../snapshot")
    out["path_traversal_not_history"] = status in (401, 404)
    server.shutdown()
    history.close()
    # a runtime WITHOUT history answers a sanitized 503 (no traceback)
    app2 = MonitorWebApp(broker=FakeBroker(), access=access, static_dir=None,
                         auth=auth)
    server2 = build_server(app2, "127.0.0.1", 0, None)
    port2 = server2.server_address[1]
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    conn = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
    conn.request("POST", "/api/v1/login", json.dumps({"password": PASSWORD}),
                 {"Content-Type": "application/json"})
    response = conn.getresponse()
    session2 = (response.getheader("Set-Cookie") or "").split(";")[0]
    response.read()
    conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
    conn.request("GET", "/api/v1/diagnostics/timeline",
                 headers={"Cookie": session2})
    response = conn.getresponse()
    status = response.status
    body = response.read().decode("utf-8")
    conn.close()
    out["no_history_503"] = status == 503 and "incident" in body \
        and "Traceback" not in body
    server2.shutdown()
    return out


def group_concurrency():
    """B1 (review): ONE reentrant lock must serialize the publisher-side
    writer, every HTTP reader thread and shutdown close(). This is a REAL
    threaded SQLite stress: a 300-publish writer (every call writes: the
    clock jumps past the 5s cadence each time) races four tight-loop
    readers, while close() lands mid-flight. Without the shared lock the
    writer/reader threads raise on the torn or closed shared connection;
    with it, zero thread exceptions and zero recorded failures.

    Harness rule: the writer never calls the lock-held private _cleanup()
    primitive itself -- that unlocked call raced the readers on the shared
    sqlite3 connection and segfaulted nondeterministically. Cleanup runs
    only via the formal locked on_publish() path: cleanup_interval=30
    plus the 6s/publish clock advance fires the production
    _on_publish_locked -> _cleanup("periodic") branch every 5th publish
    mid-contention, and retention_seconds=300 makes each pass do REAL
    DELETE work. The counting wrapper below is observation-only evidence
    cleanup ran."""
    out = {}
    t = [T0]
    h = tmp_history(clock=lambda: t[0], heartbeat_interval=1e9,
                    cleanup_interval=30.0, retention_seconds=300.0)
    cleanup_calls = {}
    counter_lock = threading.Lock()
    real_cleanup = h._cleanup

    def counting_cleanup(phase):
        with counter_lock:
            cleanup_calls[phase] = cleanup_calls.get(phase, 0) + 1
        return real_cleanup(phase)

    h._cleanup = counting_cleanup
    h.open()
    errors = []
    stop = threading.Event()

    def writer():
        n = 0
        try:
            while not stop.is_set() and n < 300:
                n += 1
                t[0] = T0 + n * 6.0
                h.on_publish(snap(active_vless=n % 4), n)
        except BaseException as exc:
            errors.append("writer:%r" % exc)

    def reader(i):
        try:
            while not stop.is_set():
                r = h.query_timeline(limit=50)
                if not isinstance(r["samples"], list):
                    errors.append("reader%d:shape" % i)
                    return
                h.health()
                time.sleep(0.001)
        except BaseException as exc:
            errors.append("reader%d:%r" % (i, exc))

    def closer():
        try:
            time.sleep(0.3)
            h.close()
        except BaseException as exc:
            errors.append("closer:%r" % exc)

    w = threading.Thread(target=writer)
    rs = [threading.Thread(target=lambda i=i: reader(i)) for i in range(4)]
    c = threading.Thread(target=closer)
    w.start()
    for r_ in rs:
        r_.start()
    c.start()
    w.join(timeout=90)
    stop.set()
    for r_ in rs + [c]:
        r_.join(timeout=90)
    out["no_deadlock"] = not any(
        x.is_alive() for x in [w] + rs + [c])
    out["no_thread_errors"] = errors == []
    out["zero_failures_under_contention"] = h.health()["failure_count"] == 0
    r = h.query_timeline(limit=10)
    out["close_midflight_soft"] = (r["samples"] == []
                                   and r["device_states"] == [])
    # rows committed BEFORE the racing close() are durable: reopen and read
    h2 = IncidentHistory(os.path.join(h._tmpdir, "diagnostics"), "conc-2",
                         clock=lambda: t[0] + 6.0)
    h2.open()
    s2, _ = rows_of(h2)
    out["rows_durable_through_close"] = len(s2) >= 10
    out["privacy_under_contention"] = not any(
        s.encode() in raw_db_bytes(h) for s in SENTINELS)
    # explicit evidence the retention path ran during the race (observed,
    # never invoked directly by the writer)
    out["cleanup_ran_under_contention"] = cleanup_calls.get("periodic", 0) >= 3
    out["startup_cleanup_ran_once"] = cleanup_calls.get("startup", 0) == 1
    h2.close()
    return out


V1_TABLE_NAMES = {"meta", "timeline_samples", "device_protocol_states"}
JOURNAL_TABLE_NAMES = {"journal_runs", "journal_events",
                       "journal_ingest_audit", "journal_ingest_state"}


def _db_shape(d):
    conn = sqlite3.connect(os.path.join(d, "diagnostics", "history.sqlite3"))
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        try:
            meta = dict(conn.execute(
                "SELECT key, value FROM meta").fetchall())
        except sqlite3.Error:
            meta = {}
        try:
            state = conn.execute(
                "SELECT terminal_seq, last_consumed_seq, gaps_total,"
                " rejected_total FROM journal_ingest_state"
                " WHERE id = 1").fetchone()
        except sqlite3.Error:
            state = None
    finally:
        conn.close()
    return tables, meta, state


def group_migrate():
    out = {}
    # ---- a REAL 0.2.0 v1 database migrates FORWARD in one transaction
    d1 = make_v1_db(T0 - 60.0)
    rows_before = v1_dump(d1)
    out1 = tempfile.mkdtemp()
    h1 = IncidentHistory(os.path.join(d1, "diagnostics"), "mig-1",
                         clock=lambda: T0, journal_exchange_dir=out1)
    h1._out = out1
    h1.open()
    out["v1_migration_enabled"] = (h1.health()["enabled"]
                                   and not h1.health()["degraded"])
    out["v1_rows_preserved"] = v1_dump(d1) == rows_before \
        and len(rows_before[0]) == 1 and len(rows_before[1]) == 1
    tables, meta, state = _db_shape(d1)
    out["v1_meta_flipped_to_2"] = meta.get("schema_version") == "2"
    out["v1_creation_metadata_kept"] = meta.get(
        "created_by_version") == "0.2.0" and meta.get(
        "created_at") == "2026-01-01T00:00:00+00:00"
    out["v1_full_v2_shape"] = (V1_TABLE_NAMES | JOURNAL_TABLE_NAMES) <= tables \
        and state == (0, None, 0, 0)
    # both write paths work immediately on the migrated database (the v1
    # fixture rows are still there: 1 seeded sample + 1 seeded device row)
    h1.on_publish(snap(), 1)
    s, st = rows_of(h1)
    write_ev(h1, 1, records=[ev_record(ts=123.5)])
    r = h1.ingest_journal_events()
    _runs, events, state2, _audit = journal_dump(h1)
    out["post_migration_publish_ingest"] = (
        len(s) == 2 and len(st) == 3 and r["consumed"] == 1
        and state2 == (1, 1, 0, 0)
        and events == [(1, 123.5, "dns", "OTHER", 0, "NONE", None, 1)])
    h1.close()
    # re-open of the MIGRATED v2 db: adopted, mutates ZERO bytes, and the
    # seeded v1 rows remain the untouched OLDEST prefix
    bytes_migrated = db_bytes(d1)
    h1b = IncidentHistory(os.path.join(d1, "diagnostics"), "mig-1b",
                          clock=lambda: T0, journal_exchange_dir=out1)
    h1b.open()
    after1b = v1_dump(d1)
    out["migrated_reopen_adopts_zero_bytes"] = (
        h1b.health()["enabled"] and not h1b.health()["degraded"]
        and db_bytes(d1) == bytes_migrated
        and after1b[0][:len(rows_before[0])] == rows_before[0]
        and after1b[1][:len(rows_before[1])] == rows_before[1])
    h1b.close()
    # ---- crash MID-MIGRATION: the ONE-transaction migration rolls back to
    # an untouched exact-v1 file; a later open simply re-runs it.
    d2 = make_v1_db(T0 - 60.0)
    before2 = v1_dump(d2)

    def boom(conn, now):
        raise RuntimeError("SENTINEL-mid-migration-death")

    h2 = IncidentHistory(os.path.join(d2, "diagnostics"), "mig-crash",
                         clock=lambda: T0)
    h2._create_journal_state_row = boom
    crashed = False
    try:
        h2.open()
    except RuntimeError:
        crashed = True
    tables2, meta2, _ = _db_shape(d2)
    out["mid_migration_crash_rolls_back_exact_v1"] = (
        crashed and not (tables2 & JOURNAL_TABLE_NAMES)
        and meta2.get("schema_version") == "1" and v1_dump(d2) == before2)
    h2b = IncidentHistory(os.path.join(d2, "diagnostics"), "mig-2",
                          clock=lambda: T0)
    h2b.open()
    tables2b, meta2b, state2b = _db_shape(d2)
    out["post_crash_reopen_migrates_clean"] = (
        h2b.health()["enabled"]
        and (V1_TABLE_NAMES | JOURNAL_TABLE_NAMES) <= tables2b
        and meta2b.get("schema_version") == "2"
        and state2b == (0, None, 0, 0) and v1_dump(d2) == before2)
    h2b.close()
    # ---- a NEWER declared version on a migrated db: refused, zero bytes
    conn3 = sqlite3.connect(os.path.join(d1, "diagnostics",
                                         "history.sqlite3"))
    conn3.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
    conn3.commit()
    conn3.close()
    bytes3 = db_bytes(d1)
    h3 = IncidentHistory(os.path.join(d1, "diagnostics"), "mig-newer",
                         clock=lambda: T0)
    h3.open()
    out["newer_schema_migrated_refused_zero_bytes"] = (
        not h3.health()["enabled"]
        and h3.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and db_bytes(d1) == bytes3)
    # ---- v1 CLAIM with journal tables already present: hybrid, refused
    d4 = make_v1_db(T0 - 60.0)
    conn4 = sqlite3.connect(os.path.join(d4, "diagnostics",
                                         "history.sqlite3"))
    conn4.execute("CREATE TABLE journal_ingest_state (id INTEGER PRIMARY"
                  " KEY, terminal_seq INTEGER, last_consumed_seq INTEGER,"
                  " gaps_total INTEGER, rejected_total INTEGER,"
                  " updated_epoch REAL)")
    conn4.commit()
    conn4.close()
    bytes4 = db_bytes(d4)
    h4 = IncidentHistory(os.path.join(d4, "diagnostics"), "mig-hybrid",
                         clock=lambda: T0)
    h4.open()
    out["hybrid_v1_claim_refused_zero_bytes"] = (
        not h4.health()["enabled"]
        and h4.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and db_bytes(d4) == bytes4)
    # ---- fresh databases are created AT v2 directly (state row included)
    h5 = tmp_history(run_id="mig-fresh")
    h5.open()
    tables5, meta5, state5 = _db_shape(h5._tmpdir)
    out["fresh_db_is_v2_immediately"] = (
        (V1_TABLE_NAMES | JOURNAL_TABLE_NAMES) <= tables5
        and meta5.get("schema_version") == "2"
        and state5 == (0, None, 0, 0)
        and meta5.get("created_by_version") == "0.2.0")
    h5.close()
    # ---- migration is one-way and repeatable: further opens are no-ops
    idem = True
    bytes_d2 = db_bytes(d2)
    for i in range(3):
        hx = IncidentHistory(os.path.join(d2, "diagnostics"), "mig-i-%d" % i,
                             clock=lambda: T0)
        hx.open()
        idem = idem and hx.health()["enabled"] and db_bytes(d2) == bytes_d2
        hx.close()
    out["v2_reopen_repeatable_zero_bytes"] = idem
    # ---- HARDENING-2 (review): "exact shape" means table-set EQUALITY.
    # An UNRELATED extra table alongside a declared shape is a stranger
    # this module never created: refused under BOTH declarations, zero
    # bytes mutated, and -- for the v1 claim -- never migrated.
    connx = sqlite3.connect(os.path.join(d1, "diagnostics",
                                         "history.sqlite3"))
    connx.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
    connx.execute("CREATE TABLE stranger (x INTEGER)")
    connx.commit()
    connx.close()
    bytes_x = db_bytes(d1)
    hx1 = IncidentHistory(os.path.join(d1, "diagnostics"), "mig-extra-v2",
                          clock=lambda: T0)
    hx1.open()
    out["v2_extra_table_refused_zero_bytes"] = (
        not hx1.health()["enabled"]
        and hx1.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and db_bytes(d1) == bytes_x)
    hx1.close()
    d5 = make_v1_db(T0 - 60.0)
    connx = sqlite3.connect(os.path.join(d5, "diagnostics",
                                         "history.sqlite3"))
    connx.execute("CREATE TABLE stranger (x INTEGER)")
    connx.commit()
    connx.close()
    bytes_x5 = db_bytes(d5)
    hx2 = IncidentHistory(os.path.join(d5, "diagnostics"), "mig-extra-v1",
                          clock=lambda: T0)
    hx2.open()
    tables_x, meta_x, _ = _db_shape(d5)
    out["v1_extra_table_refused_zero_bytes"] = (
        not hx2.health()["enabled"]
        and hx2.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and meta_x.get("schema_version") == "1"
        and "stranger" in tables_x and not (tables_x & JOURNAL_TABLE_NAMES)
        and db_bytes(d5) == bytes_x5)
    hx2.close()
    return out


def group_ingest():
    out = {}
    # ---- empty exchange dir: a full pass that moves nothing
    h = ingest_history()
    r = h.ingest_journal_events()
    runs, events, state, audit = journal_dump(h)
    out["empty_dir_noop"] = (r["consumed"] == 0 and r["gaps"] == 0
                             and r["rejected"] == 0
                             and r["blocked_at"] is None
                             and r["terminal_after"] == 0
                             and state == (0, None, 0, 0)
                             and not runs and not events and not audit)
    # ---- missing/unreadable exchange dir: soft zero movement
    h._journal_exchange_dir = os.path.join(h._tmpdir, "no-such-dir")
    r = h.ingest_journal_events()
    out["missing_dir_soft"] = (r is not None and r["consumed"] == 0
                               and not h.health()["degraded"])
    h._journal_exchange_dir = h._out
    # ---- ONE valid file: exact sanitized rows, sentinel folds applied
    recs = [ev_record(ts=100.5),
            ev_record(ts=100.75, cls="reset", proto="Reality"),
            ev_record(ts=99.25, cls="other", fp="0123abcd4567ef89"),
            ev_record(ts=101.5, proto="Hysteria2", port=443,
                      dcls="https443", n=2)]
    write_ev(h, 1, records=recs)
    r = h.ingest_journal_events()
    runs, events, state, audit = journal_dump(h)
    out["single_valid_exact_rows"] = (
        r["consumed"] == 1 and state == (1, 1, 0, 0)
        and events == [
            (1, 99.25, "other", "OTHER", 0, "NONE", "0123abcd4567ef89", 1),
            (1, 100.5, "dns", "OTHER", 0, "NONE", None, 1),
            (1, 100.75, "reset", "Reality", 0, "NONE", None, 1),
            (1, 101.5, "dns", "Hysteria2", 443, "https443", None, 2)]
        and runs == [(1, JR_RUN, 1, "NONE", 10, 3, 2, 5, 0, 0, 0,
                      99.25, 101.5, 4, 5)])
    # ---- replay of a COMMITTED file (it is still on disk): exact no-op
    dump1 = journal_dump(h)
    r = h.ingest_journal_events()
    out["replay_committed_noop"] = (r["consumed"] == 0
                                    and journal_dump(h) == dump1)
    # ---- strictly sequential files
    write_ev(h, 2, records=[ev_record(ts=102.0)])
    write_ev(h, 3, records=[ev_record(ts=103.0), ev_record(ts=104.0)])
    r = h.ingest_journal_events()
    runs, events, state, _ = journal_dump(h)
    out["sequential_files"] = (r["consumed"] == 2 and state == (3, 3, 0, 0)
                               and [x[0] for x in runs] == [1, 2, 3]
                               and len(events) == 7)
    # ---- header-only file (zero records) still commits the batch
    write_ev(h, 4, records=[])
    r = h.ingest_journal_events()
    runs, events, state, _a = journal_dump(h)
    row4 = [x for x in runs if x[0] == 4][0]
    out["header_only_zero_records"] = (r["consumed"] == 1
                                       and row4[11] is None
                                       and row4[12] is None
                                       and row4[13] == 0 and row4[14] == 0
                                       and state == (4, 4, 0, 0))
    # ---- gap: files 10 and 12 leap over 5..9 and 11 -- counted ONCE each
    write_ev(h, 10, records=[ev_record(ts=200.0)])
    write_ev(h, 12, records=[ev_record(ts=201.0)])
    r = h.ingest_journal_events()
    runs, events, state, audit = journal_dump(h)
    gap_seqs = sorted(s for k, s, c in audit if k == "gap")
    out["gap_counted_once"] = (r["consumed"] == 2 and r["gaps"] == 6
                               and state == (12, 12, 6, 0)
                               and gap_seqs == [5, 6, 7, 8, 9, 11]
                               and all(c == "sequence_gap"
                                       for k, s, c in audit if k == "gap"))
    # ---- late-arriving skipped seqs: ignored, never re-counted/retracted
    write_ev(h, 11, records=[ev_record(ts=202.0)])
    write_ev(h, 7, records=[ev_record(ts=203.0)])
    r = h.ingest_journal_events()
    runs2, events2, state2, audit2 = journal_dump(h)
    out["late_fill_ignored"] = (r["consumed"] == 0
                                and state2 == (12, 12, 6, 0)
                                and len(runs2) == len(runs)
                                and len(events2) == len(events)
                                and audit2 == audit)
    # ---- malformed filenames are INVISIBLE: no consume, no reject, no gap
    for junk in ("ev-x.jsonl", "ev-5.jsonl.tmp", "journal.txt",
                 "ev-.jsonl", "ev-1-2.jsonl"):
        with open(os.path.join(h._out, junk), "w") as fh:
            fh.write("{}\n")
    r = h.ingest_journal_events()
    out["malformed_names_ignored"] = (r["consumed"] == 0
                                      and r["rejected"] == 0
                                      and r["gaps"] == 0)
    # ---- every terminal rejection class: sanitized code, zero rows
    h2 = ingest_history()
    write_ev(h2, 1, raw="not json at all\n")
    write_ev(h2, 2, raw=json.dumps(ev_record(), sort_keys=True) + "\n")
    write_ev(h2, 3, header=ev_header(9))
    write_ev(h2, 4, header=ev_header(4, cv=JR.CLASSIFIER_VERSION + 1))
    write_ev(h2, 5, records=[dict(ev_record(), extra=1)])
    write_ev(h2, 6, raw="")
    write_ev(h2, 7, raw=json.dumps(ev_header(7), sort_keys=True) + "\n"
             + "x" * (300 * 1024))
    os.mkdir(os.path.join(h2._out, "ev-8.jsonl"))
    r = h2.ingest_journal_events()
    runs0, events0, state0, audit0 = journal_dump(h2)
    out["reject_codes_exact"] = (
        r["rejected"] == 8 and r["consumed"] == 0
        and state0 == (8, None, 0, 8)
        and [(s, c) for k, s, c in audit0] == [
            (1, "exchange_bad_json"), (2, "exchange_no_header"),
            (3, "exchange_seq_mismatch"), (4, "exchange_header_invalid"),
            (5, "exchange_event_invalid"), (6, "exchange_empty"),
            (7, "exchange_too_large"), (8, "exchange_not_regular")])
    out["rejects_zero_rows"] = not runs0 and not events0
    # ---- rejected files settle ONCE: replay counts nothing again
    r = h2.ingest_journal_events()
    _r1, _e1, st_b, au_b = journal_dump(h2)
    out["rejects_settle_once"] = (r["rejected"] == 0 and r["consumed"] == 0
                                  and st_b == (8, None, 0, 8)
                                  and len(au_b) == 8)
    # ---- a VALID file around rejects continues: no gap is fabricated
    write_ev(h2, 9, records=[ev_record(ts=300.0)])
    write_ev(h2, 10, raw="garbage\n")
    write_ev(h2, 11, records=[ev_record(ts=301.0)])
    r = h2.ingest_journal_events()
    _r2, _e2, st, _a2 = journal_dump(h2)
    out["valid_around_rejects_no_gap"] = (
        r["consumed"] == 2 and r["gaps"] == 0 and r["rejected"] == 1
        and st == (11, 11, 0, 9))
    # ---- symlinked exchange file: refused as non-regular (POSIX gate)
    if SYMLINK:
        hl = ingest_history()
        target = os.path.join(hl._out, "real-target.jsonl")
        with open(target, "w") as fh:
            fh.write("{}\n")
        os.symlink(target, os.path.join(hl._out, "ev-1.jsonl"))
        r = hl.ingest_journal_events()
        _r3, _e3, stl, adl = journal_dump(hl)
        out["reject_symlink_not_regular"] = (
            r["rejected"] == 1
            and adl == [("rejected", 1, "exchange_not_regular")]
            and stl == (1, None, 0, 1))
        hl.close()
    else:
        out["reject_symlink_not_regular"] = True  # vacuous off-POSIX
    # ---- apply failure is NOT terminal: blocks higher seqs, degrades,
    # and a fixed retry consumes the whole range in order
    h3 = ingest_history()
    write_ev(h3, 1, records=[ev_record(ts=400.0)])
    write_ev(h3, 2, records=[ev_record(ts=401.0)])
    write_ev(h3, 3, records=[ev_record(ts=402.0)])
    real_apply = h3._journal_apply_locked

    def flaky(header, records, seq, now):
        if seq == 2:
            raise sqlite3.Error("simulated disk fault")
        return real_apply(header, records, seq, now)

    h3._journal_apply_locked = flaky
    r = h3.ingest_journal_events()
    runs, _e, st, _a = journal_dump(h3)
    out["apply_fail_blocks_no_leapfrog"] = (
        r["consumed"] == 1 and r["blocked_at"] == 2 and st == (1, 1, 0, 0)
        and [x[0] for x in runs] == [1]
        and h3.health()["degraded"] and h3.health()["enabled"]
        and h3.health()["last_error_code"] == CODE_INGEST_APPLY_FAILED
        and h3.journal_status()["blocked_at"] == 2)
    h3._journal_apply_locked = real_apply
    r = h3.ingest_journal_events()
    runs, _e, st, _a = journal_dump(h3)
    out["apply_fail_retry_completes"] = (r["consumed"] == 2
                                         and r["blocked_at"] is None
                                         and st == (3, 3, 0, 0)
                                         and [x[0] for x in runs]
                                         == [1, 2, 3])
    # ---- a journal failure NEVER bleeds into the sample write path
    s_before = len(rows_of(h3)[0])
    h3.on_publish(snap(), 1)
    s_after = len(rows_of(h3)[0])
    out["ingest_failure_isolated_from_publish"] = (
        s_after == s_before + 1 and h3.health()["enabled"])
    # ---- pre-commit crash: partial rows AND the terminal advance die
    # together; the reopened process applies the file EXACTLY once more
    h4 = ingest_history()
    write_ev(h4, 1, records=[ev_record(ts=500.0, n=3)])

    def die_after_partial_insert(header, records, seq, now):
        h4._conn.execute(
            "INSERT INTO journal_runs (seq, run, source_epoch, boundary,"
            " lines, eligible, info_dropped, nomatch_dropped,"
            " priority_unusable, pfail, limited, record_count,"
            " event_count, ingested_epoch, ingested_at)"
            " VALUES (?, ?, 1, 'NONE', 0,0,0,0,0,0,0,0,0,?, '')",
            (seq, header["run"], float(now)))
        raise RuntimeError("SENTINEL-power-loss-before-commit")

    h4._journal_apply_locked = die_after_partial_insert
    died = False
    try:
        h4.ingest_journal_events()
    except RuntimeError:
        died = True
    h4.close()
    t4 = [T0]
    h4b = IncidentHistory(os.path.join(h4._tmpdir, "diagnostics"),
                          "crash-2", clock=lambda: t4[0],
                          journal_exchange_dir=h4._out)
    h4b._out = h4._out
    h4b.open()
    runs, events, st, _a = journal_dump(h4b)
    pre_ok = (died and not runs and not events
              and st == (0, None, 0, 0))
    r = h4b.ingest_journal_events()
    runs, events, st, _a = journal_dump(h4b)
    out["precommit_crash_zero_rows_zero_terminal"] = pre_ok
    out["post_crash_reapply_exactly_once"] = (
        pre_ok and r["consumed"] == 1
        and [(x[0], x[13], x[14]) for x in runs] == [(1, 1, 3)]
        and st == (1, 1, 0, 0)
        and events == [(1, 500.0, "dns", "OTHER", 0, "NONE", None, 3)])
    # ---- 20x full process-restart loop against the STILL-PRESENT file:
    # zero duplicates ever escape the terminal guard (nondeterminism gate)
    dup_ok = True
    first = None
    for i in range(20):
        hi = IncidentHistory(os.path.join(h4._tmpdir, "diagnostics"),
                             "dup-%d" % i, clock=lambda: t4[0],
                             journal_exchange_dir=h4._out)
        hi.open()
        rr = hi.ingest_journal_events()
        dump = journal_dump(hi)
        if first is None:
            first = dump
        dup_ok = dup_ok and rr["consumed"] == 0 and dump == first
        hi.close()
    out["reopen_20x_no_duplicate"] = dup_ok and bool(first[0])
    # ---- DB-level deny-by-default: closed CHECKs reject free text and
    # any cross-field invention even from a buggy writer (FK too)
    bad = [
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp,"
        " n) VALUES (1, 1.0, '%s', 'OTHER', 0, 'NONE', NULL, 1)" % S_DST,
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp,"
        " n) VALUES (1, 1.0, 'other', 'OTHER', 0, 'NONE',"
        " 'SENTINELnot-hex!!', 1)",
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp,"
        " n) VALUES (1, 1.0, 'dns', 'OTHER', 0, 'NONE',"
        " '0123456789abcdef', 1)",
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp,"
        " n) VALUES (1, 1.0, 'dns', 'OTHER', 0, 'https443', NULL, 1)",
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp,"
        " n) VALUES (999, 1.0, 'dns', 'OTHER', 0, 'NONE', NULL, 1)",
    ]
    denials = 0
    for stmt in bad:
        try:
            h4b._conn.execute(stmt)
            h4b._conn.rollback()
        except sqlite3.IntegrityError:
            denials += 1
    out["db_checks_reject_free_text"] = denials == len(bad)
    # ---- forbidden credential material NEVER persists: a rejected file
    # carrying raw sentinels leaves only sanitized enum codes behind
    with open(os.path.join(h4b._out, "ev-2.jsonl"), "w") as fh:
        fh.write(json.dumps(ev_header(2), sort_keys=True) + "\n"
                 + json.dumps(ev_record(cls=S_DST), sort_keys=True) + "\n")
    h4b.ingest_journal_events()
    _r4, _e4, _s4, au4 = journal_dump(h4b)
    h4b._tmpdir = h4._tmpdir
    out["credential_like_never_persisted"] = (
        au4[-1] == ("rejected", 2, "exchange_event_invalid")
        and not any(s.encode() in raw_db_bytes(h4b) for s in SENTINELS))
    # ---- surface contract: journal_status is a fixed sanitized shape
    stt = h.journal_status()
    out["journal_status_shape"] = (
        set(stt) == {"enabled", "contract_available",
                     "exchange_dir_configured", "terminal_seq",
                     "last_consumed_seq", "gaps_total", "rejected_total",
                     "blocked_at", "last_pass", "reader"}
        and stt["enabled"] and stt["contract_available"]
        and stt["terminal_seq"] == 12 and stt["gaps_total"] == 6
        and stt["rejected_total"] == 0
        and set(stt["last_pass"]) == {"consumed", "gaps", "rejected",
                                      "blocked_at", "contract_available",
                                      "terminal_after"})
    # ---- closed connection: the ingest entry point stays soft
    h4b.close()
    soft = True
    try:
        h4b.ingest_journal_events()
        h4b.journal_status()
    except Exception:
        soft = False
    out["closed_db_ingest_soft"] = soft
    # ---- no exchange dir configured (packaged default-off): fully inert
    h5 = tmp_history(run_id="nodir", journal_exchange_dir=None)
    h5.open()
    out["no_exchange_dir_clean"] = (
        h5.ingest_journal_events() is None
        and h5.journal_status()["exchange_dir_configured"] is False
        and not h5.health()["degraded"])
    # ---- the CHECK grammar mirrors the frozen PR-2A schema EXACTLY
    out["enum_mirrors_match"] = (
        JOURNAL_CLASSES == tuple(JR.CLASSES)
        and JOURNAL_PROTOS == tuple(JR.PROTOS)
        and JOURNAL_BOUNDARIES == tuple(JR.BOUNDS)
        and JOURNAL_DCLS[0] == "NONE"
        and JOURNAL_DCLS[1:] == tuple(JR.DCLS))
    # ---- HARDENING-1 (review): journal_ingest_audit.code is a CLOSED
    # vocabulary. (a) every disposition-code LITERAL in the two frozen
    # contract sources is a member of JOURNAL_AUDIT_CODES (so no call
    # site can ever hand the audit table a string the DB would not
    # accept), and every member except the Monitor-derived gap marker is
    # such a literal; (b) the DB accepts exactly that set and nothing
    # else -- free text, a bare prefix and a credential-like string all
    # hit the CHECK.
    literals = set()
    for mod in (JC, JR):
        with open(mod.__file__, "r") as fh:
            literals.update(re.findall(r'"(exchange_[a-z_]+)"',
                                       fh.read()))
    out["audit_code_enum_exact_vs_contract"] = (
        literals == {c for c in JOURNAL_AUDIT_CODES
                     if c != "sequence_gap"}
        and "sequence_gap" in JOURNAL_AUDIT_CODES)
    accepted = 0
    for code in JOURNAL_AUDIT_CODES:
        try:
            h._conn.execute(
                "INSERT INTO journal_ingest_audit (epoch, kind, seq,"
                " code) VALUES (?, 'rejected', ?, ?)", (T0, 9000, code))
            accepted += 1
        except sqlite3.Error:
            pass
    h._conn.rollback()
    denies = 0
    for bad_code in ("SELECT * FROM credentials", S_PW,
                     "exchange_" + "x" * 80, "sequence_gap "):
        try:
            h._conn.execute(
                "INSERT INTO journal_ingest_audit (epoch, kind, seq,"
                " code) VALUES (?, 'rejected', ?, ?)", (T0, 9001, bad_code))
            h._conn.rollback()
        except sqlite3.IntegrityError:
            denies += 1
    out["audit_db_rejects_arbitrary_code"] = (
        accepted == len(JOURNAL_AUDIT_CODES) and denies == 4)
    # (c) production call-site proof: settle a rejection with a code
    # OUTSIDE the mirror (a future contract could invent one) -- the
    # settlement FAILS fail-closed: no audit/state row, blocked, journal
    # degraded, terminal NOT advanced.
    hu = ingest_history()
    res_u = {"consumed": 0, "gaps": 0, "rejected": 0, "blocked_at": None}
    ok = hu._journal_settle_rejected(1, "exchange_invented_code", T0,
                                     res_u)
    _ru, _eu, st_u, au_u = journal_dump(hu)
    out["audit_unknown_code_settlement_refused"] = (
        ok is False and res_u["blocked_at"] == 1 and not au_u
        and st_u == (0, None, 0, 0)
        and hu.health()["degraded"]
        and hu.health()["last_error_code"] == CODE_INGEST_APPLY_FAILED)
    hu.close()
    h.close()
    h2.close()
    h3.close()
    h5.close()
    return out


def group_ingest2():
    out = {}
    # ---- cadence: publication drives ONE ingest pass per interval
    d = tempfile.mkdtemp()
    out_d = tempfile.mkdtemp()
    t = [T0]
    h = IncidentHistory(os.path.join(d, "diagnostics"), "cad-j",
                        clock=lambda: t[0], journal_exchange_dir=out_d)
    h._out = out_d
    h.open()
    write_ev(h, 1)
    h.on_publish(snap(), 1)
    out["publish_drives_ingest"] = h.journal_status()["terminal_seq"] == 1
    write_ev(h, 2)
    t[0] = T0 + 3.0
    h.on_publish(snap(), 2)          # inside the 10s gate: NO second pass
    out["sub_interval_no_second_pass"] = (
        h.journal_status()["terminal_seq"] == 1)
    t[0] = T0 + 11.0
    h.on_publish(snap(), 3)
    st3 = h.journal_status()
    out["interval_pass_consumes"] = (st3["terminal_seq"] == 2
                                     and st3["last_pass"]["consumed"] == 1)
    # ---- the ingest gate fires EVEN when the publish writes no rows
    h._journal_ingest_interval = 0.5
    write_ev(h, 3)
    t[0] = T0 + 13.0                 # 2s on: no new aggregate sample
    s_before = len(rows_of(h)[0])
    h.on_publish(snap(), 4)
    st4 = h.journal_status()
    out["ingest_runs_without_sample_write"] = (
        st4["terminal_seq"] == 3 and len(rows_of(h)[0]) == s_before)
    h.close()
    # ---- reader heartbeat availability: PR-2A's frozen 180s semantics
    h2 = ingest_history()
    hb_path = os.path.join(h2._out, "hb")

    def hb_write(payload):
        if os.path.isdir(hb_path):
            os.rmdir(hb_path)
        with open(hb_path, "w", newline="\n") as fh:
            fh.write(payload)

    def reader():
        return h2.journal_status()["reader"]

    out["hb_absent"] = reader()["status"] == "absent"
    hb_write(json.dumps({"seq": 7, "ts": int(T0 - 179)}))
    r = reader()
    out["hb_fresh"] = (r["status"] == "fresh" and r["seq"] == 7
                       and r["age_seconds"] == 179.0)
    hb_write(json.dumps({"seq": 8, "ts": int(T0 - 180)}))
    out["hb_boundary_exactly_180_fresh"] = reader()["status"] == "fresh"
    hb_write(json.dumps({"seq": 9, "ts": int(T0 - 181)}))
    r = reader()
    out["hb_stale_181"] = (r["status"] == "stale"
                           and r["age_seconds"] == 181.0)
    invalid = []
    hb_write("not json{")
    invalid.append(reader()["status"] == "invalid")
    os.remove(hb_path)
    os.mkdir(hb_path)
    invalid.append(reader()["status"] == "invalid")
    os.rmdir(hb_path)
    hb_write("x" * 5000)
    invalid.append(reader()["status"] == "invalid")
    out["hb_invalid_forms"] = all(invalid)
    out["hb_threshold_echoed"] = reader()["stale_threshold_seconds"] == 180.0
    os.remove(hb_path)
    write_ev(h2, 1, records=[ev_record(ts=700.0)])
    r = h2.ingest_journal_events()
    out["hb_stale_never_blocks_ingest"] = r["consumed"] == 1
    h2.close()
    # ---- missing continuity row: fail closed, NEVER auto-repaired
    h3 = ingest_history()
    h3._conn.execute("DELETE FROM journal_ingest_state")
    h3._conn.commit()
    res = h3.ingest_journal_events()
    out["missing_state_row_fails_closed"] = (
        res is None and h3.health()["degraded"]
        and h3.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and h3.journal_status()["terminal_seq"] is None)
    bytes3 = raw_db_bytes(h3)
    h3.close()
    h3b = IncidentHistory(os.path.join(h3._tmpdir, "diagnostics"),
                          "nostate", clock=lambda: T0)
    h3b._tmpdir = h3._tmpdir
    h3b.open()
    out["missing_state_row_reopen_refused"] = (
        not h3b.health()["enabled"]
        and h3b.health()["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and raw_db_bytes(h3b) == bytes3)
    # ---- TIME retention ages journal evidence out -- but NEVER the
    # terminal continuity row (bounded single row, the sole authority)
    h4 = ingest_history()
    write_ev(h4, 1, records=[ev_record(ts=600.0)])
    write_ev(h4, 2, raw="junk\n")
    h4.ingest_journal_events()
    h4.close()
    h4b = IncidentHistory(os.path.join(h4._tmpdir, "diagnostics"), "ret-j",
                          clock=lambda: T0 + 500.0, retention_seconds=100.0,
                          journal_exchange_dir=None)
    h4b.open()
    runs, events, st, audit = journal_dump(h4b)
    out["time_retention_journal_keeps_state"] = (
        not runs and not events and not audit
        and st == (2, 1, 0, 1) and h4b.health()["enabled"])
    h4b.close()
    # ---- SIZE retention: ALL FOUR sources prune as ONE global timeline
    h5 = tmp_history(run_id="sz", retention_seconds=10_000_000.0,
                     journal_exchange_dir=None)
    h5.open()
    base = T0 - 100000
    for k in range(800):
        e = base + 4 * k
        h5._conn.execute(
            "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
            " collector_stale, total_active_connections,"
            " reality_active_connections, hysteria2_active_connections,"
            " other_active_connections, uplink_rate, downlink_rate,"
            " skipped_events, duplicate_events, identity_conflicts,"
            " abandoned_on_reset, snapshot_generated_at)"
            " VALUES (?, '', ?, 0,0,0,0,0,0,0,0,0,0,0,?)",
            (e, "z" * 48, "y" * 16))
        h5._conn.execute(
            "INSERT INTO device_protocol_states (epoch, iso_utc, run_id,"
            " device, inbound, active_connections, device_status,"
            " uplink_rate, downlink_rate, uplink_total, downlink_total,"
            " reason) VALUES (?, '', ?, 'd', 'i', 0, 'ACTIVE',"
            " 0, 0, 0, 0, 'heartbeat')", (e + 1, "z" * 48))
        h5._conn.execute(
            "INSERT INTO journal_runs (seq, run, source_epoch, boundary,"
            " lines, eligible, info_dropped, nomatch_dropped,"
            " priority_unusable, pfail, limited, record_count,"
            " event_count, ingested_epoch, ingested_at)"
            " VALUES (?, ?, 1, 'NONE', 0,0,0,0,0,0,0,1,1,?, '')",
            (k + 1, "z" * 32, float(e + 2)))
        h5._conn.execute(
            "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls,"
            " fp, n) VALUES (?, 1.0, 'dns', 'OTHER', 0, 'NONE', NULL, 1)",
            (k + 1,))
        h5._conn.execute(
            "INSERT INTO journal_ingest_audit (epoch, kind, seq, code)"
            " VALUES (?, 'gap', ?, 'sequence_gap')", (float(e + 3), k + 1))
    h5._conn.commit()
    before5 = h5._db_bytes()
    h5._ceiling_bytes = before5 - 1
    h5._target_bytes = before5 // 2
    merged_before = [r[0] for r in h5._conn.execute(
        "SELECT epoch FROM timeline_samples"
        " UNION ALL SELECT epoch FROM device_protocol_states"
        " UNION ALL SELECT ingested_epoch FROM journal_runs"
        " UNION ALL SELECT epoch FROM journal_ingest_audit"
        " ORDER BY epoch")]
    h5._cleanup("p2b-size")
    ms = [r[0] for r in h5._conn.execute(
        "SELECT epoch FROM timeline_samples")]
    sts = [r[0] for r in h5._conn.execute(
        "SELECT epoch FROM device_protocol_states")]
    mrs = [r[0] for r in h5._conn.execute(
        "SELECT ingested_epoch FROM journal_runs")]
    mas = [r[0] for r in h5._conn.execute(
        "SELECT epoch FROM journal_ingest_audit")]
    merged_after = sorted(ms + sts + mrs + mas)
    n5 = len(merged_after)
    out["size_global_suffix_4_sources"] = bool(merged_after) and \
        merged_after == merged_before[len(merged_before) - n5:]
    out["size_all_sources_pruned"] = all(0 < len(x) < 800 for x in
                                         (ms, sts, mrs, mas))
    out["size_newest_survives"] = merged_before[-1] in merged_after
    out["size_below_target"] = h5._db_bytes() <= h5._target_bytes
    out["size_no_orphans_state_survives"] = (
        h5._conn.execute(
            "SELECT COUNT(*) FROM journal_events WHERE seq NOT IN"
            " (SELECT seq FROM journal_runs)").fetchone()[0] == 0
        and h5._conn.execute(
            "SELECT terminal_seq FROM journal_ingest_state"
            " WHERE id = 1").fetchone()[0] == 0)
    h5.close()
    # ---- sanitized status surface (never paths, never payload)
    h6 = ingest_history()
    write_ev(h6, 1)
    h6.ingest_journal_events()
    stt = h6.journal_status()
    out["journal_status_surface"] = (
        stt["enabled"] and stt["contract_available"] is True
        and stt["terminal_seq"] == 1 and stt["last_consumed_seq"] == 1
        and stt["gaps_total"] == 0 and stt["rejected_total"] == 0
        and stt["blocked_at"] is None
        and stt["reader"]["status"] == "absent")
    payload = json.dumps(stt, sort_keys=True, default=str)
    out["status_payload_sanitized"] = (
        not any(s in payload for s in SENTINELS)
        and h6._out not in payload and h6._tmpdir not in payload)
    h6.close()
    # ---- BLOCKER regression (review): a journal apply failure in the
    # SAME on_publish whose ordinary sample write SUCCEEDS must still
    # leave the history degraded with the ingest code. The write path
    # clears only its OWN health state; the journal state survives until
    # a later ingest pass completes with nothing blocked.
    h7 = ingest_history()
    write_ev(h7, 1, records=[ev_record(ts=700.0)])
    write_ev(h7, 2, records=[ev_record(ts=701.0)])   # higher seq waits
    real_apply7 = h7._journal_apply_locked

    def flaky7(header, records, seq, now):
        if seq == 1:
            raise sqlite3.Error("simulated journal-apply disk fault")
        return real_apply7(header, records, seq, now)

    h7._journal_apply_locked = flaky7
    h7.on_publish(snap(), 1)      # gate fails at seq 1; write succeeds
    s_after = len(rows_of(h7)[0])
    runs7, _e7, st7, _a7 = journal_dump(h7)
    out["swallow_sample_write_succeeds"] = (
        s_after == 1 and h7.health()["enabled"]
        and h7.journal_status()["terminal_seq"] == 0)
    out["swallow_health_not_swallowed"] = (
        h7.health()["degraded"]
        and h7.health()["last_error_code"] == CODE_INGEST_APPLY_FAILED
        and h7.journal_status()["blocked_at"] == 1)
    out["swallow_no_leapfrog_no_terminal"] = (
        not runs7 and st7 == (0, None, 0, 0)
        and h7.journal_status()["last_consumed_seq"] is None)
    h7._journal_apply_locked = real_apply7
    h7._t[0] = T0 + 11.0          # past the 10s ingest cadence
    h7.on_publish(snap(), 2)
    runs7b, _e7b, st7b, _a7b = journal_dump(h7)
    out["swallow_recovers_on_clean_pass"] = (
        not h7.health()["degraded"]
        and h7.health()["last_error_code"] is None
        and st7b == (2, 2, 0, 0) and [x[0] for x in runs7b] == [1, 2]
        and h7.journal_status()["blocked_at"] is None)
    h7.close()
    # ---- BLOCKER-1 regression (review round 2): a journal-STRUCTURAL
    # refusal (continuity row mutated away mid-run) is CONTAINED by the
    # journal boundary: nothing raises into the publisher, the P1
    # sample/device write of the SAME on_publish still lands, no
    # journal state advances or is fabricated, the row is NEVER
    # recreated, and the degraded surface stays sanitized.
    hc = ingest_history()
    write_ev(hc, 1, records=[ev_record(ts=810.0)])
    hc._conn.execute("DELETE FROM journal_ingest_state")
    hc._conn.commit()
    raised = None
    try:
        hc.on_publish(snap(), 1)
    except Exception as exc:  # noqa: BLE001 -- the point is: none
        raised = type(exc).__name__
    runs_c, events_c, st_c, audit_c = journal_dump(hc)
    out["struct_publish_not_raised_sample_lands"] = (
        raised is None and len(rows_of(hc)[0]) == 1
        and hc.health()["enabled"])
    out["struct_journal_state_frozen"] = (
        not runs_c and not events_c and not audit_c and st_c is None
        and hc.journal_status()["terminal_seq"] is None
        and hc.journal_status()["blocked_at"] is None)
    hhs = hc.health()
    out["struct_health_degraded_sanitized"] = (
        hhs["degraded"]
        and hhs["last_error_code"] == CODE_SCHEMA_UNSUPPORTED
        and not any(s in json.dumps(hhs, default=str) for s in SENTINELS))
    hc._t[0] = T0 + 11.0
    hc.on_publish(snap(), 2)
    runs_c2, _ec2, st_c2, _ac2 = journal_dump(hc)
    out["struct_second_publish_still_contained"] = (
        len(rows_of(hc)[0]) == 2 and hc.health()["enabled"]
        and hc.health()["degraded"])
    out["struct_never_recreated"] = not runs_c2 and st_c2 is None
    hc.close()
    # ---- BLOCKER-2 regression (review round 2): a filename-valid,
    # regular, in-size exchange file whose BYTES cannot be decoded must
    # never escape the journal boundary through the contract's
    # text-mode read. It is classified with a frozen CLOSED disposition
    # code and follows the frozen malformed-file semantics exactly:
    # terminal rejection settles ONCE, zero rows, higher seqs continue,
    # the ordinary sample write lands, nothing hostile persists.
    HOSTILE = bytes([0x81, 0xFF, 0x81, 0xFE, 0xFF, 0x81])
    enc = locale.getpreferredencoding(False)
    try:
        HOSTILE.decode(enc)
        # decodable junk in this locale: still a terminal rejection,
        # carried under the OTHER frozen closed code
        expect = "exchange_bad_json"
    except (UnicodeDecodeError, LookupError, ValueError):
        expect = "exchange_unreadable"
    hu8 = ingest_history()
    with open(os.path.join(hu8._out, "ev-1.jsonl"), "wb") as fh:
        fh.write(json.dumps(ev_header(1), sort_keys=True).encode()
                 + b"\n" + HOSTILE + b"\n")
    write_ev(hu8, 2, records=[ev_record(ts=850.0)])
    raised2 = None
    try:
        hu8.on_publish(snap(), 1)
    except Exception as exc:  # noqa: BLE001
        raised2 = type(exc).__name__
    runs_u, events_u, st_u, audit_u = journal_dump(hu8)
    out["undecodable_no_escape_sample_lands"] = (
        raised2 is None and len(rows_of(hu8)[0]) == 1
        and hu8.health()["enabled"] and not hu8.health()["degraded"])
    out["undecodable_rejected_once_frozen_code"] = (
        audit_u == [("rejected", 1, expect)] and st_u == (2, 2, 0, 1))
    out["undecodable_zero_rows_higher_seq_continues"] = (
        [x[0] for x in runs_u] == [2] and [x[0] for x in events_u] == [2])
    blob_u = raw_db_bytes(hu8)
    stt_u = json.dumps(hu8.journal_status(), sort_keys=True, default=str)
    out["undecodable_hostile_bytes_absent"] = (
        HOSTILE not in blob_u and hu8._out not in stt_u
        and expect in JOURNAL_AUDIT_CODES)
    write_ev(hu8, 3, records=[ev_record(ts=860.0)])
    hu8._t[0] = T0 + 11.0
    hu8.on_publish(snap(), 2)
    _r3, _e3, st3, _a3 = journal_dump(hu8)
    out["undecodable_next_seq_still_correct"] = (
        st3 == (3, 3, 0, 1) and not hu8.health()["degraded"])
    hu8.close()
    return out


GROUPS = {"storage": group_storage, "privacy": group_privacy,
          "cadence": group_cadence, "restart": group_restart,
          "retention": group_retention, "failure": group_failure,
          "concurrency": group_concurrency,
          "migrate": group_migrate, "ingest": group_ingest,
          "ingest2": group_ingest2,
          "http": group_http}


def main():
    group = sys.argv[1]
    try:
        results = GROUPS[group]()
    except Exception as exc:  # noqa: BLE001 -- the harness reports, never dies green
        results = {"_harness_error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(results, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
HARNESS_EOF

run_group() {
    GROUP="$1"
    PYTHONPATH="$ROOT/monitor-v2" "$PY" "$TMP/hist_harness.py" "$GROUP" \
        > "$TMP/out-$GROUP.json" 2> "$TMP/err-$GROUP.log"
    if ! "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' \
        "$TMP/out-$GROUP.json" 2>/dev/null; then
        printf '{"_harness_error": "harness did not produce JSON"}' \
            > "$TMP/out-$GROUP.json"
        printf 'harness stderr:\n%s\n' "$(tail -5 "$TMP/err-$GROUP.log")" >&2
    fi
}

result() {
    "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$TMP/out-$GROUP.json" "$1" 2>/dev/null || printf 'EVAL-ERROR'
}

check() { assert_eq "$(result "$1")" "True" "$2"; }

section "H1: storage safety (spec §1/§10)"
run_group "storage"
check 'd.get("_harness_error") is None' "storage harness ran clean"
check 'd["schema_created"]' "meta + v1 tables + journal v2 tables exist"
check 'd["meta_schema_version_2"]' "meta carries explicit schema_version=2"
check 'd["meta_creation_only"]' "meta holds schema version + creation metadata ONLY"
check 'd["journal_mode_delete"]' "journal_mode=DELETE (no stray wal/shm)"
check 'd["synchronous_full"]' "synchronous=FULL"
check 'd["foreign_keys_on"]' "foreign_keys=ON"
check 'd["dir_mode_0700"]' "diagnostics/ is 0700 on POSIX"
check 'd["db_mode_0600"]' "history.sqlite3 is 0600 on POSIX"
check 'd["no_wal_shm_files"]' "diagnostics/ contains ONLY history.sqlite3"
check 'd["reopen_persistence"]' "rows survive close/reopen (persistence)"
check 'd["dir_mode_tightened"]' "a too-open existing dir is tightened to 0700"
check 'd["file_as_dir_refused"]' "file-as-diagnostics-dir refused (dir_unsafe)"
check 'd["symlink_dir_refused"]' "symlinked diagnostics dir refused (Linux gate)"
check 'd["symlink_dir_no_write"]' "refused symlink dir: target tree untouched"
check 'd["symlink_db_refused"]' "symlinked history.sqlite3 refused (Linux gate)"
check 'd["symlink_db_target_intact"]' "refused symlink db: victim file intact"
check 'd["nonregular_db_refused"]' "directory-as-db refused (never a regular file)"
check 'd["no_downgrade"]' "newer on-disk schema never downgraded (fail-closed)"
check 'd["b3_noncurrent_all_refused"]' "B3: version 0/-1/3/malformed/empty ALL refused fail-closed"
check 'd["b3_refusal_zero_bytes"]' "B3: refusal mutates ZERO bytes and preserves the tampered value"
check 'd["b3_hybrid_v1_claim_refused"]' "P2B: v1 claim on a full v2 db is a hybrid: refused, zero bytes"
check 'd["b3_exact_v2_reopen_readonly"]' "B3: accepted exact-v2 re-open mutates zero bytes"
check 'd["b3_metaless_orphan_refused"]' "B3: meta claiming v2 with stripped tables is refused"
check 'd["b3_unrelated_db_refused"]' "B3: unrelated tables-only DB never claimed as v1"
check 'd["b3_zero_tables_claim_refused"]' "B3: non-empty zero-table file not treated as fresh"
check 'd["b3_garbage_soft"]' "B3: garbage db file -> sanitized refusal, no raise"
check 'd["b3_zero_byte_claimed"]' "B3: zero-byte pre-existing file IS genuinely fresh (v1)"

section "H2: privacy whitelist + protocol classes (spec §3/§4/§10)"
run_group "privacy"
check 'd.get("_harness_error") is None' "privacy harness ran clean"
check 'd["no_sentinel_in_reads"]' "sentinel conn-id/IP/dest/password/key/secret NOT in any read"
check 'd["no_sentinel_in_db_bytes"]' "sentinels NOT anywhere in the raw DB file bytes"
check 'd["sample_keys_exact"]' "sample rows are EXACTLY the whitelisted columns"
check 'd["state_keys_exact"]' "device rows are EXACTLY the whitelisted columns"
check 'd["no_id_source_dest_any_row"]' "no id/source/destination/last_error field in any row"
check 'd["device_protocol_kept"]' "device names + inbound tags kept (allowed metadata)"
check 'd["cls_tag_reality"]' "vless-in maps to Reality"
check 'd["cls_tag_hy2"]' "hy2-in maps to Hysteria2"
check 'd["cls_type_reality"]' "inbound_type=reality maps to Reality (no tag hard-code)"
check 'd["cls_type_vless"]' "inbound_type=vless maps to Reality"
check 'd["cls_type_hy2"]' "inbound_type=hysteria2 maps to Hysteria2"
check 'd["cls_unknown"]' "unrecognized protocol -> OTHER (never guessed)"
check 'd["cls_tag_wins"]' "reviewed tag table wins over inbound_type"
check 'd["aggregate_counts"]' "aggregate reality/hy2/total active counts correct"
check 'd["other_counted"]' "unknown-protocol active count is kept in OTHER"

section "H3: cadence + write rules (spec §2/§10)"
run_group "cadence"
check 'd.get("_harness_error") is None' "cadence harness ran clean"
check 'd["first_publish_samples_and_states"]' "first publish: 1 sample + device rows"
check 'd["sub_interval_no_extra_sample"]' "sub-5s publishes add NO aggregate rows"
check 'd["rate_only_no_state_row"]' "rate-only changes write NO device rows"
check 'd["sample_at_5s"]' "aggregate sample appears exactly at the 5s boundary"
check 'd["no_excessive_sampling"]' "dense publishing never exceeds the 5s cadence"
check 'd["row_on_active_change"]' "device row written IMMEDIATELY on active-count change"
check 'd["row_on_status_change"]' "device row written IMMEDIATELY on status change"
check 'd["heartbeat_never_before_60s"]' "no heartbeat row inside the 60s window"
check 'd["heartbeat_after_60s_only"]' "after 60s: exactly one heartbeat per (device,protocol)"
check 'd["heartbeat_reason"]' "periodic rows carry reason=heartbeat"
check 'd["reason_values_closed"]' "reason is always change|heartbeat"

section "H4: restart semantics (spec §2/§10)"
run_group "restart"
check 'd.get("_harness_error") is None' "restart harness ran clean"
check 'd["run_ids_differ_and_persist"]' "new process gets a DIFFERENT run_id, both survive"
check 'd["no_fabricated_gap_rows"]' "no samples fabricated across the downtime gap"
check 'd["gap_is_real_only"]' "rows exist only at real wall-clock points"

section "H5: retention (spec §5/§10)"
run_group "retention"
check 'd.get("_harness_error") is None' "retention harness ran clean"
check 'd["time_prune_oldest_gone"]' "expired horizon pruned at startup (oldest gone)"
check 'd["time_prune_newest_kept"]' "newest row survives time retention"
check 'd["time_prune_actually_pruned"]' "retention really deleted rows (discriminating)"
check 'd["cleanup_at_startup"]' "cleanup runs exactly once at startup"
check 'd["no_write_no_cleanup"]' "publish that writes nothing triggers no cleanup"
check 'd["cleanup_bounded_hourly"]' "later cleanup bounded by the (injected) interval"
check 'd["below_ceiling_no_prune"]' "under the ceiling, cleanup keeps every row"
check 'd["size_prune_keeps_newest_suffix"]' "size pruning removes ONLY the oldest prefix"
check 'd["size_prune_below_target"]' "pruned down to the injected target size"
check 'd["size_prune_max_survives"]' "newest epoch survives size pruning"
check 'd["b2_mixed_global_suffix"]' "B2: interleaved two-table pruning keeps the GLOBAL newest suffix"
check 'd["b2_mixed_both_pruned"]' "B2: BOTH tables trimmed (no per-table oldest-first counterexample)"
check 'd["b2_mixed_newest_survives"]' "B2: newest evidence in the merged order always survives"
check 'd["b2_mixed_below_target"]' "B2: mixed pruning converges to the injected target size"
check 'd["retention_failure_code"]' "retention failure -> degraded code, never raises"

section "H6: failure isolation (spec §5/§6/§7/§10)"
run_group "failure"
check 'd.get("_harness_error") is None' "failure harness ran clean"
check 'd["write_failure_never_raises"]' "broken DB: on_publish never raises"
check 'd["write_failure_degrades"]' "write failure sets degraded + code + counter"
check 'd["last_success_time_kept"]' "last successful write time preserved on failure"
check 'd["read_failure_empty"]' "broken read -> empty sanitized result, no raise"
check 'd["stripped_table_reopen_refused"]' "B3: stripped-table DB refused on reopen (no silent adoption)"
check 'd["stripped_refusal_zero_bytes"]' "B3: that refusal leaves the corrupt file byte-identical"
check 'd["recovers_after_reopen"]' "degraded clears once the corrupt db is removed + re-created"
check 'd["closed_db_soft"]' "shutdown race (closed db) still soft"
check 'd["open_never_raises"]' "hostile storage: open() fail-soft, never raises"
check 'd["broker_survives_history_explosion"]' "exploding writer cannot kill publisher/dashboard"
check 'd["hook_receives_decorated_versioned"]' "hook sees DECORATED snapshot + monotonic version"
check 'd["standalone_broker_no_history"]' "broker without history behaves exactly as before"

section "H7: read endpoint (spec §8)"
run_group "http"
check 'd.get("_harness_error") is None' "http harness ran clean"
check 'd["requires_session_401"]' "timeline is session-gated (401 without login)"
check 'd["login_ok"]' "harness logged in"
check 'd["timeline_200"]' "authenticated GET answers 200"
check 'd["top_level_keys"]' "response shape is the exact whitelist"
check 'd["history_health"]' "health keys: enabled/degraded/last_success/failure/code/run_id"
check 'd["run_id_exposed"]' "current process run_id surfaced (non-secret)"
check 'd["rows_present"]' "persisted rows are readable back"
check 'd["columns_whitelisted"]' "sample columns are the deny-by-default set"
check 'd["no_forbidden_key"]' "no id/source/destination/password key anywhere"
check 'd["no_sentinel_in_body"]' "forbidden sentinels absent from the HTTP body"
check 'd["post_405"]' "POST on the route is a 405 (GET-only surface)"
check 'd["bad_param_400"]' "malformed/negative/NaN/inf since|limit -> 400"
check 'd["limit_hard_capped"]' "oversized limit clamps to the hard max"
check 'd["since_filters"]' "since= is the only (bounded) filter"
check 'd["truncated_flag"]' "limit truncation is flagged, never silent"
check 'd["path_traversal_not_history"]' "path oddities hit normal gates, not the timeline"
check 'd["no_history_503"]' "runtime without history: sanitized 503, no traceback"

section "H8: live webapp serve end-to-end (read-only proof rows exist)"
SETUP_DIR="$TMP/live-data"
"$PY" "$WEBAPP" setup --data-dir "$SETUP_DIR" --assume-yes \
    --password 'live-hist-password-1' > "$TMP/live-setup.log" 2>&1 \
    || fail "webapp setup for live history proof failed"
LIVE_PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
"$PY" "$WEBAPP" serve --listen 127.0.0.1 --port "$LIVE_PORT" \
    --url 'http://127.0.0.1:9099' --interval 1 --data-dir "$SETUP_DIR" \
    > "$TMP/live-serve.log" 2>&1 &
LIVE_PID=$!
LIVE_OUT="$TMP/live-result.json"
if "$PY" - "$LIVE_PORT" "$SETUP_DIR" "$LIVE_OUT" <<'EOF'
import http.client, json, os, sys, time
port, data_dir, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
deadline = time.time() + 20
session = None
while time.time() < deadline:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("POST", "/api/v1/login",
                     json.dumps({"password": "live-hist-password-1"}),
                     {"Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        cookie = (r.getheader("Set-Cookie") or "").split(";")[0]
        conn.close()
        if r.status == 200:
            session = cookie
            break
    except OSError:
        time.sleep(0.25)
assert session, "live serve never accepted a login"
deadline = time.time() + 25
data = None
while time.time() < deadline:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    conn.request("GET", "/api/v1/diagnostics/timeline",
                 headers={"Cookie": session})
    r = conn.getresponse()
    data = json.loads(r.read().decode())
    conn.close()
    if data["samples"]:
        break
    time.sleep(0.5)
db = os.path.join(data_dir, "diagnostics", "history.sqlite3")
result = {
    "enabled": data["history"]["enabled"] is True,
    "not_degraded": data["history"]["degraded"] is False,
    "run_id_hex32": len(data["history"]["run_id"]) == 32,
    "sample_written": bool(data["samples"]),
    "api_status_stale_ok": (not data["samples"]) or data["samples"][-1]["api_status"] in ("STALE", "CONNECTED"),
    "db_file_exists": os.path.isfile(db),
}
leftovers = set(os.listdir(os.path.join(data_dir, "diagnostics")))
result["only_db_file"] = leftovers <= {"history.sqlite3"}
json.dump(result, open(out, "w"))
EOF
then
    json_get() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]))' "$LIVE_OUT" "$1"; }
    assert_eq "True" "$(json_get enabled)" "live serve: history enabled + open() wired"
    assert_eq "True" "$(json_get not_degraded)" "live serve: history not degraded"
    assert_eq "True" "$(json_get run_id_hex32)" "live serve: run_id is a fresh random uuid (32 hex) per process"
    assert_eq "True" "$(json_get sample_written)" "live serve: >=1 timeline sample persisted and read back"
    assert_eq "True" "$(json_get api_status_stale_ok)" "live serve: dead service.api still samples (STALE recorded, not skipped)"
    assert_eq "True" "$(json_get db_file_exists)" "live serve: <data-dir>/diagnostics/history.sqlite3 exists"
    assert_eq "True" "$(json_get only_db_file)" "live serve: diagnostics dir holds only the db (no stray journals)"
else
    fail "live webapp serve end-to-end history proof errored: $(tail -3 "$TMP/live-serve.log" 2>/dev/null | tr '\n' ' ')"
fi
kill "$LIVE_PID" 2>/dev/null || true
wait "$LIVE_PID" 2>/dev/null || true

section "H9: writer/reader/close serialization under real threads (review B1)"
run_group "concurrency"
check 'd.get("_harness_error") is None' "concurrency harness ran clean"
check 'd["no_thread_errors"]' "B1: 300-publish writer + 4 readers + racing close: zero exceptions"
check 'd["no_deadlock"]' "B1: every thread exited (the shared RLock cannot deadlock)"
check 'd["zero_failures_under_contention"]' "B1: failure_count stays 0 through the stress"
check 'd["close_midflight_soft"]' "B1: reads racing/during close() stay soft and empty, never raise"
check 'd["rows_durable_through_close"]' "B1: rows committed before close() reopen readable (no torn tx)"
check 'd["privacy_under_contention"]' "B1: sentinels still absent from raw DB bytes after stress"
check 'd["cleanup_ran_under_contention"]' "B1-fix: periodic cleanup fired via locked on_publish path mid-contention (observed, not invoked)"
check 'd["startup_cleanup_ran_once"]' "B1-fix: startup cleanup observed exactly once"

section "H10: schema v1->v2 migration (PR-2B spec §5)"
run_group "migrate"
check 'd.get("_harness_error") is None' "migrate harness ran clean"
check 'd["v1_migration_enabled"]' "real 0.2.0 v1 db opens ENABLED after forward migration"
check 'd["v1_rows_preserved"]' "v1 sample + device rows preserved untouched"
check 'd["v1_meta_flipped_to_2"]' "meta schema_version flips 1 -> 2 in the migration"
check 'd["v1_creation_metadata_kept"]' "created_at/created_by_version (0.2.0) kept"
check 'd["v1_full_v2_shape"]' "all 4 journal tables + terminal state row created"
check 'd["post_migration_publish_ingest"]' "publish + journal ingest both work post-migration"
check 'd["migrated_reopen_adopts_zero_bytes"]' "migrated v2 re-opens: adopted, ZERO bytes mutated"
check 'd["mid_migration_crash_rolls_back_exact_v1"]' "crash MID-migration rolls back to exact untouched v1"
check 'd["post_crash_reopen_migrates_clean"]' "after the crash, a normal open re-runs migration cleanly"
check 'd["newer_schema_migrated_refused_zero_bytes"]' "schema '3' on a migrated db: refused, zero bytes"
check 'd["hybrid_v1_claim_refused_zero_bytes"]' "v1 claim + journal tables hybrid: refused, zero bytes"
check 'd["fresh_db_is_v2_immediately"]' "fresh databases are created at v2 directly"
check 'd["v2_reopen_repeatable_zero_bytes"]' "migration is one-way: repeated v2 opens are no-ops"
check 'd["v2_extra_table_refused_zero_bytes"]' "exact-shape: v2 claim + unrelated extra table refused, zero bytes"
check 'd["v1_extra_table_refused_zero_bytes"]' "exact-shape: v1 claim + extra table refused, never migrated"

section "H11: journal ingest contract + exactly-once (PR-2B spec §6/§7/§13)"
run_group "ingest"
check 'd.get("_harness_error") is None' "ingest harness ran clean"
check 'd["empty_dir_noop"]' "S1 empty exchange dir: full pass, zero movement"
check 'd["missing_dir_soft"]' "unreadable exchange dir: soft, zero movement, no degrade"
check 'd["single_valid_exact_rows"]' "S2 one valid file: EXACT sanitized rows + sentinel folds"
check 'd["replay_committed_noop"]' "S4 committed file replayed from disk: exact no-op"
check 'd["sequential_files"]' "S3 strictly sequential files consume in order"
check 'd["header_only_zero_records"]' "header-only batch applies with NULL ts + zero counts"
check 'd["gap_counted_once"]' "S5 gap counted exactly once per missing seq at discovery"
check 'd["late_fill_ignored"]' "S5 late-arriving skipped seqs never retract/re-count"
check 'd["malformed_names_ignored"]' "S6 malformed filenames invisible: no consume, no reject"
check 'd["reject_codes_exact"]' "S7-S12 all 8 rejection classes settle with exact sanitized codes"
check 'd["rejects_zero_rows"]' "rejected files write ZERO rows (fail-closed, never partial)"
check 'd["rejects_settle_once"]' "S12 rejected file settles ONCE: replay counts nothing"
check 'd["valid_around_rejects_no_gap"]' "valid files around rejects continue with NO gap"
check 'd["reject_symlink_not_regular"]' "S9 symlinked exchange file rejected (Linux gate)"
check 'd["apply_fail_blocks_no_leapfrog"]' "S13 DB apply failure: blocks, no leapfrog, degraded code"
check 'd["apply_fail_retry_completes"]' "S13 fixed retry consumes the range in order"
check 'd["ingest_failure_isolated_from_publish"]' "journal failure never kills the sample write path"
check 'd["precommit_crash_zero_rows_zero_terminal"]' "S14 crash pre-commit: zero rows AND zero terminal"
check 'd["post_crash_reapply_exactly_once"]' "S14 after crash the file applies EXACTLY once"
check 'd["reopen_20x_no_duplicate"]' "S14 20x process-restart loop: not one duplicate row"
check 'd["db_checks_reject_free_text"]' "closed CHECKs + FK deny free text/fp/cross-field/orphans"
check 'd["credential_like_never_persisted"]' "S20 sentinel payload leaves only an enum code"
check 'd["journal_status_shape"]' "journal_status is the fixed sanitized surface"
check 'd["closed_db_ingest_soft"]' "closed DB: ingest entry point never raises"
check 'd["no_exchange_dir_clean"]' "no exchange dir configured: fully inert, never degrades"
check 'd["enum_mirrors_match"]' "DB enum CHECKs mirror the frozen PR-2A grammar exactly"
check 'd["audit_code_enum_exact_vs_contract"]' "audit.code enum == contract disposition-code literals + gap marker"
check 'd["audit_db_rejects_arbitrary_code"]' "audit table: enum accepted, free-text/overlong/credential denied"
check 'd["audit_unknown_code_settlement_refused"]' "unknown-code settlement fails closed: no rows, blocked, degraded"

section "H12: ingest cadence + heartbeat + unified retention (PR-2B §9/§14)"
run_group "ingest2"
check 'd.get("_harness_error") is None' "ingest2 harness ran clean"
check 'd["publish_drives_ingest"]' "publication drives the ingest pass (no extra daemon)"
check 'd["sub_interval_no_second_pass"]' "inside the 10s gate no second pass runs"
check 'd["interval_pass_consumes"]' "past the interval the pass consumes"
check 'd["ingest_runs_without_sample_write"]' "ingest gate fires even when the publish writes no rows"
check 'd["hb_absent"]' "reader heartbeat absent -> absent"
check 'd["hb_fresh"]' "179s-old heartbeat: fresh, seq + age reported"
check 'd["hb_boundary_exactly_180_fresh"]' "exactly 180s is fresh (frozen >180 rule)"
check 'd["hb_stale_181"]' "181s-old heartbeat -> stale"
check 'd["hb_invalid_forms"]' "garbage/dir/oversize heartbeat all invalid"
check 'd["hb_threshold_echoed"]' "staleness threshold echoed as the frozen 180s"
check 'd["hb_stale_never_blocks_ingest"]' "stale reader hb never blocks event ingest"
check 'd["missing_state_row_fails_closed"]' "continuity row deleted: fail closed, never repaired"
check 'd["missing_state_row_reopen_refused"]' "same DB refused at reopen, zero bytes mutated"
check 'd["time_retention_journal_keeps_state"]' "time retention prunes runs/events/audit, NEVER state"
check 'd["size_global_suffix_4_sources"]' "size pruning keeps the GLOBAL newest suffix across 4 tables"
check 'd["size_all_sources_pruned"]' "every source table participates in the one timeline"
check 'd["size_newest_survives"]' "newest evidence in the merged order always survives"
check 'd["size_below_target"]' "pruning converges below the injected target size"
check 'd["size_no_orphans_state_survives"]' "FK cascade leaves no orphan events; state row intact"
check 'd["journal_status_surface"]' "status surface carries terminal + counters + reader"
check 'd["status_payload_sanitized"]' "status JSON echoes no paths and no sentinels"
check 'd["swallow_sample_write_succeeds"]' "same-publish: journal fail + sample write lands, still enabled"
check 'd["swallow_health_not_swallowed"]' "same-publish: degraded + ingest code SURVIVE the successful write"
check 'd["swallow_no_leapfrog_no_terminal"]' "same-publish: blocked seq held, terminal unmoved, no leapfrog"
check 'd["swallow_recovers_on_clean_pass"]' "next clean ingest pass is the recovery: healthy again"
check 'd["struct_publish_not_raised_sample_lands"]' "R2-B1: structural refusal never raises; P1 sample lands"
check 'd["struct_journal_state_frozen"]' "R2-B1: journal state frozen: no rows, no terminal, never recreated"
check 'd["struct_health_degraded_sanitized"]' "R2-B1: degraded surfaces the sanitized schema code only"
check 'd["struct_second_publish_still_contained"]' "R2-B1: containment repeats on later publishes; P1 keeps writing"
check 'd["struct_never_recreated"]' "R2-B1: missing continuity row is failed closed, never repaired"
check 'd["undecodable_no_escape_sample_lands"]' "R2-B2: undecodable file never escapes on_publish; P1 lands"
check 'd["undecodable_rejected_once_frozen_code"]' "R2-B2: frozen terminal rejection settles exactly once"
check 'd["undecodable_zero_rows_higher_seq_continues"]' "R2-B2: zero rows for the hostile seq; higher seqs continue"
check 'd["undecodable_hostile_bytes_absent"]' "R2-B2: hostile bytes absent from DB and status surface"
check 'd["undecodable_next_seq_still_correct"]' "R2-B2: subsequent valid sequence stays exactly-once"

printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && [ "$PASS" -eq "$EXPECTED_PASS" ] || { printf '  (failures, or a section did not fully run)\n'; exit 1; }
printf '  ALL GREEN (incident history / issue #33 P1)\n'
