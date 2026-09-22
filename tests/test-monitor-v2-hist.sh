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
EXPECTED_PASS=130
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
import os
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


# ---------------------------------------------------------------- groups ----
def group_storage():
    out = {}
    h = tmp_history()
    h.open()
    h.on_publish(snap(), 1)
    tables = {r[0] for r in h._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    out["schema_created"] = {"meta", "timeline_samples",
                             "device_protocol_states"}.issubset(tables)
    meta = dict(h._conn.execute("SELECT key, value FROM meta"))
    out["meta_schema_version_1"] = meta.get("schema_version") == "1"
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
    # ---- B3 (review): the gate is STRICT in BOTH directions ----
    # every non-exact-v1 DECLARATION is refused fail-closed, and the
    # refusal must not touch a single byte of the existing DB.
    b = tmp_history()
    b.open()
    b.on_publish(snap(), 1)
    b.close()
    db = os.path.join(b._tmpdir, "diagnostics", "history.sqlite3")
    refused_all = intact_all = preserved = True
    for raw in ("0", "-1", "2", "abc", "1.0", ""):
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
    out["b3_nonv1_all_refused"] = refused_all
    out["b3_refusal_zero_bytes"] = intact_all and preserved
    # restore the exact-v1 shape, THEN prove an accepted re-open is pure
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    # an ACCEPTED exact-v1 re-open also mutates zero bytes (read-only gate)
    b2 = IncidentHistory(os.path.join(b._tmpdir, "diagnostics"), "b3ok",
                         clock=lambda: T0 + 60.0)
    before = raw_db_bytes(b)
    b2.open()
    out["b3_exact_v1_reopen_readonly"] = (b2.health()["enabled"]
                                          and raw_db_bytes(b) == before)
    b2.close()
    # meta CLAIMS v1 but the v1 tables are gone: refuse, never adopt via
    # CREATE-IF-NOT-EXISTS (and the shape must stay exactly as found)
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE timeline_samples")
    conn.execute("DROP TABLE device_protocol_states")
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
    with it, zero thread exceptions and zero recorded failures."""
    out = {}
    t = [T0]
    h = tmp_history(clock=lambda: t[0], heartbeat_interval=1e9)
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
                if n % 90 == 0:
                    h._cleanup("stress")   # retention/VACUUM under readers
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
    h2.close()
    return out


GROUPS = {"storage": group_storage, "privacy": group_privacy,
          "cadence": group_cadence, "restart": group_restart,
          "retention": group_retention, "failure": group_failure,
          "concurrency": group_concurrency,
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
check 'd["schema_created"]' "meta + timeline_samples + device_protocol_states exist"
check 'd["meta_schema_version_1"]' "meta carries explicit schema_version=1"
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
check 'd["b3_nonv1_all_refused"]' "B3: version 0/-1/2/malformed/empty ALL refused fail-closed"
check 'd["b3_refusal_zero_bytes"]' "B3: refusal mutates ZERO bytes and preserves the tampered value"
check 'd["b3_exact_v1_reopen_readonly"]' "B3: accepted exact-v1 re-open mutates zero bytes"
check 'd["b3_metaless_orphan_refused"]' "B3: meta claiming v1 with stripped tables is refused"
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

printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && [ "$PASS" -eq "$EXPECTED_PASS" ] || { printf '  (failures, or a section did not fully run)\n'; exit 1; }
printf '  ALL GREEN (incident history / issue #33 P1)\n'
