#!/usr/bin/env bash
# Monitor v2 Phase E4-Diag regression tests -- client-side Mihomo failover
# forensics (issue #41).
#
# Every test drives monitor-v2/mihomo/diag.py with fixture payloads shaped
# like the real Mihomo REST contract, or through the audited E4 failure
# paths. The suite guards the closed record schema, delay==0 preservation
# (the E4-H1 fix), the connection-chain leak wall (ids/IPs/metadata never
# leave the parser), GET-only and no-active-probe behavior, diff-event
# dedup, JSONL tail state recovery, size-shift rotation, 0600/0700
# discipline and the once-mode exit-code matrix.
#
# Deterministic on git-bash AND Linux: OS-divergent code paths are exercised
# through the same explicit-platform / monkeypatch technique as the E4 suite,
# so the EXPECTED_PASS gate holds identically on both hosts.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
MIHOMO="$ROOT/monitor-v2/mihomo"
DIAG="$MIHOMO/diag.py"
PY="${PYTHON:-python3}"
export MIHOMO_FIX="$MIHOMO/fixtures"
export MIHOMO_DIR="$MIHOMO"

PASS=0
FAIL=0
# The gate at the bottom of this file fails unless exactly this many
# assertions ran AND passed, so unreachable sections can never fake success.
EXPECTED_PASS=165
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -gt 0 ]; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -eq 0 ]; then pass "$3"; else fail "$3 (forbidden: $1)"; fi; }

mihomo_py() {
    PYTHONPATH="$MIHOMO" "$PY" -c "$1"
}

field() {
    printf '%s' "$1" | PYTHONPATH="$MIHOMO" "$PY" -c \
        'import json,sys; obj=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"
}

# Shared fixture-transport preamble. Like the real transport the fake exposes
# get(path) only -- no method parameter -- and it RECORDS every path so the
# GET-only / no-active-probe mandate is checked behaviorally, not just textually.
PY_PREAMBLE='
import json, os, sys
FIX = os.environ["MIHOMO_FIX"]
def load(name): return open(os.path.join(FIX, name), "rb").read()
class FakeTransport:
    def __init__(self, routes, fail=None):
        self.routes = routes; self.fail = fail or {}; self.calls = []
    def get(self, path):
        self.calls.append(path)
        if path in self.fail: raise self.fail[path]
        return self.routes[path]
def routes(version="e4diag-version-ok.json", proxies="e4diag-proxies-outer-auto.json",
           conns="e4diag-connections-pre.json", v_status=200, p_status=200, c_status=200):
    r = {}
    if version: r["/version"] = (v_status, load(version))
    if proxies: r["/proxies"] = (p_status, load(proxies))
    if conns: r["/connections"] = (c_status, load(conns))
    return r
'

section "static checks"
if "$PY" -m py_compile "$DIAG" 2>"$TMP/py.err"; then pass "py_compile diag.py"; else fail "py_compile diag.py: $(cat "$TMP/py.err")"; fi
FIX_OK=1
for f in e4diag-version-ok.json e4diag-proxies-outer-auto.json \
         e4diag-proxies-outer-reality-pin.json e4diag-proxies-reality-dead.json \
         e4diag-connections-pre.json e4diag-connections-post.json \
         e4diag-connections-idle-null.json e4diag-connections-wrong-type.json \
         e4diag-proxies-obs-overflow.json e4diag-unauthorized.json; do
    [ -f "$MIHOMO_FIX/$f" ] || FIX_OK=0
done
[ "$FIX_OK" = "1" ] && pass "all E4-Diag fixtures present" || fail "E4-Diag fixture files missing"
if grep -qE "'(PUT|POST|DELETE|PATCH)'|\"(PUT|POST|DELETE|PATCH)\"" "$DIAG" 2>/dev/null; then
    fail "control-plane method literal found in diag.py (read-only mandate)"
else
    pass "diag.py contains no control-plane method literal"
fi
if grep -qE '/proxies/[^"]*delay|delay\?|/delay"' "$DIAG" 2>/dev/null; then
    fail "active delay-probe path found in diag.py"
else
    pass "diag.py never builds an active delay-probe path"
fi
if grep -qE '/traffic|read_stream_sample' "$DIAG" 2>/dev/null; then
    fail "diag.py must not touch the /traffic stream (bounded GETs only)"
else
    pass "diag.py issues no streaming endpoints"
fi
if grep -qE 'urlopen|import requests|http\.server' "$DIAG" 2>/dev/null; then
    fail "forbidden HTTP usage in diag.py"
else
    pass "diag.py goes through the audited E4 transport only"
fi
if grep -q 'from model import' "$DIAG" 2>/dev/null; then
    fail "diag.py must not import the enrichment model (ENRICHMENT_KEYS invariant)"
else
    pass "diag.py imports nothing from model.py's enrichment layer"
fi
if grep -qE 'incident_history|client-management|api_bridge' "$DIAG" 2>/dev/null; then
    fail "diag.py references forbidden server-side / PR#43 modules"
else
    pass "diag.py references no server-side or PR #43 module"
fi
if grep -q 'token=' "$DIAG" 2>/dev/null; then
    fail "query-string credential pattern found in diag.py"
else
    pass "no query-string credential pattern in diag.py"
fi
if grep -q '0o600' "$DIAG" && grep -q '0o700' "$DIAG"; then
    pass "evidence file/dir permission literals 0600/0700 present"
else
    fail "evidence permission literals missing"
fi
if grep -qE 'password|passwd|api_key|apikey' "$DIAG" 2>/dev/null; then
    fail "unexpected credential vocabulary in diag.py"
else
    pass "no credential vocabulary in diag.py beyond the reused secret contract"
fi

section "cadence clamp (decision area 4: 30-60s, fail-safe 30)"
out="$(mihomo_py '
import json, diag
print(json.dumps({"low": diag.clamp_interval(5), "high": diag.clamp_interval(300),
                  "mid": diag.clamp_interval(45), "junk": diag.clamp_interval("x"),
                  "nan": diag.clamp_interval(float("nan")),
                  "none": diag.clamp_interval(None),
                  "edge_lo": diag.clamp_interval(30), "edge_hi": diag.clamp_interval(60)}))
')"
assert_eq "$(field "$out" 'obj["low"]')" "30.0" "below-floor interval clamps to 30s"
assert_eq "$(field "$out" 'obj["high"]')" "60.0" "above-ceiling interval clamps to 60s"
assert_eq "$(field "$out" 'obj["mid"]')" "45.0" "in-range interval kept"
assert_eq "$(field "$out" 'obj["junk"]')" "30.0" "unparseable interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["nan"]')" "30.0" "NaN interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["none"]')" "30.0" "None interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["edge_lo"]')" "30.0" "30s edge kept"
assert_eq "$(field "$out" 'obj["edge_hi"]')" "60.0" "60s edge kept"

section "timestamp parsing"
out="$(mihomo_py '
import json, diag
def iso(v):
    d = diag.parse_ts(v)
    return d.isoformat() if d else None
print(json.dumps({
    "zulu": iso("2026-09-22T12:00:00Z"),
    "offset": iso("2026-09-22T14:00:00+02:00"),
    "naive": iso("2026-09-22T12:00:00"),
    "epoch": iso(1790078400),
    "bool": iso(True),
    "junk": iso("not-a-time"),
    "none": iso(None),
    "empty": iso("  ")}))
')"
assert_eq "$(field "$out" 'obj["zulu"]')" "2026-09-22T12:00:00+00:00" "Zulu timestamps normalize to UTC"
assert_eq "$(field "$out" 'obj["offset"]')" "2026-09-22T12:00:00+00:00" "offset timestamps convert"
assert_eq "$(field "$out" 'obj["naive"]')" "2026-09-22T12:00:00+00:00" "naive timestamps assumed UTC"
assert_eq "$(field "$out" 'obj["epoch"]')" "2026-09-22T12:00:00+00:00" "epoch numbers accepted"
assert_eq "$(field "$out" 'obj["bool"]')" "None" "bool is never a timestamp"
assert_eq "$(field "$out" 'obj["junk"]')" "None" "garbage timestamp -> None"
assert_eq "$(field "$out" 'obj["none"]')" "None" "None timestamp -> None"
assert_eq "$(field "$out" 'obj["empty"]')" "None" "blank timestamp -> None"

section "history parsing: delay==0 preserved (the E4-H1 fix)"
out="$(mihomo_py '
import json, diag
entries, dropped = diag.parse_history([
    {"time": "2026-09-22T11:59:00Z", "delay": 90},
    {"time": "2026-09-22T12:00:00Z", "delay": 0},
    {"time": "2026-09-22T12:01:00Z", "delay": 88}])
keep5, _ = diag.parse_history([{"delay": i} for i in range(5)])
mixed, mixed_drop = diag.parse_history([
    {"delay": "abc"}, None, "x", {"delay": 44},
    {"time": "2026-09-22T12:00:30Z", "delay": 55}])
bool_delay, bool_drop = diag.parse_history([{"delay": True}])
bad_input, bad_drop = diag.parse_history("not-a-list")
empty, empty_drop = diag.parse_history([])
print(json.dumps({
    "d_values": [e["d"] for e in entries],
    "zero_kept": any(e["d"] == 0 and e["t"] for e in entries),
    "times": [e["t"] for e in entries],
    "keep5": [e["d"] for e in keep5],
    "mixed": [e["d"] for e in mixed], "mixed_drop": mixed_drop,
    "mixed_ts": [e["t"] for e in mixed],
    "bool": (bool_delay, bool_drop),
    "bad_input": (bad_input, bad_drop),
    "empty": (empty, empty_drop)}))
')"
assert_eq "$(field "$out" 'obj["d_values"]')" "[90, 0, 88]" "raw delay sequence kept in order"
assert_eq "$(field "$out" 'obj["zero_kept"]')" "True" "delay==0 stays a FAILED PROBE with its timestamp, not null"
assert_eq "$(field "$out" 'obj["times"][0]')" "2026-09-22T11:59:00+00:00" "history timestamps normalized to UTC"
assert_eq "$(field "$out" 'obj["keep5"]')" "[2, 3, 4]" "only the last 3 entries are kept"
assert_eq "$(field "$out" 'obj["mixed"]')" "[44, 55]" "malformed history entries dropped individually"
assert_eq "$(field "$out" 'obj["mixed_drop"]')" "3" "each dropped entry counted, never an abort"
assert_eq "$(field "$out" 'obj["mixed_ts"][0]')" "None" "missing time -> null t, entry still kept"
assert_eq "$(field "$out" 'obj["bool"]')" "[[], 1]" "bool delay rejected (never coerced to 1)"
assert_eq "$(field "$out" 'obj["bad_input"]')" "[[], 0]" "non-list history -> empty, no error"
assert_eq "$(field "$out" 'obj["empty"]')" "[[], 0]" "empty history -> empty"

section "proxies whitelist: exactly the closed fields survive"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-outer-auto.json\"))
s = diag.parse_proxies_summary(payload, [\"节点选择\", \"自动选择\", \"GHOST\"])
blob = json.dumps(s, ensure_ascii=False)
gres = {g[\"name\"]: g for g in s[\"groups\"]}
nres = {n[\"name\"]: n for n in s[\"nodes\"]}
print(json.dumps({
    \"usable\": s[\"usable\"],
    \"outer_keys\": sorted(gres[\"节点选择\"].keys()),
    \"outer_type\": gres[\"节点选择\"].get(\"type\"),
    \"outer_now\": gres[\"节点选择\"].get(\"now\"),
    \"ghost\": gres.get(\"GHOST\"),
    \"auto_hist_d\": [e[\"d\"] for e in gres[\"自动选择\"].get(\"hist\", [])],
    \"obs\": s[\"obs\"],
    \"reality_keys\": sorted(nres[\"reality-hk-01\"].keys()),
    \"reality_urls\": nres[\"reality-hk-01\"].get(\"urls\"),
    \"direct_alive\": nres[\"DIRECT\"].get(\"alive\"),
    \"hy2_hist\": [(e[\"d\"], e[\"t\"]) for e in nres[\"hy2-hk-02\"].get(\"hist\", [])],
    \"dropped\": s[\"history_dropped\"],
    \"missing_nodes\": s[\"missing_nodes\"],
    \"ghost_node_keys\": sorted(nres.get(\"reality-hk-03\", {}).keys()),
    \"no_GLOBAL\": \"GLOBAL\" not in blob,
    \"no_junk_fields\": all(t not in blob for t in (\"x-extra-junk\", \"testUrl\", \"hidden\", \"udp\", \"tolo\")),
}))
")"
assert_eq "$(field "$out" 'obj["usable"]')" "True" "contract-shaped payload usable"
assert_eq "$(field "$out" 'obj["outer_keys"]')" "['all', 'name', 'now', 'type']" "group record carries ONLY closed keys"
assert_eq "$(field "$out" 'obj["outer_type"]')" "selector" "group type captured lower-cased (H3 evidence E4 lacks)"
assert_eq "$(field "$out" 'obj["outer_now"]')" "自动选择" "group now captured verbatim, display-only"
assert_eq "$(field "$out" 'obj["ghost"]')" "{'name': 'GHOST', 'error': 'missing'}" "unknown caller group -> error:missing marker"
assert_eq "$(field "$out" 'obj["auto_hist_d"]')" "[120, 0, 88]" "fallback group probe history kept with raw delay 0 (H5)"
assert_eq "$(field "$out" 'obj["obs"]')" "['DIRECT', 'hy2-hk-02', 'reality-hk-01', 'reality-hk-03', '自动选择']" "observed set = members + selections, sorted"
assert_eq "$(field "$out" 'obj["reality_keys"]')" "['alive', 'hist', 'name', 'urls']" "node record carries ONLY closed keys"
assert_eq "$(field "$out" 'obj["reality_urls"]')" "[{'u': 'https://www.gstatic.com/generate_204', 'alive': True, 'hist': [{'d': 88, 't': '2026-09-22T12:01:00+00:00'}]}]" "extra per-test-url history (H4)"
assert_eq "$(field "$out" 'obj["direct_alive"]')" "None" "non-bool alive is UNKNOWN, never True-by-coercion"
assert_eq "$(field "$out" 'obj["hy2_hist"]')" "[[44, None], [55, '2026-09-22T12:00:30+00:00']]" "malformed entries dropped individually from node history"
assert_eq "$(field "$out" 'obj["dropped"]')" "True" "truncation/drop flagged for the err transition"
assert_eq "$(field "$out" 'obj["missing_nodes"]')" "['reality-hk-03']" "member without an entry reported as missing node"
assert_eq "$(field "$out" 'obj["ghost_node_keys"]')" "['alive', 'name']" "missing node record degrades to name+alive:null"
assert_eq "$(field "$out" 'obj["no_GLOBAL"]')" "True" "unnamed groups are never even summarized"
assert_eq "$(field "$out" 'obj["no_junk_fields"]')" "True" "unknown payload fields cannot ride into the record"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-obs-overflow.json\"))
s = diag.parse_proxies_summary(payload, [\"BIG\"])
print(json.dumps({\"obs_len\": len(s[\"obs\"]), \"nodes_len\": len(s[\"nodes\"]),
                  \"dropped\": s[\"history_dropped\"]}))
")"
assert_eq "$(field "$out" 'obj["obs_len"]')" "64" "observed set capped at 64 (cardinality guard)"
assert_eq "$(field "$out" 'obj["nodes_len"]')" "64" "node records stay inside the cap"
assert_eq "$(field "$out" 'obj["dropped"]')" "True" "cap trip flags the truncation note"

section "connections aggregation: counts only, leak wall holds"
out="$(mihomo_py "$PY_PREAMBLE
import datetime, json, diag
payload = json.loads(load(\"e4diag-proxies-reality-dead.json\"))
s = diag.parse_proxies_summary(payload, [\"节点选择\", \"自动选择\"])
current_now = {g[\"name\"]: g.get(\"now\") for g in s[\"groups\"]}
switch = datetime.datetime(2026, 9, 22, 12, 0, 30, tzinfo=datetime.timezone.utc)
conns, malformed = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-post.json\")), s[\"obs\"], s[\"member_of\"],
    current_now, {\"自动选择\": switch})
idle, _ = diag.parse_connections_summary(json.loads(load(\"e4diag-connections-idle-null.json\")), [], {}, {}, {})
wrong, _ = diag.parse_connections_summary(json.loads(load(\"e4diag-connections-wrong-type.json\")), [], {}, {}, {})
missing, _ = diag.parse_connections_summary({\"something\": 1}, [], {}, {}, {})
nosel, _ = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-post.json\")), s[\"obs\"], s[\"member_of\"], current_now, {})
blob = json.dumps(conns, ensure_ascii=False)
print(json.dumps({
    \"conns\": conns, \"malformed\": malformed, \"idle\": idle,
    \"wrong\": wrong, \"missing\": missing, \"nosel_stale\": nosel[\"stale\"],
    \"leak_id\": \"conn-0001\" in blob, \"leak_ip\": \"192.0.2.44\" in blob,
    \"leak_port\": \"55555\" in blob, \"leak_host\": \"internal-secret\" in blob,
    \"leak_meta\": \"metadata\" in blob, \"leak_rule\": \"MATCH\" in blob,
    \"leak_secret\": \"S3CR3T\" in blob}))
")"
assert_eq "$(field "$out" 'obj["conns"]["n"]')" "5" "n counts what the core reported"
assert_eq "$(field "$out" 'obj["conns"]["by_node"]')" "{'hy2-hk-02': 1, 'reality-hk-01': 2, '自动选择': 3}" "chains attributed per observed node only"
assert_eq "$(field "$out" 'obj["conns"]["multi"]')" "3" "multi = chains through >=2 observed nodes"
assert_eq "$(field "$out" 'obj["conns"]["stale"]')" "2" "stale_after_switch counts old-path conns predating the switch (H6)"
assert_eq "$(field "$out" 'obj["malformed"]')" "2" "non-dict connection entries counted, never fatal"
assert_eq "$(field "$out" 'obj["idle"]')" "{'n': 0, 'by_node': {}, 'multi': 0, 'stale': 0}" "official idle shape null -> 0"
assert_eq "$(field "$out" 'obj["wrong"]')" "None" "wrong type -> unknown, never disguised as idle"
assert_eq "$(field "$out" 'obj["missing"]')" "None" "missing key -> unknown"
assert_eq "$(field "$out" 'obj["nosel_stale"]')" "0" "no proven switch -> nothing claimed stale (evidence, not guess)"
for needle in leak_id leak_ip leak_port leak_host leak_meta leak_rule leak_secret; do
    assert_eq "$(field "$out" "obj[\"$needle\"]")" "False" "connection evidence free of $needle"
done

section "one clean cycle: closed records over fixtures"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\", \"自动选择\", \"GHOST\"],
                      secret=\"S3CR3T-CTRL-KEY\", transport=t,
                      clock=lambda: 1790078400.0)
state = diag.new_state()
recs, flags = c.collect_cycle(state, 30.0)
run = [r for r in recs if r[\"k\"] == \"run\"][0]
sample = [r for r in recs if r[\"k\"] == \"sample\"][0]
blob = \"\".join(diag.encode_record(r).decode() for r in recs)
errkinds = [r[\"c\"] for r in recs if r[\"k\"] == \"err\"]
print(json.dumps({
    \"calls\": t.calls, \"keys\": sorted(run.keys()),
    \"version\": run[\"mihomo_version\"], \"groups\": run[\"groups\"],
    \"interval\": run[\"interval_s\"], \"cver\": run[\"collector_ver\"],
    \"host\": run[\"url_host\"], \"port\": run[\"url_port\"],
    \"sample_keys\": sorted(sample.keys()),
    \"rid_ok\": bool(__import__(\"re\").fullmatch(\"[0-9a-f]{32}\", run[\"run_id\"])), \"same_run_id\": all(r[\"run_id\"] == run[\"run_id\"] for r in recs),
    \"ts\": run[\"ts\"], \"flags\": flags, \"errkinds\": errkinds,
    \"leak_id\": \"conn-0001\" in blob, \"leak_ip\": \"192.0.2.44\" in blob,
    \"leak_secret\": \"S3CR3T-CTRL-KEY\" in blob, \"leak_total\": \"downloadTotal\" in blob,
    \"delay0\": \"\\\"d\\\":0\" in blob}))
")"
assert_eq "$(field "$out" 'obj["calls"]')" "['/version', '/proxies', '/connections']" "exactly three bounded GETs, no stream, no active probe"
assert_eq "$(field "$out" 'obj["keys"]')" "['collector_ver', 'groups', 'interval_s', 'k', 'mihomo_version', 'run_id', 'ts', 'url_host', 'url_port']" "run record is a closed schema"
assert_eq "$(field "$out" 'obj["version"]')" "1.18.7" "mihomo_version from /version"
assert_eq "$(field "$out" 'obj["groups"]')" "['节点选择', '自动选择', 'GHOST']" "caller-named groups echoed (topology-free)"
assert_eq "$(field "$out" 'obj["interval"]')" "30.0" "clamped interval recorded"
assert_eq "$(field "$out" 'obj["cver"]')" "1" "collector_ver present for schema evolution"
assert_eq "$(field "$out" 'obj["host"]')" "127.0.0.1" "loopback host recorded"
assert_eq "$(field "$out" 'obj["port"]')" "9090" "port recorded"
assert_eq "$(field "$out" 'obj["sample_keys"]')" "['conns', 'groups', 'k', 'nodes', 'obs', 'run_id', 'ts']" "sample record is a closed schema"
assert_eq "$(field "$out" 'obj["same_run_id"]')" "True" "every record of a run carries the same non-secret run_id"
assert_eq "$(field "$out" 'obj["ts"]')" "2026-09-22T12:00:00+00:00" "ts stamped from the clock, UTC"
assert_eq "$(field "$out" 'obj["flags"]["sample_ok"]')" "True" "clean cycle produced a sample"
assert_eq "$(field "$out" 'obj["flags"]["api_failed"]')" "False" "clean cycle not flagged failed"
assert_eq "$(field "$out" 'obj["errkinds"]')" "['group_missing', 'node_missing', 'history_truncated']" "subject transitions recorded once each on first sight"
assert_eq "$(field "$out" 'obj["delay0"]')" "True" "delay==0 preserved raw in the written record (H1)"
for needle in leak_id leak_ip leak_secret leak_total; do
    assert_eq "$(field "$out" "obj[\"$needle\"]")" "False" "cycle bytes free of $needle"
done
assert_eq "$(field "$out" 'obj["rid_ok"]')" "True" "run_id is 32 lowercase hex"

section "incident sequence: pin -> auto switch -> dead, events fire once"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\", \"自动选择\"],
                      transport=t, clock=lambda: C[0])
C = [1790078400.0]
c.clock = lambda: C[0]
state = diag.new_state()
r1, _ = c.collect_cycle(state, 30.0)
t.routes = routes(proxies=\"e4diag-proxies-reality-dead.json\",
                  conns=\"e4diag-connections-post.json\")
C[0] += 30
r2, f2 = c.collect_cycle(state, 30.0)
t.routes = routes(proxies=\"e4diag-proxies-reality-dead.json\", conns=\"e4diag-connections-pre.json\")
C[0] += 30
r3, f3 = c.collect_cycle(state, 30.0)
C[0] += 30
r4, _ = c.collect_cycle(diag.new_state(), 30.0)  # cold process, same routes: seeds, no events
ev = lambda recs, k: [r for r in recs if r[\"k\"] == k]
conns2 = [r for r in r2 if r[\"k\"] == \"sample\"][0][\"conns\"]
errs2 = [r[\"c\"] for r in r2 if r[\"k\"] == \"err\"]
print(json.dumps({
    \"sel1\": len(ev(r1, \"sel\")), \"alive1\": len(ev(r1, \"alive\")),
    \"sel2\": [(r[\"g\"], r[\"from\"], r[\"to\"]) for r in ev(r2, \"sel\")],
    \"alive2\": [(r[\"node\"], r[\"from\"], r[\"to\"]) for r in ev(r2, \"alive\")],
    \"stale2\": conns2[\"stale\"], \"n2\": conns2[\"n\"],
    \"errs2\": errs2,
    \"sel3\": len(ev(r3, \"sel\")), \"alive3\": len(ev(r3, \"alive\")),
    \"kinds3\": sorted(set(r[\"k\"] for r in r3)),
    \"sel4\": len(ev(r4, \"sel\")), \"alive4\": len(ev(r4, \"alive\")),
    \"malformed_err\": [r for r in r2 if r[\"k\"] == \"err\" and r[\"c\"] == \"api_malformed\"][0][\"n\"]}))
")"
assert_eq "$(field "$out" 'obj["sel1"]')" "0" "first cycle only seeds: no fabricated selection event"
assert_eq "$(field "$out" 'obj["alive1"]')" "0" "first cycle only seeds: no fabricated alive event"
assert_eq "$(field "$out" 'obj["sel2"]')" "[['自动选择', 'reality-hk-01', 'hy2-hk-02']]" "selection_changed fires exactly once with from/to (H3/H6 anchor)"
assert_eq "$(field "$out" 'obj["alive2"]')" "[['reality-hk-01', True, False]]" "alive_flipped fires exactly once"
assert_eq "$(field "$out" 'obj["stale2"]')" "2" "old-path connections proven stale after the switch (H6)"
assert_eq "$(field "$out" 'obj["n2"]')" "5" "connection count observed alongside the stale evidence"
assert_eq "$(field "$out" 'obj["sel3"]')" "0" "unchanged selection: zero selection events"
assert_eq "$(field "$out" 'obj["alive3"]')" "0" "unchanged aliveness: zero alive events (dedup, no storm)"
assert_eq "$(field "$out" 'obj["kinds3"]')" "['sample']" "a quiet cycle writes exactly one sample record"
assert_eq "$(field "$out" 'obj["sel4"]')" "0" "cold process seeds from payload, never replays events"
assert_eq "$(field "$out" 'obj["alive4"]')" "0" "cold process alive-diff starts clean"
assert_contains "api_malformed" "$(field "$out" 'obj["errs2"]')" "malformed connection entries surfaced as api_malformed"
assert_eq "$(field "$out" 'obj["malformed_err"]')" "1" "first occurrence counted as n=1"

section "subject errors persist quietly; cycle errors carry the n-ledger"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"GHOST\"], transport=t,
                      clock=lambda: C[0])
C = [1790078400.0]
c.clock = lambda: C[0]
state = diag.new_state()
r1, _ = c.collect_cycle(state, 30.0)
counts = []
for i in range(9):
    C[0] += 30
    recs, _ = c.collect_cycle(state, 30.0)
    counts.append(len([r for r in recs if r[\"k\"] == \"err\"]))
print(json.dumps({\"first\": len([r for r in r1 if r[\"k\"] == \"err\"]),
                  \"later\": counts}))
")"
assert_eq "$(field "$out" 'obj["first"]')" "1" "missing group recorded once on transition"
assert_eq "$(field "$out" 'obj["later"]')" "[0, 0, 0, 0, 0, 0, 0, 0, 0]" "persistent group_missing never storms the 30s log (10 cycles -> 1 record)"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes(), fail={\"/version\": diag.TransportError(\"ConnectionResetError: boom\")})
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\"],
                      secret=\"S3CR3T-CTRL-KEY\", transport=t,
                      clock=lambda: C[0])
C = [1790078400.0]
c.clock = lambda: C[0]
state = diag.new_state()
r1, f1 = c.collect_cycle(state, 30.0)
r2, f2 = c.collect_cycle(state, 30.0)
C[0] += 30
t.routes = routes()   # recovery
t.fail = {}           # the transport only fails while told to; drop it for r3+
r3, f3 = c.collect_cycle(state, 30.0)
r4, _ = c.collect_cycle(state, 30.0)
C[0] += 30
t.routes = routes(version=\"e4diag-unauthorized.json\", proxies=None, conns=None, v_status=401)
r5, f5 = c.collect_cycle(state, 30.0)
print(json.dumps({
    \"kinds1\": sorted(set(r[\"k\"] for r in r1)), \"failed1\": f1[\"api_failed\"],
    \"c1\": r1[0][\"c\"], \"n1\": r1[0][\"n\"], \"n2\": r2[0][\"n\"],
    \"run3\": sorted(set(r[\"k\"] for r in r3)), \"failed3\": f3[\"api_failed\"],
    \"n4_after_reset\": [r[\"c\"] for r in r4 if r[\"k\"] == \"err\"],
    \"c5\": r5[0][\"c\"], \"n5\": r5[0][\"n\"],
    \"detail5\": r5[0][\"detail\"], \"redacted\": \"[redacted]\" in r5[0][\"detail\"],
    \"leak5\": \"S3CR3T-CTRL-KEY\" in json.dumps(r5)}))
")"
assert_eq "$(field "$out" 'obj["kinds1"]')" "['err']" "unreachable cycle records ONLY a sanitized err line"
assert_eq "$(field "$out" 'obj["failed1"]')" "True" "api_failed surfaced for the exit-code mapping"
assert_eq "$(field "$out" 'obj["c1"]')" "api_unreachable" "transport failure class"
assert_eq "$(field "$out" 'obj["n1"]')" "1" "first unreachable occurrence n=1"
assert_eq "$(field "$out" 'obj["n2"]')" "2" "consecutive cycle increments n (downtime is measurable)"
assert_eq "$(field "$out" 'obj["run3"]')" "['err', 'run', 'sample']" "recovery emits run header + sample; subject notes re-seed, no fabricated gap data"
assert_eq "$(field "$out" 'obj["failed3"]')" "False" "recovered cycle is not flagged"
assert_eq "$(field "$out" 'obj["n4_after_reset"]')" "[]" "clean cycles clear the cycle-error ledger"
assert_eq "$(field "$out" 'obj["c5"]')" "api_malformed" "HTTP 401 classified api_malformed"
assert_eq "$(field "$out" 'obj["n5"]')" "1" "fresh class restarts its own count"
assert_contains "HTTP 401" "$(field "$out" 'obj["detail5"]')" "status kept for diagnosis"
assert_eq "$(field "$out" 'obj["redacted"]')" "True" "secret stripped from err detail via the E4 redaction path"
assert_eq "$(field "$out" 'obj["leak5"]')" "False" "raw secret bytes never reach the record"

section "tail state recovery across restarts (T: state-restart)"
out="$(mihomo_py "$PY_PREAMBLE
import json, os, tempfile, diag
d = diag.ensure_out_dir(os.path.join(tempfile.mkdtemp(), \"evidence\"))
w = diag.DiagWriter(d)
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\", \"自动选择\"], transport=t,
                      clock=lambda: C[0])
C = [1790078400.0]
c.clock = lambda: C[0]
state = diag.new_state()
r1, _ = c.collect_cycle(state, 30.0); w.write(r1)
t.routes = routes(proxies=\"e4diag-proxies-reality-dead.json\",
                  conns=\"e4diag-connections-post.json\")
C[0] += 30
r2, _ = c.collect_cycle(state, 30.0); w.write(r2)
# crash simulation: torn final line
with open(w.path, \"ab\") as f: f.write(b\"{\\\"k\\\":\\\"samp\")
C[0] += 30
st2 = diag.load_state(w.path)
c2 = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\", \"自动选择\"],
                       transport=t, clock=lambda: C[0])
r3, _ = c2.collect_cycle(st2, 30.0)
kinds = sorted(set(r[\"k\"] for r in r3))
missing = diag.load_state(os.path.join(tempfile.mkdtemp(), \"nope\", \"diag.jsonl\"))
print(json.dumps({\"group_now\": st2[\"group_now\"], \"node_alive\": st2[\"node_alive\"],
                  \"has_sel_ts\": bool(st2[\"sel_ts\"]), \"kinds3\": kinds,
                  \"fresh\": [missing[\"group_now\"], missing[\"node_alive\"], missing[\"sel_ts\"]],
                  \"rid_len\": len(st2[\"run_id\"]), \"rid_new\": st2[\"run_id\"] != state[\"run_id\"]}))
")"
assert_eq "$(field "$out" 'obj["group_now"]["自动选择"]')" "hy2-hk-02" "selection recovered from the JSONL tail, not a sidecar"
assert_eq "$(field "$out" 'obj["node_alive"]["reality-hk-01"]')" "False" "alive state recovered across a torn final line"
assert_eq "$(field "$out" 'obj["has_sel_ts"]')" "True" "selection-change time recovered (stale math continues)"
assert_eq "$(field "$out" 'obj["kinds3"]')" "['err', 'run', 'sample']" "post-restart identical cycle duplicates NO sel/alive events; subject notes re-seed once"
assert_eq "$(field "$out" 'obj["rid_new"]')" "True" "restarted process gets a fresh run_id (gaps explicit)"
assert_eq "$(field "$out" 'obj["rid_len"]')" "32" "run_id is 32-hex"
assert_eq "$(field "$out" 'obj["fresh"]')" "[{}, {}, {}]" "missing evidence file yields clean state, never a crash"

section "writer: 0700 dir, 0600 file, size-shift rotation, visible failure"
out="$(mihomo_py "$PY_PREAMBLE
import json, os, stat, tempfile, diag
res = {}
diag._WINDOWS = False  # exercise the POSIX chmod/fchmod paths deterministically
# (a) fresh dir is created 0700 (makedirs mode), existing dir re-tightened via chmod
base = tempfile.mkdtemp()
p = os.path.join(base, \"ev\")
diag.ensure_out_dir(p)
res[\"made\"] = os.path.isdir(p)
seen = {}
real_chmod = os.chmod
def spy_chmod(path, mode): seen[\"mode\"] = mode
diag.os.chmod = spy_chmod
diag.ensure_out_dir(p)
diag.os.chmod = real_chmod
res[\"chmod_mode\"] = seen.get(\"mode\")
# (b) symlinked out dir refused fail-closed
link = os.path.join(base, \"link\")
real_islink = os.path.islink
diag.os.path.islink = lambda path: path == link
try:
    diag.ensure_out_dir(link); res[\"symlink\"] = \"ACCEPTED\"
except diag.ConfigurationError:
    res[\"symlink\"] = \"rejected\"
finally:
    diag.os.path.islink = real_islink
# (c) open flags/mode: O_APPEND|O_WRONLY|O_CREAT|O_NOFOLLOW, 0o600; fchmod 0o600
calls = {}
real_open, real_fchmod = os.open, getattr(os, \"fchmod\", None)
def spy_open(path, flags, mode=0o600, *a, **k):
    calls[\"flags\"], calls[\"mode\"] = flags, mode
    return real_open(path, flags, mode, *a, **k)
diag.os.open = spy_open
w = diag.DiagWriter(diag.ensure_out_dir(os.path.join(base, \"ev2\")))
w.write([{\"k\": \"err\", \"c\": \"config\", \"detail\": \"x\"}])
diag.os.open = real_open
want = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, \"O_NOFOLLOW\", 0)
res[\"flags\"] = calls.get(\"flags\") == want
res[\"open_mode\"] = calls.get(\"mode\") == 0o600
if real_fchmod:
    seen2 = {}
    diag.os.fchmod = lambda fd, m: seen2.__setitem__(\"m\", m)
    w.write([{\"k\": \"err\"}])
    diag.os.fchmod = real_fchmod
    res[\"fchmod_mode\"] = seen2.get(\"m\") == 0o600
else:
    res[\"fchmod_mode\"] = \"n/a\"
# (d) size-shift rotation with the real minimum bound
w2 = diag.DiagWriter(diag.ensure_out_dir(os.path.join(base, \"rot\")), max_mb=0.0039, files=3)
big = {\"k\": \"err\", \"c\": \"config\", \"detail\": \"z\" * 3000}
for i in range(5):
    w2.write([big])
res[\"rotated\"] = os.path.exists(w2.path + \".1\")
res[\"shifted\"] = os.path.exists(w2.path + \".2\")
res[\"main_exists\"] = os.path.exists(w2.path)
import os as _os
res[\"bounded\"] = _os.path.getsize(w2.path) < 4096 + 3000
# (e) rotation on a virgin dir is a no-op, not an error
try:
    diag.DiagWriter(diag.ensure_out_dir(os.path.join(base, \"virgin\"))).rotate()
    res[\"virgin\"] = \"ok\"
except Exception as e:
    res[\"virgin\"] = type(e).__name__
# (f) storage failure is an exception with path context but no record bytes
real_open2 = os.open
diag.os.open = lambda *a, **k: (_ for _ in ()).throw(OSError(28, \"No space left\"))
try:
    w.write([{\"k\": \"err\", \"detail\": \"PAYLOAD-MUST-NOT-LEAK\"}])
    res[\"wrapped\"] = \"ACCEPTED\"
except diag.StorageError as e:
    res[\"wrapped\"] = \"wrapped\" if \"PAYLOAD\" not in str(e) and \"diag.jsonl\" in str(e) else \"BAD\"
finally:
    diag.os.open = real_open2
print(json.dumps(res))
")"
assert_eq "$(field "$out" 'obj["made"]')" "True" "missing out dir created fail-closed"
assert_eq "$(field "$out" 'obj["chmod_mode"]')" "448" "existing out dir re-tightened to 0700 (448 = 0o700)"
assert_eq "$(field "$out" 'obj["symlink"]')" "rejected" "symlinked out dir refused (evidence cannot be redirected)"
assert_eq "$(field "$out" 'obj["flags"]')" "True" "append-only flags incl. O_NOFOLLOW"
assert_eq "$(field "$out" 'obj["open_mode"]')" "True" "evidence file opened as 0600"
assert_eq "$(field "$out" 'obj["fchmod_mode"]')" "True" "pre-existing file tightened via fchmod 0600"
assert_eq "$(field "$out" 'obj["rotated"]')" "True" "size cap shifts diag.jsonl to .1"
assert_eq "$(field "$out" 'obj["shifted"]')" "True" "rotation is a numeric shift (.1 -> .2)"
assert_eq "$(field "$out" 'obj["main_exists"]')" "True" "fresh main file after rotation"
assert_eq "$(field "$out" 'obj["bounded"]')" "True" "main file stays under the bound (rotation is the retention bound)"
assert_eq "$(field "$out" 'obj["virgin"]')" "ok" "rotating a never-written chain is a no-op"
assert_eq "$(field "$out" 'obj["wrapped"]')" "wrapped" "storage failure -> StorageError naming the path, never the record bytes"

section "CLI: exit-code matrix and resident escalation (decision area 9)"
out="$(mihomo_py "$PY_PREAMBLE
import contextlib, io, json, os, tempfile, diag
res = {}
base = tempfile.mkdtemp()
def run(argv, routes_=None, fail_=None, write_boom=False):
    t = FakeTransport(routes_ or routes(), fail=fail_)
    real_write = diag.DiagWriter.write
    if write_boom:
        diag.DiagWriter.write = lambda self, recs: (_ for _ in ()).throw(
            diag.StorageError(\"cannot write diag.jsonl (OSError)\"))
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                res_call = diag.main(argv, transport=t, clock=lambda: 1790078400.0)
            except SystemExit as e:
                res_call = e.code
    finally:
        diag.DiagWriter.write = real_write
    return res_call, out.getvalue(), err.getvalue()

rc, so, se = run([\"--group\", \"G\"])
res[\"missing_outdir\"] = rc
d = os.path.join(base, \"ok\")
rc, so, se = run([\"--out-dir\", d, \"--group\", \"节点选择\"])
res[\"ok\"] = rc
res[\"summary_ok\"] = json.loads(so)[\"api_failed\"]
res[\"file_written\"] = os.path.exists(os.path.join(d, \"diag.jsonl\"))
rc, so, se = run([\"--out-dir\", os.path.join(base, \"out\"), \"--group\", \"GHOST\"])
res[\"ghost_rc\"] = rc   # group missing but API healthy: observation, not failure
rc, so, se = run([\"--out-dir\", os.path.join(base, \"bad\"), \"--url\", \"http://192.168.1.9:9090\"])
res[\"nonloopback\"] = rc
rc, so, se = run([\"--out-dir\", os.path.join(base, \"dead\"), \"--group\", \"G\", \"--url\", \"http://10.0.0.1:9090\"])
res[\"badhost\"] = rc
rc, so, se = run([\"--out-dir\", os.path.join(base, \"unreach\"), \"--group\", \"G\"],
                 fail_={\"/version\": diag.TransportError(\"ConnectionRefusedError: refused\")})
res[\"api_rc\"] = rc
rc, so, se = run([\"--out-dir\", os.path.join(base, \"stor\"), \"--group\", \"节点选择\"], write_boom=True)
res[\"storage_rc\"] = rc
rc, so, se = run([\"--out-dir\", os.path.join(base, \"both\"), \"--group\", \"G\"],
                 fail_={\"/version\": diag.TransportError(\"boom\")}, write_boom=True)
res[\"both_rc\"] = rc
rc, so, se = run([\"--resident\", \"--out-dir\", os.path.join(base, \"res\"), \"--group\", \"G\"],
                 fail_={\"/version\": diag.TransportError(\"boom\")}, write_boom=True)
res[\"resident_storage\"] = rc   # storage failure must escalate, never loop blind
rc, so, se = run([\"--out-dir\", os.path.join(base, \"cyc\"), \"--group\", \"节点选择\", \"--interval\", \"5\"])
head = open(os.path.join(base, \"cyc\", \"diag.jsonl\"), encoding=\"utf-8\").readline()
res[\"interval_clamped\"] = json.loads(head)[\"interval_s\"]
rc, so, se = run([\"--prune-now\", \"--out-dir\", os.path.join(base, \"cyc\")])
res[\"prune\"] = rc
res[\"pruned\"] = os.path.exists(os.path.join(base, \"cyc\", \"diag.jsonl.1\"))
print(json.dumps(res))
")"
assert_eq "$(field "$out" 'obj["missing_outdir"]')" "2" "--out-dir is required fail-closed (argparse exit 2)"
assert_eq "$(field "$out" 'obj["ok"]')" "0" "clean once-run exits 0"
assert_eq "$(field "$out" 'obj["summary_ok"]')" "False" "summary reports no API failure"
assert_eq "$(field "$out" 'obj["file_written"]')" "True" "evidence file created under the requested dir"
assert_eq "$(field "$out" 'obj["ghost_rc"]')" "0" "a missing group is evidence, not a process failure"
assert_eq "$(field "$out" 'obj["nonloopback"]')" "2" "non-loopback URL -> config exit 2, fail-closed"
assert_eq "$(field "$out" 'obj["badhost"]')" "2" "any non-loopback host rejected before a byte leaves"
assert_eq "$(field "$out" 'obj["api_rc"]')" "3" "API unreachable -> visible exit 3, never silent 0"
assert_eq "$(field "$out" 'obj["storage_rc"]')" "4" "storage failure -> exit 4"
assert_eq "$(field "$out" 'obj["both_rc"]')" "5" "API + storage both failing -> exit 5"
assert_eq "$(field "$out" 'obj["resident_storage"]')" "4" "resident mode escalates storage failure instead of looping blind"
assert_eq "$(field "$out" 'obj["interval_clamped"]')" "30.0" "--interval 5 clamped to the 30s floor at the CLI edge"
assert_eq "$(field "$out" 'obj["prune"]')" "0" "prune-now rotates without touching the API"
assert_eq "$(field "$out" 'obj["pruned"]')" "True" "prune-now shifted the chain"

section "transport incapability + leak wall end to end (written bytes)"
out="$(mihomo_py "$PY_PREAMBLE
import json, os, tempfile, diag
t = FakeTransport(routes(proxies=\"e4diag-proxies-reality-dead.json\",
                          conns=\"e4diag-connections-post.json\"),
                  fail={})
c = diag.DiagCollector(\"http://127.0.0.1:9090\", [\"节点选择\", \"自动选择\"],
                      secret=\"S3CR3T-CTRL-KEY\", transport=t,
                      clock=lambda: 1790078400.0)
w = diag.DiagWriter(diag.ensure_out_dir(tempfile.mkdtemp()))
state = diag.new_state()
for i in range(3):
    recs, _ = c.collect_cycle(state, 30.0)
    w.write(recs)
blob = open(w.path, encoding=\"utf-8\").read()
verbs = {\"possible\": [m for m in (\"PUT\", \"POST\", \"PATCH\", \"DELETE\")
                       if hasattr(t, m.lower()) or hasattr(diag.HttpTransport, m.lower())]}
print(json.dumps({
    \"verbs\": verbs[\"possible\"],
    \"calls\": sorted(set(t.calls)),
    \"delay_path\": any(\"delay\" in p for p in t.calls),
    \"traffic_path\": any(\"traffic\" in p for p in t.calls),
    \"leak_id\": \"conn-0001\" in blob, \"leak_ip\": \"192.0.2.44\" in blob,
    \"leak_port\": \"55555\" in blob, \"leak_host\": \"internal-secret\" in blob,
    \"leak_uid\": '\"uid\"' in blob, \"leak_secret\": \"S3CR3T\" in blob,
    \"leak_start\": '\"start\"' in blob,
    \"total_counters\": \"downloadTotal\" in blob or \"uploadTotal\" in blob,
    \"lines\": len(blob.splitlines())}))
")"
assert_eq "$(field "$out" 'obj["verbs"]')" "[]" "no mutation verb exists on any transport used here"
assert_eq "$(field "$out" 'obj["calls"]')" "['/connections', '/proxies', '/version']" "only the three bounded GET paths ever requested"
assert_eq "$(field "$out" 'obj["delay_path"]')" "False" "no active delay probe requested"
assert_eq "$(field "$out" 'obj["traffic_path"]')" "False" "no /traffic stream touched"
assert_eq "$(field "$out" 'obj["leak_id"]')" "False" "connection ids absent from every written byte"
assert_eq "$(field "$out" 'obj["leak_ip"]')" "False" "destination IP absent from every written byte"
assert_eq "$(field "$out" 'obj["leak_port"]')" "False" "destination port absent from every written byte"
assert_eq "$(field "$out" 'obj["leak_host"]')" "False" "host metadata absent from every written byte"
assert_eq "$(field "$out" 'obj["leak_uid"]')" "False" "process/uid metadata absent"
assert_eq "$(field "$out" 'obj["leak_secret"]')" "False" "controller secret absent from the evidence file"
assert_eq "$(field "$out" 'obj["total_counters"]')" "False" "cumulative counters stay server-side truth (display-only traffic policy)"
out="$(mihomo_py 'import diag, json; print(json.dumps(sorted(diag.ERR_CLASSES)))')"
assert_eq "$out" '["api_malformed", "api_unreachable", "config", "group_missing", "history_truncated", "node_missing", "rotation_failed", "storage_failed"]' "failure-class enum is exactly the closed design set"

printf '\n'
if [ "$FAIL" -eq 0 ] && [ "$PASS" -eq "$EXPECTED_PASS" ]; then
    printf 'ALL GREEN: %s/%s E4-Diag checks passed\n' "$PASS" "$EXPECTED_PASS"
    exit 0
fi
printf 'FAILURES: %s failed, %s passed (gate expects exactly %s)\n' "$FAIL" "$PASS" "$EXPECTED_PASS"
exit 1
