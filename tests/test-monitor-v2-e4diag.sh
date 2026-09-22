#!/usr/bin/env bash
# Monitor v2 Phase E4-Diag regression tests -- client-side Mihomo failover
# forensics (issue #41, reviewed design 5777726169 + review 5778693980).
#
# Every test drives monitor-v2/mihomo/diag.py with fixture payloads shaped
# like the real Mihomo REST contract, or through injected failure paths on
# the real storage primitives. The suite guards: the CLOSED FOUR-TYPE record
# schema (sample/selection_changed/alive_flipped/collector -- no run/header
# record), run-local causal diffs with gap suppression (B2), HMAC test-url
# hashing with a race-safe 0600 key (B1), raw-safe per-node connection
# aggregates with no stale inference (B3), fail-closed storage primitives
# exercised through their real injection surfaces (B4), the final-encoded-
# byte 64 KiB record ceiling with structural trimming (B5), whole-cycle
# collector accounting (B6), delay==0 preservation with strict-integer
# rejection of floats (the E4-H1 fix), the leak wall (ids/IPs/hosts/rules/
# secrets/exception text/HTTP bodies never leave the parser), GET-only
# behavior and the once-mode exit-code matrix (0/2/3/4/5).
#
# Deterministic on git-bash AND Linux: OS-divergent code paths are exercised
# through explicit platform flags and injectable attributes, so the
# EXPECTED_PASS gate at the bottom holds identically on both hosts.
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
EXPECTED_PASS=343
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
# GET-only / no-active-probe mandate is checked behaviorally, not just
# textually. Routes return the (status, body) tuple the audited client
# transport returns, so _get()'s status mapping is exercised for real.
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

# Deterministic HMAC key (bytes([1])*32) and caller-named group list used
# across the parser sections.
KEY='bytes([1]) * 32'
GROUPS_OUTER="['节点选择', '自动选择']"

section "static checks: read-only mandate"
if "$PY" -m py_compile "$DIAG" 2>"$TMP/py.err"; then pass "py_compile diag.py"; else fail "py_compile diag.py: $(cat "$TMP/py.err")"; fi
FIX_OK=1
for f in e4diag-version-ok.json e4diag-proxies-outer-auto.json \
         e4diag-proxies-outer-reality-pin.json e4diag-proxies-reality-dead.json \
         e4diag-connections-pre.json e4diag-connections-post.json \
         e4diag-connections-idle-null.json e4diag-connections-wrong-type.json \
         e4diag-proxies-hostile.json e4diag-proxies-many-groups.json \
         e4diag-proxies-obs-overflow.json e4diag-unauthorized.json; do
    [ -f "$MIHOMO_FIX/$f" ] || FIX_OK=0
done
[ "$FIX_OK" = "1" ] && pass "all 12 E4-Diag fixtures present" || fail "E4-Diag fixture files missing"
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
if grep -qE '"/(traffic|rules|logs|memory|configs|restart|upgrade|providers|dns)"' "$DIAG" 2>/dev/null; then
    fail "an endpoint outside /version /proxies /connections is referenced"
else
    pass "only the three bounded GET endpoint literals exist"
fi
if grep -qF '"/connections/' "$DIAG" 2>/dev/null; then
    fail "per-connection control path found in diag.py"
else
    pass "no per-connection control/close path"
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
if grep -qE 'incident_history|client-management|client_management|api_bridge' "$DIAG" 2>/dev/null; then
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
if grep -qE '\bredact\(' "$DIAG" 2>/dev/null; then
    fail "redaction path found: diag must never carry detail text at all"
else
    pass "no redact() call: there is no detail channel to leak through"
fi
if grep -q 'TransportError' "$DIAG" 2>/dev/null; then
    fail "TransportError is referenced: exception classes must not reach evidence"
else
    pass "no TransportError reference (exception text cannot be described)"
fi
if grep -q 'probe.example.invalid' "$DIAG" || grep -q 'cp.cloudflare.com' "$DIAG"; then
    fail "a concrete health-check test URL is hard-coded in diag.py"
else
    pass "no concrete test URLs in code (raw URLs exist only transiently)"
fi

section "static checks: closed schema constants"
if grep -qF 'RECORD_TYPES = ("sample", "selection_changed", "alive_flipped", "collector")' "$DIAG"; then
    pass "RECORD_TYPES is exactly the closed four-type tuple"
else
    fail "RECORD_TYPES four-type literal missing"
fi
if grep -qF 'COLLECTOR_CODES = ("mihomo_unreachable", "proxies_invalid", "connections_invalid",' "$DIAG" \
   && grep -qF '"group_missing", "node_missing", "storage_error")' "$DIAG"; then
    pass "COLLECTOR_CODES is exactly the closed six-code enum"
else
    fail "COLLECTOR_CODES closed enum literal missing"
fi
if grep -qF 'CODE_SCOPE = {"mihomo_unreachable": "version", "proxies_invalid": "proxies",' "$DIAG" \
   && grep -qF '"connections_invalid": "connections", "group_missing": "proxies",' "$DIAG" \
   && grep -qF '"node_missing": "proxies", "storage_error": "storage"}' "$DIAG"; then
    pass "CODE_SCOPE is a closed code->scope map (scope, not detail text)"
else
    fail "CODE_SCOPE literal missing"
fi
if grep -qF 'RECORD_MAX_BYTES = 64 * 1024' "$DIAG"; then pass "record ceiling constant 64 KiB"; else fail "RECORD_MAX_BYTES missing"; fi
if grep -qF 'SCHEMA_V = 1' "$DIAG"; then pass "schema version constant v=1"; else fail "SCHEMA_V missing"; fi
if grep -qF 'MAX_GROUPS = 8' "$DIAG" && grep -qF 'OBS_CAP = 64' "$DIAG" && grep -qF 'MAX_MEMBERS = 32' "$DIAG"; then
    pass "cardinality bounds: 8 groups / 64 nodes / 32 members"
else
    fail "cardinality bound constants missing"
fi
if grep -qF 'NAME_MAX_BYTES = 128' "$DIAG" && grep -qF 'HIST_KEEP = 8' "$DIAG" && grep -qF 'NODE_URL_KEEP = 8' "$DIAG"; then
    pass "name/history/test-url caps present"
else
    fail "name/history/test-url caps missing"
fi
if grep -qF 'DELAY_MAX = 1000000' "$DIAG"; then pass "delay plausible bound constant"; else fail "DELAY_MAX missing"; fi
if grep -qF 'MIN_INTERVAL = 30.0' "$DIAG" && grep -qF 'MAX_INTERVAL = 60.0' "$DIAG"; then
    pass "cadence clamp constants 30-60s"
else
    fail "cadence clamp constants missing"
fi
if grep -qF 'MIN_FILES = 2' "$DIAG" && grep -qF 'MAX_FILES = 32' "$DIAG" \
   && grep -qF 'MAX_FILE_MB = 8' "$DIAG" && grep -qF 'TOTAL_MB_BUDGET = 32' "$DIAG"; then
    pass "rotation argument bounds 2..32 files / <=8 MiB / <=32 MiB budget"
else
    fail "rotation argument bounds missing"
fi
if grep -qF 'EXIT_CONFIG = 2' "$DIAG" && grep -qF 'EXIT_API = 3' "$DIAG" \
   && grep -qF 'EXIT_STORAGE = 4' "$DIAG" && grep -qF 'EXIT_BOTH = 5' "$DIAG"; then
    pass "visible exit-code constants 0/2/3/4/5"
else
    fail "exit-code constants missing"
fi
if grep -qF 'HMAC_KEY_BYTES = 32' "$DIAG" && grep -qF 'TEST_ID_HEX = 16' "$DIAG"; then
    pass "HMAC key size and test-id width constants"
else
    fail "HMAC constants missing"
fi
if grep -q 'hmac.new(' "$DIAG" && grep -q 'hashlib.sha256' "$DIAG"; then
    pass "test ids derive from HMAC-SHA256"
else
    fail "HMAC-SHA256 derivation missing"
fi
if grep -qF 'os.O_EXCL' "$DIAG"; then pass "key creation uses O_EXCL (race-safe, never overwrites)"; else fail "O_EXCL missing"; fi
if grep -qF 'uuid.uuid4().hex' "$DIAG"; then pass "run id is a fresh uuid4 hex per process"; else fail "uuid4 run id missing"; fi
if grep -qF '_write_all(fd, blob' "$DIAG"; then pass "record batches go through the write-until-complete loop"; else fail "_write_all on the write path missing"; fi
if grep -qF 'signal.SIGTERM' "$DIAG"; then pass "resident mode installs a SIGTERM handler"; else fail "SIGTERM handling missing"; fi
if grep -qF 'prune_now' "$DIAG"; then pass "prune-now rotation path exists"; else fail "prune-now path missing"; fi
if grep -q 'from client import' "$DIAG" && grep -qF 'parse_controller_url' "$DIAG" && grep -qF 'clamp_timeout' "$DIAG"; then
    pass "E4 audited pieces reused (URL clamp timeout), not forked"
else
    fail "client.py reuse surface missing"
fi

section "static residue: old five-kind schema must be gone"
for bad in '"k":' '"t": "run"' '"obs":' '"conns":' '"hist":' '"urls":' '"stale":' \
           '"detail":' '"g":' '"c":' '"n":' '"d":' '"u":' '"e":' \
           run_id COLLECTOR_VER collector_ver ERR_CLASSES err_kinds \
           api_unreachable api_malformed rotation_failed history_truncated \
           interval_s url_host url_port '"config"' sel_ts; do
    if grep -qF -- "$bad" "$DIAG"; then
        fail "residue of the old schema remains: $bad"
    else
        pass "no residue: $bad"
    fi
done
for bad in 'load_state' 'tail_state' 'sidecar' 'member_of'; do
    if grep -qF -- "$bad" "$DIAG"; then
        fail "residue of removed state-recovery design remains: $bad"
    else
        pass "no residue: $bad"
    fi
done

section "cadence + CLI argument validation (fail-safe, fail-closed)"
out="$(mihomo_py '
import json, diag
print(json.dumps({"low": diag.clamp_interval(5), "high": diag.clamp_interval(300),
                  "mid": diag.clamp_interval(45), "junk": diag.clamp_interval("x"),
                  "nan": diag.clamp_interval(float("nan")),
                  "none": diag.clamp_interval(None),
                  "edge_lo": diag.clamp_interval(30), "edge_hi": diag.clamp_interval(60),
                  "near_lo": diag.clamp_interval(29.9)}))
')"
assert_eq "$(field "$out" 'obj["low"]')" "30.0" "below-floor interval clamps to 30s"
assert_eq "$(field "$out" 'obj["high"]')" "60.0" "above-ceiling interval clamps to 60s"
assert_eq "$(field "$out" 'obj["mid"]')" "45.0" "in-range interval kept"
assert_eq "$(field "$out" 'obj["junk"]')" "30.0" "unparseable interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["nan"]')" "30.0" "NaN interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["none"]')" "30.0" "None interval fails safe to 30s"
assert_eq "$(field "$out" 'obj["edge_lo"]')" "30.0" "30s edge kept"
assert_eq "$(field "$out" 'obj["edge_hi"]')" "60.0" "60s edge kept"
assert_eq "$(field "$out" 'obj["near_lo"]')" "30.0" "29.9s clamped up to the floor"

out="$(mihomo_py '
import json, diag
res = {}
res["ok"] = list(diag.validate_rotation_args(4, 4))
res["edge"] = list(diag.validate_rotation_args(8, 4))   # 8*4 = 32 == budget edge
try: diag.validate_rotation_args("x", 4); res["junk"] = "ACCEPTED"
except diag.ConfigurationError: res["junk"] = "rejected"
try: diag.validate_rotation_args(0, 4); res["zero"] = "ACCEPTED"
except diag.ConfigurationError: res["zero"] = "rejected"
try: diag.validate_rotation_args(9, 4); res["bigfile"] = "ACCEPTED"
except diag.ConfigurationError: res["bigfile"] = "rejected"
try: diag.validate_rotation_args(4, 1); res["fewfiles"] = "ACCEPTED"
except diag.ConfigurationError: res["fewfiles"] = "rejected"
try: diag.validate_rotation_args(4, 33); res["manyfiles"] = "ACCEPTED"
except diag.ConfigurationError: res["manyfiles"] = "rejected"
try: diag.validate_rotation_args(8, 8); res["budget"] = "ACCEPTED"   # 64 > 32 MiB
except diag.ConfigurationError: res["budget"] = "rejected"
print(json.dumps(res))
')"
assert_eq "$(field "$out" 'obj["ok"]')" "[4.0, 4]" "default rotation arguments accepted"
assert_eq "$(field "$out" 'obj["edge"]')" "[8.0, 4]" "8 MiB x 4 files sits exactly on the budget"
assert_eq "$(field "$out" 'obj["junk"]')" "rejected" "non-numeric rotation args rejected, not silently defaulted"
assert_eq "$(field "$out" 'obj["zero"]')" "rejected" "zero-size file cap rejected"
assert_eq "$(field "$out" 'obj["bigfile"]')" "rejected" "per-file cap 8 MiB enforced"
assert_eq "$(field "$out" 'obj["fewfiles"]')" "rejected" "at least 2 files (rotation requires a shifted copy)"
assert_eq "$(field "$out" 'obj["manyfiles"]')" "rejected" "32-file retention ceiling enforced"
assert_eq "$(field "$out" 'obj["budget"]')" "rejected" "total evidence budget 32 MiB enforced"

out="$(mihomo_py '
import json, diag
res = {}
try: diag.validate_cli_groups([]); res["empty"] = "ACCEPTED"
except diag.ConfigurationError as e: res["empty"] = "required" if "at least one" in str(e) else "BAD"
try: diag.validate_cli_groups(["G%d" % i for i in range(9)]); res["many"] = "ACCEPTED"
except diag.ConfigurationError: res["many"] = "rejected"
try: diag.validate_cli_groups(["bad\x01ctrl"]); res["ctrl"] = "ACCEPTED"
except diag.ConfigurationError: res["ctrl"] = "rejected"
try: diag.validate_cli_groups(["  padded  "]); res["pad"] = "ACCEPTED"
except diag.ConfigurationError: res["pad"] = "rejected"
try: diag.validate_cli_groups(["x" * 129]); res["long"] = "ACCEPTED"
except diag.ConfigurationError: res["long"] = "rejected"
res["ok"] = diag.validate_cli_groups(["节点选择", "自动选择"])
print(json.dumps(res))
')"
assert_eq "$(field "$out" 'obj["empty"]')" "required" "zero --group is a misconfiguration refused at the CLI"
assert_eq "$(field "$out" 'obj["many"]')" "rejected" "more than 8 --group values rejected"
assert_eq "$(field "$out" 'obj["ctrl"]')" "rejected" "control characters in --group rejected"
assert_eq "$(field "$out" 'obj["pad"]')" "rejected" "padded --group refused (names stored verbatim, not silently trimmed)"
assert_eq "$(field "$out" 'obj["long"]')" "rejected" "over-128-byte --group refused"
assert_eq "$(field "$out" 'obj["ok"]')" "['节点选择', '自动选择']" "valid caller-named groups pass through verbatim"

section "timestamps: Z-form normalization everywhere"
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
    "empty": iso("  "),
    "utc_iso": diag.utc_iso(1790078400.0),
    "utc_epoch": diag.utc_iso(0),
    "iso_z_none": diag.iso_z(None)}))
')"
assert_eq "$(field "$out" 'obj["zulu"]')" "2026-09-22T12:00:00+00:00" "Zulu timestamps normalize to UTC"
assert_eq "$(field "$out" 'obj["offset"]')" "2026-09-22T12:00:00+00:00" "offset timestamps convert"
assert_eq "$(field "$out" 'obj["naive"]')" "2026-09-22T12:00:00+00:00" "naive timestamps assumed UTC"
assert_eq "$(field "$out" 'obj["epoch"]')" "2026-09-22T12:00:00+00:00" "epoch numbers accepted"
assert_eq "$(field "$out" 'obj["bool"]')" "None" "bool is never a timestamp"
assert_eq "$(field "$out" 'obj["junk"]')" "None" "garbage timestamp -> None"
assert_eq "$(field "$out" 'obj["none"]')" "None" "None timestamp -> None"
assert_eq "$(field "$out" 'obj["empty"]')" "None" "blank timestamp -> None"
assert_eq "$(field "$out" 'obj["utc_iso"]')" "2026-09-22T12:00:00Z" "record ts is second-precision Z form (design section 6)"
assert_eq "$(field "$out" 'obj["utc_epoch"]')" "1970-01-01T00:00:00Z" "epoch stamps Z form"
assert_eq "$(field "$out" 'obj["iso_z_none"]')" "None" "absent time stays null"

section "history parsing: delay==0 kept, floats rejected (B5 + the E4-H1 fix)"
out="$(mihomo_py '
import json, diag
entries, dropped, soft = diag.parse_history([
    {"time": "2026-09-22T12:00:00Z", "delay": 42},
    {"time": "2026-09-22T12:00:10Z", "delay": 1.0},
    {"time": "2026-09-22T12:00:20Z", "delay": 0},
    {"time": "2026-09-22T12:00:30Z", "delay": 44.5},
    {"delay": 7},
    {"time": "not-a-time", "delay": 9},
    {"time": "2026-09-22T11:00:30+02:00", "delay": 120}])
one, one_drop, one_soft = diag.parse_history([{"delay": 1.0}])
b, b_drop, _ = diag.parse_history([{"delay": True}])
neg, neg_drop, _ = diag.parse_history([{"delay": -5}])
big, big_drop, _ = diag.parse_history([{"delay": 1000001}])
bad, bad_drop, bad_soft = diag.parse_history("not-a-list")
empt, e_drop, e_soft = diag.parse_history([])
tail, t_drop, t_soft = diag.parse_history([{"time": "2026-09-22T12:00:00Z", "delay": i}
                                           for i in range(12)])
print(json.dumps({
    "delays": [e["delay_ms"] for e in entries],
    "times": [e["ts"] for e in entries],
    "dropped": dropped, "soft": soft,
    "float_only": (one, one_drop, one_soft),
    "bool_only": (b, b_drop),
    "negative": (neg, neg_drop),
    "over_bound": (big, big_drop),
    "bad_input": (bad, bad_drop, bad_soft),
    "empty": (empt, e_drop, e_soft),
    "tail_len": len(tail), "tail_first": tail[0]["delay_ms"]}))
')"
assert_eq "$(field "$out" 'obj["delays"]')" "[42, 0, 7, 9, 120]" "delay==0 stays a FAILED PROBE kept raw, never coerced away"
assert_eq "$(field "$out" 'obj["times"][1]')" "2026-09-22T12:00:20Z" "the zero-delay entry keeps its timestamp as evidence"
assert_eq "$(field "$out" 'obj["times"][4]')" "2026-09-22T09:00:30Z" "+02:00 history times normalize to Z form"
assert_eq "$(field "$out" 'obj["dropped"]')" "2" "float delays (1.0 AND 44.5) dropped and COUNTED, never silently truncated to int"
assert_eq "$(field "$out" 'obj["soft"]')" "2" "missing/garbage ts keeps the delay with ts null, counted soft-invalid"
assert_eq "$(field "$out" 'obj["float_only"]')" "[[], 1, 0]" "1.0 is not a probe result: rejected, not coerced to 1"
assert_eq "$(field "$out" 'obj["bool_only"]')" "[[], 1]" "bool delay rejected (never coerced to 1)"
assert_eq "$(field "$out" 'obj["negative"]')" "[[], 1]" "negative delay is not plausible evidence"
assert_eq "$(field "$out" 'obj["over_bound"]')" "[[], 1]" "delay above DELAY_MAX dropped"
assert_eq "$(field "$out" 'obj["bad_input"]')" "[[], 0, 0]" "non-list history -> empty, no error"
assert_eq "$(field "$out" 'obj["empty"]')" "[[], 0, 0]" "empty history -> empty"
assert_eq "$(field "$out" 'obj["tail_len"]')" "8" "history tail capped at 8 entries"
assert_eq "$(field "$out" 'obj["tail_first"]')" "4" "the cap keeps the NEWEST entries"

section "safe_name: bounded display names, controls refused"
out="$(mihomo_py '
import json, diag
print(json.dumps({
    "nonstr": diag.safe_name(42),
    "none": diag.safe_name(None),
    "pad": diag.safe_name("  ok-node  "),
    "blank": diag.safe_name("   "),
    "ctrl": diag.safe_name("bad\x01ctrl"),
    "c1": diag.safe_name("bad\x85ctrl"),
    "long": diag.safe_name("x" * 130),
    "edge128": diag.safe_name("y" * 128),
    "cjk": diag.safe_name("节点选择"),
    "cjk_bytes": diag.safe_name("节" * 43)}))
')"
assert_eq "$(field "$out" 'obj["nonstr"]')" "None" "non-string name dropped upstream"
assert_eq "$(field "$out" 'obj["none"]')" "None" "None name dropped"
assert_eq "$(field "$out" 'obj["pad"]')" "ok-node" "surrounding whitespace trimmed"
assert_eq "$(field "$out" 'obj["blank"]')" "None" "blank name refused"
assert_eq "$(field "$out" 'obj["ctrl"]')" "None" "C0 control characters refuse the name"
assert_eq "$(field "$out" 'obj["c1"]')" "None" "C1 control characters refuse the name"
assert_eq "$(field "$out" 'obj["long"]')" "None" "over-128-byte name refused, never truncated into a fake"
assert_eq "$(field "$out" 'obj["edge128"]')" "$(printf 'y%.0s' {1..128})" "128-byte name kept at the edge"
assert_eq "$(field "$out" 'obj["cjk"]')" "节点选择" "CJK display names pass verbatim"
assert_eq "$(field "$out" 'obj["cjk_bytes"]')" "None" "byte bound (not char count) governs: 43 CJK chars = 129 bytes"

section "proxies whitelist: only design-section-4 fields survive (B1/B5)"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-outer-auto.json\"))
s = diag.parse_proxies_summary(payload, $GROUPS_OUTER + [\"GHOST\"], hmac_key=$KEY)
blob = json.dumps(s, ensure_ascii=False)
gres = {g[\"name\"]: g for g in s[\"groups\"]}
nres = {n[\"name\"]: n for n in s[\"nodes\"]}
print(json.dumps({
    \"usable\": s[\"usable\"],
    \"g_keys\": sorted(gres[\"节点选择\"].keys()),
    \"g_type\": gres[\"节点选择\"][\"type\"],
    \"g_now\": gres[\"节点选择\"][\"now\"],
    \"g_members\": gres[\"节点选择\"][\"members\"],
    \"inner_keys\": sorted(gres[\"自动选择\"].keys()),
    \"ghost\": gres[\"GHOST\"],
    \"missing_groups\": s[\"missing_groups\"],
    \"missing_nodes\": s[\"missing_nodes\"],
    \"invalid\": s[\"invalid_fields\"],
    \"truncated\": s[\"truncated\"],
    \"watched\": s[\"watched\"],
    \"node_keys\": sorted(nres[\"reality-hk-01\"].keys()),
    \"reality_delays\": [e[\"delay_ms\"] for e in nres[\"reality-hk-01\"][\"history\"]],
    \"reality_ts0\": nres[\"reality-hk-01\"][\"history\"][1][\"ts\"],
    \"extra_ids\": [e[\"test_id\"] for e in nres[\"reality-hk-01\"][\"extra\"]],
    \"extra_flags\": [(e[\"alive\"], e[\"history\"][0][\"delay_ms\"], e[\"history\"][0][\"ts\"]) for e in nres[\"reality-hk-01\"][\"extra\"]],
    \"direct\": nres[\"DIRECT\"],
    \"hy2\": [(e[\"delay_ms\"], e[\"ts\"]) for e in nres[\"hy2-hk-02\"][\"history\"]],
    \"missing_node\": nres[\"reality-hk-03\"],
    \"no_GLOBAL\": \"GLOBAL\" not in blob,
    \"no_junk\": all(t not in blob for t in (\"x-extra-junk\", \"testUrl\", \"hidden\", \"udp\", \"tolo\")),
    \"no_raw_url\": all(t not in blob for t in (\"probe.example.invalid\", \"cp.cloudflare.com\", \"generate_204\", \"S3CR3T-QUERY\")),
}))
")"
assert_eq "$(field "$out" 'obj["usable"]')" "True" "contract-shaped payload is usable"
assert_eq "$(field "$out" 'obj["g_keys"]')" "['members', 'name', 'now', 'type']" "group record carries ONLY the closed keys (no group history)"
assert_eq "$(field "$out" 'obj["inner_keys"]')" "['members', 'name', 'now', 'type']" "fallback group carries no history either (projection whitelist)"
assert_eq "$(field "$out" 'obj["g_type"]')" "selector" "group type lower-cased"
assert_eq "$(field "$out" 'obj["g_now"]')" "自动选择" "group now captured verbatim (H3 evidence, never inferred)"
assert_eq "$(field "$out" 'obj["g_members"]')" "['DIRECT', 'hy2-hk-02', 'reality-hk-01', '自动选择']" "members sorted, only whitelist fields"
assert_eq "$(field "$out" 'obj["ghost"]')" "{'name': 'GHOST', 'type': None, 'now': None, 'members': []}" "unknown caller group -> closed null record"
assert_eq "$(field "$out" 'obj["missing_groups"]')" "['GHOST']" "missing group surfaced for the collector code"
assert_eq "$(field "$out" 'obj["missing_nodes"]')" "['reality-hk-03']" "member without an entry reported as missing node"
assert_eq "$(field "$out" 'obj["invalid"]')" "3" "invalid fields counted: DIRECT string-alive + hy2 garbage + soft ts"
assert_eq "$(field "$out" 'obj["truncated"]')" "False" "clean-size payload not flagged truncated"
assert_eq "$(field "$out" 'obj["watched"]')" "['DIRECT', 'hy2-hk-02', 'reality-hk-01', 'reality-hk-03', '自动选择']" "watched = members + current selections, sorted (nested inner group included)"
assert_eq "$(field "$out" 'obj["node_keys"]')" "['alive', 'extra', 'history', 'name', 'type']" "node record carries ONLY the closed five keys"
assert_eq "$(field "$out" 'obj["reality_delays"]')" "[90, 0, 88]" "node history keeps raw delay 0 (E4-H1 forensic gold)"
assert_eq "$(field "$out" 'obj["reality_ts0"]')" "2026-09-22T12:00:00Z" "history ts is Z form"
assert_eq "$(field "$out" 'obj["extra_ids"]')" "['55caeee2e2776ee9', '22b231740bc95627']" "test URLs projected to stable 16-hex HMAC ids (B1)"
assert_eq "$(field "$out" 'obj["extra_flags"]')" "[[True, 90, '2026-09-22T12:01:30Z'], [True, 88, '2026-09-22T12:01:00Z']]" "extra keeps alive + capped history (H4)"
assert_eq "$(field "$out" 'obj["direct"]')" "{'name': 'DIRECT', 'type': 'passsthrough', 'alive': None, 'history': [], 'extra': []}" "non-bool alive is UNKNOWN (None), never True-by-coercion"
assert_eq "$(field "$out" 'obj["hy2"]')" "[[44, None], [55, '2026-09-22T12:00:30Z']]" "malformed history entries dropped individually, kept entries in order"
assert_eq "$(field "$out" 'obj["missing_node"]')" "{'name': 'reality-hk-03', 'type': None, 'alive': None, 'history': [], 'extra': []}" "missing node degrades to closed null record"
assert_eq "$(field "$out" 'obj["no_GLOBAL"]')" "True" "unnamed groups are never even summarized"
assert_eq "$(field "$out" 'obj["no_junk"]')" "True" "unknown payload fields cannot ride into the record"
assert_eq "$(field "$out" 'obj["no_raw_url"]')" "True" "raw test URLs never reach the projection (HMAC-only)"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-outer-auto.json\"))
s = diag.parse_proxies_summary(payload, [\"节点选择\"], hmac_key=None)
nres = {n[\"name\"]: n for n in s[\"nodes\"]}
print(json.dumps({\"reality_extra\": nres[\"reality-hk-01\"][\"extra\"],
                  \"watched_len\": len(s[\"watched\"])}))
")"
assert_eq "$(field "$out" 'obj["reality_extra"]')" "[]" "without a key file extra degrades to empty, raw URLs are NEVER a fallback"
assert_eq "$(field "$out" 'obj["watched_len"]')" "4" "only the caller-named group contributes"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-reality-dead.json\"))
s = diag.parse_proxies_summary(payload, $GROUPS_OUTER, hmac_key=$KEY)
nres = {n[\"name\"]: n for n in s[\"nodes\"]}
r = nres[\"reality-hk-01\"]
print(json.dumps({
    \"alive\": r[\"alive\"],
    \"delays\": [e[\"delay_ms\"] for e in r[\"history\"]],
    \"last_ts\": r[\"history\"][-1][\"ts\"],
    \"extra\": [(e[\"test_id\"], e[\"alive\"], e[\"history\"][0][\"delay_ms\"]) for e in r[\"extra\"]],
    \"node_now\": [g[\"now\"] for g in s[\"groups\"]]}))
")"
assert_eq "$(field "$out" 'obj["alive"]')" "False" "H1: node marked dead captured as strict false"
assert_eq "$(field "$out" 'obj["delays"]')" "[90, 0, 88, 0]" "failure cadence keeps BOTH zero probes raw"
assert_eq "$(field "$out" 'obj["last_ts"]')" "2026-09-22T12:02:00Z" "newest dead-probe timestamp preserved"
assert_eq "$(field "$out" 'obj["extra"]')" "[['55caeee2e2776ee9', False, 0], ['22b231740bc95627', False, 0]]" "per-test-url views flip dead too (H4: probe-vs-relay stays visible)"
assert_eq "$(field "$out" 'obj["node_now"]')" "['自动选择', 'hy2-hk-02']" "post-failover selections read raw from both groups"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-hostile.json\"))
s = diag.parse_proxies_summary(payload, [\"G-HOSTILE\"], hmac_key=$KEY)
gres = {g[\"name\"]: g for g in s[\"groups\"]}
nres = {n[\"name\"]: n for n in s[\"nodes\"]}
print(json.dumps({
    \"members\": gres[\"G-HOSTILE\"][\"members\"],
    \"now\": gres[\"G-HOSTILE\"][\"now\"],
    \"invalid\": s[\"invalid_fields\"],
    \"watched\": s[\"watched\"],
    \"ok_hist\": [(e[\"delay_ms\"], e[\"ts\"]) for e in nres[\"ok-node\"][\"history\"]],
    \"good_alive\": nres[\"good-node\"][\"alive\"],
    \"good_hist\": nres[\"good-node\"][\"history\"]}))
")"
assert_eq "$(field "$out" 'obj["members"]')" "['good-node', 'ok-node']" "duplicate + control-char + oversized + padded members refused or deduped, never stored raw"
assert_eq "$(field "$out" 'obj["now"]')" "ok-node" "hostile now kept when valid"
assert_eq "$(field "$out" 'obj["invalid"]')" "6" "every rejected element is COUNTED (ctrl name, long name, 3 bad delays, string alive)"
assert_eq "$(field "$out" 'obj["watched"]')" "['good-node', 'ok-node']" "invalid candidates never enter the watched set"
assert_eq "$(field "$out" 'obj["ok_hist"]')" "[[44, '2026-09-22T12:02:00Z']]" "negative, over-bound and float delays all dropped; the one valid probe survives"
assert_eq "$(field "$out" 'obj["good_alive"]')" "None" "string alive is unknown"
assert_eq "$(field "$out" 'obj["good_hist"]')" "[]" "non-list history yields empty list, not a crash"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
s = diag.parse_proxies_summary(json.loads(load(\"e4diag-proxies-many-groups.json\")),
                               [\"H-GROUP-%d\" % i for i in range(8)], hmac_key=$KEY)
g0 = s[\"groups\"][0]
print(json.dumps({\"ngroups\": len(s[\"groups\"]), \"members\": len(g0[\"members\"]),
                  \"now\": g0[\"now\"],
                  \"watched\": len(s[\"watched\"]), \"nodes\": len(s[\"nodes\"]),
                  \"truncated\": s[\"truncated\"], \"invalid\": s[\"invalid_fields\"]}))
")"
assert_eq "$(field "$out" 'obj["ngroups"]')" "8" "eight watched groups supported"
assert_eq "$(field "$out" 'obj["members"]')" "32" "per-group member cap 32 enforced"
assert_eq "$(field "$out" 'obj["now"]')" "n000" "selection kept"
assert_eq "$(field "$out" 'obj["watched"]')" "64" "watched-node cardinality capped at 64"
assert_eq "$(field "$out" 'obj["nodes"]')" "64" "node records stay inside the cap"
assert_eq "$(field "$out" 'obj["truncated"]')" "True" "cap trip is flagged, never silent"
assert_eq "$(field "$out" 'obj["invalid"]')" "0" "cap-driven truncation is not an invalid field"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
s = diag.parse_proxies_summary(json.loads(load(\"e4diag-proxies-obs-overflow.json\")),
                               [\"BIG\"], hmac_key=$KEY)
print(json.dumps({\"members\": len(s[\"groups\"][0][\"members\"]),
                  \"watched\": len(s[\"watched\"]), \"nodes\": len(s[\"nodes\"]),
                  \"missing\": len(s[\"missing_nodes\"]),
                  \"truncated\": s[\"truncated\"]}))
")"
assert_eq "$(field "$out" 'obj["members"]')" "32" "70-member selector stored as 32"
assert_eq "$(field "$out" 'obj["watched"]')" "32" "watched set follows the member cap"
assert_eq "$(field "$out" 'obj["nodes"]')" "32" "one closed record per watched node"
assert_eq "$(field "$out" 'obj["missing"]')" "32" "absent node entries all reported missing"
assert_eq "$(field "$out" 'obj["truncated"]')" "True" "overflow flagged"

out="$(mihomo_py '
import json, diag
bad = {"proxies": {"G": {"type": "Selector", "now": "bad\x01name", "all": []}}}
s = diag.parse_proxies_summary(bad, ["G"], hmac_key=bytes([1]) * 32)
print(json.dumps({"broken": s["broken_groups"], "invalid": s["invalid_fields"],
                  "usable": s["usable"]}))
')"
assert_eq "$(field "$out" 'obj["broken"]')" "['G']" "a present-but-unusable now marks the chain breaker (B2)"
assert_eq "$(field "$out" 'obj["invalid"]')" "1" "broken now is counted invalid"
assert_eq "$(field "$out" 'obj["usable"]')" "True" "payload still parseable: per-subject break, not global fail"

section "connections: raw-safe per-node aggregates, zero inference (B3)"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
payload = json.loads(load(\"e4diag-proxies-outer-auto.json\"))
s = diag.parse_proxies_summary(payload, $GROUPS_OUTER, hmac_key=$KEY)
watched = s[\"watched\"]
pre, pre_mal = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-pre.json\")), watched)
post, post_mal = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-post.json\")), watched)
idle, _ = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-idle-null.json\")), watched)
wrong, _ = diag.parse_connections_summary(
    json.loads(load(\"e4diag-connections-wrong-type.json\")), watched)
missing, _ = diag.parse_connections_summary({\"downloadTotal\": 1}, watched)
empty, _ = diag.parse_connections_summary({\"connections\": []}, watched)
by = lambda lst: {a[\"node\"]: a for a in lst}
preb, postb, idleb = by(pre), by(post), by(idle)
blob = json.dumps(post, ensure_ascii=False)
needles = [\"conn-0001\", \"conn-0004\", \"192.0.2.44\", \"55555\", \"10.0.0.5\",
           \"internal-secret\", \"S3CR3T\", \"downloadTotal\", \"uploadTotal\",
           \"metadata\", \"MATCH\", \"hidden.example\", \"processPath\", \"\\\"start\\\"\"]
print(json.dumps({
    \"keys\": sorted(pre[0].keys()),
    \"pre_reality\": preb[\"reality-hk-01\"],
    \"pre_auto_count\": preb[\"自动选择\"][\"active_chain_count\"],
    \"post_hy2\": postb[\"hy2-hk-02\"],
    \"post_reality\": postb[\"reality-hk-01\"],
    \"post_auto\": postb[\"自动选择\"],
    \"post_direct\": postb[\"DIRECT\"],
    \"pre_mal\": pre_mal, \"post_mal\": post_mal,
    \"idle_is_none\": idle is None,
    \"idle_reality\": idleb[\"reality-hk-01\"],
    \"wrong\": wrong, \"missing\": missing,
    \"empty_count\": empty[0][\"active_chain_count\"],
    \"agg_nodes\": [a[\"node\"] for a in pre],
    \"watched\": watched,
    \"leaks\": [n for n in needles if n in blob],
}))
")"
assert_eq "$(field "$out" 'obj["keys"]')" "['active_chain_count', 'invalid_start_count', 'newest_start', 'node', 'oldest_start']" "aggregate carries ONLY the reviewed five fields"
assert_eq "$(field "$out" 'obj["pre_reality"]')" "{'node': 'reality-hk-01', 'active_chain_count': 2, 'oldest_start': '2026-09-22T11:50:00Z', 'newest_start': '2026-09-22T11:55:00Z', 'invalid_start_count': 0}" "pre-incident chains attributed per watched node with start window (H6)"
assert_eq "$(field "$out" 'obj["pre_auto_count"]')" "2" "inner automatic group counts its own chains (nested topology, no cross-group guess)"
assert_eq "$(field "$out" 'obj["post_hy2"]')" "{'node': 'hy2-hk-02', 'active_chain_count': 1, 'oldest_start': '2026-09-22T12:05:00Z', 'newest_start': '2026-09-22T12:05:00Z', 'invalid_start_count': 0}" "new post-failover chain on the surviving node"
assert_eq "$(field "$out" 'obj["post_reality"]')" "{'node': 'reality-hk-01', 'active_chain_count': 3, 'oldest_start': '2026-09-22T11:50:00Z', 'newest_start': '2026-09-22T11:55:00Z', 'invalid_start_count': 1}" "start-less connection raises invalid_start_count, never a fake timestamp"
assert_eq "$(field "$out" 'obj["post_auto"]')" "{'node': '自动选择', 'active_chain_count': 4, 'oldest_start': '2026-09-22T11:50:00Z', 'newest_start': '2026-09-22T12:05:00Z', 'invalid_start_count': 1}" "one connection may attribute to several watched nodes on its chain"
assert_eq "$(field "$out" 'obj["post_direct"]')" "{'node': 'DIRECT', 'active_chain_count': 0, 'oldest_start': None, 'newest_start': None, 'invalid_start_count': 0}" "untrafficked watched node stays honest zero"
assert_eq "$(field "$out" 'obj["post_mal"]')" "2" "malformed elements counted separately, never inflating confirmed chains"
assert_eq "$(field "$out" 'obj["pre_mal"]')" "0" "well-formed payload has no malformed residue"
assert_eq "$(field "$out" 'obj["idle_is_none"]')" "False" "connections:null is the official idle shape, not unknown"
assert_eq "$(field "$out" 'obj["idle_reality"]')" "{'node': 'reality-hk-01', 'active_chain_count': 0, 'oldest_start': None, 'newest_start': None, 'invalid_start_count': 0}" "null -> confirmed zeros for every watched node"
assert_eq "$(field "$out" 'obj["wrong"]')" "None" "wrong-typed connections -> unknown, never disguised as idle"
assert_eq "$(field "$out" 'obj["missing"]')" "None" "missing connections key -> unknown"
assert_eq "$(field "$out" 'obj["empty_count"]')" "0" "empty list -> confirmed zero"
assert_eq "$(field "$out" 'obj["agg_nodes"]')" "$(field "$out" 'obj["watched"]')" "aggregates exist exactly for watched nodes (outer selector names never guessed)"
assert_eq "$(field "$out" 'obj["leaks"]')" "[]" "no ids, addresses, ports, hosts, rules, counters or raw start fields in the aggregate"

section "one clean cycle: closed schema, four-type proof, run evidence in the sample"
out="$(mihomo_py "$PY_PREAMBLE
import json, re, diag
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", $GROUPS_OUTER,
                      secret=\"S3CR3T-CTRL-KEY\", transport=t,
                      clock=lambda: 1790078400.0, hmac_key=$KEY)
state = diag.new_state()
recs, flags = c.collect_cycle(state)
blob = \"\".join(diag.encode_record(r).decode() for r in recs)
sample = recs[0]
coll = [r for r in recs if r[\"t\"] == \"collector\"][0]
print(json.dumps({
    \"calls\": t.calls,
    \"kinds\": [r[\"t\"] for r in recs],
    \"sample_keys\": sorted(sample.keys()),
    \"seq1\": sample[\"seq\"],
    \"v\": sample[\"v\"],
    \"api\": sample[\"api_reachable\"],
    \"version\": sample[\"mihomo_version\"],
    \"ts\": sample[\"ts\"],
    \"run_hex\": bool(re.fullmatch(\"[0-9a-f]{32}\", sample[\"run\"])),
    \"same_run\": all(r[\"run\"] == sample[\"run\"] for r in recs),
    \"seq_up\": all(b[\"seq\"] > a[\"seq\"] for a, b in zip(recs, recs[1:])),
    \"statuses\": [sample[\"proxies_status\"], sample[\"connections_status\"]],
    \"invalid\": sample[\"invalid_fields\"],
    \"chains\": sample[\"connection_chains\"],
    \"coll\": {k: coll[k] for k in (\"t\", \"code\", \"scope\", \"count\", \"seq\")},
    \"within_four\": set(r[\"t\"] for r in recs) <= set(diag.RECORD_TYPES),
    \"flags\": flags,
    \"roundtrip\": json.loads(diag.encode_record(sample)) == sample,
    \"canonical\": diag.encode_record(sample).endswith(b\"\\n\") and diag.encode_record(sample).count(b\"\\n\") == 1,
    \"leaks\": [n for n in (\"S3CR3T-CTRL-KEY\", \"conn-0001\", \"127.0.0.1\", \"9090\",
                           \"token\", \"Authorization\") if n in blob],
}))
")"
assert_eq "$(field "$out" 'obj["calls"]')" "['/version', '/proxies', '/connections']" "exactly three bounded GETs, no stream, no active probe"
assert_eq "$(field "$out" 'obj["kinds"]')" "['sample', 'collector']" "clean-but-incomplete cycle: one sample + one collector note"
assert_eq "$(field "$out" 'obj["within_four"]')" "True" "persisted t set is STRICTLY within the four design types (no run record)"
assert_eq "$(field "$out" 'obj["sample_keys"]')" "['api_reachable', 'connection_chains', 'connections_status', 'groups', 'invalid_fields', 'mihomo_version', 'nodes', 'proxies_status', 'run', 'seq', 't', 'truncated', 'ts', 'v']" "sample is the closed 14-key schema"
assert_eq "$(field "$out" 'obj["seq1"]')" "1" "first record of a run is seq 1 (run evidence lives IN the sample)"
assert_eq "$(field "$out" 'obj["v"]')" "1" "schema version stamped on every record"
assert_eq "$(field "$out" 'obj["api"]')" "True" "api_reachable from a live /version"
assert_eq "$(field "$out" 'obj["version"]')" "1.18.7" "mihomo_version kept as bounded display string"
assert_eq "$(field "$out" 'obj["ts"]')" "2026-09-22T12:00:00Z" "ts stamped from the clock, Z form"
assert_eq "$(field "$out" 'obj["run_hex"]')" "True" "run id is 32 lowercase hex"
assert_eq "$(field "$out" 'obj["same_run"]')" "True" "every record of a run carries the same non-secret run id"
assert_eq "$(field "$out" 'obj["seq_up"]')" "True" "seq strictly increases within the run"
assert_eq "$(field "$out" 'obj["statuses"]')" "['ok', 'ok']" "both endpoints report ok"
assert_eq "$(field "$out" 'obj["invalid"]')" "3" "parser counters ride along in the sample"
assert_eq "$(field "$out" 'len(obj["chains"])')" "5" "sample carries one chain aggregate per watched node"
assert_eq "$(field "$out" '[a["active_chain_count"] for a in obj["chains"] if a["node"]=="reality-hk-01"][0]')" "2" "the dead-path node's pre-incident chains are visible raw (H6 evidence, no verdict)"
assert_eq "$(field "$out" 'obj["coll"]["code"]')" "node_missing" "unobserved member recorded via closed code enum"
assert_eq "$(field "$out" 'obj["coll"]["scope"]')" "proxies" "endpoint distinction lives in the bounded scope field"
assert_eq "$(field "$out" 'obj["coll"]["count"]')" "1" "first occurrence counted once"
assert_eq "$(field "$out" 'obj["coll"]["seq"]')" "2" "collector record follows the sample"
assert_eq "$(field "$out" 'obj["flags"]["api_failed"]')" "False" "healthy cycle not flagged"
assert_eq "$(field "$out" 'obj["flags"]["codes"]')" "['node_missing']" "flags expose the whole-cycle code set"
assert_eq "$(field "$out" 'obj["roundtrip"]')" "True" "encoded line round-trips to the exact record"
assert_eq "$(field "$out" 'obj["canonical"]')" "True" "one canonical newline-terminated JSON line"
assert_eq "$(field "$out" 'obj["leaks"]')" "[]" "secret, host, port and connection ids absent from every written byte"

section "incident run: edges fire once, gaps suppress, ledger accounts per cycle (B2/B6)"
out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes())
C = [1790078400.0]
c = diag.DiagCollector(\"http://127.0.0.1:9090\", $GROUPS_OUTER, transport=t,
                      clock=lambda: C[0], hmac_key=$KEY)
state = diag.new_state()
def cyc():
    recs, flags = c.collect_cycle(state)
    C[0] += 30
    return recs, flags
def kinds(recs): return [r[\"t\"] for r in recs]
def sel(recs): return [(r[\"group\"], r[\"from\"], r[\"to\"], r[\"seq\"]) for r in recs if r[\"t\"] == \"selection_changed\"]
def alv(recs): return [(r[\"node\"], r[\"from\"], r[\"to\"], r[\"seq\"]) for r in recs if r[\"t\"] == \"alive_flipped\"]
def col(recs): return [(r[\"code\"], r[\"scope\"], r[\"count\"], r[\"seq\"]) for r in recs if r[\"t\"] == \"collector\"]
r1, _ = cyc()
t.routes = routes(proxies=\"e4diag-proxies-outer-reality-pin.json\")
r2, _ = cyc()
t.routes = routes(proxies=\"e4diag-proxies-reality-dead.json\",
                  conns=\"e4diag-connections-post.json\")
r3, _ = cyc()
t.fail = {\"/proxies\": OSError(\"dial timeout 127.0.0.1:9090\")}
r4, _ = cyc()
t.fail = {}
t.routes = routes(conns=\"e4diag-connections-idle-null.json\")
r5, _ = cyc()
mark = len(t.calls)
t.routes = routes(v_status=500)
r6, f6 = cyc()
calls6 = t.calls[mark:]
mark = len(t.calls)
t.fail = {\"/version\": OSError(\"connection reset\")}
r7, _ = cyc()
t.fail = {}
ledger = dict(state[\"err_counts\"])
t.routes = routes(conns=\"e4diag-connections-idle-null.json\")
state2 = diag.new_state()
r8, _ = c.collect_cycle(state2)
s4 = [r for r in r4 if r[\"t\"] == \"sample\"][0]
s6 = [r for r in r6 if r[\"t\"] == \"sample\"][0]
s8 = r8[0]
allrecs = r1 + r2 + r3 + r4 + r5 + r6 + r7
keysets = sorted({tuple(sorted(r.keys())) for r in allrecs})
seqs = [r[\"seq\"] for r in allrecs]
print(json.dumps({
    \"kinds1\": kinds(r1), \"col1\": col(r1),
    \"kinds2\": kinds(r2), \"sel2\": sel(r2), \"col2\": col(r2),
    \"sel3\": sel(r3), \"alv3\": alv(r3), \"col3\": col(r3),
    \"inv3\": [r for r in r3 if r[\"t\"] == \"sample\"][0][\"invalid_fields\"],
    \"selkeys\": sorted([r for r in r3 if r[\"t\"] == \"selection_changed\"][0].keys()),
    \"alvkeys\": sorted([r for r in r3 if r[\"t\"] == \"alive_flipped\"][0].keys()),
    \"kinds4\": kinds(r4), \"s4\": [s4[\"proxies_status\"], s4[\"groups\"], s4[\"nodes\"],
                                  s4[\"connections_status\"], s4[\"invalid_fields\"],
                                  s4[\"seq\"]],
    \"col4\": col(r4),
    \"sel5\": sel(r5), \"alv5\": alv(r5), \"col5\": col(r5),
    \"s5_conns\": [r for r in r5 if r[\"t\"] == \"sample\"][0][\"connections_status\"],
    \"s6\": [s6[\"api_reachable\"], s6[\"mihomo_version\"], s6[\"proxies_status\"],
            s6[\"connections_status\"], s6[\"groups\"], s6[\"connection_chains\"], s6[\"seq\"]],
    \"col6\": col(r6), \"failed6\": f6[\"api_failed\"], \"calls6\": calls6,
    \"col7\": col(r7), \"ledger\": sorted(ledger.items()),
    \"run8_new\": r8[0][\"run\"] != r7[0][\"run\"], \"s8\": [s8[\"seq\"], s8[\"run\"] == state2[\"run\"]],
    \"ev8\": sel(r8) + alv(r8), \"col8\": col(r8),
    \"ts\": sorted(set(r[\"t\"] for r in allrecs)),
    \"keysets\": [list(k) for k in keysets],
    \"keyset_sizes\": sorted({len(k) for k in keysets}),
    \"seq_cont\": all(b > a for a, b in zip(seqs, seqs[1:])),
}))
")"
assert_eq "$(field "$out" 'obj["kinds1"]')" "['sample', 'collector']" "cycle 1 seeds silently + records the missing member once"
assert_eq "$(field "$out" 'obj["col1"]')" "[['node_missing', 'proxies', 1, 2]]" "first-cycle ledger count 1"
assert_eq "$(field "$out" 'obj["kinds2"]')" "['sample', 'selection_changed', 'collector']" "manual outer pin -> exactly one edge"
assert_eq "$(field "$out" 'obj["sel2"]')" "[['节点选择', '自动选择', 'reality-hk-01', 4]]" "selection_changed names group/from/to with its own seq (H3)"
assert_eq "$(field "$out" 'obj["col2"]')" "[['node_missing', 'proxies', 2, 5]]" "persistent code increments exactly once per cycle"
assert_eq "$(field "$out" 'obj["sel3"]')" "[['节点选择', 'reality-hk-01', '自动选择', 7], ['自动选择', 'reality-hk-01', 'hy2-hk-02', 8]]" "failover produces both edges in causal order, never a storm"
assert_eq "$(field "$out" 'obj["alv3"]')" "[['reality-hk-01', True, False, 9]]" "alive_flipped fires exactly once with booleans (H1)"
assert_eq "$(field "$out" 'obj["inv3"]')" "5" "invalid fields accumulate across proxies parse + 2 malformed connections"
assert_eq "$(field "$out" 'obj["col3"]')" "[['node_missing', 'proxies', 3, 10]]" "ledger keeps counting across incident cycles"
assert_eq "$(field "$out" 'obj["selkeys"]')" "['from', 'group', 'run', 'seq', 't', 'to', 'ts', 'v']" "selection_changed envelope is closed"
assert_eq "$(field "$out" 'obj["alvkeys"]')" "['from', 'node', 'run', 'seq', 't', 'to', 'ts', 'v']" "alive_flipped envelope is closed"
assert_eq "$(field "$out" 'obj["kinds4"]')" "['sample', 'collector']" "unavailable /proxies cycle: sample STILL emitted, zero diff events"
assert_eq "$(field "$out" 'obj["s4"]')" "['unavailable', [], [], 'ok', 2, 11]" "broken endpoint honest status, empty whitelist fields, /connections isolated and unaffected"
assert_eq "$(field "$out" 'obj["col4"]')" "[['proxies_invalid', 'proxies', 1, 12]]" "endpoint failure via closed code + scope, no detail text"
assert_eq "$(field "$out" 'obj["sel5"]')" "[]" "after the gap the changed selection is NOT claimed as an edge (no fabricated causality, B2)"
assert_eq "$(field "$out" 'obj["alv5"]')" "[]" "revived node across the gap: re-seeded silently, no alive edge"
assert_eq "$(field "$out" 'obj["col5"]')" "[['node_missing', 'proxies', 1, 14]]" "absent code reset required a FULL clean cycle (B6)"
assert_eq "$(field "$out" 'obj["s5_conns"]')" "ok" "idle connections:null sampled as confirmed zero"
assert_eq "$(field "$out" 'obj["s6"]')" "[False, None, 'unavailable', 'unavailable', [], [], 15]" "even with /version down a sample carries the run: api_reachable false, version null, statuses unavailable"
assert_eq "$(field "$out" 'obj["col6"]')" "[['mihomo_unreachable', 'version', 1, 16]]" "every /version failure class maps to the single closed code"
assert_eq "$(field "$out" 'obj["failed6"]')" "True" "version failure flags api_failed for the exit mapping"
assert_eq "$(field "$out" 'obj["calls6"]')" "['/version']" "a failed /version skips the other reads that cycle (bounded polling)"
assert_eq "$(field "$out" 'obj["col7"]')" "[['mihomo_unreachable', 'version', 2, 18]]" "consecutive version failures increment (downtime measurable)"
assert_eq "$(field "$out" 'obj["ledger"]')" "[['mihomo_unreachable', 2], ['node_missing', 1]]" "partial cycles increment but NEVER reset other codes (B6)"
assert_eq "$(field "$out" 'obj["run8_new"]')" "True" "new process -> new run id (restart is visible evidence)"
assert_eq "$(field "$out" 'obj["s8"]')" "[1, True]" "new run restarts seq at 1 inside the fresh state"
assert_eq "$(field "$out" 'obj["ev8"]')" "[]" "fresh run re-seeds from payload: prior-run state is never a diff seed (B2)"
assert_eq "$(field "$out" 'obj["col8"]')" "[['node_missing', 'proxies', 1, 2]]" "ledger is run-local too"
assert_eq "$(field "$out" 'obj["ts"]')" "['alive_flipped', 'collector', 'sample', 'selection_changed']" "persisted t set across the incident is exactly design types (no fifth run kind)"
assert_eq "$(field "$out" 'len(obj["keysets"])')" "4" "exactly four distinct record shapes persisted (sample/selection/alive/collector)"
assert_eq "$(field "$out" 'obj["keyset_sizes"]')" "[8, 14]" "closed shapes: 14-key sample, three 8-key event/collector records"
assert_eq "$(field "$out" 'obj["seq_cont"]')" "True" "seq strictly increases across every record of the run"

out="$(mihomo_py "$PY_PREAMBLE
import json, diag
t = FakeTransport(routes())
c = diag.DiagCollector(\"http://127.0.0.1:9090\", $GROUPS_OUTER + [\"GHOST-A\", \"GHOST-B\"],
                      transport=t, clock=lambda: 1790078400.0, hmac_key=$KEY)
recs, flags = c.collect_cycle(diag.new_state())
cols = [(r[\"code\"], r[\"count\"]) for r in recs if r[\"t\"] == \"collector\"]
print(json.dumps({\"cols\": cols, \"codes\": flags[\"codes\"]}))
")"
assert_eq "$(field "$out" 'obj["codes"]')" "['group_missing', 'node_missing']" "whole-cycle code set computed before the fold (B6)"
assert_eq "$(field "$out" 'obj["cols"]')" "[['group_missing', 1], ['node_missing', 1]]" "two missing groups -> ONE group_missing record, never one per group"

section "B4 storage primitives: path refusal + HMAC key race + single writer"
out="$(mihomo_py '
import json, os, stat, subprocess, sys, tempfile, types
import diag
diag._WINDOWS = False
res = {}
base = tempfile.mkdtemp()
DIR = stat.S_IFDIR | 0o700
REG = stat.S_IFREG | 0o600
def fake_lstat(overrides):
    def f(path):
        mode = overrides.get(path, DIR)
        return types.SimpleNamespace(st_mode=mode)
    return f
p = os.path.join(base, "sub", "ev")
parent = os.path.join(base, "sub")
try:
    diag.check_no_symlink_component(p, lstat=fake_lstat({parent: stat.S_IFLNK | 0o777}))
    res["sym_parent"] = "ACCEPTED"
except diag.ConfigurationError: res["sym_parent"] = "rejected"
try:
    diag.check_no_symlink_component(p, lstat=fake_lstat({p: stat.S_IFLNK | 0o777}))
    res["sym_final"] = "ACCEPTED"
except diag.ConfigurationError: res["sym_final"] = "rejected"
try:
    diag.check_no_symlink_component(p, lstat=fake_lstat({p: REG}))
    res["final_file"] = "ACCEPTED"
except diag.ConfigurationError: res["final_file"] = "rejected"
res["clean"] = diag.check_no_symlink_component(base, lstat=fake_lstat({})) == os.path.abspath(base)
modes = {}
def ok_chmod(path, mode): modes["mode"] = mode
diag.ensure_out_dir(p, chmod_fn=ok_chmod)
res["chmod_mode"] = modes.get("mode")
res["created"] = os.path.isdir(p)
def boom_chmod(path, mode): raise OSError(1, "Operation not permitted")
try:
    diag.ensure_out_dir(p, chmod_fn=boom_chmod); res["chmod_fail"] = "ACCEPTED"
except diag.ConfigurationError: res["chmod_fail"] = "rejected"
# -- HMAC key file --
loop = OSError("symlink loop"); loop.errno = getattr(os, "ELOOP", 40)
def loop_open(*a, **k): raise loop
try:
    diag.load_or_create_hmac_key(base, open_fn=loop_open); res["key_loop"] = "ACCEPTED"
except diag.ConfigurationError as e:
    res["key_loop"] = "symlink" if "symlink" in str(e) else "generic"
realfile = os.path.join(base, "regfile"); open(realfile, "wb").close()
def fd_open(*a, **k): return os.open(realfile, os.O_RDONLY)
def fifo_fstat(fd): return types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
try:
    diag.load_or_create_hmac_key(base, open_fn=fd_open, fstat_fn=fifo_fstat); res["key_fifo"] = "ACCEPTED"
except diag.ConfigurationError: res["key_fifo"] = "rejected"
def open_mode_fstat(fd): return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644)
try:
    diag.load_or_create_hmac_key(base, open_fn=fd_open, fstat_fn=open_mode_fstat); res["key_open_mode"] = "ACCEPTED"
except diag.ConfigurationError as e:
    res["key_open_mode"] = "rejected" if "permissions" in str(e) else "BAD"
def reg_fstat(fd): return types.SimpleNamespace(st_mode=REG)
short_src = iter([b"x" * 16, b""])   # one short read, then EOF
try:
    diag.load_or_create_hmac_key(base, open_fn=fd_open, fstat_fn=reg_fstat,
                                 read_fn=lambda fd, n: next(short_src))
    res["key_short"] = "ACCEPTED"
except diag.ConfigurationError: res["key_short"] = "rejected"
planted = bytes(range(32))
got = diag.load_or_create_hmac_key(base, open_fn=fd_open, fstat_fn=reg_fstat,
                                   read_fn=lambda fd, n: planted)
res["key_reload"] = got == planted and len(got) == 32
calls = []
class RaceExists(Exception): pass
def race_open(path, flags, mode=0o600, *a):
    calls.append(flags)
    if flags & getattr(os, "O_CREAT", 0x100): raise FileExistsError(17, "exists")
    if len(calls) == 1: raise FileNotFoundError(2, "gone")
    return os.open(realfile, os.O_RDONLY)
def race_read(fd, n): return planted
key2 = diag.load_or_create_hmac_key(base, open_fn=race_open, fstat_fn=reg_fstat,
                                    read_fn=race_read)
res["key_race"] = key2 == planted
res["key_race_excl"] = bool(calls[1] & os.O_EXCL) if len(calls) > 1 else False
res["race_opens"] = len(calls)
# -- instance lock --
try:
    fd = diag.acquire_instance_lock(base, lock_fn=lambda f: False)
    res["lock_busy"] = "ACCEPTED"
except diag.ConfigurationError as e:
    res["lock_busy"] = "rejected" if "another diag collector" in str(e) else "BAD"
def open_boom(*a, **k): raise OSError(13, "Permission denied")
try:
    diag.acquire_instance_lock(base, open_fn=open_boom); res["lock_open_fail"] = "ACCEPTED"
except diag.ConfigurationError: res["lock_open_fail"] = "rejected"
child_code = (
    "import sys, os; sys.path.insert(0, os.environ[\"MIHOMO_DIR\"]);"
    "import diag\n"
    "try:\n"
    "    fd = diag.acquire_instance_lock(sys.argv[1])\n"
    "except diag.ConfigurationError:\n"
    "    print(\"refused\")\n"
    "else:\n"
    "    print(\"granted\")\n"
    "    os.close(fd)\n")
holder = diag.acquire_instance_lock(base)
env = dict(os.environ); env["PYTHONPATH"] = os.environ["MIHOMO_DIR"]
r = subprocess.run([sys.executable, "-c", child_code, base], capture_output=True,
                   text=True, env=env)
res["lock_child_held"] = r.stdout.strip()
os.close(holder)
r = subprocess.run([sys.executable, "-c", child_code, base], capture_output=True,
                   text=True, env=env)
res["lock_child_free"] = r.stdout.strip()
res["lock_file"] = os.path.isfile(os.path.join(base, "diag.lock"))
# -- real key file round trip (platform-neutral: default _WINDOWS behavior) --
diag._WINDOWS = os.name == "nt"
k1 = diag.load_or_create_hmac_key(base)
k2 = diag.load_or_create_hmac_key(base)
res["key_real"] = k1 == k2 and len(k1) == 32 and os.path.getsize(os.path.join(base, "diag.key")) == 32
print(json.dumps(res))
')"
assert_eq "$(field "$out" 'obj["sym_parent"]')" "rejected" "symlink PARENT component fails closed (traversal hole closed)"
assert_eq "$(field "$out" 'obj["sym_final"]')" "rejected" "symlink final dir fails closed"
assert_eq "$(field "$out" 'obj["final_file"]')" "rejected" "regular file where the evidence dir must be is refused"
assert_eq "$(field "$out" 'obj["clean"]')" "True" "clean real path passes and resolves absolute"
assert_eq "$(field "$out" 'obj["chmod_mode"]')" "448" "existing out dir re-tightened to 0700 (448 = 0o700)"
assert_eq "$(field "$out" 'obj["created"]')" "True" "missing out dir created fail-closed"
assert_eq "$(field "$out" 'obj["chmod_fail"]')" "rejected" "chmod FAILURE is fatal on POSIX: non-private evidence is refused, not best-effort"
assert_eq "$(field "$out" 'obj["key_loop"]')" "symlink" "key file symlink (ELOOP) refused with the symlink message"
assert_eq "$(field "$out" 'obj["key_fifo"]')" "rejected" "non-regular key file (FIFO) refused via fstat verification"
assert_eq "$(field "$out" 'obj["key_open_mode"]')" "rejected" "world-readable key file (0644) refuses startup"
assert_eq "$(field "$out" 'obj["key_short"]')" "rejected" "wrong-size key file declared corrupt, never trusted"
assert_eq "$(field "$out" 'obj["key_reload"]')" "True" "existing 32-byte key re-read verbatim through the safe loader"
assert_eq "$(field "$out" 'obj["key_race"]')" "True" "lost O_EXCL race falls back to the OTHER writer's key (never truncated/overwritten)"
assert_eq "$(field "$out" 'obj["key_race_excl"]')" "True" "creation uses O_CREAT|O_EXCL"
assert_eq "$(field "$out" 'obj["lock_busy"]')" "rejected" "contended lock refuses startup BEFORE polling, naming the holder"
assert_eq "$(field "$out" 'obj["lock_open_fail"]')" "rejected" "unopenable lock file refuses startup"
assert_eq "$(field "$out" 'obj["lock_child_held"]')" "refused" "second process cannot co-write a held evidence dir (single writer)"
assert_eq "$(field "$out" 'obj["lock_child_free"]')" "granted" "lock releases with the holder fd (process-lifetime semantics)"
assert_eq "$(field "$out" 'obj["lock_file"]')" "True" "diag.lock lives inside the evidence dir"
assert_eq "$(field "$out" 'obj["key_real"]')" "True" "real key file: exactly 32 bytes, stable across reloads, never regenerated"

section "B4 writer: real primitives via injection, durable rotation, torn tail"
out="$(mihomo_py '
import json, os, stat, tempfile, types
import diag
diag._WINDOWS = False
res = {}
rec = {"v": 1, "t": "collector", "ts": "2026-09-22T12:00:00Z", "run": "f" * 32,
       "seq": 1, "code": "storage_error", "scope": "storage", "count": 1}
real_open = os.open
# (a) open flags + mode
seen = {}
def flag_spy(path, flags, mode=0o600, *a):
    seen["flags"] = flags; seen["mode"] = mode
    return real_open(path, flags, mode, *a)
base = tempfile.mkdtemp()
w = diag.DiagWriter(base)
w.open_fn = flag_spy
w.write([rec])
want = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
res["flags_ok"] = seen.get("flags") == want
res["mode_ok"] = seen.get("mode") == 0o600
# (b) fsync once per batch
fc = []
w.fsync_fn = lambda fd: (os.fsync(fd), fc.append(1))
w.write([rec])
res["fsync_once"] = len(fc) == 1
# (c) partial os.write loops until complete
def one_byte(fd, data):
    return os.write(fd, bytes(data[:1]))
w.write_fn = one_byte
w.write([rec])
lines = open(w.path).readlines()
res["loop_complete"] = len(lines) == 3 and json.loads(lines[2]) == rec
w.write_fn = os.write
# (d) zero-progress fails STOP
w.write_fn = lambda fd, data: 0
try:
    w.write([rec]); res["zero"] = "ACCEPTED"
except diag.StorageError as e:
    res["zero"] = "stop" if "diag.jsonl" in str(e) else "BAD"
# (e) write failure names the path, never the payload
def boom(fd, data): raise OSError(28, "No space left on device")
w.write_fn = boom
try:
    w.write([rec]); res["write_fail"] = "ACCEPTED"
except diag.StorageError as e:
    res["write_fail"] = ("ctx" if "diag.jsonl" in str(e) and "ffffffff" not in str(e)
                         else "BAD:" + str(e))
# (f) non-regular target refused via fstat
w2 = diag.DiagWriter(tempfile.mkdtemp())
w2.fstat_fn = lambda fd: types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
try:
    w2.write([rec]); res["fifo"] = "ACCEPTED"
except diag.StorageError as e:
    res["fifo"] = "rejected" if "regular" in str(e) else "BAD"
# (g) fchmod failure is FATAL on POSIX
w3 = diag.DiagWriter(tempfile.mkdtemp())
def chmod_boom(fd, mode): raise OSError(1, "Operation not permitted")
w3.fchmod_fn = chmod_boom
try:
    w3.write([rec]); res["fchmod_fail"] = "ACCEPTED"
except diag.StorageError: res["fchmod_fail"] = "rejected"
# (h) unopenable evidence file -> StorageError
w4 = diag.DiagWriter(tempfile.mkdtemp())
def open_boom(*a, **k): raise OSError(28, "No space left on device")
w4.open_fn = open_boom
try:
    w4.write([rec]); res["open_fail"] = "ACCEPTED"
except diag.StorageError as e:
    res["open_fail"] = "rejected" if "ffffffff" not in str(e) else "BAD"
# (i) torn trailing fragment is frame-protected, not destroyed
d5 = tempfile.mkdtemp()
with open(os.path.join(d5, "diag.jsonl"), "wb") as f:
    f.write(b"{\"k\":\"samp")
w5 = diag.DiagWriter(d5)
res["torn_pending"] = w5._torn_pending
w5.write([rec])
lines5 = open(os.path.join(d5, "diag.jsonl"), "rb").read().splitlines()
res["torn_framed"] = (len(lines5) == 2 and lines5[0] == b"{\"k\":\"samp"
                      and json.loads(lines5[1]) == rec)
w5.write([rec])
res["torn_once"] = len(open(os.path.join(d5, "diag.jsonl")).readlines()) == 3
# (j) clean/empty file: no frame prefix injected
d6 = tempfile.mkdtemp()
w6 = diag.DiagWriter(d6)
res["virgin_pending"] = w6._torn_pending
w6.write([])
res["empty_noop"] = not os.path.exists(w6.path)
w6.write([rec])
res["no_frame"] = open(w6.path, "rb").read().startswith(b"{")
# (k) size-shift rotation with fsync-before-rename + dir fsync after.
d7 = tempfile.mkdtemp()
w7 = diag.DiagWriter(d7, max_mb=0.0039, files=3)
dirsync = []
w7.fsync_dir_fn = lambda p: dirsync.append(p)
events = []
real_fsync = os.fsync
def ro_fsync(fd):
    real_fsync(fd)
    events.append("f")
w7.fsync_fn = ro_fsync
real_replace = os.replace
def tr_replace(s, d):
    events.append("r")
    return real_replace(s, d)
w7.replace_fn = tr_replace
for _ in range(150):
    w7.write([rec])
res["rot_1"] = os.path.exists(w7.path + ".1")
res["rot_2"] = os.path.exists(w7.path + ".2")
res["rot_bounded"] = not os.path.exists(w7.path + ".3")
res["dir_fsync"] = len(dirsync) >= 2
res["main_alive"] = os.path.exists(w7.path)
res["fsync_before_rename"] = ("r" in events and "f" in events
                              and events.index("r") > events.index("f"))
# (l) rotation on a never-written dir is a no-op
diag._WINDOWS = os.name == "nt"   # platform default: real _fsync_dir only where supported
try:
    diag.DiagWriter(tempfile.mkdtemp()).rotate(); res["virgin_rot"] = "ok"
except Exception as e:
    res["virgin_rot"] = type(e).__name__
print(json.dumps(res))
')"
assert_eq "$(field "$out" 'obj["flags_ok"]')" "True" "append-only O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW"
assert_eq "$(field "$out" 'obj["mode_ok"]')" "True" "evidence file created 0600"
assert_eq "$(field "$out" 'obj["fsync_once"]')" "True" "one fsync per cycle batch (durability per unit)"
assert_eq "$(field "$out" 'obj["loop_complete"]')" "True" "short os.write returns loop until complete: bytes intact"
assert_eq "$(field "$out" 'obj["zero"]')" "stop" "zero-progress write fails STOP, never spins"
assert_eq "$(field "$out" 'obj["write_fail"]')" "ctx" "write failure surfaces path context only, never record bytes"
assert_eq "$(field "$out" 'obj["fifo"]')" "rejected" "non-regular evidence target (FIFO) refused via fstat verification"
assert_eq "$(field "$out" 'obj["fchmod_fail"]')" "rejected" "fchmod 0600 failure is FATAL: unprovable privacy refuses the write"
assert_eq "$(field "$out" 'obj["open_fail"]')" "rejected" "unopenable evidence file -> StorageError without payload"
assert_eq "$(field "$out" 'obj["torn_pending"]')" "True" "pre-existing torn tail detected at startup"
assert_eq "$(field "$out" 'obj["torn_framed"]')" "True" "torn fragment frame-protected on its own line, new record valid (evidence not destroyed)"
assert_eq "$(field "$out" 'obj["torn_once"]')" "True" "frame protection applied exactly once"
assert_eq "$(field "$out" 'obj["virgin_pending"]')" "False" "no false torn detection on a fresh dir"
assert_eq "$(field "$out" 'obj["empty_noop"]')" "True" "writing no records creates nothing"
assert_eq "$(field "$out" 'obj["no_frame"]')" "True" "clean append starts straight at JSON"
assert_eq "$(field "$out" 'obj["rot_1"]')" "True" "size cap rotates diag.jsonl to .1"
assert_eq "$(field "$out" 'obj["rot_2"]')" "True" "rotation is a numeric shift (.1 -> .2)"
assert_eq "$(field "$out" 'obj["rot_bounded"]')" "True" "files=3 keeps the chain bounded (.3 never appears)"
assert_eq "$(field "$out" 'obj["dir_fsync"]')" "True" "directory fsync after every rotation rename"
assert_eq "$(field "$out" 'obj["fsync_before_rename"]')" "True" "file fsync precedes the first rotation rename"
assert_eq "$(field "$out" 'obj["main_alive"]')" "True" "fresh main file after rotation"
assert_eq "$(field "$out" 'obj["virgin_rot"]')" "ok" "rotating a never-written chain is a no-op"

section "B5 record ceiling: final encoded bytes incl. newline, structural trim only"
out="$(mihomo_py '
import json, diag
res = {}
def hist(n): return [{"ts": "2026-09-22T12:00:00Z", "delay_ms": 44} for _ in range(n)]
def extra(n): return [{"test_id": "0123456789abcdef", "alive": True, "history": hist(1)} for _ in range(n)]
def node(i): return {"name": "n%02d" % i, "type": "selector", "alive": True,
                     "history": hist(12), "extra": extra(8)}
def sample(groups, nodes, chains, invalid=7):
    return {"v": 1, "t": "sample", "ts": "2026-09-22T12:00:00Z", "run": "a" * 32,
            "seq": 1, "api_reachable": True, "mihomo_version": "1.18.7",
            "proxies_status": "ok", "connections_status": "ok",
            "groups": groups, "nodes": nodes, "connection_chains": chains,
            "truncated": False, "invalid_fields": invalid}
chains = [{"node": "n%02d" % i, "active_chain_count": 3,
           "oldest_start": "2026-09-22T11:50:00Z", "newest_start": "2026-09-22T11:55:00Z",
           "invalid_start_count": 1} for i in range(64)]
big = sample([{"name": "g%d" % i, "type": "selector", "now": "n00",
               "members": ["member-%03d-%s" % (j, "x" * 24) for j in range(32)]}
              for i in range(8)], [node(i) for i in range(64)], chains)
raw = diag._encode(big)
line = diag.encode_record(big)
d = json.loads(line)
res.update({"raw_over": len(raw) > 64 * 1024, "fits": len(line) <= 64 * 1024,
            "newline": line.endswith(b"\n") and line.count(b"\n") == 1,
            "truncated": d["truncated"], "shrank": len(d["nodes"]) < 64,
            "invalid_kept": d["invalid_fields"] == 7,
            "members_kept": d["groups"] == [] or len(d["groups"][0]["members"]) <= 32})
small = sample([{"name": "节点选择", "type": "selector", "now": "n00", "members": ["a"]}],
               [node(1)], [])
res["passthru"] = diag.encode_record(small) == diag._encode(small)
old = diag.RECORD_MAX_BYTES
diag.RECORD_MAX_BYTES = 300
line2 = diag.encode_record(small)
d2 = json.loads(line2)
res.update({"collapse_fits": len(line2) <= 300,
            "collapse_shape": [d2["t"], d2["nodes"], d2["groups"], d2["connection_chains"],
                               d2["truncated"], d2["ts"], d2["seq"]],
            "collapse_scalar": [d2["api_reachable"], d2["mihomo_version"],
                                d2["proxies_status"]]})
event = {"v": 1, "t": "selection_changed", "ts": "2026-09-22T12:00:00Z",
         "run": "b" * 32, "seq": 9, "group": "z" * 75000, "from": "a", "to": "b"}
line3 = diag.encode_record(event)
d3 = json.loads(line3)
res.update({"event_fits": len(line3) <= 300,
            "event_collapse": [d3["t"], d3["code"], d3["scope"], d3["count"], d3["seq"]]})
diag.RECORD_MAX_BYTES = old
two = sample([], [{"name": "n0", "type": "s", "alive": None, "history": hist(8), "extra": extra(8)},
                  {"name": "n1", "type": "s", "alive": None, "history": hist(8), "extra": extra(8)}], [])
target = len(diag._encode(two)) - 1
diag.RECORD_MAX_BYTES = target
line4 = diag.encode_record(two)
d4 = json.loads(line4)
res.update({"order_cap": len(line4) <= target,
            "order_extra": [len(d4["nodes"][0]["extra"]), len(d4["nodes"][-1]["extra"])],
            "order_flag": d4["truncated"]})
diag.RECORD_MAX_BYTES = old
cjk = diag.encode_record({"v": 1, "t": "selection_changed", "ts": "x", "run": "y",
                          "seq": 1, "group": "节点选择", "from": "a", "to": "b"})
res["ascii"] = ("节点选择".encode("utf-8") not in cjk) and (b"\\u8282" in cjk)
res["sorted"] = cjk == diag._encode(json.loads(cjk))
print(json.dumps(res))
')"
assert_eq "$(field "$out" 'obj["raw_over"]')" "True" "the oversized fixture really exceeds 64 KiB raw"
assert_eq "$(field "$out" 'obj["fits"]')" "True" "final encoded line INCLUDING newline is <= 64 KiB (B5 measurement point)"
assert_eq "$(field "$out" 'obj["newline"]')" "True" "still exactly one physical line (never byte-sliced JSON)"
assert_eq "$(field "$out" 'obj["truncated"]')" "True" "structural trim marks truncated=true"
assert_eq "$(field "$out" 'obj["shrank"]')" "True" "trim removed whole records, not bytes"
assert_eq "$(field "$out" 'obj["invalid_kept"]')" "True" "invalid_fields counter survives the trim"
assert_eq "$(field "$out" 'obj["members_kept"]')" "True" "member lists stay inside their cap after trim"
assert_eq "$(field "$out" 'obj["passthru"]')" "True" "under-cap records encode untouched"
assert_eq "$(field "$out" 'obj["collapse_fits"]')" "True" "an unfixable sample collapses instead of vanishing"
assert_eq "$(field "$out" 'obj["collapse_shape"]')" "['sample', [], [], [], True, '2026-09-22T12:00:00Z', 1]" "sample collapse keeps envelope + empty arrays, scalars honest"
assert_eq "$(field "$out" 'obj["collapse_scalar"]')" "[True, '1.18.7', 'ok']" "scalar facts (api/version/statuses) preserved in the collapse"
assert_eq "$(field "$out" 'obj["event_fits"]')" "True" "a pathological event line is capped too"
assert_eq "$(field "$out" 'obj["event_collapse"]')" "['collector', 'storage_error', 'storage', 1, 9]" "unfixable non-sample -> storage collector note keeping its seq"
assert_eq "$(field "$out" 'obj["order_cap"]')" "True" "trim stops as soon as the line fits"
assert_eq "$(field "$out" 'obj["order_extra"]')" "[8, 7]" "deterministic trim order: LAST node extra first, earlier evidence untouched"
assert_eq "$(field "$out" 'obj["order_flag"]')" "True" "trim flagged, never silent"
assert_eq "$(field "$out" 'obj["ascii"]')" "True" "CJK never rides as raw bytes: ASCII-escaped canonical form"
assert_eq "$(field "$out" 'obj["sorted"]')" "True" "canonical sorted-keys encoding is stable"

section "CLI: exit-code matrix 0/2/3/4/5 and fail-closed configuration"
out="$(mihomo_py "$PY_PREAMBLE
import contextlib, io, json, os, subprocess, sys, tempfile, diag
res = {}
base = tempfile.mkdtemp()
def od(name): return os.path.join(base, name)
def run(argv, routes_=None, fail_=None, write_boom=False, holder=None):
    t = FakeTransport(routes_ or routes(), fail=fail_)
    real_write = diag.DiagWriter.write
    if write_boom:
        diag.DiagWriter.write = lambda self, recs: (_ for _ in ()).throw(
            diag.StorageError(\"cannot write diag.jsonl (OSError)\"))
    o, e = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                rc = diag.main(argv, transport=t, clock=lambda: 1790078400.0)
            except SystemExit as ex:
                rc = ex.code
    finally:
        diag.DiagWriter.write = real_write
    return rc, o.getvalue(), e.getvalue()

res[\"missing_outdir\"] = run([\"--group\", \"G\"])[0]
res[\"no_group\"] = run([\"--out-dir\", od(\"ng\")])[0]
grp9 = []
for i in range(9): grp9 += [\"--group\", \"G%d\" % i]
res[\"nine_groups\"] = run([\"--out-dir\", od(\"nine\")] + grp9)[0]
res[\"bad_mb\"] = run([\"--out-dir\", od(\"mb\"), \"--group\", \"G\", \"--max-mb\", \"9\"])[0]
res[\"bad_files\"] = run([\"--out-dir\", od(\"fl\"), \"--group\", \"G\", \"--files\", \"33\"])[0]
res[\"bad_budget\"] = run([\"--out-dir\", od(\"bg\"), \"--group\", \"G\",
                          \"--max-mb\", \"8\", \"--files\", \"8\"])[0]
res[\"nonloopback\"] = run([\"--out-dir\", od(\"nl\"), \"--group\", \"G\",
                          \"--url\", \"http://192.168.1.9:9090\"])[0]
d_ok = od(\"ok\")
rc, so, se = run([\"--out-dir\", d_ok, \"--group\", \"节点选择\", \"--group\", \"自动选择\"])
res[\"ok\"] = rc
summary = json.loads(so)
res[\"summary_keys\"] = sorted(summary.keys())
res[\"summary_api\"] = summary[\"api_failed\"]
res[\"summary_codes\"] = summary[\"codes\"]
lines = [json.loads(x) for x in open(os.path.join(d_ok, \"diag.jsonl\"), encoding=\"utf-8\")]
res[\"first_sample\"] = [lines[0][\"t\"], lines[0][\"seq\"], lines[0][\"run\"] == summary[\"run\"]]
res[\"types_ok\"] = all(l[\"t\"] in diag.RECORD_TYPES for l in lines)
res[\"artifacts\"] = sorted(f for f in os.listdir(d_ok))
rc, so, se = run([\"--out-dir\", od(\"ghost\"), \"--group\", \"GHOST\"])
res[\"ghost_rc\"] = rc
res[\"ghost_codes\"] = json.loads(so)[\"codes\"]
rc, so, se = run([\"--out-dir\", od(\"unreach\"), \"--group\", \"G\"],
                 fail_={\"/version\": OSError(\"dial timeout 127.0.0.1:9090\")})
res[\"api_rc\"] = rc
res[\"api_codes\"] = json.loads(so)[\"codes\"]
res[\"api_sample\"] = json.loads(
    open(os.path.join(od(\"unreach\"), \"diag.jsonl\")).readline())[\"api_reachable\"]
res[\"storage_rc\"] = run([\"--out-dir\", od(\"stor\"), \"--group\", \"G\"], write_boom=True)[0]
res[\"both_rc\"] = run([\"--out-dir\", od(\"both\"), \"--group\", \"G\"],
                      fail_={\"/version\": OSError(\"reset\")}, write_boom=True)[0]
res[\"resident_storage\"] = run([\"--resident\", \"--out-dir\", od(\"res\"), \"--group\", \"G\"],
                               write_boom=True)[0]
rc, so, se = run([\"--out-dir\", od(\"u401\"), \"--group\", \"G\", \"--secret-file\",
                  os.path.join(base, \"nope.secret\")])
res[\"secret_missing\"] = rc   # an unusable secret must be config-visible
rc, so, se = run([\"--out-dir\", d_ok, \"--group\", \"G\"])
res[\"lock_contend\"] = rc     # second collector on a live evidence dir refuses
# prune-now in a fresh process (the in-process holders above keep their locks)
d_pr = od(\"pr\")
diag.DiagWriter(diag.ensure_out_dir(d_pr)).write(
    [{\"v\": 1, \"t\": \"collector\", \"ts\": \"x\", \"run\": \"c\" * 32, \"seq\": 1,
      \"code\": \"storage_error\", \"scope\": \"storage\", \"count\": 1}])
env = dict(os.environ); env[\"PYTHONPATH\"] = os.environ[\"MIHOMO_DIR\"]
r = subprocess.run([sys.executable, \"-c\",
                    \"import sys, diag; sys.exit(diag.main(sys.argv[1:]))\",
                    \"--prune-now\", \"--out-dir\", d_pr, \"--group\", \"G\"],
                   capture_output=True, text=True, env=env)
res[\"prune\"] = r.returncode
res[\"prune_shape\"] = sorted(json.loads(r.stdout).keys())
res[\"prune_rotated\"] = json.loads(r.stdout)[\"rotated\"]
res[\"pruned\"] = os.path.exists(os.path.join(d_pr, \"diag.jsonl.1\"))
print(json.dumps(res))
")"
assert_eq "$(field "$out" 'obj["missing_outdir"]')" "2" "--out-dir is required fail-closed (argparse exit 2)"
assert_eq "$(field "$out" 'obj["no_group"]')" "2" "zero --group refused before any byte leaves"
assert_eq "$(field "$out" 'obj["nine_groups"]')" "2" "more than 8 groups refused at the CLI"
assert_eq "$(field "$out" 'obj["bad_mb"]')" "2" "--max-mb above the per-file cap refused"
assert_eq "$(field "$out" 'obj["bad_files"]')" "2" "--files beyond the retention ceiling refused"
assert_eq "$(field "$out" 'obj["bad_budget"]')" "2" "8 MiB x 8 files over the 32 MiB budget refused"
assert_eq "$(field "$out" 'obj["nonloopback"]')" "2" "non-loopback URL rejected before a byte leaves (audited clamp)"
assert_eq "$(field "$out" 'obj["ok"]')" "0" "clean once-run exits 0"
assert_eq "$(field "$out" 'obj["summary_keys"]')" "['api_failed', 'codes', 'connections_status', 'proxies_status', 'run', 'storage_failed']" "once-summary is a closed bounded report"
assert_eq "$(field "$out" 'obj["summary_api"]')" "False" "clean run not flagged failed"
assert_eq "$(field "$out" 'obj["summary_codes"]')" "['node_missing']" "closed codes surfaced to the supervisor"
assert_eq "$(field "$out" 'obj["first_sample"]')" "['sample', 1, True]" "persisted first record: seq-1 sample carrying the SAME run as the summary (restart evidence without a run record)"
assert_eq "$(field "$out" 'obj["types_ok"]')" "True" "every persisted line stays inside the four design types"
assert_eq "$(field "$out" 'obj["artifacts"]')" "['diag.jsonl', 'diag.key', 'diag.lock']" "evidence chain, HMAC key and lock all live in the 0700 dir"
assert_eq "$(field "$out" 'obj["ghost_rc"]')" "0" "a missing group is evidence, not a process failure"
assert_eq "$(field "$out" 'obj["ghost_codes"]')" "['group_missing']" "missing group recorded via the closed enum"
assert_eq "$(field "$out" 'obj["api_rc"]')" "3" "API unreachable -> visible exit 3, never silent 0"
assert_eq "$(field "$out" 'obj["api_codes"]')" "['mihomo_unreachable']" "version failure maps to the single closed code"
assert_eq "$(field "$out" 'obj["api_sample"]')" "False" "the unreachable cycle STILL persisted its sample (run evidence survives /version downtime)"
assert_eq "$(field "$out" 'obj["storage_rc"]')" "4" "storage failure -> exit 4"
assert_eq "$(field "$out" 'obj["both_rc"]')" "5" "API + storage both failing -> exit 5"
assert_eq "$(field "$out" 'obj["resident_storage"]')" "4" "resident mode escalates storage failure instead of looping blind"
assert_eq "$(field "$out" 'obj["secret_missing"]')" "2" "unusable --secret-file refuses startup (config exit 2)"
assert_eq "$(field "$out" 'obj["lock_contend"]')" "2" "a second collector on a live evidence dir is refused through main()"
assert_eq "$(field "$out" 'obj["prune"]')" "0" "prune-now rotates without touching the API"
assert_eq "$(field "$out" 'obj["prune_shape"]')" "['path', 'rotated']" "prune report is a closed shape"
assert_eq "$(field "$out" 'obj["prune_rotated"]')" "True" "prune confirms rotation happened"
assert_eq "$(field "$out" 'obj["pruned"]')" "True" "prune-now shifted the chain"

section "leak wall end to end (written bytes)"
out="$(mihomo_py "$PY_PREAMBLE
import json, os, tempfile, diag
t = FakeTransport(routes())
C = [1790078400.0]
c = diag.DiagCollector(\"http://127.0.0.1:9090\", $GROUPS_OUTER,
                      secret=\"S3CR3T-CTRL-KEY\", transport=t,
                      clock=lambda: C[0], hmac_key=$KEY)
w = diag.DiagWriter(diag.ensure_out_dir(tempfile.mkdtemp()))
state = diag.new_state()
def cyc():
    recs, _ = c.collect_cycle(state)
    w.write(recs)
    C[0] += 30
cyc()
t.routes = routes(proxies=\"e4diag-proxies-outer-reality-pin.json\")
cyc()
t.routes = routes(proxies=\"e4diag-proxies-reality-dead.json\",
                  conns=\"e4diag-connections-post.json\")
cyc()
t.fail = {\"/proxies\": OSError(\"dial timeout 127.0.0.1:9090\"),
          \"/connections\": OSError(\"ConnectionResetError: reset 10.0.0.5:55555\")}
cyc()
t.fail = {}
t.routes = routes(v_status=401, version=\"e4diag-unauthorized.json\")
cyc()
t.fail = {\"/version\": OSError(\"backoff failed: getaddrinfo errno 127.0.0.1\")}
cyc()
blob = open(w.path, encoding=\"utf-8\").read()
needles = [\"SECRET\", \"S3CR3T\", \"probe.example.invalid\", \"cp.cloudflare.com\",
           \"generate_204\", \"conn-\", \"10.0.0.5\", \"192.0.2.44\", \"55555\",
           \"internal-secret\", \"/secret/path\", \"metadata\", \"sourceIP\",
           \"destinationIP\", \"processPath\", \"downloadTotal\", \"uploadTotal\",
           \"MATCH\", \"hidden.example\", \"payload\", \"dial timeout\", \"OSError\",
           \"Connection\", \"backoff\", \"errno\", \"getaddrinfo\", \"401 \", \"500 \",
           \"http_status\", \"detail\", \"run_id\", \"127.0.0.1\", \":9090\", \"token\",
           \"Authorization\", \"not-a-conn\"]
verbs = [m for m in (\"put\", \"post\", \"patch\", \"delete\") if hasattr(t, m) or hasattr(diag.HttpTransport, m)]
print(json.dumps({
    \"leaks\": [n for n in needles if n in blob],
    \"calls\": sorted(set(t.calls)),
    \"lines\": len(blob.splitlines()) > 10,
    \"verbs\": verbs}))
")"
assert_eq "$(field "$out" 'obj["leaks"]')" "[]" "nothing identifiable ever reaches the evidence file (full leak wall)"
assert_eq "$(field "$out" 'obj["calls"]')" "['/connections', '/proxies', '/version']" "only the three bounded GET paths were ever requested"
assert_eq "$(field "$out" 'obj["lines"]')" "True" "the incident wrote a multi-line evidence trail"
assert_eq "$(field "$out" 'obj["verbs"]')" "[]" "no mutation verb exists on any transport in play"

printf '\n'
if [ "$FAIL" -eq 0 ] && [ "$PASS" -eq "$EXPECTED_PASS" ]; then
    printf 'ALL GREEN: %s/%s E4-Diag checks passed\n' "$PASS" "$EXPECTED_PASS"
    exit 0
fi
printf 'FAILURES: %s failed, %s passed (gate expects exactly %s)\n' "$FAIL" "$PASS" "$EXPECTED_PASS"
exit 1
