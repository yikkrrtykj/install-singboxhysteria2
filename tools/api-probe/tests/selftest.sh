#!/usr/bin/env bash
# Static checks, analyzer self-test and regression tests for the Phase A probe tool.
#
# Nothing here touches /root/sbox-probe or sing-box itself: the analyzer runs against
# generated synthetic fixtures, config generation runs against a mock sing-box
# binary, and the sink is exercised over loopback. Runtime verdicts are deliberately
# NOT produced here.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd -- "$HERE/.." && pwd)"
LIB_DIR="$TOOL_DIR/lib"
ANALYZE="$LIB_DIR/analyze.py"
GEN="$HERE/fixtures/make-synthetic.py"
PY="${PYTHON:-python3}"

PASS=0
FAIL=0
SKIP=0
TMP="$(mktemp -d)"
export PYTHONPYCACHEPREFIX="$TMP/pycache"
cleanup_tmp() {
  [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null
  rm -rf -- "$TMP"
  find "$TOOL_DIR" -name '__pycache__' -type d -prune -exec rm -rf -- {} + 2>/dev/null || true
}
trap cleanup_tmp EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
expect_grep() { # expect_grep <file> <ere> <label>
  if grep -qE "$2" "$1" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $2 in $(basename "$1"))"; fi
}
expect_no_grep() {
  if grep -qE "$2" "$1" 2>/dev/null; then fail "$3 (unexpected match: $2)"; else pass "$3"; fi
}
analyze_fixture() { # analyze_fixture <dir> <variant> <extra args...>
  local dir=$1 variant=$2
  shift 2
  "$PY" "$GEN" --out "$dir" --variant "$variant" >/dev/null
  "$PY" "$ANALYZE" analyze --evidence-dir "$dir" --fixture-mode \
    --md-out "$dir/report.md" --json-out "$dir/analysis.json" "$@" >"$dir/stdout.txt" 2>&1
}

section "shell syntax"
while IFS= read -r f; do
  if bash -n "$f" 2>"$TMP/syntax.err"; then pass "bash -n $(basename "$f")"
  else fail "bash -n $(basename "$f"): $(cat "$TMP/syntax.err")"; fi
done < <(find "$TOOL_DIR" -name '*.sh' -type f | sort)

section "python syntax"
while IFS= read -r f; do
  if "$PY" -m py_compile "$f" 2>"$TMP/py.err"; then pass "py_compile $(basename "$f")"
  else fail "py_compile $(basename "$f"): $(cat "$TMP/py.err")"; fi
done < <(find "$TOOL_DIR" -name '*.py' -type f | sort)

section "guardrail lint (shipped scripts must not touch production)"
LINT_PATTERNS=(
  '\b(pkill|killall)\b'
  'systemctl[[:space:]]+(stop|restart|start|disable|enable)[[:space:]]+.*sing-box'
  '\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b'
  'rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*[[:space:]]+.*/root/sbox([^-a-z]|$)'
  'sed[[:space:]]+-i'
  '>[[:space:]]*"?\$?PROD_'
)
while IFS= read -r f; do
  clean=1
  for pattern in "${LINT_PATTERNS[@]}"; do
    if grep -nE "$pattern" "$f" >"$TMP/lint.out"; then
      clean=0
      fail "guardrail $(basename "$f"): $(head -n1 "$TMP/lint.out")"
    fi
  done
  [ "$clean" -eq 1 ] && pass "guardrail $(basename "$f")"
done < <(find "$TOOL_DIR" -name '*.sh' -type f -not -path '*/tests/*' | sort)

section "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  while IFS= read -r f; do
    if shellcheck -S warning "$f" >"$TMP/sc.out" 2>&1; then pass "shellcheck $(basename "$f")"
    else fail "shellcheck $(basename "$f"): $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
  done < <(find "$TOOL_DIR" -name '*.sh' -type f | sort)
else
  skip "shellcheck 未安装（以 bash -n + guardrail lint 替代）"
fi

section "analyzer: empty evidence dir must say NOT TESTED"
mkdir -p "$TMP/ev-empty"
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-empty" >"$TMP/empty.txt" 2>&1
expect_grep "$TMP/ev-empty/SUMMARY.txt" 'NOT TESTED / WAITING FOR RUNTIME DATA' "empty dir -> NOT TESTED marker"
expect_no_grep "$TMP/ev-empty/SUMMARY.txt" 'YES - ' "empty dir -> no invented YES"
# match the STATUS column, not the word anywhere (the notes section may mention
# verdict names in prose, e.g. the source-IP enhancement TODO)
expect_no_grep "$TMP/ev-empty/SUMMARY.txt" '[[:space:]]VERIFIED[[:space:]]' "empty dir -> no VERIFIED status"

section "analyzer: synthetic fixtures are ignored without --fixture-mode"
"$PY" "$GEN" --out "$TMP/ev-nomode" >/dev/null
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-nomode" >"$TMP/nomode.txt" 2>&1
expect_grep "$TMP/ev-nomode/SUMMARY.txt" 'NOT TESTED / WAITING FOR RUNTIME DATA' "fixtures without flag -> NOT TESTED marker"
expect_no_grep "$TMP/ev-nomode/SUMMARY.txt" 'YES - ' "fixtures without flag -> no verdict from synthetic data"

section "analyzer: derivation math on synthetic fixtures (--fixture-mode)"
analyze_fixture "$TMP/ev-ok" consistent
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.user_field +VERIFIED +YES' "reality user field -> YES when field carries the names"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^hy2\.user_field +NO +NO -' "hy2 user field -> NO when no field carries the names"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.source_ip +VERIFIED' "reality source ip -> VERIFIED with a public address"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^hy2\.source_ip +PARTIAL' "hy2 source ip -> PARTIAL when only loopback was seen"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^probe\.production_untouched +VERIFIED' "production baseline -> unchanged"
expect_no_grep "$TMP/ev-ok/SUMMARY.txt" 'INCONCLUSIVE' "no item degraded to INCONCLUSIVE"
expect_grep "$TMP/ev-ok/report.md" '字段命名与客户端视角一致' "consistent variant -> naming matches client view"
expect_grep "$TMP/ev-ok/report.md" '语义=客户端下行' "download test -> counter mapped to client downstream"
expect_grep "$TMP/ev-ok/report.md" '语义=客户端上行' "upload test -> counter mapped to client upstream"
expect_grep "$TMP/ev-ok/report.md" 'SYNTHETIC FIXTURE OUTPUT' "fixture mode -> report is banner-marked synthetic"
expect_grep "$TMP/ev-ok/report.md" 'curl bytes_downloaded' "direction basis comes from curl-reported bytes"

section "analyzer: inverted counter naming must be detected, not hard-coded"
analyze_fixture "$TMP/ev-inv" inverted
expect_grep "$TMP/ev-inv/report.md" '字段命名与客户端视角相反' "inverted variant -> naming flagged as opposite"
expect_grep "$TMP/ev-inv/report.md" '语义=客户端下行' "inverted variant -> direction still derived from traffic"

section "regression #2: direction must NOT be computed from the post-transfer snapshot"
# The fixture's -closed snapshots carry zeroed counters and no connections, so any
# implementation that still used them would fail this verdict.
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.direction +VERIFIED' "direction VERIFIED although closed snapshot is zeroed"
cp -r "$TMP/ev-ok" "$TMP/ev-nosamples"
rm -f "$TMP"/ev-nosamples/*-s[0-9][0-9].connections.json
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-nosamples" --fixture-mode >"$TMP/nosamples.txt" 2>&1
expect_grep "$TMP/ev-nosamples/SUMMARY.txt" '^reality\.direction +NOT TESTED' "without in-transfer samples -> NOT TESTED (no fallback to closed)"
expect_grep "$TMP/ev-nosamples/SUMMARY.txt" '缺少客户端下载期间的活动采样' "missing-sample reason is stated"

section "regression #4: transfer size must match the requested bytes"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^payload\.matches_request +VERIFIED' "curl-reported bytes match requested (half for probe-a/probe-b)"
expect_grep "$TMP/ev-ok/report.md" 'ab-a 请求 33554432' "attribution payload is half, not full"
cp -r "$TMP/ev-ok" "$TMP/ev-badpayload"
"$PY" - "$TMP/ev-badpayload/reality-dl-curl.json" <<'PY'
import json
import sys
json.dump({"mode": "download", "requested_bytes": 67108864, "bytes_downloaded": 4096,
           "speed_bps": 1, "http_code": 200}, open(sys.argv[1], "w"))
PY
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-badpayload" --fixture-mode >"$TMP/badpayload.txt" 2>&1
expect_grep "$TMP/ev-badpayload/SUMMARY.txt" '^payload\.matches_request +NO' "size mismatch -> NO"

section "regression #5 (HIGH): strict curl evidence gate for direction verdicts"
# Direction may only be VERIFIED/PARTIAL when the transfer is backed by complete
# curl evidence: exit code 0, HTTP 200, actually-moved bytes ~= requested_bytes,
# plus in-transfer connection sampling. No fallback to meta.payload_bytes allowed.
direction_blocked() { # direction_blocked <dir> <label>
  expect_grep "$1/SUMMARY.txt" '^reality\.direction +(INCONCLUSIVE|NOT TESTED)' "$2 -> INCONCLUSIVE/NOT TESTED"
  expect_no_grep "$1/SUMMARY.txt" '^reality\.direction +(VERIFIED|PARTIAL)' "$2 -> never VERIFIED/PARTIAL"
}
analyze_strict() { # analyze_strict <dir>
  "$PY" "$ANALYZE" analyze --evidence-dir "$1" --fixture-mode >"$TMP/$(basename "$1").out.txt" 2>&1
}

# baseline: full successful transfer -> direction may be VERIFIED
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.direction +VERIFIED' "full successful curl transfer -> direction VERIFIED"

# curl rc != 0
cp -r "$TMP/ev-ok" "$TMP/ev-rc"
printf '28\n' > "$TMP/ev-rc/reality-dl-curl.rc"
analyze_strict "$TMP/ev-rc"
direction_blocked "$TMP/ev-rc" "curl exit 28 (timeout)"
expect_grep "$TMP/ev-rc/SUMMARY.txt" 'curl exit code=28' "rc failure reason is stated"
expect_grep "$TMP/ev-rc/SUMMARY.txt" '不回退到 meta.payload_bytes' "no-fallback to meta.payload_bytes is stated"

# HTTP 500
cp -r "$TMP/ev-ok" "$TMP/ev-http500"
"$PY" - "$TMP/ev-http500/reality-dl-curl.json" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1]))
data["http_code"] = 500
json.dump(data, open(sys.argv[1], "w"))
PY
analyze_strict "$TMP/ev-http500"
direction_blocked "$TMP/ev-http500" "HTTP 500"
expect_grep "$TMP/ev-http500/SUMMARY.txt" 'HTTP code=500' "HTTP failure reason is stated"

# corrupt curl JSON (stderr garbage instead of JSON)
cp -r "$TMP/ev-ok" "$TMP/ev-corrupt"
printf 'curl: (56) Recv failure: Connection was reset\n' > "$TMP/ev-corrupt/reality-dl-curl.json"
analyze_strict "$TMP/ev-corrupt"
direction_blocked "$TMP/ev-corrupt" "corrupt curl JSON"
expect_grep "$TMP/ev-corrupt/SUMMARY.txt" 'curl JSON 不可解析' "corrupt JSON reason is stated"

# missing curl JSON
cp -r "$TMP/ev-ok" "$TMP/ev-missing"
rm -f "$TMP/ev-missing/reality-dl-curl.json"
analyze_strict "$TMP/ev-missing"
direction_blocked "$TMP/ev-missing" "missing curl JSON"

# short transfer: only 90% of the requested bytes actually moved
cp -r "$TMP/ev-ok" "$TMP/ev-short"
"$PY" - "$TMP/ev-short/reality-dl-curl.json" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1]))
data["bytes_downloaded"] = int(data["requested_bytes"] * 0.9)
json.dump(data, open(sys.argv[1], "w"))
PY
analyze_strict "$TMP/ev-short"
direction_blocked "$TMP/ev-short" "90% of requested bytes"
expect_grep "$TMP/ev-short/SUMMARY.txt" '明显小于请求' "short-transfer reason is stated"

# 100% is the accepted case (covered by the ev-ok baseline above), so anything
# beyond the window must fail symmetrically in the other direction too
cp -r "$TMP/ev-ok" "$TMP/ev-over"
"$PY" - "$TMP/ev-over/reality-dl-curl.json" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1]))
data["bytes_downloaded"] = int(data["requested_bytes"] * 1.1)
json.dump(data, open(sys.argv[1], "w"))
PY
analyze_strict "$TMP/ev-over"
direction_blocked "$TMP/ev-over" "110% of requested bytes"
expect_grep "$TMP/ev-over/SUMMARY.txt" '明显大于请求' "over-transfer reason is stated"

section "regression #6: reaped transfer pids are removed from XFER_PIDS"
# kill_transfers runs from the EXIT trap and signals every pid left in XFER_PIDS.
# A pid already waited/reaped by await_xfer must have been dropped from that array,
# otherwise a recycled pid could be signalled by mistake.
mkdir -p "$TMP/reg"
cat > "$TMP/reg/xfer_test.sh" <<'XFERTEST'
set -uo pipefail
: "${LIB_DIR:?LIB_DIR must be set}"
EVROOT="$1"   # NOT EVID_DIR: sourcing lib/*.sh resets EVID_DIR to $PROBE_ROOT/evidence
mkdir -p "$EVROOT"
fail_with() { echo "XFER_FAIL: $1"; exit "$2"; }
. "$LIB_DIR/common.sh"
. "$LIB_DIR/evidence.sh"

# helper semantics: drops the matching pid, preserves order, ignores unknown pids
XFER_PIDS=(111 222 333)
remove_xfer_pid 222 || fail_with "remove_xfer_pid returned non-zero" 1
[ "${#XFER_PIDS[@]}" -eq 2 ] || fail_with "remove_xfer_pid did not drop the pid" 2
[ "${XFER_PIDS[0]}" = "111" ] && [ "${XFER_PIDS[1]}" = "333" ] \
  || fail_with "remove_xfer_pid corrupted the remaining pids" 3
remove_xfer_pid 999
[ "${#XFER_PIDS[@]}" -eq 2 ] || fail_with "removing an unknown pid changed the array" 4

# a real background job, waited/reaped by await_xfer, must vanish from XFER_PIDS
stem="$EVROOT/fake-dl-curl"
{ sleep 0.2; } &
pid=$!
XFER_PIDS+=( "$pid" )
await_xfer "$pid" "fake transfer" "$stem" || fail_with "await_xfer returned failure" 5
case " ${XFER_PIDS[*]} " in *" $pid "*) fail_with "reaped pid still in XFER_PIDS" 6 ;; esac
[ -s "$stem.rc" ] || fail_with "rc evidence missing after await_xfer" 7
[ "$(cat "$stem.rc")" = "0" ] || fail_with "rc should be 0 for a clean wait" 8

# kill_transfers with nothing active must be a no-op (nothing left to signal)
kill_transfers
[ "${#XFER_PIDS[@]}" -eq 0 ] || fail_with "XFER_PIDS not empty after kill_transfers" 9

# while an active transfer is still running, kill_transfers DOES signal it
{ sleep 30; } &
pid2=$!
XFER_PIDS+=( "$pid2" )
kill_transfers
wait "$pid2" 2>/dev/null
rc2=$?
[ "$rc2" -ne 0 ] || fail_with "kill_transfers did not signal an active transfer" 10

echo "XFER_OK"
exit 0
XFERTEST
if out="$(LIB_DIR="$LIB_DIR" bash "$TMP/reg/xfer_test.sh" "$TMP/reg/xfer-ev" 2>&1)"; then
  pass "transfer pid lifecycle: reaped pids removed, active pids signalled (XFER_OK)"
else
  fail "transfer pid lifecycle: $(printf '%s' "$out" | grep -E 'XFER_FAIL|Error|error' | head -n2 | tr '\n' ' ')"
fi

section "regression #7: runtime local-init order in evidence.sh (set -u)"
# Under `set -u`, referencing a variable inside the same `local` statement that
# declares it explodes at runtime ("prefix: unbound variable" was hit by the
# first real VPS run). This test actually EXECUTES run_direction_test /
# run_attribution_test with the network-facing pieces mocked out, and asserts
# the curl evidence stems are assembled exactly as expected.
cat > "$TMP/reg/init_test.sh" <<'INITTEST'
set -uo pipefail
: "${LIB_DIR:?LIB_DIR must be set}"
EVROOT="$1"
fail_with() { echo "INIT_FAIL: $1"; exit "$2"; }

export PROBE_ROOT="$EVROOT/probe-root"
mkdir -p "$PROBE_ROOT"
. "$LIB_DIR/common.sh"
. "$LIB_DIR/evidence.sh"

# Mock the network/collection side; the direction-test functions themselves run
# for real, including every `local` initialisation.
record_stem() { printf '%s\n' "$4" >> "$EVROOT/stems.txt"; }
api_snapshot() { :; }
sample_transfer() { printf '0\n'; }
await_xfer() { :; }
start_download() { record_stem "$@"; XFER_LAST="mock"; }
start_upload()   { record_stem "$@"; XFER_LAST="mock"; }

out="$(run_direction_test reality dl 18081 1024 1024 2>&1)" \
  || fail_with "run_direction_test reality dl crashed: $out" 1
out="$(run_direction_test reality ul 18081 1024 1024 2>&1)" \
  || fail_with "run_direction_test reality ul crashed: $out" 2
out="$(run_direction_test hy2 dl 18082 1024 1024 2>&1)" \
  || fail_with "run_direction_test hy2 dl crashed: $out" 3
out="$(run_direction_test hy2 ul 18082 1024 1024 2>&1)" \
  || fail_with "run_direction_test hy2 ul crashed: $out" 4
case "$out" in *"unbound variable"*) fail_with "unbound variable leaked: $out" 5 ;; esac

grep -qx "$PROBE_ROOT/evidence/reality-dl-curl" "$EVROOT/stems.txt" \
  || fail_with "reality dl stem wrong: $(cat "$EVROOT/stems.txt" | tr '\n' ' ')" 6
grep -qx "$PROBE_ROOT/evidence/reality-ul-curl" "$EVROOT/stems.txt" \
  || fail_with "reality ul stem wrong" 7
grep -qx "$PROBE_ROOT/evidence/hy2-dl-curl" "$EVROOT/stems.txt" \
  || fail_with "hy2 dl stem wrong" 8
grep -qx "$PROBE_ROOT/evidence/hy2-ul-curl" "$EVROOT/stems.txt" \
  || fail_with "hy2 ul stem wrong" 9

: > "$EVROOT/stems.txt"
out="$(run_attribution_test reality 18081 18083 2>&1)" \
  || fail_with "run_attribution_test crashed: $out" 10
case "$out" in *"unbound variable"*) fail_with "unbound variable in attribution: $out" 11 ;; esac
grep -qx "$PROBE_ROOT/evidence/reality-ab-a-curl" "$EVROOT/stems.txt" \
  || fail_with "reality ab-a stem wrong" 12
grep -qx "$PROBE_ROOT/evidence/reality-ab-b-curl" "$EVROOT/stems.txt" \
  || fail_with "reality ab-b stem wrong" 13

echo "INIT_OK"
exit 0
INITTEST
if out="$(LIB_DIR="$LIB_DIR" bash "$TMP/reg/init_test.sh" "$TMP/reg/init-ev" 2>&1)"; then
  pass "runtime init order: direction/attribution run under set -u with correct stems (INIT_OK)"
else
  fail "runtime init order: $(printf '%s' "$out" | grep -E 'INIT_FAIL|Error|error' | head -n2 | tr '\n' ' ')"
fi

section "regression #4: sink honours ?bytes= and enforces the cap"
SINK_PORT_TEST=$(( 18000 + (RANDOM % 2000) ))
"$PY" "$LIB_DIR/sink.py" --port "$SINK_PORT_TEST" --bytes 1048576 >"$TMP/sink.log" 2>&1 &
SINK_PID=$!
sink_ready=0
for _ in $(seq 1 20); do
  if curl -s -o /dev/null "http://127.0.0.1:$SINK_PORT_TEST/blob?bytes=1"; then sink_ready=1; break; fi
  sleep 0.3
done
if [ "$sink_ready" -eq 1 ]; then
  got="$(curl -s -o /dev/null -w '%{size_download}' "http://127.0.0.1:$SINK_PORT_TEST/blob?bytes=524288")"
  if [ "$got" = "524288" ]; then pass "GET ?bytes=524288 served exactly 524288 bytes"; else fail "GET ?bytes=524288 served $got bytes"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SINK_PORT_TEST/blob?bytes=99999999")"
  if [ "$code" = "400" ]; then pass "GET above cap -> HTTP 400"; else fail "GET above cap -> HTTP $code"; fi
  truncate -s 262144 "$TMP/up.bin" 2>/dev/null || head -c 262144 /dev/zero > "$TMP/up.bin"
  sent="$(curl -s -o /dev/null -w '%{size_upload}' --data-binary "@$TMP/up.bin" "http://127.0.0.1:$SINK_PORT_TEST/blob")"
  if [ "$sent" = "262144" ]; then pass "POST drained exactly the uploaded 262144 bytes"; else fail "POST drained $sent bytes"; fi
else
  fail "sink did not start on 127.0.0.1:$SINK_PORT_TEST ($(head -n2 "$TMP/sink.log" | tr '\n' ' '))"
fi
kill "$SINK_PID" 2>/dev/null
SINK_PID=""

section "regression #1 + #3: probe config generation and stale-config regeneration"
MOCK="$TMP/mock-sing-box"
cat > "$MOCK" <<'MOCK'
#!/usr/bin/env bash
# Mock sing-box: only what the probe generator needs. check validates JSON.
set -uo pipefail
cmd="${1:-}"; shift || true
hex() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
case "$cmd" in
  version) printf 'sing-box version 9.9.9-mock\n' ;;
  generate)
    case "${1:-}" in
      reality-keypair) printf 'PrivateKey: %s\nPublicKey: %s\n' "$(hex 32)" "$(hex 32)" ;;
      uuid) printf '%s-%s-%s-%s-%s\n' "$(hex 4)" "$(hex 2)" "$(hex 2)" "$(hex 2)" "$(hex 6)" ;;
      rand) printf '%s\n' "$(hex 4)" ;;
      *) exit 2 ;;
    esac ;;
  check)
    file=""
    while [ $# -gt 0 ]; do case "$1" in -c) file="$2"; shift 2 ;; *) shift ;; esac; done
    [ -n "$file" ] && [ -f "$file" ] || exit 1
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$file" ;;
  run) sleep 3600 ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$MOCK"

mkdir -p "$TMP/reg/sbox-probe/certs" "$TMP/reg/sbox-probe/run" "$TMP/reg/sbox-probe/evidence"
# Non-empty placeholders so the test does not depend on openssl; the mock check only
# validates JSON, so the certificate content is irrelevant here.
printf 'dummy-cert' > "$TMP/reg/sbox-probe/certs/cert.pem"
printf 'dummy-key' > "$TMP/reg/sbox-probe/certs/private.key"
printf '{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":13579},{"type":"hysteria2","tag":"hy2-in","listen_port":24680}]}\n' > "$TMP/reg/prod.json"
printf "SERVER_IP='203.0.113.7'\nHY_HOPPING=FALSE\nHY_HOPPING_START=\nHY_HOPPING_END=\n" > "$TMP/reg/state"

cat > "$TMP/reg/probe_regress.sh" <<'REGRESS'
set -uo pipefail
. "$LIB_DIR/common.sh"
. "$LIB_DIR/probe-config.sh"
. "$LIB_DIR/evidence.sh"

fail_with() { echo "REGRESS_FAIL: $1"; exit "$2"; }

EXPOSE=0
PUBLIC_IP=203.0.113.9
export EXPOSE PUBLIC_IP

generate_all_configs || fail_with "generate_all_configs (local)" 20
check_all_configs || fail_with "check_all_configs (local)" 21
grep -q '"listen": "127.0.0.1"' "$PROBE_CONFIG" || fail_with "local config must bind 127.0.0.1" 22

# --- regression #1: two distinct Reality UUIDs -------------------------------
UUID_A="$(python3 "$LIB_DIR/analyze.py" getkey "$KEYS_FILE" reality_uuid_a)"
UUID_B="$(python3 "$LIB_DIR/analyze.py" getkey "$KEYS_FILE" reality_uuid_b)"
[ -n "$UUID_A" ] && [ -n "$UUID_B" ] || fail_with "keys.json must carry two UUIDs" 30
[ "$UUID_A" != "$UUID_B" ] || fail_with "probe-a and probe-b must not share a UUID" 31
grep -q "\"name\": \"$USER_A\", \"uuid\": \"$UUID_A\"" "$PROBE_CONFIG" || fail_with "probe-a must use UUID-A in probe.json" 32
grep -q "\"name\": \"$USER_B\", \"uuid\": \"$UUID_B\"" "$PROBE_CONFIG" || fail_with "probe-b must use UUID-B in probe.json" 33
CLIENT_A_UUID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["outbounds"][0]["uuid"])' "$PROBE_ROOT/client-a-reality.json")"
CLIENT_B_UUID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["outbounds"][0]["uuid"])' "$PROBE_ROOT/client-b-reality.json")"
[ "$CLIENT_A_UUID" = "$UUID_A" ] || fail_with "client-a-reality must carry UUID-A" 34
[ "$CLIENT_B_UUID" = "$UUID_B" ] || fail_with "client-b-reality must carry UUID-B" 35
[ "$CLIENT_A_UUID" != "$CLIENT_B_UUID" ] || fail_with "the two Reality clients must not share a UUID" 36

# --- regression #3: prepare(local) then --expose must not reuse the stale config
config_is_current || fail_with "freshly generated config must be current" 40
EXPOSE=1
export EXPOSE
ensure_config_current || fail_with "ensure_config_current" 41
grep -q '"listen": "::"' "$PROBE_CONFIG" || fail_with "run --expose must regenerate a listen :: config" 42
[ -s "$PROBE_ROOT/client-a-reality-external.json" ] || fail_with "external client configs must be written" 43
python3 "$LIB_DIR/analyze.py" check-manifest --manifest "$(probe_manifest_file)" \
  --probe-root "$PROBE_ROOT" --expose 0 --reality-port "$REALITY_PORT" --hy2-port "$HY2_PORT" \
  --clash-port "$CLASH_PORT" --sink-port "$SINK_PORT" --public-ip "$PUBLIC_IP" \
  --payload-bytes "$PAYLOAD_BYTES" --transfer-rate "$TRANSFER_RATE" \
  --probe-config "$PROBE_CONFIG" >/dev/null 2>&1 \
  && fail_with "check-manifest must report stale for different flags" 44

# idempotence: a second ensure must not touch the config
BEFORE="$(sha256sum "$PROBE_CONFIG" | awk '{print $1}')"
ensure_config_current || fail_with "ensure_config_current (second)" 45
AFTER="$(sha256sum "$PROBE_CONFIG" | awk '{print $1}')"
[ "$BEFORE" = "$AFTER" ] || fail_with "matching config must not be regenerated" 46

# editing the config by hand must invalidate the manifest
printf '\n' >> "$PROBE_CONFIG"
ensure_config_current || fail_with "ensure_config_current (after edit)" 47
grep -q '"listen": "::"' "$PROBE_CONFIG" || fail_with "edited config must be regenerated with current flags" 48

echo "REGRESS_OK"
exit 0
REGRESS

if out="$(LIB_DIR="$LIB_DIR" PROBE_ROOT="$TMP/reg/sbox-probe" PROD_BIN="$MOCK" \
          PROD_CONFIG="$TMP/reg/prod.json" PROD_STATE="$TMP/reg/state" \
          REALITY_PORT=18443 HY2_PORT=18444 CLASH_PORT=19090 \
          SINK_PORT=18080 SOCKS_AR=18081 SOCKS_AH=18082 SOCKS_BR=18083 SOCKS_BH=18084 \
          PAYLOAD_BYTES=67108864 TRANSFER_RATE=4194304 \
          bash "$TMP/reg/probe_regress.sh" 2>&1)"; then
  pass "probe config generation + manifest regression script (REGRESS_OK)"
else
  fail "probe regression script: $(printf '%s' "$out" | grep -E 'REGRESS_FAIL|Error|error' | head -n2 | tr '\n' ' ')"
fi
if grep -q '"name": "probe-a"' "$TMP/reg/sbox-probe/probe.json" 2>/dev/null; then
  ua="$(python3 "$ANALYZE" getkey "$TMP/reg/sbox-probe/keys.json" reality_uuid_a 2>/dev/null)"
  ub="$(python3 "$ANALYZE" getkey "$TMP/reg/sbox-probe/keys.json" reality_uuid_b 2>/dev/null)"
  if [ -n "$ua" ] && [ -n "$ub" ] && [ "$ua" != "$ub" ]; then
    pass "two Reality users carry different UUIDs ($ua != $ub)"
  else
    fail "Reality UUIDs: a='$ua' b='$ub'"
  fi
  if grep -q '"listen": "::"' "$TMP/reg/sbox-probe/probe.json"; then
    pass "final config was regenerated for expose mode (listen ::)"
  else
    fail "final config still not in expose mode"
  fi
else
  fail "probe.json was not generated by the regression script"
fi

printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
