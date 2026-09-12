#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PHASE_D="$ROOT/lib/phase-d.sh"
PASS=0; FAIL=0; TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
pass(){ PASS=$((PASS+1)); echo "PASS $*"; }
fail(){ FAIL=$((FAIL+1)); echo "FAIL $*"; }
check(){ if "$@"; then pass "$*"; else fail "$*"; fi; }

bash -n "$PHASE_D" && pass "bash -n phase-d" || fail "bash -n phase-d"
. "$PHASE_D"

cat >"$TMP/releases.json" <<'EOF'
[
 {"tag_name":"v1.15.0-alpha.2","draft":false,"prerelease":true},
 {"tag_name":"v1.14.2","draft":false,"prerelease":false},
 {"tag_name":"v1.14.10","draft":false,"prerelease":false},
 {"tag_name":"v1.13.99","draft":false,"prerelease":false}
]
EOF
sel="$(phase_d_select_release_from_json <"$TMP/releases.json")"
[ "$sel" = "v1.14.10" ] && pass "D1 select newest 1.14.x" || fail "D1 got $sel"
phase_d_release_tag_is_allowed v1.14.0 && pass "D1 allow 1.14.0" || fail "D1 reject 1.14.0"
phase_d_release_tag_is_allowed v1.15.0 && fail "D1 accepted 1.15.0" || pass "D1 reject 1.15.0"
phase_d_release_tag_is_allowed v1.15.0-alpha.2 && fail "D1 accepted alpha" || pass "D1 reject alpha"

cat >"$TMP/base.json" <<'EOF'
{
 "inbounds":[
  {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"u","flow":"xtls-rprx-vision"}]},
  {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"p"}]}
 ]
}
EOF
phase_d_inject_api_service "$TMP/base.json" "$TMP/api.json" && pass "D2 inject api" || fail "D2 inject api"
phase_d_api_service_exact "$TMP/api.json" && pass "D2 exact loopback api" || fail "D2 exact loopback api"
phase_d_inject_api_service "$TMP/api.json" "$TMP/api2.json" && pass "D3 idempotent call" || fail "D3 idempotent call"
[ "$(jq -S . "$TMP/api.json")" = "$(jq -S . "$TMP/api2.json")" ] && pass "D3 idempotent content" || fail "D3 changed content"

jq '.services={}' "$TMP/base.json" >"$TMP/bad.json"
phase_d_inject_api_service "$TMP/bad.json" "$TMP/out.json" >/dev/null 2>&1 && fail "D4 accepted non-array services" || pass "D4 reject non-array services"

jq '.services=[{"type":"api","tag":"monitor-api","listen":"0.0.0.0","listen_port":9091}]' "$TMP/base.json" >"$TMP/public.json"
phase_d_inject_api_service "$TMP/public.json" "$TMP/public-out.json" >/dev/null 2>&1 && fail "D5 accepted public api" || pass "D5 reject public api"

cat >"$TMP/unnamed.json" <<'EOF'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"uuid":"u","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"password":"p"}]}
]}
EOF
phase_d_config_ready "$TMP/unnamed.json" >/dev/null 2>&1 && fail "D6 accepted unnamed legacy" || pass "D6 block unnamed legacy"
phase_d_config_ready "$TMP/base.json" >/dev/null 2>&1 && pass "D6 named config ready" || fail "D6 named config rejected"

jq '(.inbounds[]|select(.tag=="hy2-in")|.users[0].name)="other"' "$TMP/base.json" >"$TMP/mismatch.json"
phase_d_config_ready "$TMP/mismatch.json" >/dev/null 2>&1 && fail "D7 accepted identity mismatch" || pass "D7 reject identity mismatch"

echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
