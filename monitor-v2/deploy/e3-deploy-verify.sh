#!/usr/bin/env bash
# e3-deploy-verify.sh -- post-deployment acceptance for the E3 M3 deploy-
# disabled rollout (compare against the preflight baseline).
#
# Acceptance contract: after deploying the new monitor release and sbox-cm,
# the production box must be in EXACTLY the pre-deployment shape except for
# the new capability being present-but-closed:
#   * sing-box config SHA256 identical to the baseline (config untouched);
#   * sing-box NOT restarted (ActiveEnterTimestamp + NRestarts identical --
#     the deployment itself must not trigger a reload/restart);
#   * monitor healthy and answering read-only HTTP;
#   * sbox-cm.socket/.service active;
#   * activation marker absent -> management plane INACTIVE;
#   * sboxweb-context RPC: management.status = inactive, client.list readable;
#   * Web E3 UI loads;
#   * a mutation attempt in the inactive state is REFUSED with
#     E_ACTIVATION_STATE and the config SHA is unchanged afterwards -- the
#     fail-closed proof. This dispatches NO mutation: the helper rejects
#     pre-intent; the only residue is one "rejected" audit record.
#
# Output: E3_M3_VERIFY=PASS (exit 0) / E3_M3_VERIFY=FAIL (exit 1).
#
# Environment overrides: same as e3-preflight.sh, plus
#   E3_MONITOR_APP used for the sboxweb-context RPC probe (web.e3rpc).
set -uo pipefail

E3_SYSTEMCTL="${E3_SYSTEMCTL:-systemctl}"
E3_CONFIG="${E3_CONFIG:-/root/sbox/sbconfig_server.json}"
E3_SING_BOX_BIN="${E3_SING_BOX_BIN:-/root/sbox/sing-box}"
E3_SBXCM_STATE="${E3_SBXCM_STATE:-/var/lib/sbox-cm}"
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_MONITOR_APP="${E3_MONITOR_APP:-/opt/singbox-monitor}"
BASELINE=""

while (($# > 0)); do
    case "$1" in
        --baseline) BASELINE="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$BASELINE" ] && [ -f "$BASELINE" ] \
    || { printf 'a --baseline FILE from e3-preflight.sh is required\n' >&2; exit 2; }

PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

printf '===== E3 M3 DEPLOY VERIFICATION (deploy-disabled contract) =====\n'

B_SHA="$(jqv "$(cat "$BASELINE")" '.config_sha256')"
B_SIZE="$(jqv "$(cat "$BASELINE")" '.config_size')"
B_TS="$(jqv "$(cat "$BASELINE")" '.singbox.active_enter_timestamp')"
B_RESTARTS="$(jqv "$(cat "$BASELINE")" '.singbox.nrestarts')"

# V01/V02: config byte-identical to the pre-deployment baseline
NOW_SHA="$(sha256sum "$E3_CONFIG" 2>/dev/null | awk '{print $1}')"
NOW_SIZE="$(stat -c %s "$E3_CONFIG" 2>/dev/null)"
if [ -n "$NOW_SHA" ] && [ "$NOW_SHA" = "$B_SHA" ]; then
    pass "V01 config SHA256 identical to the baseline ($NOW_SHA)"
else
    fail "V01 config SHA256 CHANGED (baseline=[$B_SHA] now=[$NOW_SHA])"
fi
if [ "${NOW_SIZE:-0}" = "$B_SIZE" ]; then
    pass "V02 config size identical to the baseline"
else
    fail "V02 config size changed (baseline=[$B_SIZE] now=[${NOW_SIZE:-?}])"
fi

# V03: sing-box was NOT restarted (the deploy must not reload/restart it)
SB_TS="$("$E3_SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"
SB_RESTARTS="$("$E3_SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"
SB_ACTIVE="$("$E3_SYSTEMCTL" is-active sing-box.service 2>/dev/null || true)"
if [ "$SB_ACTIVE" = "active" ] && [ "$SB_TS" = "$B_TS" ] \
        && [ "${SB_RESTARTS:-0}" = "$B_RESTARTS" ]; then
    pass "V03 sing-box NOT restarted by the deployment (ts/restarts identical)"
else
    fail "V03 sing-box restart detected (ts baseline=[$B_TS] now=[$SB_TS], restarts baseline=[$B_RESTARTS] now=[${SB_RESTARTS:-?}])"
fi

# V04: monitor healthy + read-only HTTP
MON_ACTIVE="$("$E3_SYSTEMCTL" is-active singbox-monitor.service 2>/dev/null || true)"
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    "$E3_MONITOR_URL/api/v1/session" 2>/dev/null || true)"
if [ "$MON_ACTIVE" = "active" ] && [ "$HTTP_CODE" = "200" ]; then
    pass "V04 monitor active and read-only API answers 200"
else
    fail "V04 monitor unhealthy (active=[$MON_ACTIVE], HTTP=[$HTTP_CODE])"
fi

# V05a: the SOCKET must be active. The service is socket-activated and is
# EXPECTED to be inactive until the first RPC -- requiring it here would
# contradict the D4 socket-only enablement (final review fix).
if "$E3_SYSTEMCTL" is-active --quiet sbox-cm.socket 2>/dev/null; then
    pass "V05a sbox-cm.socket active (service activation deferred to the first RPC)"
else
    fail "V05a sbox-cm.socket is NOT active"
fi

# V06: marker absent -> management plane inactive
if [ ! -e "$E3_SBXCM_STATE/management.active" ]; then
    pass "V06 activation marker absent (management plane inactive)"
else
    fail "V06 activation marker EXISTS (plane armed -- deploy-disabled violated)"
fi

# V07/V08: sboxweb-context RPC -- management.status = inactive, client.list
# readable. The probe runs from STDIN with -B (no bytecode writes): the
# current monitor release tree must stay byte-identical (final review fix --
# the previous version wrote a probe file INTO the release tree).
E3_PROBE_APP="$E3_MONITOR_APP"
SBOXWEB_PROBE(){ sudo -n -u sboxweb /usr/bin/python3 -B - "$E3_PROBE_APP" "$@" <<'PROBE'
import json, sys
sys.path.insert(0, sys.argv[1])
from web.e3rpc import E3RpcClient
client = E3RpcClient()
op = sys.argv[2]
payload = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
verdict = client.call(op, payload=payload)
print(json.dumps(verdict))
PROBE
}
STATUS_V="$(SBOXWEB_PROBE management.status 2>/dev/null)"
MSTATE="$(jqv "$STATUS_V" '.data.management_state')"
if [ "$(jqv "$STATUS_V" '.ok')" = "true" ] && [ "$MSTATE" = "inactive" ]; then
    pass "V07 management.status (sboxweb RPC) reports inactive"
else
    fail "V07 management.status must report inactive (got [$MSTATE])"
fi

# V05b: the real RPC above proves socket activation actually pulled the
# daemon up (this check deliberately comes AFTER the first RPC, not before).
if "$E3_SYSTEMCTL" is-active --quiet sbox-cm.service 2>/dev/null; then
    pass "V05b sbox-cm.service pulled up by the real RPC (socket activation works)"
else
    fail "V05b sbox-cm.service was NOT pulled up by the RPC"
fi

LIST_V="$(SBOXWEB_PROBE client.list 2>/dev/null)"
if [ "$(jqv "$LIST_V" '.ok')" = "true" ] \
        && [ "$(jqv "$LIST_V" '.data.truncated')" != "null" ]; then
    NCLIENTS="$(jqv "$LIST_V" '.data.clients | length')"
    pass "V08 client.list (sboxweb RPC) readable ($NCLIENTS clients)"
else
    fail "V08 client.list not readable over the sboxweb RPC"
fi

# V09: the Web E3 UI loads
INDEX_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    "$E3_MONITOR_URL/" 2>/dev/null || true)"
APP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    "$E3_MONITOR_URL/static/app.js" 2>/dev/null || true)"
UI_E3="$(curl -sS --max-time 5 "$E3_MONITOR_URL/" 2>/dev/null | grep -cF 'e3-clients-table' || true)"
if [ "$INDEX_CODE" = "200" ] && [ "$APP_CODE" = "200" ] \
        && [ "${UI_E3:-0}" -ge 1 ]; then
    pass "V09 Web E3 UI loads (index+app.js 200, clients table present)"
else
    fail "V09 Web E3 UI did not load (index=[$INDEX_CODE] app.js=[$APP_CODE] table=[$UI_E3])"
fi

# V10: mutation in the inactive state is fail-closed, config untouched
FAKE_KEY="m3-verify-failclosed-key-001"
ADD_V="$(SBOXWEB_PROBE client.add \
    '{"name":"deploy-verify-neg","idempotency_key":"m3-verify-failclosed-key-001"}' 2>/dev/null)"
if [ "$(jqv "$ADD_V" '.ok')" = "false" ] \
        && [ "$(jqv "$ADD_V" '.error.code')" = "E_ACTIVATION_STATE" ]; then
    pass "V10 mutation while inactive is fail-closed (E_ACTIVATION_STATE, zero changes)"
else
    fail "V10 the inactive-plane mutation was not refused with E_ACTIVATION_STATE"
fi
NOW_SHA2="$(sha256sum "$E3_CONFIG" 2>/dev/null | awk '{print $1}')"
if [ "$NOW_SHA2" = "$NOW_SHA" ]; then
    pass "V11 config SHA256 unchanged after the fail-closed probe"
else
    fail "V11 config changed during the fail-closed probe -- INVESTIGATE"
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M3_VERIFY=FAIL\n'
    exit 1
fi
printf 'E3_M3_VERIFY=PASS\n'
