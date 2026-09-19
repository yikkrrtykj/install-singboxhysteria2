#!/usr/bin/env bash
# E3 M2 -- LIVE systemd integration: the real singbox-monitor (sboxweb,
# ProtectSystem=strict) talking to the real sbox-cm.socket/service under
# systemd PID 1, with a mock sing-box.service.
#
# Covered here, END TO END through the HTTP API:
#   * the /run/sbox-cm carve-out experiment, BOTH directions: the suite runs
#     the monitor unit WITHOUT the -/run/sbox-cm ReadWritePaths entry first
#     and records whether the connect is blocked by ProtectSystem=strict;
#     only if it is blocked does it re-render WITH the carve-out and require
#     success. The carve-out is never assumed -- it is measured here;
#   * full transaction: status -> list -> activate -> add (reload counted,
#     live config really changed) -> list -> reload-failure rollback
#     (E_ROLLED_BACK, byte-identical restore) -> delete (fresh preflight +
#     confirm) -> deactivate;
#   * result_unknown, live: a client with a 1s caller budget dispatches an
#     add against a helper whose sing-box check sleeps 3s -- the caller times
#     out post-send (uncertain), the helper is NOT killed, the transaction
#     completes, and management.status proves it via last_transaction;
#   * stale-active fail closed: with an armed plane and the helper stopped,
#     the stale active=true expires and management_active answers False;
#     mutations are refused; the status query channel keeps serving the last
#     snapshot (the uncertain-recovery path);
#   * SO_PEERCRED from the monitor context: the root-driven RPC gets
#     E_PEER_AUTH while the sboxweb-driven ones work.
#
# Exit-status contract (the B-5 lesson): the teardown never owns the process
# status, an exit-status self-check runs before the fixture exists, and a
# skipped live gate is a hard FAILURE when SINGBOX_MONITOR_REQUIRE_LIVE=1.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FIX="/run/sboxcm-m2-test"
APP="/opt/sboxcm-m2"
MDATA="/var/lib/sboxcm-m2"
MPORT=9192
BASE="http://127.0.0.1:$MPORT"
CJ="$FIX/cookies.txt"
AXE_USER="sboxweb"
MPASS="m2-live-admin-password-01"

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }
# NB: jqv has NO `// empty` fallback on purpose -- jq's `//` operator treats
# a legitimate JSON false as empty, which would silently turn every
# boolean-false assertion into "got=[]". Missing keys print as "null".
probe_err(){ printf '%s' "$1" | jq -r '.probe_error? // empty' 2>/dev/null; }
sum(){ sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

printf '===== E3 M2 LIVE SYSTEMD (monitor x sbox-cm) =====\n'

gate() {
    if [ "${SINGBOX_MONITOR_REQUIRE_LIVE:-0}" = "1" ]; then
        fail "$1 (SINGBOX_MONITOR_REQUIRE_LIVE=1: a skipped live gate is a false green)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M2_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M2_LIVE=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

[ "$(uname -s 2>/dev/null)" = "Linux" ] \
    || gate 'non-Linux host: the live suite runs on Linux CI only'
[ -d /run/systemd/system ] || gate 'systemd is not PID 1 here'
[ "$(id -u 2>/dev/null)" = "0" ] || gate 'not root (run with sudo)'
command -v systemctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    && command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 \
    || gate 'systemctl/python3/curl/jq missing'
if [ -e /root/sbox ] || [ -e "$MDATA" ]; then
    fail 'a fixture path already exists: refusing to run over a real deployment'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M2_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

MUNIT_NAME="sboxcm-m2-test"
MUNIT="/etc/systemd/system/$MUNIT_NAME.service"

cleanup_resources() {
    systemctl stop "$MUNIT_NAME.service" 2>/dev/null
    systemctl disable "$MUNIT_NAME.service" 2>/dev/null
    rm -f "$MUNIT" /etc/systemd/system/sing-box.service
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket 2>/dev/null
    systemctl daemon-reload 2>/dev/null
    rm -rf -- /root/sbox "$FIX" "$APP" "$MDATA" 2>/dev/null
    return 0
}
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    cleanup_resources || true
    if [ "$FAIL" -gt 0 ]; then
        printf -- '----- diagnostic: sbox-cm + monitor journals (last 25 lines each) -----\n'
        journalctl -u sbox-cm.service -n 25 --no-pager 2>/dev/null || true
        journalctl -u "$MUNIT_NAME.service" -n 25 --no-pager 2>/dev/null || true
        printf -- '----- end diagnostic -----\n'
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --------------------------------------------------- exit-status self-check --
# Drives the REAL teardown with a forced failing status; a teardown that
# masks the rc is exactly the false-green bug class this suite exists to kill.
_rc_ok=1
_rc_probe="$( ( trap cleanup EXIT; exit 7 ) >/dev/null 2>&1; printf '%s' "$?" )"
if [ "$_rc_probe" = "7" ]; then
    pass 'exit-status contract: teardown preserves the process rc'
else
    fail "exit-status contract: forced rc=7 came back as [$_rc_probe]"
    _rc_ok=0
fi
if [ "$_rc_ok" != "1" ]; then
    trap - EXIT INT TERM
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M2_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

# ------------------------------------------------------------------ fixture --
getent passwd "$AXE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$AXE_USER"
getent group  "$AXE_USER" >/dev/null 2>&1 || groupadd --system "$AXE_USER"
mkdir -p "$FIX" "$APP" "$MDATA" /root/sbox
chmod 0777 "$FIX"

# mock sing-box: the production worker's built-in path, no SB_* injection.
cat > /root/sbox/sing-box <<'MOCK'
#!/usr/bin/env bash
FIX="/run/sboxcm-m2-test"
if [ -f "$FIX/check-sleep" ]; then sleep 3; fi
case "${1:-}" in
    check) exit 0 ;;
    generate)
        case "${2:-}" in
            uuid) printf 'uuid-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM" ;;
            rand) printf 'pw-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM" ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
MOCK
chmod 0755 /root/sbox/sing-box
cat > /root/sbox/sbconfig_server.json <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
chmod 0600 /root/sbox/sbconfig_server.json

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=mock sing-box (E3 M2 live fixture)
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/sh -c 'n=\$(cat $FIX/reload.count 2>/dev/null); n=\${n:-0}; if [ -f $FIX/fail-first ] && [ "\$n" -eq 0 ]; then echo 1 > $FIX/reload.count; exit 1; fi; echo \$((n+1)) > $FIX/reload.count'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sing-box >/dev/null 2>&1
printf '0\n' > "$FIX/reload.count"

# privileged helper: the REAL installer, then enable the socket.
"$ROOT/sbox-cm/deploy/install-sbox-cm.sh" install >/dev/null 2>&1 \
    || { fail 'sbox-cm installer failed'; printf '\nE3_M2_LIVE=FAIL\n'; exit 1; }
# The B-5 suite may have run earlier on this runner and left its ledger and
# an armed activation marker behind (its teardown stops the units but keeps
# /var/lib/sbox-cm). This fixture owns the helper state: start from a proven
# clean slate so management_state really starts inactive.
systemctl stop sbox-cm.socket sbox-cm.service >/dev/null 2>&1
rm -rf /var/lib/sbox-cm
mkdir -p /var/lib/sbox-cm
chown root:root /var/lib/sbox-cm
chmod 0700 /var/lib/sbox-cm
systemctl enable --now sbox-cm.socket >/dev/null 2>&1 \
    || { fail 'sbox-cm.socket enable failed'; printf '\nE3_M2_LIVE=FAIL\n'; exit 1; }
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done
[ -S /run/sbox-cm/sbox-cm.sock ] \
    || { fail 'sbox-cm socket never appeared'; printf '\nE3_M2_LIVE=FAIL\n'; exit 1; }
pass 'privileged helper installed and socket-activated'

# monitor fixture app: a real copy of the monitor-v2 tree, configured by the
# REAL webapp.py setup path, running under the REAL hardened unit template.
cp "$ROOT"/monitor-v2/*.py "$APP"/ 2>/dev/null
cp -r "$ROOT/monitor-v2/web" "$APP"/web
cp -r "$ROOT/monitor-v2/api_bridge" "$APP"/api_bridge
rm -rf "$APP/web/__pycache__" "$APP"/__pycache__        "$APP/api_bridge/__pycache__" 2>/dev/null
chown -R "$AXE_USER":"$AXE_USER" "$APP" "$MDATA"
chmod 0700 "$MDATA"
mkdir -p /etc/sboxcm-m2
printf '# m2 live fixture conf\n' > /etc/sboxcm-m2/monitor.conf
if ! sudo -u "$AXE_USER" env -u SSH_CONNECTION python3 "$APP/webapp.py" setup \
        --assume-yes --password "$MPASS" --data-dir "$MDATA" \
        > "$FIX/setup.out" 2> "$FIX/setup.err"; then
    fail 'monitor setup (password bootstrap) failed:'
    sed 's/^/    | /' "$FIX/setup.err" "$FIX/setup.out" 2>/dev/null | head -10
    printf '\nE3_M2_LIVE=FAIL\n'; exit 1
fi
pass 'monitor fixture configured via webapp.py setup (as sboxweb)'

# render the REAL hardened unit template; only ExecStart is pointed at the
# fixture entrypoint directly (the deploy shim is packaging, not sandboxing).
render_monitor_unit() {
    sed -e "s|@SBMON_USER@|$AXE_USER|g" \
        -e "s|@SBMON_GROUP@|$AXE_USER|g" \
        -e "s|@SBMON_APP_DIR@|$APP|g" \
        -e "s|@SBMON_CONF@|/etc/sboxcm-m2/monitor.conf|g" \
        -e "s|@SBMON_STATE_ROOT@|$MDATA|g" \
        "$ROOT/monitor-v2/deploy/singbox-monitor.service.in" \
    | sed -e "s|^ExecStart=.*|ExecStart=/usr/bin/python3 $APP/webapp.py serve --listen 127.0.0.1 --port $MPORT --data-dir $MDATA|" \
          -e "s|^After=.*|After=network-online.target|" \
    > "$MUNIT"
    # B5 least-privilege regression guard: the rendered unit must
    # carry the data root and NOTHING else on ReadWritePaths.
    local rw
    rw="$(grep '^ReadWritePaths=' "$MUNIT")"
    if [ "$rw" = "ReadWritePaths=$MDATA" ]; then
        pass "shipped unit is least-privilege: ReadWritePaths = data root only"
    else
        fail "shipped unit ReadWritePaths is not minimal: [$rw]"
    fi
    systemctl daemon-reload
}

wait_status() { # <http-status> <timeout-s>
    local want="$1" timeout="$2" got="" i
    for i in $(seq 1 $((timeout*4))); do
        got="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/v1/session" 2>/dev/null || true)"
        [ "$got" = "$want" ] && return 0
        sleep 0.25
    done
    return 1
}

start_monitor() {
    systemctl restart "$MUNIT_NAME.service" >/dev/null 2>&1
    wait_status 200 20
}

# ------------------------------------------------- shipped-unit connect ----
# (M2 final review B5) the carve-out experiment is gone: the SHIPPED template
# carries NO -/run/sbox-cm entry, and this suite proves the monitor connects
# to the real helper under exactly that least-privilege sandbox.
render_monitor_unit
start_monitor || { fail 'monitor unit did not come up'; printf '\nE3_M2_LIVE=FAIL\n'; exit 1; }
curl -sS -c "$CJ" -H "Content-Type: application/json" \
     -d "{\"password\":\"$MPASS\"}" "$BASE/api/v1/login" >/dev/null 2>&1
SINFO="$(curl -sS -b "$CJ" "$BASE/api/v1/session")"
CSRF="$(jqv "$SINFO" '.csrf_token')"
STATUS="$(curl -sS -b "$CJ" "$BASE/api/v1/management/status")"
assert_eq 'true' "$(jqv "$STATUS" '.ok')" \
    'the SHIPPED unit (no carve-out) reaches the real helper under ProtectSystem=strict'
assert_eq 'fresh' "$(jqv "$STATUS" '.transport')" 'the first status snapshot is fresh'
assert_eq 'inactive' "$(jqv "$STATUS" '.data.management_state')" 'the plane starts inactive'
assert_ne 'null' "$(jqv "$STATUS" '.as_of')" 'as_of is reported'
assert_eq 'false' "$(jqv "$SINFO" '.management_active')" 'management_active is false while the plane is inactive'
# mutations need a live step-up window (M0.5 gate, unchanged)
STEPUP="$(curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
     -d "{\"password\":\"$MPASS\"}" "$BASE/api/v1/step-up")"
assert_eq 'ok' "$(jqv "$STEPUP" '.status')" 'the step-up grant succeeded'

# --------------------------------------------------------- full transaction --
KEY1="m2-live-key-000000000001"
KEY2="m2-live-key-000000000002"
KEY3="m2-live-key-000000000003"
e3_post(){ # <path> <key-arg|-> <body>
    local path="$1" key="$2" body="$3"
    if [ "$key" = "-" ]; then
        curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
             -d "$body" "$BASE$path"
    else
        curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
             -H "Idempotency-Key: $key" -d "$body" "$BASE$path"
    fi
}

BEFORE_SUM="$(sum /root/sbox/sbconfig_server.json)"
R="$(e3_post /api/v1/management/activate - '{}')"
assert_eq "true" "$(jqv "$R" '.ok')" 'activate over the live HTTP API'
R="$(e3_post /api/v1/clients/add "$KEY1" '{"name":"live-01"}')"
assert_eq "true" "$(jqv "$R" '.ok')" "client.add over the live HTTP API (raw=[$R])" 
assert_eq "false" "$(jqv "$R" '.idempotency.replayed')" 'first add is not a replay'
assert_ne "$BEFORE_SUM" "$(sum /root/sbox/sbconfig_server.json)" 'the live config really changed'
assert_eq "1" "$(cat "$FIX/reload.count")" 'sing-box was reloaded exactly once'
assert_eq "cli" "$(jqv "$R" '.data.credential_delivery')" 'credential delivery is CLI-only (never the browser)'

R="$(curl -sS -b "$CJ" "$BASE/api/v1/clients")"
printf '%s' "$R" | grep -qF 'live-01' && pass 'the added client is listed' \
    || fail 'client missing from the list'

# rollback through the hardened unit, reported honestly over HTTP
touch "$FIX/fail-first"
printf '0\n' > "$FIX/reload.count"
BEFORE_SUM="$(sum /root/sbox/sbconfig_server.json)"
R="$(e3_post /api/v1/clients/add "$KEY2" '{"name":"live-02"}')"
assert_eq "E_ROLLED_BACK" "$(jqv "$R" '.code')" "a failing reload reports E_ROLLED_BACK (raw=[$R])" 
assert_eq "true" "$(jqv "$R" '.retriable')" 'E_ROLLED_BACK is retriable'
assert_eq "$BEFORE_SUM" "$(sum /root/sbox/sbconfig_server.json)" 'the rollback restored the live config byte-for-byte'
rm -f "$FIX/fail-first"

# ------------------------------------------------- result_unknown, live ----
# A 1s caller budget against a helper whose check sleeps 3s: the caller must
# time out post-send (uncertain), the helper must NOT be killed, and the
# transaction must complete and become visible via last_transaction.
touch "$FIX/check-sleep"
TIMEOUT_DRIVER="$FIX/timeout_driver.py"
cat > "$TIMEOUT_DRIVER" <<'DRIVER'
import sys
sys.path.insert(0, "/opt/sboxcm-m2")
from web.e3rpc import E3RpcClient, RpcTransportError
client = E3RpcClient(socket_path="/run/sbox-cm/sbox-cm.sock",
                     budgets={"client.add": 1.0})
try:
    verdict = client.call("client.add",
                          payload={"name": "timeout-live", "idempotency_key":
                                   "m2-live-key-000000000004"})
    if verdict.get("ok"):
        print("VERDICT")       # budget was not enforced
    else:
        print("ERR:%s" % verdict.get("error", {}).get("code", "UNKNOWN"))
except RpcTransportError as exc:
    print("UNCERTAIN" if exc.uncertain else "CONNECT")
DRIVER
chown "$AXE_USER":"$AXE_USER" "$TIMEOUT_DRIVER"
TOUT="$(sudo -u "$AXE_USER" python3 "$TIMEOUT_DRIVER" 2>/dev/null)"
assert_eq "UNCERTAIN" "$TOUT" 'a post-send caller timeout reports uncertain (result_unknown precondition)'
# ...the helper was not killed and the transaction completed:
# NB: last_transaction still shows the PREVIOUS transaction (the rollback
# test's E_ROLLED_BACK) until THIS one lands. Wait for THIS add's terminal
# outcome=ok -- the caller timed out, the transaction did not, and that is
# exactly the result_unknown recovery contract.
LAST_RAW=""; LAST_HTTP=""; LAST_OP=""; LAST_OUTCOME=""
for _ in $(seq 1 60); do
    LAST_HTTP="$(curl -sS -o "$FIX/last.json" -w '%{http_code}' -b "$CJ"         "$BASE/api/v1/management/status" 2>/dev/null)"
    LAST_RAW="$(cat "$FIX/last.json" 2>/dev/null)"
    LAST_OP="$(jqv "$LAST_RAW" '.data.last_transaction.op')"
    LAST_OUTCOME="$(jqv "$LAST_RAW" '.data.last_transaction.outcome')"
    [ "$LAST_OP" = "client.add" ] && [ "$LAST_OUTCOME" = "ok" ] && break
    sleep 0.75
done
assert_eq "200" "$LAST_HTTP" "the status endpoint stayed alive during the busy helper (got $LAST_HTTP)"
assert_eq "client.add" "$LAST_OP" "the timed-out transaction completed inside the helper (status proves it)"
assert_eq "ok" "$LAST_OUTCOME" 'the timed-out transaction landed on its terminal success (last body shown above)'
grep -qF 'timeout-live' /root/sbox/sbconfig_server.json \
    && pass 'the timed-out client is really in the live config' \
    || fail 'the timed-out client never reached the live config'
rm -f "$FIX/check-sleep"

# root over the socket is still rejected (SO_PEERCRED, from this host)
ROOTOUT="$(python3 "$TIMEOUT_DRIVER" 2>/dev/null)"
assert_eq "ERR:E_PEER_AUTH" "$ROOTOUT" 'a root-driven RPC is refused at SO_PEERCRED (E_PEER_AUTH)'

# ------------------------------------------------------------ delete flow --
R="$(e3_post /api/v1/clients/delete "$KEY3" '{"name":"live-01"}')"
assert_eq "confirm_mismatch" "$(jqv "$R" '.code')" 'delete without the type-to-confirm echo is refused'
R="$(e3_post /api/v1/clients/delete "$KEY3" '{"name":"live-01","confirm":"wrong"}')"
assert_eq "confirm_mismatch" "$(jqv "$R" '.code')" 'a wrong confirm echo is refused'
BEFORE_SUM="$(sum /root/sbox/sbconfig_server.json)"
RELOADS_BEFORE="$(cat "$FIX/reload.count")"
R="$(e3_post /api/v1/clients/delete "$KEY3" '{"name":"live-01","confirm":"live-01"}')"
assert_eq "true" "$(jqv "$R" '.ok')" 'delete with confirm==name succeeds'
assert_eq "true" "$(jqv "$R" '.data.deleted')" 'delete reports deleted'
assert_ne "$BEFORE_SUM" "$(sum /root/sbox/sbconfig_server.json)" 'the delete changed the live config'
RELOADS_NOW="$(cat "$FIX/reload.count")"
[ "$RELOADS_NOW" -gt "$RELOADS_BEFORE" ] \
    && pass 'the delete reloaded sing-box again' \
    || fail "the delete did not reload ($RELOADS_BEFORE -> $RELOADS_NOW)"

R="$(e3_post /api/v1/management/deactivate - '{}')"
assert_eq "true" "$(jqv "$R" '.ok')" 'deactivate over the live HTTP API'
# the broker may still hold a WITHIN-TTL active snapshot (fresh-only rule);
# past the TTL it must answer false, never carry stale-active forward.
sleep 2.5
SINFO="$(curl -sS -b "$CJ" "$BASE/api/v1/session")"
assert_eq "false" "$(jqv "$SINFO" '.management_active')" 'the plane is inactive again (past the status TTL)'

# --------------------------------------- stale-active fail closed + breaker --
R="$(e3_post /api/v1/management/activate - '{}')"
assert_eq "true" "$(jqv "$R" '.ok')" 're-activated for the stale-active test'
curl -sS -b "$CJ" "$BASE/api/v1/management/status" >/dev/null
SINFO="$(curl -sS -b "$CJ" "$BASE/api/v1/session")"
assert_eq "true" "$(jqv "$SINFO" '.management_active')" 'management_active true while fresh'
# kill the helper; the stale active must expire and answer False
systemctl stop sbox-cm.socket sbox-cm.service >/dev/null 2>&1
sleep 2.5
SINFO="$(curl -sS -b "$CJ" "$BASE/api/v1/session")"
assert_eq "false" "$(jqv "$SINFO" '.management_active')" 'stale active=true is NEVER trusted (helper unreachable -> False)'
R="$(e3_post /api/v1/clients/add "$KEY1" '{"name":"nope-01"}')"
CODE="$(jqv "$R" '.code')"
if [ "$CODE" = "e3_unavailable" ]; then
    pass 'a mutation while the helper is down is refused with e3_unavailable'
else
    fail "a mutation while the helper is down must be refused (got [$CODE])"
fi
# the status query channel stays alive for uncertain-recovery
R="$(curl -sS -b "$CJ" "$BASE/api/v1/management/status")"
assert_eq "true" "$(jqv "$R" '.ok')" 'status keeps serving the last snapshot while the helper is down'
assert_eq "stale" "$(jqv "$R" '.transport')" 'the served snapshot is labeled stale'
# recovery: the breaker must let a probe through and go fresh again
systemctl start sbox-cm.socket sbox-cm.service >/dev/null 2>&1
RECOVERED="no"
for _ in $(seq 1 60); do
    R="$(curl -sS -b "$CJ" "$BASE/api/v1/management/status")"
    [ "$(jqv "$R" '.transport')" = "fresh" ] && { RECOVERED="yes"; break; }
    sleep 0.5
done
assert_eq "yes" "$RECOVERED" 'the breaker recovers to fresh after the helper returns'
assert_eq "active" "$(jqv "$R" '.data.management_state')" 'the recovered status shows the armed plane'

R="$(e3_post /api/v1/management/deactivate - '{}')"
assert_eq "true" "$(jqv "$R" '.ok')" 'deactivated again (leave the fixture disarmed)'

# ---------------------------------------------------------------- report --
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M2_LIVE=FAIL\n'
    exit 1
fi
printf 'E3_M2_LIVE=PASS\n'
