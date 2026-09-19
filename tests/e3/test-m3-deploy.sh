#!/usr/bin/env bash
# E3 M3 -- deploy tooling test: the production preflight / deploy-verify /
# rollback scripts are executed for real against a live fixture (mock
# sing-box.service, real sbox-cm units, real rendered monitor unit under
# systemd PID 1) -- the same fixture approach as the M2 live gate.
#
# Covered:
#   preflight PASS + baseline JSON saved with config sha / service states
#   preflight FAIL: activation marker present / helper socket down /
#                   sing-box check rejecting the live config
#   deploy-verify PASS: config sha identical, sing-box not restarted,
#                   monitor HTTP 200, sbox-cm active, marker absent,
#                   sboxweb RPC status=inactive + client.list readable,
#                   Web E3 UI loads, mutation while inactive fail-closed
#                   (E_ACTIVATION_STATE) with the config untouched
#   deploy-verify FAIL: config modified after the baseline
#   rollback PASS: privileged plane closed+disabled, config untouched,
#                   marker absent, monitor answering, packaging rollback
#                   invoked with the previous release id
#
# Exit-status contract and skip=FAIL flag as in the M1/M2 live gates.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FIX="/run/sboxcm-m3-test"
APP="/opt/sboxcm-m3"
MDATA="/var/lib/sboxcm-m3"
MPORT=9193
BASE="http://127.0.0.1:$MPORT"
CJ="$FIX/cookies.txt"
AXE_USER="sboxweb"
MPASS="m3-deploy-admin-password-01"
PREFLIGHT="$ROOT/monitor-v2/deploy/e3-preflight.sh"
VERIFY="$ROOT/monitor-v2/deploy/e3-deploy-verify.sh"
ROLLBACK="$ROOT/monitor-v2/deploy/e3-rollback.sh"
STUB_INSTALLER="$FIX/stub-install-monitor.sh"

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

printf '===== E3 M3 DEPLOY TOOLING (preflight / verify / rollback) =====\n'

gate() {
    if [ "${SBOX_E3_REQUIRE_LIVE:-0}" = "1" ]; then
        fail "$1 (SBOX_E3_REQUIRE_LIVE=1: a skipped live gate is a false green)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

[ "$(uname -s 2>/dev/null)" = "Linux" ] \
    || gate 'non-Linux host: the deploy tooling runs on Linux CI only'
[ -d /run/systemd/system ] || gate 'systemd is not PID 1 here'
[ "$(id -u 2>/dev/null)" = "0" ] || gate 'not root (run with sudo)'
command -v systemctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    && command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 \
    || gate 'systemctl/python3/curl/jq missing'
if [ -e /root/sbox ] || [ -e "$MDATA" ] || [ -e /etc/systemd/system/singbox-monitor.service ]; then
    fail 'a fixture path already exists: refusing to run over a real deployment'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    systemctl stop singbox-monitor.service 2>/dev/null
    systemctl disable singbox-monitor.service 2>/dev/null
    rm -f /etc/systemd/system/singbox-monitor.service /etc/systemd/system/sing-box.service
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl daemon-reload 2>/dev/null
    rm -rf -- /root/sbox "$FIX" "$APP" "$MDATA" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

_rc_probe="$( ( trap cleanup EXIT; exit 7 ) >/dev/null 2>&1; printf '%s' "$?" )"
if [ "$_rc_probe" = "7" ]; then
    pass 'exit-status contract: teardown preserves the process rc'
else
    fail "exit-status contract: forced rc=7 came back as [$_rc_probe]"
    trap - EXIT INT TERM
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

# ------------------------------------------------------------------ fixture --
getent passwd "$AXE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$AXE_USER"
getent group  "$AXE_USER" >/dev/null 2>&1 || groupadd --system "$AXE_USER"
mkdir -p "$FIX" "$APP" "$MDATA" /root/sbox
chmod 0777 "$FIX"

cat > /root/sbox/sing-box <<'MOCK'
#!/usr/bin/env bash
FIX="/run/sboxcm-m3-test"
case "${1:-}" in
    check)
        if grep -q "__BROKEN__" "${3:-}" 2>/dev/null; then exit 1; fi
        exit 0 ;;
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
write_config() {
    cat > /root/sbox/sbconfig_server.json <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
    chmod 0600 /root/sbox/sbconfig_server.json
}
write_config

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=mock sing-box (E3 M3 fixture)
[Service]
Type=simple
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sing-box >/dev/null 2>&1

"$ROOT/sbox-cm/deploy/install-sbox-cm.sh" install >/dev/null 2>&1 \
    || { fail 'sbox-cm installer failed'; printf '\nE3_M3_DEPLOY=FAIL\n'; exit 1; }
systemctl enable --now sbox-cm.socket >/dev/null 2>&1
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done

cp "$ROOT"/monitor-v2/*.py "$APP"/ 2>/dev/null
cp -r "$ROOT/monitor-v2/web" "$APP"/web
cp -r "$ROOT/monitor-v2/api_bridge" "$APP"/api_bridge
printf 'm3-test\n' > "$APP"/VERSION
rm -rf "$APP/web/__pycache__" "$APP"/__pycache__ "$APP/api_bridge/__pycache__" 2>/dev/null
chown -R "$AXE_USER":"$AXE_USER" "$APP" "$MDATA"
chmod 0700 "$MDATA"
sudo -u "$AXE_USER" env -u SSH_CONNECTION python3 "$APP/webapp.py" setup \
    --assume-yes --password "m3-deploy-admin-password-01" --data-dir "$MDATA" \
    >/dev/null 2>&1 \
    || { fail 'monitor setup failed'; printf '\nE3_M3_DEPLOY=FAIL\n'; exit 1; }
sed -e "s|@SBMON_USER@|$AXE_USER|g" \
    -e "s|@SBMON_GROUP@|$AXE_USER|g" \
    -e "s|@SBMON_APP_DIR@|$APP|g" \
    -e "s|@SBMON_STATE_ROOT@|$MDATA|g" \
    "$ROOT/monitor-v2/deploy/singbox-monitor.service.in" \
| sed -e "s|^ExecStart=.*|ExecStart=/usr/bin/python3 $APP/webapp.py serve --listen 127.0.0.1 --port $MPORT --data-dir $MDATA|" \
      -e "s|^After=.*|After=network-online.target|" \
> /etc/systemd/system/singbox-monitor.service
systemctl daemon-reload
systemctl enable --now singbox-monitor.service >/dev/null 2>&1
for _ in $(seq 1 40); do
    [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/api/v1/session" 2>/dev/null)" = "200" ] && break
    sleep 0.25
done
pass 'fixture live: mock sing-box + real sbox-cm + real rendered monitor unit'

# export the script override environment for every invocation below
export E3_SYSTEMCTL=systemctl
export E3_CONFIG=/root/sbox/sbconfig_server.json
export E3_SING_BOX_BIN=/root/sbox/sing-box
export E3_SBXCM_STATE=/var/lib/sbox-cm
export E3_SBXCM_SOCKET=/run/sbox-cm/sbox-cm.sock
export E3_MONITOR_URL="$BASE"
export E3_MONITOR_APP="$APP"

# ---------------------------------------------------------------- preflight --
BASELINE="$FIX/baseline.json"
OUT="$(bash "$PREFLIGHT" --baseline-out "$BASELINE")"
RC=$?
printf '%s\n' "$OUT" | grep -q 'E3_PREFLIGHT=PASS' && { PASS=$((PASS+1)); printf '  PASS preflight reports PASS\n'; } \
    || { FAIL=$((FAIL+1)); printf '  FAIL preflight (rc=%s):\n%s\n' "$RC" "$OUT"; }
[ -f "$BASELINE" ] && pass 'baseline JSON saved' || fail 'baseline JSON missing'
assert_eq "false" "$(jqv "$(cat "$BASELINE")" '.marker_present')" 'baseline records marker_present=false'
assert_eq "active" "$(jqv "$(cat "$BASELINE")" '.singbox.active')" 'baseline records sing-box active'
BASE_SHA="$(jqv "$(cat "$BASELINE")" '.config_sha256')"
[ -n "$BASE_SHA" ] && pass 'baseline records the config SHA256' || fail 'baseline SHA empty'

# preflight FAIL: activation marker present
printf '%s\n' '{"v":1,"state":"active"}' > /var/lib/sbox-cm/management.active
if bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with an armed marker must FAIL'
else
    pass 'preflight with an armed marker FAILS (deploy-disabled contract)'
fi
rm -f /var/lib/sbox-cm/management.active

# preflight FAIL: helper socket down
systemctl stop sbox-cm.socket sbox-cm.service >/dev/null 2>&1
if bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with the helper socket down must FAIL'
else
    pass 'preflight with the helper socket down FAILS'
fi
systemctl start sbox-cm.socket >/dev/null 2>&1
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done

# preflight FAIL: sing-box check rejects the live config
cp /root/sbox/sbconfig_server.json "$FIX/config.bak"
python3 - <<'PY'
import json
p = "/root/sbox/sbconfig_server.json"
cfg = open(p).read().replace('"inbounds"', '"__BROKEN__": true, "inbounds"')
open(p, "w").write(cfg)
PY
if bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with a check-rejected config must FAIL'
else
    pass 'preflight with a check-rejected config FAILS'
fi
cp "$FIX/config.bak" /root/sbox/sbconfig_server.json
chmod 0600 /root/sbox/sbconfig_server.json

# ------------------------------------------------- deploy-verify (PASS) --
VOUT="$(bash "$VERIFY" --baseline "$BASELINE")"
RC=$?
printf '%s\n' "$VOUT" | grep -q 'E3_M3_VERIFY=PASS' \
    && pass 'deploy-verify reports PASS (deploy-disabled acceptance)' \
    || { FAIL=$((FAIL+1)); printf '  FAIL deploy-verify (rc=%s):\n%s\n' "$RC" "$VOUT"; }
printf '%s' "$VOUT" | grep -qF 'E_ACTIVATION_STATE' \
    && pass 'verify proves mutation fail-closed while inactive' \
    || fail 'verify did not prove the fail-closed refusal'
printf '%s' "$VOUT" | grep -qF 'identical to the baseline' \
    && pass 'verify proves the config is byte-identical' \
    || fail 'verify did not compare the config SHA'
printf '%s' "$VOUT" | grep -qF 'NOT restarted' \
    && pass 'verify proves sing-box was not restarted' \
    || fail 'verify did not check the restart counter'

# deploy-verify FAIL: config modified after the baseline
python3 - <<'PY'
import json
p = "/root/sbox/sbconfig_server.json"
cfg = json.loads(open(p).read())
cfg["inbounds"][0]["users"][0]["name"] = "tampered"
open(p, "w").write(json.dumps(cfg))
PY
if bash "$VERIFY" --baseline "$BASELINE" >/dev/null 2>&1; then
    fail 'deploy-verify with a modified config must FAIL'
else
    pass 'deploy-verify with a modified config FAILS'
fi
cp "$FIX/config.bak" /root/sbox/sbconfig_server.json
chmod 0600 /root/sbox/sbconfig_server.json

# ------------------------------------------------------- rollback (PASS) --
cat > "$STUB_INSTALLER" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> /run/sboxcm-m3-test/stub-installer.log
exit 0
STUB
chmod 0755 "$STUB_INSTALLER"
printf 'rel-old\nrel-previous\n' > "$FIX/releases.history"
RBOUT="$(E3_INSTALL_MONITOR="$STUB_INSTALLER" E3_RELEASES_DIR="$FIX" \
    bash "$ROLLBACK" --baseline "$BASELINE")"
RC=$?
printf '%s' "$RBOUT" | grep -q 'E3_M3_ROLLBACK=PASS' \
    && pass 'rollback reports PASS' \
    || { FAIL=$((FAIL+1)); printf '  FAIL rollback (rc=%s):\n%s\n' "$RC" "$RBOUT"; }
grep -qF 'rollback rel-previous' "$FIX/stub-installer.log" \
    && pass 'rollback invoked the packaging rollback with the previous release id' \
    || fail 'rollback did not call the packaging rollback with the previous release'
SOCK_STATE="$(systemctl is-active sbox-cm.socket 2>/dev/null || true)"
SOCK_EN="$(systemctl is-enabled sbox-cm.socket 2>/dev/null || true)"
assert_eq "inactive" "$SOCK_STATE" 'rollback stopped the sbox-cm socket'
assert_eq "disabled" "$SOCK_EN" 'rollback disabled the sbox-cm socket'
NOW_SHA="$(sha256sum /root/sbox/sbconfig_server.json | awk '{print $1}')"
assert_eq "$BASE_SHA" "$NOW_SHA" 'rollback left the config byte-identical'
[ ! -e /var/lib/sbox-cm/management.active ] \
    && pass 'rollback leaves the plane closed' \
    || fail 'rollback left an activation marker'
HTTP="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/api/v1/session" 2>/dev/null)"
assert_eq "200" "$HTTP" 'monitor still answers after the rollback'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M3_DEPLOY=FAIL\n'
    exit 1
fi
printf 'E3_M3_DEPLOY=PASS\n'
