#!/usr/bin/env bash
# M3-C Phase 2 production-shape gate: the reviewed bridge and real
# E3RpcClient drive the real socket/service, worker, and canonical library.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="$ROOT/monitor-v2/deploy/e3-m3c-phase2-rpc.py"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"
FIX=/run/sboxcm-m3c2-live
APP="$FIX/release/app/monitor-v2"
CONFIG=/root/sbox/sbconfig_server.json
STATE=/var/lib/sbox-cm
REQUIRE_LIVE="${E3_PHASE2_REQUIRE_LIVE:-0}"
PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
gate(){
    if [ "$REQUIRE_LIVE" = 1 ]; then
        fail "$1 (E3_PHASE2_REQUIRE_LIVE=1: SKIP is forbidden)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3C_PHASE2_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3C_PHASE2_LIVE=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

printf '===== E3 M3-C PHASE 2 LIVE =====\n'
[ "$(uname -s 2>/dev/null)" = Linux ] || gate 'non-Linux host'
[ -d /run/systemd/system ] || gate 'systemd is not PID 1'
[ "$(id -u 2>/dev/null)" = 0 ] || gate 'root is required'
for tool in systemctl python3 jq sudo sha256sum; do command -v "$tool" >/dev/null 2>&1 || gate "$tool is missing"; done
if [ -e /root/sbox ] || [ -e "$FIX" ]; then
    fail 'fixture path exists; refusing to run over a real deployment'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3C_PHASE2_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

cleanup_resources(){
    systemctl stop sbox-cm.socket sbox-cm.service sing-box.service >/dev/null 2>&1 || true
    systemctl disable sbox-cm.socket sing-box.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf -- /root/sbox "$FIX" "$STATE" /run/sbox-cm
}
cleanup(){ local rc=$?; trap - EXIT INT TERM; cleanup_resources; exit "$rc"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

getent group sboxweb >/dev/null 2>&1 || groupadd --system sboxweb
getent passwd sboxweb >/dev/null 2>&1 || useradd --system --no-create-home -g sboxweb sboxweb
mkdir -p /root/sbox "$APP" "$FIX"
cat > /root/sbox/sing-box <<'MOCK'
#!/usr/bin/env bash
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
# Deliberately non-canonical formatting proves that final equivalence is
# semantic config + exact inventory, not raw-byte identity.
cat > "$CONFIG" <<'JSON'
{
  "inbounds": [
    { "type": "vless", "tag": "vless-in", "users": [ { "name": "legacy", "uuid": "LEGACY-UUID", "flow": "xtls-rprx-vision" } ] },
    { "type": "hysteria2", "tag": "hy2-in", "users": [ { "name": "legacy", "password": "LEGACY-PASS" } ] }
  ]
}
JSON
chmod 0600 "$CONFIG"
cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=mock sing-box (M3-C Phase 2 live)
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sing-box.service >/dev/null 2>&1

"$INSTALLER" install >/dev/null 2>&1 || { fail 'real sbox-cm install failed'; exit 1; }
systemctl stop sbox-cm.socket sbox-cm.service >/dev/null 2>&1 || true
rm -rf -- "$STATE" /run/sbox-cm
mkdir -p "$STATE"; chown root:root "$STATE"; chmod 0700 "$STATE"
systemctl enable --now sbox-cm.socket >/dev/null 2>&1 || { fail 'real socket enable failed'; exit 1; }
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done
[ -S /run/sbox-cm/sbox-cm.sock ] || { fail 'real socket never appeared'; exit 1; }
cp -r "$ROOT/monitor-v2/web" "$APP/web"
rm -rf "$APP/web/__pycache__"
chmod -R a+rX "$FIX/release"

rpc(){ # op payload
    local op="$1" payload="$2"
    sudo -n -u sboxweb /usr/bin/python3 -B - "$op" "$APP" "$payload" <"$BRIDGE"
}
jqv(){ printf '%s' "$1" | jq -r "$2"; }
semantic(){ jq -cS . "$CONFIG" | sha256sum | awk '{print $1}'; }
rawsha(){ sha256sum "$CONFIG" | awk '{print $1}'; }
inventory(){ printf '%s' "$1" | jq -cS '.data.clients|sort_by(.name)'; }

RAW_BEFORE="$(rawsha)"; SEM_BEFORE="$(semantic)"
SING_TS="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)"
SING_NR="$(systemctl show -p NRestarts --value sing-box.service)"

R="$(rpc management.status '{}')"
assert_eq true "$(jqv "$R" '.ok')" 'real E3RpcClient reaches sbox-cm.socket'
assert_eq inactive "$(jqv "$R" '.data.management_state')" 'real plane starts inactive'
R="$(rpc client.list '{}')"; INV_BEFORE="$(inventory "$R")"
assert_eq '[{"mutable":false,"name":"legacy","protocols":["reality","hy2"],"reserved":true,"source":"untracked"}]' "$INV_BEFORE" 'baseline inventory is exact'

R="$(rpc management.activate '{}')"
assert_eq true "$(jqv "$R" '.ok')" 'real management.activate succeeds'
assert_eq active "$(jqv "$(rpc management.status '{}')" '.data.management_state')" 'real status observes active'
R="$(rpc client.add '{"name":"m3c-live","idempotency_key":"m3c2-live-add-0001"}')"
assert_eq true "$(jqv "$R" '.ok')" 'real canonical client.add succeeds'
assert_eq true "$(jqv "$R" '.transaction.health_verified')" 'real add transaction verifies health'
R="$(rpc client.list '{}')"
assert_eq 1 "$(printf '%s' "$R" | jq '[.data.clients[]|select(.name=="m3c-live")]|length')" 'real list sees one canary generation'
R="$(rpc client.delete '{"name":"m3c-live","idempotency_key":"m3c2-live-del-0001"}')"
assert_eq true "$(jqv "$R" '.ok')" 'real canonical client.delete succeeds'
assert_eq true "$(jqv "$R" '.transaction.health_verified')" 'real delete transaction verifies health'
R="$(rpc client.list '{}')"
assert_eq "$INV_BEFORE" "$(inventory "$R")" 'final real inventory exactly equals baseline'
R="$(rpc management.deactivate '{}')"
assert_eq true "$(jqv "$R" '.ok')" 'real management.deactivate succeeds'
assert_eq inactive "$(jqv "$(rpc management.status '{}')" '.data.management_state')" 'real plane ends inactive'
[ ! -e "$STATE/management.active" ] && pass 'real activation marker is absent' || fail 'real activation marker remains'
assert_eq "$SEM_BEFORE" "$(semantic)" 'real final semantic config equals baseline'
[ "$RAW_BEFORE" != "$(rawsha)" ] && pass 'real canonical worker demonstrates raw JSON may change' || fail 'live fixture did not exercise raw serialization drift'
assert_eq "$SING_TS" "$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)" 'sing-box was not restarted'
assert_eq "$SING_NR" "$(systemctl show -p NRestarts --value sing-box.service)" 'sing-box restart counter is unchanged'
assert_eq 4 "$(jq -s '[.[]|select(.op=="management.activate" or .op=="client.add" or .op=="client.delete" or .op=="management.deactivate")|select(.actor.session_fp==null and .actor.stepup_fp==null)]|length' "$STATE/audit/cm.jsonl")" 'all four real operator mutations keep actor fields null'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -ne 0 ]; then printf 'E3_M3C_PHASE2_LIVE=FAIL\n'; exit 1; fi
printf 'E3_M3C_PHASE2_LIVE=PASS\n'
