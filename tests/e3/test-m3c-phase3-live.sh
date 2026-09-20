#!/usr/bin/env bash
# M3-C Phase 3 production-shape gate: real socket/service, E3RpcClient,
# worker, and canonical state library. The disposable fixture ends active.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="$ROOT/monitor-v2/deploy/e3-m3c-phase2-rpc.py"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"
FIX=/run/sboxcm-m3c3-live; APP="$FIX/release/app/monitor-v2"
CONFIG=/root/sbox/sbconfig_server.json; STATE=/var/lib/sbox-cm
REQUIRE_LIVE="${E3_PHASE3_REQUIRE_LIVE:-0}"
PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
gate(){
  if [ "$REQUIRE_LIVE" = 1 ]; then fail "$1 (required LIVE cannot skip)"; printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3C_PHASE3_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"; exit 1; fi
  skip "$1"; printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3C_PHASE3_LIVE=SKIP\n' "$PASS" "$FAIL" "$SKIP"; exit 0
}

printf '===== E3 M3-C PHASE 3 LIVE =====\n'
[ "$(uname -s 2>/dev/null)" = Linux ] || gate 'non-Linux host'
[ -d /run/systemd/system ] || gate 'systemd is not PID 1'
[ "$(id -u)" = 0 ] || gate 'root required'
for tool in systemctl python3 jq sudo sha256sum; do command -v "$tool" >/dev/null 2>&1 || gate "$tool missing"; done
if [ -e /root/sbox ] || [ -e "$FIX" ]; then fail 'fixture path exists; refusing real deployment overlap'; exit 1; fi

cleanup_resources(){
  systemctl stop sbox-cm.socket sbox-cm.service sing-box.service >/dev/null 2>&1 || true
  systemctl disable sbox-cm.socket sing-box.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/sing-box.service; systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf -- /root/sbox "$FIX" "$STATE" /run/sbox-cm
}
cleanup(){ local rc=$?; trap - EXIT INT TERM; cleanup_resources; exit "$rc"; }
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM

getent group sboxweb >/dev/null 2>&1 || groupadd --system sboxweb
getent passwd sboxweb >/dev/null 2>&1 || useradd --system --no-create-home -g sboxweb sboxweb
mkdir -p /root/sbox "$APP" "$FIX"
cat > /root/sbox/sing-box <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in check) exit 0;; generate) [ "${2:-}" = uuid ] && printf 'uuid-%s\n' "$RANDOM" || printf 'pw-%s\n' "$RANDOM";; *) exit 2;; esac
MOCK
chmod 0755 /root/sbox/sing-box
cat > "$CONFIG" <<'JSON'
{"inbounds":[{"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY","flow":"xtls-rprx-vision"}]},{"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"PASS"}]}]}
JSON
chmod 0600 "$CONFIG"
cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=mock sing-box (M3-C Phase 3 live)
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now sing-box.service >/dev/null 2>&1
"$INSTALLER" install >/dev/null 2>&1 || { fail 'real helper install failed'; exit 1; }
systemctl stop sbox-cm.socket sbox-cm.service >/dev/null 2>&1 || true
rm -rf -- "$STATE" /run/sbox-cm; mkdir -p "$STATE"; chmod 0700 "$STATE"
systemctl enable --now sbox-cm.socket >/dev/null 2>&1 || { fail 'real socket enable failed'; exit 1; }
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done
[ -S /run/sbox-cm/sbox-cm.sock ] || { fail 'real socket unavailable'; exit 1; }
cp -r "$ROOT/monitor-v2/web" "$APP/web"; rm -rf "$APP/web/__pycache__"; chmod -R a+rX "$FIX/release"

rpc(){ sudo -n -u sboxweb /usr/bin/python3 -B - "$1" "$APP" '{}' <"$BRIDGE"; }
jqv(){ printf '%s' "$1"|jq -r "$2"; }
RAW="$(sha256sum "$CONFIG"|awk '{print $1}')"; SEM="$(jq -cS . "$CONFIG"|sha256sum|awk '{print $1}')"
TS="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)"; NR="$(systemctl show -p NRestarts --value sing-box.service)"
R="$(rpc management.status)"; assert_eq true "$(jqv "$R" .ok)" 'real RPC reaches socket'; assert_eq inactive "$(jqv "$R" .data.management_state)" 'real plane begins inactive'
L="$(rpc client.list)"; INV="$(printf '%s' "$L"|jq -cS '.data.clients|sort_by(.name)')"; assert_eq 1 "$(printf '%s' "$L"|jq '.data.clients|length')" 'real baseline has one client'
R="$(rpc management.activate)"; assert_eq true "$(jqv "$R" .ok)" 'real management.activate succeeds'; assert_eq false "$(jqv "$R" '.data.no_op')" 'real activation is not a no-op'
assert_eq active "$(jqv "$(rpc management.status)" .data.management_state)" 'real status observes active'
[ -f "$STATE/management.active" ] && [ ! -L "$STATE/management.active" ] && pass 'real marker is a regular file' || fail 'real marker unsafe'
assert_eq 644 "$(stat -c %a "$STATE/management.active")" 'real marker mode is 0644'
assert_eq active "$(jq -r .state "$STATE/management.active")" 'real marker JSON is active'
L2="$(rpc client.list)"; assert_eq "$INV" "$(printf '%s' "$L2"|jq -cS '.data.clients|sort_by(.name)')" 'real inventory is unchanged'
assert_eq "$RAW" "$(sha256sum "$CONFIG"|awk '{print $1}')" 'real raw config is unchanged'
assert_eq "$SEM" "$(jq -cS . "$CONFIG"|sha256sum|awk '{print $1}')" 'real semantic config is unchanged'
assert_eq "$TS" "$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)" 'real sing-box timestamp unchanged'
assert_eq "$NR" "$(systemctl show -p NRestarts --value sing-box.service)" 'real sing-box restart count unchanged'
assert_eq 0 "$(jq -s '[.[]|select(.op=="client.add" or .op=="client.delete")]|length' "$STATE/audit/cm.jsonl")" 'real go-live performs no client mutation'
assert_eq 1 "$(jq -s '[.[]|select(.op=="management.activate")|select(.actor.session_fp==null and .actor.stepup_fp==null)]|length' "$STATE/audit/cm.jsonl")" 'operator activation keeps actor fingerprints null'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M3C_PHASE3_LIVE=FAIL\n'; exit 1; }
printf 'E3_M3C_PHASE3_LIVE=PASS\n'
