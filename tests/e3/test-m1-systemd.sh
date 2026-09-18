#!/usr/bin/env bash
# E3 M1 -- B-5 LIVE systemd integration test (E3 M1 review: "verify" alone is
# not B-5 CLOSED).
#
# This suite starts the REAL hardened sbox-cm.socket/service units under the
# REAL systemd PID 1, with a mock sing-box.service, and drives full
# transactions THROUGH the socket with SO_PEERCRED:
#
#   socket ownership (root:sboxweb 0660) + socket activation
#   sboxweb accepted / other uid + root rejected (PEERCRED)
#   status/activate/client.add (reload counted)/list/delete/deactivate
#   reload failure -> automatic rollback through the hardened unit
#   state-dir ownership: daemon start fails closed on a non-root owner (B8)
#   startup reconciliation on restart
#
# Requires: Linux, systemd running as PID 1, root. Everywhere else: SKIP --
# Windows dev hosts and CI without usable systemd are NOT M1 acceptance.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }

printf '===== E3 M1 SYSTEMD LIVE (B-5) =====\n'

if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
    skip 'non-Linux host: the live systemd suite is exercised on Linux CI only'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi
if [ ! -d /run/systemd/system ]; then
    skip 'systemd is not PID 1 here (container/dev host): SKIP'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi
if [ "$(id -u 2>/dev/null)" != "0" ]; then
    skip 'not root (run with sudo): the live units need real root'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi
if ! command -v systemctl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    skip 'systemctl/python3 missing'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi

FIX="/run/sbox-cm-test"
SOCK="/run/sbox-cm/sbox-cm.sock"
STATE="/var/lib/sbox-cm"
SBROOT="/root/sbox"
PY_PROBE="$FIX/probe.py"

cleanup() {
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket 2>/dev/null
    systemctl stop sing-box 2>/dev/null
    systemctl disable sing-box 2>/dev/null
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload 2>/dev/null
    rm -rf -- "$SBROOT" "$FIX" 2>/dev/null
    exit 0
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------ fixture --
getent passwd sboxweb >/dev/null 2>&1 || useradd --system --no-create-home sboxweb
getent group  sboxweb >/dev/null 2>&1 || groupadd --system sboxweb

mkdir -p "$SBROOT" "$FIX"
chmod 0777 "$FIX"
cat > "$SBROOT/mock-sing-box" <<'MOCK'
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
chmod 0755 "$SBROOT/mock-sing-box"
cat > "$SBROOT/sbconfig_server.json" <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
chmod 0600 "$SBROOT/sbconfig_server.json"

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=mock sing-box (E3 M1 B-5 fixture)
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/sh -c 'if [ -f $FIX/fail-first ] && [ \$(cat $FIX/reload.count 2>/dev/null || echo 0) -eq 0 ]; then echo 1 > $FIX/reload.count; exit 1; fi; n=\$((\$(cat $FIX/reload.count 2>/dev/null || echo 0)+1)); echo \$n > $FIX/reload.count'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sing-box >/dev/null 2>&1
: > "$FIX/reload.count"

# The ONE RPC client: connects as the INVOKING user (sudo -u <user>), so the
# PEERCRED uid is exactly the user we want to test.
cat > "$PY_PROBE" <<'PROBE'
import json, socket, struct, sys
req = json.loads(sys.argv[1])
body = json.dumps(req, separators=(",", ":")).encode("utf-8")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(60)
s.connect("/run/sbox-cm/sbox-cm.sock")
s.sendall(struct.pack(">I", len(body)) + body)
hdr = b""
while len(hdr) < 4:
    c = s.recv(4 - len(hdr))
    if not c:
        sys.exit(3)
    hdr += c
(ln,) = struct.unpack(">I", hdr)
buf = b""
while len(buf) < ln:
    c = s.recv(ln - len(buf))
    if not c:
        sys.exit(3)
    buf += c
s.close()
sys.stdout.write(buf.decode("utf-8"))
PROBE

rpc(){ # <user> <request-json> -> response JSON
    sudo -u "$1" /usr/bin/python3 "$PY_PROBE" "$2" 2>/dev/null
}
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }
sum(){ sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
reload_count(){ cat "$FIX/reload.count" 2>/dev/null || printf 0; }

# -------------------------------------------------------------------- install --
"$INSTALLER" install >/dev/null 2>&1 || { fail 'installer failed'; printf '\nE3_M1_SYSTEMD=FAIL\n'; exit 1; }
pass 'installer installed the real units'
systemctl enable --now sbox-cm.socket >/dev/null 2>&1 || { fail 'socket enable failed'; printf '\nE3_M1_SYSTEMD=FAIL\n'; exit 1; }

for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { fail 'socket file never appeared'; printf '\nE3_M1_SYSTEMD=FAIL\n'; exit 1; }
pass 'socket-activated socket file exists'

assert_eq 'root sboxweb' "$(stat -c '%U %G' "$SOCK")" 'socket owner is root:sboxweb'
assert_eq '660' "$(stat -c '%a' "$SOCK")" 'socket mode is 0660'

# --------------------------------------------------- B8: ownership fail-closed --
systemctl stop sbox-cm.service 2>/dev/null
chown 1001:1001 "$STATE"
systemctl start sbox-cm.service >/dev/null 2>&1
sleep 1
STATE_FAILED=$(systemctl is-failed sbox-cm.service 2>/dev/null || printf failed)
assert_eq failed "$STATE_FAILED" 'a non-root-owned state dir makes the daemon FAIL to start (B8)'
systemctl reset-failed sbox-cm.service 2>/dev/null
chown root:root "$STATE"
systemctl start sbox-cm.service >/dev/null 2>&1
sleep 1
assert_eq active "$(systemctl is-active sbox-cm.service 2>/dev/null)" 'daemon starts once ownership is root:root'

# ------------------------------------------------------------------ peer auth --
o="$(rpc nobody '{"v":"e3-rpc/1","request_id":"reqid-peer-other0001","op":"management.status"}')"
assert_eq E_PEER_AUTH "$(jqv "$o" '.error.code')" 'an unrelated uid is rejected (PEERCRED)'
o="$(rpc root '{"v":"e3-rpc/1","request_id":"reqid-peer-root0001","op":"management.status"}')"
assert_eq E_PEER_AUTH "$(jqv "$o" '.error.code')" 'root is rejected over the socket (no RPC back door)'

# ------------------------------------------------------------ full transaction --
o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-status001","op":"management.status"}')"
assert_eq true "$(jqv "$o" '.ok')" 'status answers over the live socket'
assert_eq inactive "$(jqv "$o" '.data.management_state')" 'live helper starts inactive'

o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-activate1","op":"management.activate"}')"
assert_eq true "$(jqv "$o" '.ok')" 'activate over the live socket'

BEFORE_SUM="$(sum "$SBROOT/sbconfig_server.json")"
o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-add-00001","name":"live-01","idempotency_key":"live-key-00000001","op":"client.add"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.add over the live socket'
assert_eq false "$(jqv "$o" '.idempotency.replayed')" 'first add is not a replay'
assert_ne "$BEFORE_SUM" "$(sum "$SBROOT/sbconfig_server.json")" 'the live config really changed'
assert_eq 1 "$(reload_count)" 'the hardened unit reloaded sing-box exactly once'

o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-list-0001","op":"client.list"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.list over the live socket'
printf '%s' "$o" | grep -qF 'live-01' && pass 'the added client is listed' || fail 'client missing from list'

o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-del-00001","name":"live-01","idempotency_key":"live-key-00000002","op":"client.delete"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.delete over the live socket'
assert_eq 2 "$(reload_count)" 'delete reloaded sing-box again'

o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-deact001","op":"management.deactivate"}')"
assert_eq true "$(jqv "$o" '.ok')" 'deactivate over the live socket'
assert_eq inactive "$(jqv "$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-status002","op":"management.status"}')" '.data.management_state')" \
    'the plane is inactive again'

# ------------------------------------------------------------------- rollback --
systemctl start sbox-cm.service >/dev/null 2>&1
rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-activate2","op":"management.activate"}' >/dev/null
touch "$FIX/fail-first"
: > "$FIX/reload.count"
BEFORE_SUM="$(sum "$SBROOT/sbconfig_server.json")"
o="$(rpc sboxweb '{"v":"e3-rpc/1","request_id":"reqid-live-rlbk0001","name":"live-02","idempotency_key":"live-key-00000003","op":"client.add"}')"
rm -f "$FIX/fail-first"
assert_eq false "$(jqv "$o" '.ok')" 'a failing reload is reported as failure'
assert_eq E_ROLLED_BACK "$(jqv "$o" '.error.code')" 'the hardened unit rolled back automatically'
assert_eq "$BEFORE_SUM" "$(sum "$SBROOT/sbconfig_server.json")" 'rollback restored the live config byte-for-byte'
assert_eq active "$(systemctl is-active sbox-cm.service 2>/dev/null)" 'the daemon survived the rollback'

# ------------------------------------------------- startup reconciliation ----
printf '%s\n' '{"v":1,"request_id":"reqid-live-orphan01","op":"client.add","phase":"replace","backup_path":null,"generation":1}' \
    > "$STATE/journal/reqid-live-orphan01.json"
[ -f "$STATE/journal/reqid-live-orphan01.json" ] && pass 'orphan journal staged' || fail 'staging failed'
systemctl restart sbox-cm.service >/dev/null 2>&1
sleep 2
[ ! -f "$STATE/journal/reqid-live-orphan01.json" ] \
    && pass 'startup reconciliation cleared the orphan journal on restart' \
    || fail 'orphan journal survived restart'
assert_eq active "$(systemctl is-active sbox-cm.service 2>/dev/null)" 'daemon healthy after reconciliation'

# -------------------------------------------------------------------- sandbox --
if command -v systemd-analyze >/dev/null 2>&1; then
    SCORE="$(systemd-analyze security sbox-cm.service 2>/dev/null | tail -n 1 | grep -oE '[0-9]+\.[0-9]+' | head -n 1)"
    if [ -n "$SCORE" ]; then
        pass "hardening exposure under the REAL units: ${SCORE} (informational)"
    else
        skip 'systemd-analyze security unavailable for the live unit'
    fi
fi

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_SYSTEMD=FAIL\n'; exit 1; }
printf 'E3_M1_SYSTEMD=PASS\n'
