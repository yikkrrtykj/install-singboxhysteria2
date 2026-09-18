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
# Exit-status contract (E3 M1 review B-5 false green): the suite's process
# status MUST carry the result. The EXIT trap only tears the fixture down; the
# status is captured first and re-raised by cleanup(). A FAILing suite that
# exits 0 is a false green in CI, and that is exactly what this file used to do
# (`cleanup() { ...; exit 0; }`). An exit-status contract check below re-drives
# the real teardown and fails the run if it ever stops propagating the status.
#
# Requires: Linux, systemd running as PID 1, root. Everywhere else: SKIP --
# Windows dev hosts and CI without usable systemd are NOT M1 acceptance. In CI
# the gate is invoked with SBOX_CM_REQUIRE_LIVE=1, which turns "the live suite
# could not execute" into a hard FAILURE instead of a silent SKIP.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"

FIX="/run/sbox-cm-test"
SOCK="/run/sbox-cm/sbox-cm.sock"
STATE="/var/lib/sbox-cm"
SBROOT="/root/sbox"
PY_PROBE="$FIX/probe.py"
AXE_USER="sboxweb"
PEER_USER="sboxcm-peertest"
REQUIRE_LIVE="${SBOX_CM_REQUIRE_LIVE:-0}"

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }

printf '===== E3 M1 SYSTEMD LIVE (B-5) =====\n'

# A gate that could not be satisfied is a SKIP on an ordinary host, but a hard
# FAILURE when the caller demands that the live gate really execute.
gate() { # <reason>
    if [ "$REQUIRE_LIVE" = "1" ]; then
        fail "$1 (SBOX_CM_REQUIRE_LIVE=1: a skipped live gate is a false green)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

[ "$(uname -s 2>/dev/null)" = "Linux" ] \
    || gate 'non-Linux host: the live systemd suite is exercised on Linux CI only'
[ -d /run/systemd/system ] \
    || gate 'systemd is not PID 1 here (container/dev host)'
[ "$(id -u 2>/dev/null)" = "0" ] \
    || gate 'not root (run with sudo): the live units need real root'
if ! command -v systemctl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    gate 'systemctl/python3 missing'
fi

# Destructive-path guard, deliberately BEFORE the trap is armed: this suite OWNS
# /root/sbox (it overwrites sbconfig_server.json there and deletes the tree on
# exit). If anything already lives there, this is a real deployment and the
# fixture must not run over it.
if [ -e "$SBROOT" ]; then
    fail "$SBROOT already exists: refusing to run the destructive B-5 fixture over a real deployment (use a disposable host)"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

cleanup_resources() {
    # Teardown ONLY. This function must never call `exit`: the process status
    # belongs to cleanup() below.
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket 2>/dev/null
    systemctl stop sing-box 2>/dev/null
    systemctl disable sing-box 2>/dev/null
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload 2>/dev/null
    rm -rf -- "$SBROOT" "$FIX" 2>/dev/null
    if [ -n "$PEER_USER" ]; then
        userdel "$PEER_USER" 2>/dev/null || true
    fi
    return 0
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    cleanup_resources || true
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ------------------------------------------------------------- status probes --
# `systemctl is-failed` reports a TRANSITION state (`activating`) while the unit
# is still inside Restart=on-failure, so it must never be sampled once and
# asserted on. Wait (bounded) for a STABLE ActiveState instead.
unit_state(){ systemctl show -p ActiveState --value "$1" 2>/dev/null || true; }
unit_detail(){ systemctl show -p ActiveState -p SubState -p Result "$1" 2>/dev/null | tr '\n' ' '; }
wait_unit_state(){ # <unit> <ActiveState> <timeout-seconds> -> rc 0 when reached
    local unit="$1" want="$2" timeout="$3" waited=0 cur=""
    while :; do
        cur="$(unit_state "$unit")"
        [ "$cur" = "$want" ] && return 0
        waited=$((waited+1))
        [ "$waited" -ge "$((timeout*10))" ] && return 1
        sleep 0.1
    done
}

# --------------------------------------------------- exit-status contract check --
# The B-5 review found this suite green in CI while printing FAIL=10: the EXIT
# trap ran `exit 0`, so the process status never carried the failure. Both
# checks below run BEFORE the fixture exists -- there is nothing to tear down
# yet, but the real teardown path is exercised verbatim.
#
#   1. static: the teardown must not own the process status at all;
#   2. dynamic: the REAL cleanup() is driven with a forced failing status and
#      that status must come back out of the child process.
# A failure here disarms the traps before exiting, so a broken teardown cannot
# mask the very failure it caused. The fixture is deliberately left behind in
# that case: leaking a test fixture is acceptable, lying about the result is not.
_teardown_ok=1
if declare -f cleanup_resources | grep -qE '\bexit[[:space:]]+[0-9$]'; then
    fail 'cleanup_resources() calls exit: the teardown path must not set the process status'
    _teardown_ok=0
fi
rc_probe="$(
    ( trap cleanup EXIT; exit 7 ) >/dev/null 2>&1
    printf '%s' "$?"
)"
if [ "$rc_probe" = "7" ]; then
    pass 'a failing result survives the EXIT trap as the process rc (no false-green exit status)'
else
    fail "a failing result must survive the EXIT trap as the process rc (forced rc=7 came back as [$rc_probe])"
    _teardown_ok=0
fi
if [ "$_teardown_ok" != "1" ]; then
    trap - EXIT INT TERM
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_SYSTEMD=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

# ------------------------------------------------------------------ fixture --
getent passwd "$AXE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$AXE_USER"
getent group  "$AXE_USER" >/dev/null 2>&1 || groupadd --system "$AXE_USER"

# A SECOND identity for the SO_PEERCRED test: uid != sboxweb, but a member of
# the sboxweb group, so connect() passes the socket's DAC and only the
# daemon-side peer check can reject it. Testing with `nobody` proved nothing:
# `nobody` cannot open the 0660 socket at all, so the call died at DAC and the
# assertion never reached SO_PEERCRED (E3 M1 review B-5).
if getent passwd "$PEER_USER" >/dev/null 2>&1; then
    userdel "$PEER_USER" >/dev/null 2>&1 || true
fi
useradd --system --no-create-home "$PEER_USER" >/dev/null 2>&1 || true
usermod -aG "$AXE_USER" "$PEER_USER" >/dev/null 2>&1 || true

mkdir -p "$SBROOT" "$FIX"
chmod 0777 "$FIX"
# The production worker runs from built-in constants and REJECTS SB_* injection:
# its sing-box is /root/sbox/sing-box, full stop. The fixture therefore has to
# BE that path -- a `mock-sing-box` file would never be executed, credential
# generation would fail and every mutation would come back E_INTERNAL.
cat > "$SBROOT/sing-box" <<'MOCK'
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
chmod 0755 "$SBROOT/sing-box"
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
# PEERCRED uid is exactly the user we want to test. A call that never reached
# the daemon answers with {"probe_error": ...} instead of an empty string, so a
# DAC-blocked call can never masquerade as a protocol-level verdict.
cat > "$PY_PROBE" <<'PROBE'
import json, socket, struct, sys
req = json.loads(sys.argv[1])
body = json.dumps(req, separators=(",", ":")).encode("utf-8")


def probe_error(stage, detail):
    sys.stdout.write(json.dumps({"probe_error": "%s: %s" % (stage, detail)}))
    sys.exit(0)


s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(60)
try:
    s.connect("/run/sbox-cm/sbox-cm.sock")
except OSError as exc:
    probe_error("connect", exc)

try:
    s.sendall(struct.pack(">I", len(body)) + body)
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            probe_error("recv-header", "peer closed")
        hdr += c
    (ln,) = struct.unpack(">I", hdr)
    buf = b""
    while len(buf) < ln:
        c = s.recv(ln - len(buf))
        if not c:
            probe_error("recv-body", "peer closed")
        buf += c
except OSError as exc:
    probe_error("io", exc)
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
# The unit carries Restart=on-failure, so a failing start is first reported as
# `activating` (SubState=auto-restart) and only becomes permanently `failed`
# once the start limit trips. Wait for the stable state, then assert on it.
if wait_unit_state sbox-cm.service failed 60; then
    pass 'a non-root-owned state dir makes the daemon FAIL to start (B8 fail-closed)'
else
    fail "a non-root-owned state dir must make the daemon FAIL to start (B8): still [$(unit_detail sbox-cm.service)] after 60s"
fi
systemctl reset-failed sbox-cm.service 2>/dev/null
chown root:root "$STATE"
systemctl start sbox-cm.service >/dev/null 2>&1
if wait_unit_state sbox-cm.service active 30; then
    pass 'daemon starts once ownership is root:root'
else
    fail "daemon must start once ownership is root:root: [$(unit_detail sbox-cm.service)] after 30s"
fi

# Type=simple is `active` before the daemon has finished its startup
# reconciliation and reached accept(), so readiness is a SERVED request, not a
# unit state. The served response is then reused for the first status
# assertions below.
READY_JSON=""
for _ in $(seq 1 300); do
    o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-ready001","op":"management.status"}')"
    if [ -n "$o" ] && [ -z "$(jqv "$o" '.probe_error')" ]; then
        READY_JSON="$o"
        break
    fi
    sleep 0.1
done
assert_eq true "$(jqv "$READY_JSON" '.ok')" 'the daemon serves requests once startup reconciliation finished'

# ------------------------------------------------------------------ peer auth --
# Layer 2 (SO_PEERCRED) is only reachable once layer 1 (the socket's DAC) has
# been passed, so the test identity must be a NON-sboxweb uid that IS in the
# sboxweb group -- otherwise the assertion below is vacuous.
assert_ne "$(id -u "$AXE_USER")" "$(id -u "$PEER_USER")" 'the peer-test identity is not the allowed uid'
if id -Gn "$PEER_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$AXE_USER"; then
    pass "$PEER_USER is in the $AXE_USER group (socket DAC passes, so PEERCRED is really exercised)"
else
    fail "$PEER_USER is not in the $AXE_USER group: connect() would be refused by the socket's DAC and the PEERCRED assertion would prove nothing"
fi

o="$(rpc "$PEER_USER" '{"v":"e3-rpc/1","request_id":"reqid-peer-other0001","op":"management.status"}')"
if [ -n "$(jqv "$o" '.probe_error')" ]; then
    fail "the peer-test call never reached the daemon (probe said: $(jqv "$o" '.probe_error')) -- a call refused by the socket's DAC cannot prove SO_PEERCRED"
else
    assert_eq E_PEER_AUTH "$(jqv "$o" '.error.code')" 'an unrelated uid that already passed socket DAC is rejected at SO_PEERCRED'
fi
o="$(rpc root '{"v":"e3-rpc/1","request_id":"reqid-peer-root0001","op":"management.status"}')"
assert_eq E_PEER_AUTH "$(jqv "$o" '.error.code')" 'root is rejected over the socket (no RPC back door)'

# ------------------------------------------------------------ full transaction --
o="$READY_JSON"
assert_eq true "$(jqv "$o" '.ok')" 'status answers over the live socket'
assert_eq inactive "$(jqv "$o" '.data.management_state')" 'live helper starts inactive'

o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-activate1","op":"management.activate"}')"
assert_eq true "$(jqv "$o" '.ok')" 'activate over the live socket'

BEFORE_SUM="$(sum "$SBROOT/sbconfig_server.json")"
o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-add-00001","name":"live-01","idempotency_key":"live-key-00000001","op":"client.add"}')"
assert_eq true "$(jqv "$o" '.ok')" "client.add over the live socket (got: $(jqv "$o" '.error.code'))"
assert_eq false "$(jqv "$o" '.idempotency.replayed')" 'first add is not a replay'
assert_ne "$BEFORE_SUM" "$(sum "$SBROOT/sbconfig_server.json")" 'the live config really changed'
assert_eq 1 "$(reload_count)" 'the hardened unit reloaded sing-box exactly once'

o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-list-0001","op":"client.list"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.list over the live socket'
printf '%s' "$o" | grep -qF 'live-01' && pass 'the added client is listed' || fail 'client missing from list'

o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-del-00001","name":"live-01","idempotency_key":"live-key-00000002","op":"client.delete"}')"
assert_eq true "$(jqv "$o" '.ok')" "client.delete over the live socket (got: $(jqv "$o" '.error.code'))"
assert_eq 2 "$(reload_count)" 'delete reloaded sing-box again'

o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-deact001","op":"management.deactivate"}')"
assert_eq true "$(jqv "$o" '.ok')" 'deactivate over the live socket'
assert_eq inactive "$(jqv "$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-status002","op":"management.status"}')" '.data.management_state')" \
    'the plane is inactive again'

# ------------------------------------------------------------------- rollback --
systemctl start sbox-cm.service >/dev/null 2>&1
rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-activate2","op":"management.activate"}' >/dev/null
touch "$FIX/fail-first"
: > "$FIX/reload.count"
BEFORE_SUM="$(sum "$SBROOT/sbconfig_server.json")"
o="$(rpc "$AXE_USER" '{"v":"e3-rpc/1","request_id":"reqid-live-rlbk0001","name":"live-02","idempotency_key":"live-key-00000003","op":"client.add"}')"
rm -f "$FIX/fail-first"
assert_eq false "$(jqv "$o" '.ok')" 'a failing reload is reported as failure'
assert_eq E_ROLLED_BACK "$(jqv "$o" '.error.code')" 'the hardened unit rolled back automatically'
assert_eq "$BEFORE_SUM" "$(sum "$SBROOT/sbconfig_server.json")" 'rollback restored the live config byte-for-byte'
assert_eq active "$(unit_state sbox-cm.service)" 'the daemon survived the rollback'

# ------------------------------------------------- startup reconciliation ----
printf '%s\n' '{"v":1,"request_id":"reqid-live-orphan01","op":"client.add","phase":"replace","backup_path":null,"generation":1}' \
    > "$STATE/journal/reqid-live-orphan01.json"
[ -f "$STATE/journal/reqid-live-orphan01.json" ] && pass 'orphan journal staged' || fail 'staging failed'
systemctl restart sbox-cm.service >/dev/null 2>&1
for _ in $(seq 1 100); do [ -f "$STATE/journal/reqid-live-orphan01.json" ] || break; sleep 0.1; done
[ ! -f "$STATE/journal/reqid-live-orphan01.json" ] \
    && pass 'startup reconciliation cleared the orphan journal on restart' \
    || fail 'orphan journal survived restart'
assert_eq active "$(unit_state sbox-cm.service)" 'daemon healthy after reconciliation'

# -------------------------------------------------------------------- sandbox --
if command -v systemd-analyze >/dev/null 2>&1; then
    SCORE="$(systemd-analyze security sbox-cm.service 2>/dev/null | tail -n 1 | grep -oE '[0-9]+\.[0-9]+' | head -n 1)"
    if [ -n "$SCORE" ]; then
        pass "hardening exposure under the REAL units: ${SCORE} (informational)"
    else
        skip 'systemd-analyze security unavailable for the live unit'
    fi
fi

# ---------------------------------------------------------------- report --
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf -- '----- diagnostic: sbox-cm.service journal (last 40 lines) -----\n'
    journalctl -u sbox-cm.service -n 40 --no-pager 2>/dev/null || true
    printf -- '----- end diagnostic -----\n'
    printf 'E3_M1_SYSTEMD=FAIL\n'
    exit 1
fi
printf 'E3_M1_SYSTEMD=PASS\n'
