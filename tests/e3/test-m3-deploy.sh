#!/usr/bin/env bash
# E3 M3 -- deploy tooling test: the production preflight / deploy-verify /
# rollback scripts are executed for real against a live fixture, in the REAL
# FIRST-DEPLOY ORDER (final review freeze):
#
#   1. mock sing-box + an ALREADY-DEPLOYED monitor (release symlink) and
#      ZERO sbox-cm capability;
#   2. preflight --baseline-out  ->  PASS, and the baseline REALLY records
#      helper.libexec/socket_unit/service_unit = false (measured, not forged);
#   3. the REAL install-sbox-cm.sh install (D3);
#   4. D4 = enable --now sbox-cm.socket ONLY; the service must still be
#      inactive until the first RPC;
#   5. deploy-verify: V05a socket active, V07 real sboxweb RPC (which pulls
#      the service up), V05b service active, config untouched, fail-closed
#      mutation while inactive, release tree byte-identical;
#   6. rollback: units/libexec/all four capability files gone again, state/
#      audit tree kept, config byte-identical, monitor release still the
#      baseline one.
#
# Negative contracts: preflight FAILS on an armed marker / broken config /
# existing helper capability / partial libexec / non-symlink monitor app,
# and a failed preflight never creates or overwrites a baseline.
# Exit-status contract and skip=FAIL flag as in the M1/M2 live gates.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FIX="/run/sboxcm-m3-test"
RELDIR="/opt/sboxcm-m3-releases"
RELLINK="/opt/sboxcm-m3"
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
REL_ID="rel-0001"

PASS=0; FAIL=0; SKIP=0
# Frozen assertion count: PASS + FAIL + SKIP must equal this, so a
# section that silently disappears (e.g. an undefined helper) fails
# the suite instead of quietly shrinking it.
EXPECTED_TOTAL=53
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }
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
# The refuse-check covers THIS suite's own fixture paths; sbox-cm paths are
# handled by explicit hygiene below (earlier suites in the same CI job --
# M1 B-5 / M2 live -- legitimately leave units/libexec/state behind).
if [ -e /root/sbox ] || [ -e "$MDATA" ] || [ -e /etc/systemd/system/singbox-monitor.service ] \
        || [ -e "$RELLINK" ]; then
    fail 'a fixture path already exists: refusing to run over a real deployment'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

# CI hygiene: strip any leftover sbox-cm capability from earlier suites so
# the fixture really starts from the ZERO-capability first-deploy state.
systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
systemctl disable sbox-cm.socket sbox-cm.service 2>/dev/null
rm -f /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service
rm -rf /usr/local/lib/sbox-cm /var/lib/sbox-cm
systemctl daemon-reload 2>/dev/null
if [ ! -e /etc/systemd/system/sbox-cm.socket ] \
        && [ ! -e /etc/systemd/system/sbox-cm.service ] \
        && [ ! -e /usr/local/lib/sbox-cm/sbox-cm ]; then
    pass 'fixture hygiene: ZERO sbox-cm capability after cleanup (true first-deploy slate)'
else
    fail 'fixture hygiene failed: sbox-cm capability still present'
fi

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    systemctl stop singbox-monitor.service 2>/dev/null
    systemctl disable singbox-monitor.service 2>/dev/null
    rm -f /etc/systemd/system/singbox-monitor.service /etc/systemd/system/sing-box.service
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket sbox-cm.service 2>/dev/null
    rm -f /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service
    systemctl daemon-reload 2>/dev/null
    rm -rf -- /root/sbox "$FIX" "$RELLINK" "$RELDIR" "$MDATA" /usr/local/lib/sbox-cm 2>/dev/null
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
mkdir -p "$FIX" "$MDATA" /root/sbox "$RELDIR/$REL_ID"
chmod 0777 "$FIX"

cat > /root/sbox/sing-box <<'MOCK'
#!/usr/bin/env bash
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

# monitor release tree + symlink (the packaging layout the preflight freezes)
# B1: the REAL packaging layout -- <release>/VERSION, <release>/app/monitor-v2/
# {webapp.py,collector.py,web/,api_bridge/}, <release>/bin, <release>/lib.
mkdir -p "$RELDIR/$REL_ID/app/monitor-v2" "$RELDIR/$REL_ID/bin" "$RELDIR/$REL_ID/lib"
cp "$ROOT"/monitor-v2/*.py "$RELDIR/$REL_ID/app/monitor-v2/" 2>/dev/null
cp -r "$ROOT/monitor-v2/web" "$RELDIR/$REL_ID/app/monitor-v2/web"
cp -r "$ROOT/monitor-v2/api_bridge" "$RELDIR/$REL_ID/app/monitor-v2/api_bridge"
printf 'm3-test\n' > "$RELDIR/$REL_ID/VERSION"
rm -rf "$RELDIR/$REL_ID/app/monitor-v2/web/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/api_bridge/__pycache__" 2>/dev/null
ln -sfn "$RELDIR/$REL_ID" "$RELLINK"
chown -R "$AXE_USER":"$AXE_USER" "$RELDIR" "$MDATA"
chmod 0700 "$MDATA"
sudo -u "$AXE_USER" env -u SSH_CONNECTION python3 "$RELLINK/app/monitor-v2/webapp.py" setup \
    --assume-yes --password "m3-deploy-admin-password-01" --data-dir "$MDATA" \
    >/dev/null 2>&1 \
    || { fail 'monitor setup failed'; printf '\nE3_M3_DEPLOY=FAIL\n'; exit 1; }
sed -e "s|@SBMON_USER@|$AXE_USER|g" \
    -e "s|@SBMON_GROUP@|$AXE_USER|g" \
    -e "s|@SBMON_APP_DIR@|$RELLINK|g" \
    -e "s|@SBMON_CONF@|/etc/sboxcm-m3/monitor.conf|g" \
    -e "s|@SBMON_STATE_ROOT@|$MDATA|g" \
    "$ROOT/monitor-v2/deploy/singbox-monitor.service.in" \
| sed -e "s|^ExecStart=.*|ExecStart=/usr/bin/python3 $RELLINK/app/monitor-v2/webapp.py serve --listen 127.0.0.1 --port $MPORT --data-dir $MDATA|" \
      -e "s|^After=.*|After=network-online.target|" \
> /etc/systemd/system/singbox-monitor.service
mkdir -p /etc/sboxcm-m3
printf '# m3 fixture conf\n' > /etc/sboxcm-m3/monitor.conf
systemctl daemon-reload
systemctl enable --now singbox-monitor.service >/dev/null 2>&1
for _ in $(seq 1 40); do
    [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/api/v1/session" 2>/dev/null)" = "200" ] && break
    sleep 0.25
done
pass 'fixture live: mock sing-box + deployed monitor in the REAL app/monitor-v2 release layout + ZERO sbox-cm capability'
assert_ne '' "$(ls -1 "$RELDIR/$REL_ID/app/monitor-v2/webapp.py" 2>/dev/null)" \
    'B1: the release tree carries app/monitor-v2/webapp.py (real packaging layout)'
[ -f "$RELDIR/$REL_ID/VERSION" ] \
    && pass 'B1: VERSION stays at the release root' \
    || fail 'B1: VERSION is not at the release root'

export E3_SYSTEMCTL=systemctl
export E3_CONFIG=/root/sbox/sbconfig_server.json
export E3_SING_BOX_BIN=/root/sbox/sing-box
export E3_SBXCM_STATE=/var/lib/sbox-cm
export E3_SBXCM_LIBEXEC=/usr/local/lib/sbox-cm
export E3_SBXCM_SOCKET=/run/sbox-cm/sbox-cm.sock
export E3_MONITOR_URL="$BASE"
export E3_MONITOR_APP="$RELLINK"

# --------------------------------- preflight BEFORE the helper is installed --
BASELINE="$FIX/baseline.json"
OUT="$(bash "$PREFLIGHT" --baseline-out "$BASELINE")"
RC=$?
printf '%s\n' "$OUT" | grep -q 'E3_PREFLIGHT=PASS' \
    && pass 'preflight (BEFORE any sbox-cm install) reports PASS' \
    || { FAIL=$((FAIL+1)); printf '  FAIL preflight (rc=%s):\n%s\n' "$RC" "$OUT"; }
assert_eq "false" "$(jqv "$(cat "$BASELINE")" '.helper.libexec_present')" \
    'baseline REALLY records helper.libexec_present=false (measured pre-deploy)'
assert_eq "false" "$(jqv "$(cat "$BASELINE")" '.helper.socket_unit_present')" \
    'baseline REALLY records helper.socket_unit_present=false'
RESIDUE="$(ls -1 "$BASELINE".tmp.* "$BASELINE"*.err* 2>/dev/null || true)"
assert_eq '' "$RESIDUE" 'no baseline temp/error residue after a successful preflight'
assert_eq "false" "$(jqv "$(cat "$BASELINE")" '.helper.service_unit_present')" \
    'baseline REALLY records helper.service_unit_present=false'
assert_eq "$REL_ID" "$(jqv "$(cat "$BASELINE")" '.monitor.release_id')" \
    'baseline freezes the exact monitor release id from the live symlink'
BASE_SHA="$(jqv "$(cat "$BASELINE")" '.config_sha256')"

# preflight FAIL: armed marker (and a failed preflight never touches the baseline)
mkdir -p /var/lib/sbox-cm
chmod 0700 /var/lib/sbox-cm
printf '%s\n' '{"v":1,"state":"active"}' > /var/lib/sbox-cm/management.active
FAIL_BASE="$FIX/baseline-fail.json"
printf 'SENTINEL-BASELINE\n' > "$FAIL_BASE"
if bash "$PREFLIGHT" --baseline-out "$FAIL_BASE" >/dev/null 2>&1; then
    fail 'preflight with an armed marker must FAIL'
else
    pass 'preflight with an armed marker FAILS (deploy-disabled contract)'
fi
assert_eq "SENTINEL-BASELINE" "$(cat "$FAIL_BASE")" \
    'a failed preflight did not create/overwrite the baseline (marker case)'
rm -f /var/lib/sbox-cm/management.active
rmdir /var/lib/sbox-cm 2>/dev/null || true   # restore the absent first-deploy state

# preflight FAIL: broken config (check-rejected) -- no baseline either
cp /root/sbox/sbconfig_server.json "$FIX/config.bak"
python3 - <<'PY'
import json
p = "/root/sbox/sbconfig_server.json"
cfg = open(p).read().replace('"inbounds"', '"__BROKEN__": true, "inbounds"')
open(p, "w").write(cfg)
PY
FAIL_BASE2="$FIX/baseline-fail2.json"
if bash "$PREFLIGHT" --baseline-out "$FAIL_BASE2" >/dev/null 2>&1; then
    fail 'preflight with a check-rejected config must FAIL'
else
    pass 'preflight with a check-rejected config FAILS'
fi
[ ! -e "$FAIL_BASE2" ] \
    && pass 'a failed preflight created NO baseline (check-reject case)' \
    || fail 'a failed preflight wrote a baseline (check-reject case)'
cp "$FIX/config.bak" /root/sbox/sbconfig_server.json
chmod 0600 /root/sbox/sbconfig_server.json

# preflight FAIL: monitor app is NOT a symlink
mkdir -p "$FIX/not-a-symlink"
printf 'x\n' > "$FIX/not-a-symlink/VERSION"
printf 'x\n' > "$FIX/not-a-symlink/webapp.py"
if E3_MONITOR_APP="$FIX/not-a-symlink" bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with a non-symlink monitor app must FAIL'
else
    pass 'preflight with a non-symlink monitor app FAILS (release link contract)'
fi

# preflight FAIL: a stale runtime socket is leftover capability, not a
# clean first-deploy state (final review hardening)
mkdir -p /run/sbox-cm
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('/run/sbox-cm/sbox-cm.sock')
s.close()
PY
chown root:sboxweb /run/sbox-cm/sbox-cm.sock
chmod 0660 /run/sbox-cm/sbox-cm.sock
if bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with a stale runtime socket must FAIL'
else
    pass 'preflight with a root:sboxweb 0660 stale runtime socket FAILS solely because the path exists'
fi
rm -f /run/sbox-cm/sbox-cm.sock

# ------------------------------------- D3: the REAL installer, then D4/D5 --
"$ROOT/sbox-cm/deploy/install-sbox-cm.sh" install >/dev/null 2>&1 \
    || { fail 'D3 real sbox-cm install failed'; printf '\nE3_M3_DEPLOY=FAIL\n'; exit 1; }
pass 'D3 sbox-cm installed by the REAL installer'

# preflight FAIL: existing helper capability (first-deploy-only freeze)
if bash "$PREFLIGHT" >/dev/null 2>&1; then
    fail 'preflight with an existing helper capability must FAIL'
else
    pass 'preflight with an existing helper capability FAILS (first-deploy-only freeze)'
fi
P00_OUT="$(bash "$PREFLIGHT" 2>&1 || true)"
printf '%s' "$P00_OUT" | grep -qF 'existing sbox-cm deployment requires a separately reviewed upgrade path' \
    && pass 'the freeze message is the exact approved wording' \
    || fail 'the freeze message wording is wrong'

# partial libexec: remove one of the two binaries -> still FAIL, accurate list
mv /usr/local/lib/sbox-cm/sbox-cm-ops "$FIX/sbox-cm-ops.saved"
P00_PARTIAL="$(bash "$PREFLIGHT" 2>&1 || true)"
printf '%s' "$P00_PARTIAL" | grep -qF 'existing sbox-cm deployment requires a separately reviewed upgrade path' \
    && pass 'partial helper capability still FAILS (freeze holds)' \
    || fail 'partial helper capability did not fail the preflight'
bash "$PREFLIGHT" 2>&1 | grep -qF 'sbox-cm-ops' \
    && fail 'partial helper capability wrongly reported sbox-cm-ops as present' \
    || pass 'partial enumeration is accurate (sbox-cm-ops reported absent)'
mv "$FIX/sbox-cm-ops.saved" /usr/local/lib/sbox-cm/sbox-cm-ops

# D4: socket-only enablement -- the service must stay inactive
systemctl enable --now sbox-cm.socket >/dev/null 2>&1 \
    || { fail 'D4 sbox-cm.socket enable failed'; printf '\nE3_M3_DEPLOY=FAIL\n'; exit 1; }
for _ in $(seq 1 50); do [ -S /run/sbox-cm/sbox-cm.sock ] && break; sleep 0.1; done
assert_eq "active" "$(systemctl is-active sbox-cm.socket 2>/dev/null || true)" \
    'D4 sbox-cm.socket is active'
assert_eq "inactive" "$(systemctl is-active sbox-cm.service 2>/dev/null || true)" \
    'D4 the service is still INACTIVE before the first RPC (socket-only enablement)'

# ------------------------------------------------- deploy-verify (PASS) --
TREE_BEFORE="$(find "$RELLINK/" -type f | sort | xargs sha256sum 2>/dev/null | sha256sum | awk '{print $1}')"
VOUT="$(bash "$VERIFY" --baseline "$BASELINE")"
RC=$?
TREE_AFTER="$(find "$RELLINK/" -type f | sort | xargs sha256sum 2>/dev/null | sha256sum | awk '{print $1}')"
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
printf '%s' "$VOUT" | grep -qF 'pulled up by the real RPC' \
    && pass 'verify proves socket activation pulled the service up (V05b, real RPC)' \
    || fail 'verify did not prove the socket-activation pull-up'
assert_eq "$TREE_BEFORE" "$TREE_AFTER" \
    'verify leaves the monitor release tree byte-identical (no probe file, no bytecode)'

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
EXPECT_REL="$(jqv "$(cat "$BASELINE")" '.monitor.release_id')"
cat > "$STUB_INSTALLER" <<'STUB'
#!/usr/bin/env bash
printf '%s
' "$*" >> /run/sboxcm-m3-test/stub-installer.log
exit 0
STUB
chmod 0755 "$STUB_INSTALLER"
RBOUT="$(E3_INSTALL_MONITOR="$STUB_INSTALLER" E3_RELEASES_DIR="$RELDIR" \
    bash "$ROLLBACK" --baseline "$BASELINE")"
RC=$?
printf '%s' "$RBOUT" | grep -q 'E3_M3_ROLLBACK=PASS' \
    && pass 'rollback reports PASS (first-deploy inverse)' \
    || { FAIL=$((FAIL+1)); printf '  FAIL rollback (rc=%s):\n%s\n' "$RC" "$RBOUT"; }
grep -qF "rollback $EXPECT_REL" "$FIX/stub-installer.log" \
    && pass 'rollback invoked the packaging rollback with the BASELINE release id' \
    || fail 'rollback did not use the baseline release id'
[ ! -e /usr/local/lib/sbox-cm/sbox-cm ] \
    && pass 'rollback removed the sbox-cm binary' \
    || fail 'sbox-cm binary survived the rollback'
[ ! -e /usr/local/lib/sbox-cm/sbox-cm-ops ] \
    && pass 'rollback removed sbox-cm-ops' \
    || fail 'sbox-cm-ops survived the rollback'
[ ! -e /usr/local/lib/sbox-cm/lib/client-management.sh ] \
    && pass 'rollback removed lib/client-management.sh' \
    || fail 'lib/client-management.sh survived the rollback'
[ ! -e /usr/local/lib/sbox-cm/lib/sbox-cm-state.sh ] \
    && pass 'rollback removed lib/sbox-cm-state.sh' \
    || fail 'lib/sbox-cm-state.sh survived the rollback'
[ ! -e /etc/systemd/system/sbox-cm.socket ] \
    && pass 'rollback removed the socket unit' \
    || fail 'socket unit survived the rollback'
[ ! -e /etc/systemd/system/sbox-cm.service ] \
    && pass 'rollback removed the service unit' \
    || fail 'service unit survived the rollback'
[ ! -S /run/sbox-cm/sbox-cm.sock ] \
    && pass 'rollback removed the socket file' \
    || fail 'socket file survived the rollback'
[ -d /var/lib/sbox-cm ] \
    && pass 'rollback KEEPS the state/audit tree (explicit policy)' \
    || fail 'rollback purged the state/audit tree'
[ ! -e /var/lib/sbox-cm/management.active ] \
    && pass 'rollback leaves the plane closed' \
    || fail 'rollback left an activation marker'
NOW_SHA="$(sha256sum /root/sbox/sbconfig_server.json | awk '{print $1}')"
assert_eq "$BASE_SHA" "$NOW_SHA" 'rollback left the config byte-identical'
assert_eq "$REL_ID" "$(basename "$(readlink -f "$RELLINK")")" \
    'monitor release id still the baseline one after rollback'
HTTP="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/api/v1/session" 2>/dev/null)"
assert_eq "200" "$HTTP" 'monitor still answers after the rollback'

# rollback FAIL: missing installer (fail-closed, no silent pass)
if E3_INSTALL_MONITOR="$FIX/no-such-installer.sh" E3_RELEASES_DIR="$RELDIR" \
        bash "$ROLLBACK" --baseline "$BASELINE" >/dev/null 2>&1; then
    fail 'rollback with a missing installer must FAIL'
else
    pass 'rollback with a missing installer FAILS'
fi

# rollback FAIL: baseline release id does not exist on disk
jq '.monitor.release_id = "no-such-release"' "$BASELINE" > "$FIX/baseline-badrel.json"
if E3_INSTALL_MONITOR="$STUB_INSTALLER" E3_RELEASES_DIR="$RELDIR" \
        bash "$ROLLBACK" --baseline "$FIX/baseline-badrel.json" >/dev/null 2>&1; then
    fail 'rollback with a nonexistent target release must FAIL'
else
    pass 'rollback with a nonexistent target release FAILS'
fi

# rollback FAIL: a service-disable failure can never be a silent pass
cat > "$FIX/stub-systemctl" <<'STUBCTL'
#!/usr/bin/env bash
if [ "${1:-}" = "disable" ]; then
    printf '%s\n' "$*" >> /run/sboxcm-m3-test/stub-systemctl.log
    exit 1
fi
exec /usr/bin/systemctl "$@"
STUBCTL
chmod 0755 "$FIX/stub-systemctl"
RB2="$(E3_SYSTEMCTL="$FIX/stub-systemctl" E3_INSTALL_MONITOR="$STUB_INSTALLER" \
    E3_RELEASES_DIR="$RELDIR" bash "$ROLLBACK" --baseline "$BASELINE" 2>/dev/null)"
if printf '%s' "$RB2" | grep -q 'E3_M3_ROLLBACK=FAIL'; then
    pass 'a service-disable failure FAILS the rollback (never a silent pass)'
else
    fail 'a service-disable failure did not fail the rollback'
fi

# rollback FAIL: a daemon-reload failure can never be a silent pass
cat > "$FIX/stub-reload" <<'STUBRL'
#!/usr/bin/env bash
if [ "${1:-}" = "daemon-reload" ]; then exit 1; fi
exec /usr/bin/systemctl "$@"
STUBRL
chmod 0755 "$FIX/stub-reload"
RB3="$(E3_SYSTEMCTL="$FIX/stub-reload" E3_INSTALL_MONITOR="$STUB_INSTALLER" \
    E3_RELEASES_DIR="$RELDIR" bash "$ROLLBACK" --baseline "$BASELINE" 2>/dev/null)"
if printf '%s' "$RB3" | grep -q 'E3_M3_ROLLBACK=FAIL'; then
    pass 'a daemon-reload failure FAILS the rollback (never a silent pass)'
else
    fail 'a daemon-reload failure did not fail the rollback'
fi

# B2: the DEFAULT installer resolver must be the sibling install-monitor.sh
# inside the rollback script's own deploy directory (no /opt/... guess).
DEPLOY_DIR_GOT="$(sed -n 's/^DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE\[0\]}")" && pwd)"$/yes/p' \
    "$ROOT/monitor-v2/deploy/e3-rollback.sh" | head -1)"
if [ "$DEPLOY_DIR_GOT" = "yes" ]; then
    pass 'B2: rollback resolves its own DEPLOY_DIR from BASH_SOURCE'
else
    fail 'B2: rollback does not resolve DEPLOY_DIR from BASH_SOURCE'
fi
grep -qF 'E3_INSTALL_MONITOR="${E3_INSTALL_MONITOR:-$DEPLOY_DIR/install-monitor.sh}"' \
    "$ROOT/monitor-v2/deploy/e3-rollback.sh" \
    && pass 'B2: the default installer path is the sibling install-monitor.sh' \
    || fail 'B2: the default installer path is not the sibling script'
grep -qF '/opt/singbox-monitor-releases/install-monitor.sh' \
    "$ROOT/monitor-v2/deploy/e3-rollback.sh" \
    && fail 'B2: a stale /opt installer default is still present' \
    || pass 'B2: no stale /opt installer default remains'
grep -qF '[ ! -x "$E3_INSTALL_MONITOR" ]' "$ROOT/monitor-v2/deploy/e3-rollback.sh" \
    && pass 'B2: R2 requires the installer to be EXECUTABLE' \
    || fail 'B2: R2 does not check installer executability'

TOTAL=$((PASS + FAIL + SKIP))
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
printf 'TOTAL=%d (expected %d)\n' "$TOTAL" "$EXPECTED_TOTAL"
if [ "$FAIL" -ne 0 ] || [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    printf 'E3_M3_DEPLOY=FAIL\n'
    exit 1
fi
printf 'E3_M3_DEPLOY=PASS\n'
