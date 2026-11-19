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
#
# Issue #96 / E3 M3 follow-up: some CI runner images mount /run noexec. An
# executable mode bit there is not enough to run a file -- execve(2)/access(X_OK)
# still refuse it -- so executable fixtures MUST NOT live under the /run state
# root. The /run state root carries only data (baseline/logs/cookies); every
# stub the production rollback executes is created in a dedicated EXECROOT that
# was proved executable by actually running a probe there. The negative
# rollback contracts additionally assert their SPECIFIC failure reason, so a
# broken fixture can never masquerade as an intended rollback refusal.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FIX="/run/sboxcm-m3-test"
EXECROOT=""
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
REL_ID="rel-0001"

PASS=0; FAIL=0; SKIP=0
# Frozen assertion count: PASS + FAIL + SKIP must equal this, so a
# section that silently disappears (e.g. an undefined helper) fails
# the suite instead of quietly shrinking it. The noexec simulation adds its
# own environment-verification assertion, so the expected total is explicit
# for both invocation modes.
EXPECTED_TOTAL=88
if [ "${SBOX_E3_EXPECT_FIX_NOEXEC:-0}" = "1" ]; then
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + 1))
fi
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

# Fixture executables and their evidence markers live in a root-private scratch
# tree whose ancestry is trusted. A world-writable or non-root parent would let
# another local identity substitute a path; /run is data-only and is explicitly
# not a candidate. The probe proves the filesystem really executes a file.
trusted_parent() {
    local parent=$1 owner mode
    [ -d "$parent" ] || return 1
    case "$parent" in
        /run|/run/*) return 1 ;;
    esac
    owner="$(stat -c %u "$parent" 2>/dev/null)" || return 1
    mode="$(stat -c %a "$parent" 2>/dev/null)" || return 1
    [ "$owner" = "0" ] || return 1
    [ $(( 0$mode & 022 )) -eq 0 ] || return 1
    return 0
}

probe_exec_root() {
    local dir=$1
    local probe="$dir/.exec-probe.sh"
    printf '#!/usr/bin/env bash\nprintf ok\n' > "$probe" 2>/dev/null || return 1
    chmod 0755 "$probe" 2>/dev/null || return 1
    [ "$("$probe" 2>/dev/null)" = "ok" ]
}

make_exec_root() {
    local candidate created
    for candidate in "${SBOX_E3_EXEC_ROOT:-}" /opt /var/lib /usr/local /root; do
        [ -n "$candidate" ] || continue
        trusted_parent "$candidate" || continue
        created="$(mktemp -d "$candidate/.e3-m3-exec.XXXXXXXX" 2>/dev/null)" || continue
        chmod 0700 "$created" 2>/dev/null || { rm -rf -- "$created"; continue; }
        if probe_exec_root "$created"; then
            EXECROOT="$created"
            return 0
        fi
        rm -rf -- "$created"
    done
    return 1
}

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
    [ -n "${EXECROOT:-}" ] && rm -rf -- "$EXECROOT" 2>/dev/null
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

# ------------------------------------------------ executable fixture root --
# Executables live OUTSIDE the /run state root; the probe above each candidate
# proves the filesystem really allows execution (a mode bit is not enough).
if ! make_exec_root; then
    fail 'no exec-capable fixture root: every candidate is non-executable/unwritable'
    trap - EXIT INT TERM
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi
case "$EXECROOT" in
    /run|/run/*)
        fail "executable fixture root [$EXECROOT] must not be under the noexec-prone /run"
        rm -rf -- "$EXECROOT" 2>/dev/null
        trap - EXIT INT TERM
        printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
        ;;
esac
pass 'executable fixture root is outside /run and really executable'

EVIDENCE_DIR="$EXECROOT/evidence"
mkdir -p "$EVIDENCE_DIR" 2>/dev/null || true
chmod 0700 "$EVIDENCE_DIR" 2>/dev/null || true
assert_eq "0" "$(stat -c %u "$EXECROOT" 2>/dev/null)" \
    'executable fixture root is root-owned'
assert_eq "700" "$(stat -c %a "$EXECROOT" 2>/dev/null)" \
    'executable fixture root is root-private (0700)'
assert_eq "0" "$(stat -c %u "$EVIDENCE_DIR" 2>/dev/null)" \
    'per-case evidence directory is root-owned'
assert_eq "700" "$(stat -c %a "$EVIDENCE_DIR" 2>/dev/null)" \
    'per-case evidence directory is root-private (0700)'
if trusted_parent "$(dirname "$EXECROOT")"; then
    pass 'executable fixture root has a trusted root-owned, non-writable parent'
else
    fail 'executable fixture root parent is not a trusted root-owned, non-writable directory'
fi

STUB_INSTALLER="$EXECROOT/stub-install-monitor.sh"
FAIL_INSTALLER="$EXECROOT/stub-install-monitor-fail.sh"
NONEXEC_INSTALLER="$EXECROOT/stub-install-monitor-nonexec.sh"

# ------------------------------------------------------------------ fixture --
getent passwd "$AXE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$AXE_USER"
getent group  "$AXE_USER" >/dev/null 2>&1 || groupadd --system "$AXE_USER"
mkdir -p "$FIX" "$MDATA" /root/sbox "$RELDIR/$REL_ID"
chmod 0777 "$FIX"
export SBOX_E3_M3_STUB_LOG="$FIX/stub-installer.log"
export SBOX_E3_M3_SYSTEMCTL_LOG="$FIX/stub-systemctl.log"

# Evidence-only diagnostics (never assertions): record the effective mount
# options and the native exec behavior of the /run state root and EXECROOT, so
# every CI log distinguishes a native noexec runner from the controlled
# simulation. The probe file is removed immediately.
diag_mount_opts() {
    findmnt -T "$1" -no OPTIONS 2>/dev/null || printf 'unknown'
}
printf 'fixture-evidence run_opts=%s fix_opts=%s execroot_opts=%s\n' \
    "$(diag_mount_opts /run)" "$(diag_mount_opts "$FIX")" "$(diag_mount_opts "$EXECROOT")"
printf '#!/usr/bin/env bash\nprintf ran\n' > "$FIX/.native-exec-probe.sh"
chmod 0755 "$FIX/.native-exec-probe.sh"
if "$FIX/.native-exec-probe.sh" >/dev/null 2>&1; then
    native_fix_exec=yes
else
    native_fix_exec=no
fi
rm -f "$FIX/.native-exec-probe.sh"
printf 'fixture-evidence native_run_exec=%s controlled_noexec=%s\n' \
    "$native_fix_exec" "${SBOX_E3_EXPECT_FIX_NOEXEC:-0}"

# Negative environment experiment: with SBOX_E3_EXPECT_FIX_NOEXEC=1 the caller
# has mounted the state root noexec, and the suite must PROVE that (execution
# refused) while still passing every real rollback contract through EXECROOT.
if [ "${SBOX_E3_EXPECT_FIX_NOEXEC:-0}" = "1" ]; then
    printf '#!/usr/bin/env bash\nprintf ran\n' > "$FIX/.noexec-probe.sh"
    chmod 0755 "$FIX/.noexec-probe.sh"
    if [ ! -f "$FIX/.noexec-probe.sh" ]; then
        fail 'could not create the execution probe inside the simulated noexec state root: experiment invalid'
    elif [ -z "$(find "$FIX/.noexec-probe.sh" -perm /111 -print -quit 2>/dev/null)" ]; then
        fail 'the execution probe inside the simulated noexec state root lacks executable mode bits: experiment invalid'
    elif "$FIX/.noexec-probe.sh" >/dev/null 2>&1; then
        fail 'simulated noexec state root is actually executable: the experiment does not prove the noexec contract'
    else
        pass 'simulated noexec state root rejects execution: executable/state separation is under test'
    fi
    rm -f "$FIX/.noexec-probe.sh"
fi

install -m 0755 "$ROOT/tests/lib/mock-sing-box" /root/sbox/sing-box
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
# {webapp.py,collector.py,web/,api_bridge/,diagnostics/}, <release>/bin,
# <release>/lib. PR-3B: diagnostics/ is part of that boot-critical payload
# (webapp.py imports the scheduler), so the hand-built release must mirror it
# or this fixture stops being the layout the preflight freezes.
mkdir -p "$RELDIR/$REL_ID/app/monitor-v2" "$RELDIR/$REL_ID/bin" "$RELDIR/$REL_ID/lib"
cp "$ROOT"/monitor-v2/*.py "$RELDIR/$REL_ID/app/monitor-v2/" 2>/dev/null
cp -r "$ROOT/monitor-v2/web" "$RELDIR/$REL_ID/app/monitor-v2/web"
cp -r "$ROOT/monitor-v2/api_bridge" "$RELDIR/$REL_ID/app/monitor-v2/api_bridge"
cp -r "$ROOT/monitor-v2/diagnostics" "$RELDIR/$REL_ID/app/monitor-v2/diagnostics"
# PR-6B: remote_probe/ joined the boot-critical monitor payload
# (webapp.py wires the ingest plane at startup).
cp -r "$ROOT/monitor-v2/remote_probe" "$RELDIR/$REL_ID/app/monitor-v2/remote_probe"
printf 'm3-test\n' > "$RELDIR/$REL_ID/VERSION"
rm -rf "$RELDIR/$REL_ID/app/monitor-v2/web/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/api_bridge/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/diagnostics/__pycache__" \
       "$RELDIR/$REL_ID/app/monitor-v2/remote_probe/__pycache__" 2>/dev/null
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
    -e "s|@SBMON_PROBE_TARGETS_FILE@|/etc/sboxcm-m3/probe-targets.json|g" \
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
# E3_SBXCM_SOCKET is intentionally NOT exported: rollback must mirror the
# preflight default (/run/sbox-cm/sbox-cm.sock) without an explicit override.
# Fixture-only override semantics remain available to callers that set it.

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
mv /usr/local/lib/sbox-cm/sbox-cm-ops "$EXECROOT/sbox-cm-ops.saved"
P00_PARTIAL="$(bash "$PREFLIGHT" 2>&1 || true)"
printf '%s' "$P00_PARTIAL" | grep -qF 'existing sbox-cm deployment requires a separately reviewed upgrade path' \
    && pass 'partial helper capability still FAILS (freeze holds)' \
    || fail 'partial helper capability did not fail the preflight'
bash "$PREFLIGHT" 2>&1 | grep -qF 'sbox-cm-ops' \
    && fail 'partial helper capability wrongly reported sbox-cm-ops as present' \
    || pass 'partial enumeration is accurate (sbox-cm-ops reported absent)'
mv "$EXECROOT/sbox-cm-ops.saved" /usr/local/lib/sbox-cm/sbox-cm-ops

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
printf '%s\n' "$*" >> "${SBOX_E3_M3_STUB_LOG:-/dev/null}"
exit 0
STUB
chmod 0755 "$STUB_INSTALLER"
# Prove the stub REALLY executes before the production rollback relies on it.
# A noexec scratch filesystem would otherwise turn every negative rollback
# contract below into a false positive ("it failed, so the test passed").
if "$STUB_INSTALLER" fixture-exec-probe >/dev/null 2>&1 \
        && grep -qF 'fixture-exec-probe' "$SBOX_E3_M3_STUB_LOG"; then
    pass 'rollback installer stub is really executable on its exec-capable filesystem'
else
    fail 'rollback installer stub cannot execute: fixture infrastructure is broken, not a rollback result'
fi
: > "$SBOX_E3_M3_STUB_LOG"
if [ -z "$(find "$FIX" -type f -perm /111 -print -quit 2>/dev/null)" ]; then
    pass 'no executable fixture file lives inside the /run state root'
else
    fail 'an executable fixture file lives inside the /run state root (noexec-prone)'
fi
# P1 regression: the removed E3_SBXCM_UNIT_DIR override must never retarget a
# destructive rollback. The decoy directory is passed via the old env name and
# must remain untouched while the real /etc/systemd/system units are removed.
DECOY_UNITS="$EVIDENCE_DIR/decoy-units"
rm -rf "$DECOY_UNITS"; mkdir -p "$DECOY_UNITS"
printf 'decoy\n' > "$DECOY_UNITS/sbox-cm.socket"
printf 'decoy\n' > "$DECOY_UNITS/sbox-cm.service"
RBOUT="$(E3_SBXCM_UNIT_DIR="$DECOY_UNITS" E3_INSTALL_MONITOR="$STUB_INSTALLER" \
    E3_RELEASES_DIR="$RELDIR" bash "$ROLLBACK" --baseline "$BASELINE")"
RC=$?
printf '%s' "$RBOUT" | grep -q 'E3_M3_ROLLBACK=PASS' \
    && pass 'rollback reports PASS (first-deploy inverse)' \
    || { FAIL=$((FAIL+1)); printf '  FAIL rollback (rc=%s):\n%s\n' "$RC" "$RBOUT"; }
if [ -f "$DECOY_UNITS/sbox-cm.socket" ] && [ -f "$DECOY_UNITS/sbox-cm.service" ]; then
    pass 'B3: ignored unit-dir override cannot retarget the destructive rollback (decoy intact)'
else
    fail 'B3: rollback followed the removed unit-dir override (decoy touched)'
fi
grep -qF "rollback $EXPECT_REL" "$SBOX_E3_M3_STUB_LOG" \
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

# rollback FAIL: missing installer (fail-closed, no silent pass). The reason is
# asserted so an unrelated fixture failure cannot satisfy this negative test.
MISS_OUT="$(E3_INSTALL_MONITOR="$EXECROOT/no-such-installer.sh" E3_RELEASES_DIR="$RELDIR" \
    bash "$ROLLBACK" --baseline "$BASELINE" 2>&1)"; MISS_RC=$?
if [ "$MISS_RC" -ne 0 ]; then
    pass 'rollback with a missing installer FAILS'
else
    fail 'rollback with a missing installer must FAIL'
fi
if printf '%s' "$MISS_OUT" | grep -qF 'R2 install-monitor.sh missing or not executable'; then
    pass 'missing-installer refusal names the executability gate (not another fixture failure)'
else
    fail 'missing-installer refusal did not name the executability gate'
fi

# rollback FAIL: baseline release id does not exist on disk (reason asserted).
jq '.monitor.release_id = "no-such-release"' "$BASELINE" > "$FIX/baseline-badrel.json"
BADREL_OUT="$(E3_INSTALL_MONITOR="$STUB_INSTALLER" E3_RELEASES_DIR="$RELDIR" \
    bash "$ROLLBACK" --baseline "$FIX/baseline-badrel.json" 2>&1)"; BADREL_RC=$?
if [ "$BADREL_RC" -ne 0 ]; then
    pass 'rollback with a nonexistent target release FAILS'
else
    fail 'rollback with a nonexistent target release must FAIL'
fi
if printf '%s' "$BADREL_OUT" | grep -qF 'R2 target release directory for [no-such-release] does not exist'; then
    pass 'nonexistent-release refusal names the missing release (not another fixture failure)'
else
    fail 'nonexistent-release refusal did not name the missing release'
fi

# rollback FAIL: the installer exists and is executable but refuses (exit 1).
# That is distinct from missing/not-executable and must be reported as such.
# The fresh protected marker proves the failing installer was really invoked.
FAILINST_LOG="$EVIDENCE_DIR/failing-installer.log"
rm -f "$FAILINST_LOG"
cat > "$FAIL_INSTALLER" <<'STUBFAIL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SBOX_E3_M3_STUB_LOG:-/dev/null}"
exit 1
STUBFAIL
chmod 0755 "$FAIL_INSTALLER"
FAILINST_OUT="$(E3_INSTALL_MONITOR="$FAIL_INSTALLER" E3_RELEASES_DIR="$RELDIR" \
    SBOX_E3_M3_STUB_LOG="$FAILINST_LOG" \
    bash "$ROLLBACK" --baseline "$BASELINE" 2>&1)"; FAILINST_RC=$?
if [ "$FAILINST_RC" -ne 0 ]; then
    pass 'rollback with an executable installer that fails FAILS'
else
    fail 'rollback with an executable installer that fails must FAIL'
fi
if printf '%s' "$FAILINST_OUT" | grep -qF "R2 install-monitor.sh rollback to [$EXPECT_REL] FAILED"; then
    pass 'failing-installer refusal reports the rollback-command failure (not the executability gate)'
else
    fail 'failing-installer refusal did not report the rollback-command failure'
fi
if grep -qxF "rollback $EXPECT_REL" "$FAILINST_LOG" 2>/dev/null; then
    pass 'failing installer really executed and received the R2 rollback argv'
else
    fail 'no independent marker proving the failing installer was executed'
fi

# rollback FAIL: an existing but NON-executable installer is refused by the
# executability gate itself -- the branch that used to fire accidentally on a
# noexec /run is now an intentional, deterministic discriminator.
NONEXEC_LOG="$EVIDENCE_DIR/nonexec-installer.log"
rm -f "$NONEXEC_LOG"
cp "$STUB_INSTALLER" "$NONEXEC_INSTALLER"
chmod 0644 "$NONEXEC_INSTALLER"
if [ -f "$NONEXEC_INSTALLER" ]; then
    pass 'non-executable installer case: the negative input file exists'
else
    fail 'non-executable installer case: the negative input file is missing'
fi
if [ -z "$(find "$NONEXEC_INSTALLER" -perm /111 -print -quit 2>/dev/null)" ]; then
    pass 'non-executable installer case: the input really carries no execute bits'
else
    fail 'non-executable installer case: the input still has execute bits'
fi
NX_OUT="$(E3_INSTALL_MONITOR="$NONEXEC_INSTALLER" E3_RELEASES_DIR="$RELDIR" \
    SBOX_E3_M3_STUB_LOG="$NONEXEC_LOG" \
    bash "$ROLLBACK" --baseline "$BASELINE" 2>&1)"; NX_RC=$?
if [ "$NX_RC" -ne 0 ]; then
    pass 'rollback with a non-executable installer FAILS (fail-closed)'
else
    fail 'rollback with a non-executable installer must FAIL'
fi
if printf '%s' "$NX_OUT" | grep -qF 'R2 install-monitor.sh missing or not executable'; then
    pass 'non-executable installer is refused by the executability gate'
else
    fail 'non-executable installer was not refused by the executability gate'
fi
if [ ! -e "$NONEXEC_LOG" ]; then
    pass 'non-executable installer was never executed (no marker created)'
else
    fail 'non-executable installer produced an execution marker'
fi

# A negative control is only valid when the injection stub really executed with
# the intended argv. Re-establish the real first-deploy fixture so R1 has units
# to manage (no unrelated "unit does not exist" failures), then give each case
# its own freshly written stub and its own root-private exact-argv marker.
reset_first_deploy_fixture() {
    systemctl stop sbox-cm.socket sbox-cm.service 2>/dev/null
    systemctl disable sbox-cm.socket sbox-cm.service 2>/dev/null
    rm -f /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service
    rm -rf -- /usr/local/lib/sbox-cm /var/lib/sbox-cm /run/sbox-cm
    systemctl daemon-reload 2>/dev/null
    "$ROOT/sbox-cm/deploy/install-sbox-cm.sh" install >/dev/null 2>&1
}

# rollback FAIL: a service-disable failure can never be a silent pass.
if ! reset_first_deploy_fixture; then
    fail 'RB2 setup: could not re-establish the real sbox-cm first-deploy fixture'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi
RB2_CTL="$EXECROOT/rb2-systemctl"
RB2_CTRL_LOG="$EVIDENCE_DIR/rb2-systemctl.log"
RB2_INST_LOG="$EVIDENCE_DIR/rb2-installer.log"
rm -f "$RB2_CTRL_LOG" "$RB2_INST_LOG"
cat > "$RB2_CTL" <<'STUBCTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SBOX_E3_M3_SYSTEMCTL_LOG:-/dev/null}"
if [ "${1:-}" = "disable" ]; then exit 1; fi
exec /usr/bin/systemctl "$@"
STUBCTL
chmod 0755 "$RB2_CTL"
RB2="$(E3_SYSTEMCTL="$RB2_CTL" E3_INSTALL_MONITOR="$STUB_INSTALLER" \
    E3_RELEASES_DIR="$RELDIR" SBOX_E3_M3_STUB_LOG="$RB2_INST_LOG" \
    SBOX_E3_M3_SYSTEMCTL_LOG="$RB2_CTRL_LOG" \
    bash "$ROLLBACK" --baseline "$BASELINE" 2>&1)"; RB2_RC=$?
if [ "$RB2_RC" -ne 0 ]; then
    pass 'service-disable case: rollback exited non-zero'
else
    fail 'service-disable case: rollback must exit non-zero'
fi
if printf '%s' "$RB2" | grep -q 'E3_M3_ROLLBACK=FAIL'; then
    pass 'a service-disable failure FAILS the rollback (never a silent pass)'
else
    fail 'a service-disable failure did not fail the rollback'
fi
if printf '%s' "$RB2" | grep -qF 'R1 disabling sbox-cm.socket FAILED'; then
    pass 'service-disable refusal names the failed disable (not another fixture failure)'
else
    fail 'service-disable refusal did not name the failed disable'
fi
if grep -qxF 'disable sbox-cm.socket' "$RB2_CTRL_LOG" 2>/dev/null; then
    pass 'service-disable case: the stub really received the disable argv'
else
    fail 'service-disable case: no independent marker for the disable argv (stub may not have executed)'
fi
if grep -qxF 'stop sbox-cm.socket' "$RB2_CTRL_LOG" 2>/dev/null; then
    pass 'service-disable case: the stub really executed and delegated a non-injected argv'
else
    fail 'service-disable case: the stub did not execute/delegate a non-injected argv'
fi
if printf '%s' "$RB2" | grep -qF "PASS R2 monitor release flipped back to [$EXPECT_REL]"; then
    pass 'service-disable case: R2 succeeded with the real installer invocation'
else
    fail 'service-disable case: R2 did not succeed'
fi
if grep -qF "rollback $EXPECT_REL" "$RB2_INST_LOG" 2>/dev/null; then
    pass 'service-disable case: the installer marker proves the R2 invocation'
else
    fail 'service-disable case: no installer execution marker for R2'
fi
if printf '%s' "$RB2" | grep -Eq 'FAIL R2|FAIL R3|FAIL R4'; then
    fail 'service-disable case: an unrelated R2/R3/R4 failure is present'
else
    pass 'service-disable case: only the injected R1 disable failure is present'
fi

# rollback FAIL: a daemon-reload failure can never be a silent pass.
if ! reset_first_deploy_fixture; then
    fail 'RB3 setup: could not re-establish the real sbox-cm first-deploy fixture'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M3_DEPLOY=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi
RB3_CTL="$EXECROOT/rb3-systemctl"
RB3_CTRL_LOG="$EVIDENCE_DIR/rb3-systemctl.log"
RB3_INST_LOG="$EVIDENCE_DIR/rb3-installer.log"
rm -f "$RB3_CTRL_LOG" "$RB3_INST_LOG"
cat > "$RB3_CTL" <<'STUBRL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SBOX_E3_M3_SYSTEMCTL_LOG:-/dev/null}"
if [ "${1:-}" = "daemon-reload" ]; then exit 1; fi
exec /usr/bin/systemctl "$@"
STUBRL
chmod 0755 "$RB3_CTL"
RB3="$(E3_SYSTEMCTL="$RB3_CTL" E3_INSTALL_MONITOR="$STUB_INSTALLER" \
    E3_RELEASES_DIR="$RELDIR" SBOX_E3_M3_STUB_LOG="$RB3_INST_LOG" \
    SBOX_E3_M3_SYSTEMCTL_LOG="$RB3_CTRL_LOG" \
    bash "$ROLLBACK" --baseline "$BASELINE" 2>&1)"; RB3_RC=$?
if [ "$RB3_RC" -ne 0 ]; then
    pass 'daemon-reload case: rollback exited non-zero'
else
    fail 'daemon-reload case: rollback must exit non-zero'
fi
if printf '%s' "$RB3" | grep -q 'E3_M3_ROLLBACK=FAIL'; then
    pass 'a daemon-reload failure FAILS the rollback (never a silent pass)'
else
    fail 'a daemon-reload failure did not fail the rollback'
fi
if printf '%s' "$RB3" | grep -qF 'R3 systemctl daemon-reload FAILED after removing the units'; then
    pass 'daemon-reload refusal names the failed reload (not another fixture failure)'
else
    fail 'daemon-reload refusal did not name the failed reload'
fi
if grep -qxF 'daemon-reload' "$RB3_CTRL_LOG" 2>/dev/null; then
    pass 'daemon-reload case: the stub really received the daemon-reload argv'
else
    fail 'daemon-reload case: no independent marker for the daemon-reload argv (stub may not have executed)'
fi
if grep -qxF 'stop sbox-cm.socket' "$RB3_CTRL_LOG" 2>/dev/null; then
    pass 'daemon-reload case: the stub really executed and delegated a non-injected argv'
else
    fail 'daemon-reload case: the stub did not execute/delegate a non-injected argv'
fi
if printf '%s' "$RB3" | grep -qF "PASS R2 monitor release flipped back to [$EXPECT_REL]"; then
    pass 'daemon-reload case: R2 succeeded with the real installer invocation'
else
    fail 'daemon-reload case: R2 did not succeed'
fi
if grep -qF "rollback $EXPECT_REL" "$RB3_INST_LOG" 2>/dev/null; then
    pass 'daemon-reload case: the installer marker proves the R2 invocation'
else
    fail 'daemon-reload case: no installer execution marker for R2'
fi
if printf '%s' "$RB3" | grep -Eq 'FAIL R1|FAIL R2|FAIL R4'; then
    fail 'daemon-reload case: an unrelated R1/R2/R4 failure is present'
else
    pass 'daemon-reload case: only the injected R3 daemon-reload failure is present'
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
grep -qF 'E3_SBXCM_SOCKET="${E3_SBXCM_SOCKET:-/run/sbox-cm/sbox-cm.sock}"' \
    "$ROOT/monitor-v2/deploy/e3-rollback.sh" \
    && pass 'B3: rollback mirrors the preflight default socket path' \
    || fail 'B3: rollback does not mirror the preflight default socket path'
grep -qE '^E3_SBXCM_UNIT_DIR=' "$ROOT/monitor-v2/deploy/e3-rollback.sh" \
    && fail 'B3: rollback still accepts a new unit-dir environment override' \
    || pass 'B3: rollback exposes no new unit-dir environment override'

TOTAL=$((PASS + FAIL + SKIP))
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
printf 'TOTAL=%d (expected %d)\n' "$TOTAL" "$EXPECTED_TOTAL"
if [ "$FAIL" -ne 0 ] || [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    printf 'E3_M3_DEPLOY=FAIL\n'
    exit 1
fi
printf 'E3_M3_DEPLOY=PASS\n'
