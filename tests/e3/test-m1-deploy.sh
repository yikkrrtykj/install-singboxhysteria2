#!/usr/bin/env bash
# E3 M1 -- deployment contract: install converges but NEVER activates; enable
# and disable are explicit; disabling must close BOTH the socket and the
# service (stopping the service alone leaves the socket able to restart it);
# uninstall keeps the runtime state unless --purge-state is given.
#
# Runs against a temporary prefix with a recording systemctl stub: no root, no
# real systemd, no sing-box.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
ok(){ [ "$1" = "0" ] && pass "$2" || fail "$2"; }
no(){ [ "$1" != "0" ] && pass "$2" || fail "$2"; }
# Run a deploy command and surface its captured output when it fails, so a CI
# failure is attributable instead of a bare rc.
run_deploy(){ # <outfile> <args...>
    local out="$1"; shift
    "$INSTALLER" "$@" >"$out" 2>&1
    local rc=$?
    if [ "$rc" != "0" ]; then
        printf '  NOTE %s rc=%s:\n' "$*" "$rc"
        sed 's/^/    | /' "$out"
    fi
    return "$rc"
}

printf '===== E3 M1 DEPLOY =====\n'

if ! command -v install >/dev/null 2>&1; then
    skip 'coreutils install unavailable'
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_DEPLOY=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi

PREFIX="$TMP/root"
UNIT_IN="$TMP/units"
STATE="$TMP/state"
SYSTEMCTL_LOG="$TMP/systemctl.log"
DAEMON_LOG="$TMP/daemon.log"
mkdir -p "$PREFIX" "$UNIT_IN"

SHIM="$TMP/shim"
mkdir -p "$SHIM"
cat > "$SHIM/systemctl" <<SHIMEOF
#!/usr/bin/env bash
case "\$1" in
    is-enabled) printf '%s\n' "\${MOCK_ENABLED:-enabled}"; exit 0 ;;
    is-active)  printf '%s\n' "\${MOCK_ACTIVE:-active}"; exit 0 ;;
esac
printf '%s\n' "\$*" >> "$SYSTEMCTL_LOG"
exit 0
SHIMEOF
chmod +x "$SHIM/systemctl"

export SBXCM_PREFIX="$PREFIX"
export SBXCM_LIBEXEC="/usr/local/lib/sbox-cm"
export SBXCM_UNIT_DIR="/etc/systemd/system"
export SBXCM_SYSTEMCTL="$SHIM/systemctl"
export SBXCM_GROUP="sboxweb"
export SB_CM_STATE_DIR="$STATE"

LIBEXEC="$PREFIX/usr/local/lib/sbox-cm"
UNITS="$PREFIX/etc/systemd/system"
: > "$SYSTEMCTL_LOG"

# ------------------------------------------------------------------ install ----
printf '\n== install converges without activating ==\n'
run_deploy "$TMP/install.out" install
ok $? 'install exits 0'
[ -f "$LIBEXEC/sbox-cm" ] && pass 'daemon staged' || fail 'daemon missing'
[ -f "$LIBEXEC/sbox-cm-ops" ] && pass 'worker staged' || fail 'worker missing'
[ -f "$LIBEXEC/lib/client-management.sh" ] && pass 'transaction library staged' \
    || fail 'transaction library missing'
[ -f "$LIBEXEC/lib/sbox-cm-state.sh" ] && pass 'state library staged' || fail 'state library missing'
[ -f "$UNITS/sbox-cm.socket" ] && pass 'socket unit staged' || fail 'socket unit missing'
[ -f "$UNITS/sbox-cm.service" ] && pass 'service unit staged' || fail 'service unit missing'
[ -d "$STATE" ] && pass 'runtime state directory created' || fail 'state directory missing'

if grep -q 'SocketGroup=sboxweb' "$UNITS/sbox-cm.socket"; then
    pass 'socket group placeholder was rendered'
else
    fail 'socket group placeholder not rendered'
fi
if grep -q '@SBXCM' "$UNITS/sbox-cm.socket" "$UNITS/sbox-cm.service"; then
    fail 'unrendered @SBXCM placeholder left in a unit'
else
    pass 'no unrendered placeholders remain'
fi
if grep -qE '(^| )(enable|start)( |$)' "$SYSTEMCTL_LOG"; then
    fail 'install implicitly enabled/started a unit'
else
    pass 'install never enables or starts a unit (default safe state)'
fi

# ------------------------------------------------------------------- enable ----
printf '\n== enable opens the channel explicitly (socket activation) ==\n'
: > "$SYSTEMCTL_LOG"
"$INSTALLER" enable >"$TMP/enable.out" 2>&1
ok $? 'enable exits 0'
if grep -qxF 'enable --now sbox-cm.socket' "$SYSTEMCTL_LOG"; then
    pass 'enable --now targets the socket unit'
else
    fail "enable did not target the socket: $(tr '\n' ';' < "$SYSTEMCTL_LOG")"
fi
if grep -qF 'sbox-cm.service' "$SYSTEMCTL_LOG"; then
    fail 'enable touched the service unit (service must be socket-activated only)'
else
    pass 'enable never enables the service independently'
fi

# ------------------------------------------------------------------ disable ----
printf '\n== disable closes BOTH socket and service ==\n'
: > "$SYSTEMCTL_LOG"
"$INSTALLER" disable >"$TMP/disable.out" 2>&1
ok $? 'disable exits 0'
for want in 'stop sbox-cm.socket' 'disable sbox-cm.socket' 'stop sbox-cm.service' 'disable sbox-cm.service'; do
    grep -qxF "$want" "$SYSTEMCTL_LOG" && pass "disable issued: $want" || fail "missing: $want"
done
first_stop="$(grep -n 'stop ' "$SYSTEMCTL_LOG" | head -n1)"
case "$first_stop" in
    *sbox-cm.socket*) pass 'the socket is stopped before the service (no re-activation window)' ;;
    *) fail "first stop is not the socket: $first_stop" ;;
esac

printf '\n== disable skips the service disable when it is not enabled ==\n'
: > "$SYSTEMCTL_LOG"
MOCK_ENABLED=disabled "$INSTALLER" disable >"$TMP/disable2.out" 2>&1
ok $? 'disable exits 0 when the service was never enabled'
if grep -qxF 'disable sbox-cm.service' "$SYSTEMCTL_LOG"; then
    fail 'disable attempted to disable a non-enabled service'
else
    pass 'disable does not touch a service that was never enabled'
fi
for want in 'stop sbox-cm.socket' 'stop sbox-cm.service' 'disable sbox-cm.socket'; do
    grep -qxF "$want" "$SYSTEMCTL_LOG" && pass "disable still issued: $want" || fail "missing: $want"
done

# ------------------------------------------------------------------ recover ----
printf '\n== recover uses the root CLI, never a manual rm ==\n'
# Replace the staged daemon with a recorder so the CLI verb is observable.
cat > "$LIBEXEC/sbox-cm" <<DAEMONEOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$DAEMON_LOG"
exit 0
DAEMONEOF
chmod +x "$LIBEXEC/sbox-cm"
: > "$DAEMON_LOG"
"$INSTALLER" recover >"$TMP/recover.out" 2>&1
ok $? 'recover exits 0'
if grep -qxF 'mgmt-deactivate' "$DAEMON_LOG"; then
    pass 'recover delegates to sbox-cm mgmt-deactivate'
else
    fail "recover did not call mgmt-deactivate: $(tr '\n' ';' < "$DAEMON_LOG")"
fi
if grep -qE 'rm .*management\.active' "$INSTALLER"; then
    fail 'installer deletes the marker file directly (forbidden)'
else
    pass 'installer never hand-deletes the activation marker'
fi

# ------------------------------------------------------------------ status ----
# The deploy CLI status (and the RPC management.status alike) is strictly
# read-only: reconciliation happens exactly once in the daemon's STARTUP path,
# never as a side effect of a status report.
printf '\n== deploy CLI status is strictly read-only ==\n'
: > "$DAEMON_LOG"
"$INSTALLER" status >"$TMP/status.out" 2>&1
ok $? 'status exits 0'
grep -qF "$LIBEXEC" "$TMP/status.out" && pass 'status prints the libexec path' || fail 'libexec path missing'
grep -qF 'sbox-cm.socket' "$TMP/status.out" && pass 'status prints the socket unit' || fail 'socket unit missing'
grep -qF 'reconcile' "$TMP/status.out" && pass 'status reports the durable reconcile state' \
    || fail 'status does not report the reconcile state'
if [ -s "$DAEMON_LOG" ]; then
    fail "status invoked the daemon: $(tr '\n' ';' < "$DAEMON_LOG")"
else
    pass 'status never invokes the daemon (no reconcile, no repair)'
fi

# ---------------------------------------------------------------- uninstall ----
printf '\n== uninstall disables and preserves runtime state ==\n'
: > "$SYSTEMCTL_LOG"
"$INSTALLER" uninstall >"$TMP/uninstall.out" 2>&1
ok $? 'uninstall exits 0'
[ -e "$UNITS/sbox-cm.socket" ] && fail 'socket unit left behind' || pass 'socket unit removed'
[ -e "$UNITS/sbox-cm.service" ] && fail 'service unit left behind' || pass 'service unit removed'
[ -e "$LIBEXEC" ] && fail 'libexec tree left behind' || pass 'libexec tree removed'
[ -d "$STATE" ] && pass 'runtime state preserved (no --purge-state)' || fail 'state directory was removed'

"$INSTALLER" install >/dev/null 2>&1
printf 'sentinel\n' > "$STATE/ledger-marker"
"$INSTALLER" uninstall --purge-state >/dev/null 2>&1
[ -e "$STATE" ] && fail '--purge-state did not remove the state directory' \
    || pass '--purge-state removes the state directory'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_DEPLOY=FAIL\n'; exit 1; }
printf 'E3_M1_DEPLOY=PASS\n'
