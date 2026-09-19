#!/usr/bin/env bash
# e3-rollback.sh -- full rollback for the E3 M3 deploy-disabled rollout.
#
# M3-B v1 IS FIRST-DEPLOY-ONLY: the preflight guarantees the helper did not
# exist before this deployment, so the rollback is the exact inverse of ONE
# install:
#   R1  close the privileged plane: stop + disable sbox-cm.socket FIRST (the
#       socket would restart the service on the next connection), then stop +
#       disable sbox-cm.service. A disable failure FAILS the rollback;
#   R2  restore the EXACT monitor release recorded in the preflight baseline
#       (monitor.release_id, taken from the live symlink at preflight time --
#       the ONLY rollback target; there is NO override). Missing installer /
#       missing target release / failed flip / a live release id that does
#       not match afterwards => FAIL;
#   R3  uninstall THIS round's sbox-cm capability (unit files + the whole
#       libexec tree) and verify all six capability paths are gone. POLICY
#       (explicit, never silent): the /var/lib/sbox-cm state/audit tree is
#       KEPT -- the audit trail belongs to the security record and is not
#       purged by a rollback;
#   R4  verify: monitor answering read-only HTTP, sing-box config SHA256
#       IDENTICAL to the preflight baseline, activation marker absent.
#
# The sing-box config and the sing-box service are NEVER touched.
#
# Output: E3_M3_ROLLBACK=PASS (exit 0) / E3_M3_ROLLBACK=FAIL (exit 1).
#
# Usage: e3-rollback.sh --baseline FILE
# (there is deliberately NO --monitor-release override: the target comes
# exclusively from baseline.monitor.release_id)
# Environment overrides: same as e3-preflight.sh, plus
#   E3_INSTALL_MONITOR  path to install-monitor.sh
#   E3_RELEASES_DIR     monitor releases dir
set -uo pipefail

E3_SYSTEMCTL="${E3_SYSTEMCTL:-systemctl}"
E3_CONFIG="${E3_CONFIG:-/root/sbox/sbconfig_server.json}"
E3_SBXCM_STATE="${E3_SBXCM_STATE:-/var/lib/sbox-cm}"
E3_SBXCM_LIBEXEC="${E3_SBXCM_LIBEXEC:-/usr/local/lib/sbox-cm}"
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_MONITOR_APP="${E3_MONITOR_APP:-/opt/singbox-monitor}"
E3_MONITOR_UNIT="${E3_MONITOR_UNIT:-singbox-monitor.service}"
E3_INSTALL_MONITOR="${E3_INSTALL_MONITOR:-/opt/singbox-monitor-releases/install-monitor.sh}"
E3_RELEASES_DIR="${E3_RELEASES_DIR:-/opt/singbox-monitor-releases}"
BASELINE=""

while (($# > 0)); do
    case "$1" in
        --baseline) BASELINE="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$BASELINE" ] && [ -f "$BASELINE" ] \
    || { printf 'a --baseline FILE from e3-preflight.sh is required\n' >&2; exit 2; }

BL="$(cat "$BASELINE")"
B_SHA="$(printf '%s' "$BL" | jq -r '.config_sha256 // empty')"
TARGET_RELEASE="$(printf '%s' "$BL" | jq -r '.monitor.release_id // empty')"

PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }

printf '===== E3 M3 ROLLBACK =====\n'

# R1: close the privileged plane (socket FIRST, then the service). A disable
# failure must fail the rollback (never a silent pass).
"$E3_SYSTEMCTL" stop sbox-cm.socket 2>/dev/null
if ! "$E3_SYSTEMCTL" disable sbox-cm.socket >/dev/null 2>&1; then
    fail "R1 disabling sbox-cm.socket FAILED"
fi
"$E3_SYSTEMCTL" stop sbox-cm.service 2>/dev/null
if ! "$E3_SYSTEMCTL" disable sbox-cm.service >/dev/null 2>&1; then
    fail "R1 disabling sbox-cm.service FAILED"
fi
SOCK_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)"
SVC_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)"
if [ "$SOCK_STATE" = "inactive" ] && [ "$SVC_STATE" = "inactive" ]; then
    pass "R1 privileged plane closed (socket+service stopped)"
else
    fail "R1 privileged plane not fully closed (socket=[$SOCK_STATE] service=[$SVC_STATE])"
fi
for unit in sbox-cm.socket sbox-cm.service; do
    if [ -f "/etc/systemd/system/$unit" ]; then
        EN="$("$E3_SYSTEMCTL" is-enabled "$unit" 2>/dev/null || true)"
        if [ "$EN" = "disabled" ]; then
            pass "R1 $unit is disabled"
        else
            fail "R1 $unit disable did not stick (is-enabled=[$EN])"
        fi
    fi
done

# R2: restore the EXACT monitor release from the baseline (fail-closed)
if [ -z "$TARGET_RELEASE" ]; then
    fail "R2 the baseline carries NO monitor.release_id -- refusing to guess a rollback target"
elif [ ! -f "$E3_INSTALL_MONITOR" ]; then
    fail "R2 install-monitor.sh missing at $E3_INSTALL_MONITOR -- cannot restore release [$TARGET_RELEASE]"
elif [ ! -d "$E3_RELEASES_DIR/$TARGET_RELEASE" ] \
        && [ ! -d "$(dirname "$E3_MONITOR_APP")/$TARGET_RELEASE" ]; then
    fail "R2 target release directory for [$TARGET_RELEASE] does not exist"
else
    if "$E3_INSTALL_MONITOR" rollback "$TARGET_RELEASE" >/dev/null 2>&1; then
        pass "R2 monitor release flipped back to [$TARGET_RELEASE]"
    else
        fail "R2 install-monitor.sh rollback to [$TARGET_RELEASE] FAILED"
    fi
fi
NOW_RELEASE_ID="$(basename "$(readlink -f "$E3_MONITOR_APP" 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$TARGET_RELEASE" ] && [ "$NOW_RELEASE_ID" = "$TARGET_RELEASE" ]; then
    pass "R2-final live monitor release id == baseline release id [$TARGET_RELEASE]"
else
    fail "R2-final live monitor release id [$NOW_RELEASE_ID] != baseline [$TARGET_RELEASE]"
fi

# R3: uninstall THIS round's sbox-cm capability (the preflight guaranteed it
# did not exist before this deployment). The state/audit tree is KEPT.
rm -f /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service
"$E3_SYSTEMCTL" daemon-reload 2>/dev/null
rm -rf -- "$E3_SBXCM_LIBEXEC"
CAP_GONE="yes"
for f in "$E3_SBXCM_LIBEXEC/sbox-cm" "$E3_SBXCM_LIBEXEC/sbox-cm-ops" \
         "$E3_SBXCM_LIBEXEC/lib/client-management.sh" \
         "$E3_SBXCM_LIBEXEC/lib/sbox-cm-state.sh" \
         /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service \
         "$E3_SBXCM_SOCKET"; do
    [ -e "$f" ] && { CAP_GONE="no"; fail "R3 capability path still present: $f"; }
done
if [ "$CAP_GONE" = "yes" ]; then
    pass "R3 capability uninstalled: all unit files, libexec binaries and lib scripts are gone (socket file included)"
fi
[ -d "$E3_SBXCM_STATE" ] \
    && pass "R3 state/audit tree KEPT by policy (never silently purged)" \
    || fail "R3 the state/audit tree vanished (must be kept)"

# R4: post-rollback verification
MON_OK="no"
for _ in $(seq 1 24); do
    CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "$E3_MONITOR_URL/api/v1/session" 2>/dev/null || true)"
    [ "$CODE" = "200" ] && { MON_OK="yes"; break; }
    sleep 0.5
done
if [ "$MON_OK" = "yes" ]; then
    pass "R4 monitor answers read-only HTTP after rollback"
else
    fail "R4 monitor did not come back after rollback"
fi

NOW_SHA="$(sha256sum "$E3_CONFIG" 2>/dev/null | awk '{print $1}')"
if [ -n "$NOW_SHA" ] && [ "$NOW_SHA" = "$B_SHA" ]; then
    pass "R4 sing-box config SHA256 identical to the preflight baseline (config never touched)"
else
    fail "R4 config SHA256 differs from the baseline (baseline=[$B_SHA] now=[$NOW_SHA])"
fi

if [ ! -e "$E3_SBXCM_STATE/management.active" ]; then
    pass "R4 activation marker absent (plane stays closed through the rollback)"
else
    fail "R4 activation marker EXISTS after rollback"
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M3_ROLLBACK=FAIL\n'
    exit 1
fi
printf 'E3_M3_ROLLBACK=PASS\n'
