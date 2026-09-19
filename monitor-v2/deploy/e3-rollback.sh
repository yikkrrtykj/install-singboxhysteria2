#!/usr/bin/env bash
# e3-rollback.sh -- full rollback for the E3 M3 deploy-disabled rollout.
#
# FAIL-CLOSED orchestration (final review): every rollback step either
# succeeds or turns E3_M3_ROLLBACK into FAIL -- "no rollback performed" is
# never an acceptable outcome.
#
#   R1  close the privileged plane: stop + disable sbox-cm.socket FIRST (the
#       socket would restart the service on the next connection), then stop +
#       disable sbox-cm.service;
#   R2  restore the EXACT monitor release recorded in the preflight baseline
#       (monitor.release_id, taken from the live symlink at preflight time --
#       never re-guessed from releases.history). A --monitor-release argument
#       is an explicit operator override only. Missing installer / missing
#       target release / failed flip => FAIL. After the flip, the live
#       release id must equal the target id;
#   R3  restore the sbox-cm PRE-DEPLOYMENT state from baseline.helper:
#       * helper was fully absent -> uninstall THIS round's capability
#         (units + libexec). The state/audit tree is explicitly KEPT
#         (security audit trail) -- never silently purged;
#       * helper was present -> nothing is deleted and the original
#         active/enabled states are restored;
#       * a PARTIAL pre-state is unexpected and fails the rollback;
#   R4  verify: monitor answering read-only HTTP, sing-box config SHA256
#       IDENTICAL to the preflight baseline, activation marker absent;
#   R5  verify the sbox-cm state matches the baseline/target state for BOTH
#       units (active AND enabled -- not just the socket).
#
# The sing-box config and the sing-box service are NEVER touched.
#
# Output: E3_M3_ROLLBACK=PASS (exit 0) / E3_M3_ROLLBACK=FAIL (exit 1).
#
# Usage: e3-rollback.sh --baseline FILE [--monitor-release ID]
# Environment overrides: same as e3-preflight.sh, plus
#   E3_INSTALL_MONITOR  path to install-monitor.sh
#   E3_RELEASES_DIR     monitor releases dir
set -uo pipefail

E3_SYSTEMCTL="${E3_SYSTEMCTL:-systemctl}"
E3_CONFIG="${E3_CONFIG:-/root/sbox/sbconfig_server.json}"
E3_SBXCM_STATE="${E3_SBXCM_STATE:-/var/lib/sbox-cm}"
E3_SBXCM_LIBEXEC="${E3_SBXCM_LIBEXEC:-/usr/local/lib/sbox-cm}"
E3_SBXCM_SOCKET="${E3_SBXCM_SOCKET:-/run/sbox-cm/sbox-cm.sock}"
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_MONITOR_APP="${E3_MONITOR_APP:-/opt/singbox-monitor}"
E3_MONITOR_UNIT="${E3_MONITOR_UNIT:-singbox-monitor.service}"
E3_INSTALL_MONITOR="${E3_INSTALL_MONITOR:-/opt/singbox-monitor-releases/install-monitor.sh}"
E3_RELEASES_DIR="${E3_RELEASES_DIR:-/opt/singbox-monitor-releases}"
BASELINE=""; OVERRIDE_RELEASE=""

while (($# > 0)); do
    case "$1" in
        --baseline) BASELINE="${2:-}"; shift 2 ;;
        --monitor-release) OVERRIDE_RELEASE="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$BASELINE" ] && [ -f "$BASELINE" ] \
    || { printf 'a --baseline FILE from e3-preflight.sh is required\n' >&2; exit 2; }

BL="$(cat "$BASELINE")"
B_SHA="$(printf '%s' "$BL" | jq -r '.config_sha256 // empty')"
TARGET_RELEASE="$(printf '%s' "$BL" | jq -r '.monitor.release_id // empty')"
MON_UNIT="$E3_MONITOR_UNIT"

PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
jqv2(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

printf '===== E3 M3 ROLLBACK =====\n'

# R1: close the privileged plane (socket FIRST, then the service). A disable
# FAILURE must fail the rollback (final review: a disable failure can never
# be a silent pass).
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
if [ -f /etc/systemd/system/sbox-cm.socket ]; then
    EN1="$("$E3_SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)"
    if [ "$EN1" = "disabled" ]; then
        pass "R1 socket is disabled"
    else
        fail "R1 socket disable did not stick (is-enabled=[$EN1])"
    fi
fi
if [ -f /etc/systemd/system/sbox-cm.service ]; then
    EN2="$("$E3_SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)"
    if [ "$EN2" = "disabled" ]; then
        pass "R1 service is disabled"
    else
        fail "R1 service disable did not stick (is-enabled=[$EN2])"
    fi
fi

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

# R3: restore the sbox-cm PRE-DEPLOYMENT state from baseline.helper
PRE_LIBEXEC="$(printf '%s' "$BL" | jq -r '.helper.libexec_present // empty')"
PRE_SOCK_UNIT="$(printf '%s' "$BL" | jq -r '.helper.socket_unit_present // empty')"
PRE_SVC_UNIT="$(printf '%s' "$BL" | jq -r '.helper.service_unit_present // empty')"
PRE_STATE_DIR="$(printf '%s' "$BL" | jq -r '.helper.state_dir_present // empty')"
PRE_SOCK_ACTIVE="$(printf '%s' "$BL" | jq -r '.helper.socket_active // empty')"
PRE_SOCK_ENABLED="$(printf '%s' "$BL" | jq -r '.helper.socket_enabled // empty')"
PRE_SVC_ACTIVE="$(printf '%s' "$BL" | jq -r '.helper.service_active // empty')"
PRE_SVC_ENABLED="$(printf '%s' "$BL" | jq -r '.helper.service_enabled // empty')"

# baseline stores JSON booleans (true/false); classify with that in mind
PRE_LIBEXEC_T="no"; [ "$PRE_LIBEXEC" = "true" ] && PRE_LIBEXEC_T="yes"
PRE_SOCK_UNIT_T="no"; [ "$PRE_SOCK_UNIT" = "true" ] && PRE_SOCK_UNIT_T="yes"
PRE_SVC_UNIT_T="no"; [ "$PRE_SVC_UNIT" = "true" ] && PRE_SVC_UNIT_T="yes"

HELPER_WAS_ABSENT="no"
if [ "$PRE_SOCK_UNIT_T" = "no" ] && [ "$PRE_SVC_UNIT_T" = "no" ] \
        && [ "$PRE_LIBEXEC_T" = "no" ]; then
    HELPER_WAS_ABSENT="yes"
fi
HELPER_WAS_PRESENT="no"
if [ "$PRE_SOCK_UNIT_T" = "yes" ] && [ "$PRE_SVC_UNIT_T" = "yes" ] \
        && [ "$PRE_LIBEXEC_T" = "yes" ]; then
    HELPER_WAS_PRESENT="yes"
fi

if [ "$HELPER_WAS_ABSENT" = "yes" ]; then
    # The helper did not exist before this deployment: uninstall THIS round's
    # capability (units + libexec). POLICY (explicit, not silent): the
    # sbox-cm state/audit tree under $E3_SBXCM_STATE is KEPT -- the audit
    # trail belongs to the security record and is never purged by a
    # rollback.
    rm -f /etc/systemd/system/sbox-cm.socket /etc/systemd/system/sbox-cm.service
    "$E3_SYSTEMCTL" daemon-reload 2>/dev/null
    rm -rf -- "$E3_SBXCM_LIBEXEC"
    if [ ! -e /etc/systemd/system/sbox-cm.socket ] \
            && [ ! -e /etc/systemd/system/sbox-cm.service ] \
            && [ ! -e "$E3_SBXCM_LIBEXEC/sbox-cm" ]; then
        pass "R3 helper was ABSENT before: capability uninstalled (units + libexec removed; state/audit tree KEPT by policy)"
    else
        fail "R3 helper uninstall incomplete"
    fi
elif [ "$HELPER_WAS_PRESENT" = "yes" ]; then
    # Restore the original active/enabled states -- nothing is deleted.
    if [ "$PRE_SOCK_ACTIVE" = "active" ]; then
        "$E3_SYSTEMCTL" start sbox-cm.socket 2>/dev/null
    else
        "$E3_SYSTEMCTL" stop sbox-cm.socket 2>/dev/null
    fi
    [ "$PRE_SOCK_ENABLED" = "enabled" ] \
        && "$E3_SYSTEMCTL" enable sbox-cm.socket 2>/dev/null \
        || "$E3_SYSTEMCTL" disable sbox-cm.socket 2>/dev/null
    if [ "$PRE_SVC_ACTIVE" = "active" ]; then
        "$E3_SYSTEMCTL" start sbox-cm.service 2>/dev/null
    else
        "$E3_SYSTEMCTL" stop sbox-cm.service 2>/dev/null
    fi
    [ "$PRE_SVC_ENABLED" = "enabled" ] \
        && "$E3_SYSTEMCTL" enable sbox-cm.service 2>/dev/null \
        || "$E3_SYSTEMCTL" disable sbox-cm.service 2>/dev/null
    pass "R3 helper was PRESENT before: original units kept, active/enabled states restored"
else
    fail "R3 PARTIAL helper pre-state (libexec=$PRE_LIBEXEC socket_unit=$PRE_SOCK_UNIT service_unit=$PRE_SVC_UNIT) -- cannot roll back safely"
fi

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

# R5-final: BOTH units must match the baseline/target states (active AND
# enabled) -- checking only the socket is not enough.
if [ "$HELPER_WAS_ABSENT" = "yes" ]; then
    WANT_SOCK_ACTIVE="inactive"; WANT_SOCK_ENABLED="not-installed"
    WANT_SVC_ACTIVE="inactive";  WANT_SVC_ENABLED="not-installed"
else
    WANT_SOCK_ACTIVE="$PRE_SOCK_ACTIVE"; WANT_SOCK_ENABLED="$PRE_SOCK_ENABLED"
    WANT_SVC_ACTIVE="$PRE_SVC_ACTIVE";   WANT_SVC_ENABLED="$PRE_SVC_ENABLED"
fi
GOT_SOCK_ACTIVE="$("$E3_SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)"
GOT_SOCK_ENABLED="$("$E3_SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)"
GOT_SVC_ACTIVE="$("$E3_SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)"
GOT_SVC_ENABLED="$("$E3_SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)"
if [ "$HELPER_WAS_ABSENT" = "yes" ]; then
    if [ ! -e /etc/systemd/system/sbox-cm.socket ] \
            && [ ! -e /etc/systemd/system/sbox-cm.service ]; then
        pass "R5-final helper restored to the ABSENT pre-state (units gone)"
    else
        fail "R5-final helper units still present after the absent-restore"
    fi
else
    if [ "$GOT_SOCK_ACTIVE" = "$WANT_SOCK_ACTIVE" ] \
            && [ "$GOT_SOCK_ENABLED" = "$WANT_SOCK_ENABLED" ]; then
        pass "R5-final socket active/enabled match the baseline ($GOT_SOCK_ACTIVE/$GOT_SOCK_ENABLED)"
    else
        fail "R5-final socket state mismatch (want $WANT_SOCK_ACTIVE/$WANT_SOCK_ENABLED, got $GOT_SOCK_ACTIVE/$GOT_SOCK_ENABLED)"
    fi
    if [ "$GOT_SVC_ACTIVE" = "$WANT_SVC_ACTIVE" ] \
            && [ "$GOT_SVC_ENABLED" = "$WANT_SVC_ENABLED" ]; then
        pass "R5-final service active/enabled match the baseline ($GOT_SVC_ACTIVE/$GOT_SVC_ENABLED)"
    else
        fail "R5-final service state mismatch (want $WANT_SVC_ACTIVE/$WANT_SVC_ENABLED, got $GOT_SVC_ACTIVE/$GOT_SVC_ENABLED)"
    fi
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M3_ROLLBACK=FAIL\n'
    exit 1
fi
printf 'E3_M3_ROLLBACK=PASS\n'
