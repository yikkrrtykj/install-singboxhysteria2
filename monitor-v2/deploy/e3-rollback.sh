#!/usr/bin/env bash
# e3-rollback.sh -- full rollback for the E3 M3 deploy-disabled rollout.
#
# Ordered, minimal, and config-blind:
#   R1  close the privileged plane: stop + disable sbox-cm.socket FIRST (the
#       socket would restart the service on the next connection), then stop +
#       disable sbox-cm.service (the M0.5/M1 disable contract);
#   R2  restore the previous monitor release via the EXISTING packaging
#       rollback (`install-monitor.sh rollback [release-id]` -- symlink flip +
#       monitor restart only); when no explicit id is given, the most recent
#       previous release from releases.history is used;
#   R3  verify: monitor answering read-only HTTP, sing-box config SHA256
#       IDENTICAL to the preflight baseline, activation marker absent,
#       sbox-cm units stopped and disabled;
#   the sing-box config and the sing-box service are NEVER touched.
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
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_INSTALL_MONITOR="${E3_INSTALL_MONITOR:-/opt/singbox-monitor-releases/install-monitor.sh}"
E3_RELEASES_DIR="${E3_RELEASES_DIR:-/opt/singbox-monitor-releases}"
BASELINE=""; ROLLBACK_RELEASE=""

while (($# > 0)); do
    case "$1" in
        --baseline) BASELINE="${2:-}"; shift 2 ;;
        --monitor-release) ROLLBACK_RELEASE="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$BASELINE" ] && [ -f "$BASELINE" ] \
    || { printf 'a --baseline FILE from e3-preflight.sh is required\n' >&2; exit 2; }

PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

printf '===== E3 M3 ROLLBACK =====\n'

# R1: close the privileged plane (socket FIRST, then the service)
"$E3_SYSTEMCTL" stop sbox-cm.socket 2>/dev/null
"$E3_SYSTEMCTL" disable sbox-cm.socket 2>/dev/null
"$E3_SYSTEMCTL" stop sbox-cm.service 2>/dev/null
"$E3_SYSTEMCTL" disable sbox-cm.service 2>/dev/null
SOCK_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)"
SVC_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)"
SOCK_EN="$("$E3_SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)"
if [ "$SOCK_STATE" = "inactive" ] && [ "$SVC_STATE" = "inactive" ] \
        && [ "$SOCK_EN" = "disabled" ]; then
    pass "R1 privileged plane closed (socket+service stopped, socket disabled)"
else
    fail "R1 privileged plane not fully closed (socket=[$SOCK_STATE] service=[$SVC_STATE] enabled=[$SOCK_EN])"
fi

# R2: restore the previous monitor release (packaging rollback: symlink flip
# + monitor restart ONLY -- never a sing-box touch)
if [ -z "$ROLLBACK_RELEASE" ] && [ -f "$E3_RELEASES_DIR/releases.history" ]; then
    # most recent PREVIOUS release from the history file (newest first)
    ROLLBACK_RELEASE="$(grep -oE '^[^|]+' "$E3_RELEASES_DIR/releases.history" \
        | sed 's/[[:space:]]*$//' | awk 'NR==2{print}' | tail -1)"
fi
if [ -n "$ROLLBACK_RELEASE" ] && [ -f "$E3_INSTALL_MONITOR" ]; then
    if "$E3_INSTALL_MONITOR" rollback "$ROLLBACK_RELEASE" >/dev/null 2>&1; then
        pass "R2 monitor release rolled back to [$ROLLBACK_RELEASE]"
    else
        fail "R2 install-monitor.sh rollback to [$ROLLBACK_RELEASE] failed"
    fi
else
    note "R2 no monitor release rollback performed (no id given or installer missing) -- operator keeps the current release"
fi

# R3: post-rollback verification
MON_OK="no"
for _ in $(seq 1 24); do
    CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "$E3_MONITOR_URL/api/v1/session" 2>/dev/null || true)"
    [ "$CODE" = "200" ] && { MON_OK="yes"; break; }
    sleep 0.5
done
if [ "$MON_OK" = "yes" ]; then
    pass "R3 monitor answers read-only HTTP after rollback"
else
    fail "R3 monitor did not come back after rollback"
fi

NOW_SHA="$(sha256sum "$E3_CONFIG" 2>/dev/null | awk '{print $1}')"
B_SHA="$(jqv "$(cat "$BASELINE")" '.config_sha256')"
if [ -n "$NOW_SHA" ] && [ "$NOW_SHA" = "$B_SHA" ]; then
    pass "R4 sing-box config SHA256 identical to the preflight baseline (config never touched)"
else
    fail "R4 config SHA256 differs from the baseline (baseline=[$B_SHA] now=[$NOW_SHA])"
fi

if [ ! -e "$E3_SBXCM_STATE/management.active" ]; then
    pass "R5 activation marker absent (plane stays closed through the rollback)"
else
    fail "R5 activation marker EXISTS after rollback"
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_M3_ROLLBACK=FAIL\n'
    exit 1
fi
printf 'E3_M3_ROLLBACK=PASS\n'
