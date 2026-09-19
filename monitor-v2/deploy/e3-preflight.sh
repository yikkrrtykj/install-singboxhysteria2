#!/usr/bin/env bash
# e3-preflight.sh -- READ-ONLY production preflight for the E3 M3 deployment.
#
# M3-B v1 IS FIRST-DEPLOY-ONLY (final review freeze): this preflight FAILS
# when ANY sbox-cm capability already exists -- an existing deployment
# requires a separately reviewed upgrade path. "Absent" means ALL of:
#   sbox-cm, sbox-cm-ops, lib/client-management.sh, lib/sbox-cm-state.sh,
#   the socket unit and the service unit. A leftover /var/lib/sbox-cm
#   state/audit tree alone is tolerated (audit trail), provided the
#   activation marker is absent and owner/group/mode are safe.
#
# Read-only guarantees: no config writes, no reload/restart, no marker
# write, no activate, no client create/delete. The ONLY file written is the
# baseline JSON, and ONLY when every check passes: atomic (same-directory
# mktemp -> write -> chmod 0600 -> verify -> mv) so a failed write can never
# overwrite an existing baseline.
#
# Output: one PASS/FAIL line per check, then
#     E3_PREFLIGHT=PASS (exit 0) / E3_PREFLIGHT=FAIL (exit 1).
#
# Environment overrides (tests; production uses the defaults):
#   E3_SYSTEMCTL       systemctl binary          (default: systemctl)
#   E3_CONFIG          sing-box server config    (default: /root/sbox/sbconfig_server.json)
#   E3_SING_BOX_BIN    sing-box binary           (default: /root/sbox/sing-box)
#   E3_SBXCM_STATE     sbox-cm state dir         (default: /var/lib/sbox-cm)
#   E3_SBXCM_LIBEXEC   sbox-cm libexec dir       (default: /usr/local/lib/sbox-cm)
#   E3_SBXCM_SOCKET    sbox-cm socket path       (default: /run/sbox-cm/sbox-cm.sock)
#   E3_MONITOR_URL     monitor base URL          (default: http://127.0.0.1:9191)
#   E3_MONITOR_APP     monitor app link          (default: /opt/singbox-monitor, MUST be a symlink)
#   E3_MONITOR_UNIT    monitor unit name         (default: singbox-monitor.service)
#   E3_DISK_MIN_MB     min free MB on / and /var (default: 1024)
set -uo pipefail

E3_SYSTEMCTL="${E3_SYSTEMCTL:-systemctl}"
E3_CONFIG="${E3_CONFIG:-/root/sbox/sbconfig_server.json}"
E3_SING_BOX_BIN="${E3_SING_BOX_BIN:-/root/sbox/sing-box}"
E3_SBXCM_STATE="${E3_SBXCM_STATE:-/var/lib/sbox-cm}"
E3_SBXCM_LIBEXEC="${E3_SBXCM_LIBEXEC:-/usr/local/lib/sbox-cm}"
E3_SBXCM_SOCKET="${E3_SBXCM_SOCKET:-/run/sbox-cm/sbox-cm.sock}"
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_MONITOR_APP="${E3_MONITOR_APP:-/opt/singbox-monitor}"
E3_MONITOR_UNIT="${E3_MONITOR_UNIT:-singbox-monitor.service}"
E3_DISK_MIN_MB="${E3_DISK_MIN_MB:-1024}"
BASELINE_OUT=""

while (($# > 0)); do
    case "$1" in
        --baseline-out) BASELINE_OUT="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
note(){ printf '  INFO %s\n' "$*"; }

printf '===== E3 M3 PRODUCTION PREFLIGHT (read-only) =====\n'

# ------------------------------------------- P00 helper capability ABSENT --
# M3-B v1 is FIRST-DEPLOY-ONLY: any existing sbox-cm capability (binaries,
# lib scripts, unit files) means an upgrade path is needed and this
# preflight refuses to green-light a fresh deploy.
CAP_PRESENT=""
[ -e "$E3_SBXCM_LIBEXEC/sbox-cm" ] && CAP_PRESENT="$CAP_PRESENT sbox-cm"
[ -e "$E3_SBXCM_LIBEXEC/sbox-cm-ops" ] && CAP_PRESENT="$CAP_PRESENT sbox-cm-ops"
[ -e "$E3_SBXCM_LIBEXEC/lib/client-management.sh" ] \
    && CAP_PRESENT="$CAP_PRESENT lib/client-management.sh"
[ -e "$E3_SBXCM_LIBEXEC/lib/sbox-cm-state.sh" ] \
    && CAP_PRESENT="$CAP_PRESENT lib/sbox-cm-state.sh"
[ -e /etc/systemd/system/sbox-cm.socket ] && CAP_PRESENT="$CAP_PRESENT socket-unit"
[ -e /etc/systemd/system/sbox-cm.service ] && CAP_PRESENT="$CAP_PRESENT service-unit"
if [ -z "$CAP_PRESENT" ]; then
    pass "P00 no sbox-cm capability present (clean first-deploy precondition)"
else
    fail "P00 existing sbox-cm deployment requires a separately reviewed upgrade path (found:$CAP_PRESENT)"
fi

# ------------------------------------------------- P01 monitor release link --
# The monitor MUST be deployed as the packaging release symlink: the preflight
# baseline freezes the exact rollback target from it.
if [ -L "$E3_MONITOR_APP" ]; then
    pass "P01 monitor app is a symlink ($E3_MONITOR_APP)"
else
    fail "P01 monitor app is NOT a symlink: $E3_MONITOR_APP (packaging releases deploy a symlink)"
fi
MON_RELEASE_TARGET="$(readlink -f "$E3_MONITOR_APP" 2>/dev/null || true)"
MON_RELEASE_ID="$(basename "$MON_RELEASE_TARGET" 2>/dev/null || true)"
if [ -n "$MON_RELEASE_TARGET" ] && [ -d "$MON_RELEASE_TARGET" ]; then
    pass "P01 release target resolves and exists ($MON_RELEASE_TARGET, id=$MON_RELEASE_ID)"
else
    fail "P01 release target does not resolve to a directory (got [$MON_RELEASE_TARGET])"
fi
if [ -n "$MON_RELEASE_ID" ]; then
    pass "P01 release id non-empty"
else
    fail "P01 release id is EMPTY"
fi
if [ -f "$MON_RELEASE_TARGET/VERSION" ]; then
    pass "P01 monitor VERSION file present ($(tr -d ' \t\r\n' < "$MON_RELEASE_TARGET/VERSION" 2>/dev/null))"
else
    fail "P01 monitor VERSION file missing at $MON_RELEASE_TARGET/VERSION"
fi
# B1: the REAL packaging layout puts the runtime at
# app/monitor-v2/ inside the release tree.
if [ -f "$MON_RELEASE_TARGET/app/monitor-v2/webapp.py" ]; then
    pass "P01 monitor entrypoint present (app/monitor-v2/webapp.py)"
else
    fail "P01 monitor entrypoint missing at $MON_RELEASE_TARGET/app/monitor-v2/webapp.py"
fi

# ------------------------------------------------------- P02/P03 services --
if "$E3_SYSTEMCTL" is-active --quiet sing-box.service 2>/dev/null; then
    pass "P02 sing-box.service is active"
else
    fail "P02 sing-box.service is NOT active"
fi
if "$E3_SYSTEMCTL" is-active --quiet "$E3_MONITOR_UNIT" 2>/dev/null; then
    pass "P03 monitor unit ($E3_MONITOR_UNIT) is active"
else
    fail "P03 monitor unit ($E3_MONITOR_UNIT) is NOT active"
fi

# ------------------------------------------------------- P04 config hash --
if [ -f "$E3_CONFIG" ]; then
    CONFIG_SHA="$(sha256sum "$E3_CONFIG" 2>/dev/null | awk '{print $1}')"
    CONFIG_SIZE="$(stat -c %s "$E3_CONFIG" 2>/dev/null)"
    if [ -n "$CONFIG_SHA" ]; then
        pass "P04 config SHA256 recorded ($CONFIG_SHA)"
    else
        fail "P04 config SHA256 could not be computed"
    fi
else
    CONFIG_SHA=""; CONFIG_SIZE=""
    fail "P04 config file missing: $E3_CONFIG"
fi

# --------------------------------------------------- P05 sing-box check --
if [ -f "$E3_CONFIG" ] && [ -x "$E3_SING_BOX_BIN" ]; then
    if "$E3_SING_BOX_BIN" check -c "$E3_CONFIG" >/dev/null 2>&1; then
        pass "P05 sing-box check accepts the current config"
    else
        fail "P05 sing-box check REJECTS the current config"
    fi
else
    fail "P05 cannot run sing-box check (binary or config missing)"
fi

# --------------------------------------------------- P06 monitor HTTP --
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    "$E3_MONITOR_URL/api/v1/session" 2>/dev/null || true)"
if [ "$HTTP_CODE" = "200" ]; then
    pass "P06 monitor read-only API answers 200"
else
    fail "P06 monitor read-only API answered [$HTTP_CODE] (want 200)"
fi

# ------------------------------------------------------- P07 sboxweb --
if getent passwd sboxweb >/dev/null 2>&1 \
        && [ "$(getent group sboxweb | cut -d: -f1)" = "sboxweb" ]; then
    pass "P07 sboxweb user and group exist"
else
    fail "P07 sboxweb user/group missing"
fi

# ------------------------------------------------------- P08 /root/sbox --
if [ -d /root/sbox ] && [ "$(stat -c %U /root/sbox 2>/dev/null)" = "root" ]; then
    if [ -f "$E3_CONFIG" ]; then
        pass "P08 /root/sbox present, root-owned, config inside"
    else
        fail "P08 /root/sbox present but config missing"
    fi
else
    fail "P08 /root/sbox missing or not root-owned"
fi

# ------------------------------------------------- P09 /var/lib/sbox-cm --
# A leftover state/audit tree alone is tolerated (audit trail), but its
# owner/group/mode must be safe, and the marker must be absent (P14).
if [ -d "$E3_SBXCM_STATE" ]; then
    OWNER="$(stat -c '%U %G %a' "$E3_SBXCM_STATE" 2>/dev/null)"
    if [ "$OWNER" = "root root 700" ]; then
        pass "P09 sbox-cm state dir is root:root 0700 (owner+group+mode)"
    else
        fail "P09 sbox-cm state dir owner/group/mode unexpected: [$OWNER] (want 'root root 700')"
    fi
else
    note "P09 sbox-cm state dir absent (created by the first deploy)"
fi

# ------------------------------------------------- P10 /run/sbox-cm socket --
if [ -S "$E3_SBXCM_SOCKET" ]; then
    SOCKOWN="$(stat -c '%U %G %a' "$E3_SBXCM_SOCKET" 2>/dev/null)"
    if [ "$SOCKOWN" = "root sboxweb 660" ]; then
        pass "P10 sbox-cm socket present (root:sboxweb 0660)"
    else
        fail "P10 sbox-cm socket ownership/mode unexpected: [$SOCKOWN]"
    fi
else
    note "P10 sbox-cm socket absent (created when the socket unit starts)"
fi

# ------------------------------------------------------- P12 disk space --
DISK_OK=1
for mnt in / /var; do
    FREE_MB="$(df -Pm "$mnt" 2>/dev/null | awk 'NR==2{print $4}')"
    if [ -z "$FREE_MB" ] || [ "$FREE_MB" -lt "$E3_DISK_MIN_MB" ]; then
        DISK_OK=0
        fail "P12 free space on $mnt: ${FREE_MB:-unknown} MB (< $E3_DISK_MIN_MB MB)"
    fi
done
[ "$DISK_OK" = "1" ] && pass "P12 free space on / and /var >= $E3_DISK_MIN_MB MB"

# ------------------------------------------------- P13 systemd overall --
SYSTEM_STATE="$("$E3_SYSTEMCTL" is-system-running 2>/dev/null || true)"
if [ "$SYSTEM_STATE" = "running" ] || [ "$SYSTEM_STATE" = "degraded" ]; then
    if [ "$SYSTEM_STATE" = "degraded" ]; then
        note "P13 systemd is degraded (some unrelated unit failed); deployment can proceed"
    else
        pass "P13 systemd is fully operational"
    fi
else
    fail "P13 systemd state is [$SYSTEM_STATE] (want running or degraded)"
fi

# ------------------------------------- P14 activation marker (must be off) --
if [ -e "$E3_SBXCM_STATE/management.active" ]; then
    fail "P14 activation marker EXISTS -- the plane is armed; deployment requires the closed default state"
else
    pass "P14 activation marker absent (management plane closed, the safe default)"
fi

# ------------------------------------------------------------- baseline --
# ONLY a fully PASSing preflight may produce a baseline (a failed preflight
# must never create or overwrite one). Hardened write: umask 077, a
# SAME-DIRECTORY mktemp, write, chmod 0600, verify it parses as JSON, and
# only then the atomic mv -- a failed write can never clobber an existing
# baseline.
if [ "$FAIL" -gt 0 ]; then
    if [ -n "$BASELINE_OUT" ]; then
        note "baseline NOT written: the preflight failed (an existing baseline is left untouched)"
    fi
    printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
    printf 'E3_PREFLIGHT=FAIL\n'
    exit 1
fi

# P00 guarantees NO capability at this point, so the sbox-cm state for the
# baseline is derived from the actual (absent) unit/binary state.
SB_SOCKET_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)"
SB_SERVICE_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)"
SB_SOCKET_ENABLED="$("$E3_SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)"
SB_SERVICE_ENABLED="$("$E3_SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)"
SOCKET_UNIT_PRESENT="no"
SERVICE_UNIT_PRESENT="no"
[ -f /etc/systemd/system/sbox-cm.socket ] && SOCKET_UNIT_PRESENT="yes"
[ -f /etc/systemd/system/sbox-cm.service ] && SERVICE_UNIT_PRESENT="yes"
MON_ENABLED="$("$E3_SYSTEMCTL" is-enabled "$E3_MONITOR_UNIT" 2>/dev/null || true)"
MON_ACTIVE="$("$E3_SYSTEMCTL" is-active "$E3_MONITOR_UNIT" 2>/dev/null || true)"
SB_ACTIVE="$("$E3_SYSTEMCTL" is-active sing-box.service 2>/dev/null || true)"
SB_TS="$("$E3_SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"
SB_RESTARTS="$("$E3_SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"
HELPER_STATE_DIR_PRESENT="no"
[ -d "$E3_SBXCM_STATE" ] && HELPER_STATE_DIR_PRESENT="yes"
MARKER="false"
[ -e "$E3_SBXCM_STATE/management.active" ] && MARKER="true"

if [ -n "$BASELINE_OUT" ]; then
    umask 077
    TMP_BASE="$(mktemp "${BASELINE_OUT}.tmp.XXXXXX")" \
        || TMP_BASE=""
    if [ -n "$TMP_BASE" ] \
        && jq -n \
            --arg config_sha256 "$CONFIG_SHA" \
            --argjson config_size "${CONFIG_SIZE:-0}" \
            --arg sb_active "$SB_ACTIVE" \
            --arg sb_ts "$SB_TS" \
            --argjson sb_restarts "${SB_RESTARTS:-0}" \
            --arg mon_active "$MON_ACTIVE" \
            --arg mon_enabled "$MON_ENABLED" \
            --arg mon_release_id "$MON_RELEASE_ID" \
            --arg mon_release_target "$MON_RELEASE_TARGET" \
            --argjson marker "$MARKER" \
            --argjson helper_libexec_present false \
            --argjson helper_socket_unit_present false \
            --argjson helper_service_unit_present false \
            --argjson helper_state_dir_present "$([ "$HELPER_STATE_DIR_PRESENT" = "yes" ] && echo true || echo false)" \
            --arg helper_socket_active "$SB_SOCKET_STATE" \
            --arg helper_socket_enabled "$SB_SOCKET_ENABLED" \
            --arg helper_service_active "$SB_SERVICE_STATE" \
            --arg helper_service_enabled "$SB_SERVICE_ENABLED" \
            --arg saved_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            '{config_sha256:$config_sha256, config_size:$config_size,
              singbox:{active:$sb_active, active_enter_timestamp:$sb_ts, nrestarts:$sb_restarts},
              monitor:{active:$mon_active, enabled:$mon_enabled,
                       release_id:$mon_release_id, release_target:$mon_release_target},
              marker_present:$marker,
              helper:{libexec_present:$helper_libexec_present,
                      socket_unit_present:$helper_socket_unit_present,
                      service_unit_present:$helper_service_unit_present,
                      state_dir_present:$helper_state_dir_present,
                      socket_active:$helper_socket_active,
                      socket_enabled:$helper_socket_enabled,
                      service_active:$helper_service_active,
                      service_enabled:$helper_service_enabled},
              saved_at:$saved_at}' > "$TMP_BASE" 2>"$TMP_BASE.err" \
        && chmod 0600 "$TMP_BASE" \
        && jq -e . "$TMP_BASE" >/dev/null 2>&1 \
        && rm -f "$TMP_BASE.err" \
        && mv "$TMP_BASE" "$BASELINE_OUT"; then
        pass "baseline saved atomically to $BASELINE_OUT (0600, all checks passed)"
    else
        fail "baseline could not be written to $BASELINE_OUT: $(head -c 200 "${TMP_BASE:-/dev/null}.err" 2>/dev/null)"
        [ -n "$TMP_BASE" ] && rm -f "$TMP_BASE" "$TMP_BASE.err"
    fi
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_PREFLIGHT=FAIL\n'
    exit 1
fi
printf 'E3_PREFLIGHT=PASS\n'
