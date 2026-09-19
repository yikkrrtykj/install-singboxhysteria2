#!/usr/bin/env bash
# e3-preflight.sh -- READ-ONLY production preflight for the E3 M3 deployment.
#
# Checks deployment readiness WITHOUT changing anything:
#   * no config writes          (config is only hashed; `sing-box check` runs
#                                with -c against the CURRENT file, read-only)
#   * no reload / restart       (only read-only systemctl queries)
#   * no marker write           (the activation marker is only TESTED)
#   * no activate               (no RPC mutation is sent at all)
#   * no client create/delete
#
# The ONLY file this script writes is the baseline JSON given via
# --baseline-out PATH (explicitly requested by the operator; used later by
# e3-deploy-verify.sh / e3-rollback.sh for before/after comparison).
#
# Output: one PASS/FAIL line per check, then
#     E3_PREFLIGHT=PASS   (exit 0)   every check passed
#     E3_PREFLIGHT=FAIL   (exit 1)   at least one check failed
#
# Environment overrides (tests; production uses the defaults):
#   E3_SYSTEMCTL      systemctl binary          (default: systemctl)
#   E3_CONFIG         sing-box server config    (default: /root/sbox/sbconfig_server.json)
#   E3_SING_BOX_BIN   sing-box binary           (default: /root/sbox/sing-box)
#   E3_SBXCM_STATE    sbox-cm state dir         (default: /var/lib/sbox-cm)
#   E3_SBXCM_SOCKET   sbox-cm socket path       (default: /run/sbox-cm/sbox-cm.sock)
#   E3_MONITOR_URL    monitor base URL          (default: http://127.0.0.1:9191)
#   E3_MONITOR_APP    monitor app link          (default: /opt/singbox-monitor)
#   E3_DISK_MIN_MB    min free MB on / and /var (default: 1024)
set -uo pipefail

E3_SYSTEMCTL="${E3_SYSTEMCTL:-systemctl}"
E3_CONFIG="${E3_CONFIG:-/root/sbox/sbconfig_server.json}"
E3_SING_BOX_BIN="${E3_SING_BOX_BIN:-/root/sbox/sing-box}"
E3_SBXCM_STATE="${E3_SBXCM_STATE:-/var/lib/sbox-cm}"
E3_SBXCM_SOCKET="${E3_SBXCM_SOCKET:-/run/sbox-cm/sbox-cm.sock}"
E3_MONITOR_URL="${E3_MONITOR_URL:-http://127.0.0.1:9191}"
E3_MONITOR_APP="${E3_MONITOR_APP:-/opt/singbox-monitor}"
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
CHECK(){ # <description> <cmd...>  (read-only command; rc 0 = PASS)
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; return 0; else fail "$desc"; return 1; fi
}

printf '===== E3 M3 PRODUCTION PREFLIGHT (read-only) =====\n'

# ------------------------------------------------------------ P01 versions --
if [ -f "$E3_MONITOR_APP/VERSION" ]; then
    pass "P01 monitor VERSION file present ($(tr -d ' \t\r\n' < "$E3_MONITOR_APP/VERSION" 2>/dev/null))"
else
    fail "P01 monitor VERSION file missing at $E3_MONITOR_APP/VERSION"
fi
if [ -f "$E3_MONITOR_APP/webapp.py" ]; then
    pass "P01 monitor entrypoint present"
else
    fail "P01 monitor entrypoint missing under $E3_MONITOR_APP"
fi
if [ -f /usr/local/lib/sbox-cm/sbox-cm ] && [ -f /usr/local/lib/sbox-cm/sbox-cm-ops ]; then
    pass "P01 sbox-cm libexec files present"
else
    note "P01 sbox-cm libexec files not present yet (first E3 deploy installs them)"
fi

# ------------------------------------------------------- P02/P03 services --
if "$E3_SYSTEMCTL" is-active --quiet sing-box.service 2>/dev/null; then
    pass "P02 sing-box.service is active"
else
    fail "P02 sing-box.service is NOT active"
fi
if "$E3_SYSTEMCTL" is-active --quiet singbox-monitor.service 2>/dev/null; then
    pass "P03 singbox-monitor.service is active"
else
    fail "P03 singbox-monitor.service is NOT active"
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
if [ -d "$E3_SBXCM_STATE" ]; then
    OWNER="$(stat -c '%U %a' "$E3_SBXCM_STATE" 2>/dev/null)"
    if [ "$OWNER" = "root 700" ] || [ "$OWNER" = "root 0700" ]; then
        pass "P09 sbox-cm state dir is root:root 0700"
    else
        fail "P09 sbox-cm state dir owner/mode unexpected: [$OWNER] (want root 700)"
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

# ------------------------------------------- P11 sbox-cm units existence --
SB_SOCKET_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)"
SB_SERVICE_STATE="$("$E3_SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)"
SB_SOCKET_ENABLED="$("$E3_SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)"
if [ -f /etc/systemd/system/sbox-cm.socket ] \
        && [ -f /etc/systemd/system/sbox-cm.service ]; then
    pass "P11 sbox-cm units installed (socket=$SB_SOCKET_STATE service=$SB_SERVICE_STATE enabled=$SB_SOCKET_ENABLED)"
else
    note "P11 sbox-cm units not installed yet (first E3 deploy installs them)"
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
if [ -n "$BASELINE_OUT" ]; then
    SB_ACTIVE="$("$E3_SYSTEMCTL" is-active sing-box.service 2>/dev/null || true)"
    SB_TS="$("$E3_SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"
    SB_RESTARTS="$("$E3_SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"
    MON_ACTIVE="$("$E3_SYSTEMCTL" is-active singbox-monitor.service 2>/dev/null || true)"
    MARKER="false"
    [ -e "$E3_SBXCM_STATE/management.active" ] && MARKER="true"
    jq -n \
        --arg config_sha256 "$CONFIG_SHA" \
        --argjson config_size "${CONFIG_SIZE:-0}" \
        --arg sb_active "$SB_ACTIVE" \
        --arg sb_ts "$SB_TS" \
        --argjson sb_restarts "${SB_RESTARTS:-0}" \
        --arg mon_active "$MON_ACTIVE" \
        --argjson marker "$MARKER" \
        --arg saved_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{config_sha256:$config_sha256, config_size:$config_size,
          singbox:{active:$sb_active, active_enter_timestamp:$sb_ts, nrestarts:$sb_restarts},
          monitor:{active:$mon_active}, marker_present:$marker, saved_at:$saved_at}' \
        > "$BASELINE_OUT" 2>/dev/null \
        && pass "baseline saved to $BASELINE_OUT" \
        || fail "baseline could not be written to $BASELINE_OUT"
fi

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'E3_PREFLIGHT=FAIL\n'
    exit 1
fi
printf 'E3_PREFLIGHT=PASS\n'
