#!/usr/bin/env bash
# E3 M3-C Phase 1 orchestrator: production preflight + deploy-disabled only.
#
# This script deliberately has no Phase 2 command or continuation.  It only
# sequences the already-reviewed deployment primitives and adds crash-safe
# gates/journaling around them.
set -uo pipefail

readonly FROZEN_PAYLOAD_BASE="f0e1480e1527ffb5906e715dd3acff8b29b8c024"
readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly PRIMITIVE_BASH="/usr/bin/bash"
if [ "${E3_PHASE1_TEST_MODE:-0}" != "1" ]; then
    PATH="$SAFE_PATH"
    export PATH
fi
readonly DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "$DEPLOY_DIR/../.." && pwd)"
# Phase 1 must retain every existing rollback candidate even if another
# release appears before the installer acquires its deploy lock.  This
# process-only value is intentionally effectively-no-prune.
readonly PHASE1_NO_PRUNE_KEEP="2147483647"

TEST_MODE="${E3_PHASE1_TEST_MODE:-0}"
if [ "$TEST_MODE" != "0" ] && [ "$TEST_MODE" != "1" ]; then
    printf 'ERROR: E3_PHASE1_TEST_MODE must be 0 or 1\n' >&2
    exit 2
fi

# Production defaults are immutable.  Fixture overrides are accepted only
# behind the explicit test gate so an inherited environment cannot redirect a
# production run to alternate primitives or paths.
if [ "$TEST_MODE" = "1" ]; then
    STATE_DIR="${E3_PHASE1_TEST_STATE_DIR:?test state dir required}"
    CONFIG="${E3_PHASE1_TEST_CONFIG:?test config required}"
    MONITOR_APP="${E3_PHASE1_TEST_MONITOR_APP:?test monitor app required}"
    RELEASES_DIR="${E3_PHASE1_TEST_RELEASES_DIR:?test releases dir required}"
    SBXCM_STATE="${E3_PHASE1_TEST_SBXCM_STATE:?test helper state required}"
    SBXCM_LIBEXEC="${E3_PHASE1_TEST_SBXCM_LIBEXEC:?test helper libexec required}"
    UNIT_DIR="${E3_PHASE1_TEST_UNIT_DIR:?test unit dir required}"
    SOCKET_PATH="${E3_PHASE1_TEST_SOCKET:?test socket path required}"
    MONITOR_URL="${E3_PHASE1_TEST_MONITOR_URL:-http://127.0.0.1:9191}"
    SYSTEMCTL="${E3_PHASE1_TEST_SYSTEMCTL:?test systemctl required}"
    CURL="${E3_PHASE1_TEST_CURL:?test curl required}"
    PREFLIGHT="${E3_PHASE1_TEST_PREFLIGHT:?test preflight required}"
    INSTALL_MONITOR="${E3_PHASE1_TEST_INSTALL_MONITOR:?test monitor installer required}"
    INSTALL_SBXCM="${E3_PHASE1_TEST_INSTALL_SBXCM:?test helper installer required}"
    DEPLOY_VERIFY="${E3_PHASE1_TEST_DEPLOY_VERIFY:?test verifier required}"
    FULL_ROLLBACK="${E3_PHASE1_TEST_ROLLBACK:?test rollback required}"
    STATUS_PROBE="${E3_PHASE1_TEST_STATUS_PROBE:?test status probe required}"
    TEST_FIXTURE_ROOT="${E3_PHASE1_TEST_FIXTURE_ROOT:?test fixture root required}"
    TEST_SOURCE_HEAD="${E3_PHASE1_TEST_SOURCE_HEAD:?test source head required}"
    PHASE1_LOCK="${E3_PHASE1_TEST_LOCK:?test lock path required}"
    FLOCK_BIN="${E3_PHASE1_TEST_FLOCK:-/usr/bin/flock}"
    LOCK_BACKEND="${E3_PHASE1_TEST_LOCK_BACKEND:-flock}"
    PRIMITIVE_PATH="$(dirname -- "$SYSTEMCTL"):$PATH"
else
    [ "$(id -u)" = "0" ] || { printf 'ERROR: Phase 1 must run as root\n' >&2; exit 1; }
    STATE_DIR="/var/lib/e3-m3c-phase1"
    CONFIG="/root/sbox/sbconfig_server.json"
    MONITOR_APP="/opt/singbox-monitor"
    RELEASES_DIR="/opt/singbox-monitor-releases"
    SBXCM_STATE="/var/lib/sbox-cm"
    SBXCM_LIBEXEC="/usr/local/lib/sbox-cm"
    UNIT_DIR="/etc/systemd/system"
    SOCKET_PATH="/run/sbox-cm/sbox-cm.sock"
    MONITOR_URL="http://127.0.0.1:9191"
    SYSTEMCTL="/usr/bin/systemctl"
    CURL="/usr/bin/curl"
    PREFLIGHT="$DEPLOY_DIR/e3-preflight.sh"
    INSTALL_MONITOR="$DEPLOY_DIR/install-monitor.sh"
    INSTALL_SBXCM="$REPO_ROOT/sbox-cm/deploy/install-sbox-cm.sh"
    DEPLOY_VERIFY="$DEPLOY_DIR/e3-deploy-verify.sh"
    FULL_ROLLBACK="$DEPLOY_DIR/e3-rollback.sh"
    STATUS_PROBE=""
    TEST_FIXTURE_ROOT=""
    TEST_SOURCE_HEAD=""
    PHASE1_LOCK="/run/lock/e3-m3c-phase1.lock"
    FLOCK_BIN="/usr/bin/flock"
    LOCK_BACKEND="flock"
    PRIMITIVE_PATH="$SAFE_PATH"
fi

ART_DIR="$STATE_DIR/artifacts"
BASELINE="$STATE_DIR/baseline.json"
JOURNAL="$STATE_DIR/journal.json"
D3_EVIDENCE="$ART_DIR/04-sbox-cm-install.log"
MARKER="$SBXCM_STATE/management.active"

PHASE="new"
SOURCE_HEAD=""
BASE_RELEASE=""
BASE_RELEASE_TARGET=""
MONITOR_STARTED=false
MONITOR_COMPLETED=false
HELPER_STARTED=false
HELPER_COMPLETED=false
SOCKET_STARTED=false
SOCKET_COMPLETED=false
VERIFY_COMPLETED=false
FINAL_STATUS="not_started"
RECOVERY_MODE=0

die() {
    if [ "$RECOVERY_MODE" = "1" ]; then
        printf 'CRITICAL STOP: %s\n' "$*" >&2
    else
        printf 'ERROR: %s\n' "$*" >&2
    fi
    exit 1
}
critical() { printf 'CRITICAL: %s\n' "$*" >&2; exit 1; }

canonical_dir() {
    [ -d "$1" ] || return 1
    (cd -- "$1" 2>/dev/null && pwd -P)
}

same_dir() {
    local left right
    left="$(canonical_dir "$1")" || return 1
    right="$(canonical_dir "$2")" || return 1
    [ "$left" = "$right" ]
}

acquire_phase1_lock() {
    local lock_parent
    lock_parent="$(dirname -- "$PHASE1_LOCK")"
    mkdir -p -- "$lock_parent" || die "cannot create Phase 1 lock directory"
    if [ "$TEST_MODE" = "1" ] && [ "$LOCK_BACKEND" = "mkdir" ]; then
        mkdir -- "$PHASE1_LOCK.fixture-held" 2>/dev/null \
            || die "another Phase 1 command holds the exclusive lock"
        trap 'rmdir -- "$PHASE1_LOCK.fixture-held" 2>/dev/null || true' EXIT
        return 0
    fi
    [ "$LOCK_BACKEND" = "flock" ] || die "invalid Phase 1 lock backend"
    [ -x "$FLOCK_BIN" ] || die "Phase 1 flock binary is unavailable"
    umask 077
    exec 8>>"$PHASE1_LOCK" || die "cannot open Phase 1 lock"
    chmod 0600 "$PHASE1_LOCK" || die "cannot protect Phase 1 lock"
    "$FLOCK_BIN" -n 8 || die "another Phase 1 command holds the exclusive lock"
}

# Every reviewed shell primitive runs through the fixed Bash interpreter with
# an empty environment.  The only accepted process-local assignment is the
# reviewed no-prune value for install-monitor.  Test fixtures get only the
# explicitly gated E3_PHASE1_TEST_* paths they require; production receives no
# E3/SBMON/SBXCM override from the operator's shell.
run_primitive() {
    local keep_assignment="" primitive
    if [ "${1:-}" = "SBMON_KEEP_RELEASES=$PHASE1_NO_PRUNE_KEEP" ]; then
        keep_assignment="$1"
        shift
    fi
    [ "$#" -ge 1 ] || die "reviewed primitive path is missing"
    primitive="$1"
    shift
    case "$primitive" in
        "$PREFLIGHT"|"$INSTALL_MONITOR"|"$INSTALL_SBXCM"|"$DEPLOY_VERIFY"|"$FULL_ROLLBACK") ;;
        *) die "refusing unreviewed primitive path: $primitive" ;;
    esac
    if [ -n "$keep_assignment" ] && [ "$primitive" != "$INSTALL_MONITOR" ]; then
        die "SBMON_KEEP_RELEASES is only valid for install-monitor"
    fi
    if [ "$TEST_MODE" = "1" ]; then
        if [ -n "$keep_assignment" ]; then
            env -i \
                PATH="$PRIMITIVE_PATH" HOME="$STATE_DIR" LC_ALL=C \
                FX="$TEST_FIXTURE_ROOT" ROOT="$REPO_ROOT" \
                E3_PHASE1_TEST_CONFIG="$CONFIG" \
                E3_PHASE1_TEST_MONITOR_APP="$MONITOR_APP" \
                E3_PHASE1_TEST_RELEASES_DIR="$RELEASES_DIR" \
                E3_PHASE1_TEST_SBXCM_STATE="$SBXCM_STATE" \
                E3_PHASE1_TEST_SBXCM_LIBEXEC="$SBXCM_LIBEXEC" \
                E3_PHASE1_TEST_UNIT_DIR="$UNIT_DIR" \
                E3_PHASE1_TEST_SOCKET="$SOCKET_PATH" \
                "$keep_assignment" "$PRIMITIVE_BASH" "$primitive" "$@"
        else
            env -i \
                PATH="$PRIMITIVE_PATH" HOME="$STATE_DIR" LC_ALL=C \
                FX="$TEST_FIXTURE_ROOT" ROOT="$REPO_ROOT" \
                E3_PHASE1_TEST_CONFIG="$CONFIG" \
                E3_PHASE1_TEST_MONITOR_APP="$MONITOR_APP" \
                E3_PHASE1_TEST_RELEASES_DIR="$RELEASES_DIR" \
                E3_PHASE1_TEST_SBXCM_STATE="$SBXCM_STATE" \
                E3_PHASE1_TEST_SBXCM_LIBEXEC="$SBXCM_LIBEXEC" \
                E3_PHASE1_TEST_UNIT_DIR="$UNIT_DIR" \
                E3_PHASE1_TEST_SOCKET="$SOCKET_PATH" \
                "$PRIMITIVE_BASH" "$primitive" "$@"
        fi
    else
        if [ -n "$keep_assignment" ]; then
            env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C \
                "$keep_assignment" "$PRIMITIVE_BASH" "$primitive" "$@"
        else
            env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C \
                "$PRIMITIVE_BASH" "$primitive" "$@"
        fi
    fi
}

ensure_state_dir() {
    umask 077
    mkdir -p -- "$ART_DIR" || die "cannot create state directory: $STATE_DIR"
    chmod 0700 "$STATE_DIR" "$ART_DIR" || die "cannot protect Phase 1 state"
    if [ "$TEST_MODE" = "0" ]; then
        chown root:root "$STATE_DIR" "$ART_DIR" || die "cannot set Phase 1 state ownership"
        [ "$(stat -c '%U %G %a' "$STATE_DIR")" = "root root 700" ] \
            || die "Phase 1 state directory is not root:root 0700"
    fi
}

journal_write() {
    local tmp
    ensure_state_dir
    tmp="$(mktemp "$STATE_DIR/.journal.tmp.XXXXXX")" || die "cannot create journal temp file"
    if ! jq -n \
        --arg phase "$PHASE" \
        --arg source_head "$SOURCE_HEAD" \
        --arg baseline_path "$BASELINE" \
        --arg release_id "$BASE_RELEASE" \
        --arg release_target "$BASE_RELEASE_TARGET" \
        --argjson monitor_started "$MONITOR_STARTED" \
        --argjson monitor_completed "$MONITOR_COMPLETED" \
        --argjson helper_started "$HELPER_STARTED" \
        --argjson helper_completed "$HELPER_COMPLETED" \
        --argjson socket_started "$SOCKET_STARTED" \
        --argjson socket_completed "$SOCKET_COMPLETED" \
        --argjson verify_completed "$VERIFY_COMPLETED" \
        --arg final_status "$FINAL_STATUS" \
        --arg updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schema:1,phase:$phase,source_head:$source_head,baseline_path:$baseline_path,
          baseline_release_id:$release_id,baseline_release_target:$release_target,
          monitor_mutation:{started:$monitor_started,completed:$monitor_completed},
          helper_install:{started:$helper_started,completed:$helper_completed},
          socket_enable:{started:$socket_started,completed:$socket_completed},
          verify_completed:$verify_completed,final_status:$final_status,updated_at:$updated_at}' \
        >"$tmp"; then
        rm -f -- "$tmp"
        die "cannot serialize Phase 1 journal"
    fi
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; die "cannot protect journal temp file"; }
    jq -e . "$tmp" >/dev/null 2>&1 || { rm -f -- "$tmp"; die "journal JSON validation failed"; }
    mv -f -- "$tmp" "$JOURNAL" || { rm -f -- "$tmp"; die "atomic journal replace failed"; }
}

journal_load() {
    [ -r "$JOURNAL" ] || die "Phase 1 journal is unavailable: $JOURNAL"
    jq -e '.schema == 1' "$JOURNAL" >/dev/null 2>&1 || die "Phase 1 journal is invalid"
    PHASE="$(jq -er '.phase' "$JOURNAL")" || die "journal phase missing"
    SOURCE_HEAD="$(jq -er '.source_head' "$JOURNAL")" || die "journal source head missing"
    BASE_RELEASE="$(jq -er '.baseline_release_id' "$JOURNAL")" || die "journal baseline id missing"
    BASE_RELEASE_TARGET="$(jq -er '.baseline_release_target' "$JOURNAL")" || die "journal baseline target missing"
    MONITOR_STARTED="$(jq -r '.monitor_mutation.started' "$JOURNAL")"
    MONITOR_COMPLETED="$(jq -r '.monitor_mutation.completed' "$JOURNAL")"
    HELPER_STARTED="$(jq -r '.helper_install.started' "$JOURNAL")"
    HELPER_COMPLETED="$(jq -r '.helper_install.completed' "$JOURNAL")"
    SOCKET_STARTED="$(jq -r '.socket_enable.started' "$JOURNAL")"
    SOCKET_COMPLETED="$(jq -r '.socket_enable.completed' "$JOURNAL")"
    VERIFY_COMPLETED="$(jq -r '.verify_completed' "$JOURNAL")"
    local value
    for value in "$MONITOR_STARTED" "$MONITOR_COMPLETED" "$HELPER_STARTED" \
        "$HELPER_COMPLETED" "$SOCKET_STARTED" "$SOCKET_COMPLETED" "$VERIFY_COMPLETED"; do
        [ "$value" = "true" ] || [ "$value" = "false" ] \
            || die "journal boolean state missing"
    done
    FINAL_STATUS="$(jq -er '.final_status' "$JOURNAL")" || die "journal final status missing"
}

source_identity_gate() {
    local approved dirty
    approved="${E3_PHASE1_APPROVED_HEAD:-}"
    [ -x "$PRIMITIVE_BASH" ] || die "fixed primitive interpreter is unavailable: $PRIMITIVE_BASH"
    if [ "$TEST_MODE" = "1" ]; then
        SOURCE_HEAD="$TEST_SOURCE_HEAD"
        [ -n "$approved" ] && [ "$SOURCE_HEAD" = "$approved" ] \
            || die "checkout HEAD does not equal E3_PHASE1_APPROVED_HEAD"
        return 0
    fi
    [[ "$approved" =~ ^[0-9a-f]{40}$ ]] \
        || die "E3_PHASE1_APPROVED_HEAD must be the exact reviewed 40-hex merge SHA"
    git -C "$REPO_ROOT" cat-file -e "$FROZEN_PAYLOAD_BASE^{commit}" 2>/dev/null \
        || die "frozen payload commit is unavailable"
    git -C "$REPO_ROOT" merge-base --is-ancestor "$FROZEN_PAYLOAD_BASE" HEAD \
        || die "checkout does not descend from the reviewed payload"
    SOURCE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)" || die "cannot resolve source HEAD"
    [ "$SOURCE_HEAD" = "$approved" ] \
        || die "checkout HEAD does not equal E3_PHASE1_APPROVED_HEAD"
    dirty="$(git -C "$REPO_ROOT" status --porcelain)"
    [ -z "$dirty" ] || die "source checkout is dirty"
    git -C "$REPO_ROOT" diff --quiet "$FROZEN_PAYLOAD_BASE" -- \
        monitor-v2 sbox-cm lib \
        ':(exclude)monitor-v2/deploy/e3-m3c-phase1.sh' \
        || die "production payload differs from the reviewed frozen commit"
    for f in "$PREFLIGHT" "$INSTALL_MONITOR" "$INSTALL_SBXCM" "$DEPLOY_VERIFY" "$FULL_ROLLBACK"; do
        [ -f "$f" ] || die "required primitive missing: $f"
    done
    printf 'PASS source identity: reviewed payload %s at checkout %s\n' \
        "$FROZEN_PAYLOAD_BASE" "$SOURCE_HEAD"
}

baseline_load_validate() {
    local mode expected_target
    [ -r "$BASELINE" ] || die "PASSing preflight baseline is unavailable: $BASELINE"
    jq -e '
      (.config_sha256 | type == "string" and length == 64) and
      (.config_size | type == "number" and . > 0) and
      (.singbox.active == "active") and
      (.singbox.active_enter_timestamp | type == "string" and length > 0) and
      (.singbox.nrestarts | type == "number") and
      (.monitor.active == "active") and
      (.monitor.enabled | type == "string" and length > 0) and
      (.monitor.release_id | type == "string" and length > 0) and
      (.monitor.release_target | type == "string" and length > 0) and
      (.marker_present == false) and
      (.helper.libexec_present == false) and
      (.helper.socket_unit_present == false) and
      (.helper.service_unit_present == false)
    ' "$BASELINE" >/dev/null || die "baseline violates the Phase 1 contract"
    mode="$(stat -c %a "$BASELINE" 2>/dev/null || true)"
    if [ "$TEST_MODE" = "0" ] || [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
        [ "$mode" = "600" ] || die "baseline mode is not 0600"
    fi
    if [ "$TEST_MODE" = "0" ]; then
        [ "$(stat -c '%U %G' "$BASELINE")" = "root root" ] \
            || die "baseline owner is not root:root"
    fi
    BASE_RELEASE="$(jq -er '.monitor.release_id' "$BASELINE")" || die "baseline release id missing"
    BASE_RELEASE_TARGET="$(jq -er '.monitor.release_target' "$BASELINE")" || die "baseline release target missing"
    expected_target="$RELEASES_DIR/$BASE_RELEASE"
    if [ "$TEST_MODE" = "0" ]; then
        [ "$BASE_RELEASE_TARGET" = "$expected_target" ] \
            || die "baseline release target does not match the exact packaging path (baseline=[$BASE_RELEASE_TARGET] expected=[$expected_target])"
    else
        same_dir "$BASE_RELEASE_TARGET" "$expected_target" \
            || die "baseline release target does not match the packaging path (baseline=[$BASE_RELEASE_TARGET] expected=[$expected_target])"
    fi
    [ -d "$BASE_RELEASE_TARGET" ] || die "exact baseline release target is unavailable"
}

capability_present() {
    local p
    for p in \
        "$SBXCM_LIBEXEC/sbox-cm" \
        "$SBXCM_LIBEXEC/sbox-cm-ops" \
        "$SBXCM_LIBEXEC/lib/client-management.sh" \
        "$SBXCM_LIBEXEC/lib/sbox-cm-state.sh" \
        "$UNIT_DIR/sbox-cm.socket" \
        "$UNIT_DIR/sbox-cm.service" \
        "$SOCKET_PATH"; do
        if [ -e "$p" ] || [ -L "$p" ]; then
            return 0
        fi
    done
    return 1
}

invariants_hold() {
    local sha size ts restarts active
    sha="$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')"
    size="$(stat -c %s "$CONFIG" 2>/dev/null || true)"
    ts="$("$SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"
    restarts="$("$SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"
    active="$("$SYSTEMCTL" is-active sing-box.service 2>/dev/null || true)"
    [ "$sha" = "$(jq -r '.config_sha256' "$BASELINE")" ] \
        && [ "$size" = "$(jq -r '.config_size' "$BASELINE")" ] \
        && [ "$ts" = "$(jq -r '.singbox.active_enter_timestamp' "$BASELINE")" ] \
        && [ "$restarts" = "$(jq -r '.singbox.nrestarts' "$BASELINE")" ] \
        && [ "$active" = "active" ]
}

monitor_http_ok() {
    [ "$("$CURL" -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "$MONITOR_URL/api/v1/session" 2>/dev/null || true)" = "200" ]
}

status_probe_json() {
    if [ "$TEST_MODE" = "1" ]; then
        env -i \
            PATH="$PRIMITIVE_PATH" HOME="$STATE_DIR" LC_ALL=C \
            FX="$TEST_FIXTURE_ROOT" ROOT="$REPO_ROOT" \
            "$PRIMITIVE_BASH" "$STATUS_PROBE"
        return
    fi
    env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C \
        /usr/bin/sudo -n -u sboxweb /usr/bin/python3 -B - \
        "$MONITOR_APP/app/monitor-v2" <<'PY'
import json
import sys

sys.path.insert(0, sys.argv[1])
from web.e3rpc import E3RpcClient

print(json.dumps(E3RpcClient().call("management.status")))
PY
}

independent_status_inactive() {
    local result rc=0
    result="$(status_probe_json 2>/dev/null)" || rc=$?
    printf '%s\n' "$result" >"$ART_DIR/06-independent-status.json"
    [ "$rc" -eq 0 ] \
        && [ "$(printf '%s' "$result" | jq -r '.ok // false' 2>/dev/null)" = "true" ] \
        && [ "$(printf '%s' "$result" | jq -r '.data.management_state // empty' 2>/dev/null)" = "inactive" ]
}

monitor_only_rollback() {
    local reason="$1" rc=0 target active enabled
    printf 'STOP: %s\n' "$reason" >&2
    PHASE="recovering_monitor"
    FINAL_STATUS="rollback_in_progress"
    journal_write
    if ! same_dir "$(readlink -f "$MONITOR_APP" 2>/dev/null || true)" "$BASE_RELEASE_TARGET"; then
        run_primitive "$INSTALL_MONITOR" rollback "$BASE_RELEASE" 2>&1 \
            | tee "$ART_DIR/98-monitor-only-rollback.log"
        rc="${PIPESTATUS[0]}"
    fi
    target="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
    active="$("$SYSTEMCTL" is-active singbox-monitor.service 2>/dev/null || true)"
    enabled="$("$SYSTEMCTL" is-enabled singbox-monitor.service 2>/dev/null || true)"
    if [ "$rc" -eq 0 ] \
        && same_dir "$target" "$BASE_RELEASE_TARGET" \
        && [ "$active" = "$(jq -r '.monitor.active' "$BASELINE")" ] \
        && [ "$enabled" = "$(jq -r '.monitor.enabled' "$BASELINE")" ] \
        && monitor_http_ok; then
        PHASE="recovered"
        FINAL_STATUS="monitor_rollback_pass"
        journal_write
        printf 'ROLLBACK PASS: monitor restored to exact baseline state\n'
        return 0
    fi
    PHASE="critical"
    FINAL_STATUS="monitor_rollback_failed"
    journal_write
    printf 'CRITICAL: monitor-only rollback did not restore the complete baseline state\n' >&2
    return 1
}

full_rollback() {
    local reason="$1" rc=0
    printf 'STOP+ROLLBACK: %s\n' "$reason" >&2
    PHASE="recovering_full"
    FINAL_STATUS="rollback_in_progress"
    journal_write
    run_primitive "$FULL_ROLLBACK" --baseline "$BASELINE" 2>&1 \
        | tee "$ART_DIR/99-full-rollback.log"
    rc="${PIPESTATUS[0]}"
    if [ "$rc" -eq 0 ] \
        && grep -qx 'E3_M3_ROLLBACK=PASS' "$ART_DIR/99-full-rollback.log"; then
        PHASE="recovered"
        FINAL_STATUS="full_rollback_pass"
        journal_write
        printf 'ROLLBACK PASS: Phase 1 deployment removed; audit/state retained\n'
        return 0
    fi
    PHASE="critical"
    FINAL_STATUS="full_rollback_failed"
    journal_write
    printf 'CRITICAL: rollback incomplete; preserve evidence and escalate manually\n' >&2
    return 1
}

recover_classified() {
    baseline_load_validate
    # Monitor-only recovery needs positive proof that D3 never started.  Any
    # capability, D3 evidence, journal ambiguity, or started flag selects the
    # full reviewed rollback primitive.
    if ! capability_present \
        && [ ! -e "$D3_EVIDENCE" ] \
        && [ "$HELPER_STARTED" = "false" ]; then
        monitor_only_rollback "interrupted after monitor mutation and before helper install"
    else
        full_rollback "helper install may have started; fail-closed full recovery required"
    fi
}

cmd_preflight() {
    local rc=0
    [ ! -e "$STATE_DIR" ] || die "Phase 1 state already exists; use status or recover"
    source_identity_gate
    ensure_state_dir
    run_primitive "$PREFLIGHT" --baseline-out "$BASELINE" 2>&1 \
        | tee "$ART_DIR/01-preflight.log"
    rc="${PIPESTATUS[0]}"
    if [ "$rc" -ne 0 ] \
        || ! grep -qx 'E3_PREFLIGHT=PASS' "$ART_DIR/01-preflight.log" \
        || [ ! -f "$BASELINE" ]; then
        die "production preflight did not PASS; deployment is forbidden"
    fi
    baseline_load_validate
    same_dir "$(readlink -f "$MONITOR_APP" 2>/dev/null || true)" "$BASE_RELEASE_TARGET" \
        || die "live monitor target drifted after preflight"
    capability_present && die "first-deploy capability appeared during preflight"
    [ ! -e "$MARKER" ] || die "activation marker exists"
    monitor_http_ok || die "monitor HTTP is unhealthy"
    PHASE="preflight_complete"
    FINAL_STATUS="ready_to_apply"
    journal_write
    printf 'PASS Phase 1 preflight: baseline=%s\n' "$BASELINE"
}

apply_fail() {
    local reason="$1"
    if [ "$HELPER_STARTED" = "true" ] || [ -e "$D3_EVIDENCE" ] || capability_present; then
        full_rollback "$reason" || true
    else
        monitor_only_rollback "$reason" || true
    fi
    exit 1
}

cmd_apply() {
    local frozen_version live_target live_version current_release rc verify_log current_source
    source_identity_gate
    current_source="$SOURCE_HEAD"
    journal_load
    [ "$PHASE" = "preflight_complete" ] && [ "$FINAL_STATUS" = "ready_to_apply" ] \
        || die "apply requires a fresh successful preflight journal"
    baseline_load_validate
    [ "$SOURCE_HEAD" = "$current_source" ] || die "source head differs from the preflight checkout"
    capability_present && die "first-deploy capability exists before apply"
    [ ! -e "$MARKER" ] || die "activation marker exists before apply"

    frozen_version="$(tr -d ' \t\r\n' < "$REPO_ROOT/monitor-v2/VERSION")"
    live_target="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
    live_version="$(tr -d ' \t\r\n' < "$live_target/VERSION" 2>/dev/null || true)"
    current_release="$(basename "$live_target")"
    [ -n "$frozen_version" ] && [ "$live_version" = "$frozen_version" ] \
        || die "reviewed same-version restage precondition failed"
    same_dir "$live_target" "$BASE_RELEASE_TARGET" && [ "$current_release" = "$BASE_RELEASE" ] \
        || die "live release no longer matches the preflight baseline"
    {
        printf 'frozen_repo_version=%s\n' "$frozen_version"
        printf 'current_live_version=%s\n' "$live_version"
        printf 'current_release_id=%s\n' "$current_release"
        printf 'current_release_target=%s\n' "$live_target"
        printf 'phase1_keep_releases=%s\n' "$PHASE1_NO_PRUNE_KEEP"
        printf 'phase1_retention_contract=effectively-no-prune\n'
    } | tee "$ART_DIR/03-monitor-before.txt"

    PHASE="monitor_mutation_started"
    MONITOR_STARTED=true
    FINAL_STATUS="in_progress"
    journal_write
    rc=0
    run_primitive SBMON_KEEP_RELEASES="$PHASE1_NO_PRUNE_KEEP" \
        "$INSTALL_MONITOR" upgrade --repair 2>&1 \
        | tee "$ART_DIR/03-monitor-upgrade.log"
    rc="${PIPESTATUS[0]}"
    [ "$rc" -eq 0 ] || apply_fail "monitor upgrade failed"
    MONITOR_COMPLETED=true
    PHASE="monitor_mutation_complete"
    journal_write
    [ -d "$BASE_RELEASE_TARGET" ] \
        || apply_fail "baseline rollback target was pruned or disappeared"
    ! same_dir "$(readlink -f "$MONITOR_APP" 2>/dev/null || true)" "$BASE_RELEASE_TARGET" \
        || apply_fail "repair did not restage to a new release"
    monitor_http_ok || apply_fail "monitor HTTP unhealthy after repair"
    invariants_hold || apply_fail "D2 invariant drift: config or sing-box changed"
    printf 'PASS D2 gate: repair-restage complete; baseline retained; invariants unchanged\n'

    PHASE="helper_install_started"
    HELPER_STARTED=true
    journal_write
    : >"$D3_EVIDENCE"
    chmod 0600 "$D3_EVIDENCE"
    rc=0
    run_primitive "$INSTALL_SBXCM" install 2>&1 | tee -a "$D3_EVIDENCE"
    rc="${PIPESTATUS[0]}"
    [ "$rc" -eq 0 ] || apply_fail "helper installation failed or was partial"
    HELPER_COMPLETED=true
    PHASE="helper_install_complete"
    journal_write
    "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 \
        || apply_fail "daemon-reload failed after helper install"
    [ "$("$SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)" = "inactive" ] \
        || apply_fail "helper socket is active before D4"
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)" = "disabled" ] \
        || apply_fail "helper socket is enabled before D4"
    [ "$("$SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)" = "inactive" ] \
        || apply_fail "helper service is active before D4"
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)" = "disabled" ] \
        || apply_fail "helper service is enabled before D4"
    [ ! -e "$MARKER" ] || apply_fail "activation marker appeared after helper install"
    invariants_hold || apply_fail "D3 invariant drift: config or sing-box changed"
    printf 'PASS D3 gate: helper installed disabled/inactive; invariants unchanged\n'

    PHASE="socket_enable_started"
    SOCKET_STARTED=true
    journal_write
    "$SYSTEMCTL" enable --now sbox-cm.socket >/dev/null 2>&1 \
        || apply_fail "socket-only enable failed"
    SOCKET_COMPLETED=true
    PHASE="socket_enabled"
    journal_write
    [ "$("$SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)" = "active" ] \
        || apply_fail "socket is not active after D4"
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)" = "enabled" ] \
        || apply_fail "socket is not enabled after D4"
    [ "$("$SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)" = "inactive" ] \
        || apply_fail "service was active before the first RPC"
    printf 'PASS D4 gate: socket enabled/active; service inactive before first RPC\n'

    verify_log="$ART_DIR/05-deploy-verify.log"
    rc=0
    run_primitive "$DEPLOY_VERIFY" --baseline "$BASELINE" 2>&1 | tee "$verify_log"
    rc="${PIPESTATUS[0]}"
    [ "$rc" -eq 0 ] && grep -qx 'E3_M3_VERIFY=PASS' "$verify_log" \
        || apply_fail "deploy verification failed"
    # Final closed-plane gate: independently re-measure every security and
    # no-restart invariant after the verifier.  Its V07 text is not trusted.
    [ "$("$SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)" = "active" ] \
        || apply_fail "final gate: helper socket is not active"
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)" = "enabled" ] \
        || apply_fail "final gate: helper socket is not enabled"
    [ "$("$SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)" = "active" ] \
        || apply_fail "final gate: first RPC did not leave helper service active"
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)" = "disabled" ] \
        || apply_fail "final gate: helper service must remain disabled"
    independent_status_inactive \
        || apply_fail "final gate: independent management status is not inactive"
    [ ! -e "$MARKER" ] || apply_fail "final gate: activation marker exists"
    invariants_hold || apply_fail "final gate: config or sing-box invariant drift"
    printf 'PASS final closed-plane gate: socket active/enabled; service active/disabled; management inactive; invariants unchanged\n'

    VERIFY_COMPLETED=true
    PHASE="complete"
    FINAL_STATUS="deploy_disabled_complete"
    journal_write
    printf 'PRODUCTION DEPLOYED = YES\n'
    printf 'E3 MANAGEMENT ENABLED = NO\n'
    printf 'management_state = inactive\n'
    printf 'M3-C Phase 2 = NOT STARTED\n'
    exit 0
}

cmd_recover() {
    local current_source
    RECOVERY_MODE=1
    source_identity_gate
    current_source="$SOURCE_HEAD"
    if [ ! -r "$JOURNAL" ] || ! jq -e '
        (.schema == 1) and
        (.monitor_mutation.started | type == "boolean") and
        (.monitor_mutation.completed | type == "boolean") and
        (.helper_install.started | type == "boolean") and
        (.helper_install.completed | type == "boolean") and
        (.socket_enable.started | type == "boolean") and
        (.socket_enable.completed | type == "boolean") and
        (.verify_completed | type == "boolean")
      ' "$JOURNAL" >/dev/null 2>&1; then
        baseline_load_validate
        PHASE="uncertain"
        MONITOR_STARTED=true
        MONITOR_COMPLETED=false
        HELPER_STARTED=true
        HELPER_COMPLETED=false
        SOCKET_STARTED=true
        SOCKET_COMPLETED=false
        VERIFY_COMPLETED=false
        FINAL_STATUS="uncertain"
        full_rollback "journal state is unavailable or uncertain; fail-closed full recovery required" || exit 1
        exit 1
    fi
    journal_load
    [ "$SOURCE_HEAD" = "$current_source" ] \
        || die "journal source_head does not match the approved recovery checkout"
    case "$FINAL_STATUS" in
        deploy_disabled_complete)
            die "Phase 1 is complete; recover is not an automatic uninstall command"
            ;;
        monitor_rollback_pass|full_rollback_pass)
            die "this Phase 1 attempt already ended in rollback"
            ;;
    esac
    recover_classified || exit 1
    # A recovered/interrupted attempt always ends here; it can never resume.
    exit 1
}

cmd_status() {
    [ -r "$JOURNAL" ] || { printf 'phase=not_started\n'; exit 0; }
    journal_load
    printf 'phase=%s\n' "$PHASE"
    printf 'baseline=%s\n' "$BASELINE"
    printf 'baseline_release_id=%s\n' "$BASE_RELEASE"
    printf 'baseline_release_target=%s\n' "$BASE_RELEASE_TARGET"
    printf 'monitor_mutation_started=%s completed=%s\n' "$MONITOR_STARTED" "$MONITOR_COMPLETED"
    printf 'helper_install_started=%s completed=%s\n' "$HELPER_STARTED" "$HELPER_COMPLETED"
    printf 'socket_enable_started=%s completed=%s\n' "$SOCKET_STARTED" "$SOCKET_COMPLETED"
    printf 'verify_completed=%s\n' "$VERIFY_COMPLETED"
    printf 'final_status=%s\n' "$FINAL_STATUS"
}

usage() {
    printf 'usage: %s {preflight|apply|recover|status}\n' "${0##*/}" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
    preflight) acquire_phase1_lock; cmd_preflight ;;
    apply)     acquire_phase1_lock; cmd_apply ;;
    recover)   acquire_phase1_lock; cmd_recover ;;
    status)    cmd_status ;;
    *)         usage ;;
esac
