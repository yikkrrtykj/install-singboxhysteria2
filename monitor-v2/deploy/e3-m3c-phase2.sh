#!/usr/bin/env bash
# E3 M3-C Phase 2: one production activation/canary/deactivation attempt.
#
# preflight is read-only with respect to the production plane; it only writes
# root-owned Phase 2 evidence.  canary is a separate, explicitly approved
# command.  All mutations cross the existing E3 RPC/transaction boundary.
set -uo pipefail

readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly PREFLIGHT_TTL_SECONDS=900
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
readonly RPC_BRIDGE="$SCRIPT_DIR/e3-m3c-phase2-rpc.py"

TEST_MODE="${E3_PHASE2_TEST_MODE:-0}"
if [ "$TEST_MODE" != 0 ] && [ "$TEST_MODE" != 1 ]; then
    printf 'ERROR: E3_PHASE2_TEST_MODE must be 0 or 1\n' >&2
    exit 2
fi

if [ "$TEST_MODE" = 1 ]; then
    PHASE1_STATE="${E3_PHASE2_TEST_PHASE1_STATE:?test Phase 1 state required}"
    STATE_DIR="${E3_PHASE2_TEST_STATE_DIR:?test Phase 2 state required}"
    CONFIG="${E3_PHASE2_TEST_CONFIG:?test config required}"
    MONITOR_APP="${E3_PHASE2_TEST_MONITOR_APP:?test monitor app required}"
    SBXCM_STATE="${E3_PHASE2_TEST_SBXCM_STATE:?test helper state required}"
    MONITOR_URL="${E3_PHASE2_TEST_MONITOR_URL:-http://fixture.invalid}"
    SYSTEMCTL="${E3_PHASE2_TEST_SYSTEMCTL:?test systemctl required}"
    CURL="${E3_PHASE2_TEST_CURL:?test curl required}"
    RPC_FIXTURE="${E3_PHASE2_TEST_RPC:?test RPC fixture required}"
    TEST_FIXTURE_ROOT="${E3_PHASE2_TEST_FIXTURE_ROOT:?test fixture root required}"
    TEST_SOURCE_HEAD="${E3_PHASE2_TEST_SOURCE_HEAD:?test source head required}"
    PHASE2_LOCK="${E3_PHASE2_TEST_LOCK:?test lock required}"
    MONITOR_DEPLOY_LOCK="${E3_PHASE2_TEST_MONITOR_LOCK:?test monitor deploy lock required}"
    FLOCK_BIN="${E3_PHASE2_TEST_FLOCK:-/usr/bin/flock}"
    LOCK_BACKEND="${E3_PHASE2_TEST_LOCK_BACKEND:-flock}"
    CONFIG_LOCK="${E3_PHASE2_TEST_CONFIG_LOCK:?test config lock required}"
    CONFIG_LOCK_BACKEND="${E3_PHASE2_TEST_CONFIG_LOCK_BACKEND:-flock}"
    LEDGER="${E3_PHASE2_TEST_LEDGER:?test ledger required}"
    TEST_NOW="${E3_PHASE2_TEST_NOW:-2000000000}"
    TEST_TOKEN="${E3_PHASE2_TEST_TOKEN:-0123456789abcdef}"
    TEST_CRASH_AFTER="${E3_PHASE2_TEST_CRASH_AFTER:-}"
    TEST_EVIDENCE_FAILURES="${E3_PHASE2_TEST_EVIDENCE_FAILURES:-}"
    EVIDENCE_BACKEND="${E3_PHASE2_TEST_EVIDENCE_BACKEND:-fixture}"
    TEST_PHASE1_ANCESTOR="${E3_PHASE2_TEST_PHASE1_ANCESTOR:?test Phase 1 ancestor required}"
    ROOT_RECOVERY="${E3_PHASE2_TEST_ROOT_RECOVERY:?test root recovery required}"
    RPC_PATH="$(dirname -- "$SYSTEMCTL"):$PATH"
else
    [ "$(id -u)" = 0 ] || { printf 'ERROR: Phase 2 must run as root\n' >&2; exit 1; }
    PATH="$SAFE_PATH"; export PATH
    PHASE1_STATE="/var/lib/e3-m3c-phase1"
    STATE_DIR="/var/lib/e3-m3c-phase2"
    CONFIG="/root/sbox/sbconfig_server.json"
    MONITOR_APP="/opt/singbox-monitor"
    SBXCM_STATE="/var/lib/sbox-cm"
    MONITOR_URL="http://127.0.0.1:9191"
    SYSTEMCTL="/usr/bin/systemctl"
    CURL="/usr/bin/curl"
    RPC_FIXTURE=""
    TEST_FIXTURE_ROOT=""
    TEST_SOURCE_HEAD=""
    PHASE2_LOCK="/run/lock/e3-m3c-phase2.lock"
    MONITOR_DEPLOY_LOCK="/run/lock/singbox-monitor-deploy.lock"
    FLOCK_BIN="/usr/bin/flock"
    LOCK_BACKEND="flock"
    CONFIG_LOCK="/root/sbox/config.lock"
    CONFIG_LOCK_BACKEND="flock"
    LEDGER="$SBXCM_STATE/ledger/cm-ledger.jsonl"
    TEST_NOW=""
    TEST_TOKEN=""
    TEST_CRASH_AFTER=""
    TEST_EVIDENCE_FAILURES=""
    EVIDENCE_BACKEND="real"
    TEST_PHASE1_ANCESTOR=""
    ROOT_RECOVERY="$REPO_ROOT/sbox-cm/deploy/install-sbox-cm.sh"
    RPC_PATH="$SAFE_PATH"
fi

readonly PHASE1_BASELINE="$PHASE1_STATE/baseline.json"
readonly PHASE1_JOURNAL="$PHASE1_STATE/journal.json"
readonly BASELINE="$STATE_DIR/baseline.json"
readonly JOURNAL="$STATE_DIR/journal.json"
readonly MARKER="$SBXCM_STATE/management.active"
readonly TX_JOURNAL_DIR="$SBXCM_STATE/journal"

SOURCE_HEAD=""
CREATED_EPOCH=0
BASE_CONFIG_SHA=""
BASE_CONFIG_SIZE=0
BASE_CONFIG_SEMANTIC_SHA=""
BASE_SING_TS=""
BASE_SING_RESTARTS=0
BASE_INVENTORY_SHA=""
BASE_INVENTORY_COUNT=0
BASE_SOURCE_HEAD=""
BASE_CREATED_EPOCH=0
BASE_CANARY_NAME=""
BASE_ADD_KEY=""
BASE_DELETE_KEY=""
BASE_LIVE_MONITOR_TARGET=""
BASE_LIVE_RPC_SHA=""
RPC_APP_ROOT=""
CANARY_NAME=""
ADD_KEY=""
DELETE_KEY=""
PHASE="new"
ACTIVATION_STARTED=false
ACTIVATION_COMPLETED=false
ADD_STARTED=false
ADD_COMPLETED=false
DELETE_STARTED=false
DELETE_COMPLETED=false
DEACTIVATION_STARTED=false
DEACTIVATION_COMPLETED=false
FINAL_STATUS="not_started"
ACTIVATION_RESULT=null
ADD_RESULT=null
DELETE_RESULT=null
DEACTIVATION_RESULT=null
FINAL_MEASUREMENTS=null
EVIDENCE_FAILED=false

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
critical() { printf 'CRITICAL: %s\n' "$*" >&2; exit 1; }

now_epoch() {
    if [ "$TEST_MODE" = 1 ]; then printf '%s\n' "$TEST_NOW"; else date +%s; fi
}

acquire_lock() {
    local parent
    parent="$(dirname -- "$PHASE2_LOCK")"
    mkdir -p -- "$parent" || die "cannot create Phase 2 lock directory"
    if [ "$TEST_MODE" = 1 ] && [ "$LOCK_BACKEND" = mkdir ]; then
        mkdir -- "$PHASE2_LOCK.fixture-held" 2>/dev/null \
            || die "another Phase 2 command holds the exclusive lock"
        trap 'rmdir -- "$PHASE2_LOCK.fixture-held" 2>/dev/null || true' EXIT
        return 0
    fi
    [ "$LOCK_BACKEND" = flock ] || die "invalid Phase 2 lock backend"
    [ -x "$FLOCK_BIN" ] || die "Phase 2 flock is unavailable"
    umask 077
    exec 8>>"$PHASE2_LOCK" || die "cannot open Phase 2 lock"
    chmod 0600 "$PHASE2_LOCK" || die "cannot protect Phase 2 lock"
    "$FLOCK_BIN" -n 8 || die "another Phase 2 command holds the exclusive lock"
}

acquire_monitor_deploy_lock() {
    local parent
    parent="$(dirname -- "$MONITOR_DEPLOY_LOCK")"
    mkdir -p -- "$parent" || die "cannot create monitor deployment lock directory"
    if [ "$TEST_MODE" = 1 ] && [ "$LOCK_BACKEND" = mkdir ]; then
        mkdir -- "$MONITOR_DEPLOY_LOCK.fixture-held" 2>/dev/null \
            || die "monitor deployment lock is held; refusing Phase 2 command"
        trap 'rmdir -- "$PHASE2_LOCK.fixture-held" "$MONITOR_DEPLOY_LOCK.fixture-held" 2>/dev/null || true' EXIT
        return 0
    fi
    [ "$LOCK_BACKEND" = flock ] || die "invalid monitor deployment lock backend"
    [ -x "$FLOCK_BIN" ] || die "Phase 2 flock is unavailable"
    umask 077
    exec 7>>"$MONITOR_DEPLOY_LOCK" || die "cannot open canonical monitor deployment lock"
    "$FLOCK_BIN" -n 7 || die "monitor deployment lock is held; refusing Phase 2 command"
}

acquire_command_locks() {
    # Global order is fixed: Phase 2 lock first, canonical monitor deploy lock
    # second. Monitor deployment takes only its own lock, so no reverse edge
    # exists. Both locks remain held by their FDs until the command exits.
    acquire_lock
    acquire_monitor_deploy_lock
}

source_identity_gate() {
    local approved dirty
    approved="${E3_PHASE2_APPROVED_HEAD:-}"
    if [ "$TEST_MODE" = 1 ]; then
        SOURCE_HEAD="$TEST_SOURCE_HEAD"
        [ -n "$approved" ] && [ "$SOURCE_HEAD" = "$approved" ] \
            || die "checkout HEAD does not equal E3_PHASE2_APPROVED_HEAD"
        return 0
    fi
    [[ "$approved" =~ ^[0-9a-f]{40}$ ]] \
        || die "E3_PHASE2_APPROVED_HEAD must be the exact reviewed 40-hex merge SHA"
    SOURCE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)" || die "cannot resolve source HEAD"
    [ "$SOURCE_HEAD" = "$approved" ] \
        || die "checkout HEAD does not equal E3_PHASE2_APPROVED_HEAD"
    dirty="$(git -C "$REPO_ROOT" status --porcelain)"
    [ -z "$dirty" ] || die "source checkout is dirty"
    [ -f "$RPC_BRIDGE" ] || die "reviewed Phase 2 RPC adapter is missing"
    printf 'PASS source identity: checkout=%s\n' "$SOURCE_HEAD"
}

ensure_state_dir() {
    umask 077
    mkdir -p -- "$STATE_DIR" || return 1
    chmod 0700 "$STATE_DIR" || return 1
    if [ "$TEST_MODE" = 0 ]; then
        chown root:root "$STATE_DIR" || return 1
        [ "$(stat -c '%U %G %a' "$STATE_DIR")" = 'root root 700' ] \
            || return 1
    fi
}

evidence_injected_failure() { # context stage
    [ "$TEST_MODE" = 1 ] || return 1
    case ",${TEST_EVIDENCE_FAILURES}," in
      *",$1:$2,"*|*",*:$2,"*)
        printf 'INJECTED evidence failure: %s:%s\n' "$1" "$2" >&2
        return 0
        ;;
    esac
    return 1
}

evidence_fsync() { # path context stage
    local path="$1" context="$2" stage="$3"
    evidence_injected_failure "$context" "$stage" && return 1
    if [ "$TEST_MODE" = 1 ] && [ "$EVIDENCE_BACKEND" = fixture ]; then return 0; fi
    [ "$EVIDENCE_BACKEND" = real ] || return 1
    sync -f "$path" 2>/dev/null || command sync 2>/dev/null
}

atomic_json_write() { # path context; JSON on stdin
    local path="$1" context="$2" tmp dir
    ensure_state_dir || { printf 'ERROR: cannot protect Phase 2 state\n' >&2; return 1; }
    dir="$(dirname -- "$path")"
    [ ! -L "$path" ] || { printf 'ERROR: refusing symlink evidence target\n' >&2; return 1; }
    tmp="$(mktemp "$STATE_DIR/.json.tmp.XXXXXX")" || return 1
    if evidence_injected_failure "$context" write || ! jq -c . >"$tmp"; then
        rm -f -- "$tmp"; return 1
    fi
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    if [ "$TEST_MODE" = 0 ]; then chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }; fi
    evidence_fsync "$tmp" "$context" file_fsync || { rm -f -- "$tmp"; return 1; }
    if evidence_injected_failure "$context" rename || ! mv -f -- "$tmp" "$path"; then
        rm -f -- "$tmp"; return 1
    fi
    evidence_fsync "$dir" "$context" dir_fsync || return 1
    return 0
}

# Direct field lookup preserves false/true; missing and explicit null remain null.
sanitize_result() {
    jq -c '{ok:(.ok // false),code:(.code // null),stage:(.stage // null),
      data:(if (.data|type)=="object" then {
        management_state:(.data.management_state // null),
        no_op:.data.no_op,name:(.data.name // null),
        deleted:.data.deleted,derived_cleanup:.data.derived_cleanup
      } else null end),idempotency:(.idempotency // null),
      transaction:(.transaction // null),transport_error:(.transport_error // null),
      adapter_error:(.adapter_error // null)}' 2>/dev/null
}

journal_write() { # evidence context; returns failure, never exits
    local context="${1:-journal}"
    if ! jq -n \
      --arg source "$SOURCE_HEAD" --arg phase "$PHASE" --arg baseline "$BASELINE" \
      --arg name "$CANARY_NAME" --arg add_key "$ADD_KEY" --arg delete_key "$DELETE_KEY" \
      --arg final "$FINAL_STATUS" --arg updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --argjson created "$CREATED_EPOCH" \
      --argjson activation_started "$ACTIVATION_STARTED" \
      --argjson activation_completed "$ACTIVATION_COMPLETED" \
      --argjson add_started "$ADD_STARTED" --argjson add_completed "$ADD_COMPLETED" \
      --argjson delete_started "$DELETE_STARTED" --argjson delete_completed "$DELETE_COMPLETED" \
      --argjson deactivation_started "$DEACTIVATION_STARTED" \
      --argjson deactivation_completed "$DEACTIVATION_COMPLETED" \
      --argjson activation_result "$ACTIVATION_RESULT" --argjson add_result "$ADD_RESULT" \
      --argjson delete_result "$DELETE_RESULT" --argjson deactivation_result "$DEACTIVATION_RESULT" \
      --argjson final_measurements "$FINAL_MEASUREMENTS" '
      {schema:1,source_head:$source,phase:$phase,baseline_path:$baseline,
       preflight_created_epoch:$created,
       canary:{name:$name,add_idempotency_key:$add_key,delete_idempotency_key:$delete_key},
       activation:{started:$activation_started,completed:$activation_completed,result:$activation_result},
       add:{started:$add_started,completed:$add_completed,result:$add_result},
       delete:{started:$delete_started,completed:$delete_completed,result:$delete_result},
       deactivation:{started:$deactivation_started,completed:$deactivation_completed,result:$deactivation_result},
       final_measurements:$final_measurements,final_status:$final,updated_at:$updated}' \
      | atomic_json_write "$JOURNAL" "$context"; then
        printf 'ERROR: Phase 2 journal checkpoint is not durable (%s)\n' "$context" >&2
        return 1
    fi
    return 0
}

journal_write_strict() {
    journal_write "$1" || die "cannot durably write the Phase 2 journal"
}

cleanup_evidence_write() {
    if ! journal_write "$1"; then
        EVIDENCE_FAILED=true
        printf 'CRITICAL: cleanup evidence write failed at %s; cleanup will continue\n' "$1" >&2
        return 1
    fi
    return 0
}

postactivation_checkpoint() {
    local context="$1"
    if ! journal_write "$context"; then
        EVIDENCE_FAILED=true
        cleanup_attempt "post-activation evidence failure at $context" || true
        exit 1
    fi
}

journal_load() {
    [ -r "$JOURNAL" ] || { printf 'ERROR: Phase 2 journal is unavailable\n' >&2; return 1; }
    jq -e '.schema==1' "$JOURNAL" >/dev/null 2>&1 \
        || { printf 'ERROR: Phase 2 journal is invalid\n' >&2; return 1; }
    SOURCE_HEAD="$(jq -er '.source_head' "$JOURNAL")" || return 1
    PHASE="$(jq -er '.phase' "$JOURNAL")" || return 1
    CREATED_EPOCH="$(jq -er '.preflight_created_epoch' "$JOURNAL")" || return 1
    CANARY_NAME="$(jq -er '.canary.name' "$JOURNAL")" || return 1
    ADD_KEY="$(jq -er '.canary.add_idempotency_key' "$JOURNAL")" || return 1
    DELETE_KEY="$(jq -er '.canary.delete_idempotency_key' "$JOURNAL")" || return 1
    ACTIVATION_STARTED="$(jq -r '.activation.started' "$JOURNAL")"
    ACTIVATION_COMPLETED="$(jq -r '.activation.completed' "$JOURNAL")"
    ADD_STARTED="$(jq -r '.add.started' "$JOURNAL")"
    ADD_COMPLETED="$(jq -r '.add.completed' "$JOURNAL")"
    DELETE_STARTED="$(jq -r '.delete.started' "$JOURNAL")"
    DELETE_COMPLETED="$(jq -r '.delete.completed' "$JOURNAL")"
    DEACTIVATION_STARTED="$(jq -r '.deactivation.started' "$JOURNAL")"
    DEACTIVATION_COMPLETED="$(jq -r '.deactivation.completed' "$JOURNAL")"
    ACTIVATION_RESULT="$(jq -c '.activation.result' "$JOURNAL")"
    ADD_RESULT="$(jq -c '.add.result' "$JOURNAL")"
    DELETE_RESULT="$(jq -c '.delete.result' "$JOURNAL")"
    DEACTIVATION_RESULT="$(jq -c '.deactivation.result' "$JOURNAL")"
    FINAL_MEASUREMENTS="$(jq -c '.final_measurements' "$JOURNAL")"
    FINAL_STATUS="$(jq -er '.final_status' "$JOURNAL")" || return 1
    local value
    for value in "$ACTIVATION_STARTED" "$ACTIVATION_COMPLETED" "$ADD_STARTED" \
      "$ADD_COMPLETED" "$DELETE_STARTED" "$DELETE_COMPLETED" \
      "$DEACTIVATION_STARTED" "$DEACTIVATION_COMPLETED"; do
        [ "$value" = true ] || [ "$value" = false ] || return 1
    done
    [[ "$SOURCE_HEAD" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "$CANARY_NAME" =~ ^m3c-[0-9a-f]{16}$ ]] || return 1
    [[ "$ADD_KEY" =~ ^m3c2-add-[0-9a-f]{16}$ ]] || return 1
    [[ "$DELETE_KEY" =~ ^m3c2-del-[0-9a-f]{16}$ ]] || return 1
    return 0
}

phase1_gate() {
    local p1_source
    [ -r "$PHASE1_BASELINE" ] && [ -r "$PHASE1_JOURNAL" ] \
        || die "successful Phase 1 evidence is unavailable"
    [ ! -L "$PHASE1_BASELINE" ] && [ ! -L "$PHASE1_JOURNAL" ] \
        || die "Phase 1 evidence must not be symlinks"
    if [ "$TEST_MODE" = 0 ] || [ "$(uname -s 2>/dev/null)" = Linux ]; then
        [ "$(stat -c '%a' "$PHASE1_BASELINE")" = 600 ] &&
        [ "$(stat -c '%a' "$PHASE1_JOURNAL")" = 600 ] \
            || die "Phase 1 evidence is not mode 0600"
    fi
    if [ "$TEST_MODE" = 0 ]; then
        [ "$(stat -c '%u %g' "$PHASE1_BASELINE")" = '0 0' ] &&
        [ "$(stat -c '%u %g' "$PHASE1_JOURNAL")" = '0 0' ] \
            || die "Phase 1 evidence is not root:root"
    fi
    jq -e '
      .schema==1 and .phase=="complete" and .final_status=="deploy_disabled_complete" and
      .monitor_mutation.started==true and .monitor_mutation.completed==true and
      .helper_install.started==true and .helper_install.completed==true and
      .socket_enable.started==true and .socket_enable.completed==true and
      .verify_completed==true
    ' "$PHASE1_JOURNAL" >/dev/null || die "Phase 1 journal is not complete"
    jq -e '
      (.config_sha256|type=="string" and length==64) and
      (.config_size|type=="number" and .>0) and
      (.singbox.active=="active") and
      (.singbox.active_enter_timestamp|type=="string" and length>0) and
      (.singbox.nrestarts|type=="number")
    ' "$PHASE1_BASELINE" >/dev/null || die "Phase 1 baseline is invalid"
    p1_source="$(jq -er '.source_head' "$PHASE1_JOURNAL")" \
        || die "Phase 1 source_head is unavailable"
    [[ "$p1_source" =~ ^[0-9a-f]{40}$ ]] \
        || die "Phase 1 source_head is not a 40-hex commit"
    if [ "$TEST_MODE" = 1 ]; then
        [ "$p1_source" = "$TEST_PHASE1_ANCESTOR" ] \
            || die "Phase 1 source is not an approved test ancestor"
    else
        git -C "$REPO_ROOT" merge-base --is-ancestor "$p1_source" "$SOURCE_HEAD" \
            || die "Phase 1 source is not an ancestor of the approved Phase 2 HEAD"
    fi
}

baseline_load() {
    [ -r "$BASELINE" ] || die "successful fresh Phase 2 preflight is unavailable"
    jq -e '
      .schema==1 and
      (.source_head|type=="string" and test("^[0-9a-f]{40}$")) and
      (.created_epoch|type=="number") and
      (.canary.name|type=="string" and test("^m3c-[0-9a-f]{16}$")) and
      (.canary.add_idempotency_key|type=="string" and test("^m3c2-add-[0-9a-f]{16}$")) and
      (.canary.delete_idempotency_key|type=="string" and test("^m3c2-del-[0-9a-f]{16}$")) and
      (.live_rpc.target|type=="string" and length>0) and
      (.live_rpc.sha256|type=="string" and test("^[0-9a-f]{64}$"))
    ' "$BASELINE" >/dev/null 2>&1 || die "Phase 2 baseline is invalid"
    BASE_SOURCE_HEAD="$(jq -er '.source_head' "$BASELINE")"
    BASE_CREATED_EPOCH="$(jq -er '.created_epoch' "$BASELINE")"
    BASE_CANARY_NAME="$(jq -er '.canary.name' "$BASELINE")"
    BASE_ADD_KEY="$(jq -er '.canary.add_idempotency_key' "$BASELINE")"
    BASE_DELETE_KEY="$(jq -er '.canary.delete_idempotency_key' "$BASELINE")"
    BASE_LIVE_MONITOR_TARGET="$(jq -er '.live_rpc.target' "$BASELINE")"
    BASE_LIVE_RPC_SHA="$(jq -er '.live_rpc.sha256' "$BASELINE")"
    BASE_CONFIG_SHA="$(jq -er '.config.sha256' "$BASELINE")"
    BASE_CONFIG_SIZE="$(jq -er '.config.size' "$BASELINE")"
    BASE_CONFIG_SEMANTIC_SHA="$(jq -er '.config.semantic_sha256' "$BASELINE")"
    BASE_SING_TS="$(jq -er '.singbox.active_enter_timestamp' "$BASELINE")"
    BASE_SING_RESTARTS="$(jq -er '.singbox.nrestarts' "$BASELINE")"
    BASE_INVENTORY_SHA="$(jq -er '.inventory.sha256' "$BASELINE")"
    BASE_INVENTORY_COUNT="$(jq -er '.inventory.count' "$BASELINE")"
    if [ "$TEST_MODE" = 0 ] || [ "$(uname -s 2>/dev/null)" = Linux ]; then
        [ "$(stat -c %a "$BASELINE")" = 600 ] || die "Phase 2 baseline is not 0600"
    fi
    if [ "$TEST_MODE" = 0 ]; then
        [ "$(stat -c '%u %g' "$BASELINE")" = '0 0' ] \
            || die "Phase 2 baseline is not root:root"
    fi
}

live_rpc_source_gate() { # optional expected target/hash
    local target live_rpc reviewed_rpc live_sha reviewed_sha
    target="$(readlink -f -- "$MONITOR_APP" 2>/dev/null)" \
        || { printf 'ERROR: cannot resolve the live monitor release target\n' >&2; return 1; }
    if [ "$TEST_MODE" = 1 ] && command -v cygpath >/dev/null 2>&1; then
        target="$(cygpath -m "$target")"
    fi
    live_rpc="$target/app/monitor-v2/web/e3rpc.py"
    reviewed_rpc="$REPO_ROOT/monitor-v2/web/e3rpc.py"
    [ -f "$live_rpc" ] && [ ! -L "$live_rpc" ] && [ -r "$live_rpc" ] \
        || { printf 'ERROR: live monitor RPC implementation is unavailable or unsafe\n' >&2; return 1; }
    [ -f "$reviewed_rpc" ] && [ -r "$reviewed_rpc" ] \
        || { printf 'ERROR: reviewed checkout RPC implementation is unavailable\n' >&2; return 1; }
    live_sha="$(sha256sum "$live_rpc" | awk '{print $1}')"
    reviewed_sha="$(sha256sum "$reviewed_rpc" | awk '{print $1}')"
    [ "$live_sha" = "$reviewed_sha" ] \
        || { printf 'ERROR: live monitor RPC implementation differs from the approved checkout\n' >&2; return 1; }
    if [ -n "$BASE_LIVE_MONITOR_TARGET" ]; then
        [ "$target" = "$BASE_LIVE_MONITOR_TARGET" ] && [ "$live_sha" = "$BASE_LIVE_RPC_SHA" ] \
            || { printf 'ERROR: live monitor RPC target/hash drifted since Phase 2 preflight\n' >&2; return 1; }
    fi
    CURRENT_LIVE_MONITOR_TARGET="$target"
    CURRENT_LIVE_RPC_SHA="$live_sha"
    RPC_APP_ROOT="$target/app/monitor-v2"
}

rpc_call() { # op payload-json
    local op="$1" payload="$2"
    case "$op" in
      management.status|management.activate|management.deactivate|client.list|client.add|client.delete) ;;
      *) die "RPC operation is not allowed: $op" ;;
    esac
    if [ "$TEST_MODE" = 1 ]; then
        printf '%s' "$payload" | env -i PATH="$RPC_PATH" HOME="$STATE_DIR" LC_ALL=C \
          FX="$TEST_FIXTURE_ROOT" RPC_APP_ROOT="$RPC_APP_ROOT" /usr/bin/bash "$RPC_FIXTURE" "$op"
    else
        [ -n "$RPC_APP_ROOT" ] && [ -d "$RPC_APP_ROOT" ] &&
        [ -r "$RPC_APP_ROOT/web/e3rpc.py" ] || {
            printf 'ERROR: pinned reviewed RPC app root became unavailable\n' >&2
            return 70
        }
        env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C \
          /usr/bin/sudo -n -u sboxweb /usr/bin/python3 -B - \
          "$op" "$RPC_APP_ROOT" "$payload" <"$RPC_BRIDGE"
    fi
}

config_measure() {
    CURRENT_CONFIG_SHA="$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')"
    CURRENT_CONFIG_SIZE="$(stat -c %s "$CONFIG" 2>/dev/null || true)"
    CURRENT_CONFIG_SEMANTIC_SHA="$(jq -cS . "$CONFIG" 2>/dev/null | sha256sum | awk '{print $1}')"
}

singbox_measure() {
    CURRENT_SING_ACTIVE="$("$SYSTEMCTL" is-active sing-box.service 2>/dev/null || true)"
    CURRENT_SING_TS="$("$SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"
    CURRENT_SING_RESTARTS="$("$SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"
}

monitor_healthy() {
    [ "$("$CURL" -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      "$MONITOR_URL/api/v1/session" 2>/dev/null || true)" = 200 ]
}

tx_state_clean() {
    [ ! -e "$SBXCM_STATE/degraded.json" ] || return 1
    local f
    for f in "$TX_JOURNAL_DIR"/*.json; do [ ! -e "$f" ] || return 1; done
    return 0
}

config_lock_free() {
    if [ "$TEST_MODE" = 1 ] && [ "$CONFIG_LOCK_BACKEND" = fixture ]; then
        [ ! -e "$TEST_FIXTURE_ROOT/config-lock-busy" ]
        return
    fi
    [ "$CONFIG_LOCK_BACKEND" = flock ] || return 1
    [ -e "$CONFIG_LOCK" ] || return 0
    [ -f "$CONFIG_LOCK" ] || return 1
    ( exec 9<"$CONFIG_LOCK" 2>/dev/null && "$FLOCK_BIN" -n 9 2>/dev/null ) >/dev/null 2>&1
}

units_closed_plane() {
    [ "$("$SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null || true)" = active ] &&
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null || true)" = enabled ] &&
    [ "$("$SYSTEMCTL" is-active sbox-cm.service 2>/dev/null || true)" = active ] &&
    [ "$("$SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null || true)" = disabled ]
}

status_inactive_clean() { # JSON
    local j="$1"
    [ "$(printf '%s' "$j" | jq -r '.ok // false')" = true ] &&
    [ "$(printf '%s' "$j" | jq -r '.data.management_state // empty')" = inactive ] &&
    [ "$(printf '%s' "$j" | jq -r '.data.helper.degraded == false')" = true ] &&
    [ "$(printf '%s' "$j" | jq -r '.data.helper.reconcile // empty')" = clean ] &&
    [ "$(printf '%s' "$j" | jq -r '.data.lock.acquirable == true')" = true ]
}

inventory_measure() { # list JSON -> CURRENT_INVENTORY_*
    local j="$1" canonical
    [ "$(printf '%s' "$j" | jq -r '.ok // false')" = true ] || return 1
    [ "$(printf '%s' "$j" | jq -r '.data.truncated == false')" = true ] || return 1
    canonical="$(printf '%s' "$j" | jq -cS '.data.clients | sort_by(.name)')" || return 1
    CURRENT_INVENTORY_SHA="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
    CURRENT_INVENTORY_COUNT="$(printf '%s' "$j" | jq -r '.data.clients | length')"
}

preactivation_gates() { # sets STATUS_JSON
    phase1_gate
    config_measure; singbox_measure
    [ "$CURRENT_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] &&
    [ "$CURRENT_CONFIG_SIZE" = "$BASE_CONFIG_SIZE" ] &&
    [ "$CURRENT_CONFIG_SEMANTIC_SHA" = "$BASE_CONFIG_SEMANTIC_SHA" ] \
        || die "config differs from the Phase 1 baseline"
    [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] &&
    [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ] \
        || die "sing-box state differs from the Phase 1 baseline"
    monitor_healthy || die "monitor HTTP is unhealthy"
    units_closed_plane || die "helper units violate the closed-plane contract"
    [ ! -e "$MARKER" ] || die "activation marker exists before activation"
    tx_state_clean || die "helper is degraded or has unresolved transaction journals"
    config_lock_free || die "config lock is not independently acquirable"
    STATUS_JSON="$(rpc_call management.status '{}')" || die "management.status transport failed"
    status_inactive_clean "$STATUS_JSON" \
        || die "management.status is not inactive/clean/lock-acquirable"
}

generate_token() {
    if [ "$TEST_MODE" = 1 ]; then printf '%s\n' "$TEST_TOKEN"; return; fi
    /usr/bin/od -An -N8 -tx1 /dev/urandom | tr -d ' \n'
}

maybe_test_crash() {
    if [ "$TEST_MODE" = 1 ] && [ -n "$TEST_CRASH_AFTER" ] && [ "$TEST_CRASH_AFTER" = "$1" ]; then
        printf 'TEST CRASH after %s\n' "$1" >&2
        exit 99
    fi
}

canary_present_in() { # list JSON
    [ "$(printf '%s' "$1" | jq --arg n "$CANARY_NAME" '[.data.clients[]|select(.name==$n)]|length')" = 1 ]
}

inventory_without_canary_matches() { # list JSON
    local canonical sha
    canonical="$(printf '%s' "$1" | jq -cS --arg n "$CANARY_NAME" \
      '[.data.clients[]|select(.name!=$n)]|sort_by(.name)')" || return 1
    sha="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
    [ "$sha" = "$BASE_INVENTORY_SHA" ]
}

delete_retry_attributable() {
    [ -r "$LEDGER" ] || return 1
    jq -s -e --arg key "$DELETE_KEY" --arg name "$CANARY_NAME" \
      'any(.[]; .kind=="intent" and .key==$key and .op=="client.delete" and
        .name==$name and .state=="in_flight" and
        (.old_cred_digest|type=="string" and test("^[0-9a-f]{64}$")))' \
      "$LEDGER" >/dev/null 2>&1
}

final_measure() {
    local status_json="$1" list_json="$2"
    config_measure; singbox_measure; inventory_measure "$list_json" || return 1
    FINAL_MEASUREMENTS="$(jq -n \
      --arg sha "$CURRENT_CONFIG_SHA" --argjson size "$CURRENT_CONFIG_SIZE" \
      --arg sem "$CURRENT_CONFIG_SEMANTIC_SHA" --arg inv "$CURRENT_INVENTORY_SHA" \
      --argjson count "$CURRENT_INVENTORY_COUNT" --arg ts "$CURRENT_SING_TS" \
      --argjson nr "$CURRENT_SING_RESTARTS" \
      --arg state "$(printf '%s' "$status_json" | jq -r '.data.management_state // empty')" \
      '{config:{sha256:$sha,size:$size,semantic_sha256:$sem},inventory:{sha256:$inv,count:$count},
        singbox:{active_enter_timestamp:$ts,nrestarts:$nr},management_state:$state}')"
    # Canonical add/delete may reserialize JSON.  Final equivalence is therefore
    # the semantic config digest plus the exact client inventory, not raw bytes.
    [ "$CURRENT_CONFIG_SEMANTIC_SHA" = "$BASE_CONFIG_SEMANTIC_SHA" ] &&
    [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] &&
    [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] &&
    [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] &&
    [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ] &&
    [ "$(printf '%s' "$status_json" | jq -r '.data.management_state // empty')" = inactive ] &&
    [ ! -e "$MARKER" ] && tx_state_clean && monitor_healthy
}

root_recovery_deactivate() {
    if [ "$TEST_MODE" = 1 ]; then
        env -i PATH="$RPC_PATH" HOME="$STATE_DIR" LC_ALL=C FX="$TEST_FIXTURE_ROOT" \
          /usr/bin/bash "$ROOT_RECOVERY"
    else
        env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C \
          /usr/bin/bash "$ROOT_RECOVERY" recover
    fi
}

cleanup_attempt() { # returns 0 only when exact pre-canary state is restored
    local reason="$1" status_json="" list_json="" result="" state="" cleanup_bad=0
    printf 'STOP+CLEANUP: %s\n' "$reason" >&2
    PHASE=cleanup_started; FINAL_STATUS=cleanup_in_progress
    cleanup_evidence_write cleanup_started || cleanup_bad=1
    status_json="$(rpc_call management.status '{}')" || cleanup_bad=1
    list_json="$(rpc_call client.list '{}')" || cleanup_bad=1
    if [ -n "$list_json" ] && canary_present_in "$list_json"; then
        if delete_retry_attributable; then
            DELETE_STARTED=true; PHASE=cleanup_delete_started
            cleanup_evidence_write cleanup_delete_started || cleanup_bad=1
            result="$(rpc_call client.delete "$(jq -cn --arg n "$CANARY_NAME" --arg k "$DELETE_KEY" '{name:$n,idempotency_key:$k}')")"
            if [ "$?" -eq 0 ] && [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ]; then
                DELETE_COMPLETED=true
                DELETE_RESULT="$(printf '%s' "$result" | sanitize_result)"
            else
                cleanup_bad=1
            fi
            PHASE=cleanup_delete_finished
            cleanup_evidence_write cleanup_delete_finished || cleanup_bad=1
        else
            printf 'CRITICAL: client name exists without a generation-bound DELETE intent; refusing delete\n' >&2
            cleanup_bad=1
        fi
    fi
    DEACTIVATION_STARTED=true; PHASE=cleanup_deactivation_started
    cleanup_evidence_write cleanup_deactivation_started || cleanup_bad=1
    state="$(printf '%s' "$status_json" | jq -r '.data.management_state // empty' 2>/dev/null)"
    if [ "$state" = active_stale ]; then
        if root_recovery_deactivate; then
            DEACTIVATION_COMPLETED=true
            DEACTIVATION_RESULT='{"ok":true,"code":"ROOT_RECOVERY"}'
        else
            cleanup_bad=1
        fi
    else
        result="$(rpc_call management.deactivate '{}')"
        if [ "$?" -eq 0 ] && [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ]; then
            DEACTIVATION_COMPLETED=true
            DEACTIVATION_RESULT="$(printf '%s' "$result" | sanitize_result)"
        else
            printf 'CRITICAL: reviewed RPC deactivation unavailable; attempting sanctioned root recovery\n' >&2
            if root_recovery_deactivate; then
                DEACTIVATION_COMPLETED=true
                DEACTIVATION_RESULT='{"ok":true,"code":"ROOT_RECOVERY_AFTER_RPC_FAILURE"}'
            else
                cleanup_bad=1
            fi
        fi
    fi
    PHASE=cleanup_deactivation_finished
    cleanup_evidence_write cleanup_deactivation_finished || cleanup_bad=1
    status_json="$(rpc_call management.status '{}')" || cleanup_bad=1
    list_json="$(rpc_call client.list '{}')" || cleanup_bad=1
    if [ "$EVIDENCE_FAILED" = true ]; then cleanup_bad=1; fi
    if [ "$cleanup_bad" -eq 0 ] && status_inactive_clean "$status_json" \
      && ! canary_present_in "$list_json" && final_measure "$status_json" "$list_json"; then
        PHASE=recovered; FINAL_STATUS=cleanup_complete
        cleanup_evidence_write cleanup_complete || {
            printf 'CRITICAL: cleanup succeeded but durable completion evidence failed; manual intervention required\n' >&2
            return 1
        }
        printf 'CLEANUP PASS: canary absent and management inactive\n'
        return 0
    fi
    PHASE=critical; FINAL_STATUS=manual_intervention
    cleanup_evidence_write cleanup_manual_intervention || true
    if [ "$EVIDENCE_FAILED" = true ]; then
        printf 'CRITICAL: Phase 2 evidence durability failed; manual intervention required\n' >&2
    fi
    printf 'CRITICAL: Phase 2 cleanup could not prove the pre-canary state\n' >&2
    return 1
}

canary_fail() {
    local reason="$1"
    if [ "$ACTIVATION_STARTED" = true ]; then cleanup_attempt "$reason" || true; fi
    exit 1
}

cmd_preflight() {
    local list_json token p1_source
    [ ! -e "$STATE_DIR" ] || die "Phase 2 state already exists; use status or recover"
    source_identity_gate
    phase1_gate
    live_rpc_source_gate || die "live RPC source identity gate failed"
    BASE_CONFIG_SHA="$(jq -er '.config_sha256' "$PHASE1_BASELINE")"
    BASE_CONFIG_SIZE="$(jq -er '.config_size' "$PHASE1_BASELINE")"
    BASE_SING_TS="$(jq -er '.singbox.active_enter_timestamp' "$PHASE1_BASELINE")"
    BASE_SING_RESTARTS="$(jq -er '.singbox.nrestarts' "$PHASE1_BASELINE")"
    config_measure
    BASE_CONFIG_SEMANTIC_SHA="$CURRENT_CONFIG_SEMANTIC_SHA"
    [ "$CURRENT_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] && [ "$CURRENT_CONFIG_SIZE" = "$BASE_CONFIG_SIZE" ] \
        || die "config SHA/size differs from Phase 1 baseline"
    preactivation_gates
    list_json="$(rpc_call client.list '{}')" || die "client.list failed"
    inventory_measure "$list_json" || die "client.list is invalid or truncated"
    BASE_INVENTORY_SHA="$CURRENT_INVENTORY_SHA"
    BASE_INVENTORY_COUNT="$CURRENT_INVENTORY_COUNT"
    token="$(generate_token)"
    [[ "$token" =~ ^[0-9a-f]{16}$ ]] || die "canary token generation failed"
    CANARY_NAME="m3c-$token"; ADD_KEY="m3c2-add-$token"; DELETE_KEY="m3c2-del-$token"
    ! canary_present_in "$list_json" || die "generated canary name already exists"
    CREATED_EPOCH="$(now_epoch)"
    p1_source="$(jq -er '.source_head' "$PHASE1_JOURNAL")"
    if ! jq -n --arg source "$SOURCE_HEAD" --argjson created "$CREATED_EPOCH" \
      --arg p1_source "$p1_source" --arg p1_baseline "$PHASE1_BASELINE" --arg p1_journal "$PHASE1_JOURNAL" \
      --arg name "$CANARY_NAME" --arg add_key "$ADD_KEY" --arg delete_key "$DELETE_KEY" \
      --arg live_target "$CURRENT_LIVE_MONITOR_TARGET" --arg live_sha "$CURRENT_LIVE_RPC_SHA" \
      --arg sha "$BASE_CONFIG_SHA" --argjson size "$BASE_CONFIG_SIZE" \
      --arg sem "$BASE_CONFIG_SEMANTIC_SHA" --arg ts "$BASE_SING_TS" \
      --argjson nr "$BASE_SING_RESTARTS" --arg inv "$BASE_INVENTORY_SHA" \
      --argjson count "$BASE_INVENTORY_COUNT" '
      {schema:1,source_head:$source,created_epoch:$created,
       phase1:{source_head:$p1_source,baseline_path:$p1_baseline,journal_path:$p1_journal},
       canary:{name:$name,add_idempotency_key:$add_key,delete_idempotency_key:$delete_key},
       live_rpc:{target:$live_target,sha256:$live_sha},
       config:{sha256:$sha,size:$size,semantic_sha256:$sem},
       singbox:{active:"active",active_enter_timestamp:$ts,nrestarts:$nr},
       inventory:{sha256:$inv,count:$count},management_state:"inactive"}' \
      | atomic_json_write "$BASELINE" baseline; then
        die "cannot serialize the Phase 2 baseline"
    fi
    PHASE=preflight_complete; FINAL_STATUS=ready_for_separate_canary_approval
    journal_write_strict preflight_complete
    printf 'PHASE2 PREFLIGHT=PASS\n'
    printf 'HARD STOP: do not run canary without separate operator approval\n'
}

cmd_canary() {
    local current_source age result list_json status_json expected_count
    source_identity_gate; current_source="$SOURCE_HEAD"
    journal_load || die "Phase 2 journal is unavailable or invalid"
    baseline_load
    [ "$SOURCE_HEAD" = "$current_source" ] && [ "$BASE_SOURCE_HEAD" = "$current_source" ] \
        || die "preflight source differs from approved checkout"
    [ "$CANARY_NAME" = "$BASE_CANARY_NAME" ] && [ "$ADD_KEY" = "$BASE_ADD_KEY" ] &&
    [ "$DELETE_KEY" = "$BASE_DELETE_KEY" ] && [ "$CREATED_EPOCH" = "$BASE_CREATED_EPOCH" ] \
        || die "journal immutable recovery identifiers differ from baseline"
    live_rpc_source_gate || die "live RPC source identity gate failed"
    [ "$PHASE" = preflight_complete ] && [ "$FINAL_STATUS" = ready_for_separate_canary_approval ] \
        || die "canary requires a fresh successful Phase 2 preflight"
    age=$(( $(now_epoch) - CREATED_EPOCH ))
    [ "$age" -ge 0 ] && [ "$age" -le "$PREFLIGHT_TTL_SECONDS" ] || die "Phase 2 preflight is stale"
    preactivation_gates

    ACTIVATION_STARTED=true; PHASE=activation_started; FINAL_STATUS=canary_in_progress
    journal_write_strict activation_started
    result="$(rpc_call management.activate '{}')"
    [ "$?" -eq 0 ] || canary_fail "management.activate transport failure"
    ACTIVATION_RESULT="$(printf '%s' "$result" | sanitize_result)"
    [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.management_state // empty')" = active ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.no_op == false')" = true ] \
        || canary_fail "management.activate was rejected"
    ACTIVATION_COMPLETED=true; PHASE=activation_complete; postactivation_checkpoint activation_complete; maybe_test_crash activation_complete

    status_json="$(rpc_call management.status '{}')" || canary_fail "active status check failed"
    [ "$(printf '%s' "$status_json" | jq -r '.data.management_state // empty')" = active ] \
        || canary_fail "management did not become active"
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] || canary_fail "activation marker is absent or unsafe"
    PHASE=active_verified; postactivation_checkpoint active_verified; maybe_test_crash active_verified

    list_json="$(rpc_call client.list '{}')" || canary_fail "pre-add client.list failed"
    inventory_measure "$list_json" || canary_fail "pre-add inventory is invalid"
    [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] &&
    [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] &&
    ! canary_present_in "$list_json" || canary_fail "pre-add inventory drifted"
    PHASE=list_before_add; postactivation_checkpoint list_before_add; maybe_test_crash list_before_add

    ADD_STARTED=true; PHASE=add_started; postactivation_checkpoint add_started; maybe_test_crash add_started
    result="$(rpc_call client.add \
      "$(jq -cn --arg n "$CANARY_NAME" --arg k "$ADD_KEY" '{name:$n,idempotency_key:$k}')")"
    [ "$?" -eq 0 ] || canary_fail "client.add transport failure"
    ADD_RESULT="$(printf '%s' "$result" | sanitize_result)"
    [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.name // empty')" = "$CANARY_NAME" ] &&
    [ "$(printf '%s' "$result" | jq -r '.idempotency.replayed == false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.changed // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.reload_performed // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.health_verified // false')" = true ] \
        || canary_fail "client.add did not prove a healthy transaction"
    ADD_COMPLETED=true; PHASE=add_complete; postactivation_checkpoint add_complete; maybe_test_crash add_complete
    singbox_measure
    [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] &&
    [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ] \
        || canary_fail "sing-box health drifted after add"
    list_json="$(rpc_call client.list '{}')" || canary_fail "post-add client.list failed"
    inventory_measure "$list_json" || canary_fail "post-add inventory invalid"
    expected_count=$((BASE_INVENTORY_COUNT + 1))
    canary_present_in "$list_json" && inventory_without_canary_matches "$list_json" &&
    [ "$CURRENT_INVENTORY_COUNT" = "$expected_count" ] \
        || canary_fail "canary client was not uniquely visible after add"
    PHASE=add_verified; postactivation_checkpoint add_verified; maybe_test_crash add_verified

    DELETE_STARTED=true; PHASE=delete_started; postactivation_checkpoint delete_started; maybe_test_crash delete_started
    result="$(rpc_call client.delete \
      "$(jq -cn --arg n "$CANARY_NAME" --arg k "$DELETE_KEY" '{name:$n,idempotency_key:$k}')")"
    [ "$?" -eq 0 ] || canary_fail "client.delete transport failure"
    DELETE_RESULT="$(printf '%s' "$result" | sanitize_result)"
    [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.deleted // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.idempotency.replayed == false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.changed // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.reload_performed // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.transaction.health_verified // false')" = true ] \
        || canary_fail "client.delete did not prove a healthy transaction"
    DELETE_COMPLETED=true; PHASE=delete_complete; postactivation_checkpoint delete_complete; maybe_test_crash delete_complete
    list_json="$(rpc_call client.list '{}')" || canary_fail "post-delete client.list failed"
    inventory_measure "$list_json" || canary_fail "post-delete inventory invalid"
    ! canary_present_in "$list_json" && [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] &&
    [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] \
        || canary_fail "post-delete inventory does not equal baseline"
    PHASE=delete_verified; postactivation_checkpoint delete_verified; maybe_test_crash delete_verified

    DEACTIVATION_STARTED=true; PHASE=deactivation_started; postactivation_checkpoint deactivation_started; maybe_test_crash deactivation_started
    result="$(rpc_call management.deactivate '{}')"
    [ "$?" -eq 0 ] || canary_fail "management.deactivate transport failure"
    DEACTIVATION_RESULT="$(printf '%s' "$result" | sanitize_result)"
    [ "$(printf '%s' "$result" | jq -r '.ok // false')" = true ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.management_state // empty')" = inactive ] &&
    [ "$(printf '%s' "$result" | jq -r '.data.no_op == false')" = true ] \
        || canary_fail "management.deactivate was rejected"
    DEACTIVATION_COMPLETED=true; PHASE=deactivation_complete; postactivation_checkpoint deactivation_complete; maybe_test_crash deactivation_complete
    status_json="$(rpc_call management.status '{}')" || canary_fail "final management.status failed"
    status_inactive_clean "$status_json" || canary_fail "final management state is not inactive"
    [ ! -e "$MARKER" ] || canary_fail "activation marker remains after deactivate"
    list_json="$(rpc_call client.list '{}')" || canary_fail "final client.list failed"
    final_measure "$status_json" "$list_json" || canary_fail "final production state differs from pre-canary baseline"
    PHASE=complete; FINAL_STATUS=canary_complete; postactivation_checkpoint canary_complete
    printf 'PHASE2 CANARY=PASS\n'
    printf 'management_state = inactive\n'
    printf 'activation_marker = absent\n'
    printf 'canary_client = absent\n'
    exit 0
}

cmd_recover() {
    local current_source journal_ok=0
    source_identity_gate; current_source="$SOURCE_HEAD"
    baseline_load
    [ "$BASE_SOURCE_HEAD" = "$current_source" ] \
        || critical "baseline source_head differs from approved recovery checkout"
    if ! live_rpc_source_gate; then
        root_recovery_deactivate || true
        critical "live RPC source identity drifted; root recovery was attempted and manual intervention is required"
    fi
    if journal_load; then
        journal_ok=1
        [ "$SOURCE_HEAD" = "$current_source" ] \
            || critical "journal source_head differs from approved recovery checkout"
        [ "$CANARY_NAME" = "$BASE_CANARY_NAME" ] && [ "$ADD_KEY" = "$BASE_ADD_KEY" ] &&
        [ "$DELETE_KEY" = "$BASE_DELETE_KEY" ] && [ "$CREATED_EPOCH" = "$BASE_CREATED_EPOCH" ] \
            || critical "journal immutable recovery identifiers differ from baseline"
    else
        printf 'CRITICAL: mutable journal unavailable/corrupt; recovering only from immutable baseline\n' >&2
        SOURCE_HEAD="$BASE_SOURCE_HEAD"
        CREATED_EPOCH="$BASE_CREATED_EPOCH"
        CANARY_NAME="$BASE_CANARY_NAME"
        ADD_KEY="$BASE_ADD_KEY"
        DELETE_KEY="$BASE_DELETE_KEY"
        PHASE=recovery_unknown
        ACTIVATION_STARTED=true
        ACTIVATION_COMPLETED=false
        ADD_STARTED=false; ADD_COMPLETED=false
        DELETE_STARTED=false; DELETE_COMPLETED=false
        DEACTIVATION_STARTED=false; DEACTIVATION_COMPLETED=false
        FINAL_STATUS=manual_intervention
        ACTIVATION_RESULT=null; ADD_RESULT=null; DELETE_RESULT=null; DEACTIVATION_RESULT=null
        FINAL_MEASUREMENTS=null
    fi
    case "$FINAL_STATUS" in
      canary_complete) die "Phase 2 canary already completed" ;;
      cleanup_complete) die "Phase 2 cleanup already completed" ;;
    esac
    if [ "$journal_ok" -eq 1 ] && [ "$ACTIVATION_STARTED" != true ]; then
        PHASE=recovered; FINAL_STATUS=aborted_before_activation; journal_write_strict aborted_before_activation
        printf 'RECOVERY PASS: no activation attempt had started\n'
        return 0
    fi
    cleanup_attempt "recovering an interrupted Phase 2 canary" \
        || critical "Phase 2 recovery requires manual intervention"
}

cmd_status() {
    if [ ! -r "$JOURNAL" ]; then printf 'phase=not_started\n'; return 0; fi
    journal_load || die "Phase 2 journal is invalid"
    printf 'phase=%s\n' "$PHASE"
    printf 'source_head=%s\n' "$SOURCE_HEAD"
    printf 'activation_started=%s completed=%s\n' "$ACTIVATION_STARTED" "$ACTIVATION_COMPLETED"
    printf 'add_started=%s completed=%s\n' "$ADD_STARTED" "$ADD_COMPLETED"
    printf 'delete_started=%s completed=%s\n' "$DELETE_STARTED" "$DELETE_COMPLETED"
    printf 'deactivation_started=%s completed=%s\n' "$DEACTIVATION_STARTED" "$DEACTIVATION_COMPLETED"
    printf 'final_status=%s\n' "$FINAL_STATUS"
}

usage() {
    printf 'usage: %s preflight | canary --approve-activation | recover | status\n' "${0##*/}" >&2
    exit 2
}

case "${1:-}" in
  preflight) [ "$#" -eq 1 ] || usage; acquire_command_locks; cmd_preflight ;;
  canary)
    [ "$#" -eq 2 ] && [ "${2:-}" = --approve-activation ] || usage
    acquire_command_locks; cmd_canary
    ;;
  recover) [ "$#" -eq 1 ] || usage; acquire_command_locks; cmd_recover ;;
  status) [ "$#" -eq 1 ] || usage; cmd_status ;;
  *) usage ;;
esac
