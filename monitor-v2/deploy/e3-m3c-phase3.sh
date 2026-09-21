#!/usr/bin/env bash
# E3 M3-C Phase 3: persistent production management go-live.
#
# preflight only writes root-owned evidence. enable is a separate, explicitly
# approved command and its sole normal-path mutation is management.activate.
set -uo pipefail

readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly PREFLIGHT_TTL_SECONDS=900
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
readonly RPC_BRIDGE="$SCRIPT_DIR/e3-m3c-phase2-rpc.py"

TEST_MODE="${E3_PHASE3_TEST_MODE:-0}"
if [ "$TEST_MODE" != 0 ] && [ "$TEST_MODE" != 1 ]; then
    printf 'ERROR: E3_PHASE3_TEST_MODE must be 0 or 1\n' >&2; exit 2
fi

if [ "$TEST_MODE" = 1 ]; then
    PHASE2_STATE="${E3_PHASE3_TEST_PHASE2_STATE:?test Phase 2 state required}"
    STATE_DIR="${E3_PHASE3_TEST_STATE_DIR:?test Phase 3 state required}"
    CONFIG="${E3_PHASE3_TEST_CONFIG:?test config required}"
    MONITOR_APP="${E3_PHASE3_TEST_MONITOR_APP:?test monitor app required}"
    SBXCM_STATE="${E3_PHASE3_TEST_SBXCM_STATE:?test helper state required}"
    MONITOR_URL="${E3_PHASE3_TEST_MONITOR_URL:-http://fixture.invalid}"
    SYSTEMCTL="${E3_PHASE3_TEST_SYSTEMCTL:?test systemctl required}"
    CURL="${E3_PHASE3_TEST_CURL:?test curl required}"
    RPC_FIXTURE="${E3_PHASE3_TEST_RPC:?test RPC fixture required}"
    TEST_FIXTURE_ROOT="${E3_PHASE3_TEST_FIXTURE_ROOT:?test fixture root required}"
    TEST_SOURCE_HEAD="${E3_PHASE3_TEST_SOURCE_HEAD:?test source head required}"
    TEST_SOURCE_DIRTY="${E3_PHASE3_TEST_SOURCE_DIRTY:-0}"
    PHASE3_LOCK="${E3_PHASE3_TEST_LOCK:?test lock required}"
    MONITOR_DEPLOY_LOCK="${E3_PHASE3_TEST_MONITOR_LOCK:?test monitor lock required}"
    FLOCK_BIN="${E3_PHASE3_TEST_FLOCK:-/usr/bin/flock}"
    LOCK_BACKEND="${E3_PHASE3_TEST_LOCK_BACKEND:-flock}"
    CONFIG_LOCK="${E3_PHASE3_TEST_CONFIG_LOCK:?test config lock required}"
    CONFIG_LOCK_BACKEND="${E3_PHASE3_TEST_CONFIG_LOCK_BACKEND:-flock}"
    TEST_NOW="${E3_PHASE3_TEST_NOW:-2000000000}"
    TEST_CRASH_AFTER="${E3_PHASE3_TEST_CRASH_AFTER:-}"
    TEST_EVIDENCE_FAILURES="${E3_PHASE3_TEST_EVIDENCE_FAILURES:-}"
    EVIDENCE_BACKEND="${E3_PHASE3_TEST_EVIDENCE_BACKEND:-fixture}"
    TEST_PHASE2_ANCESTOR="${E3_PHASE3_TEST_PHASE2_ANCESTOR:?test Phase 2 ancestor required}"
    ROOT_RECOVERY="${E3_PHASE3_TEST_ROOT_RECOVERY:?test root recovery required}"
    RPC_PATH="$(dirname -- "$SYSTEMCTL"):$PATH"
else
    [ "$(id -u)" = 0 ] || { printf 'ERROR: Phase 3 must run as root\n' >&2; exit 1; }
    PATH="$SAFE_PATH"; export PATH
    PHASE2_STATE="/var/lib/e3-m3c-phase2"
    STATE_DIR="/var/lib/e3-m3c-phase3"
    CONFIG="/root/sbox/sbconfig_server.json"
    MONITOR_APP="/opt/singbox-monitor"
    SBXCM_STATE="/var/lib/sbox-cm"
    MONITOR_URL="http://127.0.0.1:9191"
    SYSTEMCTL="/usr/bin/systemctl"
    CURL="/usr/bin/curl"
    RPC_FIXTURE=""; TEST_FIXTURE_ROOT=""; TEST_SOURCE_HEAD=""
    TEST_SOURCE_DIRTY="0"
    PHASE3_LOCK="/run/lock/e3-m3c-phase3.lock"
    MONITOR_DEPLOY_LOCK="/run/lock/singbox-monitor-deploy.lock"
    FLOCK_BIN="/usr/bin/flock"; LOCK_BACKEND="flock"
    CONFIG_LOCK="/root/sbox/config.lock"; CONFIG_LOCK_BACKEND="flock"
    TEST_NOW=""; TEST_CRASH_AFTER=""; TEST_EVIDENCE_FAILURES=""
    EVIDENCE_BACKEND="real"; TEST_PHASE2_ANCESTOR=""
    ROOT_RECOVERY="$REPO_ROOT/sbox-cm/deploy/install-sbox-cm.sh"
    RPC_PATH="$SAFE_PATH"
fi

readonly PHASE2_BASELINE="$PHASE2_STATE/baseline.json"
readonly PHASE2_JOURNAL="$PHASE2_STATE/journal.json"
readonly BASELINE="$STATE_DIR/baseline.json"
readonly JOURNAL="$STATE_DIR/journal.json"
readonly MARKER="$SBXCM_STATE/management.active"
readonly TX_JOURNAL_DIR="$SBXCM_STATE/journal"

SOURCE_HEAD=""; CREATED_EPOCH=0; PHASE="new"; FINAL_STATUS="not_started"
ACTIVATION_STARTED=false; ACTIVATION_COMPLETED=false
ACTIVATION_RESULT=null; FINAL_MEASUREMENTS=null; EVIDENCE_FAILED=false
BASE_SOURCE_HEAD=""; BASE_CREATED_EPOCH=0; BASE_PHASE2_SOURCE_HEAD=""
BASE_CANARY_NAME=""; BASE_LIVE_MONITOR_TARGET=""; BASE_LIVE_RPC_SHA=""
BASE_CONFIG_SHA=""; BASE_CONFIG_SIZE=0; BASE_CONFIG_SEMANTIC_SHA=""
BASE_INVENTORY_SHA=""; BASE_INVENTORY_COUNT=0
BASE_SING_TS=""; BASE_SING_RESTARTS=0; RPC_APP_ROOT=""

die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
critical(){ printf 'CRITICAL: %s\n' "$*" >&2; exit 1; }
now_epoch(){ if [ "$TEST_MODE" = 1 ]; then printf '%s\n' "$TEST_NOW"; else date +%s; fi; }

acquire_phase3_lock(){
    mkdir -p -- "$(dirname -- "$PHASE3_LOCK")" || die "cannot create Phase 3 lock directory"
    if [ "$TEST_MODE" = 1 ] && [ "$LOCK_BACKEND" = mkdir ]; then
        mkdir -- "$PHASE3_LOCK.fixture-held" 2>/dev/null || die "another Phase 3 command holds the exclusive lock"
        trap 'rmdir -- "$PHASE3_LOCK.fixture-held" 2>/dev/null || true' EXIT; return
    fi
    [ "$LOCK_BACKEND" = flock ] && [ -x "$FLOCK_BIN" ] || die "Phase 3 flock is unavailable"
    umask 077; exec 8>>"$PHASE3_LOCK" || die "cannot open Phase 3 lock"
    chmod 0600 "$PHASE3_LOCK" || die "cannot protect Phase 3 lock"
    "$FLOCK_BIN" -n 8 || die "another Phase 3 command holds the exclusive lock"
}

acquire_monitor_deploy_lock(){
    mkdir -p -- "$(dirname -- "$MONITOR_DEPLOY_LOCK")" || die "cannot create monitor lock directory"
    if [ "$TEST_MODE" = 1 ] && [ "$LOCK_BACKEND" = mkdir ]; then
        mkdir -- "$MONITOR_DEPLOY_LOCK.fixture-held" 2>/dev/null || die "monitor deployment lock is held"
        trap 'rmdir -- "$PHASE3_LOCK.fixture-held" "$MONITOR_DEPLOY_LOCK.fixture-held" 2>/dev/null || true' EXIT; return
    fi
    umask 077; exec 7>>"$MONITOR_DEPLOY_LOCK" || die "cannot open canonical monitor deployment lock"
    "$FLOCK_BIN" -n 7 || die "monitor deployment lock is held"
}

acquire_command_locks(){
    # Fixed global order: Phase 3 first, canonical monitor deployment second.
    # Both descriptors remain open until this command exits.
    acquire_phase3_lock
    acquire_monitor_deploy_lock
}

source_identity_gate(){
    local approved dirty
    approved="${E3_PHASE3_APPROVED_HEAD:-}"
    if [ "$TEST_MODE" = 1 ]; then
        SOURCE_HEAD="$TEST_SOURCE_HEAD"
        [ -n "$approved" ] && [ "$SOURCE_HEAD" = "$approved" ] || die "checkout HEAD does not equal E3_PHASE3_APPROVED_HEAD"
        [ "$TEST_SOURCE_DIRTY" = 0 ] || die "source checkout is dirty"
        return
    fi
    [[ "$approved" =~ ^[0-9a-f]{40}$ ]] || die "E3_PHASE3_APPROVED_HEAD must be the exact reviewed 40-hex merge SHA"
    SOURCE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)" || die "cannot resolve source HEAD"
    [ "$SOURCE_HEAD" = "$approved" ] || die "checkout HEAD does not equal E3_PHASE3_APPROVED_HEAD"
    dirty="$(git -C "$REPO_ROOT" status --porcelain)"; [ -z "$dirty" ] || die "source checkout is dirty"
    [ -f "$RPC_BRIDGE" ] || die "reviewed RPC adapter is missing"
}

ensure_state_dir(){
    umask 077; mkdir -p -- "$STATE_DIR" && chmod 0700 "$STATE_DIR" || return 1
    if [ "$TEST_MODE" = 0 ]; then
        chown root:root "$STATE_DIR" || return 1
        [ "$(stat -c '%U %G %a' "$STATE_DIR")" = 'root root 700' ] || return 1
    fi
}

evidence_injected_failure(){
    [ "$TEST_MODE" = 1 ] || return 1
    case ",${TEST_EVIDENCE_FAILURES}," in *",$1:$2,"*|",*:$2,") return 0;; esac
    return 1
}

evidence_fsync(){
    evidence_injected_failure "$2" "$3" && return 1
    if [ "$TEST_MODE" = 1 ] && [ "$EVIDENCE_BACKEND" = fixture ]; then return 0; fi
    [ "$EVIDENCE_BACKEND" = real ] || return 1
    sync -f "$1" 2>/dev/null || command sync 2>/dev/null
}

atomic_json_write(){
    local path="$1" context="$2" tmp dir
    ensure_state_dir || return 1; dir="$(dirname -- "$path")"
    [ ! -L "$path" ] || return 1
    tmp="$(mktemp "$STATE_DIR/.json.tmp.XXXXXX")" || return 1
    if evidence_injected_failure "$context" write || ! jq -c . >"$tmp"; then rm -f -- "$tmp"; return 1; fi
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    if [ "$TEST_MODE" = 0 ]; then chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }; fi
    evidence_fsync "$tmp" "$context" file_fsync || { rm -f -- "$tmp"; return 1; }
    if evidence_injected_failure "$context" rename || ! mv -f -- "$tmp" "$path"; then rm -f -- "$tmp"; return 1; fi
    evidence_fsync "$dir" "$context" dir_fsync
}

# Direct field lookup preserves false/true; missing and explicit null remain null.
sanitize_result(){ jq -c '{ok:(.ok//false),code:(.code//null),data:{management_state:(.data.management_state//null),no_op:.data.no_op},transport_error:(.transport_error//null),adapter_error:(.adapter_error//null)}' 2>/dev/null; }

journal_write(){
    local context="${1:-journal}"
    jq -n --arg source "$SOURCE_HEAD" --arg phase "$PHASE" --arg baseline "$BASELINE" \
      --arg final "$FINAL_STATUS" --arg updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --argjson created "$CREATED_EPOCH" --argjson started "$ACTIVATION_STARTED" \
      --argjson completed "$ACTIVATION_COMPLETED" --argjson result "$ACTIVATION_RESULT" \
      --argjson measurements "$FINAL_MEASUREMENTS" \
      '{schema:1,source_head:$source,phase:$phase,baseline_path:$baseline,preflight_created_epoch:$created,
        activation:{started:$started,completed:$completed,result:$result},final_measurements:$measurements,
        final_status:$final,updated_at:$updated}' | atomic_json_write "$JOURNAL" "$context"
}

journal_write_strict(){ journal_write "$1" || die "cannot durably write the Phase 3 journal"; }
cleanup_evidence_write(){ journal_write "$1" || { EVIDENCE_FAILED=true; printf 'CRITICAL: cleanup evidence write failed at %s\n' "$1" >&2; return 1; }; }
postactivation_checkpoint(){
    if ! journal_write "$1"; then EVIDENCE_FAILED=true; cleanup_attempt "post-activation evidence failure at $1" || true; exit 1; fi
}

journal_load(){
    [ -r "$JOURNAL" ] && jq -e '.schema==1' "$JOURNAL" >/dev/null 2>&1 || return 1
    SOURCE_HEAD="$(jq -er '.source_head' "$JOURNAL")" || return 1
    PHASE="$(jq -er '.phase' "$JOURNAL")" || return 1
    CREATED_EPOCH="$(jq -er '.preflight_created_epoch' "$JOURNAL")" || return 1
    ACTIVATION_STARTED="$(jq -r '.activation.started' "$JOURNAL")"
    ACTIVATION_COMPLETED="$(jq -r '.activation.completed' "$JOURNAL")"
    ACTIVATION_RESULT="$(jq -c '.activation.result' "$JOURNAL")"
    FINAL_MEASUREMENTS="$(jq -c '.final_measurements' "$JOURNAL")"
    FINAL_STATUS="$(jq -er '.final_status' "$JOURNAL")" || return 1
    [[ "$SOURCE_HEAD" =~ ^[0-9a-f]{40}$ ]] || return 1
    for v in "$ACTIVATION_STARTED" "$ACTIVATION_COMPLETED"; do [ "$v" = true ] || [ "$v" = false ] || return 1; done
}

safe_evidence_file(){
    [ -r "$1" ] && [ -f "$1" ] && [ ! -L "$1" ] || return 1
    if [ "$TEST_MODE" = 0 ] || [ "$(uname -s 2>/dev/null)" = Linux ]; then [ "$(stat -c %a "$1")" = 600 ] || return 1; fi
    if [ "$TEST_MODE" = 0 ]; then [ "$(stat -c '%u %g' "$1")" = '0 0' ] || return 1; fi
}

phase2_gate(){
    local p2_source
    [ -d "$PHASE2_STATE" ] && [ ! -L "$PHASE2_STATE" ] || die "Phase 2 state directory is unavailable or unsafe"
    if [ "$TEST_MODE" = 0 ] || [ "$(uname -s 2>/dev/null)" = Linux ]; then [ "$(stat -c %a "$PHASE2_STATE")" = 700 ] || die "Phase 2 state directory is not mode 0700"; fi
    if [ "$TEST_MODE" = 0 ]; then [ "$(stat -c '%u %g' "$PHASE2_STATE")" = '0 0' ] || die "Phase 2 state directory is not root:root"; fi
    safe_evidence_file "$PHASE2_BASELINE" && safe_evidence_file "$PHASE2_JOURNAL" || die "Phase 2 evidence is unavailable or unsafe"
    jq -e '.schema==1 and .phase=="complete" and .final_status=="canary_complete" and
      .activation.started==true and .activation.completed==true and
      .add.started==true and .add.completed==true and .delete.started==true and .delete.completed==true and
      .deactivation.started==true and .deactivation.completed==true and
      (.final_measurements.config.sha256|type=="string" and test("^[0-9a-f]{64}$")) and
      (.final_measurements.config.size|type=="number" and .>0) and
      (.final_measurements.config.semantic_sha256|type=="string" and test("^[0-9a-f]{64}$")) and
      (.final_measurements.inventory.sha256|type=="string" and test("^[0-9a-f]{64}$")) and
      (.final_measurements.inventory.count|type=="number" and .>=0) and
      .final_measurements.management_state=="inactive"' "$PHASE2_JOURNAL" >/dev/null || die "Phase 2 journal is not a completed canary"
    jq -e '(.canary.name|type=="string" and test("^m3c-")) and
      (.singbox.active_enter_timestamp|type=="string" and length>0) and (.singbox.nrestarts|type=="number")' \
      "$PHASE2_BASELINE" >/dev/null || die "Phase 2 baseline is invalid"
    p2_source="$(jq -er '.source_head' "$PHASE2_JOURNAL")" || die "Phase 2 source_head unavailable"
    [[ "$p2_source" =~ ^[0-9a-f]{40}$ ]] || die "Phase 2 source_head invalid"
    if [ "$TEST_MODE" = 1 ]; then
        [ "$p2_source" = "$TEST_PHASE2_ANCESTOR" ] || die "Phase 2 source is not an approved test ancestor"
    else
        git -C "$REPO_ROOT" merge-base --is-ancestor "$p2_source" "$SOURCE_HEAD" || die "Phase 2 source is not an ancestor of approved Phase 3 HEAD"
    fi
}

baseline_load(){
    safe_evidence_file "$BASELINE" || die "successful fresh Phase 3 preflight is unavailable"
    jq -e '.schema==1 and (.source_head|test("^[0-9a-f]{40}$")) and (.created_epoch|type=="number") and
      (.live_rpc.target|type=="string" and length>0) and (.live_rpc.sha256|test("^[0-9a-f]{64}$")) and
      (.config.sha256|test("^[0-9a-f]{64}$")) and (.config.semantic_sha256|test("^[0-9a-f]{64}$")) and
      (.inventory.sha256|test("^[0-9a-f]{64}$"))' "$BASELINE" >/dev/null || die "Phase 3 baseline is invalid"
    BASE_SOURCE_HEAD="$(jq -er '.source_head' "$BASELINE")"; BASE_CREATED_EPOCH="$(jq -er '.created_epoch' "$BASELINE")"
    BASE_PHASE2_SOURCE_HEAD="$(jq -er '.phase2.source_head' "$BASELINE")"; BASE_CANARY_NAME="$(jq -er '.phase2.canary_name' "$BASELINE")"
    BASE_LIVE_MONITOR_TARGET="$(jq -er '.live_rpc.target' "$BASELINE")"; BASE_LIVE_RPC_SHA="$(jq -er '.live_rpc.sha256' "$BASELINE")"
    BASE_CONFIG_SHA="$(jq -er '.config.sha256' "$BASELINE")"; BASE_CONFIG_SIZE="$(jq -er '.config.size' "$BASELINE")"
    BASE_CONFIG_SEMANTIC_SHA="$(jq -er '.config.semantic_sha256' "$BASELINE")"
    BASE_INVENTORY_SHA="$(jq -er '.inventory.sha256' "$BASELINE")"; BASE_INVENTORY_COUNT="$(jq -er '.inventory.count' "$BASELINE")"
    BASE_SING_TS="$(jq -er '.singbox.active_enter_timestamp' "$BASELINE")"; BASE_SING_RESTARTS="$(jq -er '.singbox.nrestarts' "$BASELINE")"
}

live_rpc_source_gate(){
    local target live_rpc reviewed_rpc live_sha reviewed_sha
    target="$(readlink -f -- "$MONITOR_APP" 2>/dev/null)" || return 1
    if [ "$TEST_MODE" = 1 ] && command -v cygpath >/dev/null 2>&1; then target="$(cygpath -m "$target")"; fi
    live_rpc="$target/app/monitor-v2/web/e3rpc.py"; reviewed_rpc="$REPO_ROOT/monitor-v2/web/e3rpc.py"
    [ -f "$live_rpc" ] && [ ! -L "$live_rpc" ] && [ -r "$live_rpc" ] && [ -r "$reviewed_rpc" ] || return 1
    live_sha="$(sha256sum "$live_rpc"|awk '{print $1}')"; reviewed_sha="$(sha256sum "$reviewed_rpc"|awk '{print $1}')"
    [ "$live_sha" = "$reviewed_sha" ] || return 1
    if [ -n "$BASE_LIVE_MONITOR_TARGET" ]; then [ "$target" = "$BASE_LIVE_MONITOR_TARGET" ] && [ "$live_sha" = "$BASE_LIVE_RPC_SHA" ] || return 1; fi
    CURRENT_LIVE_MONITOR_TARGET="$target"; CURRENT_LIVE_RPC_SHA="$live_sha"; RPC_APP_ROOT="$target/app/monitor-v2"
}

rpc_call(){
    local op="$1" payload="$2"
    case "$op" in management.status|client.list|management.activate|management.deactivate) ;; *) die "RPC operation is not allowed: $op";; esac
    if [ "$TEST_MODE" = 1 ]; then
        printf '%s' "$payload" | env -i PATH="$RPC_PATH" HOME="$STATE_DIR" LC_ALL=C FX="$TEST_FIXTURE_ROOT" RPC_APP_ROOT="$RPC_APP_ROOT" /usr/bin/bash "$RPC_FIXTURE" "$op"
    else
        [ -n "$RPC_APP_ROOT" ] && [ -d "$RPC_APP_ROOT" ] && [ -r "$RPC_APP_ROOT/web/e3rpc.py" ] || { printf 'ERROR: pinned reviewed RPC app root became unavailable\n' >&2; return 70; }
        env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C /usr/bin/sudo -n -u sboxweb /usr/bin/python3 -B - "$op" "$RPC_APP_ROOT" "$payload" <"$RPC_BRIDGE"
    fi
}

config_measure(){ CURRENT_CONFIG_SHA="$(sha256sum "$CONFIG" 2>/dev/null|awk '{print $1}')"; CURRENT_CONFIG_SIZE="$(stat -c %s "$CONFIG" 2>/dev/null||true)"; CURRENT_CONFIG_SEMANTIC_SHA="$(jq -cS . "$CONFIG" 2>/dev/null|sha256sum|awk '{print $1}')"; }
singbox_measure(){ CURRENT_SING_ACTIVE="$("$SYSTEMCTL" is-active sing-box.service 2>/dev/null||true)"; CURRENT_SING_TS="$("$SYSTEMCTL" show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null)"; CURRENT_SING_RESTARTS="$("$SYSTEMCTL" show -p NRestarts --value sing-box.service 2>/dev/null)"; }
monitor_healthy(){ [ "$("$CURL" -sS -o /dev/null -w '%{http_code}' --max-time 5 "$MONITOR_URL/api/v1/session" 2>/dev/null||true)" = 200 ]; }
tx_state_clean(){ [ ! -e "$SBXCM_STATE/degraded.json" ] || return 1; local f; for f in "$TX_JOURNAL_DIR"/*.json; do [ ! -e "$f" ] || return 1; done; }
config_lock_free(){
    if [ "$TEST_MODE" = 1 ] && [ "$CONFIG_LOCK_BACKEND" = fixture ]; then [ ! -e "$TEST_FIXTURE_ROOT/config-lock-busy" ]; return; fi
    [ "$CONFIG_LOCK_BACKEND" = flock ] || return 1; [ -e "$CONFIG_LOCK" ] || return 0; [ -f "$CONFIG_LOCK" ] || return 1
    (exec 9<"$CONFIG_LOCK" 2>/dev/null && "$FLOCK_BIN" -n 9 2>/dev/null) >/dev/null 2>&1
}
units_ready(){ [ "$("$SYSTEMCTL" is-active sbox-cm.socket 2>/dev/null||true)" = active ] && [ "$("$SYSTEMCTL" is-enabled sbox-cm.socket 2>/dev/null||true)" = enabled ] && [ "$("$SYSTEMCTL" is-active sbox-cm.service 2>/dev/null||true)" = active ] && [ "$("$SYSTEMCTL" is-enabled sbox-cm.service 2>/dev/null||true)" = disabled ]; }
status_clean_as(){ local j="$1" want="$2"; [ "$(printf '%s' "$j"|jq -r '.ok//false')" = true ] && [ "$(printf '%s' "$j"|jq -r '.data.management_state//empty')" = "$want" ] && [ "$(printf '%s' "$j"|jq -r '.data.helper.degraded==false')" = true ] && [ "$(printf '%s' "$j"|jq -r '.data.helper.reconcile//empty')" = clean ] && [ "$(printf '%s' "$j"|jq -r '.data.lock.acquirable==true')" = true ]; }
inventory_measure(){ local j="$1" canonical; [ "$(printf '%s' "$j"|jq -r '.ok//false')" = true ] && [ "$(printf '%s' "$j"|jq -r '.data.truncated==false')" = true ] || return 1; canonical="$(printf '%s' "$j"|jq -cS '.data.clients|sort_by(.name)')" || return 1; CURRENT_INVENTORY_SHA="$(printf '%s' "$canonical"|sha256sum|awk '{print $1}')"; CURRENT_INVENTORY_COUNT="$(printf '%s' "$j"|jq -r '.data.clients|length')"; }
canary_absent(){ [ "$(printf '%s' "$1"|jq --arg n "$BASE_CANARY_NAME" '[.data.clients[]|select(.name==$n)]|length')" = 0 ]; }

load_phase2_terminal(){
    BASE_PHASE2_SOURCE_HEAD="$(jq -er '.source_head' "$PHASE2_JOURNAL")"; BASE_CANARY_NAME="$(jq -er '.canary.name' "$PHASE2_BASELINE")"
    BASE_CONFIG_SHA="$(jq -er '.final_measurements.config.sha256' "$PHASE2_JOURNAL")"; BASE_CONFIG_SIZE="$(jq -er '.final_measurements.config.size' "$PHASE2_JOURNAL")"
    BASE_CONFIG_SEMANTIC_SHA="$(jq -er '.final_measurements.config.semantic_sha256' "$PHASE2_JOURNAL")"
    BASE_INVENTORY_SHA="$(jq -er '.final_measurements.inventory.sha256' "$PHASE2_JOURNAL")"; BASE_INVENTORY_COUNT="$(jq -er '.final_measurements.inventory.count' "$PHASE2_JOURNAL")"
    BASE_SING_TS="$(jq -er '.singbox.active_enter_timestamp' "$PHASE2_BASELINE")"; BASE_SING_RESTARTS="$(jq -er '.singbox.nrestarts' "$PHASE2_BASELINE")"
}

preactivation_gates(){
    local status list
    phase2_gate; config_measure; singbox_measure
    [ "$CURRENT_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] && [ "$CURRENT_CONFIG_SIZE" = "$BASE_CONFIG_SIZE" ] && [ "$CURRENT_CONFIG_SEMANTIC_SHA" = "$BASE_CONFIG_SEMANTIC_SHA" ] || die "config differs from Phase 2 terminal state"
    [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] && [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ] || die "sing-box state drifted"
    monitor_healthy && units_ready && [ ! -e "$MARKER" ] && tx_state_clean && config_lock_free || die "closed-plane preactivation gates failed"
    status="$(rpc_call management.status '{}')" || die "management.status transport failed"; status_clean_as "$status" inactive || die "management is not inactive and clean"
    list="$(rpc_call client.list '{}')" || die "client.list failed"; inventory_measure "$list" || die "client inventory invalid"
    [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] && [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] && canary_absent "$list" || die "client inventory drifted or Phase 2 canary remains"
}

marker_valid(){
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] && jq -e '.v==1 and .state=="active"' "$MARKER" >/dev/null 2>&1 || return 1
    if [ "$TEST_MODE" = 0 ] || [ "$(uname -s 2>/dev/null)" = Linux ]; then [ "$(stat -c %a "$MARKER")" = 644 ] || return 1; fi
    if [ "$TEST_MODE" = 0 ]; then [ "$(stat -c '%u %g' "$MARKER")" = '0 0' ] || return 1; fi
}

final_active_measure(){
    local status="$1" list="$2"
    config_measure; singbox_measure; inventory_measure "$list" || return 1
    FINAL_MEASUREMENTS="$(jq -n --arg sha "$CURRENT_CONFIG_SHA" --argjson size "$CURRENT_CONFIG_SIZE" --arg sem "$CURRENT_CONFIG_SEMANTIC_SHA" --arg inv "$CURRENT_INVENTORY_SHA" --argjson count "$CURRENT_INVENTORY_COUNT" --arg ts "$CURRENT_SING_TS" --argjson nr "$CURRENT_SING_RESTARTS" '{config:{sha256:$sha,size:$size,semantic_sha256:$sem},inventory:{sha256:$inv,count:$count},singbox:{active_enter_timestamp:$ts,nrestarts:$nr},management_state:"active"}')"
    status_clean_as "$status" active && marker_valid && units_ready && tx_state_clean && config_lock_free && monitor_healthy &&
    [ "$CURRENT_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] && [ "$CURRENT_CONFIG_SIZE" = "$BASE_CONFIG_SIZE" ] && [ "$CURRENT_CONFIG_SEMANTIC_SHA" = "$BASE_CONFIG_SEMANTIC_SHA" ] &&
    [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] && [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] && canary_absent "$list" &&
    [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] && [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ]
}

root_recovery_deactivate(){
    if [ "$TEST_MODE" = 1 ]; then env -i PATH="$RPC_PATH" HOME="$STATE_DIR" LC_ALL=C FX="$TEST_FIXTURE_ROOT" /usr/bin/bash "$ROOT_RECOVERY"; else env -i PATH="$SAFE_PATH" HOME=/root USER=root LOGNAME=root LC_ALL=C /usr/bin/bash "$ROOT_RECOVERY" recover; fi
}

cleanup_attempt(){
    local reason="$1" result="" status="" list="" bad=0
    printf 'STOP+CLEANUP: %s\n' "$reason" >&2; PHASE=cleanup_started; FINAL_STATUS=cleanup_in_progress
    cleanup_evidence_write cleanup_started || bad=1
    result="$(rpc_call management.deactivate '{}')"
    if [ "$?" -ne 0 ] || [ "$(printf '%s' "$result"|jq -r '.ok//false' 2>/dev/null)" != true ]; then
        printf 'CRITICAL: reviewed RPC deactivation unavailable; attempting sanctioned root recovery\n' >&2
        root_recovery_deactivate || bad=1
    fi
    status="$(rpc_call management.status '{}')" || bad=1; list="$(rpc_call client.list '{}')" || bad=1
    config_measure; singbox_measure; inventory_measure "$list" || bad=1
    if [ "$bad" -eq 0 ] && status_clean_as "$status" inactive && [ ! -e "$MARKER" ] && tx_state_clean && monitor_healthy &&
      [ "$CURRENT_CONFIG_SHA" = "$BASE_CONFIG_SHA" ] && [ "$CURRENT_CONFIG_SIZE" = "$BASE_CONFIG_SIZE" ] && [ "$CURRENT_CONFIG_SEMANTIC_SHA" = "$BASE_CONFIG_SEMANTIC_SHA" ] &&
      [ "$CURRENT_INVENTORY_SHA" = "$BASE_INVENTORY_SHA" ] && [ "$CURRENT_INVENTORY_COUNT" = "$BASE_INVENTORY_COUNT" ] &&
      [ "$CURRENT_SING_ACTIVE" = active ] && [ "$CURRENT_SING_TS" = "$BASE_SING_TS" ] && [ "$CURRENT_SING_RESTARTS" = "$BASE_SING_RESTARTS" ] && [ "$EVIDENCE_FAILED" = false ]; then
        PHASE=failed_closed; FINAL_STATUS=enable_failed_closed; cleanup_evidence_write enable_failed_closed || return 1
        printf 'CLEANUP PASS: management inactive; production data preserved\n'; return 0
    fi
    PHASE=critical; FINAL_STATUS=manual_intervention; cleanup_evidence_write manual_intervention || true
    printf 'CRITICAL: Phase 3 cleanup could not prove the closed production state\n' >&2; return 1
}

enable_fail(){ if [ "$ACTIVATION_STARTED" = true ]; then cleanup_attempt "$1" || true; fi; exit 1; }
maybe_test_crash(){ if [ "$TEST_MODE" = 1 ] && [ "$TEST_CRASH_AFTER" = "$1" ]; then printf 'TEST CRASH after %s\n' "$1" >&2; exit 99; fi; }

cmd_preflight(){
    local status list
    [ ! -e "$STATE_DIR" ] || die "Phase 3 state already exists; use status or recover"
    source_identity_gate; phase2_gate; load_phase2_terminal
    live_rpc_source_gate || die "live RPC source identity gate failed"
    preactivation_gates
    status="$(rpc_call management.status '{}')" || die "final preflight status failed"
    list="$(rpc_call client.list '{}')" || die "final preflight list failed"
    CREATED_EPOCH="$(now_epoch)"
    jq -n --arg source "$SOURCE_HEAD" --argjson created "$CREATED_EPOCH" --arg p2source "$BASE_PHASE2_SOURCE_HEAD" --arg p2base "$PHASE2_BASELINE" --arg p2journal "$PHASE2_JOURNAL" --arg canary "$BASE_CANARY_NAME" --arg target "$CURRENT_LIVE_MONITOR_TARGET" --arg rpcsha "$CURRENT_LIVE_RPC_SHA" --arg sha "$BASE_CONFIG_SHA" --argjson size "$BASE_CONFIG_SIZE" --arg sem "$BASE_CONFIG_SEMANTIC_SHA" --arg inv "$BASE_INVENTORY_SHA" --argjson count "$BASE_INVENTORY_COUNT" --arg ts "$BASE_SING_TS" --argjson nr "$BASE_SING_RESTARTS" \
      '{schema:1,source_head:$source,created_epoch:$created,phase2:{source_head:$p2source,baseline_path:$p2base,journal_path:$p2journal,canary_name:$canary},live_rpc:{target:$target,sha256:$rpcsha},config:{sha256:$sha,size:$size,semantic_sha256:$sem},inventory:{sha256:$inv,count:$count},singbox:{active:"active",active_enter_timestamp:$ts,nrestarts:$nr},management_state:"inactive"}' | atomic_json_write "$BASELINE" baseline || die "cannot durably write Phase 3 baseline"
    PHASE=preflight_complete; FINAL_STATUS=ready_for_separate_go_live_approval; journal_write_strict preflight_complete
    printf 'PHASE3 PREFLIGHT=PASS\nHARD STOP: do not enable management without separate go-live approval\n'
}

cmd_enable(){
    local current_source age result status list
    source_identity_gate; current_source="$SOURCE_HEAD"; journal_load || die "Phase 3 journal unavailable or invalid"; baseline_load
    [ "$SOURCE_HEAD" = "$current_source" ] && [ "$BASE_SOURCE_HEAD" = "$current_source" ] || die "preflight source differs from approved checkout"
    [ "$CREATED_EPOCH" = "$BASE_CREATED_EPOCH" ] || die "journal/baseline creation identity differs"
    [ "$PHASE" = preflight_complete ] && [ "$FINAL_STATUS" = ready_for_separate_go_live_approval ] || die "enable requires fresh successful Phase 3 preflight"
    age=$(( $(now_epoch)-CREATED_EPOCH )); [ "$age" -ge 0 ] && [ "$age" -le "$PREFLIGHT_TTL_SECONDS" ] || die "Phase 3 preflight is stale"
    live_rpc_source_gate || die "live RPC source identity gate failed"; preactivation_gates
    ACTIVATION_STARTED=true; PHASE=activation_started; FINAL_STATUS=go_live_in_progress; journal_write_strict activation_started; maybe_test_crash activation_started
    result="$(rpc_call management.activate '{}')"; [ "$?" -eq 0 ] || enable_fail "management.activate transport failure"
    ACTIVATION_RESULT="$(printf '%s' "$result"|sanitize_result)"
    [ "$(printf '%s' "$result"|jq -r '.ok//false')" = true ] && [ "$(printf '%s' "$result"|jq -r '.data.management_state//empty')" = active ] && [ "$(printf '%s' "$result"|jq -r '.data.no_op==false')" = true ] || enable_fail "management.activate rejected or no-op"
    ACTIVATION_COMPLETED=true; PHASE=activation_complete; postactivation_checkpoint activation_complete; maybe_test_crash activation_complete
    status="$(rpc_call management.status '{}')" || enable_fail "post-activation status failed"
    list="$(rpc_call client.list '{}')" || enable_fail "post-activation client.list failed"
    final_active_measure "$status" "$list" || enable_fail "post-activation production invariants failed"
    PHASE=complete; FINAL_STATUS=go_live_active; postactivation_checkpoint go_live_active
    printf 'PHASE3 GO_LIVE=PASS\nE3 MANAGEMENT ENABLED = YES\nmanagement_state = active\nactivation_marker = present\n'
    exit 0
}

cmd_recover(){
    local current_source journal_ok=0
    source_identity_gate; current_source="$SOURCE_HEAD"; baseline_load
    [ "$BASE_SOURCE_HEAD" = "$current_source" ] || critical "baseline source differs from approved recovery checkout"
    if journal_load; then journal_ok=1; [ "$SOURCE_HEAD" = "$current_source" ] || critical "journal source differs from approved recovery checkout"; else SOURCE_HEAD="$BASE_SOURCE_HEAD"; CREATED_EPOCH="$BASE_CREATED_EPOCH"; PHASE=recovery_unknown; ACTIVATION_STARTED=true; ACTIVATION_COMPLETED=false; FINAL_STATUS=manual_intervention; fi
    case "$FINAL_STATUS" in go_live_active) die "Phase 3 go-live is complete and active; recover refuses to disable normal production";; enable_failed_closed) die "Phase 3 attempt already failed closed";; esac
    if [ "$journal_ok" -eq 1 ] && [ "$ACTIVATION_STARTED" != true ]; then PHASE=recovered; FINAL_STATUS=aborted_before_activation; journal_write_strict aborted_before_activation; printf 'RECOVERY PASS: no activation attempt had started\n'; return; fi
    if ! live_rpc_source_gate; then printf 'CRITICAL: live RPC source unavailable; using sanctioned root recovery\n' >&2; RPC_APP_ROOT=""; fi
    cleanup_attempt "recovering interrupted Phase 3 enable" || critical "Phase 3 recovery requires manual intervention"
}

cmd_status(){
    if [ ! -r "$JOURNAL" ]; then printf 'phase=not_started\n'; return; fi
    journal_load || die "Phase 3 journal invalid"
    printf 'phase=%s\nsource_head=%s\nactivation_started=%s completed=%s\nfinal_status=%s\n' "$PHASE" "$SOURCE_HEAD" "$ACTIVATION_STARTED" "$ACTIVATION_COMPLETED" "$FINAL_STATUS"
}

usage(){ printf 'usage: %s preflight | enable --approve-go-live | recover | status\n' "${0##*/}" >&2; exit 2; }
case "${1:-}" in
  preflight) [ "$#" -eq 1 ] || usage; acquire_command_locks; cmd_preflight;;
  enable) [ "$#" -eq 2 ] && [ "${2:-}" = --approve-go-live ] || usage; acquire_command_locks; cmd_enable;;
  recover) [ "$#" -eq 1 ] || usage; acquire_command_locks; cmd_recover;;
  status) [ "$#" -eq 1 ] || usage; cmd_status;;
  *) usage;;
esac
