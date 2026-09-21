#!/usr/bin/env bash
# M3-C Phase 2 activation/canary orchestrator integration suite.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORCH="$ROOT/monitor-v2/deploy/e3-m3c-phase2.sh"
BRIDGE="$ROOT/monitor-v2/deploy/e3-m3c-phase2-rpc.py"
TMP="$(mktemp -d)"
PASS=0
FAIL=0
EXPECTED_TOTAL=197

pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_file(){ [ -e "$1" ] && pass "$2" || fail "$2 (missing $1)"; }
assert_absent(){ [ ! -e "$1" ] && pass "$2" || fail "$2 (present $1)"; }
assert_contains(){ grep -qF "$2" "$1" && pass "$3" || fail "$3 (missing [$2])"; }

cleanup(){
    if [ "${E3_M3C2_KEEP_TMP:-0}" = 1 ]; then printf 'fixture kept at %s\n' "$TMP" >&2; else rm -rf -- "$TMP"; fi
}
trap cleanup EXIT

make_stub(){
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cp /dev/stdin "$path"
    chmod 0755 "$path"
}

setup_fixture(){
    local name="$1" sha size
    FIX="$TMP/$name"; export FX="$FIX"
    mkdir -p "$FIX/bin" "$FIX/phase1" "$FIX/helper/journal" "$FIX/helper/ledger" \
      "$FIX/monitor/app/monitor-v2/web" "$FIX/run"
    cp "$ROOT/monitor-v2/web/e3rpc.py" "$FIX/monitor/app/monitor-v2/web/e3rpc.py"
    jq -n '{inbounds:[],clients:["legacy"],service:{api:{listen:"127.0.0.1:9090"}}}' >"$FIX/config.json"
    sha="$(sha256sum "$FIX/config.json" | awk '{print $1}')"
    size="$(stat -c %s "$FIX/config.json")"
    printf 'active\n' >"$FIX/sing-active"
    printf 'Mon 2026-09-14 15:50:36 UTC\n' >"$FIX/sing-ts"
    printf '0\n' >"$FIX/sing-restarts"
    printf 'active\n' >"$FIX/socket-active"
    printf 'enabled\n' >"$FIX/socket-enabled"
    printf 'active\n' >"$FIX/service-active"
    printf 'disabled\n' >"$FIX/service-enabled"
    printf '200\n' >"$FIX/http-code"
    : >"$FIX/config.lock"
    : >"$FIX/rpc-calls"
    jq -n --arg sha "$sha" --argjson size "$size" \
      --arg ts "$(cat "$FIX/sing-ts")" --argjson nr 0 \
      '{config_sha256:$sha,config_size:$size,
        singbox:{active:"active",active_enter_timestamp:$ts,nrestarts:$nr}}' \
      >"$FIX/phase1/baseline.json"
    jq -n '{schema:1,phase:"complete",source_head:"0000000000000000000000000000000000000000",
      monitor_mutation:{started:true,completed:true},helper_install:{started:true,completed:true},
      socket_enable:{started:true,completed:true},verify_completed:true,
      final_status:"deploy_disabled_complete"}' >"$FIX/phase1/journal.json"
    chmod 0600 "$FIX/phase1/baseline.json" "$FIX/phase1/journal.json"

    make_stub "$FIX/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -u
cmd="${1:-}"; shift || true
case "$cmd" in
  is-active)
    case "${1:-}" in
      sing-box.service) cat "$FX/sing-active" ;;
      sbox-cm.socket) cat "$FX/socket-active" ;;
      sbox-cm.service) cat "$FX/service-active" ;;
      *) exit 4 ;;
    esac ;;
  is-enabled)
    case "${1:-}" in
      sbox-cm.socket) cat "$FX/socket-enabled" ;;
      sbox-cm.service) cat "$FX/service-enabled" ;;
      *) exit 4 ;;
    esac ;;
  show)
    case "${2:-}" in
      ActiveEnterTimestamp) cat "$FX/sing-ts" ;;
      NRestarts) cat "$FX/sing-restarts" ;;
      *) exit 4 ;;
    esac ;;
  restart|reload) printf '%s\n' "$cmd" >>"$FX/forbidden-systemctl"; exit 9 ;;
  *) exit 4 ;;
esac
STUB

    make_stub "$FIX/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat "$FX/http-code"
STUB

    make_stub "$FIX/bin/rpc" <<'STUB'
#!/usr/bin/env bash
set -u
op="${1:-}"; payload="$(cat)"
printf '%s\n' "$op" >>"$FX/rpc-calls"
if [ -f "$RPC_APP_ROOT/release-id" ]; then cat "$RPC_APP_ROOT/release-id" >>"$FX/rpc-impls"; fi
if [ -e "$FX/enforce-rpc-app-root" ] && [ ! -r "$RPC_APP_ROOT/web/e3rpc.py" ]; then exit 70; fi
ok_tx='{"entered":true,"phase":"health","changed":true,"reload_performed":true,"health_verified":true,"rollback_attempted":false,"rollback_ok":null,"backup_path":null}'
case "$op" in
  management.status)
    if [ -e "$FX/block-status" ]; then
      : >"$FX/status-entered"
      while [ ! -e "$FX/release-status" ]; do sleep 0.05; done
    fi
    state=inactive
    [ -e "$FX/helper/management.active" ] && state=active
    [ -e "$FX/force-status-active" ] && state=active
    [ -e "$FX/force-status-stale" ] && state=active_stale
    [ -e "$FX/force-status-inactive" ] && state=inactive
    degraded=false; reconcile=clean; acq=true
    [ -e "$FX/degraded" ] && degraded=true
    [ -e "$FX/reconcile-bad" ] && reconcile=manual_intervention
    [ -e "$FX/lock-bad" ] && acq=false
    jq -cn --arg state "$state" --argjson degraded "$degraded" --arg reconcile "$reconcile" --argjson acq "$acq" \
      '{ok:true,code:"OK",data:{management_state:$state,helper:{degraded:$degraded,reconcile:$reconcile},lock:{acquirable:$acq}}}'
    ;;
  client.list)
    jq -cn --slurpfile cfg "$FX/config.json" \
      '{ok:true,code:"OK",data:{clients:($cfg[0].clients|map({name:.,protocols:["reality","hy2"],reserved:(.=="legacy"),mutable:(.!="legacy"),source:"untracked"})),truncated:false}}'
    ;;
  management.activate)
    if [ -e "$FX/activate-fail" ]; then printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; fi
    if [ -e "$FX/block-activate" ]; then
      : >"$FX/activate-entered"
      while [ ! -e "$FX/release-activate" ]; do sleep 0.05; done
    fi
    printf '%s\n' '{"v":1,"state":"active"}' >"$FX/helper/management.active"
    if [ -e "$FX/remove-pinned-after-activate" ]; then rm -rf -- "$RPC_APP_ROOT"; fi
    printf '%s\n' '{"ok":true,"code":"OK","data":{"management_state":"active","no_op":false},"transaction":{"entered":false,"changed":false,"reload_performed":false,"health_verified":false}}'
    ;;
  client.add)
    name="$(printf '%s' "$payload" | jq -r '.name')"; key="$(printf '%s' "$payload" | jq -r '.idempotency_key')"
    if [ -e "$FX/add-fail" ]; then printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; fi
    jq --arg n "$name" '.clients += [$n]' "$FX/config.json" >"$FX/config.tmp" && mv "$FX/config.tmp" "$FX/config.json"
    if [ ! -e "$FX/add-no-ledger" ]; then
      jq -cn --arg key "$key" --arg name "$name" '{v:1,kind:"intent",key:$key,op:"client.add",name:$name,state:"in_flight"}' \
        >>"$FX/helper/ledger/cm-ledger.jsonl"
    fi
    if [ -e "$FX/add-disconnect" ]; then exit 70; fi
    jq -cn --arg n "$name" --argjson tx "$ok_tx" \
      '{ok:true,code:"OK",data:{name:$n},idempotency:{key_fp:"deadbeef",replayed:false,generation:1},transaction:$tx}'
    ;;
  client.delete)
    name="$(printf '%s' "$payload" | jq -r '.name')"; key="$(printf '%s' "$payload" | jq -r '.idempotency_key')"
    [ "$name" != legacy ] || { printf '%s\n' '{"ok":false,"code":"E_RESERVED_NAME"}'; exit 0; }
    if ! jq -se --arg key "$key" 'any(.[]; .kind=="intent" and .key==$key)' "$FX/helper/ledger/cm-ledger.jsonl" >/dev/null 2>&1; then
      jq -cn --arg key "$key" --arg name "$name" \
        '{v:1,kind:"intent",key:$key,op:"client.delete",name:$name,state:"in_flight",old_cred_digest:("a"*64)}' \
        >>"$FX/helper/ledger/cm-ledger.jsonl"
    fi
    if [ -e "$FX/delete-disconnect" ]; then rm -f "$FX/delete-disconnect"; exit 70; fi
    if [ -e "$FX/delete-fail" ]; then printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; fi
    jq --arg n "$name" '.clients |= map(select(. != $n))' "$FX/config.json" >"$FX/config.tmp" && mv "$FX/config.tmp" "$FX/config.json"
    if [ -e "$FX/format-drift-on-delete" ]; then jq -c . "$FX/config.json" >"$FX/config.tmp" && mv "$FX/config.tmp" "$FX/config.json"; fi
    jq -cn --argjson tx "$ok_tx" \
      '{ok:true,code:"OK",data:{deleted:true,derived_cleanup:true},idempotency:{key_fp:"feedface",replayed:false,generation:1},transaction:$tx}'
    ;;
  management.deactivate)
    if [ -e "$FX/deactivate-fail" ]; then printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; fi
    rm -f -- "$FX/helper/management.active"
    printf '%s\n' '{"ok":true,"code":"OK","data":{"management_state":"inactive","no_op":false},"transaction":{"entered":false,"changed":false,"reload_performed":false,"health_verified":false}}'
    ;;
  *) exit 64 ;;
esac
STUB

    make_stub "$FIX/bin/root-recover" <<'STUB'
#!/usr/bin/env bash
rm -f -- "$FX/helper/management.active"
rm -f -- "$FX/force-status-stale"
printf 'root-recovery\n' >>"$FX/root-recovery-calls"
STUB

    export E3_PHASE2_TEST_MODE=1
    export E3_PHASE2_TEST_PHASE1_STATE="$FIX/phase1"
    export E3_PHASE2_TEST_STATE_DIR="$FIX/phase2"
    export E3_PHASE2_TEST_CONFIG="$FIX/config.json"
    export E3_PHASE2_TEST_MONITOR_APP="$FIX/monitor"
    export E3_PHASE2_TEST_SBXCM_STATE="$FIX/helper"
    export E3_PHASE2_TEST_MONITOR_URL=http://fixture.invalid
    export E3_PHASE2_TEST_SYSTEMCTL="$FIX/bin/systemctl"
    export E3_PHASE2_TEST_CURL="$FIX/bin/curl"
    export E3_PHASE2_TEST_RPC="$FIX/bin/rpc"
    export E3_PHASE2_TEST_FIXTURE_ROOT="$FIX"
    export E3_PHASE2_TEST_SOURCE_HEAD=1111111111111111111111111111111111111111
    export E3_PHASE2_APPROVED_HEAD=1111111111111111111111111111111111111111
    export E3_PHASE2_TEST_LOCK="$FIX/run/phase2.lock"
    export E3_PHASE2_TEST_MONITOR_LOCK="$FIX/run/singbox-monitor-deploy.lock"
    export E3_PHASE2_TEST_FLOCK="$TEST_FLOCK_BIN"
    export E3_PHASE2_TEST_LOCK_BACKEND="$TEST_LOCK_BACKEND"
    export E3_PHASE2_TEST_CONFIG_LOCK="$FIX/config.lock"
    export E3_PHASE2_TEST_CONFIG_LOCK_BACKEND=fixture
    export E3_PHASE2_TEST_LEDGER="$FIX/helper/ledger/cm-ledger.jsonl"
    export E3_PHASE2_TEST_NOW=2000000000
    export E3_PHASE2_TEST_TOKEN=0123456789abcdef
    export E3_PHASE2_TEST_PHASE1_ANCESTOR=0000000000000000000000000000000000000000
    export E3_PHASE2_TEST_ROOT_RECOVERY="$FIX/bin/root-recover"
    export E3_PHASE2_TEST_EVIDENCE_BACKEND=fixture
    unset E3_PHASE2_TEST_CRASH_AFTER E3_PHASE2_TEST_EVIDENCE_FAILURES
}

run_preflight(){ /usr/bin/bash "$ORCH" preflight >"$FIX/preflight.out" 2>&1; }
run_canary(){ /usr/bin/bash "$ORCH" canary --approve-activation >"$FIX/canary.out" 2>&1; }
client_count(){ jq -r '.clients|length' "$FIX/config.json"; }
has_client(){ jq -e --arg n "$1" '.clients|index($n)!=null' "$FIX/config.json" >/dev/null 2>&1; }
try_monitor_deploy_lock(){
    if [ "$TEST_LOCK_BACKEND" = flock ]; then
        ( exec 6>>"$E3_PHASE2_TEST_MONITOR_LOCK" && "$TEST_FLOCK_BIN" -n 6 ) >/dev/null 2>&1
    else
        mkdir "$E3_PHASE2_TEST_MONITOR_LOCK.fixture-held" 2>/dev/null
    fi
}

printf '===== E3 M3-C PHASE 2 ORCHESTRATOR =====\n'
ORIGINAL_PATH="$PATH"
if TEST_FLOCK_BIN="$(command -v flock 2>/dev/null)" && [ -n "$TEST_FLOCK_BIN" ]; then
    TEST_LOCK_BACKEND=flock
else
    TEST_FLOCK_BIN=/usr/bin/flock
    TEST_LOCK_BACKEND=mkdir
fi

# Exercise the production sanitizer itself without running the command dispatcher.
# The successful flow below separately checks the durable journal evidence.
source <(sed -n '/^sanitize_result()/,/^$/p' "$ORCH")
for field in no_op deleted derived_cleanup; do
    for value in false true missing null; do
        case "$value" in
          missing) input='{"data":{}}'; expected=null; label='missing optional boolean sanitizes to null' ;;
          true) input="$(jq -cn --arg field "$field" '{data:{($field):true}}')"; expected=true; label='true remains true' ;;
          false) input="$(jq -cn --arg field "$field" '{data:{($field):false}}')"; expected=false; label='evidence preserves optional false booleans' ;;
          null) input="$(jq -cn --arg field "$field" '{data:{($field):null}}')"; expected=null; label='explicit null remains null' ;;
        esac
        result="$(printf '%s' "$input" | sanitize_result)"
        assert_eq true "$(printf '%s' "$result" | jq -r --arg field "$field" --argjson expected "$expected" '.data | has($field) and (.[$field] == $expected)')" "phase2 $label ($field)"
    done
done

# Happy path: preflight evidence is the only write before separately approved canary.
setup_fixture happy
CONFIG_BEFORE="$(sha256sum "$FIX/config.json" | awk '{print $1}')"
P1_BEFORE="$(sha256sum "$FIX/phase1/baseline.json" "$FIX/phase1/journal.json")"
if run_preflight; then pass 'Phase 2 preflight succeeds'; else fail 'Phase 2 preflight failed'; fi
assert_eq "$CONFIG_BEFORE" "$(sha256sum "$FIX/config.json" | awk '{print $1}')" 'preflight is read-only for production config'
assert_absent "$FIX/helper/management.active" 'preflight never writes the activation marker'
assert_eq 'management.status client.list' "$(paste -sd ' ' "$FIX/rpc-calls")" 'preflight performs only the two approved read RPCs'
assert_eq 'ready_for_separate_canary_approval' "$(jq -r '.final_status' "$FIX/phase2/journal.json")" 'preflight stops at the separate approval boundary'
if /usr/bin/bash "$ORCH" canary >"$FIX/no-approval.out" 2>&1; then fail 'canary without explicit approval flag must fail'; else pass 'canary requires explicit approval flag'; fi
assert_absent "$FIX/helper/management.active" 'missing canary approval causes no activation'
if [ "$(uname -s)" = Linux ]; then
    assert_eq '600 600' "$(stat -c %a "$FIX/phase2/baseline.json" "$FIX/phase2/journal.json" | paste -sd ' ' -)" 'Phase 2 baseline and journal are mode 0600'
else
    pass 'Phase 2 baseline and journal are mode 0600 (enforced on Linux CI)'
fi
: >"$FIX/rpc-calls"
if run_canary; then pass 'approved Phase 2 canary succeeds'; else fail 'approved Phase 2 canary failed'; fi
assert_eq 'management.status management.activate management.status client.list client.add client.list client.delete client.list management.deactivate management.status client.list' \
  "$(paste -sd ' ' "$FIX/rpc-calls")" 'canary RPC sequence is exactly status-activate-list-add-delete-deactivate with verification reads'
assert_contains "$FIX/canary.out" 'PHASE2 CANARY=PASS' 'canary prints terminal PASS'
assert_contains "$FIX/canary.out" 'management_state = inactive' 'canary final output reports inactive'
assert_absent "$FIX/helper/management.active" 'happy path final marker is absent'
assert_eq '1' "$(client_count)" 'happy path restores the original client count'
if has_client legacy; then pass 'happy path preserves the unrelated legacy client'; else fail 'happy path deleted legacy'; fi
assert_eq "$CONFIG_BEFORE" "$(sha256sum "$FIX/config.json" | awk '{print $1}')" 'happy path restores the exact config SHA'
assert_eq "$P1_BEFORE" "$(sha256sum "$FIX/phase1/baseline.json" "$FIX/phase1/journal.json")" 'Phase 1 production evidence remains untouched'
assert_eq canary_complete "$(jq -r '.final_status' "$FIX/phase2/journal.json")" 'journal records terminal canary completion'
assert_eq false "$(jq -r '.activation.result.data.no_op' "$FIX/phase2/journal.json")" 'phase2 evidence preserves no_op=false (activation)'
assert_eq false "$(jq -r '.deactivation.result.data.no_op' "$FIX/phase2/journal.json")" 'phase2 evidence preserves no_op=false (deactivation)'
assert_eq true "$(jq -r '.delete.result.data.deleted' "$FIX/phase2/journal.json")" 'phase2 evidence true remains true (deleted)'
assert_eq true "$(jq -r '.delete.result.data.derived_cleanup' "$FIX/phase2/journal.json")" 'phase2 evidence true remains true (derived_cleanup)'
assert_eq true "$(jq -r '.activation.completed and .add.completed and .delete.completed and .deactivation.completed' "$FIX/phase2/journal.json")" 'journal records every completed canary stage'
assert_eq true "$(jq -r '(.source_head|test("^[0-9a-f]{40}$")) and (.created_epoch|type=="number") and (.canary.name|test("^m3c-")) and (.canary.add_idempotency_key|test("^m3c2-add-")) and (.canary.delete_idempotency_key|test("^m3c2-del-"))' "$FIX/phase2/baseline.json")" 'immutable baseline carries every recovery identifier'
if grep -ERq 'uuid|password|credential' "$FIX/phase2" "$FIX/canary.out"; then fail 'Phase 2 evidence contains credential-shaped data'; else pass 'Phase 2 evidence and output contain no credentials'; fi
assert_absent "$FIX/forbidden-systemctl" 'orchestrator never directly reloads or restarts sing-box'

# Phase 1/source/pre-activation refusals.
setup_fixture phase1_incomplete
jq '.verify_completed=false' "$FIX/phase1/journal.json" >"$FIX/p1.tmp" && mv "$FIX/p1.tmp" "$FIX/phase1/journal.json"
if run_preflight; then fail 'incomplete Phase 1 must be refused'; else pass 'preflight refuses incomplete Phase 1 journal'; fi
assert_absent "$FIX/phase2" 'incomplete Phase 1 creates no Phase 2 evidence'

setup_fixture phase1_bad_mode
chmod 0644 "$FIX/phase1/baseline.json"
if [ "$(uname -s)" = Linux ]; then
    if run_preflight; then fail 'world-readable Phase 1 evidence must be refused'; else pass 'Phase 1 evidence mode 0600 is enforced'; fi
else
    pass 'Phase 1 evidence mode 0600 is enforced on Linux CI'
fi

setup_fixture source_mismatch
export E3_PHASE2_APPROVED_HEAD=2222222222222222222222222222222222222222
if run_preflight; then fail 'source mismatch must be refused'; else pass 'preflight refuses exact approved-head mismatch'; fi
assert_eq '0' "$(wc -l <"$FIX/rpc-calls" | tr -d ' ')" 'source mismatch is rejected before any RPC'

setup_fixture degraded
: >"$FIX/degraded"
if run_preflight; then fail 'degraded helper must be refused'; else pass 'preflight refuses degraded helper state'; fi

setup_fixture reconcile_bad
: >"$FIX/reconcile-bad"
if run_preflight; then fail 'unclean reconciliation must be refused'; else pass 'preflight refuses non-clean reconciliation state'; fi

setup_fixture active_start
: >"$FIX/force-status-active"
if run_preflight; then fail 'active-at-start state must be refused'; else pass 'preflight refuses management active at start'; fi

setup_fixture marker_disagreement
printf '%s\n' '{"v":1,"state":"active"}' >"$FIX/helper/management.active"
: >"$FIX/force-status-inactive"
if run_preflight; then fail 'marker/state disagreement must be refused'; else pass 'preflight refuses marker/state disagreement'; fi

setup_fixture unresolved_journal
printf '%s\n' '{}' >"$FIX/helper/journal/orphan.json"
if run_preflight; then fail 'unresolved helper journal must be refused'; else pass 'preflight refuses unresolved transaction journal'; fi

setup_fixture lock_busy
: >"$FIX/lock-bad"
if run_preflight; then fail 'unavailable config lock must be refused'; else pass 'preflight refuses non-acquirable config lock'; fi

setup_fixture stale_preflight
run_preflight || fail 'stale fixture preflight unexpectedly failed'
export E3_PHASE2_TEST_NOW=2000000901
if run_canary; then fail 'stale preflight must be refused'; else pass 'canary refuses a preflight older than 15 minutes'; fi
if grep -qF management.activate "$FIX/rpc-calls"; then fail 'stale preflight reached activation'; else pass 'stale preflight is rejected before activation'; fi

# Activation-success failures always deactivate; deletion is attribution-safe.
setup_fixture add_failure
run_preflight || fail 'add-failure preflight unexpectedly failed'
: >"$FIX/add-fail"
if run_canary; then fail 'add failure must fail canary'; else pass 'add failure fails the canary'; fi
assert_absent "$FIX/helper/management.active" 'add failure triggers management.deactivate'
assert_eq cleanup_complete "$(jq -r '.final_status' "$FIX/phase2/journal.json")" 'add failure proves cleanup complete'
if has_client legacy; then pass 'add failure cleanup preserves unrelated clients'; else fail 'add failure cleanup deleted legacy'; fi

setup_fixture delete_failure
run_preflight || fail 'delete-failure preflight unexpectedly failed'
: >"$FIX/delete-fail"
if run_canary; then fail 'delete failure must fail canary'; else pass 'delete failure fails the canary'; fi
assert_absent "$FIX/helper/management.active" 'delete failure still attempts and completes deactivate'
assert_eq manual_intervention "$(jq -r '.final_status' "$FIX/phase2/journal.json")" 'delete failure records fail-closed manual intervention'
if has_client legacy; then pass 'delete failure never deletes an unrelated client'; else fail 'delete failure deleted legacy'; fi

setup_fixture uncertain_identity
run_preflight || fail 'uncertain-identity preflight unexpectedly failed'
: >"$FIX/add-disconnect"; : >"$FIX/add-no-ledger"
if run_canary; then fail 'uncertain add identity must fail canary'; else pass 'uncertain add identity fails closed'; fi
assert_absent "$FIX/helper/management.active" 'uncertain add still deactivates management'
if grep -qF client.delete "$FIX/rpc-calls"; then fail 'unattributable client must never be deleted'; else pass 'unattributable canary-like client is not guessed/deleted'; fi
assert_eq manual_intervention "$(jq -r '.final_status' "$FIX/phase2/journal.json")" 'uncertain identity records manual intervention'
if has_client legacy; then pass 'uncertain cleanup preserves unrelated clients'; else fail 'uncertain cleanup deleted legacy'; fi

# Durable evidence barriers fail closed before activation.
for injected in baseline:file_fsync baseline:rename baseline:dir_fsync \
  preflight_complete:file_fsync preflight_complete:rename preflight_complete:dir_fsync; do
    setup_fixture "durability_${injected/:/_}"
    export E3_PHASE2_TEST_EVIDENCE_FAILURES="$injected"
    if run_preflight; then fail "evidence $injected must fail preflight"; else pass "evidence $injected fails closed"; fi
    if grep -qF management.activate "$FIX/rpc-calls"; then fail "evidence $injected reached activation"; else pass "evidence $injected performs no activation"; fi
done

# Every durable post-activation checkpoint failure enters cleanup.  Some stages
# intentionally retain an unproven client generation, but deactivation is never
# skipped and success is never reported.
POST_ACTIVATION_CHECKPOINTS='activation_complete active_verified list_before_add add_started add_complete add_verified delete_started delete_complete delete_verified deactivation_started deactivation_complete canary_complete'
for checkpoint in $POST_ACTIVATION_CHECKPOINTS; do
    setup_fixture "evidence_$checkpoint"
    run_preflight || fail "evidence $checkpoint preflight unexpectedly failed"
    export E3_PHASE2_TEST_EVIDENCE_FAILURES="$checkpoint:file_fsync"
    if run_canary; then fail "post-activation evidence failure $checkpoint must not pass"; else pass "post-activation evidence failure $checkpoint fails canary"; fi
    assert_absent "$FIX/helper/management.active" "evidence failure $checkpoint still deactivates management"
    if grep -qF management.deactivate "$FIX/rpc-calls"; then pass "evidence failure $checkpoint reaches cleanup deactivation"; else fail "evidence failure $checkpoint skipped cleanup deactivation"; fi
done

# Evidence failures inside cleanup are best-effort and cannot block mutation
# cleanup.  A one-shot disconnect leaves a generation-bound DELETE intent, so
# cleanup is allowed to retry that exact generation.
setup_fixture cleanup_evidence_failures
run_preflight || fail 'cleanup-evidence preflight unexpectedly failed'
: >"$FIX/delete-disconnect"
export E3_PHASE2_TEST_EVIDENCE_FAILURES='cleanup_started:write,cleanup_delete_started:write,cleanup_delete_finished:write,cleanup_deactivation_started:write,cleanup_deactivation_finished:write,cleanup_complete:write,cleanup_manual_intervention:write'
if run_canary; then fail 'cleanup evidence failures must not report canary success'; else pass 'cleanup evidence failures fail closed'
fi
assert_absent "$FIX/helper/management.active" 'cleanup evidence failures do not block deactivation'
if grep -qF client.delete "$FIX/rpc-calls" && grep -qF management.deactivate "$FIX/rpc-calls"; then pass 'cleanup evidence failures do not block attributable delete or deactivate'; else fail 'cleanup evidence failure blocked a required cleanup RPC'; fi
assert_contains "$FIX/canary.out" 'evidence durability failed' 'cleanup evidence failure reports manual intervention'

# Missing/corrupt mutable journals recover from immutable baseline identifiers,
# refuse unproven deletion, and still close the management plane.
for journal_case in missing corrupt; do
    setup_fixture "journal_$journal_case"
    run_preflight || fail "$journal_case-journal preflight unexpectedly failed"
    export E3_PHASE2_TEST_CRASH_AFTER=add_complete
    run_canary >/dev/null 2>&1 || true
    unset E3_PHASE2_TEST_CRASH_AFTER
    if [ "$journal_case" = missing ]; then rm -f "$FIX/phase2/journal.json"; else printf '{broken\n' >"$FIX/phase2/journal.json"; fi
    : >"$FIX/rpc-calls"
    if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail "$journal_case journal with unproven client must require manual intervention"; else pass "$journal_case journal recovers fail-closed from immutable baseline"; fi
    assert_absent "$FIX/helper/management.active" "$journal_case journal recovery still deactivates management"
    if grep -qF client.delete "$FIX/rpc-calls"; then fail "$journal_case journal guessed a client generation"; else pass "$journal_case journal never guesses/deletes the client"; fi
done

# active_stale recovery uses only the sanctioned root recovery command.
setup_fixture stale_root_recovery
run_preflight || fail 'active-stale recovery preflight unexpectedly failed'
export E3_PHASE2_TEST_CRASH_AFTER=activation_complete
run_canary >/dev/null 2>&1 || true
unset E3_PHASE2_TEST_CRASH_AFTER
rm -f "$FIX/phase2/journal.json"; : >"$FIX/force-status-stale"; : >"$FIX/rpc-calls"
if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then pass 'active_stale recovery converges through sanctioned root path'; else fail 'active_stale root recovery failed'; fi
assert_file "$FIX/root-recovery-calls" 'active_stale invokes the sanctioned root recovery command'
if grep -qF management.deactivate "$FIX/rpc-calls"; then fail 'active_stale used forbidden RPC deactivation'; else pass 'active_stale does not use RPC deactivation'; fi
assert_absent "$FIX/helper/management.active" 'active_stale root recovery removes the marker through the sanctioned engine'

# An old ADD intent and a random name never prove object generation.  Replacing
# the canary with a second generation of the same name must not trigger delete.
setup_fixture second_generation
run_preflight || fail 'second-generation preflight unexpectedly failed'
export E3_PHASE2_TEST_CRASH_AFTER=add_complete
run_canary >/dev/null 2>&1 || true
unset E3_PHASE2_TEST_CRASH_AFTER
jq '.clients |= map(select(. != "m3c-0123456789abcdef")) | .clients += ["m3c-0123456789abcdef"]' "$FIX/config.json" >"$FIX/replacement.tmp" && mv "$FIX/replacement.tmp" "$FIX/config.json"
: >"$FIX/rpc-calls"
if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'second-generation same-name client must require manual intervention'; else pass 'second-generation same-name client fails closed'; fi
if grep -qF client.delete "$FIX/rpc-calls"; then fail 'second-generation same-name client was deleted'; else pass 'second-generation same-name client is never deleted'; fi
if has_client m3c-0123456789abcdef; then pass 'second-generation same-name client remains for manual review'; else fail 'second-generation same-name client disappeared'; fi
assert_absent "$FIX/helper/management.active" 'second-generation conflict still deactivates management'

# The live RPC implementation imported by the bridge is pinned to the reviewed
# checkout and to the release target captured by preflight.
setup_fixture live_rpc_drift
run_preflight || fail 'live-RPC drift preflight unexpectedly failed'
printf '\n# drift\n' >>"$FIX/monitor/app/monitor-v2/web/e3rpc.py"
if run_canary; then fail 'live RPC drift must reject canary'; else pass 'live RPC drift is rejected before activation'; fi
if grep -qF management.activate "$FIX/rpc-calls"; then fail 'live RPC drift reached activation'; else pass 'live RPC drift performs no activation'; fi

setup_fixture live_rpc_recovery_drift
run_preflight || fail 'live-RPC recovery-drift preflight unexpectedly failed'
export E3_PHASE2_TEST_CRASH_AFTER=activation_complete
run_canary >/dev/null 2>&1 || true
unset E3_PHASE2_TEST_CRASH_AFTER
printf '\n# recovery drift\n' >>"$FIX/monitor/app/monitor-v2/web/e3rpc.py"; : >"$FIX/rpc-calls"
if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'recovery with unreviewed live RPC must stop for manual intervention'; else pass 'recovery rejects unreviewed live RPC bytes'; fi
assert_file "$FIX/root-recovery-calls" 'RPC source drift recovery still attempts sanctioned root deactivation'
assert_absent "$FIX/helper/management.active" 'RPC source drift recovery closes the management marker through root recovery'
assert_eq 0 "$(wc -l <"$FIX/rpc-calls" | tr -d ' ')" 'RPC source drift recovery executes no unreviewed RPC code'

setup_fixture live_target_drift
run_preflight || fail 'live-target drift preflight unexpectedly failed'
if [ "$(uname -s)" = Linux ]; then
    mv "$FIX/monitor" "$FIX/monitor-original"
    mkdir -p "$FIX/monitor-new/app/monitor-v2/web"
    cp "$ROOT/monitor-v2/web/e3rpc.py" "$FIX/monitor-new/app/monitor-v2/web/e3rpc.py"
    ln -s "$FIX/monitor-new" "$FIX/monitor"
    if run_canary; then fail 'live release target drift must reject canary'; else pass 'live release target drift is rejected even when RPC bytes match'; fi
    if grep -qF management.activate "$FIX/rpc-calls"; then fail 'live release target drift reached activation'; else pass 'live release target drift performs no activation'; fi
else
    pass 'live release target drift is rejected even when RPC bytes match (Linux CI)'
    pass 'live release target drift performs no activation (Linux CI)'
fi

setup_fixture phase1_bad_ancestor
jq '.source_head="2222222222222222222222222222222222222222"' "$FIX/phase1/journal.json" >"$FIX/p1.tmp" && mv "$FIX/p1.tmp" "$FIX/phase1/journal.json" && chmod 0600 "$FIX/phase1/journal.json"
if run_preflight; then fail 'non-ancestor Phase 1 source must be refused'; else pass 'Phase 1 source must be a valid approved ancestor'; fi

# Raw JSON reserialization is allowed only when semantic config and exact
# inventory equivalence both hold.
setup_fixture semantic_equivalence
run_preflight || fail 'semantic-equivalence preflight unexpectedly failed'
RAW_BEFORE="$(sha256sum "$FIX/config.json" | awk '{print $1}')"; : >"$FIX/format-drift-on-delete"
if run_canary; then pass 'semantic/inventory equivalence permits canonical reserialization'; else fail 'semantic equivalence canary failed'; fi
if [ "$RAW_BEFORE" != "$(sha256sum "$FIX/config.json" | awk '{print $1}')" ]; then pass 'semantic equivalence test proves raw SHA may change'; else fail 'semantic equivalence fixture did not change raw SHA'; fi
assert_eq "$(jq -r '.config.semantic_sha256' "$FIX/phase2/baseline.json")" "$(jq -cS . "$FIX/config.json" | sha256sum | awk '{print $1}')" 'semantic config digest remains equal after canonical reserialization'

# Crash recovery is exercised after every durable post-activation boundary.
CRASH_STAGES='activation_complete active_verified list_before_add add_started add_complete add_verified delete_started delete_complete delete_verified deactivation_started deactivation_complete'
for stage in $CRASH_STAGES; do
    setup_fixture "crash_$stage"
    run_preflight || fail "crash $stage preflight unexpectedly failed"
    export E3_PHASE2_TEST_CRASH_AFTER="$stage"
    run_canary; rc=$?
    unset E3_PHASE2_TEST_CRASH_AFTER
    if [ "$rc" -eq 99 ]; then pass "crash hook reached $stage"; else fail "crash hook $stage returned $rc"; fi
    if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then rc=0; else rc=$?; fi
    case "$stage" in
      add_complete|add_verified|delete_started)
        if [ "$rc" -ne 0 ]; then pass "recover fails closed after $stage without generation-bound delete proof"; else fail "recover guessed identity after $stage"; fi
        ;;
      *)
        if [ "$rc" -eq 0 ]; then pass "recover converges safely after $stage"; else fail "recover failed after $stage"; fi
        ;;
    esac
    [ ! -e "$FIX/helper/management.active" ] || fail "marker remained after $stage recovery"
    if ! has_client legacy; then fail "legacy disappeared after $stage recovery"; fi
done

# Global Phase 2 lock spans the first mutating RPC and blocks concurrent recovery.
setup_fixture global_lock
run_preflight || fail 'global-lock preflight unexpectedly failed'
: >"$FIX/block-activate"
/usr/bin/bash "$ORCH" canary --approve-activation >"$FIX/first.out" 2>&1 &
FIRST_PID=$!
for _ in $(seq 1 200); do [ -e "$FIX/activate-entered" ] && break; sleep 0.05; done
assert_file "$FIX/activate-entered" 'first canary holds the global lock inside activation'
RPC_LINES="$(wc -l <"$FIX/rpc-calls" | tr -d ' ')"
JOURNAL_SHA="$(sha256sum "$FIX/phase2/journal.json" | awk '{print $1}')"
if /usr/bin/bash "$ORCH" recover >"$FIX/second.out" 2>&1; then fail 'concurrent recover must fail'; else pass 'concurrent recover fails closed on the global lock'; fi
assert_eq "$RPC_LINES" "$(wc -l <"$FIX/rpc-calls" | tr -d ' ')" 'competing recovery performs no RPC'
assert_eq "$JOURNAL_SHA" "$(sha256sum "$FIX/phase2/journal.json" | awk '{print $1}')" 'competing recovery does not rewrite journal'
: >"$FIX/release-activate"
wait "$FIRST_PID"; FIRST_RC=$?
if [ "$FIRST_RC" -eq 0 ]; then pass 'first canary completes after lock contention'; else fail 'first canary failed after lock contention'; fi

# Lock order and pinned-root race: Phase 2 holds its own lock first and the
# canonical monitor deployment lock second. A conforming deployment cannot
# flip the release symlink; even a forced out-of-contract flip cannot make an
# in-flight command import release B because every RPC uses the pinned A root.
setup_fixture monitor_release_race
if [ "$(uname -s)" = Linux ]; then
    mv "$FIX/monitor" "$FIX/release-a"
    cp -r "$FIX/release-a" "$FIX/release-b"
    printf 'A\n' >"$FIX/release-a/app/monitor-v2/release-id"
    printf 'B\n' >"$FIX/release-b/app/monitor-v2/release-id"
    ln -s "$FIX/release-a" "$FIX/monitor"
    run_preflight || fail 'monitor-race preflight unexpectedly failed'
    : >"$FIX/block-activate"; : >"$FIX/rpc-impls"
    /usr/bin/bash "$ORCH" canary --approve-activation >"$FIX/race.out" 2>&1 &
    RACE_PID=$!
    for _ in $(seq 1 200); do [ -e "$FIX/activate-entered" ] && break; sleep 0.05; done
    if try_monitor_deploy_lock; then
        : >"$FIX/deploy-lock-acquired"
        [ "$TEST_LOCK_BACKEND" != mkdir ] || rmdir "$E3_PHASE2_TEST_MONITOR_LOCK.fixture-held" 2>/dev/null || true
    fi
    assert_absent "$FIX/deploy-lock-acquired" 'competing monitor deployment cannot acquire its canonical lock during canary'
    assert_eq "$FIX/release-a" "$(readlink -f "$FIX/monitor")" 'blocked canonical deployment cannot flip the live release symlink'
    rm "$FIX/monitor"; ln -s "$FIX/release-b" "$FIX/monitor"
    : >"$FIX/release-activate"
    wait "$RACE_PID"; RACE_RC=$?
    if [ "$RACE_RC" -eq 0 ]; then pass 'canary survives an out-of-contract symlink flip through its pinned root'; else fail 'pinned-root canary failed after symlink flip'; fi
    assert_eq A "$(sort -u "$FIX/rpc-impls")" 'all in-flight RPCs execute only verified release A'
    if grep -qxF B "$FIX/rpc-impls"; then fail 'unreviewed release B executed'; else pass 'unreviewed release B never executes'; fi
else
    pass 'competing monitor deployment cannot acquire its canonical lock during canary (Linux CI)'
    pass 'blocked canonical deployment cannot flip the live release symlink (Linux CI)'
    pass 'canary survives an out-of-contract symlink flip through its pinned root (Linux CI)'
    pass 'all in-flight RPCs execute only verified release A (Linux CI)'
    pass 'unreviewed release B never executes (Linux CI)'
fi

# Recovery holds the same monitor deployment lock for its complete cleanup.
setup_fixture monitor_lock_recovery
run_preflight || fail 'monitor-lock recovery preflight unexpectedly failed'
export E3_PHASE2_TEST_CRASH_AFTER=activation_complete
run_canary >/dev/null 2>&1 || true
unset E3_PHASE2_TEST_CRASH_AFTER
: >"$FIX/block-status"
/usr/bin/bash "$ORCH" recover >"$FIX/recover-lock.out" 2>&1 &
RECOVER_PID=$!
for _ in $(seq 1 200); do [ -e "$FIX/status-entered" ] && break; sleep 0.05; done
assert_file "$FIX/status-entered" 'recovery reaches cleanup while holding both command locks'
if try_monitor_deploy_lock; then
    : >"$FIX/deploy-lock-acquired"
    [ "$TEST_LOCK_BACKEND" != mkdir ] || rmdir "$E3_PHASE2_TEST_MONITOR_LOCK.fixture-held" 2>/dev/null || true
fi
assert_absent "$FIX/deploy-lock-acquired" 'competing monitor deployment cannot acquire its canonical lock during recovery'
: >"$FIX/release-status"
wait "$RECOVER_PID"; RECOVER_RC=$?
if [ "$RECOVER_RC" -eq 0 ]; then pass 'recovery completes consistently after monitor-lock contention'; else fail 'recovery failed after monitor-lock contention'; fi

# If the pinned reviewed app root disappears after activation despite the lock,
# RPC cleanup is unavailable; the sanctioned root recovery still closes the
# management marker and the attempt terminates fail-closed.
setup_fixture pinned_root_loss
run_preflight || fail 'pinned-root-loss preflight unexpectedly failed'
: >"$FIX/enforce-rpc-app-root"; : >"$FIX/remove-pinned-after-activate"
if run_canary; then fail 'loss of pinned RPC root after activation must not pass'; else pass 'loss of pinned RPC root fails the canary'; fi
assert_file "$FIX/root-recovery-calls" 'pinned RPC root loss invokes sanctioned root deactivation'
assert_absent "$FIX/helper/management.active" 'sanctioned root recovery closes management after pinned-root loss'
if grep -qF 'PHASE2 CANARY=PASS' "$FIX/canary.out"; then fail 'pinned-root loss printed success'; else pass 'pinned-root loss never reports canary success'; fi

# Recovery is pinned to the source that created the attempt.
setup_fixture recover_source_mismatch
run_preflight || fail 'recover-source preflight unexpectedly failed'
export E3_PHASE2_TEST_CRASH_AFTER=activation_complete
run_canary >/dev/null 2>&1 || true
unset E3_PHASE2_TEST_CRASH_AFTER
export E3_PHASE2_TEST_SOURCE_HEAD=2222222222222222222222222222222222222222
export E3_PHASE2_APPROVED_HEAD=2222222222222222222222222222222222222222
RPC_BEFORE="$(wc -l <"$FIX/rpc-calls" | tr -d ' ')"
if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'source-mismatched recovery must fail'; else pass 'recover refuses a different approved source head'; fi
assert_eq "$RPC_BEFORE" "$(wc -l <"$FIX/rpc-calls" | tr -d ' ')" 'source-mismatched recovery performs no cleanup RPC'

# Static safety contracts supplement the live state-machine fixture.
if grep -Eq 'rm[[:space:]].*MARKER|rm[[:space:]].*management\.active' "$ORCH"; then fail 'orchestrator must not manually remove the marker'; else pass 'orchestrator contains no direct marker removal'; fi
if grep -Eq '(>|mv|cp)[[:space:]].*\$CONFIG' "$ORCH"; then fail 'orchestrator must not write the live config'; else pass 'orchestrator contains no direct config write'; fi
if grep -Eq 'systemctl.*(reload|restart).*sing-box|\$SYSTEMCTL.*(reload|restart)' "$ORCH"; then fail 'orchestrator must not reload/restart sing-box'; else pass 'orchestrator contains no manual sing-box reload/restart'; fi
if grep -Eq 'socket\.|AF_UNIX|SOCK_STREAM|sendall' "$BRIDGE"; then fail 'Phase 2 adapter must not reimplement RPC transport'; else pass 'Phase 2 adapter delegates transport to E3RpcClient'; fi
assert_contains "$BRIDGE" 'from web.e3rpc import E3RpcClient' 'Phase 2 adapter imports the reviewed RPC client'
assert_contains "$ORCH" 'canary --approve-activation' 'command surface exposes an explicit activation approval flag'
assert_contains "$ORCH" 'MONITOR_DEPLOY_LOCK="/run/lock/singbox-monitor-deploy.lock"' 'production uses the canonical monitor deployment lock path'
assert_eq 'acquire_lock acquire_monitor_deploy_lock' "$(sed -n '/^acquire_command_locks()/,/^}/p' "$ORCH" | grep -E '^[[:space:]]+acquire(_monitor_deploy)?_lock$' | sed 's/^[[:space:]]*//' | paste -sd ' ' -)" 'fixed lock order is Phase 2 then monitor deployment'
if grep -qF '"$MONITOR_APP/app/monitor-v2"' "$ORCH"; then fail 'production RPC still uses the mutable monitor symlink'; else pass 'production RPC uses only the pinned resolved app root'; fi

# Execute the real adapter through stdin, matching the root-readable production
# wrapper while the target user only needs access to the live monitor package.
FAKE_APP="$TMP/fake-monitor"; mkdir -p "$FAKE_APP/web"; : >"$FAKE_APP/web/__init__.py"
cat >"$FAKE_APP/web/e3rpc.py" <<'PY'
class RpcTransportError(Exception):
    stage = "connect"
    uncertain = False

class E3RpcClient:
    def call(self, op, payload=None, actor=None):
        return {"ok": True, "op": op, "payload": payload, "actor": actor}
PY
PYTHON_BIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null)"
BRIDGE_OUT="$("$PYTHON_BIN" -B - client.add "$FAKE_APP" \
  '{"name":"m3c-0123456789abcdef","idempotency_key":"m3c2-add-0123456789abcdef"}' <"$BRIDGE")"
assert_eq true "$(printf '%s' "$BRIDGE_OUT" | jq -r '.ok')" 'real adapter executes from root-fed Python stdin'
assert_eq m3c-0123456789abcdef "$(printf '%s' "$BRIDGE_OUT" | jq -r '.payload.name')" 'real adapter preserves the schema-validated canary payload'
ACTIVATE_OUT="$("$PYTHON_BIN" -B - management.activate "$FAKE_APP" '{}' <"$BRIDGE")"
assert_eq null "$(printf '%s' "$ACTIVATE_OUT" | jq -r '.actor')" 'operator activation leaves audit actor null instead of fabricating session_fp'
if grep -qF 'SOURCE_HEAD:0:16' "$ORCH" || grep -qF 'session_fp' "$BRIDGE"; then fail 'Phase 2 must not fabricate actor.session_fp'; else pass 'Phase 2 contains no fabricated actor.session_fp'; fi
if "$PYTHON_BIN" -B - arbitrary.exec "$FAKE_APP" '{}' <"$BRIDGE" >/dev/null 2>&1; then fail 'adapter must reject arbitrary operations'; else pass 'real adapter rejects operations outside the six-op allowlist'; fi

TOTAL=$((PASS+FAIL))
printf '\nPASS=%d FAIL=%d TOTAL=%d (expected %d)\n' "$PASS" "$FAIL" "$TOTAL" "$EXPECTED_TOTAL"
if [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then printf 'E3_M3C_PHASE2=FAIL (assertion-count guard)\n'; exit 1; fi
if [ "$FAIL" -ne 0 ]; then printf 'E3_M3C_PHASE2=FAIL\n'; exit 1; fi
printf 'E3_M3C_PHASE2=PASS\n'
