#!/usr/bin/env bash
# M3-C Phase 2 activation/canary orchestrator integration suite.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORCH="$ROOT/monitor-v2/deploy/e3-m3c-phase2.sh"
BRIDGE="$ROOT/monitor-v2/deploy/e3-m3c-phase2-rpc.py"
TMP="$(mktemp -d)"
PASS=0
FAIL=0
EXPECTED_TOTAL=84

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
      "$FIX/monitor/app/monitor-v2" "$FIX/run"
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
    jq -n '{schema:1,phase:"complete",source_head:"phase1-production-head",
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
ok_tx='{"entered":true,"phase":"health","changed":true,"reload_performed":true,"health_verified":true,"rollback_attempted":false,"rollback_ok":null,"backup_path":null}'
case "$op" in
  management.status)
    state=inactive
    [ -e "$FX/helper/management.active" ] && state=active
    [ -e "$FX/force-status-active" ] && state=active
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
    name="$(printf '%s' "$payload" | jq -r '.name')"
    if [ -e "$FX/delete-fail" ]; then printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; fi
    [ "$name" != legacy ] || { printf '%s\n' '{"ok":false,"code":"E_RESERVED_NAME"}'; exit 0; }
    jq --arg n "$name" '.clients |= map(select(. != $n))' "$FX/config.json" >"$FX/config.tmp" && mv "$FX/config.tmp" "$FX/config.json"
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
    export E3_PHASE2_TEST_FLOCK="$TEST_FLOCK_BIN"
    export E3_PHASE2_TEST_LOCK_BACKEND="$TEST_LOCK_BACKEND"
    export E3_PHASE2_TEST_CONFIG_LOCK="$FIX/config.lock"
    export E3_PHASE2_TEST_CONFIG_LOCK_BACKEND=fixture
    export E3_PHASE2_TEST_LEDGER="$FIX/helper/ledger/cm-ledger.jsonl"
    export E3_PHASE2_TEST_NOW=2000000000
    export E3_PHASE2_TEST_TOKEN=0123456789abcdef
    unset E3_PHASE2_TEST_CRASH_AFTER
}

run_preflight(){ /usr/bin/bash "$ORCH" preflight >"$FIX/preflight.out" 2>&1; }
run_canary(){ /usr/bin/bash "$ORCH" canary --approve-activation >"$FIX/canary.out" 2>&1; }
client_count(){ jq -r '.clients|length' "$FIX/config.json"; }
has_client(){ jq -e --arg n "$1" '.clients|index($n)!=null' "$FIX/config.json" >/dev/null 2>&1; }

printf '===== E3 M3-C PHASE 2 ORCHESTRATOR =====\n'
ORIGINAL_PATH="$PATH"
if TEST_FLOCK_BIN="$(command -v flock 2>/dev/null)" && [ -n "$TEST_FLOCK_BIN" ]; then
    TEST_LOCK_BACKEND=flock
else
    TEST_FLOCK_BIN=/usr/bin/flock
    TEST_LOCK_BACKEND=mkdir
fi

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
assert_eq true "$(jq -r '.activation.completed and .add.completed and .delete.completed and .deactivation.completed' "$FIX/phase2/journal.json")" 'journal records every completed canary stage'
if grep -ERq 'uuid|password|credential' "$FIX/phase2" "$FIX/canary.out"; then fail 'Phase 2 evidence contains credential-shaped data'; else pass 'Phase 2 evidence and output contain no credentials'; fi
assert_absent "$FIX/forbidden-systemctl" 'orchestrator never directly reloads or restarts sing-box'

# Phase 1/source/pre-activation refusals.
setup_fixture phase1_incomplete
jq '.verify_completed=false' "$FIX/phase1/journal.json" >"$FIX/p1.tmp" && mv "$FIX/p1.tmp" "$FIX/phase1/journal.json"
if run_preflight; then fail 'incomplete Phase 1 must be refused'; else pass 'preflight refuses incomplete Phase 1 journal'; fi
assert_absent "$FIX/phase2" 'incomplete Phase 1 creates no Phase 2 evidence'

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

# Crash recovery is exercised after every durable post-activation boundary.
CRASH_STAGES='activation_complete active_verified list_before_add add_started add_complete add_verified delete_started delete_complete delete_verified deactivation_started deactivation_complete'
for stage in $CRASH_STAGES; do
    setup_fixture "crash_$stage"
    run_preflight || fail "crash $stage preflight unexpectedly failed"
    export E3_PHASE2_TEST_CRASH_AFTER="$stage"
    run_canary; rc=$?
    unset E3_PHASE2_TEST_CRASH_AFTER
    if [ "$rc" -eq 99 ]; then pass "crash hook reached $stage"; else fail "crash hook $stage returned $rc"; fi
    if /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then
        pass "recover converges safely after $stage"
    else
        fail "recover failed after $stage"
    fi
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
if "$PYTHON_BIN" -B - arbitrary.exec "$FAKE_APP" '{}' <"$BRIDGE" >/dev/null 2>&1; then fail 'adapter must reject arbitrary operations'; else pass 'real adapter rejects operations outside the six-op allowlist'; fi

TOTAL=$((PASS+FAIL))
printf '\nPASS=%d FAIL=%d TOTAL=%d (expected %d)\n' "$PASS" "$FAIL" "$TOTAL" "$EXPECTED_TOTAL"
if [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then printf 'E3_M3C_PHASE2=FAIL (assertion-count guard)\n'; exit 1; fi
if [ "$FAIL" -ne 0 ]; then printf 'E3_M3C_PHASE2=FAIL\n'; exit 1; fi
printf 'E3_M3C_PHASE2=PASS\n'
