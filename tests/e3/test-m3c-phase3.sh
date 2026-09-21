#!/usr/bin/env bash
# M3-C Phase 3 persistent go-live orchestrator integration suite.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORCH="$ROOT/monitor-v2/deploy/e3-m3c-phase3.sh"
TMP="$(mktemp -d)"
PASS=0; FAIL=0; EXPECTED_TOTAL=94
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_file(){ [ -e "$1" ] && pass "$2" || fail "$2 (missing $1)"; }
assert_absent(){ [ ! -e "$1" ] && pass "$2" || fail "$2 (present $1)"; }
assert_contains(){ grep -qF "$2" "$1" && pass "$3" || fail "$3 (missing [$2])"; }
cleanup(){ if [ "${E3_M3C3_KEEP_TMP:-0}" = 1 ]; then printf 'fixture kept: %s\n' "$TMP"; else rm -rf -- "$TMP"; fi; }
trap cleanup EXIT

make_stub(){ local p="$1"; mkdir -p "$(dirname "$p")"; cp /dev/stdin "$p"; chmod 0755 "$p"; }

setup_fixture(){
    local name="$1" sha size sem inv canonical_inv
    FIX="$TMP/$name"; export FX="$FIX"
    mkdir -p "$FIX/bin" "$FIX/phase2" "$FIX/helper/journal" "$FIX/monitor/app/monitor-v2/web" "$FIX/run"
    chmod 0700 "$FIX/phase2"
    cp "$ROOT/monitor-v2/web/e3rpc.py" "$FIX/monitor/app/monitor-v2/web/e3rpc.py"
    jq -n '{inbounds:[],clients:["legacy"],service:{api:{listen:"127.0.0.1:9090"}}}' >"$FIX/config.json"
    sha="$(sha256sum "$FIX/config.json"|awk '{print $1}')"; size="$(stat -c %s "$FIX/config.json")"; sem="$(jq -cS . "$FIX/config.json"|sha256sum|awk '{print $1}')"
    canonical_inv="$(jq -cSn '[{name:"legacy",protocols:["reality","hy2"],reserved:true,mutable:false,source:"untracked"}]|sort_by(.name)')"
    inv="$(printf '%s' "$canonical_inv"|sha256sum|awk '{print $1}')"
    printf 'active\n' >"$FIX/sing-active"; printf 'Mon 2026-09-14 15:50:36 UTC\n' >"$FIX/sing-ts"; printf '0\n' >"$FIX/sing-restarts"
    printf 'active\n' >"$FIX/socket-active"; printf 'enabled\n' >"$FIX/socket-enabled"; printf 'active\n' >"$FIX/service-active"; printf 'disabled\n' >"$FIX/service-enabled"; printf '200\n' >"$FIX/http-code"
    : >"$FIX/config.lock"; : >"$FIX/rpc-calls"
    jq -n --arg ts "$(cat "$FIX/sing-ts")" '{schema:1,source_head:("1"*40),created_epoch:1999999000,canary:{name:"m3c-oldcanary",add_idempotency_key:"m3c2-add-oldcanary",delete_idempotency_key:"m3c2-del-oldcanary"},live_rpc:{target:"/old",sha256:("a"*64)},config:{sha256:("b"*64),size:1,semantic_sha256:("c"*64)},singbox:{active:"active",active_enter_timestamp:$ts,nrestarts:0},inventory:{sha256:("d"*64),count:1},management_state:"inactive"}' >"$FIX/phase2/baseline.json"
    jq -n --arg sha "$sha" --argjson size "$size" --arg sem "$sem" --arg inv "$inv" '{schema:1,source_head:("1"*40),phase:"complete",preflight_created_epoch:1999999000,canary:{name:"m3c-oldcanary"},activation:{started:true,completed:true},add:{started:true,completed:true},delete:{started:true,completed:true},deactivation:{started:true,completed:true},final_measurements:{config:{sha256:$sha,size:$size,semantic_sha256:$sem},inventory:{sha256:$inv,count:1},singbox:{active_enter_timestamp:"Mon 2026-09-14 15:50:36 UTC",nrestarts:0},management_state:"inactive"},final_status:"canary_complete"}' >"$FIX/phase2/journal.json"
    chmod 0600 "$FIX/phase2/baseline.json" "$FIX/phase2/journal.json"

    make_stub "$FIX/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
 is-active) case "${2:-}" in sing-box.service) cat "$FX/sing-active";; sbox-cm.socket) cat "$FX/socket-active";; sbox-cm.service) cat "$FX/service-active";; esac;;
 is-enabled) case "${2:-}" in sbox-cm.socket) cat "$FX/socket-enabled";; sbox-cm.service) cat "$FX/service-enabled";; esac;;
 show) case "${3:-}" in ActiveEnterTimestamp) cat "$FX/sing-ts";; NRestarts) cat "$FX/sing-restarts";; esac;;
 restart|reload) printf '%s\n' "$1" >>"$FX/forbidden-systemctl"; exit 9;;
 *) exit 4;;
esac
STUB
    make_stub "$FIX/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat "$FX/http-code"
STUB
    make_stub "$FIX/bin/rpc" <<'STUB'
#!/usr/bin/env bash
set -u
op="${1:-}"; cat >/dev/null; printf '%s\n' "$op" >>"$FX/rpc-calls"
if [ -e "$FX/enforce-root" ] && [ ! -r "$RPC_APP_ROOT/web/e3rpc.py" ]; then exit 70; fi
state=inactive; [ -e "$FX/helper/management.active" ] && state=active
case "$op" in
 management.status)
   if [ -e "$FX/block-status" ]; then : >"$FX/status-entered"; while [ ! -e "$FX/release-status" ]; do sleep 0.05; done; fi
   if [ -e "$FX/status-transport-fail" ] || { [ "$state" = active ] && [ -e "$FX/status-fail-after-active" ]; }; then exit 70; fi
   [ -e "$FX/force-status-active" ] && state=active
   degraded=false; reconcile=clean; acq=true
   [ -e "$FX/degraded" ] && degraded=true; [ -e "$FX/reconcile-bad" ] && reconcile=manual_intervention; [ -e "$FX/lock-bad" ] && acq=false
   jq -cn --arg state "$state" --argjson degraded "$degraded" --arg reconcile "$reconcile" --argjson acq "$acq" '{ok:true,data:{management_state:$state,helper:{degraded:$degraded,reconcile:$reconcile},lock:{acquirable:$acq}}}';;
 client.list)
   clients='["legacy"]'; [ -e "$FX/inventory-drift" ] && clients='["legacy","drift"]'; [ -e "$FX/canary-remains" ] && clients='["legacy","m3c-oldcanary"]'
   jq -cn --argjson names "$clients" '{ok:true,data:{clients:($names|map({name:.,protocols:["reality","hy2"],reserved:(.=="legacy"),mutable:(.!="legacy"),source:"untracked"})),truncated:false}}';;
 management.activate)
   [ -e "$FX/block-activate" ] && { : >"$FX/activate-entered"; while [ ! -e "$FX/release-activate" ]; do sleep 0.05; done; }
    [ -e "$FX/activate-transport-fail" ] && exit 70
    [ -e "$FX/activate-reject" ] && { printf '%s\n' '{"ok":false,"code":"E_TEST"}'; exit 0; }
   [ -e "$FX/activate-noop" ] && { printf '%s\n' '{"ok":true,"data":{"management_state":"active","no_op":true}}'; exit 0; }
   mkdir -p "$FX/helper"; printf '%s\n' '{"v":1,"state":"active"}' >"$FX/helper/management.active"; chmod 0644 "$FX/helper/management.active"
   [ -e "$FX/bad-marker-json" ] && printf 'bad\n' >"$FX/helper/management.active"
   [ -e "$FX/bad-marker-mode" ] && chmod 0600 "$FX/helper/management.active"
   [ -e "$FX/remove-pinned-after-activate" ] && rm -rf -- "$RPC_APP_ROOT"
   printf '%s\n' '{"ok":true,"data":{"management_state":"active","no_op":false}}';;
 management.deactivate)
   [ -e "$FX/deactivate-fail" ] && { printf '%s\n' '{"ok":false}'; exit 0; }
   rm -f -- "$FX/helper/management.active"; printf '%s\n' '{"ok":true,"data":{"management_state":"inactive","no_op":false}}';;
 *) exit 64;;
esac
STUB
    make_stub "$FIX/bin/root-recover" <<'STUB'
#!/usr/bin/env bash
rm -f -- "$FX/helper/management.active"; printf 'root\n' >>"$FX/root-recovery-calls"
STUB
    export E3_PHASE3_TEST_MODE=1 E3_PHASE3_TEST_PHASE2_STATE="$FIX/phase2" E3_PHASE3_TEST_STATE_DIR="$FIX/phase3"
    export E3_PHASE3_TEST_CONFIG="$FIX/config.json" E3_PHASE3_TEST_MONITOR_APP="$FIX/monitor" E3_PHASE3_TEST_SBXCM_STATE="$FIX/helper"
    export E3_PHASE3_TEST_SYSTEMCTL="$FIX/bin/systemctl" E3_PHASE3_TEST_CURL="$FIX/bin/curl" E3_PHASE3_TEST_RPC="$FIX/bin/rpc" E3_PHASE3_TEST_FIXTURE_ROOT="$FIX"
    export E3_PHASE3_TEST_SOURCE_HEAD=2222222222222222222222222222222222222222 E3_PHASE3_APPROVED_HEAD=2222222222222222222222222222222222222222
    export E3_PHASE3_TEST_LOCK="$FIX/run/phase3.lock" E3_PHASE3_TEST_MONITOR_LOCK="$FIX/run/singbox-monitor-deploy.lock" E3_PHASE3_TEST_FLOCK="$TEST_FLOCK_BIN" E3_PHASE3_TEST_LOCK_BACKEND="$TEST_LOCK_BACKEND"
    export E3_PHASE3_TEST_CONFIG_LOCK="$FIX/config.lock" E3_PHASE3_TEST_CONFIG_LOCK_BACKEND=fixture E3_PHASE3_TEST_NOW=2000000000 E3_PHASE3_TEST_PHASE2_ANCESTOR=1111111111111111111111111111111111111111
    export E3_PHASE3_TEST_ROOT_RECOVERY="$FIX/bin/root-recover" E3_PHASE3_TEST_EVIDENCE_BACKEND=fixture
    unset E3_PHASE3_TEST_CRASH_AFTER E3_PHASE3_TEST_EVIDENCE_FAILURES E3_PHASE3_TEST_SOURCE_DIRTY
}

run_preflight(){ /usr/bin/bash "$ORCH" preflight >"$FIX/preflight.out" 2>&1; }
run_enable(){ /usr/bin/bash "$ORCH" enable --approve-go-live >"$FIX/enable.out" 2>&1; }
run_recover(){ /usr/bin/bash "$ORCH" recover >"$FIX/recover.out" 2>&1; }

printf '===== E3 M3-C PHASE 3 ORCHESTRATOR =====\n'
if TEST_FLOCK_BIN="$(command -v flock 2>/dev/null)" && [ -n "$TEST_FLOCK_BIN" ]; then TEST_LOCK_BACKEND=flock; else TEST_FLOCK_BIN=/usr/bin/flock; TEST_LOCK_BACKEND=mkdir; fi

# Exercise the production sanitizer itself without running the command dispatcher.
# The successful flow below separately checks the durable journal evidence.
source <(sed -n '/^sanitize_result()/,/^$/p' "$ORCH")
for field in no_op; do
    for value in false true missing null; do
        case "$value" in
          missing) input='{"data":{}}'; expected=null; label='missing optional boolean sanitizes to null' ;;
          true) input="$(jq -cn --arg field "$field" '{data:{($field):true}}')"; expected=true; label='true remains true' ;;
          false) input="$(jq -cn --arg field "$field" '{data:{($field):false}}')"; expected=false; label='evidence preserves optional false booleans' ;;
          null) input="$(jq -cn --arg field "$field" '{data:{($field):null}}')"; expected=null; label='explicit null remains null' ;;
        esac
        result="$(printf '%s' "$input" | sanitize_result)"
        assert_eq true "$(printf '%s' "$result" | jq -r --arg field "$field" --argjson expected "$expected" '.data | has($field) and (.[$field] == $expected)')" "phase3 $label ($field)"
    done
done

# Happy path and hard approval boundary.
setup_fixture happy
CFG_SHA="$(sha256sum "$FIX/config.json"|awk '{print $1}')"; CFG_SEM="$(jq -cS . "$FIX/config.json"|sha256sum|awk '{print $1}')"; CFG_SIZE="$(stat -c %s "$FIX/config.json")"
run_preflight || fail 'happy preflight executes'
assert_contains "$FIX/preflight.out" 'PHASE3 PREFLIGHT=PASS' 'preflight prints PASS'
assert_contains "$FIX/preflight.out" 'HARD STOP' 'preflight prints hard stop'
assert_absent "$FIX/helper/management.active" 'preflight never activates management'
assert_eq ready_for_separate_go_live_approval "$(jq -r .final_status "$FIX/phase3/journal.json")" 'preflight journal freezes approval boundary'
if [ "$(uname -s)" = Linux ]; then
  assert_eq 600 "$(stat -c %a "$FIX/phase3/baseline.json")" 'baseline is mode 0600'
  assert_eq 600 "$(stat -c %a "$FIX/phase3/journal.json")" 'journal is mode 0600'
else
  pass 'baseline mode 0600 is enforced on Linux CI'
  pass 'journal mode 0600 is enforced on Linux CI'
fi
RPC_BEFORE="$(wc -l <"$FIX/rpc-calls"|tr -d ' ')"; /usr/bin/bash "$ORCH" enable >"$FIX/no-approval.out" 2>&1 && fail 'enable without approval accepted' || pass 'enable without approval rejected'
assert_eq "$RPC_BEFORE" "$(wc -l <"$FIX/rpc-calls"|tr -d ' ')" 'missing approval performs zero RPC mutation'
: >"$FIX/rpc-calls"; run_enable || fail 'happy enable executes'
assert_eq 1 "$(grep -c '^management.activate$' "$FIX/rpc-calls")" 'success calls management.activate exactly once'
assert_eq 0 "$(grep -c '^client.add$\|^client.delete$' "$FIX/rpc-calls")" 'success calls zero client mutation RPCs'
assert_eq 0 "$(grep -c '^management.deactivate$' "$FIX/rpc-calls")" 'success never deactivates'
assert_file "$FIX/helper/management.active" 'success leaves marker present'
assert_eq go_live_active "$(jq -r .final_status "$FIX/phase3/journal.json")" 'success journal is go_live_active'
assert_eq false "$(jq -r '.activation.result.data.no_op' "$FIX/phase3/journal.json")" 'phase3 activation evidence preserves no_op=false'
assert_eq true "$(jq -r '.activation.started and .activation.completed' "$FIX/phase3/journal.json")" 'activation checkpoints are complete'
assert_contains "$FIX/enable.out" 'PHASE3 GO_LIVE=PASS' 'success prints go-live PASS'
assert_contains "$FIX/enable.out" 'E3 MANAGEMENT ENABLED = YES' 'success prints enabled contract'
assert_eq "$CFG_SHA" "$(sha256sum "$FIX/config.json"|awk '{print $1}')" 'raw config SHA unchanged'
assert_eq "$CFG_SEM" "$(jq -cS . "$FIX/config.json"|sha256sum|awk '{print $1}')" 'semantic config SHA unchanged'
assert_eq "$CFG_SIZE" "$(stat -c %s "$FIX/config.json")" 'config size unchanged'
assert_eq "$(jq -r .inventory.sha256 "$FIX/phase3/baseline.json")" "$(jq -r .final_measurements.inventory.sha256 "$FIX/phase3/journal.json")" 'exact inventory hash unchanged'
assert_eq "$(jq -r .singbox.active_enter_timestamp "$FIX/phase3/baseline.json")" "$(jq -r .final_measurements.singbox.active_enter_timestamp "$FIX/phase3/journal.json")" 'sing-box timestamp unchanged'
assert_eq "$(jq -r .singbox.nrestarts "$FIX/phase3/baseline.json")" "$(jq -r .final_measurements.singbox.nrestarts "$FIX/phase3/journal.json")" 'sing-box restart count unchanged'
assert_absent "$FIX/forbidden-systemctl" 'orchestrator never reloads/restarts sing-box'
run_recover && fail 'recover disabled completed go-live' || pass 'recover refuses completed active go-live'
assert_file "$FIX/helper/management.active" 'completed go-live remains active after refused recover'

# Phase 2/source/evidence and preactivation gate refusals.
setup_fixture p2-incomplete; jq '.final_status="cleanup_complete"' "$FIX/phase2/journal.json" >"$FIX/t" && mv "$FIX/t" "$FIX/phase2/journal.json"; chmod 0600 "$FIX/phase2/journal.json"; run_preflight && fail 'incomplete Phase 2 accepted' || pass 'incomplete Phase 2 rejected'
setup_fixture p2-ancestor; export E3_PHASE3_TEST_PHASE2_ANCESTOR=ffffffffffffffffffffffffffffffffffffffff; run_preflight && fail 'non-ancestor Phase 2 accepted' || pass 'non-ancestor Phase 2 rejected'
setup_fixture wrong-head; export E3_PHASE3_APPROVED_HEAD=ffffffffffffffffffffffffffffffffffffffff; run_preflight && fail 'wrong approved HEAD accepted' || pass 'wrong approved HEAD rejected'
setup_fixture dirty-head; export E3_PHASE3_TEST_SOURCE_DIRTY=1; run_preflight && fail 'dirty checkout accepted' || pass 'dirty checkout rejected'
setup_fixture unsafe-mode; chmod 0644 "$FIX/phase2/journal.json"; if [ "$(uname -s)" = Linux ]; then run_preflight && fail 'unsafe evidence accepted' || pass 'unsafe Phase 2 evidence mode rejected'; else pass 'unsafe evidence permission gate exercised on Linux CI'; fi
setup_fixture unsafe-dir; chmod 0755 "$FIX/phase2"; if [ "$(uname -s)" = Linux ]; then run_preflight && fail 'unsafe evidence directory accepted' || pass 'unsafe Phase 2 directory mode rejected'; else pass 'unsafe evidence directory gate exercised on Linux CI'; fi
setup_fixture marker; printf '{}' >"$FIX/helper/management.active"; run_preflight && fail 'existing marker accepted' || pass 'existing marker rejected'
setup_fixture active; touch "$FIX/force-status-active"; run_preflight && fail 'active management accepted' || pass 'active management rejected'
setup_fixture config-drift; printf ' ' >>"$FIX/config.json"; run_preflight && fail 'raw config drift accepted' || pass 'raw config drift rejected'
setup_fixture inventory-drift; touch "$FIX/inventory-drift"; run_preflight && fail 'inventory drift accepted' || pass 'inventory drift rejected'
setup_fixture canary-remains; touch "$FIX/canary-remains"; run_preflight && fail 'Phase 2 canary remnant accepted' || pass 'Phase 2 canary remnant rejected'
setup_fixture sing-restart; printf '1\n' >"$FIX/sing-restarts"; run_preflight && fail 'sing-box restart drift accepted' || pass 'sing-box restart drift rejected'
setup_fixture sing-time; printf 'changed\n' >"$FIX/sing-ts"; run_preflight && fail 'sing-box timestamp drift accepted' || pass 'sing-box timestamp drift rejected'
setup_fixture degraded; touch "$FIX/degraded"; run_preflight && fail 'degraded helper accepted' || pass 'degraded helper rejected'
setup_fixture reconcile; touch "$FIX/reconcile-bad"; run_preflight && fail 'unresolved reconciliation accepted' || pass 'unresolved reconciliation rejected'
setup_fixture tx-journal; printf '{}' >"$FIX/helper/journal/open.json"; run_preflight && fail 'transaction journal accepted' || pass 'transaction journal rejected'
setup_fixture lock-busy; touch "$FIX/config-lock-busy"; run_preflight && fail 'busy config lock accepted' || pass 'busy config lock rejected'
setup_fixture monitor-http; printf '500\n' >"$FIX/http-code"; run_preflight && fail 'unhealthy monitor accepted' || pass 'unhealthy monitor rejected'
setup_fixture monitor-hash; printf '# drift\n' >>"$FIX/monitor/app/monitor-v2/web/e3rpc.py"; run_preflight && fail 'monitor source drift accepted' || pass 'monitor source drift rejected'

# TTL and post-activation fail-closed behavior.
setup_fixture stale; run_preflight || fail 'stale case preflight'; export E3_PHASE3_TEST_NOW=2000000901; run_enable && fail 'stale preflight accepted' || pass 'stale preflight rejected'; assert_absent "$FIX/helper/management.active" 'stale preflight causes zero activation'
setup_fixture activate-transport; run_preflight || fail 'transport preflight'; touch "$FIX/activate-transport-fail"; run_enable && fail 'activation transport failure passed' || pass 'activation transport failure fails closed'; assert_absent "$FIX/helper/management.active" 'transport failure leaves marker absent'
setup_fixture activate-reject; run_preflight || fail 'reject preflight'; touch "$FIX/activate-reject"; run_enable && fail 'activation rejection passed' || pass 'activation rejection fails closed'; assert_absent "$FIX/helper/management.active" 'activation rejection leaves marker absent'
setup_fixture activate-noop; run_preflight || fail 'no-op preflight'; touch "$FIX/activate-noop"; run_enable && fail 'activation no-op accepted' || pass 'activation no-op is not go-live success'; assert_absent "$FIX/helper/management.active" 'activation no-op cleanup leaves marker absent'
setup_fixture bad-marker; run_preflight || fail 'bad marker preflight'; touch "$FIX/bad-marker-json"; run_enable && fail 'invalid marker passed' || pass 'invalid marker triggers cleanup'; assert_absent "$FIX/helper/management.active" 'invalid marker cleanup closes management'; assert_eq enable_failed_closed "$(jq -r .final_status "$FIX/phase3/journal.json")" 'invalid marker records failed closed'
if [ "$(uname -s)" = Linux ]; then
  setup_fixture bad-marker-mode; run_preflight || fail 'bad marker mode preflight'; touch "$FIX/bad-marker-mode"; run_enable && fail 'unsafe marker mode passed' || pass 'unsafe marker mode triggers cleanup'; assert_absent "$FIX/helper/management.active" 'unsafe marker mode cleanup closes management'
else
  pass 'unsafe marker mode is rejected on Linux CI'; pass 'unsafe marker mode cleanup is verified on Linux CI'
fi
setup_fixture status-fail; run_preflight || fail 'status failure preflight'; touch "$FIX/status-fail-after-active"; run_enable && fail 'post-activation status failure passed' || pass 'post-activation status failure rejected'; assert_absent "$FIX/helper/management.active" 'post-status failure cleanup closes management'

# Durable evidence barriers and crash recovery.
for stage in write file_fsync rename dir_fsync; do
  setup_fixture "activation-evidence-$stage"; run_preflight || fail "evidence $stage preflight"; export E3_PHASE3_TEST_EVIDENCE_FAILURES="activation_complete:$stage"; run_enable && fail "activation evidence $stage passed" || pass "activation evidence $stage fails closed"; assert_absent "$FIX/helper/management.active" "activation evidence $stage still deactivates"
done
setup_fixture crash-started; run_preflight || fail 'crash-started preflight'; export E3_PHASE3_TEST_CRASH_AFTER=activation_started; run_enable >/dev/null 2>&1; unset E3_PHASE3_TEST_CRASH_AFTER; run_recover || fail 'recovery after activation_started'; assert_absent "$FIX/helper/management.active" 'activation_started recovery ends inactive'
setup_fixture crash-active; run_preflight || fail 'crash-active preflight'; export E3_PHASE3_TEST_CRASH_AFTER=activation_complete; run_enable >/dev/null 2>&1; unset E3_PHASE3_TEST_CRASH_AFTER; run_recover || fail 'normal RPC recovery after activation'; assert_absent "$FIX/helper/management.active" 'normal recovery deactivates active management'; assert_eq enable_failed_closed "$(jq -r .final_status "$FIX/phase3/journal.json")" 'normal recovery records failed closed'
setup_fixture missing-journal; run_preflight || fail 'missing journal preflight'; printf '{}' >"$FIX/helper/management.active"; rm -f "$FIX/phase3/journal.json"; run_recover || fail 'missing journal recovery'; assert_absent "$FIX/helper/management.active" 'missing journal recovery closes management'
setup_fixture corrupt-journal; run_preflight || fail 'corrupt journal preflight'; printf '{}' >"$FIX/helper/management.active"; printf 'bad\n' >"$FIX/phase3/journal.json"; run_recover || fail 'corrupt journal recovery'; assert_absent "$FIX/helper/management.active" 'corrupt journal recovery closes management'

# Pinned-root loss uses sanctioned root recovery and never client mutation.
setup_fixture pinned-loss; run_preflight || fail 'pinned loss preflight'; touch "$FIX/enforce-root" "$FIX/remove-pinned-after-activate"; run_enable && fail 'pinned root loss passed' || pass 'pinned root loss fails closed'; assert_file "$FIX/root-recovery-calls" 'pinned root loss invokes sanctioned root recovery'; assert_absent "$FIX/helper/management.active" 'root recovery closes management after pinned-root loss'; assert_eq 0 "$(grep -c '^client.add$\|^client.delete$' "$FIX/rpc-calls")" 'pinned-root recovery never mutates clients'
setup_fixture recovery-source-drift; run_preflight || fail 'source drift recovery preflight'; printf '{}' >"$FIX/helper/management.active"; printf 'bad\n' >"$FIX/phase3/journal.json"; printf '# drift\n' >>"$FIX/monitor/app/monitor-v2/web/e3rpc.py"; touch "$FIX/enforce-root"; run_recover && fail 'source-drift recovery claimed full success' || pass 'source-drift recovery remains fail-closed'; assert_file "$FIX/root-recovery-calls" 'source-drift recovery invokes sanctioned root recovery'; assert_absent "$FIX/helper/management.active" 'source-drift root recovery closes management'

# Global/canonical lock ordering spans activation.
setup_fixture locks; run_preflight || fail 'lock preflight'; touch "$FIX/block-activate"; run_enable & PID=$!
for _ in $(seq 1 100); do [ -e "$FIX/activate-entered" ] && break; sleep 0.03; done
assert_file "$FIX/activate-entered" 'enable holds locks inside activation'
if [ "$TEST_LOCK_BACKEND" = flock ]; then (exec 6>>"$E3_PHASE3_TEST_MONITOR_LOCK" && "$TEST_FLOCK_BIN" -n 6) >/dev/null 2>&1 && fail 'competing monitor deploy acquired lock' || pass 'competing monitor deploy cannot acquire canonical lock'; else mkdir "$E3_PHASE3_TEST_MONITOR_LOCK.fixture-held" 2>/dev/null && fail 'competing monitor deploy acquired fixture lock' || pass 'competing monitor deploy cannot acquire canonical lock'; fi
RPC_LINES="$(wc -l <"$FIX/rpc-calls"|tr -d ' ')"; /usr/bin/bash "$ORCH" recover >"$FIX/concurrent.out" 2>&1 && fail 'concurrent recover acquired Phase 3 lock' || pass 'concurrent recover fails immediately on Phase 3 lock'; assert_eq "$RPC_LINES" "$(wc -l <"$FIX/rpc-calls"|tr -d ' ')" 'competing recover performs no RPC'; touch "$FIX/release-activate"; wait "$PID" || fail 'blocked enable completes after release'

# Static surface and fixed lock/source contracts.
assert_contains "$ORCH" 'MONITOR_DEPLOY_LOCK="/run/lock/singbox-monitor-deploy.lock"' 'production monitor lock is canonical'
assert_eq 'acquire_phase3_lock acquire_monitor_deploy_lock' "$(sed -n '/^acquire_command_locks()/,/^}/p' "$ORCH"|grep -E '^[[:space:]]+acquire_(phase3|monitor_deploy)_lock$'|sed 's/^[[:space:]]*//'|paste -sd ' ' -)" 'lock order is Phase 3 then monitor deployment'
assert_contains "$ORCH" 'enable --approve-go-live' 'command surface has explicit go-live approval'
assert_eq 0 "$(grep -c 'rpc_call client\.add\|rpc_call client\.delete' "$ORCH")" 'orchestrator has no client mutation call path'
assert_eq 1 "$(grep -c 'rpc_call management\.activate' "$ORCH")" 'orchestrator has one activation call site'
assert_absent "$FIX/forbidden-systemctl" 'no test path reloads or restarts sing-box'

TOTAL=$((PASS+FAIL))
printf '\nPASS=%d FAIL=%d TOTAL=%d (expected %d)\n' "$PASS" "$FAIL" "$TOTAL" "$EXPECTED_TOTAL"
[ "$FAIL" -eq 0 ] || { printf 'E3_M3C_PHASE3=FAIL\n'; exit 1; }
printf 'E3_M3C_PHASE3=PASS\n'
