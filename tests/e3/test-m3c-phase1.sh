#!/usr/bin/env bash
# E3 M3-C Phase 1 orchestrator integration tests.  The orchestrator runs as a
# real process against a stateful filesystem/systemctl fixture; only the five
# reviewed primitives are replaced by narrow behavioral doubles.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
ORCH="$ROOT/monitor-v2/deploy/e3-m3c-phase1.sh"
TMP="$(mktemp -d)"
PASS=0
FAIL=0
EXPECTED_TOTAL=66

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
assert_eq() { [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_file() { [ -e "$1" ] && pass "$2" || fail "$2 (missing $1)"; }
assert_absent() { [ ! -e "$1" ] && pass "$2" || fail "$2 (present $1)"; }
assert_contains() { grep -qF "$2" "$1" && pass "$3" || fail "$3 (missing [$2])"; }

cleanup() {
    if [ "${E3_M3C_KEEP_TMP:-0}" = "1" ]; then
        printf 'fixture kept at %s\n' "$TMP" >&2
    else
        rm -rf -- "$TMP"
    fi
}
trap cleanup EXIT

make_stub() { # make_stub path [mode]; body comes from stdin
    local path="$1"
    local mode="${2:-0755}"
    mkdir -p "$(dirname "$path")"
    cp /dev/stdin "$path"
    chmod "$mode" "$path"
}

setup_fixture() {
    local name="$1"
    FIX="$TMP/$name"
    export FX="$FIX"
    mkdir -p "$FIX/bin" "$FIX/releases/rel-old-1/app/monitor-v2" \
        "$FIX/releases/rel-old-2/app/monitor-v2" \
        "$FIX/releases/rel-base/app/monitor-v2" "$FIX/helper-state" \
        "$FIX/libexec" "$FIX/units" "$FIX/run"
    printf '0.0.9\n' >"$FIX/releases/rel-old-1/VERSION"
    printf '0.0.9\n' >"$FIX/releases/rel-old-2/VERSION"
    cp "$ROOT/monitor-v2/VERSION" "$FIX/releases/rel-base/VERSION"
    printf '# fixture webapp\n' >"$FIX/releases/rel-base/app/monitor-v2/webapp.py"
    # Keep the target in a file and put a fixture readlink ahead of PATH.
    # This is equivalent to a symlink on Linux CI and also lets the suite run
    # under Git Bash, where directory symlink creation is privilege-dependent.
    : >"$FIX/monitor"
    printf '%s\n' "$FIX/releases/rel-base" >"$FIX/monitor.target"
    printf '{"inbounds":[]}\n' >"$FIX/config.json"
    printf 'active\n' >"$FIX/sing-active"
    printf 'enabled\n' >"$FIX/monitor-enabled"
    printf 'active\n' >"$FIX/monitor-active"
    printf 'inactive\n' >"$FIX/socket-active"
    printf 'disabled\n' >"$FIX/socket-enabled"
    printf 'inactive\n' >"$FIX/service-active"
    printf 'disabled\n' >"$FIX/service-enabled"
    printf 'Sun 2026-09-20 00:00:00 UTC\n' >"$FIX/sing-ts"
    printf '0\n' >"$FIX/sing-restarts"
    printf '200\n' >"$FIX/http-code"
    : >"$FIX/monitor-calls"
    : >"$FIX/full-rollback-count"
    : >"$FIX/monitor-rollback-count"
    : >"$FIX/primitive-env.log"
    : >"$FIX/status-probe-count"
    printf 'inactive\n' >"$FIX/independent-status"

    make_stub "$FIX/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -u
quiet=0
cmd="${1:-}"; shift || true
if [ "${1:-}" = "--quiet" ]; then quiet=1; shift; fi
case "$cmd" in
  is-active)
    unit="${1:-}"
    case "$unit" in
      sing-box.service) f="$FX/sing-active" ;;
      singbox-monitor.service) f="$FX/monitor-active" ;;
      sbox-cm.socket) f="$FX/socket-active" ;;
      sbox-cm.service) f="$FX/service-active" ;;
      *) exit 4 ;;
    esac
    v="$(cat "$f")"; [ "$quiet" = 1 ] || printf '%s\n' "$v"
    [ "$v" = active ]
    ;;
  is-enabled)
    unit="${1:-}"
    case "$unit" in
      singbox-monitor.service) f="$FX/monitor-enabled" ;;
      sbox-cm.socket) f="$FX/socket-enabled" ;;
      sbox-cm.service) f="$FX/service-enabled" ;;
      *) printf 'disabled\n'; exit 1 ;;
    esac
    cat "$f"; [ "$(cat "$f")" = enabled ]
    ;;
  show)
    prop="${2:-}"
    case "$prop" in
      ActiveEnterTimestamp) cat "$FX/sing-ts" ;;
      NRestarts) cat "$FX/sing-restarts" ;;
      *) exit 2 ;;
    esac
    ;;
  daemon-reload) [ ! -e "$FX/daemon-reload-fail" ] ;;
  enable)
    [ "${1:-}" = "--now" ] && [ "${2:-}" = "sbox-cm.socket" ] || exit 2
    printf 'enabled\n' >"$FX/socket-enabled"
    printf 'active\n' >"$FX/socket-active"
    ;;
  *) exit 2 ;;
esac
STUB

    make_stub "$FIX/bin/readlink" <<'STUB'
#!/usr/bin/env bash
last="${!#}"
if [ "$last" = "$FX/monitor" ]; then
  cat "$FX/monitor.target"
else
  /usr/bin/readlink "$@"
fi
STUB

    make_stub "$FIX/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat "$FX/http-code"
STUB

    make_stub "$FIX/bin/preflight" 0644 <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
[ "${1:-}" = "--baseline-out" ] || exit 2
out="${2:-}"
sha="$(sha256sum "$E3_PHASE1_TEST_CONFIG" | awk '{print $1}')"
size="$(stat -c %s "$E3_PHASE1_TEST_CONFIG")"
target="$(readlink -f "$E3_PHASE1_TEST_MONITOR_APP")"
id="$(basename "$target")"
tmp="$(mktemp "$out.tmp.XXXXXX")"
jq -n --arg sha "$sha" --argjson size "$size" \
  --arg ts "$(cat "$FX/sing-ts")" --argjson nr "$(cat "$FX/sing-restarts")" \
  --arg id "$id" --arg target "$target" \
  '{config_sha256:$sha,config_size:$size,
    singbox:{active:"active",active_enter_timestamp:$ts,nrestarts:$nr},
    monitor:{active:"active",enabled:"enabled",release_id:$id,release_target:$target},
    marker_present:false,
    helper:{libexec_present:false,socket_unit_present:false,service_unit_present:false}}' >"$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$out"
printf 'E3_PREFLIGHT=PASS\n'
STUB

    make_stub "$FIX/bin/install-monitor" 0644 <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
printf '%s keep=%s\n' "$*" "${SBMON_KEEP_RELEASES:-unset}" >>"$FX/monitor-calls"
case "${1:-}" in
  upgrade)
    if [ -e "$FX/block-monitor-upgrade" ]; then
      : >"$FX/monitor-upgrade-entered"
      while [ ! -e "$FX/release-monitor-upgrade" ]; do sleep 0.05; done
    fi
    if [ "${2:-}" != "--repair" ]; then
      printf 'action=noop\n'
      exit 0
    fi
    n="$(($(find "$FX/releases" -mindepth 1 -maxdepth 1 -type d -name 'rel-new-*' | wc -l) + 1))"
    id="rel-new-$n"
    if [ -e "$FX/concurrent-release" ]; then
      mkdir -p "$FX/releases/rel-concurrent/app/monitor-v2"
      printf '0.1.0\n' >"$FX/releases/rel-concurrent/VERSION"
    fi
    mkdir -p "$FX/releases/$id/app/monitor-v2"
    cp "$ROOT/monitor-v2/VERSION" "$FX/releases/$id/VERSION"
    printf '# restaged\n' >"$FX/releases/$id/app/monitor-v2/webapp.py"
    printf '%s\n' "$FX/releases/$id" >"$FX/monitor.target"
    keep="${SBMON_KEEP_RELEASES:-3}"
    count="$(find "$FX/releases" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    # Simulate the dangerous outcome of pruning after a concurrent release:
    # the baseline is the first candidate.  The Phase 1 no-prune value must
    # make this branch unreachable.
    if [ "$count" -gt "$keep" ]; then rm -rf -- "$FX/releases/rel-base"; fi
    if [ -e "$FX/d2-drift" ]; then printf 'drifted timestamp\n' >"$FX/sing-ts"; fi
    printf 'action=repair version=%s\n' "$(tr -d ' \t\r\n' <"$ROOT/monitor-v2/VERSION")"
    ;;
  rollback)
    id="${2:-}"
    [ -d "$FX/releases/$id" ] || exit 1
    printf x >>"$FX/monitor-rollback-count"
    printf '%s\n' "$FX/releases/$id" >"$FX/monitor.target"
    printf 'active\n' >"$FX/monitor-active"
    printf 'enabled\n' >"$FX/monitor-enabled"
    ;;
  *) exit 2 ;;
esac
STUB

    make_stub "$FIX/bin/install-helper" 0644 <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
[ "${1:-}" = install ] || exit 2
mkdir -p "$E3_PHASE1_TEST_SBXCM_LIBEXEC/lib" "$E3_PHASE1_TEST_UNIT_DIR"
: >"$E3_PHASE1_TEST_SBXCM_LIBEXEC/sbox-cm"
if [ -e "$FX/helper-partial-fail" ]; then exit 9; fi
: >"$E3_PHASE1_TEST_SBXCM_LIBEXEC/sbox-cm-ops"
: >"$E3_PHASE1_TEST_SBXCM_LIBEXEC/lib/client-management.sh"
: >"$E3_PHASE1_TEST_SBXCM_LIBEXEC/lib/sbox-cm-state.sh"
: >"$E3_PHASE1_TEST_UNIT_DIR/sbox-cm.socket"
: >"$E3_PHASE1_TEST_UNIT_DIR/sbox-cm.service"
printf 'inactive\n' >"$FX/socket-active"
printf 'disabled\n' >"$FX/socket-enabled"
printf 'inactive\n' >"$FX/service-active"
printf 'disabled\n' >"$FX/service-enabled"
STUB

    make_stub "$FIX/bin/verify" 0644 <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
[ "${1:-}" = "--baseline" ] || exit 2
if [ "$(cat "$FX/service-active")" != inactive ]; then
  printf 'service was not inactive before first RPC\n' >&2
  exit 8
fi
printf 'yes\n' >"$FX/service-was-inactive-before-rpc"
printf 'active\n' >"$FX/service-active"
if [ -e "$FX/verify-fail" ]; then
  printf 'E3_M3_VERIFY=FAIL\n'
  exit 7
fi
printf '  PASS V07 management.status (sboxweb RPC) reports inactive\n'
printf '  PASS V05b sbox-cm.service pulled up by the real RPC (socket activation works)\n'
printf 'E3_M3_VERIFY=PASS\n'
if [ -e "$FX/post-verify-socket-disabled" ]; then printf 'disabled\n' >"$FX/socket-enabled"; fi
if [ -e "$FX/post-verify-service-enabled" ]; then printf 'enabled\n' >"$FX/service-enabled"; fi
STUB

    make_stub "$FIX/bin/status-probe" <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
printf x >>"$FX/status-probe-count"
jq -n --arg state "$(cat "$FX/independent-status")" \
  '{ok:true,data:{management_state:$state}}'
STUB

    make_stub "$FIX/bin/full-rollback" 0644 <<'STUB'
#!/usr/bin/env bash
set -u
env | sort >>"$FX/primitive-env.log"
[ "${1:-}" = "--baseline" ] || exit 2
printf x >>"$FX/full-rollback-count"
rm -rf -- "$E3_PHASE1_TEST_SBXCM_LIBEXEC"
rm -f -- "$E3_PHASE1_TEST_UNIT_DIR/sbox-cm.socket" \
  "$E3_PHASE1_TEST_UNIT_DIR/sbox-cm.service" "$E3_PHASE1_TEST_SOCKET"
id="$(jq -r '.monitor.release_id' "$2")"
printf '%s\n' "$FX/releases/$id" >"$FX/monitor.target"
printf 'inactive\n' >"$FX/socket-active"
printf 'disabled\n' >"$FX/socket-enabled"
printf 'inactive\n' >"$FX/service-active"
printf 'disabled\n' >"$FX/service-enabled"
printf 'active\n' >"$FX/monitor-active"
printf 'enabled\n' >"$FX/monitor-enabled"
printf 'E3_M3_ROLLBACK=PASS\n'
STUB

    export E3_PHASE1_TEST_MODE=1
    export E3_PHASE1_TEST_STATE_DIR="$FIX/phase1"
    export E3_PHASE1_TEST_CONFIG="$FIX/config.json"
    export E3_PHASE1_TEST_MONITOR_APP="$FIX/monitor"
    export E3_PHASE1_TEST_RELEASES_DIR="$FIX/releases"
    export E3_PHASE1_TEST_SBXCM_STATE="$FIX/helper-state"
    export E3_PHASE1_TEST_SBXCM_LIBEXEC="$FIX/libexec"
    export E3_PHASE1_TEST_UNIT_DIR="$FIX/units"
    export E3_PHASE1_TEST_SOCKET="$FIX/run/sbox-cm.sock"
    export E3_PHASE1_TEST_MONITOR_URL="http://fixture.invalid"
    export E3_PHASE1_TEST_SYSTEMCTL="$FIX/bin/systemctl"
    export E3_PHASE1_TEST_CURL="$FIX/bin/curl"
    export E3_PHASE1_TEST_PREFLIGHT="$FIX/bin/preflight"
    export E3_PHASE1_TEST_INSTALL_MONITOR="$FIX/bin/install-monitor"
    export E3_PHASE1_TEST_INSTALL_SBXCM="$FIX/bin/install-helper"
    export E3_PHASE1_TEST_DEPLOY_VERIFY="$FIX/bin/verify"
    export E3_PHASE1_TEST_ROLLBACK="$FIX/bin/full-rollback"
    export E3_PHASE1_TEST_STATUS_PROBE="$FIX/bin/status-probe"
    export E3_PHASE1_TEST_FIXTURE_ROOT="$FIX"
    export E3_PHASE1_TEST_SOURCE_HEAD="fixture-reviewed-head"
    export E3_PHASE1_APPROVED_HEAD="fixture-reviewed-head"
    export E3_PHASE1_TEST_LOCK="$FIX/phase1.lock"
    export E3_PHASE1_TEST_FLOCK="$TEST_FLOCK_BIN"
    export E3_PHASE1_TEST_LOCK_BACKEND="$TEST_LOCK_BACKEND"
    export PATH="$FIX/bin:$ORIGINAL_PATH"
}

run_preflight() {
    bash "$ORCH" preflight >"$FIX/preflight.out" 2>&1
}

set_journal() { # jq filter
    local filter="$1" tmp="$FIX/journal.tmp"
    jq "$filter" "$FIX/phase1/journal.json" >"$tmp" && chmod 0600 "$tmp" \
        && mv "$tmp" "$FIX/phase1/journal.json"
}

printf '===== E3 M3-C PHASE 1 ORCHESTRATOR =====\n'
ORIGINAL_PATH="$PATH"
if TEST_FLOCK_BIN="$(command -v flock 2>/dev/null)" && [ -n "$TEST_FLOCK_BIN" ]; then
    TEST_LOCK_BACKEND=flock
else
    TEST_FLOCK_BIN=/usr/bin/flock
    TEST_LOCK_BACKEND=mkdir
fi

# Success path: prove the same-version distinction, no-prune retention,
# socket-only activation ordering, final invariants, and exact terminal output.
setup_fixture success
BASE_LINK="$(readlink -f "$FIX/monitor")"
/usr/bin/bash "$FIX/bin/install-monitor" upgrade >"$FIX/plain-upgrade.out"
assert_eq "$BASE_LINK" "$(readlink -f "$FIX/monitor")" \
    'same-version ordinary upgrade is a true noop in the fixture'
assert_contains "$FIX/plain-upgrade.out" 'action=noop' \
    'ordinary same-version upgrade reports action=noop'
if [ "$(uname -s)" = "Linux" ]; then
    PRIMITIVE_MODES="$(stat -c %a "$FIX/bin/preflight" "$FIX/bin/install-monitor" \
        "$FIX/bin/install-helper" "$FIX/bin/verify" "$FIX/bin/full-rollback" \
        | paste -sd ' ' -)"
    assert_eq '644 644 644 644 644' "$PRIMITIVE_MODES" \
        '0644 reviewed shell primitives execute only via fixed /usr/bin/bash'
else
    pass '0644 reviewed shell primitives execute only via fixed /usr/bin/bash (enforced on Linux CI)'
fi
: >"$FIX/primitive-env.log"
: >"$FIX/concurrent-release"
# Poison every known override family.  The orchestrator's clean environment
# must keep these values out of all five primitives and the status probe.
export E3_CONFIG=/poison/e3-config
export E3_MONITOR_APP=/poison/e3-monitor
export E3_SBXCM_STATE=/poison/e3-state
export E3_SBXCM_LIBEXEC=/poison/e3-libexec
export E3_INSTALL_MONITOR=/poison/e3-installer
export E3_RELEASES_DIR=/poison/e3-releases
export SBMON_APP_LINK=/poison/sbmon-app
export SBMON_RELEASES_DIR=/poison/sbmon-releases
export SBMON_KEEP_RELEASES=1
export SBMON_SYSTEMCTL=/poison/systemctl
export SBXCM_PREFIX=/poison/prefix
export SBXCM_LIBEXEC=/poison/sbxcm-libexec
export SBXCM_UNIT_DIR=/poison/units
export SB_CM_STATE_DIR=/poison/cm-state
export SBXCM_SYSTEMCTL=/poison/sbxcm-systemctl
run_preflight || fail 'success fixture preflight unexpectedly failed'
SHA_BEFORE="$(sha256sum "$FIX/config.json" | awk '{print $1}')"
SIZE_BEFORE="$(stat -c %s "$FIX/config.json")"
TS_BEFORE="$(cat "$FIX/sing-ts")"
NR_BEFORE="$(cat "$FIX/sing-restarts")"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then pass 'orchestrator success path exits zero'; else fail 'orchestrator success path failed'; fi
assert_contains "$FIX/monitor-calls" 'upgrade --repair keep=2147483647' \
    'orchestrator forces repair with the effectively-no-prune retention value'
assert_file "$FIX/releases/rel-concurrent" 'fixture adds a concurrent release inside the installer window'
assert_file "$FIX/releases/rel-base" 'baseline release survives the repair restage'
if grep -qF '/poison/' "$FIX/primitive-env.log"; then fail 'poisoned inherited overrides reached a primitive'; else pass 'clean primitive environments reject poisoned E3/SBMON/SBXCM overrides'; fi
assert_eq 'yes' "$(cat "$FIX/service-was-inactive-before-rpc" 2>/dev/null)" \
    'service is inactive immediately before the first verifier RPC'
assert_eq 'active' "$(cat "$FIX/service-active")" 'first RPC socket-activates the service'
assert_eq '1' "$(wc -c <"$FIX/status-probe-count" | tr -d ' ')" \
    'final gate executes one independent read-only status probe'
assert_contains "$FIX/apply.out" 'PRODUCTION DEPLOYED = YES' 'final output contains deployed=yes exactly'
assert_contains "$FIX/apply.out" 'E3 MANAGEMENT ENABLED = NO' 'final output contains management enabled=no exactly'
assert_contains "$FIX/apply.out" 'management_state = inactive' 'final output contains inactive state exactly'
assert_contains "$FIX/apply.out" 'M3-C Phase 2 = NOT STARTED' 'final output contains Phase 2 hard stop exactly'
assert_eq "$SHA_BEFORE" "$(sha256sum "$FIX/config.json" | awk '{print $1}')" 'config SHA remains unchanged'
assert_eq "$SIZE_BEFORE" "$(stat -c %s "$FIX/config.json")" 'config size remains unchanged'
assert_eq "$TS_BEFORE" "$(cat "$FIX/sing-ts")" 'sing-box ActiveEnterTimestamp remains unchanged'
assert_eq "$NR_BEFORE" "$(cat "$FIX/sing-restarts")" 'sing-box NRestarts remains unchanged'
assert_absent "$FIX/helper-state/management.active" 'activation marker remains absent'
assert_eq 'deploy_disabled_complete' "$(jq -r '.final_status' "$FIX/phase1/journal.json")" \
    'atomic journal records the terminal deploy-disabled status'
if [ "$(uname -s)" = "Linux" ]; then
    assert_eq '600' "$(stat -c %a "$FIX/phase1/journal.json")" 'journal is mode 0600'
else
    pass 'journal 0600 is enforced on Linux CI (NTFS does not expose Unix mode bits)'
fi

# D2 invariant drift has positive proof D3 did not start, so monitor-only.
setup_fixture d2_drift
run_preflight || fail 'D2 drift fixture preflight unexpectedly failed'
: >"$FIX/d2-drift"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'D2 drift must fail apply'; else pass 'D2 invariant drift fails closed'; fi
assert_eq '1' "$(wc -c <"$FIX/monitor-rollback-count" | tr -d ' ')" 'D2 drift selects monitor-only rollback'
assert_eq '0' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" 'D2 drift does not invoke full rollback'
assert_eq 'rel-base' "$(basename "$(readlink -f "$FIX/monitor")")" 'D2 recovery restores exact baseline release'

# A partial D3 mutation is never classified as monitor-only.
setup_fixture d3_partial
run_preflight || fail 'D3 partial fixture preflight unexpectedly failed'
: >"$FIX/helper-partial-fail"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'partial helper install must fail apply'; else pass 'partial helper install fails closed'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" 'D3 partial failure selects full rollback'
assert_absent "$FIX/libexec/sbox-cm" 'full rollback removes partial helper capability'

# Recovered after D3 completion: journal/evidence force full rollback even if
# an interruption happened before socket enable.
setup_fixture d3_interrupted
run_preflight || fail 'D3 interruption fixture preflight unexpectedly failed'
mkdir -p "$FIX/libexec/lib"
: >"$FIX/libexec/sbox-cm"; : >"$FIX/phase1/artifacts/04-sbox-cm-install.log"
set_journal '.phase="helper_install_complete" | .monitor_mutation.started=true | .monitor_mutation.completed=true | .helper_install.started=true | .helper_install.completed=true | .final_status="in_progress"'
if bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'recover must terminate an interrupted attempt nonzero'; else pass 'D3-complete interruption terminates the attempt'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" 'D3-complete interruption uses full rollback'

# Corrupt/incomplete journal data is classified as uncertain, never inferred
# as "D3 not started" merely because capability paths happen to be absent.
setup_fixture uncertain_journal
run_preflight || fail 'uncertain journal fixture preflight unexpectedly failed'
set_journal 'del(.helper_install.started)'
if bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'uncertain recovery must terminate the attempt nonzero'; else pass 'uncertain journal terminates the attempt'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" 'uncertain journal selects full rollback'

# D2 completed and D3 positively not started: no paths, no evidence, false flag.
setup_fixture d2_interrupted
run_preflight || fail 'D2 interruption fixture preflight unexpectedly failed'
mkdir -p "$FIX/releases/rel-interrupted/app/monitor-v2"
cp "$ROOT/monitor-v2/VERSION" "$FIX/releases/rel-interrupted/VERSION"
printf '%s\n' "$FIX/releases/rel-interrupted" >"$FIX/monitor.target"
set_journal '.phase="monitor_mutation_complete" | .monitor_mutation.started=true | .monitor_mutation.completed=true | .final_status="in_progress"'
if bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'monitor-only recover must still end the attempt nonzero'; else pass 'D2-only interruption terminates the attempt'; fi
assert_eq '1' "$(wc -c <"$FIX/monitor-rollback-count" | tr -d ' ')" 'D2-only interruption uses monitor-only rollback'
assert_contains "$FIX/recover.out" 'ROLLBACK PASS: monitor restored to exact baseline state' \
    'complete monitor baseline proof is required before rollback PASS'

# A symlink flip alone is insufficient: unhealthy HTTP makes recovery critical.
setup_fixture rollback_http_bad
run_preflight || fail 'HTTP rollback fixture preflight unexpectedly failed'
mkdir -p "$FIX/releases/rel-interrupted/app/monitor-v2"
cp "$ROOT/monitor-v2/VERSION" "$FIX/releases/rel-interrupted/VERSION"
printf '%s\n' "$FIX/releases/rel-interrupted" >"$FIX/monitor.target"
printf '503\n' >"$FIX/http-code"
set_journal '.phase="monitor_mutation_complete" | .monitor_mutation.started=true | .monitor_mutation.completed=true | .final_status="in_progress"'
bash "$ORCH" recover >"$FIX/recover.out" 2>&1 || true
assert_contains "$FIX/recover.out" 'CRITICAL: monitor-only rollback did not restore the complete baseline state' \
    'restored symlink with unhealthy HTTP is CRITICAL'
if grep -qF 'ROLLBACK PASS: monitor restored' "$FIX/recover.out"; then fail 'unhealthy monitor must not report rollback PASS'; else pass 'unhealthy monitor never reports rollback PASS'; fi

# Verify failure occurs after helper/socket mutation and must use full rollback.
setup_fixture verify_failure
run_preflight || fail 'verify failure fixture preflight unexpectedly failed'
: >"$FIX/verify-fail"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'deploy-verify failure must fail apply'; else pass 'deploy-verify failure fails closed'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" 'deploy-verify failure selects full rollback'
assert_eq 'full_rollback_pass' "$(jq -r '.final_status' "$FIX/phase1/journal.json")" \
    'journal records completed full recovery after verify failure'

# A forged verifier line is not evidence: the independent JSON probe decides.
setup_fixture independent_status_active
run_preflight || fail 'independent-status fixture preflight unexpectedly failed'
printf 'active\n' >"$FIX/independent-status"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'independent active status must fail apply'; else pass 'fake V07 inactive cannot override independent active status'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" \
    'independent active status selects full rollback'
if [ "$(jq -r '.final_status' "$FIX/phase1/journal.json")" = deploy_disabled_complete ]; then fail 'active status must not write terminal success'; else pass 'active status never writes deploy_disabled_complete'; fi
if grep -qF 'PRODUCTION DEPLOYED = YES' "$FIX/apply.out"; then fail 'active status must not print final success'; else pass 'active status prints none of the final success block'; fi

# Post-verifier unit drift is caught by the final closed-plane remeasurement.
setup_fixture socket_post_verify_disabled
run_preflight || fail 'socket drift fixture preflight unexpectedly failed'
: >"$FIX/post-verify-socket-disabled"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'post-verify disabled socket must fail apply'; else pass 'post-verify socket-disabled drift fails closed'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" \
    'post-verify socket drift selects full rollback'

setup_fixture service_post_verify_enabled
run_preflight || fail 'service drift fixture preflight unexpectedly failed'
: >"$FIX/post-verify-service-enabled"
if bash "$ORCH" apply >"$FIX/apply.out" 2>&1; then fail 'post-verify enabled service must fail apply'; else pass 'post-verify service-enabled drift fails closed'; fi
assert_eq '1' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" \
    'post-verify service drift selects full rollback'

# Execution approval names one exact reviewed head; a different checkout
# identity is rejected before the preflight primitive runs.
setup_fixture approved_head_mismatch
export E3_PHASE1_APPROVED_HEAD='different-reviewed-head'
if bash "$ORCH" preflight >"$FIX/preflight.out" 2>&1; then fail 'mismatched approved head must reject execution'; else pass 'exact approved-head mismatch rejects execution before mutation'; fi

# B5: the lock spans the whole apply, including time blocked inside a child
# primitive.  A competing recover must fail before touching any evidence.
setup_fixture concurrent_phase1_lock
run_preflight || fail 'concurrency fixture preflight unexpectedly failed'
: >"$FIX/block-monitor-upgrade"
bash "$ORCH" apply >"$FIX/first-apply.out" 2>&1 &
FIRST_PID=$!
for _ in $(seq 1 200); do
    [ -e "$FIX/monitor-upgrade-entered" ] && break
    sleep 0.05
done
assert_file "$FIX/monitor-upgrade-entered" 'first apply reaches the blocked primitive while holding the Phase 1 lock'
JOURNAL_SHA_LOCKED="$(sha256sum "$FIX/phase1/journal.json" | awk '{print $1}')"
ENV_LINES_LOCKED="$(wc -l <"$FIX/primitive-env.log" | tr -d ' ')"
bash "$ORCH" recover >"$FIX/second-recover.out" 2>&1
SECOND_RC=$?
if [ "$SECOND_RC" -ne 0 ]; then pass 'competing recover fails immediately'; else fail 'competing recover must not acquire the Phase 1 lock'; fi
assert_contains "$FIX/second-recover.out" 'another Phase 1 command holds the exclusive lock' \
    'competing recover reports the fail-closed lock gate'
assert_eq "$ENV_LINES_LOCKED" "$(wc -l <"$FIX/primitive-env.log" | tr -d ' ')" \
    'competing recover calls no primitive'
assert_eq "$JOURNAL_SHA_LOCKED" "$(sha256sum "$FIX/phase1/journal.json" | awk '{print $1}')" \
    'competing recover does not rewrite the journal'
assert_absent "$FIX/libexec/sbox-cm" 'competing recover does not install helper capability'
assert_eq 'inactive' "$(cat "$FIX/socket-active")" 'competing recover does not enable the socket'
: >"$FIX/release-monitor-upgrade"
wait "$FIRST_PID"
FIRST_RC=$?
if [ "$FIRST_RC" -eq 0 ]; then pass 'first apply completes normally after releasing its blocked primitive'; else fail 'first apply failed after lock contention'; fi
assert_eq 'deploy_disabled_complete' "$(jq -r '.final_status' "$FIX/phase1/journal.json")" \
    'first apply leaves a consistent terminal state after contention'

# B6: valid-journal recovery is pinned to the attempt's recorded source head.
setup_fixture recover_source_mismatch
run_preflight || fail 'recover source mismatch fixture preflight unexpectedly failed'
mkdir -p "$FIX/releases/rel-interrupted/app/monitor-v2"
cp "$ROOT/monitor-v2/VERSION" "$FIX/releases/rel-interrupted/VERSION"
printf '%s\n' "$FIX/releases/rel-interrupted" >"$FIX/monitor.target"
set_journal '.phase="monitor_mutation_complete" | .monitor_mutation.started=true | .monitor_mutation.completed=true | .final_status="in_progress"'
export E3_PHASE1_TEST_SOURCE_HEAD='fixture-new-head'
export E3_PHASE1_APPROVED_HEAD='fixture-new-head'
if bash "$ORCH" recover >"$FIX/recover.out" 2>&1; then fail 'source-mismatched recover must refuse'; else pass 'recover refuses a valid journal recorded by a different source head'; fi
assert_contains "$FIX/recover.out" 'CRITICAL STOP: journal source_head does not match the approved recovery checkout' \
    'recover source mismatch is a CRITICAL STOP'
assert_eq '0' "$(wc -c <"$FIX/monitor-rollback-count" | tr -d ' ')" \
    'source-mismatched recover never invokes monitor rollback'
assert_eq '0' "$(wc -c <"$FIX/full-rollback-count" | tr -d ' ')" \
    'source-mismatched recover never invokes full rollback'

# Static safety properties supplement (not replace) the live state-machine tests.
if rg -qF 'management.activate' "$ORCH"; then fail 'orchestrator source must not contain the activation operation'; else pass 'orchestrator source contains no activation operation'; fi
NEXT_AFTER_FINAL="$(awk '/M3-C Phase 2 = NOT STARTED/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}' "$ORCH")"
assert_eq 'exit 0' "$NEXT_AFTER_FINAL" 'success output is immediately followed by a hard exit'
if grep -Eq '(^|[[:space:]])(client\.add|client\.delete)([[:space:]]|$)' "$ORCH"; then fail 'orchestrator must not implement client mutations'; else pass 'orchestrator implements no client mutation path'; fi

TOTAL=$((PASS + FAIL))
printf '\nPASS=%d FAIL=%d TOTAL=%d (expected %d)\n' "$PASS" "$FAIL" "$TOTAL" "$EXPECTED_TOTAL"
if [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    printf 'E3_M3C_PHASE1=FAIL (assertion-count guard)\n'
    exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    printf 'E3_M3C_PHASE1=FAIL\n'
    exit 1
fi
printf 'E3_M3C_PHASE1=PASS\n'
