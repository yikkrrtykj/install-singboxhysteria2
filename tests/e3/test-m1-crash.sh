#!/usr/bin/env bash
# E3 M1 -- crash points INSIDE the canonical commit engine (E3 M1 review B1).
#
# The phase hook (CM_TX_JOURNAL_HOOK) journals every commit phase BEFORE its
# irreversible action -- critically BEFORE the mv in 'replace'. This suite does
# NOT fabricate journal files: it kill -9s the shell at each phase boundary via
# the hook itself, then verifies
#   * what the durable journal recorded at the instant of death,
#   * what the disk (live config) did or did not change,
#   * that the real worker's startup reconciliation converges the runtime to a
#     proven-safe state (and degrades when it cannot).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/lib/client-management.sh"
STATE_LIB="$ROOT/lib/sbox-cm-state.sh"
WORKER="$ROOT/sbox-cm/sbox-cm-ops"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }

printf '===== E3 M1 CRASH POINTS (commit phases) =====\n'

SB="$TMP/sandbox"
mkdir -p "$SB/clients"
export SB_SERVER_CONFIG="$SB/sbconfig_server.json"
export SB_STATE_FILE="$SB/config"
export SB_CLIENTS_DIR="$SB/clients"
export SB_SING_BOX_BIN="$SB/mock-sing-box"
export SB_LOCK_FILE="$SB/config.lock"
export SB_CM_STATE_DIR="$SB/state"
export SB_CM_LIB_DIR="$ROOT/lib"
export SBOX_CM_TEST_SANDBOX=1
export MOCK_SB_ACTIVE=1 MOCK_RELOAD=ok MOCK_RELOAD_COUNTER="$TMP/reload.count"

SHIM="$TMP/shim"; mkdir -p "$SHIM"
REAL_FLOCK="$(command -v flock 2>/dev/null || true)"
if [ -z "$REAL_FLOCK" ]; then
    printf '#!/usr/bin/env bash\nexit 0\n' > "$SHIM/flock"
    chmod +x "$SHIM/flock"
fi
cat > "$SHIM/systemctl" <<'SHIMEOF'
#!/usr/bin/env bash
case "${1:-}" in
    is-active) [ "${MOCK_SB_ACTIVE:-1}" = "1" ] && exit 0 || exit 3 ;;
    reload)
        [ "${MOCK_RELOAD:-ok}" = "fail-all" ] && exit 1
        exit 0 ;;
    *) exit 0 ;;
esac
SHIMEOF
chmod +x "$SHIM/systemctl"
printf '#!/usr/bin/env bash\nexit 1\n' > "$SHIM/pgrep"
chmod +x "$SHIM/pgrep"
export PATH="$SHIM:$PATH"

cat > "$SB/mock-sing-box" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
    check) exit 0 ;;
    generate)
        case "${2:-}" in
            uuid) printf 'uuid-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM" ;;
            rand) printf 'pw-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM" ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
MOCK
chmod +x "$SB/mock-sing-box"

warning(){ :; }
info(){ :; }
# shellcheck source=/dev/null
. "$LIB"
# shellcheck source=/dev/null
. "$STATE_LIB"
# neutral identity audit, exactly as the M0 commit mechanics suite does
candidate_problems(){ return 0; }

cm_state_init || { fail 'state init failed'; exit 1; }

write_live() {
    cat > "$SB_SERVER_CONFIG" <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
}
sum(){ sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
journal_file(){ printf '%s/state/journal/crashreq-0001.json\n' "$SB"; }
clear_journal(){ rm -f "$SB/state/journal"/*.json 2>/dev/null; rm -f "$SB/state/degraded.json"; }

# The hook journal like the worker's w_journal_hook, then (for the scenario's
# target phase) kill -9 THIS subshell -- simulating a power cut / SIGKILL at
# exactly that commit phase boundary. BASHPID (not $$) is the real subshell.
RUN_ID="crashreq-0001"
OPNAME="client.add"
KILL_AT=""
w_crash_hook() { # <phase> [backup_path]
    cm_journal_write "$RUN_ID" "$OPNAME" "$1" "${2:-}" 1 || return 1
    if [ -n "$KILL_AT" ] && [ "$1" = "$KILL_AT" ]; then
        kill -9 "$BASHPID" 2>/dev/null
        return 1
    fi
    return 0
}

run_kill() { # <phase> -> sets J_PHASE J_BACKUP OLD_SUM NEW_DISK(bool)
    local phase="$1" cand
    write_live
    clear_journal
    OLD_SUM="$(sum "$SB_SERVER_CONFIG")"
    cand="$(new_candidate_path)"
    printf '{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"},{"name":"crash-user","uuid":"CRASH-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"},{"name":"crash-user","password":"CRASH-PASS"}]}
]}\n' > "$cand"
    NEW_SUM_EXPECTED="$(sum "$cand")"
    KILL_AT="$phase"
    ( CM_TX_JOURNAL_HOOK=w_crash_hook; commit_server_config "$cand" "kill-test" ) >/dev/null 2>&1
    KILL_AT=""
    J_PHASE="$(jq -r '.phase // "none"' "$(journal_file)" 2>/dev/null)"
    J_BACKUP="$(jq -r '.backup_path // "null"' "$(journal_file)" 2>/dev/null)"
}

converge_via_reconcile() { # -> prints "true" or "false"
    printf '' | bash "$WORKER" --maintenance reconcile 2>/dev/null \
        | jq -r '.data.reconciled // false'
}

printf '\n== kill -9 at phase=check (before any mutation) ==\n'
run_kill check
assert_eq check "$J_PHASE" 'journal durably recorded phase=check at death'
assert_eq null "$J_BACKUP" 'no backup existed yet at phase=check'
assert_eq "$OLD_SUM" "$(sum "$SB_SERVER_CONFIG")" 'live config untouched'
assert_eq true "$(converge_via_reconcile)" 'reconcile proved the state safe'
[ -f "$(journal_file)" ] && fail 'journal not cleared after proven-safe reconcile' \
    || pass 'journal cleared after proven-safe reconcile'

printf '\n== kill -9 at phase=backup (backup exists, disk untouched) ==\n'
run_kill backup
assert_eq backup "$J_PHASE" 'journal durably recorded phase=backup at death'
assert_ne null "$J_BACKUP" 'journal carries the backup path for recovery'
assert_eq "$OLD_SUM" "$(sum "$SB_SERVER_CONFIG")" 'live config untouched'
assert_eq true "$(converge_via_reconcile)" 'reconcile proved the state safe'

printf '\n== kill -9 at phase=replace (the critical durable boundary) ==\n'
run_kill replace
assert_eq replace "$J_PHASE" 'journal durably recorded phase=replace BEFORE the mv'
assert_ne null "$J_BACKUP" 'journal carries backup_path through the replace boundary'
assert_eq "$OLD_SUM" "$(sum "$SB_SERVER_CONFIG")" 'live config NOT yet replaced at phase=replace'
assert_eq true "$(converge_via_reconcile)" 'reconcile proved the state safe'

printf '\n== kill -9 at phase=reload (mv done, reload pending) ==\n'
run_kill reload
assert_eq reload "$J_PHASE" 'journal durably recorded phase=reload at death'
assert_eq "$NEW_SUM_EXPECTED" "$(sum "$SB_SERVER_CONFIG")" 'live config IS the new one (disk committed)'
assert_eq true "$(converge_via_reconcile)" 'reconcile reloaded the runtime onto the new config'

printf '\n== kill -9 at phase=health ==\n'
run_kill health
assert_eq health "$J_PHASE" 'journal durably recorded phase=health at death'
assert_eq "$NEW_SUM_EXPECTED" "$(sum "$SB_SERVER_CONFIG")" 'live config remains the new one'
assert_eq true "$(converge_via_reconcile)" 'reconcile re-verified health'

printf '\n== kill -9 at phase=replace + reload broken -> restore from journal backup ==\n'
run_kill replace
export MOCK_RELOAD=fail-all
RES="$(converge_via_reconcile)"
unset MOCK_RELOAD
assert_eq false "$RES" 'reconcile refused to claim a proven-safe state'
assert_eq "$OLD_SUM" "$(sum "$SB_SERVER_CONFIG")" 'reconcile restored the journal backup to disk'
[ -f "$SB/state/degraded.json" ] && pass 'unprovable reconcile set the durable degraded flag' \
    || fail 'degraded flag missing after failed reconcile'

clear_journal
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_CRASH=FAIL\n'; exit 1; }
printf 'E3_M1_CRASH=PASS\n'
