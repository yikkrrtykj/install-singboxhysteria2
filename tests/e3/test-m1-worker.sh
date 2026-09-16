#!/usr/bin/env bash
# E3 M1 -- privileged transaction worker: the six ops, ledger, journal,
# idempotency, reconciliation and degraded semantics.
#
# Entirely sandboxed: temporary root, mock sing-box, shimmed systemctl/pgrep.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKER_FILE="$ROOT/sbox-cm/sbox-cm-ops"
WORKER_CMD=(bash "$WORKER_FILE")
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }

printf '===== E3 M1 WORKER =====\n'

if [ ! -f "$WORKER_FILE" ]; then
    fail "worker missing: $WORKER_FILE"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M1_WORKER=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi
if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
    skip 'non-Linux: flock/fsync semantics are exercised on Linux CI only'
fi

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

SHIM="$TMP/shim"
mkdir -p "$SHIM"

# Resolve the REAL flock before this harness can shadow it. Without util-linux
# flock (MSYS2/Windows dev boxes) the suite installs a no-op stand-in so the
# lock-using paths still run; the live-contention assertion is then SKIPped
# because a stand-in cannot emulate exclusion. Linux/CI always has the real one.
REAL_FLOCK="$(command -v flock 2>/dev/null || true)"
HAS_REAL_FLOCK=0
[ -n "$REAL_FLOCK" ] && HAS_REAL_FLOCK=1
if [ "$HAS_REAL_FLOCK" = "0" ]; then
    printf '#!/usr/bin/env bash\n# no-op stand-in: no util-linux flock on this platform\nexit 0\n' > "$SHIM/flock"
    chmod +x "$SHIM/flock"
fi

export MOCK_SB_ACTIVE=1 MOCK_RELOAD=ok MOCK_RELOAD_COUNTER="$TMP/reload.count"
export PROC_HYGIENE_LOG="$TMP/proc-hygiene.log"
: > "$PROC_HYGIENE_LOG"

# A /proc sampler that runs at the EXACT instants the privileged worker (or one
# of its children) holds a planned credential in memory: the mock generator is
# invoked while the values live in the worker's shell variables, and the jq
# shim is invoked while the credential JSON is in flight over the anonymous
# pipe. Everything it sees stays inside this log; the sentinel assertions below
# require zero hits.
cat > "$SHIM/proc-hygiene-probe" <<'PROBE'
#!/usr/bin/env bash
[ -d /proc ] || exit 0
log="${PROC_HYGIENE_LOG:-}"
[ -n "$log" ] || exit 0
# Sampled only inside the mutation window: the harness itself legitimately
# passes the sentinel as `jq --arg` AFTER the transaction, and that must not be
# mistaken for a product leak.
[ -f "${log}.on" ] || exit 0
for p in /proc/[0-9]*; do
    {
        printf 'CMD %s ' "$p"; tr '\000' ' ' < "$p/cmdline" 2>/dev/null; printf '\n'
        printf 'ENV %s ' "$p"; tr '\000' '\n' < "$p/environ" 2>/dev/null; printf '\n'
    } >> "$log" 2>/dev/null
done
exit 0
PROBE
chmod +x "$SHIM/proc-hygiene-probe"

REAL_JQ="$(command -v jq)"
cat > "$SHIM/jq" <<SHIMEOF
#!/usr/bin/env bash
"$SHIM/proc-hygiene-probe" >/dev/null 2>&1
exec "$REAL_JQ" "\$@"
SHIMEOF
chmod +x "$SHIM/jq"

# The mock generator is driven by a FILE FLAG, never by an environment variable:
# passing the sentinel through the environment would make the /proc scan find
# the sentinel in this harness's own environ and produce a false positive.
cat > "$SB/mock-sing-box" <<'MOCK'
#!/usr/bin/env bash
# Deterministic sentinel for the FIRST client (flag file present) so the test
# can assert the exact values in the live config; otherwise every call returns
# a UNIQUE value so repeated adds cannot collide on the config's structural
# duplicate-uuid/password audit.
DIR="${0%/*}"
SENTINEL_UUID="M1_SECRET_SENTINEL_UUID_0123456789abcdef"
SENTINEL_PASSWORD="M1_SECRET_SENTINEL_PASSWORD_0123456789abcdef"
command -v proc-hygiene-probe >/dev/null 2>&1 && proc-hygiene-probe >/dev/null 2>&1
case "${1:-}" in
    check) exit 0 ;;
    generate)
        case "${2:-}" in
            uuid) if [ -f "$DIR/.sentinel-on" ]; then
                      printf '%s\n' "$SENTINEL_UUID"
                  else
                      printf 'uuid-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM"
                  fi ;;
            rand) if [ -f "$DIR/.sentinel-on" ]; then
                      printf '%s\n' "$SENTINEL_PASSWORD"
                  else
                      printf 'pw-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM"
                  fi ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
MOCK
chmod +x "$SB/mock-sing-box"

cat > "$SHIM/systemctl" <<'SHIMEOF'
#!/usr/bin/env bash
case "${1:-}" in
    is-active) [ "${MOCK_SB_ACTIVE:-1}" = "1" ] && exit 0 || exit 3 ;;
    reload)
        [ "${MOCK_RELOAD:-ok}" = "fail-all" ] && exit 1
        if [ "${MOCK_RELOAD:-ok}" = "fail-once" ]; then
            n=0
            [ -f "$MOCK_RELOAD_COUNTER" ] && n="$(cat "$MOCK_RELOAD_COUNTER")"
            n=$((n + 1))
            printf '%s' "$n" > "$MOCK_RELOAD_COUNTER"
            [ "$n" -eq 1 ] && exit 1
        fi
        exit 0 ;;
    *) exit 0 ;;
esac
SHIMEOF
chmod +x "$SHIM/systemctl"
printf '#!/usr/bin/env bash\nexit 1\n' > "$SHIM/pgrep"
chmod +x "$SHIM/pgrep"
export PATH="$SHIM:$PATH"

write_live() {
    cat > "$SB_SERVER_CONFIG" <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
}
write_live

LIVE_SUM="$(sha256sum "$SB_SERVER_CONFIG" | awk '{print $1}')"
LEDGER="$SB/state/ledger/cm-ledger.jsonl"
AUDIT="$SB/state/audit/cm.jsonl"

wout(){ printf '%s' "$2" | "${WORKER_CMD[@]}" "$1" 2>"$TMP/w.err"; }
jqv(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null; }
count(){ if [ -f "$1" ]; then grep -c -- "$2" "$1" || true; else printf '0'; fi; }
sum(){ sha256sum "$1" | awk '{print $1}'; }

# ------------------------------------------------------------------ status ----
printf '\n== status / list before activation ==\n'
o="$(wout management.status '{"request_id":"reqid-status-000001"}')"
assert_eq true "$(jqv "$o" '.ok')" 'status succeeds'
assert_eq inactive "$(jqv "$o" '.data.management_state')" 'status reports inactive without a marker'
assert_eq false "$(jqv "$o" '.data.helper.degraded')" 'status reports not degraded'
assert_eq false "$(jqv "$o" '.data.management_active')" 'management_active is false by default'

o="$(wout client.list '{"request_id":"reqid-list-0000002"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.list works while inactive'
assert_eq legacy "$(jqv "$o" '.data.clients[0].name')" 'list returns the existing client'
assert_eq true "$(jqv "$o" '.data.clients[0].reserved')" 'legacy is reserved'
assert_eq false "$(jqv "$o" '.data.clients[0].mutable')" 'legacy is not mutable'
assert_eq untracked "$(jqv "$o" '.data.clients[0].source')" 'source is untracked (never guessed)'
assert_eq false "$(jqv "$o" '.data.truncated')" 'list is not truncated'
if printf '%s' "$o" | grep -qF 'LEGACY-UUID' || printf '%s' "$o" | grep -qF 'LEGACY-PASS'; then
    fail 'client.list leaked credentials'
else
    pass 'client.list carries zero credentials'
fi

# --------------------------------------------------------- activation gate ----
printf '\n== add is refused while inactive ==\n'
o="$(wout client.add '{"request_id":"reqid-add-inactiv1","name":"vmix-01","idempotency_key":"key-000000000001"}')"
assert_eq false "$(jqv "$o" '.ok')" 'add refused while inactive'
assert_eq E_ACTIVATION_STATE "$(jqv "$o" '.code')" 'inactive add returns E_ACTIVATION_STATE'
assert_eq "$LIVE_SUM" "$(sum "$SB_SERVER_CONFIG")" 'inactive add mutated nothing'

# ----------------------------------------------------------------- activate ----
printf '\n== management.activate ==\n'
o="$(wout management.activate '{"request_id":"reqid-activate-0001","actor":{"session_fp":"0123456789abcdef"}}')"
assert_eq true "$(jqv "$o" '.ok')" 'activate succeeds'
assert_eq false "$(jqv "$o" '.data.no_op')" 'activate is not a no-op the first time'
[ -f "$SB/state/management.active" ] && pass 'marker exists' || fail 'marker missing'
assert_eq active "$(jqv "$(wout management.status '{"request_id":"reqid-status-000003"}')" '.data.management_state')" \
    'status reports active after activate'

o="$(wout management.activate '{"request_id":"reqid-activate-0002"}')"
assert_eq true "$(jqv "$o" '.data.no_op')" 'second activate is a no-op (idempotent)'

# ---------------------------------------------------------------------- add ----
printf '\n== client.add (planned credential transaction) ==\n'
SENTINEL_UUID="M1_SECRET_SENTINEL_UUID_0123456789abcdef"
SENTINEL_PASSWORD="M1_SECRET_SENTINEL_PASSWORD_0123456789abcdef"
touch "$SB/.sentinel-on"
: > "$PROC_HYGIENE_LOG"
touch "$PROC_HYGIENE_LOG.on"
o="$(wout client.add '{"request_id":"reqid-add-000000001","name":"vmix-01","idempotency_key":"key-000000000001"}')"
rm -f "$PROC_HYGIENE_LOG.on"
assert_eq true "$(jqv "$o" '.ok')" 'add succeeds while active'
assert_eq vmix-01 "$(jqv "$o" '.data.name')" 'add reports the name'
assert_eq false "$(jqv "$o" '.idempotency.replayed')" 'first add is not a replay'
if jq -e --arg u "$SENTINEL_UUID" --arg p "$SENTINEL_PASSWORD" '
      ([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-01")|.uuid][0]) == $u
      and ([.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="vmix-01")|.password][0]) == $p
      and ([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")]|length) == 1
    ' "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass 'live config received both protocols, legacy preserved'
else
    fail 'live config after add is wrong'
fi
assert_eq 1 "$(count "$LEDGER" '"kind":"intent"')" 'exactly one durable intent'
assert_eq 1 "$(count "$LEDGER" '"kind":"outcome"')" 'exactly one durable outcome'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-add-000000001"')" 'exactly one audit record'
assert_eq 0 "$(ls -1 "$SB/state/journal" 2>/dev/null | wc -l | tr -d ' ')" 'journal cleared after success'
if grep -qF "$SENTINEL_UUID" "$LEDGER" || grep -qF "$SENTINEL_PASSWORD" "$LEDGER"; then
    fail 'ledger contains credential material'
else
    pass 'ledger contains only digests'
fi
if grep -qF "$SENTINEL_UUID" "$AUDIT" || grep -qF "$SENTINEL_PASSWORD" "$AUDIT"; then
    fail 'audit contains credential material'
else
    pass 'audit contains only fingerprints'
fi

printf '\n== dynamic secret hygiene (sampled during the mutation) ==\n'
if [ -d /proc ]; then
    if [ -s "$PROC_HYGIENE_LOG" ]; then
        pass "process hygiene sampling captured $(wc -l < "$PROC_HYGIENE_LOG" | tr -d ' ') sample lines"
    else
        fail 'process hygiene sampling captured nothing (probe never ran)'
    fi
    if grep -qF "$SENTINEL_UUID" "$PROC_HYGIENE_LOG" \
       || grep -qF "$SENTINEL_PASSWORD" "$PROC_HYGIENE_LOG"; then
        fail 'credential sentinel appeared in some /proc cmdline or environ'
    else
        pass 'zero credential hits across /proc/*/cmdline and /proc/*/environ'
    fi
    n_journal="$(grep -cF "$SENTINEL_UUID" "$SB/state/journal"/*.json 2>/dev/null | tr -d ' ' || true)"
    [ "${n_journal:-0}" = "0" ] && pass 'no credential in the tx journal' \
        || fail "credential found in the tx journal ($n_journal)"
else
    skip 'no /proc: dynamic process hygiene sampling skipped'
fi

# Later clients must get fresh credentials: the sentinel is only for the first.
rm -f "$SB/.sentinel-on"

ADD_SUM="$(sum "$SB_SERVER_CONFIG")"

printf '\n== idempotency ==\n'
o="$(wout client.add '{"request_id":"reqid-add-retry-0001","name":"vmix-01","idempotency_key":"key-000000000001"}')"
assert_eq true "$(jqv "$o" '.ok')" 'same key retry succeeds'
assert_eq true "$(jqv "$o" '.idempotency.replayed')" 'same key retry is a replay'
assert_eq "$ADD_SUM" "$(sum "$SB_SERVER_CONFIG")" 'replay performed no second transaction'
assert_eq 1 "$(count "$LEDGER" '"kind":"intent"')" 'replay added no ledger intent'

o="$(wout client.add '{"request_id":"reqid-add-conflict1","name":"other-01","idempotency_key":"key-000000000001"}')"
assert_eq false "$(jqv "$o" '.ok')" 'same key different semantics is refused'
assert_eq E_IDEMPOTENCY_CONFLICT "$(jqv "$o" '.code')" 'conflict returns E_IDEMPOTENCY_CONFLICT'

# ------------------------------------------------------------------- delete ----
printf '\n== client.delete ==\n'
mkdir -p "$SB/clients/vmix-01"
printf 'x\n' > "$SB/clients/vmix-01/mihomo.yaml"
o="$(wout client.delete '{"request_id":"reqid-del-000000001","name":"vmix-01","idempotency_key":"key-000000000002"}')"
assert_eq true "$(jqv "$o" '.ok')" 'delete succeeds'
assert_eq true "$(jqv "$o" '.data.deleted')" 'delete reports deleted'
assert_eq true "$(jqv "$o" '.data.derived_cleanup')" 'derived cleanup succeeded'
if jq -e '([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-01")]|length)==0
          and ([.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="vmix-01")]|length)==0
          and ([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")]|length)==1' \
        "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass 'delete removed both protocols and kept legacy'
else
    fail 'live config after delete is wrong'
fi
[ ! -d "$SB/clients/vmix-01" ] && pass 'derived directory removed' || fail 'derived directory left behind'

# ------------------------------------------------------- second generation ----
printf '\n== delete must never remove a rebuilt same-name client ==\n'
o="$(wout client.add '{"request_id":"reqid-add-vmix02-0","name":"vmix-02","idempotency_key":"key-000000000003"}')"
assert_eq true "$(jqv "$o" '.ok')" 'add vmix-02 succeeds'

# shellcheck source=/dev/null
warning(){ :; }
info(){ :; }
# shellcheck source=/dev/null
. "$ROOT/lib/client-management.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/sbox-cm-state.sh"

OLD_DIGEST="$(cm_old_cred_digest "$SB_SERVER_CONFIG" vmix-02)"
CM_DIGEST="$(cm_request_digest "client.delete" "vmix-02")"
cm_ledger_append_intent "key-000000000004" "client.delete" "vmix-02" "$CM_DIGEST" 1 \
    "reqid-del-vmix02-0" "old_cred_digest" "$OLD_DIGEST" \
    || fail 'could not stage the stale delete intent'

# rotate vmix-02 in place (as an external actor would)
jq '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-02")|.uuid) = "ROTATED-UUID"
    | (.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="vmix-02")|.password) = "ROTATED-PASS"' \
    "$SB_SERVER_CONFIG" > "$SB/rotated.json" && mv "$SB/rotated.json" "$SB_SERVER_CONFIG"

o="$(wout client.delete '{"request_id":"reqid-del-vmix02-0","name":"vmix-02","idempotency_key":"key-000000000004"}')"
assert_eq false "$(jqv "$o" '.ok')" 'stale delete intent is refused'
assert_eq E_RECONCILE_CONFLICT "$(jqv "$o" '.code')" 'returns E_RECONCILE_CONFLICT'
if jq -e '([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-02" and .uuid=="ROTATED-UUID")]|length)==1' \
        "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass 'the rebuilt second generation client was NOT deleted'
else
    fail 'second generation client was damaged'
fi

# ------------------------------------------------------------------ degraded ----
printf '\n== degraded semantics ==\n'
cm_degraded_set manual_intervention 'test-injected'
o="$(wout client.add '{"request_id":"reqid-add-degraded1","name":"vmix-03","idempotency_key":"key-000000000005"}')"
assert_eq false "$(jqv "$o" '.ok')" 'add refused while degraded'
assert_eq E_MANUAL_INTERVENTION "$(jqv "$o" '.code')" 'degraded add returns E_MANUAL_INTERVENTION'
o="$(wout management.status '{"request_id":"reqid-status-degrad1"}')"
assert_eq true "$(jqv "$o" '.ok')" 'status stays available while degraded'
assert_eq true "$(jqv "$o" '.data.helper.degraded')" 'status reports degraded=true'
o="$(wout client.list '{"request_id":"reqid-list-degraded1"}')"
assert_eq true "$(jqv "$o" '.ok')" 'client.list stays available while degraded'
o="$(wout management.deactivate '{"request_id":"reqid-deact-degrad1"}')"
assert_eq false "$(jqv "$o" '.ok')" 'deactivate refused while degraded'
cm_degraded_clear

# ---------------------------------------------------------------- lock failure ----
printf '\n== lock acquisition failure performs zero mutation ==\n'
# Platform-independent: flock EXISTS but the exclusive acquire fails/times out.
FLSHIM="$TMP/flshim"
mkdir -p "$FLSHIM"
printf '#!/usr/bin/env bash\nexit 1\n' > "$FLSHIM/flock"
chmod +x "$FLSHIM/flock"
before="$(sum "$SB_SERVER_CONFIG")"
o="$( export PATH="$FLSHIM:$PATH"; wout client.add '{"request_id":"reqid-add-lockfail1","name":"vmix-05","idempotency_key":"key-000000000007"}' )"
assert_eq E_LOCK "$(jqv "$o" '.code')" 'failed lock acquire returns E_LOCK'
assert_eq "$before" "$(sum "$SB_SERVER_CONFIG")" 'failed lock acquire left the config untouched'
if jq -e '([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-05")]|length)==0' \
        "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass 'nothing was created by the failed-lock attempt'
else
    fail 'the failed-lock attempt mutated the config'
fi
cand_count=0
for f in "$SB"/*candidate*; do [ -e "$f" ] && cand_count=$((cand_count + 1)); done
assert_eq 0 "$cand_count" 'the failed-lock attempt left no candidate behind'

printf '\n== live lock contention (real flock) ==\n'
if [ "$HAS_REAL_FLOCK" = "1" ]; then
    HOLD_PID=""
    SB_LOCK_FILE="$SB_LOCK_FILE" bash -c \
        'exec 9>>"$SB_LOCK_FILE"; flock -w 30 9; touch "$SB_LOCK_FILE.held"; sleep 30' &
    HOLD_PID=$!
    for _ in $(seq 1 50); do
        [ -f "$SB_LOCK_FILE.held" ] && break
        sleep 0.1
    done
    before="$(sum "$SB_SERVER_CONFIG")"
    export SB_LOCK_TIMEOUT=1
    o="$(wout client.add '{"request_id":"reqid-add-locked-01","name":"vmix-04","idempotency_key":"key-000000000006"}')"
    unset SB_LOCK_TIMEOUT
    assert_eq E_LOCK "$(jqv "$o" '.code')" 'a concurrently held lock yields E_LOCK'
    assert_eq "$before" "$(sum "$SB_SERVER_CONFIG")" 'lock contention left the config untouched'
    kill "$HOLD_PID" 2>/dev/null || true
    wait "$HOLD_PID" 2>/dev/null || true
    rm -f "$SB_LOCK_FILE.held"
else
    skip 'real flock unavailable: live-contention assertion skipped'
fi

# ---------------------------------------------------------------- reconcile ----
printf '\n== startup reconciliation ==\n'
mkdir -p "$SB/state/journal"
printf '%s\n' \
  '{"v":1,"request_id":"reqid-orphan-000001","op":"client.add","phase":"replace","backup_path":null,"generation":1}' \
  > "$SB/state/journal/reqid-orphan-000001.json"
export MOCK_RELOAD=fail-all
o="$(printf '' | "${WORKER_CMD[@]}" --maintenance reconcile 2>"$TMP/r.err")"
assert_eq true "$(jqv "$o" '.ok')" 'reconcile returns a protocol result'
assert_eq false "$(jqv "$o" '.data.reconciled')" 'unprovable journal marks reconcile as not reconciled'
assert_eq true "$(jqv "$o" '.data.degraded')" 'unprovable journal sets degraded'
[ -f "$SB/state/degraded.json" ] && pass 'degraded flag is durable' || fail 'degraded flag missing'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-orphan-000001"')" 'reconcile wrote exactly one audit'
printf '' | "${WORKER_CMD[@]}" --maintenance reconcile >/dev/null 2>&1
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-orphan-000001"')" 'second reconcile adds no second audit'
export MOCK_RELOAD=ok

printf '\n== reload failure rolls back (F6/F7) ==\n'
cm_degraded_clear
before="$(sum "$SB_SERVER_CONFIG")"
export MOCK_RELOAD=fail-once
rm -f "$MOCK_RELOAD_COUNTER"
o="$(wout client.add '{"request_id":"reqid-add-rollback0","name":"vmix-09","idempotency_key":"key-000000000009"}')"
unset MOCK_RELOAD
assert_eq false "$(jqv "$o" '.ok')" 'reload failure is reported as failure'
assert_eq E_ROLLED_BACK "$(jqv "$o" '.code')" \
    "reload failure maps to E_ROLLED_BACK (phase=$(jqv "$o" '.transaction.phase') detail=$(jqv "$o" '.detail'))"
assert_eq "$before" "$(sum "$SB_SERVER_CONFIG")" 'rolled-back add restored the live config byte-for-byte'
if jq -e '([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-09")]|length)==0' \
        "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass 'rolled-back client never appears in the live config'
else
    fail 'rolled-back client leaked into the live config'
fi

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_WORKER=FAIL\n'; exit 1; }
printf 'E3_M1_WORKER=PASS\n'
