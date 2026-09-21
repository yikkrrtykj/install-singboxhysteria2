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
# M4 export fixtures (spec §12): fixed credential pair driven by flag files,
# same file-flag discipline as the sentinel above (never an env var).
FIXTURE_UUID="11111111-2222-3333-4444-555555555555"
FIXTURE_PASSWORD="super-secret-hy2-fixture"
command -v proc-hygiene-probe >/dev/null 2>&1 && proc-hygiene-probe >/dev/null 2>&1
case "${1:-}" in
    check) exit 0 ;;
    generate)
        case "${2:-}" in
            uuid) if [ -f "$DIR/.fixture-on" ]; then
                      printf '%s\n' "$FIXTURE_UUID"
                  elif [ -f "$DIR/.sentinel-on" ]; then
                      printf '%s\n' "$SENTINEL_UUID"
                  else
                      printf 'uuid-%s-%s-%s\n' "$$" "$RANDOM" "$RANDOM"
                  fi ;;
            rand) if [ -f "$DIR/.fixturepw-on" ]; then
                      printf '%s\n' "$FIXTURE_PASSWORD"
                  elif [ -f "$DIR/.sentinel-on" ]; then
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

# ------------------------------------------------ status read-only contract ----
printf '\n== status is strictly read-only: the lock probe never creates the anchor ==\n'
rm -f "$SB_LOCK_FILE"
o="$(wout management.status '{"request_id":"reqid-status-lockpr1"}')"
assert_eq true "$(jqv "$o" '.ok')" 'status works without a lock anchor'
assert_eq true "$(jqv "$o" '.data.lock.acquirable')" 'a missing anchor reads as acquirable'
[ ! -e "$SB_LOCK_FILE" ] && pass 'status did NOT create the lock anchor' \
    || fail 'status created the lock anchor (read-only contract violated)'

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

# ------------------------------------------------------- M4 client.export ----
printf '\n== client.export (M4: the sanctioned sensitive read) ==\n'
# The renderer reads the install-state facts from SB_STATE_FILE; a real
# install writes them, the sandbox provides the same shape.
cat > "$SB_STATE_FILE" <<'STATE'
SERVER_IP='203.0.113.7'
PUBLIC_KEY='PUBKEYfixture000000000000000000000000000000000000'
HY_SERVER_NAME='www.example.com'
HY_HOPPING=FALSE
STATE
# Give the live config the shape the frozen renderer parses (ports + Reality
# block); user sets stay exactly as the transactions left them.
jq '.inbounds |= map(
      if .tag == "vless-in" then
        .listen_port = 8443
        | .tls = {"enabled":true,"server_name":"www.example.com",
                  "reality":{"enabled":true,
                             "handshake":{"server":"www.example.com","server_port":443},
                             "private_key":"PRIV-NEVER-ASSERTED","short_id":["abcd1234"]}}
      elif .tag == "hy2-in" then
        .listen_port = 8444
      else . end)' \
    "$SB_SERVER_CONFIG" > "$SB/shaped.json" && mv "$SB/shaped.json" "$SB_SERVER_CONFIG"

FIXTURE_UUID="11111111-2222-3333-4444-555555555555"
FIXTURE_PASSWORD="super-secret-hy2-fixture"
touch "$SB/.fixture-on" "$SB/.fixturepw-on"
o="$(wout client.add '{"request_id":"reqid-add-export0","name":"exp-01","idempotency_key":"key-000000000a01"}')"
rm -f "$SB/.fixture-on" "$SB/.fixturepw-on"
assert_eq true "$(jqv "$o" '.ok')" 'add exp-01 with the export fixtures'

LEDGER_N="$(count "$LEDGER" '"kind":"intent"')"
AUDIT_N="$(count "$AUDIT" '"request_id"')"
CONFIG_N="$(sum "$SB_SERVER_CONFIG")"
export MOCK_RELOAD=fail-once
rm -f "$MOCK_RELOAD_COUNTER"
: > "$TMP/x.err"
touch "$PROC_HYGIENE_LOG.on"
o="$(wout client.export '{"request_id":"reqid-export-000001","name":"exp-01","actor":{"session_fp":"0123456789abcdef","stepup_fp":"fedcba9876543210"}}' 2>"$TMP/x.err")"
rm -f "$PROC_HYGIENE_LOG.on"
assert_eq true "$(jqv "$o" '.ok')" 'export succeeds while active'
assert_eq OK "$(jqv "$o" '.code')" 'export code is OK'
assert_eq done "$(jqv "$o" '.stage')" 'export stage is done'
assert_eq mihomo-yaml "$(jqv "$o" '.data.format')" 'export reports the mihomo-yaml format'
assert_eq exp-01-mihomo.yaml "$(jqv "$o" '.data.filename')" 'export filename is <name>-mihomo.yaml'
Y="$(jqv "$o" '.data.content')"
if printf '%s' "$Y" | grep -qF "uuid: $FIXTURE_UUID" \
   && printf '%s' "$Y" | grep -qF "password: $FIXTURE_PASSWORD"; then
    pass 'the exported YAML carries the client credentials'
else
    fail 'the exported YAML lacks the client credentials'
fi
assert_eq 203.0.113.7 "$(printf '%s\n' "$Y" | grep -m1 'server: ' | sed 's/.*server: //')" \
    'export resolves the server facts from state'
if printf '%s\n' "$Y" | head -n 1 | grep -qx 'mixed-port: 7897'; then
    pass 'export content starts at the exact first template byte'
else
    fail 'export content does not start at byte 0 of the template'
fi
if printf '%s' "$o" | jq -e '.data.content | endswith("\n\n")' >/dev/null 2>&1; then
    pass 'export content keeps the template trailing blank line (X-sentinel fidelity)'
else
    fail 'trailing bytes were stripped from the export'
fi
assert_eq null "$(jqv "$o" '.idempotency')" 'export is not an idempotent transaction'
assert_eq false "$(jqv "$o" '.transaction.changed')" 'export transaction reports no change'
assert_eq false "$(jqv "$o" '.transaction.reload_performed')" 'export performed no reload'
[ ! -f "$MOCK_RELOAD_COUNTER" ] && pass 'export never invoked systemctl reload' \
    || fail 'export triggered a reload'
unset MOCK_RELOAD
export MOCK_RELOAD=ok

printf '\n== client.export is strictly read-only ==\n'
assert_eq "$CONFIG_N" "$(sum "$SB_SERVER_CONFIG")" 'export left the live config byte-identical'
assert_eq "$LEDGER_N" "$(count "$LEDGER" '"kind":"intent"')" 'export wrote no ledger intent'
assert_eq "$LEDGER_N" "$(count "$LEDGER" '"kind":"outcome"')" 'export wrote no ledger outcome'
assert_eq 0 "$(ls -1 "$SB/state/journal" 2>/dev/null | wc -l | tr -d ' ')" 'export wrote no journal'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-export-000001"')" 'export wrote exactly one audit record'
EXP_ROW="$(grep -F '"request_id":"reqid-export-000001"' "$AUDIT" | tail -n 1)"
assert_eq client.export "$(jqv "$EXP_ROW" '.op')" 'the export audit records the op'
assert_eq ok "$(jqv "$EXP_ROW" '.outcome')" 'the export audit records the outcome'
assert_eq 0123456789abcdef "$(jqv "$EXP_ROW" '.actor.session_fp')" 'the export audit carries session_fp'
assert_eq fedcba9876543210 "$(jqv "$EXP_ROW" '.actor.stepup_fp')" 'the export audit carries stepup_fp'
assert_eq null "$(jqv "$EXP_ROW" '.key_fp')" 'the export audit has no idempotency key_fp'
assert_eq 0 "$(jqv "$EXP_ROW" '.generation')" 'the export audit records generation 0'

printf '\n== client.export fixture leak sweep ==\n'
if grep -qF "$FIXTURE_UUID" "$AUDIT" || grep -qF "$FIXTURE_PASSWORD" "$AUDIT"; then
    fail 'audit contains credential material'
else
    pass 'the audit holds only metadata'
fi
if grep -qF "$FIXTURE_UUID" "$LEDGER" || grep -qF "$FIXTURE_PASSWORD" "$LEDGER"; then
    fail 'ledger contains credential material'
else
    pass 'the ledger was not touched by the export'
fi
if grep -qF "$FIXTURE_UUID" "$TMP/x.err" || grep -qF "$FIXTURE_PASSWORD" "$TMP/x.err"; then
    fail 'worker stderr contains credential material'
else
    pass 'worker stderr is credential-free'
fi
if [ -d /proc ]; then
    if grep -qF "$FIXTURE_UUID" "$PROC_HYGIENE_LOG" \
       || grep -qF "$FIXTURE_PASSWORD" "$PROC_HYGIENE_LOG"; then
        fail 'credential sentinel appeared in some /proc cmdline or environ'
    else
        pass 'zero fixture credential hits across /proc/*/cmdline and /proc/*/environ'
    fi
else
    skip 'no /proc: dynamic process hygiene sampling skipped'
fi

printf '\n== client.export re-executes on every dispatch (the helper caches nothing) ==\n'
# The daemon-side replay cache is bypassed for sensitive ops (M4), so a second
# dispatch really re-runs the read -- there is NO transactional dedup anywhere:
# the audit-id exactly-once guard (request_id:generation) still collapses the
# duplicate to a single audit record.
o2="$(wout client.export '{"request_id":"reqid-export-000001","name":"exp-01"}')"
assert_eq true "$(jqv "$o2" '.ok')" 'the same request_id re-executes rather than dedups'
assert_eq "$Y" "$(jqv "$o2" '.data.content')" 'both exports render identical bytes'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-export-000001"')" \
    'the audit-id guard keeps one audit record for the repeated request_id'
o3="$(wout client.export '{"request_id":"reqid-export-000002","name":"exp-01"}')"
assert_eq true "$(jqv "$o3" '.ok')" 'a fresh request_id also succeeds'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-export-000002"')" 'each new request_id writes its own audit'
assert_eq "$Y" "$(jqv "$o3" '.data.content')" 'export is never served from a cache'
assert_eq "$CONFIG_N" "$(sum "$SB_SERVER_CONFIG")" 'the repeat exports also mutated nothing'

printf '\n== client.export legacy (the shared account is exportable) ==\n'
o="$(wout client.export '{"request_id":"reqid-export-legacy01","name":"legacy"}')"
assert_eq true "$(jqv "$o" '.ok')" 'legacy exports'
assert_eq legacy-mihomo.yaml "$(jqv "$o" '.data.filename')" 'legacy filename'
if printf '%s' "$o" | grep -qF 'LEGACY-UUID' && printf '%s' "$o" | grep -qF 'LEGACY-PASS'; then
    pass 'legacy export contains the legacy credentials'
else
    fail 'legacy export is missing its credentials'
fi

printf '\n== client.export refusals (fail-closed, zero YAML) ==\n'
o="$(wout client.export '{"request_id":"reqid-export-ghost001","name":"ghost-99"}')"
assert_eq false "$(jqv "$o" '.ok')" 'unknown client is refused'
assert_eq E_NOT_FOUND "$(jqv "$o" '.code')" 'unknown client returns E_NOT_FOUND'
o="$(wout client.export '{"request_id":"reqid-export-key00001","name":"exp-01","idempotency_key":"key-000000000a02"}')"
assert_eq E_SCHEMA "$(jqv "$o" '.code')" 'export refuses an idempotency_key'
o="$(wout client.export '{"request_id":"reqid-export-badname01","name":"../etc/passwd"}')"
assert_eq E_SCHEMA "$(jqv "$o" '.code')" 'export refuses an invalid name'

# incomplete credentials: name present, uuid emptied. candidate_problems
# already flags an empty uuid as an inconsistent user set, so this proves the
# preconditions gate refuses an inconsistent config BEFORE any render ships.
o="$(wout client.add '{"request_id":"reqid-add-expbroken","name":"exp-brk1","idempotency_key":"key-000000000a03"}')"
jq '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="exp-brk1")|.uuid) = ""' \
    "$SB_SERVER_CONFIG" > "$SB/broken.json" && mv "$SB/broken.json" "$SB_SERVER_CONFIG"
o="$(wout client.export '{"request_id":"reqid-export-broken01","name":"exp-brk1"}')"
assert_eq false "$(jqv "$o" '.ok')" 'a client with emptied credentials is refused'
assert_eq E_CONFIG_INCONSISTENT "$(jqv "$o" '.code')" 'incomplete credentials map to E_CONFIG_INCONSISTENT'
printf '%s' "$o" | grep -qF "$FIXTURE_PASSWORD" && fail 'the refusal echoed credential material' \
    || pass 'the refusal is credential-free'
# repair OUT OF BAND: while the config is inconsistent the helper refuses
# every mutation, so the harness restores the bytes directly.
jq '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="exp-brk1")|.uuid) = "REPAIRED-UUID-brk1"
    | (.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="exp-brk1")|.password) = "REPAIRED-PASS-brk1"' \
    "$SB_SERVER_CONFIG" > "$SB/repair1.json" && mv "$SB/repair1.json" "$SB_SERVER_CONFIG"
o="$(wout client.delete '{"request_id":"reqid-del-expbrk0001","name":"exp-brk1","idempotency_key":"key-000000000a08"}')"
assert_eq true "$(jqv "$o" '.ok')" 'cleanup: exp-brk1 removed before the next scenario'

# over the 48 KiB frame cap: refuse, NEVER truncate
BIG="$(printf 'p%.0s' $(seq 1 60000))"
o="$(wout client.add '{"request_id":"reqid-add-expbig0001","name":"exp-big1","idempotency_key":"key-000000000a04"}')"
# the oversized value travels via ENV: --arg would blow the argv limit under
# the jq shim on some platforms, and this value is not secret material.
BIG_PW="$BIG" jq '(.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="exp-big1")|.password) = $ENV.BIG_PW' \
    "$SB_SERVER_CONFIG" > "$SB/big.json" && mv "$SB/big.json" "$SB_SERVER_CONFIG"
o="$(wout client.export '{"request_id":"reqid-export-big0001","name":"exp-big1"}')"
if ! printf '%s' "$o" | jq -e '.ok == false' >/dev/null 2>&1; then
    fail 'the oversized injection did not land on this platform; the over-cap case is untested'
else
assert_eq false "$(jqv "$o" '.ok')" 'an over-cap export is refused'
assert_eq E_INTERNAL "$(jqv "$o" '.code')" 'over-cap maps to E_INTERNAL (fail-closed, no truncation)'
printf '%s' "$o" | grep -qF "$FIXTURE_PASSWORD" && fail 'the over-cap refusal echoed credential material' \
    || pass 'the over-cap refusal is credential-free'
fi

printf '\n== client.export refusals while degraded / inactive ==\n'
# sourcing is idempotent (pure function definitions); the later sections
# source the same libraries again.
# shellcheck source=/dev/null
. "$ROOT/lib/sbox-cm-state.sh"
cm_degraded_set manual_intervention 'export-test'
o="$(wout client.export '{"request_id":"reqid-export-degrad01","name":"exp-01"}')"
assert_eq false "$(jqv "$o" '.ok')" 'export refused while degraded'
assert_eq E_MANUAL_INTERVENTION "$(jqv "$o" '.code')" 'degraded export returns E_MANUAL_INTERVENTION'
cm_degraded_clear
o="$(wout management.deactivate '{"request_id":"reqid-deact-export01"}')"
assert_eq true "$(jqv "$o" '.ok')" 'deactivated for the export gate test'
o="$(wout client.export '{"request_id":"reqid-export-inactiv1","name":"exp-01"}')"
assert_eq false "$(jqv "$o" '.ok')" 'export refused while inactive'
assert_eq E_ACTIVATION_STATE "$(jqv "$o" '.code')" 'inactive export returns E_ACTIVATION_STATE'
o="$(wout management.activate '{"request_id":"reqid-activate-exptr1","actor":{"session_fp":"0123456789abcdef"}}')"
assert_eq true "$(jqv "$o" '.ok')" 'reactivated for the remaining sections'

# clean up the export fixtures so the later sections see the state they expect
o="$(wout client.delete '{"request_id":"reqid-del-export03","name":"exp-big1","idempotency_key":"key-000000000a07"}')"
assert_eq true "$(jqv "$o" '.ok')" 'cleanup: exp-big1 deleted'
o="$(wout client.delete '{"request_id":"reqid-del-export01","name":"exp-01","idempotency_key":"key-000000000a05"}')"
assert_eq true "$(jqv "$o" '.ok')" 'cleanup: exp-01 deleted'

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
o="$( export PATH="$FLSHIM:$PATH"; wout client.export '{"request_id":"reqid-export-lockfl1","name":"legacy"}' )"
assert_eq E_LOCK "$(jqv "$o" '.code')" 'export refuses when the lock cannot be acquired'
printf '%s' "$o" | grep -qF 'LEGACY-PASS' && fail 'the lock-refused export echoed YAML' \
    || pass 'the lock-refused export dispatched no YAML'

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

# ------------------------------------------------------- active_stale split ----
printf '\n== active_stale: the public RPC refuses, root maintenance recovers (B4) ==\n'
mv "$SB_SERVER_CONFIG" "$TMP/live.hidden"
o="$(wout management.status '{"request_id":"reqid-status-stale01"}')"
assert_eq active_stale "$(jqv "$o" '.data.management_state')" 'missing live config reports active_stale'
o="$(wout management.deactivate '{"request_id":"reqid-deact-stale01"}')"
assert_eq false "$(jqv "$o" '.ok')" 'public deactivate REFUSES an active_stale marker'
assert_eq E_ACTIVATION_STATE "$(jqv "$o" '.code')" 'active_stale deactivate returns E_ACTIVATION_STATE'
[ -f "$SB/state/management.active" ] && pass 'the public RPC did NOT remove the marker' \
    || fail 'marker was removed through the RPC (root-recovery bypass)'
o="$(printf '' | "${WORKER_CMD[@]}" --maintenance mgmt-deactivate 2>"$TMP/md.err")"
assert_eq true "$(jqv "$o" '.ok')" 'root maintenance verb succeeds'
[ ! -f "$SB/state/management.active" ] && pass 'maintenance verb removed the stale marker' \
    || fail 'maintenance verb did not remove the marker'
mv "$TMP/live.hidden" "$SB_SERVER_CONFIG"
o="$(wout management.activate '{"request_id":"reqid-activate-recvr1","actor":{"session_fp":"0123456789abcdef"}}')"
assert_eq true "$(jqv "$o" '.ok')" 'reactivation after recovery succeeds'

# ---------------------------------------------- deactivate actor (M2-A0) ----
printf '\n== management.deactivate carries the actor into the audit (M2-A0) ==\n'
o="$(wout management.deactivate '{"request_id":"reqid-deact-actor01","actor":{"session_fp":"0123456789abcdef","stepup_fp":"fedcba9876543210"}}')"
assert_eq true "$(jqv "$o" '.ok')" 'deactivate accepts an actor and succeeds'
assert_eq inactive "$(jqv "$(wout management.status '{"request_id":"reqid-status-actor02"}')" '.data.management_state')" \
    'the plane is inactive after the actor deactivate'
ACTOR_ROW="$(grep -F '"request_id":"reqid-deact-actor01"' "$AUDIT" | tail -n 1)"
assert_eq 0123456789abcdef "$(jqv "$ACTOR_ROW" '.actor.session_fp')" 'the deactivate audit carries session_fp'
assert_eq fedcba9876543210 "$(jqv "$ACTOR_ROW" '.actor.stepup_fp')" 'the deactivate audit carries stepup_fp'
o="$(wout management.deactivate '{"request_id":"reqid-deact-noactor1"}')"
assert_eq true "$(jqv "$o" '.ok')" 'deactivate without an actor stays compatible'
NOACT_ROW="$(grep -F '"request_id":"reqid-deact-noactor1"' "$AUDIT" | tail -n 1)"
assert_eq null "$(jqv "$NOACT_ROW" '.actor.session_fp')" 'the actor-less deactivate audit has a null session_fp'
o="$(wout management.activate '{"request_id":"reqid-activate-actor3","actor":{"session_fp":"0123456789abcdef"}}')"
assert_eq true "$(jqv "$o" '.ok')" 'reactivated with an actor for the following sections'

# ------------------------------------------- delete replay original attempt ----
printf '\n== delete replay finalizes the ORIGINAL attempt (B3) ==\n'
o="$(wout client.add '{"request_id":"reqid-add-vmix06-0","name":"vmix-06","idempotency_key":"key-0000000000b1"}')"
assert_eq true "$(jqv "$o" '.ok')" 'add vmix-06 for the replay scenario'
OLD6="$(cm_old_cred_digest "$SB_SERVER_CONFIG" vmix-06)"
DD6="$(cm_request_digest "client.delete" "vmix-06")"
cm_ledger_append_intent "key-0000000000b2" "client.delete" "vmix-06" "$DD6" 1 \
    "reqid-del-orig-001" "old_cred_digest" "$OLD6" \
    || fail 'could not stage the in-flight delete intent'
printf '%s\n' '{"v":1,"request_id":"reqid-del-orig-001","op":"client.delete","phase":"candidate","backup_path":null,"generation":1}' \
    > "$SB/state/journal/reqid-del-orig-001.json"
# the delete DID take effect (out-of-band), but outcome/journal/audit never landed
jq '(.inbounds[]|select(.tag=="vless-in")|.users) |= map(select(.name != "vmix-06"))
    | (.inbounds[]|select(.tag=="hy2-in")|.users) |= map(select(.name != "vmix-06"))' \
    "$SB_SERVER_CONFIG" > "$SB/replay.json" && mv "$SB/replay.json" "$SB_SERVER_CONFIG"
o="$(wout client.delete '{"request_id":"reqid-del-new-0002","name":"vmix-06","idempotency_key":"key-0000000000b2"}')"
assert_eq true "$(jqv "$o" '.ok')" 'same-key retry with a NEW request_id replays'
assert_eq true "$(jqv "$o" '.idempotency.replayed')" 'the retry is marked replayed'
[ ! -f "$SB/state/journal/reqid-del-orig-001.json" ] \
    && pass 'the ORIGINAL request journal was finalized (not the retry only)' \
    || fail 'original orphan journal was left behind'
assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-del-orig-001"')" \
    'the original attempt got exactly one audit record'

IS_LINUX=0
[ "$(uname -s 2>/dev/null)" = "Linux" ] && IS_LINUX=1

if [ "$IS_LINUX" = "1" ]; then
    printf '\n== F15: replay whose outcome cannot be made durable is E_STATE_UNCERTAIN ==\n'
    o="$(wout client.add '{"request_id":"reqid-add-vmix07-0","name":"vmix-07","idempotency_key":"key-0000000000c1"}')"
    OLD7="$(cm_old_cred_digest "$SB_SERVER_CONFIG" vmix-07)"
    DD7="$(cm_request_digest "client.delete" "vmix-07")"
    cm_ledger_append_intent "key-0000000000c2" "client.delete" "vmix-07" "$DD7" 1 \
        "reqid-del-vmix07-0" "old_cred_digest" "$OLD7" \
        || fail 'could not stage the vmix-07 delete intent'
    jq '(.inbounds[]|select(.tag=="vless-in")|.users) |= map(select(.name != "vmix-07"))
        | (.inbounds[]|select(.tag=="hy2-in")|.users) |= map(select(.name != "vmix-07"))' \
        "$SB_SERVER_CONFIG" > "$SB/replay7.json" && mv "$SB/replay7.json" "$SB_SERVER_CONFIG"
    chmod 0400 "$LEDGER"
    o="$(wout client.delete '{"request_id":"reqid-del-vmix07-1","name":"vmix-07","idempotency_key":"key-0000000000c2"}')"
    chmod 0600 "$LEDGER"
    assert_eq false "$(jqv "$o" '.ok')" 'outcome append failure is NEVER a plain success'
    assert_eq E_STATE_UNCERTAIN "$(jqv "$o" '.code')" 'F15 maps to E_STATE_UNCERTAIN'
    o="$(wout client.delete '{"request_id":"reqid-del-vmix07-2","name":"vmix-07","idempotency_key":"key-0000000000c2"}')"
    assert_eq true "$(jqv "$o" '.ok')" 'the same key completes after the ledger is writable again'

    printf '\n== derived cleanup is reported for what actually happened ==\n'
    o="$(wout client.add '{"request_id":"reqid-add-vmix08-0","name":"vmix-08","idempotency_key":"key-0000000000d1"}')"
    OLD8="$(cm_old_cred_digest "$SB_SERVER_CONFIG" vmix-08)"
    DD8="$(cm_request_digest "client.delete" "vmix-08")"
    cm_ledger_append_intent "key-0000000000d2" "client.delete" "vmix-08" "$DD8" 1 \
        "reqid-del-vmix08-0" "old_cred_digest" "$OLD8" \
        || fail 'could not stage the vmix-08 delete intent'
    mkdir -p "$SB/clients/vmix-08"
    jq '(.inbounds[]|select(.tag=="vless-in")|.users) |= map(select(.name != "vmix-08"))
        | (.inbounds[]|select(.tag=="hy2-in")|.users) |= map(select(.name != "vmix-08"))' \
        "$SB_SERVER_CONFIG" > "$SB/replay8.json" && mv "$SB/replay8.json" "$SB_SERVER_CONFIG"
    chmod 0555 "$SB/clients"
    o="$(wout client.delete '{"request_id":"reqid-del-vmix08-1","name":"vmix-08","idempotency_key":"key-0000000000d2"}')"
    chmod 0755 "$SB/clients"
    assert_eq true "$(jqv "$o" '.ok')" 'the delete itself still replays ok'
    assert_eq false "$(jqv "$o" '.data.derived_cleanup')" \
        'failed derived cleanup is reported as derived_cleanup=false (no false success)'
    rm -rf "$SB/clients/vmix-08"

    printf '\n== audit failure keeps the journal and defers (B5) ==\n'
    chmod 0444 "$AUDIT"
    o="$(wout client.add '{"request_id":"reqid-add-auditdef1","name":"vmix-11","idempotency_key":"key-0000000000e1"}')"
    chmod 0600 "$AUDIT"
    assert_eq true "$(jqv "$o" '.ok')" 'the mutation itself still succeeded'
    printf '%s' "$o" | grep -qF 'audit_deferred' && pass 'the response warns audit_deferred (not a silent success)' \
        || fail 'audit failure was not surfaced in warnings'
    assert_eq 0 "$(count "$AUDIT" '"request_id":"reqid-add-auditdef1"')" 'no audit record was written'
    [ -f "$SB/state/journal/reqid-add-auditdef1.json" ] \
        && pass 'the journal was KEPT for reconciliation' \
        || fail 'the journal was cleared despite the missing audit'
    printf '' | "${WORKER_CMD[@]}" --maintenance reconcile >/dev/null 2>&1
    assert_eq 1 "$(count "$AUDIT" '"request_id":"reqid-add-auditdef1"')" \
        'reconciliation appended exactly the one missing audit'
    [ ! -f "$SB/state/journal/reqid-add-auditdef1.json" ] \
        && pass 'reconciliation cleared the journal only after the audit landed' \
        || fail 'journal was not cleared after audit recovery'

    printf '\n== export fail-closed on audit failure (M4 §7): zero YAML shipped ==\n'
    touch "$SB/audit-unwritable.marker"   # documentation only; chmod does the job
    chmod 0444 "$AUDIT"
    o="$(wout client.export '{"request_id":"reqid-export-auditfl1","name":"legacy"}')"
    chmod 0600 "$AUDIT"
    assert_eq false "$(jqv "$o" '.ok')" 'export refuses when its audit cannot be made durable'
    assert_eq E_INTERNAL "$(jqv "$o" '.code')" 'the export audit failure maps to E_INTERNAL'
    assert_eq 0 "$(count "$AUDIT" '"request_id":"reqid-export-auditfl1"')" 'no audit record was written'
    printf '%s' "$o" | grep -qF 'LEGACY-PASS' && fail 'the export shipped YAML despite the audit failure' \
        || pass 'no YAML was delivered on the export audit failure'
    rm -f "$SB/audit-unwritable.marker"
else
    skip 'POSIX permission fault injection is exercised on Linux CI only'
fi

# ------------------------------------------------- ledger corruption (B2) ----
printf '\n== ledger corruption is fail-closed (B2) ==\n'
cp "$LEDGER" "$TMP/ledger.good"
repair_ledger(){ cp "$TMP/ledger.good" "$LEDGER"; }

printf '{broken json\n' >> "$LEDGER"
o="$(wout client.add '{"request_id":"reqid-add-ledgcor1","name":"vmix-10","idempotency_key":"key-0000000000f1"}')"
assert_eq false "$(jqv "$o" '.ok')" 'a malformed complete line refuses mutation'
assert_eq E_LEDGER_UNAVAILABLE "$(jqv "$o" '.code')" 'corrupt ledger returns E_LEDGER_UNAVAILABLE'
repair_ledger

HEX64="$(printf 'a%.0s' $(seq 1 64))"
printf '{"v":1,"kind":"intent","key":"key-0000000000f2","op":"client.add","name":"x","digest":"%s","generation":"two","state":"in_flight","ts":"t","request_id":"reqid-ledgcor-002","planned_cred_digest":"%s"}\n' "$HEX64" "$HEX64" >> "$LEDGER"
o="$(wout client.add '{"request_id":"reqid-add-ledgcor2","name":"vmix-10","idempotency_key":"key-0000000000f3"}')"
assert_eq E_LEDGER_UNAVAILABLE "$(jqv "$o" '.code')" 'a non-numeric generation refuses mutation'
repair_ledger

printf '{"v":1,"kind":"intent","key":"key-0000000000f4","op":"client.add","name":"x","digest":"%s","generation":1,"state":"done","ts":"t","request_id":"reqid-ledgcor-004","planned_cred_digest":"%s"}\n' "$HEX64" "$HEX64" >> "$LEDGER"
o="$(wout client.add '{"request_id":"reqid-add-ledgcor3","name":"vmix-10","idempotency_key":"key-0000000000f5"}')"
assert_eq E_LEDGER_UNAVAILABLE "$(jqv "$o" '.code')" 'a kind/state mismatch refuses mutation'
repair_ledger

printf '{"v":1,"kind":"intent","key":"short","op":"client.add","name":"x","digest":"%s","generation":1,"state":"in_flight","ts":"t","request_id":"reqid-ledgcor-005","planned_cred_digest":"%s"}\n' "$HEX64" "$HEX64" >> "$LEDGER"
o="$(wout client.add '{"request_id":"reqid-add-ledgcor4","name":"vmix-10","idempotency_key":"key-0000000000f6"}')"
assert_eq E_LEDGER_UNAVAILABLE "$(jqv "$o" '.code')" 'a key-schema violation refuses mutation'
repair_ledger

# partial tail: a torn write that was never durable -> truncated, op proceeds
printf '{"v":1,"kind":"inte' >> "$LEDGER"
[ "$(tail -c 1 "$LEDGER" | od -An -tuC | tr -d '[:space:]')" != "10" ] \
    && pass 'partial tail staged (no trailing newline)' || fail 'partial tail staging failed'
o="$(wout client.add '{"request_id":"reqid-add-ledgcor5","name":"vmix-10","idempotency_key":"key-0000000000f7"}')"
assert_eq true "$(jqv "$o" '.ok')" 'a torn partial tail is repaired and the op proceeds'
[ "$(tail -c 1 "$LEDGER" | od -An -tuC | tr -d '[:space:]')" = "10" ] \
    && pass 'the partial tail is gone from the ledger' || fail 'partial tail survived'
repair_ledger

# complete record that only lost its terminating newline -> preserved
printf '{"v":1,"kind":"intent","key":"key-0000000000f8","op":"client.add","name":"zz","digest":"%s","generation":1,"state":"in_flight","ts":"t","request_id":"reqid-ledgcor-008","planned_cred_digest":"%s"}' "$HEX64" "$HEX64" >> "$LEDGER"
o="$(wout client.add '{"request_id":"reqid-add-ledgcor6","name":"vmix-12","idempotency_key":"key-0000000000f9"}')"
assert_eq true "$(jqv "$o" '.ok')" 'a newline-less complete record does not block the helper'
grep -qF '"key":"key-0000000000f8"' "$LEDGER" \
    && pass 'the complete tail record was preserved (newline re-appended)' \
    || fail 'a valid record was dropped by the repair'
assert_eq E_IDEMPOTENCY_CONFLICT "$(jqv "$(wout client.add '{"request_id":"reqid-add-ledgcor7","name":"other-11","idempotency_key":"key-0000000000f8"}')" '.code')" \
    'the preserved record is still authoritative for its key'
repair_ledger

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_WORKER=FAIL\n'; exit 1; }
printf 'E3_M1_WORKER=PASS\n'
