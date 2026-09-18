#!/usr/bin/env bash
# E3 M1 -- M1-A0 / M1-A: canonical library closure + planned credential hygiene.
#
# Runs entirely in a temporary sandbox with a mock sing-box and a jq shim that
# records every jq argv. No root, no systemd, no network.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/lib/client-management.sh"
STATE_LIB="$ROOT/lib/sbox-cm-state.sh"
INSTALL="$ROOT/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_ne(){ [ "$1" != "$2" ] && pass "$3" || fail "$3 (both=[$1])"; }

printf '===== E3 M1 SHARED LIB (M1-A0 + M1-A) =====\n'

SENTINEL_UUID="M1_SECRET_SENTINEL_UUID_0123456789abcdef"
SENTINEL_PASSWORD="M1_SECRET_SENTINEL_PASSWORD_0123456789abcdef"

# ---------------------------------------------------------------- static ----
printf '\n== canonical uniqueness ==\n'
for fn in validate_client_name client_name_exists get_reality_client_names get_hy2_client_names \
          client_structure_problems candidate_problems audit_client_consistency \
          get_client_credentials cm_cred_digest cm_cred_digest_of cm_plan_client_credential \
          cm_cred_forget cm_add_candidate_planned cm_delete_candidate cm_old_cred_digest \
          cm_planned_cred_digest cm_render_planned_candidate cm_add_client_candidate_planned; do
    lc="$(grep -cE "^${fn}\\(\\)" "$LIB" || true)"
    ic="$(grep -cE "^${fn}\\(\\)" "$INSTALL" || true)"
    [ "$lc" = "1" ] && [ "$ic" = "0" ] && pass "$fn single source in shared lib" \
        || fail "$fn lib=$lc install=$ic"
done

if grep -nE -- '--arg[= ]+(uuid|password)' "$LIB" "$INSTALL" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -q .; then
    fail 'credential-bearing --arg still present in lib/install'
else
    pass 'no credential-bearing jq --arg in lib/install'
fi

bash -n "$LIB" && pass 'bash -n shared lib' || fail 'bash -n shared lib'
bash -n "$STATE_LIB" && pass 'bash -n state lib' || fail 'bash -n state lib'

# ---------------------------------------------------------------- sandbox ----
SB="$TMP/sandbox"
mkdir -p "$SB/clients"
export SB_SERVER_CONFIG="$SB/sbconfig_server.json"
export SB_CLIENTS_DIR="$SB/clients"
export SB_LOCK_FILE="$SB/config.lock"
export SB_SING_BOX_BIN="$SB/mock-sing-box"
export SB_CM_STATE_DIR="$SB/state"
export SBOX_CM_TEST_SANDBOX=1

cat > "$SB/mock-sing-box" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
    check) exit 0 ;;
    generate)
        case "${2:-}" in
            uuid) printf '%s\n' "${MOCK_UUID:-11111111-2222-3333-4444-555555555555}" ;;
            rand) printf '%s\n' "${MOCK_PASSWORD:-aabbccddeeff00112233445566778899}" ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
MOCK
chmod +x "$SB/mock-sing-box"

# jq shim: records every argv so argv hygiene is a runtime assertion, not a grep.
JQ_LOG="$TMP/jq-argv.log"
: > "$JQ_LOG"
REAL_JQ="$(command -v jq)"
SHIM="$TMP/shim"
mkdir -p "$SHIM"
cat > "$SHIM/jq" <<SHIMEOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$JQ_LOG"
exec "$REAL_JQ" "\$@"
SHIMEOF
chmod +x "$SHIM/jq"
export PATH="$SHIM:$PATH"

warning(){ :; }
info(){ :; }
# shellcheck source=/dev/null
. "$LIB"
# shellcheck source=/dev/null
. "$STATE_LIB"

write_live() {
    cat > "$SB_SERVER_CONFIG" <<'JSON'
{"inbounds":[
 {"type":"vless","tag":"vless-in","users":[{"name":"legacy","uuid":"LEGACY-UUID","flow":"xtls-rprx-vision"}]},
 {"type":"hysteria2","tag":"hy2-in","users":[{"name":"legacy","password":"LEGACY-PASS"}]}
]}
JSON
}
write_live

# ---------------------------------------------------------------- digest ----
printf '\n== credential digest (byte-exact definition) ==\n'
d1="$(cm_cred_digest_of "UUID-X" "PASS-Y")"
d2="$(cm_cred_digest_of "UUID-X" "PASS-Y")"
assert_eq "$d1" "$d2" 'cm_cred_digest_of is deterministic'
want="$(printf '%s\n%s' "UUID-X" "PASS-Y" | sha256sum | awk '{print $1}')"
assert_eq "$want" "$d1" 'digest == SHA256(uuid + LF + password)'
assert_ne "$(cm_cred_digest_of "ab" "c")" "$(cm_cred_digest_of "a" "bc")" \
    'digest is not ambiguous across the separator'
assert_eq "$(cm_cred_digest_of "LEGACY-UUID" "LEGACY-PASS")" \
          "$(cm_old_cred_digest "$SB_SERVER_CONFIG" legacy)" \
    'cm_old_cred_digest uses the same canonical primitive'

# ------------------------------------------------------------- planned cred ----
printf '\n== planned credential -> candidate ==\n'
export MOCK_UUID="$SENTINEL_UUID" MOCK_PASSWORD="$SENTINEL_PASSWORD"
cm_plan_client_credential
assert_eq "$SENTINEL_UUID" "$CM_PLAN_UUID" 'planned uuid comes from the generator'
assert_eq "$SENTINEL_PASSWORD" "$CM_PLAN_PASSWORD" 'planned password comes from the generator'
assert_eq "$(cm_cred_digest_of "$SENTINEL_UUID" "$SENTINEL_PASSWORD")" \
          "$(cm_planned_cred_digest)" 'cm_planned_cred_digest uses the canonical primitive'

CAND="$TMP/cand.json"
: > "$JQ_LOG"
rm -f "$CAND"
if cm_render_planned_candidate "$SB_SERVER_CONFIG" "vmix-01" "$CAND"; then
    pass 'cm_render_planned_candidate succeeds'
else
    fail 'cm_render_planned_candidate failed'
fi

if grep -qF "$SENTINEL_UUID" "$JQ_LOG" || grep -qF "$SENTINEL_PASSWORD" "$JQ_LOG"; then
    fail 'jq argv contained credential material'
else
    pass 'jq argv carried no credential material'
fi

if jq -e --arg n "vmix-01" '
      ([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name==$n)|.uuid]|length)==1
      and ([.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name==$n)|.password]|length)==1
      and ([.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")]|length)==1
    ' "$CAND" >/dev/null 2>&1; then
    pass 'candidate adds the name to BOTH inbounds and keeps legacy'
else
    fail 'candidate shape wrong'
fi

cm_cred_forget
[ -z "${CM_PLAN_UUID:-}" ] && [ -z "${CM_PLAN_PASSWORD:-}" ] \
    && pass 'cm_cred_forget clears credential memory' \
    || fail 'cm_cred_forget left credential material behind'

# credential JSON is invalid -> fail closed, no candidate
printf '{"uuid":"","password":"x"}' > "$TMP/badcred.json"
if cm_add_candidate_planned "$SB_SERVER_CONFIG" "nope" "$TMP/bad-cand.json" \
        < "$TMP/badcred.json" 2>/dev/null; then
    fail 'cm_add_candidate_planned accepted an empty uuid'
else
    pass 'cm_add_candidate_planned rejects malformed credential input'
fi

# ---------------------------------------------------------------- delete ----
printf '\n== delete candidate ==\n'
DEL="$TMP/del.json"
cm_delete_candidate "$SB_SERVER_CONFIG" "legacy" "$DEL"
if jq -e '([.inbounds[]|select(.tag=="vless-in")|.users[]]|length)==0
          and ([.inbounds[]|select(.tag=="hy2-in")|.users[]]|length)==0' "$DEL" >/dev/null 2>&1; then
    pass 'cm_delete_candidate removes the name from both inbounds'
else
    fail 'cm_delete_candidate output wrong'
fi

# ------------------------------------------------------------ schema utils ----
printf '\n== schema helpers ==\n'
cm_idempotency_key_ok "0123456789abcdef" && pass 'valid key accepted' || fail 'valid key rejected'
cm_idempotency_key_ok "short" && fail 'short key accepted' || pass 'short key rejected'
cm_idempotency_key_ok "$(printf 'a%.0s' $(seq 1 129))" && fail 'overlong key accepted' || pass 'overlong key rejected'
cm_idempotency_key_ok "abcdefghijklmnop/../x" && fail 'path-ish key accepted' || pass 'illegal char key rejected'
cm_safe_id "0123456789abcdef" && pass 'safe id accepted' || fail 'safe id rejected'
cm_safe_id "../etc" && fail 'unsafe id accepted' || pass 'unsafe id rejected'

assert_eq "$(cm_request_digest "client.add" "vmix-01")" "$(cm_request_digest "client.add" "vmix-01")" \
    'request digest is stable'
assert_ne "$(cm_request_digest "client.add" "vmix-01")" "$(cm_request_digest "client.delete" "vmix-01")" \
    'request digest binds the op'

assert_eq "$(cm_key_fp "0123456789abcdef")" \
          "$(printf '%s' "0123456789abcdef" | sha256sum | awk '{print $1}' | cut -c1-8)" \
    'cm_key_fp is sha256(key) prefix 8'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_SHARED_LIB=FAIL\n'; exit 1; }
printf 'E3_M1_SHARED_LIB=PASS\n'
