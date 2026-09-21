#!/usr/bin/env bash
# E3 M4 -- canonical Mihomo/Clash YAML renderer contract.
#
# lib/client-management.sh::cm_render_client_mihomo_yaml is the SINGLE source
# of the client config: install.sh's generate_client_configuration, the
# shared-account display wrapper AND the privileged client.export op all
# render through it, so CLI files and Web downloads are byte-identical BY
# CONSTRUCTION. This suite pins that construction (static wiring: exactly one
# template in the repo, builtin-printf-only emission, no external heredoc)
# and the renderer's own contract (pure, deterministic, fail-closed on
# per-client AND GLOBAL inconsistency, credential pass-through, hopping
# variant, legacy exportability).
#
# Sandbox only: temporary files, no root, no network, no sing-box.
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

printf '===== E3 M4 RENDERER =====\n'

FIXTURE_UUID="11111111-2222-3333-4444-555555555555"
FIXTURE_PASSWORD="super-secret-hy2-fixture"

# ------------------------------------------------------------ static wiring --
printf '\n== single source, real reuse ==\n'
lc="$(grep -cE '^cm_render_client_mihomo_yaml\(\)' "$LIB" || true)"
ic="$(grep -cE '^cm_render_client_mihomo_yaml\(\)' "$INSTALL" || true)"
assert_eq 0 "$ic" 'install.sh does NOT define a second renderer'
calls="$(grep -cE 'cm_render_client_mihomo_yaml "\$name" "\$cfg"' "$INSTALL" || true)"
deleg="$(grep -cE 'cm_render_client_mihomo_yaml "\$RESERVED_CLIENT_NAME"' "$INSTALL" || true)"
if [ "$lc" = "1" ] && [ "$calls" -ge 1 ] && [ "$deleg" -ge 1 ]; then
    pass 'lib defines the renderer once; install.sh delegates BOTH paths to it'
else
    fail "renderer wiring (lib=$lc generate-calls=$calls display-calls=$deleg)"
fi
# R2: the shared-account display path used to carry a SECOND full template.
# It must be GONE now -- ANY copy of the template body in install.sh is a
# contract FAILURE, not an allowed case.
tmpl_uses="$(grep -cE 'mixed-port: 7897' "$INSTALL" || true)"
assert_eq 0 "$tmpl_uses" 'install.sh carries NO copy of the YAML template (any copy = FAIL)'

# R3: the credential-bearing renderer must emit through the shell BUILTIN
# printf only. An external `cat`/heredoc can have its stdin backed by a temp
# file; credential bytes must never touch one.
rb="$(awk '/^cm_render_client_mihomo_yaml\(\)/{f=1} f{print} f&&/^\}/{exit}' "$LIB")"
[ -n "$rb" ] && pass 'extracted the renderer function body' || fail 'could not extract renderer body'
if printf '%s\n' "$rb" | grep -qE '<<[[:space:]]*["'"'"']?[A-Za-z_]'; then
    fail 'R3: the renderer still contains a heredoc'
else
    pass 'R3: the renderer contains no heredoc'
fi
if printf '%s\n' "$rb" | grep -qw cat; then
    fail 'R3: the renderer still shells out to cat'
else
    pass 'R3: the renderer shells out to no cat'
fi
printf '%s\n' "$rb" | grep -q 'printf' \
    && pass 'R3: emission goes through builtin printf' \
    || fail 'R3: renderer does not emit via printf'
bash -n "$LIB" && pass 'bash -n shared lib' || fail 'bash -n shared lib'

# ------------------------------------------------------------------ sandbox --
SB="$TMP/sandbox"
mkdir -p "$SB/clients"
export SB_SERVER_CONFIG="$SB/sbconfig_server.json"
export SB_STATE_FILE="$SB/config"
export SB_CLIENTS_DIR="$SB/clients"
export SB_LOCK_FILE="$SB/config.lock"
export SBOX_CM_TEST_SANDBOX=1

cat > "$SB_STATE_FILE" <<'STATE'
SERVER_IP='203.0.113.7'
PUBLIC_KEY='PUBKEYfixture000000000000000000000000000000000000'
HY_SERVER_NAME='www.example.com'
HY_HOPPING=FALSE
STATE

write_live() { # two clients + the shared legacy account, realistic shape
    cat > "$SB_SERVER_CONFIG" <<JSON
{"inbounds":[
 {"type":"vless","tag":"vless-in","listen_port":8443,
  "users":[
    {"name":"legacy","uuid":"$FIXTURE_UUID","flow":"xtls-rprx-vision"},
    {"name":"vmix-01","uuid":"CLIENT-UUID-1","flow":"xtls-rprx-vision"}],
  "tls":{"enabled":true,"server_name":"www.example.com",
         "reality":{"enabled":true,"handshake":{"server":"www.example.com","server_port":443},
                    "private_key":"PRIV-XYZ",
                    "short_id":["abcd1234"]}}},
 {"type":"hysteria2","tag":"hy2-in","listen_port":8444,
  "users":[
    {"name":"legacy","password":"$FIXTURE_PASSWORD"},
    {"name":"vmix-01","password":"CLIENT-PASS-1"}],
  "tls":{"enabled":true,"alpn":["h3"]}}
]}
JSON
}
write_live

warning(){ :; }
info(){ :; }
# shellcheck source=/dev/null
. "$LIB"
# shellcheck source=/dev/null
. "$STATE_LIB"

render_to(){ # <out-file> <name> -> renderer exit code
    cm_render_client_mihomo_yaml "$2" > "$1" 2>"$TMP/err"
}

# ------------------------------------------------------------- determinism --
printf '\n== pure, deterministic, credential pass-through ==\n'
A="$TMP/a.yaml"; B="$TMP/b.yaml"
if render_to "$A" vmix-01; then pass 'render vmix-01 succeeds'; else fail 'render vmix-01 failed'; fi
render_to "$B" vmix-01
cmp -s "$A" "$B" && pass 'two renders are byte-identical (deterministic)' \
    || fail 'render is not deterministic'
assert_eq 0 "$(wc -c < "$TMP/err" | tr -d ' ')" 'the renderer wrote nothing to stderr'
if head -n 1 "$A" | grep -qx 'mixed-port: 7897'; then
    pass 'output starts at the exact first template byte'
else
    fail 'output does not start at byte 0 of the template'
fi
LAST2="$(tail -c 2 "$A" | od -An -tu1 | tr -d ' \n')"
assert_eq "1010" "$LAST2" 'the template trailing blank line survives (ends with LF LF)'
for want in \
    'server: 203.0.113.7' \
    'port: 8443' \
    'uuid: CLIENT-UUID-1' \
    'short-id: abcd1234' \
    'public-key: PUBKEYfixture000000000000000000000000000000000000' \
    'servername: www.example.com' \
    'password: CLIENT-PASS-1' \
    'port: 8444' \
    'sni: www.example.com'; do
    grep -qF -- "$want" "$A" && pass "render contains [$want]" \
        || fail "render is missing [$want]"
done
grep -qF 'PRIV-XYZ' "$A" && fail 'the server private key leaked into the client config' \
    || pass 'the server private key is never rendered'

# two distinct clients resolve their OWN credentials
C="$TMP/c.yaml"
render_to "$C" legacy
grep -qF "uuid: $FIXTURE_UUID" "$C" && grep -qF "password: $FIXTURE_PASSWORD" "$C" \
    && pass 'legacy renders with its own credentials' \
    || fail 'legacy render carries the wrong credentials'
cmp -s "$A" "$C" && fail 'two clients rendered identical bytes' \
    || pass 'per-client credentials are resolved per name'

# ------------------------------------------------------------------ hopping --
printf '\n== port-hopping variant ==\n'
cat > "$SB_STATE_FILE" <<'STATE'
SERVER_IP='203.0.113.7'
PUBLIC_KEY='PUBKEYfixture000000000000000000000000000000000000'
HY_SERVER_NAME='www.example.com'
HY_HOPPING=TRUE
HY_HOPPING_START=40000
HY_HOPPING_END=40100
STATE
D="$TMP/d.yaml"
if render_to "$D" vmix-01; then pass 'hopping render succeeds'; else fail 'hopping render failed'; fi
if grep -qF 'ports: 40000-40100' "$D" && grep -qF 'hop-interval: 30' "$D"; then
    pass 'hopping variant emits ports + hop-interval'
else
    fail 'hopping fields missing'
fi
grep -qF '    port: 8444' "$D" && pass 'hopping keeps the base hy2 port line' \
    || fail 'hopping lost the base port'
# non-hopping output must NOT contain the hopping fields
grep -qF 'hop-interval' "$A" && fail 'non-hopping render contains hopping fields' \
    || pass 'non-hopping render is free of hopping fields'

# ----------------------------------------------------------------- fail-closed
printf '\n== fail-closed inputs, zero stdout ==\n'
EMPTY="$TMP/empty.out"
bad_case(){ # <label> <name>
    : > "$EMPTY"
    if cm_render_client_mihomo_yaml "$2" > "$EMPTY" 2>/dev/null; then
        fail "renderer accepted $1"
    elif [ -s "$EMPTY" ]; then
        fail "renderer printed bytes while refusing $1"
    else
        pass "renderer refuses $1 with zero stdout"
    fi
}
bad_case 'an invalid name' '../etc/passwd'
bad_case 'an unknown client' 'ghost-99'
# missing config file
if SB_SERVER_CONFIG="$TMP/nope.json" cm_render_client_mihomo_yaml vmix-01 >/dev/null 2>&1; then
    fail 'renderer accepted a missing config'
else
    pass 'renderer refuses a missing config'
fi
# corrupt config
printf '{broken' > "$TMP/corrupt.json"
if SB_SERVER_CONFIG="$TMP/corrupt.json" cm_render_client_mihomo_yaml vmix-01 >/dev/null 2>&1; then
    fail 'renderer accepted a corrupt config'
else
    pass 'renderer refuses a corrupt config'
fi
# emptied credentials (uuid present as "")
jq '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="vmix-01")|.uuid) = ""' \
    "$SB_SERVER_CONFIG" > "$TMP/nocred.json"
if SB_SERVER_CONFIG="$TMP/nocred.json" cm_render_client_mihomo_yaml vmix-01 >/dev/null 2>&1; then
    fail 'renderer shipped a config with incomplete credentials'
else
    pass 'renderer refuses incomplete credentials'
fi
# restore the non-hopping state + config and confirm the refusal cases never
# damaged the bytes the first section pinned
cat > "$SB_STATE_FILE" <<'STATE'
SERVER_IP='203.0.113.7'
PUBLIC_KEY='PUBKEYfixture000000000000000000000000000000000000'
HY_SERVER_NAME='www.example.com'
HY_HOPPING=FALSE
STATE
write_live
render_to "$B" vmix-01
cmp -s "$A" "$B" && pass 'restored state renders the exact bytes pinned by the first section' \
    || fail 'state drifted across refusal cases'

# ------------------------------------------------- R4: global fail-closed ----
# The renderer must refuse when the SHARED source of truth is inconsistent,
# even though the REQUESTED client is perfectly valid: mismatched name sets,
# duplicate names/credentials, empty uuid/password on ANOTHER client, or an
# invalid flow anywhere all mean zero YAML, zero bytes, rc only.
printf '\n== R4: global inconsistency refuses a valid requested client ==\n'
glob_case(){ # <label> <jq-filter>  (vmix-01 itself stays valid in every case)
    write_live
    if ! jq "$2" "$SB_SERVER_CONFIG" > "$TMP/broken.json" 2>/dev/null; then
        fail "R4 fixture build failed: $1"; return
    fi
    cp "$TMP/broken.json" "$SB_SERVER_CONFIG"
    : > "$EMPTY"
    if cm_render_client_mihomo_yaml vmix-01 > "$EMPTY" 2>/dev/null; then
        fail "R4 shipped YAML despite global inconsistency ($1)"
    elif [ -s "$EMPTY" ]; then
        fail "R4 printed bytes while refusing ($1)"
    else
        pass "R4 refuses with zero stdout ($1)"
    fi
}
glob_case 'another client lost its uuid' \
    '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")|.uuid) = ""'
glob_case 'another client duplicates the requested uuid' \
    '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")|.uuid) = "CLIENT-UUID-1"'
glob_case 'another client carries an invalid flow' \
    '(.inbounds[]|select(.tag=="vless-in")|.users[]|select(.name=="legacy")|.flow) = "none"'
glob_case 'Reality/HY2 name sets diverge' \
    '(.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="legacy")|.name) = "legacy2"'
glob_case 'HY2 gains a duplicate-name user' \
    '(.inbounds[]|select(.tag=="hy2-in")|.users) += [{"name":"vmix-01","password":"OTHER-PASS-9"}]'
glob_case 'HY2 duplicates the requested password' \
    '(.inbounds[]|select(.tag=="hy2-in")|.users) += [{"name":"ghost-a","password":"CLIENT-PASS-1"}]'
glob_case 'another client lost its password' \
    '(.inbounds[]|select(.tag=="hy2-in")|.users[]|select(.name=="legacy")|.password) = ""'
write_live
render_to "$B" vmix-01
cmp -s "$A" "$B" && pass 'consistent config renders the pinned bytes again after the R4 cases' \
    || fail 'R4 refusal cases damaged the pinned bytes'

# -------------------------------------------------------------------- purity --
printf '\n== purity: the renderer touches no files ==\n'
touch "$TMP/watched"
BEFORE="$(sha256sum "$TMP/watched" | awk '{print $1}')"
LIST_BEFORE="$(ls -1 "$TMP" | sort | sha256sum | awk '{print $1}')"
SB_CLIENTS_DIR="$TMP/never-created" cm_render_client_mihomo_yaml vmix-01 >/dev/null 2>&1
[ ! -e "$TMP/never-created" ] && pass 'rendering created no clients subtree' \
    || fail 'the renderer wrote into the clients dir'
AFTER="$(sha256sum "$TMP/watched" | awk '{print $1}')"
assert_eq "$BEFORE" "$AFTER" 'the renderer modified no watched file'
LIST_AFTER="$(ls -1 "$TMP" | sort | sha256sum | awk '{print $1}')"
assert_eq "$LIST_BEFORE" "$LIST_AFTER" 'the renderer left no temp files behind'

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M4_RENDERER=FAIL\n'; exit 1; }
printf 'E3_M4_RENDERER=PASS\n'
