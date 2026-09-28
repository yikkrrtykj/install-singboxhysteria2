#!/usr/bin/env bash
# Issue #48 PR-48A -- offline multi-VPS Mihomo profile merge contract.
#
# Scope: tools/mihomo-multi-vps-merge.py, an operator-local, hermetic tool that
# merges two canonical `client.export` Mihomo profiles (VPS A + VPS B) into one
# four-node profile. It is a CANONICAL PROFILE PARSER, not a general YAML
# merger: anything that is not the current
# lib/client-management.sh :: cm_render_client_mihomo_yaml output must fail
# closed with a fixed error code.
#
# Discriminators T1..T34 of the PR-48A spec are exercised here, plus the static
# gates (stdlib-only, no network / subprocess module, the canonical shape the
# parser pins is still the shape the renderer emits).
#
# Sandbox only: temporary files, no root, no network, no VPS, no production
# config. Every credential below is an obvious test sentinel, never a real one.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/mihomo-multi-vps-merge.py"
RENDER_LIB="$ROOT/lib/client-management.sh"
TMP="$(mktemp -d)"
LOGS="$TMP/logs"
mkdir -p "$LOGS"
trap 'rm -rf -- "$TMP"' EXIT

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
assert_diff() { if diff -u "$1" "$2" >/dev/null 2>&1; then pass "$3"; else
    fail "$3 (bytes differ)"; diff -u "$1" "$2" | head -20; fi; }

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" --version >/dev/null 2>&1 || { printf '  FAIL no python interpreter\n'; exit 1; }

POSIX_HOST=1
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) POSIX_HOST=0 ;;
esac

sha256() { "$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
count_files() { find "$@" | wc -l | tr -d ' '; }

# --------------------------------------------------------------- fixtures ---
SERVER_A="203.0.113.7"
SERVER_B="198.51.100.9"
UUID_A="a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5"
UUID_B="f6f6f6f6-7777-8888-9999-aaaaaaaaaaaa"
PASSPHRASE_A="aaaaaaaaaaaaaaaa1111111111111111"
PASSPHRASE_B="bbbbbbbbbbbbbbbb2222222222222222"
PUBKEY_A="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBKEY_B="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
SHORTID_A="0123456789abcdef"
SHORTID_B="fedcba9876543210"
NAME="event-vmix01"

mk_export() { # <path> <server> <uuid> <password> <pubkey> <shortid> <hopping>
    local out=$1 server=$2 uuid=$3 password=$4 pubkey=$5 shortid=$6 hop=$7
    local hyports="    port: 8444"
    if [ "$hop" = "TRUE" ]; then
        hyports="    port: 8444
    ports: 40000-40100
    hop-interval: 30"
    fi
    cat > "$out" <<EOF
mixed-port: 7897
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
unified-delay: true
ipv6: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: "0.0.0.0:53"
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

tun:
  enable: true
  stack: mixed
  device: Mihomo
  mtu: 1420
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53

proxies:
  - name: Reality
    type: vless
    server: $server
    port: 8443
    uuid: $uuid
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: $pubkey
      short-id: $shortid

  - name: Hysteria2
    type: hysteria2
    server: $server
$hyports
    password: $password
    up: "300 Mbps"
    down: "300 Mbps"
    sni: www.example.com
    skip-cert-verify: true
    alpn:
      - h3


proxy-groups:
  - name: 节点选择
    type: select
    default-selected: 自动选择
    proxies:
      - Reality
      - Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: fallback
    proxies:
      - Reality
      - Hysteria2
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"


rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择

EOF
}

# The downloaded file name is the only carrier of the logical client name, so
# the fixtures are named exactly the way the Web export names them.
mkdir -p "$TMP/vpsA" "$TMP/vpsB"
A="$TMP/vpsA/$NAME-mihomo.yaml"
B="$TMP/vpsB/$NAME-mihomo.yaml"
mk_export "$A" "$SERVER_A" "$UUID_A" "$PASSPHRASE_A" "$PUBKEY_A" "$SHORTID_A" FALSE
mk_export "$B" "$SERVER_B" "$UUID_B" "$PASSPHRASE_B" "$PUBKEY_B" "$SHORTID_B" TRUE

MUTATE_SCRIPT='
import re
import sys
src, dst, code = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, encoding="utf-8") as fh:
    text = fh.read()
exec(code)
with open(dst, "w", encoding="utf-8", newline="") as fh:
    fh.write(text)
'
mutate() { # <src> <dst> <python statements rewriting `text` (re is available)>
    "$PY" -c "$MUTATE_SCRIPT" "$1" "$2" "$3"
}

# ------------------------------------------------------------------ runner ---
RUNS=0
expect_mode=""
run_merge() { # <args...> ; sets RC / OUT / ERR from the captured log files
    RUNS=$((RUNS + 1))
    local log="$LOGS/run$RUNS"
    "$PY" "$TOOL" "$@" >"$log.out" 2>"$log.err"
    RC=$?
    # Windows redirects print() as CRLF; the harness normalises, the product
    # contract is the line content.
    OUT="$(tr -d '\r' < "$log.out")"
    ERR="$(tr -d '\r' < "$log.err")"
}

expect_ok() { # <label> <args...>
    local label=$1; shift
    run_merge "$@"
    if [ "$RC" -eq 0 ] && [ "$OUT" = "merge: OK
mode: $expect_mode
output: written" ] && [ -z "$ERR" ]; then
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR])"
    fi
}

expect_code() { # <want-code> <label> <args...>
    local want=$1 label=$2; shift 2
    run_merge "$@"
    if [ "$RC" -ne 0 ] && [ "$ERR" = "merge: FAIL $want" ] && [ -z "$OUT" ]; then
        pass "$label -> $want"
    else
        fail "$label (rc=$RC want=[$want] stderr=[$ERR] stdout=[$OUT])"
    fi
}

expect_rc() { # <want-rc> <label> <args...>
    local want=$1 label=$2; shift 2
    run_merge "$@"
    assert_eq "$want" "$RC" "$label"
}

proxy_names() { awk '/^proxies:/{f=1;next} /^proxy-groups:/{f=0}
    f && /^  - name: /{sub(/^  - name: /,"");print}' "$1"; }
selector_members() { awk '/^  - name: 节点选择$/{f=1;next} /^  - name: /{f=0}
    f && /^      - /{sub(/^      - /,"");print}' "$1"; }
auto_members() { awk '/^  - name: 自动选择$/{f=1;next} /^    url: /{f=0}
    f && /^      - /{sub(/^      - /,"");print}' "$1"; }
block_of() { awk -v n="  - name: $2" '$0==n{f=1} f && $0==""{exit} f' "$1"; }
prelude_of() { sed -n '1,/^proxies:$/p' "$1"; }
rules_of() { awk '/^rules:/{f=1} f && NF' "$1"; }

printf '===== MULTI-VPS MIHOMO PROFILE MERGE (issue #48 PR-48A) =====\n'

# ------------------------------------------------------------- static gates --
section 'static gates'
"$PY" -m py_compile "$TOOL" && pass 'py_compile tools/mihomo-multi-vps-merge.py' \
    || fail 'py_compile failed'
bash -n "$0" && pass 'bash -n this suite' || fail 'bash -n this suite'

imports="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(sorted(set(re.findall(
    r"^(?:import|from)\s+([a-zA-Z_][\w]*)", text, re.M)))))
PY
)"
bad=""
for module in $imports; do
    case "$module" in
        __future__|argparse|ipaddress|os|re|stat|sys|tempfile) ;;
        *) bad="$bad $module" ;;
    esac
done
[ -z "$bad" ] && pass "stdlib allowlist holds (imports: $imports)" \
    || fail "non-allowlisted import(s):$bad"
for module in socket ssl urllib http ftplib smtplib subprocess sched selectors \
              asyncio threading multiprocessing sqlite3 yaml json base64 hashlib; do
    case " $imports " in
        *" $module "*) fail "the tool imports $module (hermetic mandate)" ;;
    esac
done
pass 'no network, subprocess, scheduling or third-party YAML module imported'
grep -qiE 'pyyaml|import yaml|ruamel' "$TOOL" \
    && fail 'a YAML library is referenced' || pass 'no YAML library dependency'

# The CLI surface is fixed: paths plus the logical name only. A --uuid or
# --password option would put a credential into argv. It is read from the
# SOURCE rather than from --help, because this tool deliberately has no help
# output: argparse builds help and error text out of argv, and argv may sit
# next to credential material (the refusal is gated in the R1 usage section).
cli_flags="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(re.findall(r'add_argument\("(--[a-z-]+)"', text)))
PY
)"
for forbidden in uuid password server pubkey public-key short-id secret token \
                 url host force; do
    printf '%s\n' "$cli_flags" | grep -qiE -- "--$forbidden" \
        && fail "the CLI exposes a --$forbidden option" || true
done
pass 'no credential-bearing or --force CLI option exists'
assert_eq '--name --primary --backup --output' "$cli_flags" \
    'CLI flags are exactly --name / --primary / --backup / --output'

# The parser pins the renderer's canonical shape. If the template ever moves,
# that is real drift: this gate must turn red instead of every merge silently
# failing closed.
for marker in 'expected-status: "204"' '    interval: 60' '    timeout: 5000' \
              '    lazy: false' 'default-selected: 自动选择' \
              'flow: xtls-rprx-vision' 'skip-cert-verify: true' \
              '    hop-interval: 30' 'client-fingerprint: chrome' \
              '    ports: ' '      - h3' '  - MATCH,节点选择'; do
    grep -qF -- "$marker" "$RENDER_LIB" \
        && pass "renderer template still carries [$marker]" \
        || fail "renderer template lost [$marker]: the canonical contract must be updated"
done
grep -qF 'type: url-test' "$RENDER_LIB" \
    && fail 'the renderer emits a url-test group again' \
    || pass 'the renderer emits no url-test group'

# ------------------------------------------------------------ T1 / T29 -----
section 'T1 single-VPS passthrough'
expect_mode=single
OUT1="$TMP/single-out.yaml"
expect_ok 'T1 single mode succeeds' --name "$NAME" --primary "$A" --output "$OUT1"
assert_diff "$A" "$OUT1" 'T1 single-mode output is byte-for-byte the primary export'
OUT1H="$TMP/single-hop-out.yaml"
expect_ok 'T1 single mode on a hopping export' --name "$NAME" --primary "$B" --output "$OUT1H"
assert_diff "$B" "$OUT1H" 'T1 single-mode output byte-for-byte identical (hopping variant)'
if [ "$POSIX_HOST" = "1" ]; then
    assert_eq 600 "$(stat -c '%a' "$OUT1")" 'T29 single-mode output mode is 0600'
else
    skip 'T29 single output mode assertion (no POSIX permission bits on this host)'
fi

# ----------------------------------------------------------- T2..T8 dual ----
section 'T2..T8 dual merge'
expect_mode=dual
M="$TMP/dual-out.yaml"
expect_ok 'T2 dual merge succeeds' --name "$NAME" --primary "$A" --backup "$B" --output "$M"
assert_eq 'Reality
Hysteria2
Backup-Reality
Backup-Hysteria2' "$(proxy_names "$M")" \
    'T2 exactly four proxies: primary pair first, backup pair last'
assert_eq 1 "$(grep -cx '  - name: Reality' "$M")" 'T3 primary Reality name unchanged'
assert_eq 1 "$(grep -cx '  - name: Hysteria2' "$M")" 'T3 primary Hysteria2 name unchanged'
block_of "$M" Reality > "$TMP/g1"; block_of "$A" Reality > "$TMP/e1"
assert_diff "$TMP/e1" "$TMP/g1" 'T3 primary Reality block is byte-identical in the merge'
block_of "$M" Hysteria2 > "$TMP/g2"; block_of "$A" Hysteria2 > "$TMP/e2"
assert_diff "$TMP/e2" "$TMP/g2" 'T3 primary Hysteria2 block is byte-identical in the merge'
{ printf '  - name: Backup-Reality\n'; block_of "$B" Reality | tail -n +2; } > "$TMP/e3"
block_of "$M" Backup-Reality > "$TMP/g3"
assert_diff "$TMP/e3" "$TMP/g3" \
    'T4 backup Reality block copied verbatim except for its name'
{ printf '  - name: Backup-Hysteria2\n'; block_of "$B" Hysteria2 | tail -n +2; } > "$TMP/e4"
block_of "$M" Backup-Hysteria2 > "$TMP/g4"
assert_diff "$TMP/e4" "$TMP/g4" \
    'T4 backup Hysteria2 block copied verbatim except for its name'
assert_eq 2 "$(grep -c "server: $SERVER_A" "$M")" 'T4 primary endpoint kept in both tunnels'
assert_eq 2 "$(grep -c "server: $SERVER_B" "$M")" 'T4 backup endpoint kept in both tunnels'
assert_eq 1 "$(grep -c "uuid: $UUID_A" "$M")" 'T4 primary Reality UUID kept once, untouched'
assert_eq 1 "$(grep -c "uuid: $UUID_B" "$M")" 'T4 backup Reality UUID kept once, untouched'
assert_eq 1 "$(grep -c "password: $PASSPHRASE_A" "$M")" 'T4 primary HY2 password untouched'
assert_eq 1 "$(grep -c "password: $PASSPHRASE_B" "$M")" 'T4 backup HY2 password untouched'
assert_eq 1 "$(grep -c "public-key: $PUBKEY_B" "$M")" 'T4 backup Reality public-key untouched'
assert_eq 1 "$(grep -c "short-id: $SHORTID_B" "$M")" 'T4 backup short-id untouched'

assert_eq 'Reality
Hysteria2
Backup-Reality
Backup-Hysteria2' "$(auto_members "$M")" \
    'T5 fallback member order is Reality / Hysteria2 / Backup-Reality / Backup-Hysteria2'
assert_eq 'Reality
Hysteria2
Backup-Reality
Backup-Hysteria2
自动选择
DIRECT' "$(selector_members "$M")" \
    'T6 Selector order is the four nodes, then 自动选择, then DIRECT'
assert_eq '自动选择' \
    "$(awk '/^    default-selected: /{sub(/^    default-selected: /,"");print;exit}' "$M")" \
    'T7 default-selected is still 自动选择'
assert_eq '    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"' \
    "$(awk '/^    (url|interval|timeout|lazy|expected-status): /{print}' "$M")" \
    'T8 the accepted #42 probe policy is carried over byte-for-byte'
assert_eq 1 "$(grep -cx '    interval: 60' "$M")" 'T8 interval stays 60 and appears once'
assert_eq 0 "$(grep -c '^    interval: 30$' "$M")" 'T8 no 30s probe interval introduced'
assert_eq 1 "$(grep -cx '    type: fallback' "$M")" 'T8 exactly one automatic group, still fallback'
assert_eq 1 "$(grep -cx '    type: select' "$M")" 'T8 exactly one manual Selector group'

# ------------------------------------------------------------ T9..T12 -------
section 'T9..T12 port-hopping matrix'
hop_case() { # <label> <hopA> <hopB>
    local label=$1 hopa=$2 hopb=$3
    local dir="$TMP/$label" fa fb out="$TMP/$label-out.yaml" want=0
    mkdir -p "$dir/A" "$dir/B"
    fa="$dir/A/$NAME-mihomo.yaml"; fb="$dir/B/$NAME-mihomo.yaml"
    mk_export "$fa" "$SERVER_A" "$UUID_A" "$PASSPHRASE_A" "$PUBKEY_A" "$SHORTID_A" "$hopa"
    mk_export "$fb" "$SERVER_B" "$UUID_B" "$PASSPHRASE_B" "$PUBKEY_B" "$SHORTID_B" "$hopb"
    [ "$hopa" = TRUE ] && want=$((want + 1))
    [ "$hopb" = TRUE ] && want=$((want + 1))
    expect_mode=dual
    expect_ok "$label merge (A hopping=$hopa B hopping=$hopb)" \
        --name "$NAME" --primary "$fa" --backup "$fb" --output "$out"
    assert_eq "$want" "$(grep -cx '    ports: 40000-40100' "$out")" \
        "$label keeps exactly the sources' hopping ports lines"
    assert_eq "$want" "$(grep -cx '    hop-interval: 30' "$out")" \
        "$label keeps exactly the sources' hop-interval lines"
}
hop_case T9 FALSE FALSE
hop_case T10 TRUE FALSE
hop_case T11 FALSE TRUE
hop_case T12 TRUE TRUE

# ----------------------------------------------------- T13..T17 merge gates --
section 'T13..T17 source / credential / provenance gates'
mkdir -p "$TMP/same" "$TMP/split" "$TMP/reuseuuid" "$TMP/reusepass" "$TMP/wrongp" \
    "$TMP/wrongb" "$TMP/wrongsuffix" "$TMP/bad" "$TMP/badb"
expect_mode=dual
SAME_SERVER="$TMP/same/$NAME-mihomo.yaml"
mutate "$B" "$SAME_SERVER" "text = text.replace('$SERVER_B', '$SERVER_A')"
expect_code E_SOURCE_COLLISION 'T13 both exports carry the same VPS endpoint' \
    --name "$NAME" --primary "$A" --backup "$SAME_SERVER" --output "$TMP/o13.yaml"

SPLIT="$TMP/split/$NAME-mihomo.yaml"
mutate "$A" "$SPLIT" "text = text.replace('    server: $SERVER_A\n', '    server: 192.0.2.66\n', 1)"
expect_code E_SOURCE_COLLISION 'T13b an export whose two tunnels name different servers' \
    --name "$NAME" --primary "$SPLIT" --backup "$B" --output "$TMP/o13b.yaml"

REUSED_UUID="$TMP/reuseuuid/$NAME-mihomo.yaml"
mutate "$B" "$REUSED_UUID" "text = text.replace('$UUID_B', '$UUID_A')"
expect_code E_CREDENTIAL_REUSE 'T14 reused Reality UUID' \
    --name "$NAME" --primary "$A" --backup "$REUSED_UUID" --output "$TMP/o14.yaml"

REUSED_PASS="$TMP/reusepass/$NAME-mihomo.yaml"
mutate "$B" "$REUSED_PASS" "text = text.replace('$PASSPHRASE_B', '$PASSPHRASE_A')"
expect_code E_CREDENTIAL_REUSE 'T15 reused HY2 password' \
    --name "$NAME" --primary "$A" --backup "$REUSED_PASS" --output "$TMP/o15.yaml"

expect_code E_SOURCE_COLLISION 'T15b the same export passed as A and B (one endpoint first gate)' \
    --name "$NAME" --primary "$A" --backup "$A" --output "$TMP/o15b.yaml"
SHARED_UUID_ONLY="$TMP/reuseuuid2/$NAME-mihomo.yaml"
mkdir -p "$TMP/reuseuuid2"
mutate "$B" "$SHARED_UUID_ONLY" "text = text.replace('$UUID_B', '$UUID_A')"
expect_code E_CREDENTIAL_REUSE 'T15c distinct endpoints but one shared Reality UUID' \
    --name "$NAME" --primary "$A" --backup "$SHARED_UUID_ONLY" --output "$TMP/o15c.yaml"

WRONG_PRIMARY="$TMP/wrongp/other-client-mihomo.yaml"
cp "$A" "$WRONG_PRIMARY"
expect_code E_NAME_MISMATCH 'T16 primary download name does not carry the logical name' \
    --name "$NAME" --primary "$WRONG_PRIMARY" --output "$TMP/o16.yaml"
cp "$A" "$TMP/wrongsuffix/$NAME-mihomo.yml"
expect_code E_NAME_MISMATCH 'T16b only the exact <name>-mihomo.yaml suffix is canonical' \
    --name "$NAME" --primary "$TMP/wrongsuffix/$NAME-mihomo.yml" --output "$TMP/o16b.yaml"

WRONG_BACKUP="$TMP/wrongb/other-client-mihomo.yaml"
cp "$B" "$WRONG_BACKUP"
expect_code E_NAME_MISMATCH 'T17 backup download name does not carry the logical name' \
    --name "$NAME" --primary "$A" --backup "$WRONG_BACKUP" --output "$TMP/o17.yaml"
# The provenance guard is a mix-up guard, never an identity proof: a correctly
# named file is still validated for canonical shape and independent credentials.
expect_code E_CREDENTIAL_REUSE 'T17b correct names but shared tenant credentials' \
    --name "$NAME" --primary "$A" --backup "$REUSED_PASS" --output "$TMP/o17b.yaml"
expect_mode=single
expect_code E_NAME_MISMATCH 'T17c single mode enforces the name too' \
    --name "$NAME" --primary "$WRONG_PRIMARY" --output "$TMP/o17c.yaml"

# ----------------------------------------------------- T18..T27 canonical ----
section 'T18..T27 canonical validation fails closed'
BADP="$TMP/bad/$NAME-mihomo.yaml"
BADB="$TMP/badb/$NAME-mihomo.yaml"
neg_primary() { # <label> <mutation>
    mutate "$A" "$BADP" "$2"
    expect_code E_PRIMARY_NOT_CANONICAL "$1" \
        --name "$NAME" --primary "$BADP" --output "$TMP/neg-out.yaml"
}
neg_backup() { # <label> <mutation>
    mutate "$B" "$BADB" "$2"
    expect_code E_BACKUP_NOT_CANONICAL "$1" \
        --name "$NAME" --primary "$A" --backup "$BADB" --output "$TMP/neg-out.yaml"
}
neg_primary 'T18 missing Reality proxy' \
    "text = text[:text.index('  - name: Reality')] + text[text.index('  - name: Hysteria2'):]"
neg_primary 'T19 missing Hysteria2 proxy' \
    "text = text[:text.index('  - name: Hysteria2')] + text[text.index('proxy-groups:'):]"
neg_primary 'T20 extra proxy' \
    "text = text.replace('      - h3\n', '      - h3\n\n  - name: Extra\n    type: ss\n    server: 192.0.2.5\n    port: 8388\n    password: xxxxxxxx\n', 1)"
neg_primary 'T21 wrong group type (automatic group is no longer fallback)' \
    "text = text.replace('    type: fallback', '    type: select', 1)"
neg_primary 'T22 old url-test template' \
    "text = text.replace('    type: fallback\n    proxies:\n      - Reality\n      - Hysteria2\n    url: \"https://www.gstatic.com/generate_204\"\n    interval: 60\n    timeout: 5000\n    lazy: false\n    expected-status: \"204\"', '    type: url-test\n    proxies:\n      - Reality\n      - Hysteria2\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    lazy: true')"
neg_primary 'T23 duplicate proxy name' \
    "text = text.replace('  - name: Hysteria2', '  - name: Reality', 1)"
neg_primary 'T23b duplicate field inside a proxy' \
    "text = text.replace('    uuid: $UUID_A\n', '    uuid: $UUID_A\n    uuid: $UUID_A\n', 1)"
neg_primary 'T23c duplicate top-level section' \
    "text = text + 'proxies:\n'"
neg_primary 'extra proxy field' \
    "text = text.replace('    udp: true', '    udp: true\n    tfo: true', 1)"
neg_primary 'extra top-level key' \
    "text = text.replace('proxies:\n', 'external-controller: 127.0.0.1:9090\nproxies:\n', 1)"
neg_primary 'unknown top-level key name' \
    "text = text.replace('rules:', 'rules2:', 1)"
neg_primary 'YAML anchor in a value' \
    "text = text.replace('    uuid: $UUID_A', '    uuid: &anchor $UUID_A', 1)"
neg_primary 'YAML alias in a value' \
    "text = text.replace('    server: $SERVER_A\n    port: 8443', '    server: *anchor\n    port: 8443', 1)"
neg_primary 'YAML tag in a value' \
    "text = text.replace('    uuid: $UUID_A', '    uuid: !!str $UUID_A', 1)"
neg_primary 'proxy-groups section renamed' \
    "text = text.replace('  - name: 自动选择', '  - name: 自动选择2', 1)"
neg_primary 'half hopping pair (ports without hop-interval)' \
    "text = text.replace('    port: 8444\n', '    port: 8444\n    ports: 40000-40100\n', 1)"
neg_primary 'half hopping pair (hop-interval without ports)' \
    "text = text.replace('    port: 8444\n', '    port: 8444\n    hop-interval: 30\n', 1)"
neg_primary 'inverted hopping range' \
    "text = text.replace('    port: 8444\n', '    port: 8444\n    ports: 40100-40000\n    hop-interval: 30\n', 1)"
neg_primary 'reversed proxy order' \
    "i = text.index('  - name: Reality'); j = text.index('  - name: Hysteria2'); k = text.index('proxy-groups:')
text = text[:i] + text[j:k] + text[i:j] + text[k:]"
neg_primary 'rules drifted' \
    "text = text.replace('  - MATCH,节点选择', '  - MATCH,自动选择', 1)"
neg_primary 'trailing blank line lost' \
    "text = text.rstrip('\n') + '\n'"
neg_primary 'credential field emptied' \
    "text = text.replace('    uuid: $UUID_A', '    uuid: ', 1)"
neg_primary 'Reality type drifted' \
    "text = text.replace('    type: vless', '    type: trojan', 1)"
neg_backup 'the same defect on the backup side reports E_BACKUP_NOT_CANONICAL' \
    "text = text.replace('  - name: Hysteria2', '  - name: Hysteria3', 1)"
neg_backup 'a backup with an extra proxy is refused' \
    "text = text.replace('      - h3\n', '      - h3\n\n  - name: Extra\n    type: ss\n    server: 192.0.2.5\n    port: 8388\n    password: xxxxxxxx\n', 1)"

section 'T24..T27 byte-level input gates'
BIN="$TMP/bin/$NAME-mihomo.yaml"
mkdir -p "$TMP/bin"
cp "$A" "$BIN"; printf '\xff\xfe' >> "$BIN"
expect_code E_PRIMARY_NOT_CANONICAL 'T24 malformed UTF-8' \
    --name "$NAME" --primary "$BIN" --output "$TMP/neg-out.yaml"
cp "$A" "$BIN"; printf 'a\x00b' >> "$BIN"
expect_code E_PRIMARY_NOT_CANONICAL 'T25 NUL byte' \
    --name "$NAME" --primary "$BIN" --output "$TMP/neg-out.yaml"
cp "$A" "$BIN"; printf '\t' >> "$BIN"
expect_code E_PRIMARY_NOT_CANONICAL 'T25b tab character' \
    --name "$NAME" --primary "$BIN" --output "$TMP/neg-out.yaml"
cp "$A" "$BIN"
"$PY" -c 'import sys
open(sys.argv[1], "ab").write(b"x" * (48 * 1024))' "$BIN"
expect_code E_PRIMARY_NOT_CANONICAL 'T26 input larger than 48 KiB' \
    --name "$NAME" --primary "$BIN" --output "$TMP/neg-out.yaml"
cp "$A" "$BIN"
"$PY" -c 'import sys
p = sys.argv[1]
text = open(p, encoding="utf-8").read()
open(p, "w", encoding="utf-8", newline="\r\n").write(text)' "$BIN"
expect_code E_PRIMARY_NOT_CANONICAL 'T26b CRLF line endings are not the canonical export' \
    --name "$NAME" --primary "$BIN" --output "$TMP/neg-out.yaml"
cp "$A" "$TMP/bin/real.yaml"
mkdir -p "$TMP/binlink"
if ln -s "$TMP/bin/real.yaml" "$TMP/binlink/$NAME-mihomo.yaml" 2>/dev/null \
        && [ -L "$TMP/binlink/$NAME-mihomo.yaml" ]; then
    expect_code E_PRIMARY_NOT_CANONICAL 'T27 symlink input refused' \
        --name "$NAME" --primary "$TMP/binlink/$NAME-mihomo.yaml" --output "$TMP/neg-out.yaml"
else
    skip 'T27 symlink gate (this host cannot create symlinks; Linux CI runs it)'
fi
expect_code E_PRIMARY_NOT_CANONICAL 'missing primary file' \
    --name "$NAME" --primary "$TMP/nope.yaml" --output "$TMP/neg-out.yaml"
expect_code E_PRIMARY_NOT_CANONICAL 'directory as primary input' \
    --name "$NAME" --primary "$TMP/vpsA" --output "$TMP/neg-out.yaml"
: > "$TMP/empty.yaml"
expect_code E_PRIMARY_NOT_CANONICAL 'empty file' \
    --name "$NAME" --primary "$TMP/empty.yaml" --output "$TMP/neg-out.yaml"

section 'usage errors'
expect_code E_USAGE 'invalid logical client name' \
    --name "bad name" --primary "$A" --output "$TMP/neg-out.yaml"
expect_rc 2 'missing --primary is an argparse usage error' \
    --name "$NAME" --output "$TMP/neg-out.yaml"

# --------------------------------------------------------- T28..T30 output ---
section 'T28..T30 output hygiene'
PRE="$TMP/pre-existing.yaml"
cp "$B" "$PRE"
PRE_SHA="$(sha256 "$PRE")"
expect_mode=dual
expect_code E_OUTPUT_EXISTS 'T28 an existing output is never overwritten' \
    --name "$NAME" --primary "$A" --backup "$B" --output "$PRE"
assert_eq "$PRE_SHA" "$(sha256 "$PRE")" 'T28 the pre-existing output is byte-identical afterwards'
expect_mode=single
expect_code E_OUTPUT_EXISTS 'T28b single mode also refuses an existing output' \
    --name "$NAME" --primary "$A" --output "$PRE"
expect_code E_IO 'an output in a missing directory is refused' \
    --name "$NAME" --primary "$A" --output "$TMP/no-such-dir/out.yaml"

if [ "$POSIX_HOST" = "1" ]; then
    assert_eq 600 "$(stat -c '%a' "$M")" 'T29 dual output mode is 0600'
    assert_eq 600 "$(stat -c '%a' "$OUT1H")" 'T29 single output mode is 0600'
    saved_umask="$(umask)"
    umask 002
    OUT_GROUP="$TMP/group-readable-attempt.yaml"
    expect_ok 'T29b merge succeeds under a permissive umask' \
        --name "$NAME" --primary "$A" --output "$OUT_GROUP"
    assert_eq 600 "$(stat -c '%a' "$OUT_GROUP")" \
        'T29b mode is 0600 even when umask 002 would allow 0664'
    umask "$saved_umask"
else
    skip 'T29 dual output mode assertions (no POSIX permission bits on this host)'
fi
assert_eq 0 "$(count_files "$TMP" -name '.mihomo-merge-*')" \
    'T30 no temporary file is left behind after the successes and the failures'
assert_eq 0 "$(count_files "$TMP" -maxdepth 1 \( -name 'neg-out.yaml' -o -name 'o1*.yaml' -o -name 'out.yaml' \) -print)" \
    'T30b every rejected merge left no output file at all'
assert_diff "$A" "$TMP/vpsA/$NAME-mihomo.yaml" 'the primary input is never modified'
assert_diff "$B" "$TMP/vpsB/$NAME-mihomo.yaml" 'the backup input is never modified'

# ------------------------------------------------- R1 review round 1 fixes ---
# Each block below is the exact counterexample raised in review, not a restated
# generic check.

expect_exact() { # <label> -- run the last merge and compare rc/stdout/stderr
    local label=$1 want_rc=$2 want_err=$3
    if [ "$RC" = "$want_rc" ] && [ "$OUT" = "" ] && [ "$ERR" = "$want_err" ]; then
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR])"
    fi
}

expect_usage() { # <label> <args...> : fixed E_USAGE line, nothing echoed back
    local label=$1; shift
    run_merge "$@"
    local echoed=""
    for arg in "$@"; do
        [ -n "$arg" ] || continue
        case "$OUT$ERR" in
            *"$arg"*) echoed="$echoed [$arg]" ;;
        esac
    done
    if [ "$RC" = 2 ] && [ "$OUT" = "" ] && [ "$ERR" = "merge: FAIL E_USAGE" ] \
            && [ -z "$echoed" ]; then
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR] echoed:$echoed)"
    fi
}

section 'R1 B1 the whole canonical prefix must match byte for byte'
# Mechanical parity: whatever the renderer prints before `proxies:` IS the
# constant. A typo in this suite or in the tool cannot hide behind the other.
prefix_parity="$("$PY" - "$TOOL" "$RENDER_LIB" <<'PY'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("merge_tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

body = open(sys.argv[2], encoding="utf-8").read()
start = body.index("    printf 'mixed-port: 7897")
lines = [body[start:].split("\n", 1)[0].split("printf '", 1)[1]]
for line in body[start:].split("\n", 1)[1].split("\n"):
    if line == "proxies:":
        break
    lines.append(line)
mine, theirs = lines, list(tool.CANONICAL_PREFIX_LINES)
if mine == theirs:
    print("OK %d lines" % len(mine))
else:
    at = next((i for i, (a, b) in enumerate(zip(mine, theirs)) if a != b),
              min(len(mine), len(theirs)))
    print("MISMATCH renderer=%d tool=%d first difference at line %d"
          % (len(mine), len(theirs), at + 1))
PY
)"
assert_eq "OK 43 lines" "$prefix_parity" \
    'R1 B1 CANONICAL_PREFIX_LINES equals the renderer pre-proxies region'

# Every one of these is a well-formed YAML document with canonical SECTION
# KEYS -- the old key-name-only check accepted all of them and passed the
# result straight into the merged profile.
prefix_case() { # <label> <python statement rewriting `text`>
    mutate "$A" "$TMP/r1-prefix.yaml" "$2"
    expect_code E_PRIMARY_NOT_CANONICAL "R1 B1 $1" \
        --name "$NAME" --primary "$TMP/r1-prefix.yaml" \
        --output "$TMP/r1-prefix-out.yaml"
}
prefix_case 'allow-lan widened to false' \
    'text = text.replace("allow-lan: true", "allow-lan: false", 1)'
prefix_case 'mixed-port changed' \
    'text = text.replace("mixed-port: 7897", "mixed-port: 1080", 1)'
prefix_case 'store-selected removed (store-selected is load-bearing)' \
    'text = text.replace("  store-selected: true\n", "", 1)'
prefix_case 'a DNS server injected under the canonical nameserver list' \
    'text = text.replace("    - 223.5.5.5\n", "    - 223.5.5.5\n    - 185.199.108.153\n", 1)'
prefix_case 'a fake-ip-range swapped out' \
    'text = text.replace("198.18.0.1/16", "10.0.0.1/8", 1)'
prefix_case 'the tun block dropped entirely' \
    'text = text.replace("tun:\n  enable: true\n  stack: mixed\n  device: Mihomo\n  mtu: 1420\n  auto-route: true\n  auto-redirect: true\n  auto-detect-interface: true\n  dns-hijack:\n    - any:53\n    - tcp://any:53\n\n", "", 1)'
prefix_case 'two prefix keys swapped order' \
    'text = text.replace("mode: rule\nlog-level: info\n", "log-level: info\nmode: rule\n", 1)'
prefix_case 'the blank line before tun removed (line cadence drift)' \
    'text = text.replace("      - 240.0.0.0/4\n\ntun:", "      - 240.0.0.0/4\ntun:", 1)'
prefix_case 'an extra indented option under profile' \
    'text = text.replace("  store-fake-ip: true\n", "  store-fake-ip: true\n  whatever: yes\n", 1)'
prefix_case 'the whole prefix duplicated before proxies' \
    'text = text.replace("proxies:\n", "mixed-port: 7897\nproxies:\n", 1)'
# and the shape itself must still be accepted, so the cases above prove
# strictness rather than a broken fixture.
expect_mode=single
expect_ok 'R1 B1 the untouched canonical export is still accepted' \
    --name "$NAME" --primary "$A" --output "$TMP/r1-ok.yaml"

section 'R1 B2 usage failures can never echo argv'
expect_usage 'unknown long option carrying a secret-shaped value' \
    --name "$NAME" --primary "$A" --output "$TMP/neg-out.yaml" \
    "--password=$UUID_A"
expect_usage 'positional argument whose value is a real export path' \
    --name "$NAME" --primary "$A" --output "$TMP/neg-out.yaml" "$B"
expect_usage 'missing --primary' --name "$NAME" --output "$TMP/neg-out.yaml"
expect_usage 'missing --output' --name "$NAME" --primary "$A"
expect_usage '--name without a value' --name --primary "$A" --output "$TMP/neg-out.yaml"
expect_usage 'abbreviated option name' \
    --name "$NAME" --pri "$A" --output "$TMP/neg-out.yaml"
expect_usage 'short option' --name "$NAME" --primary "$A" -o "$TMP/neg-out.yaml"
expect_usage 'help is refused, not printed' --help
expect_usage 'short help is refused, not printed' -h
expect_usage 'no arguments at all'
expect_usage 'an option-like token in the name position' \
    --name "--password=$UUID_A" --primary "$A" --output "$TMP/neg-out.yaml"
# A usage failure must not even reach the file layer.
assert_eq 0 "$(count_files "$TMP" -name 'neg-out.yaml' -print)" \
    'R1 B2 no usage failure created an output file'

section 'R1 B3 logical name parity with the canonical client-name contract'
name_parity="$("$PY" - "$TOOL" "$RENDER_LIB" <<'PY'
import importlib.util
import re
import sys

spec = importlib.util.spec_from_file_location("merge_tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
lib = open(sys.argv[2], encoding="utf-8").read()
canonical = re.search(r"CLIENT_NAME_PATTERN='(.*)'", lib).group(1)
mine = tool.CLIENT_NAME_RE.pattern
strip = lambda p: re.sub(r"^(?:\^|\\A)|(?:\$|\\Z)$", "", p)
print("OK" if strip(canonical) == strip(mine) else
      "MISMATCH canonical=%r tool=%r" % (canonical, mine))
PY
)"
assert_eq OK "$name_parity" \
    'R1 B3 CLIENT_NAME_RE equals lib/client-management.sh CLIENT_NAME_PATTERN'
NAME32="abcdefghij0123456789ABCDEFGH0123"   # exactly 32 chars
assert_eq 32 "${#NAME32}" 'R1 B3 the 32-character test name really is 32 long'
mkdir -p "$TMP/vps32"
mk_export "$TMP/vps32/$NAME32-mihomo.yaml" "$SERVER_A" "$UUID_A" \
          "$PASSPHRASE_A" "$PUBKEY_A" "$SHORTID_A" FALSE
expect_ok 'R1 B3 a 32-character canonical client name is accepted' \
    --name "$NAME32" --primary "$TMP/vps32/$NAME32-mihomo.yaml" \
    --output "$TMP/r1-name32.yaml"
expect_usage 'R1 B3 a 33-character name is refused' \
    --name "${NAME32}x" --primary "$A" --output "$TMP/neg-out.yaml"
expect_usage 'R1 B3 a name with an embedded newline is refused' \
    --name "$NAME
" --primary "$A" --output "$TMP/neg-out.yaml"
expect_usage 'R1 B3 a name starting with a separator is refused' \
    --name "_$NAME" --primary "$A" --output "$TMP/neg-out.yaml"
expect_usage 'R1 B3 an empty name is refused' \
    --name "" --primary "$A" --output "$TMP/neg-out.yaml"
expect_usage 'R1 B3 a path-shaped name is refused' \
    --name "../../etc/$NAME" --primary "$A" --output "$TMP/neg-out.yaml"

section 'R1 B4 malformed and truncated input is structural, never E_IO'
"$PY" - "$A" "$TMP/r1cut" <<'PY'
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read()
text = raw.decode("utf-8")
os.makedirs(dst, exist_ok=True)
body = text.split("\n")
for taken in range(len(body)):          # every whole-line truncation
    payload = "\n".join(body[:taken]) + ("\n" if taken else "")
    if payload.encode("utf-8") == raw:
        continue                        # reassembly of the original, not a cut
    open(os.path.join(dst, "lines-%03d.yaml" % taken), "wb").write(
        payload.encode("utf-8"))
for back in (1, 2, 3, 8, 40, 200):      # cut mid-line off the tail
    open(os.path.join(dst, "bytes-%03d.yaml" % back), "wb").write(raw[:-back])
PY
CUTS=0
CUT_BAD=""
for variant in "$TMP/r1cut"/*.yaml; do
    CUTS=$((CUTS + 1))
    rm -f "$TMP/r1-cut-out.yaml"
    run_merge --name "$NAME" --primary "$variant" --output "$TMP/r1-cut-out.yaml"
    [ "$RC" = 1 ] && [ "$ERR" = "merge: FAIL E_PRIMARY_NOT_CANONICAL" ] \
        && [ "$OUT" = "" ] || CUT_BAD="$CUT_BAD $(basename "$variant"):rc=$RC:err=$ERR"
done
assert_eq '' "$CUT_BAD" \
    "R1 B4 every one of the $CUTS truncations reports E_PRIMARY_NOT_CANONICAL, none E_IO"
assert_eq 0 "$(count_files "$TMP" -maxdepth 1 -name 'r1-cut-out.yaml' -print)" \
    'R1 B4 not one truncation variant produced an output file'

# The same sweep on the PORT-HOPPING form: `ports:` is followed by a
# `hop-interval:` line, and a cut between those two used to index past the end
# of the document.
"$PY" - "$B" "$TMP/r1cut-b" <<'PY'
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read()
text = raw.decode("utf-8")
os.makedirs(dst, exist_ok=True)
body = text.split("\n")
for taken in range(len(body)):
    payload = "\n".join(body[:taken]) + ("\n" if taken else "")
    if payload.encode("utf-8") == raw:
        continue
    open(os.path.join(dst, "lines-%03d.yaml" % taken), "wb").write(
        payload.encode("utf-8"))
PY
CUTS_B=0
CUT_BAD_B=""
for variant in "$TMP/r1cut-b"/*.yaml; do
    CUTS_B=$((CUTS_B + 1))
    rm -f "$TMP/r1-cut-b-out.yaml"
    run_merge --name "$NAME" --primary "$A" --backup "$variant" \
        --output "$TMP/r1-cut-b-out.yaml"
    [ "$RC" = 1 ] && [ "$ERR" = "merge: FAIL E_BACKUP_NOT_CANONICAL" ] \
        && [ "$OUT" = "" ] || CUT_BAD_B="$CUT_BAD_B $(basename "$variant"):rc=$RC:err=$ERR"
done
assert_eq '' "$CUT_BAD_B" \
    "R1 B4 every one of the $CUTS_B hopping-form truncations reports E_BACKUP_NOT_CANONICAL"
# Explicitly name the two read positions that the bounds helpers now guard:
# the line after the Reality block, and the hop-interval line after `ports:`.
"$PY" - "$A" "$TMP/r1-site1.yaml" <<'PY'
import sys
body = open(sys.argv[1], encoding="utf-8").read().split("\n")
cut = next(i for i, line in enumerate(body)
           if line.startswith("      short-id:")) + 1
open(sys.argv[2], "w", encoding="utf-8", newline="").write("\n".join(body[:cut]))
PY
expect_code E_PRIMARY_NOT_CANONICAL \
    'R1 B4 a cut right after the Reality block (guarded read position) is structural' \
    --name "$NAME" --primary "$TMP/r1-site1.yaml" \
    --output "$TMP/r1-site1-out.yaml"
"$PY" - "$B" "$TMP/r1-site2.yaml" <<'PY'
import sys
body = open(sys.argv[1], encoding="utf-8").read().split("\n")
cut = body.index("    ports: 40000-40100") + 1
open(sys.argv[2], "w", encoding="utf-8", newline="").write("\n".join(body[:cut]))
PY
expect_code E_BACKUP_NOT_CANONICAL \
    'R1 B4 a cut between ports: and hop-interval: (guarded read position) is structural' \
    --name "$NAME" --primary "$A" --backup "$TMP/r1-site2.yaml" \
    --output "$TMP/r1-site2-out.yaml"

# The same classification must hold when the DAMAGE is on the backup side.
truncate_backup() { # <label> <lines to keep>
    "$PY" -c 'import sys
body = open(sys.argv[1], encoding="utf-8").read().split("\n")
open(sys.argv[2], "w", encoding="utf-8", newline="").write("\n".join(body[:int(sys.argv[3])]))' \
        "$B" "$TMP/r1-backup.yaml" "$2"
    expect_mode=dual
    expect_code E_BACKUP_NOT_CANONICAL "$1" \
        --name "$NAME" --primary "$A" --backup "$TMP/r1-backup.yaml" \
        --output "$TMP/r1-backup-out.yaml"
    expect_mode=single
}
truncate_backup 'R1 B4 a truncated backup reports its own code' 60
truncate_backup 'R1 B4 a backup cut inside the prefix reports its own code' 20
for missing in 'proxy-groups:' 'rules:' 'proxies:'; do
    "$PY" -c 'import sys
text = open(sys.argv[1], encoding="utf-8").read()
open(sys.argv[2], "w", encoding="utf-8", newline="").write(
    text.replace(sys.argv[3] + "\n", "", 1))' "$A" "$TMP/r1-sect.yaml" "$missing"
    expect_code E_PRIMARY_NOT_CANONICAL \
        "R1 B4 a document missing the $missing section is structural, not I/O" \
        --name "$NAME" --primary "$TMP/r1-sect.yaml" \
        --output "$TMP/r1-sect-out.yaml"
done
# Structural edits at EVERY position, not just truncation: a line deleted, a
# line blanked, an extra indented option injected, a second copy of a line, and
# an injected column-0 option (the `external-controller` shape that would open
# the controller to the network). Each is a well-formed-ish document that must
# be refused by the shape gate.
"$PY" - "$A" "$TMP/r1mut" <<'PY'
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
body = open(src, encoding="utf-8").read().split("\n")
os.makedirs(dst, exist_ok=True)
kinds = {
    "del": lambda i: body[:i] + body[i + 1:],
    "blank": lambda i: body[:i] + [""] + body[i + 1:],
    "dup": lambda i: body[:i] + [body[i]] + body[i:],
    "inject": lambda i: body[:i] + ["  hostile: yes"] + body[i:],
    "option": lambda i: body[:i] + ["external-controller: 0.0.0.0:9090"] + body[i:],
}
for name, build in kinds.items():
    for position in range(len(body)):
        payload = "\n".join(build(position)) + "\n"
        if payload == "\n".join(body):
            continue            # an edit that reconstructs the original is not a mutation
        with open(os.path.join(dst, "%s-%03d.yaml" % (name, position)),
                  "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
PY
MUTS=0
MUT_BAD=""
for variant in "$TMP/r1mut"/*.yaml; do
    MUTS=$((MUTS + 1))
    rm -f "$TMP/r1-mut-out.yaml"
    run_merge --name "$NAME" --primary "$variant" --output "$TMP/r1-mut-out.yaml"
    [ "$RC" = 1 ] && [ "$ERR" = "merge: FAIL E_PRIMARY_NOT_CANONICAL" ] \
        && [ "$OUT" = "" ] || MUT_BAD="$MUT_BAD $(basename "$variant"):rc=$RC:err=$ERR"
done
assert_eq '' "$MUT_BAD" \
    "R1 B4 every one of the $MUTS single-position structural edits reports E_PRIMARY_NOT_CANONICAL"

# One directory that cannot exist is the ONLY thing allowed to say E_IO.
expect_code E_IO 'a missing output directory still reports E_IO (real I/O)' \
    --name "$NAME" --primary "$A" --output "$TMP/no-such-dir-r1/out.yaml"
grep -lE 'Traceback|IndexError|StopIteration|KeyError' "$LOGS"/*.err >/dev/null 2>&1 \
    && fail 'R1 B4 some invocation leaked a Python traceback' \
    || pass "R1 B4 zero tracebacks across all $RUNS invocations so far"

# ------------------------------------------------------- T31 credential -----
section 'T31 credential hygiene'
LEAKS=0
for sentinel in "$SERVER_A" "$SERVER_B" "$UUID_A" "$UUID_B" "$PASSPHRASE_A" \
                "$PASSPHRASE_B" "$PUBKEY_A" "$PUBKEY_B" "$SHORTID_A" "$SHORTID_B" \
                'uuid:' 'password:' 'server:' 'public-key:' 'short-id:' 'node选择'; do
    if grep -lF -- "$sentinel" "$LOGS"/*.out "$LOGS"/*.err >/dev/null 2>&1; then
        fail "T31 a credential-shaped token reached stdout/stderr: [$sentinel]"
        LEAKS=$((LEAKS + 1))
    fi
done
[ "$LEAKS" -eq 0 ] && pass "T31 $RUNS invocations produced zero credential or YAML bytes on stdout/stderr"
run_merge --name "$NAME" --primary "$A" --output "$TMP/receipt.yaml"
assert_eq 'merge: OK
mode: single
output: written' "$OUT" \
    'the success receipt names only the mode and the fact of writing'
assert_eq '' "$ERR" 'the success receipt writes nothing to stderr'
# The merged file itself is the only place the credentials may live.
assert_eq 1 "$(grep -c "uuid: $UUID_B" "$M")" 'T31b the backup credential is present in the output YAML as intended'
assert_eq 1 "$(grep -c "password: $PASSPHRASE_B" "$M")" 'T31b the backup password is present in the output YAML as intended'

# ------------------------------------------------- T32..T34 compatibility ---
section 'T32..T34 byte stability and store-selected compatibility'
prelude_of "$A" > "$TMP/e5"; prelude_of "$M" > "$TMP/g5"
assert_diff "$TMP/e5" "$TMP/g5" 'T32 everything before proxies: stays primary bytes'
rules_of "$A" > "$TMP/e6"; rules_of "$M" > "$TMP/g6"
assert_diff "$TMP/e6" "$TMP/g6" 'T32b everything from rules: on stays primary bytes'
assert_eq 'rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择' "$(rules_of "$M")" \
    'T33 rules stay exactly GEOIP,LAN / GEOIP,CN / MATCH,节点选择'
# Every value a previously deployed single-VPS profile can have persisted in
# cache.db must still resolve in the merged profile: no dangling pin.
for cached in Reality Hysteria2 自动选择 DIRECT; do
    if printf '%s\n' "$(selector_members "$M")" | grep -qxF -- "$cached"; then
        pass "T34 outer cached selection [$cached] still resolves"
    else
        fail "T34 outer cached selection [$cached] became dangling"
    fi
done
for cached in Reality Hysteria2; do
    if printf '%s\n' "$(auto_members "$M")" | grep -qxF -- "$cached"; then
        pass "T34 inner cached selection [$cached] still resolves"
    else
        fail "T34 inner cached selection [$cached] became dangling"
    fi
done
assert_eq '节点选择
自动选择' "$(awk '/^  - name: /{sub(/^  - name: /,"");print}' "$M" | tail -2)" \
    'T34b both group names survive unchanged (the store-selected cache keys)'
assert_eq 'fallback' \
    "$(awk '/^  - name: 自动选择$/{f=1;next} f&&/^    type: /{sub(/^    type: /,"");print;exit}' "$M")" \
    'T34c 自动选择 stays a fallback group, so a persisted inner pin keeps its meaning'
assert_eq 'Reality' "$(auto_members "$M" | head -1)" \
    'T34d Reality stays the first fallback member (primary preference, #42 semantics)'

# ------------------------------------------------------------------ summary --
printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
