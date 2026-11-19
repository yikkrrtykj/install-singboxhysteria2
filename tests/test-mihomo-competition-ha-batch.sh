#!/usr/bin/env bash
# Issue #48 HA-02 -- competition dual-active batch delivery contract.
#
# Scope: tools/mihomo-competition-ha-batch.py, an operator-local, hermetic tool
# that turns a terminal inventory plus two canonical `client.export` trees
# (A/ and B/) into one four-node Mihomo profile per terminal, with a local
# SHA-256 delivery manifest and rollback of the files the batch created.
#
# The batch tool must REUSE the canonical parser of
# tools/mihomo-multi-vps-merge.py (issue #48 PR-48A): this suite proves the
# reuse, byte-identical output, unchanged single-VPS behavior, the four-node
# priority contract, complete HY2 hopping preservation, every fail-closed input
# gate the competition HA contract requires, real POSIX mode and real Windows
# ACL enforcement, no-clobber and case-insensitive output collisions, the
# all-or-nothing prevalidation boundary, rollback on injected partial failure,
# credential redaction, and the opt-in pinned-core load harness.
#
# Sandbox only: temporary files, no root, no network, no VPS, no production
# config. Every credential below is an obvious test sentinel, never a real one.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/mihomo-competition-ha-batch.py"
MERGE="$ROOT/tools/mihomo-multi-vps-merge.py"
CORE_LOAD="$ROOT/tests/mihomo-competition-ha-core-load.py"
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
assert_contains() { case "$1" in *"$2"*) pass "$3" ;; *) fail "$3 (missing [$2] in [$1])" ;; esac; }
assert_absent() { case "$1" in *"$2"*) fail "$3 (found [$2] in [$1])" ;;
    *) pass "$3" ;; esac; }
assert_file() { [ -f "$1" ] && pass "$2" || fail "$2 (missing $1)"; }

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" --version >/dev/null 2>&1 || { printf '  FAIL no python interpreter\n'; exit 1; }

POSIX_HOST=1
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) POSIX_HOST=0 ;;
esac
IS_WINDOWS=0
[ "$POSIX_HOST" = "0" ] && IS_WINDOWS=1

sha256() { "$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
size_of() { "$PY" -c 'import os,sys;print(os.path.getsize(sys.argv[1]))' "$1"; }
jget() { "$PY" - "$1" "$2" <<'PY'
import json
import sys
node = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    node = node[int(part)] if part.isdigit() else node[part]
print(node)
PY
}
proxy_names() { awk '/^proxies:/{f=1;next} /^proxy-groups:/{f=0}
    f && /^  - name: /{sub(/^  - name: /,"");print}' "$1"; }
selector_members() { awk '/^  - name: 节点选择$/{f=1;next} /^  - name: /{f=0}
    f && /^      - /{sub(/^      - /,"");print}' "$1"; }
auto_members() { awk '/^  - name: 自动选择$/{f=1;next} /^    url: /{f=0}
    f && /^      - /{sub(/^      - /,"");print}' "$1"; }
block_of() { awk -v n="  - name: $2" '$0==n{f=1} f && $0==""{exit} f' "$1"; }
line_join() { paste -sd' ' - | sed 's/ *$//'; }
count_outputs() { find "$1" -maxdepth 1 -name '*-ha.yaml' -type f 2>/dev/null | wc -l | tr -d ' '; }
count_entries() { find "$1" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' '; }

# --------------------------------------------------------------- fixtures ---
SERVER_A="203.0.113.7"
SERVER_B="198.51.100.9"
SERVER_C="192.0.2.10"
PUBKEY_A="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBKEY_B="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
SHORTID_A="0123456789abcdef"
SHORTID_B="fedcba9876543210"
HOP_ALL=0
LEGACY_ALL=0
HOPA=0
HOPB=0

uuid_a() { printf '1%07d-1111-2222-3333-%012d' "$1" "$1"; }
uuid_b() { printf '2%07d-1111-2222-3333-%012d' "$1" "$1"; }
pw_a() { printf 'ha-A-%02d-pppppppppppppppppppppppp' "$1"; }
pw_b() { printf 'ha-B-%02d-qqqqqqqqqqqqqqqqqqqqqqqq' "$1"; }

mk_export() { # <path> <server> <uuid> <password> <pubkey> <shortid> <ports|""> <legacy 0|1>
    local out=$1 server=$2 uuid=$3 password=$4 pubkey=$5 shortid=$6
    local ports=$7 legacy=$8
    local hy_ports="    port: 8444"
    if [ -n "$ports" ]; then
        hy_ports="    port: 8444
    ports: $ports
    hop-interval: 30"
    fi
    local pw_block="    password: $password"
    if [ "$legacy" = "1" ]; then
        pw_block="$pw_block
    up: \"300 Mbps\"
    down: \"300 Mbps\""
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
$hy_ports
$pw_block
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
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$out"
}

mk_tree() { # <dir> <count> <a_first>
    local dir=$1 count=$2 a_first=$3
    mkdir -p "$dir/exports/A" "$dir/exports/B" "$dir/delivery"
    if [ "$POSIX_HOST" = "1" ]; then
        chmod 700 "$dir" "$dir/exports" "$dir/exports/A" "$dir/exports/B" "$dir/delivery"
    fi
    printf 'terminal,group\n' > "$dir/terminals.csv"
    local i name group hop_a hop_b legacy
    for ((i = 1; i <= count; i++)); do
        name=$(printf 'event-ob%02d' "$i")
        if [ "$i" -le "$a_first" ]; then group=A-first; else group=B-first; fi
        printf '%s,%s\n' "$name" "$group" >> "$dir/terminals.csv"
        hop_a=""
        hop_b=""
        case "$HOP_ALL" in
            1) hop_a=$(printf '%d-%d' $((40000 + i)) $((40020 + i)))
               hop_b=$(printf '%d-%d' $((41000 + i)) $((41020 + i))) ;;
            2) hop_a=$(printf '%d-%d' $((40000 + i)) $((40020 + i))) ;;
            3) hop_b=$(printf '%d-%d' $((41000 + i)) $((41020 + i))) ;;
            *) [ $((i % 3)) -eq 0 ] && hop_a=$(printf '%d-%d' $((40000 + i)) $((40020 + i)))
               [ $((i % 2)) -eq 0 ] && hop_b=$(printf '%d-%d' $((41000 + i)) $((41020 + i))) ;;
        esac
        legacy=0
        if [ "$LEGACY_ALL" = "1" ]; then legacy=1; else
            if [ "$i" -eq 5 ] || [ "$i" -eq 17 ]; then legacy=1; fi
        fi
        mk_export "$dir/exports/A/$name-mihomo.yaml" "$SERVER_A" "$(uuid_a "$i")" \
            "$(pw_a "$i")" "$PUBKEY_A" "$SHORTID_A" "$hop_a" "$legacy"
        mk_export "$dir/exports/B/$name-mihomo.yaml" "$SERVER_B" "$(uuid_b "$i")" \
            "$(pw_b "$i")" "$PUBKEY_B" "$SHORTID_B" "$hop_b" "$legacy"
    done
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$dir/terminals.csv"
}

clone_tree() { # <src> <name> ; echoes the clone path
    local src=$1 dst="$TMP/$2"
    rm -rf -- "$dst"
    cp -R "$src" "$dst"
    printf '%s\n' "$dst"
}

in_args() { # <root> [version] ; one whitespace-separated argument line
    printf '%s ' --inventory "$1/terminals.csv" --exports "$1/exports" \
        --output-dir "$1/delivery" --config-version "${2:-test-r1}"
}

# ----------------------------------------------------------------- runner ---
RUNS=0
RC=0
OUT=""
ERR=""
ERR1=""
run_batch() { # <args...> ; sets RC / OUT / ERR / ERR1
    RUNS=$((RUNS + 1))
    local log="$LOGS/run$RUNS"
    "$PY" "$TOOL" "$@" >"$log.out" 2>"$log.err"
    RC=$?
    # Windows redirects print() as CRLF; the product contract is line content.
    OUT="$(tr -d '\r' < "$log.out")"
    ERR="$(tr -d '\r' < "$log.err")"
    ERR1="${ERR%%$'\n'*}"
}

expect_ok_lines() { # <terminals> <a_first_count> <b_first_count> <version> <label> <args...>
    local n=$1 a=$2 b=$3 version=$4 label=$5
    shift 5
    run_batch "$@"
    local want="ha-batch: OK
terminals: $n
groups: A-first=$a B-first=$b
version: $version
manifest: ha-delivery-$version.json"
    if [ "$RC" -eq 0 ] && [ "$OUT" = "$want" ] && [ -z "$ERR" ]; then
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR])"
    fi
}

expect_code() { # <want-code> <label> <args...>
    local want=$1 label=$2
    shift 2
    run_batch "$@"
    if [ "$RC" -ne 0 ] && [ -n "$ERR1" ] && [ "${ERR1#"ha-batch: FAIL $want"}" != "$ERR1" ] \
       && [ -z "$OUT" ]; then
        pass "$label -> $want"
    else
        fail "$label (rc=$RC want=[$want] stderr=[$ERR] stdout=[$OUT])"
    fi
}

expect_code_exit() { # <want-rc> <want-code> <label> <args...>
    local want_rc=$1 want=$2 label=$3
    shift 3
    run_batch "$@"
    if [ "$RC" -eq "$want_rc" ] && [ "$ERR1" = "ha-batch: FAIL $want" ] && [ -z "$OUT" ]; then
        pass "$label -> $want (exit $want_rc)"
    else
        fail "$label (rc=$RC want-rc=$want_rc want=[$want] stderr=[$ERR] stdout=[$OUT])"
    fi
}

assert_no_secret() { # <label> ; checks OUT+ERR of the last run
    local combined="$OUT$ERR"
    local label=$1 found=""
    for sentinel in "$SERVER_A" "$SERVER_B" "1111-2222-3333" "ha-A-" "ha-B-" \
                    "$PUBKEY_A" "$PUBKEY_B" "$SHORTID_A" "$SHORTID_B" \
                    "UUID" "password:" "proxies:" "skip-cert-verify"; do
        case "$combined" in *"$sentinel"*) found="$found [$sentinel]" ;; esac
    done
    [ -z "$found" ] && pass "$label" || fail "$label (leaked:$found)"
}

printf '===== COMPETITION HA BATCH DELIVERY (issue #48 HA-02) =====\n'

# ------------------------------------------------------------- static gates --
section 'static gates'
"$PY" -m py_compile "$TOOL" && pass 'py_compile tools/mihomo-competition-ha-batch.py' \
    || fail 'py_compile tools/mihomo-competition-ha-batch.py'
"$PY" -m py_compile "$CORE_LOAD" && pass 'py_compile tests/mihomo-competition-ha-core-load.py' \
    || fail 'py_compile core-load harness'
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
        __future__|hashlib|importlib|json|os|re|stat|sys|time) ;;
        *) bad="$bad $module" ;;
    esac
done
[ -z "$bad" ] && pass "stdlib allowlist holds (imports: $imports)" \
    || fail "non-allowlisted import(s):$bad"
for module in socket ssl urllib http ftplib smtplib subprocess sched selectors \
              asyncio threading multiprocessing sqlite3 yaml base64 argparse; do
    case " $imports " in
        *" $module "*) fail "the batch tool imports $module (hermetic mandate)" ;;
    esac
done
pass 'no network, subprocess, scheduling, third-party YAML or duplicated CLI parser imported'
grep -qiE 'pyyaml|import yaml|ruamel' "$TOOL" \
    && fail 'a YAML library is referenced' || pass 'no YAML library dependency'
grep -q 'spec_from_file_location' "$TOOL" && grep -q 'MERGE_TOOL_NAME' "$TOOL" \
    && pass 'the batch tool loads the canonical parser by path' \
    || fail 'the batch tool does not load the canonical parser'
for forbidden in 'def read_export' 'def parse_export' 'def build_output' \
                 'def write_output' 'CANONICAL_PREFIX_LINES' 'RULES_LINES' \
                 'GROUPS_SINGLE_OUTER' 'HISTERIA2_TAIL'; do
    grep -qF -- "$forbidden" "$TOOL" \
        && fail "the batch tool duplicates canonical parser internals [$forbidden]" || true
done
pass 'no canonical parser internals are duplicated in the batch tool'
grep -qE 'generate_204|gstatic|expected-status|interval: [0-9]|timeout: [0-9]|lazy: (true|false)' "$TOOL" \
    && fail 'the batch tool hardcodes a health-probe parameter' \
    || pass 'the batch tool never rewrites the #42 probe policy'

# The exact CLI surface: paths and a version label only.
cli_flags="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(re.findall(r'add_argument\("(--[a-z-]+)"', text)))
PY
)"
assert_eq '--inventory --exports --output-dir --config-version' "$cli_flags" \
    'CLI flags are exactly --inventory / --exports / --output-dir / --config-version'
for forbidden in uuid password server pubkey public-key short-id secret token \
                 url host force backup; do
    printf '%s\n' "$cli_flags" | grep -qiE -- "--$forbidden" \
        && fail "the CLI exposes a --$forbidden option" || true
done
pass 'no credential-bearing, role-selector or --force CLI option exists'

# The merged contract that the batch tool must reuse is still exported.
"$PY" - "$MERGE" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("merge", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for name in ("parse_export", "check_provenance", "check_sources",
             "check_credentials", "build_output", "write_output",
             "_SilentParser", "MergeError", "CLIENT_NAME_RE"):
    if not hasattr(module, name):
        raise SystemExit("missing " + name)
print("ok")
PY
[ $? -eq 0 ] && pass 'the canonical merge tool still exports every reused gate' \
    || fail 'the canonical merge tool lost a reused gate'

# Renderer drift: the canonical shape the reused parser pins is still emitted.
for marker in 'expected-status: "204"' '    interval: 60' '    timeout: 5000' \
              '    lazy: false' 'default-selected: 自动选择' \
              'flow: xtls-rprx-vision' 'skip-cert-verify: true' \
              '    hop-interval: 30' '    ports: ' '  - MATCH,节点选择'; do
    grep -qF -- "$marker" "$RENDER_LIB" \
        && pass "renderer template still carries [$marker]" \
        || fail "renderer template lost [$marker]: canonical contract must be updated"
done

# ------------------------------------------------------- T1 single A-first ---
section 'T1 single A-first terminal'
HOP_ALL=0; LEGACY_ALL=0
T1="$TMP/t1"
mk_tree "$T1" 1 1
read -r -a T1ARGS <<< "$(in_args "$T1")"
expect_ok_lines 1 1 0 test-r1 'T1 one A-first terminal succeeds' "${T1ARGS[@]}"
T1OUT="$T1/delivery/event-ob01-ha.yaml"
T1MAN="$T1/delivery/ha-delivery-test-r1.json"
assert_file "$T1OUT" 'T1 delivery profile exists'
assert_file "$T1MAN" 'T1 delivery manifest exists'
"$PY" "$MERGE" --name event-ob01 --primary "$T1/exports/A/event-ob01-mihomo.yaml" \
    --backup "$T1/exports/B/event-ob01-mihomo.yaml" --output "$TMP/t1-merge.yaml" >/dev/null
assert_diff "$TMP/t1-merge.yaml" "$T1OUT" 'T1 output is byte-identical to the PR-48A merge'
assert_eq 'Reality Hysteria2 Backup-Reality Backup-Hysteria2' \
    "$(proxy_names "$T1OUT" | line_join)" 'T1 proxy order is the four-node contract'
assert_eq 'Reality Hysteria2 Backup-Reality Backup-Hysteria2 自动选择 DIRECT' \
    "$(selector_members "$T1OUT" | line_join)" 'T1 selector member order'
assert_eq 'Reality Hysteria2 Backup-Reality Backup-Hysteria2' \
    "$(auto_members "$T1OUT" | line_join)" 'T1 fallback member order'
assert_eq 'Reality' "$(auto_members "$T1OUT" | head -1)" \
    'T1 A-first keeps Reality as the first fallback member'
for marker in '    url: "https://www.gstatic.com/generate_204"' '    interval: 60' \
              '    timeout: 5000' '    lazy: false' '    expected-status: "204"'; do
    assert_eq 1 "$(grep -cF -- "$marker" "$T1OUT")" "T1 output keeps [$marker]"
done
assert_eq "$SERVER_A" "$(block_of "$T1OUT" Reality | awk '/^    server: /{print $2}')" \
    'T1 primary Reality is VPS A'
assert_eq "$SERVER_B" "$(block_of "$T1OUT" Backup-Reality | awk '/^    server: /{print $2}')" \
    'T1 backup Reality is VPS B'
assert_eq 'mihomo-competition-ha-batch/1' "$(jget "$T1MAN" schema)" 'T1 manifest schema'
assert_eq 1 "$(jget "$T1MAN" terminal_count)" 'T1 manifest terminal_count'
assert_eq 1 "$(jget "$T1MAN" groups.A-first)" 'T1 manifest A-first count'
assert_eq 0 "$(jget "$T1MAN" groups.B-first)" 'T1 manifest B-first count'
assert_eq 'event-ob01' "$(jget "$T1MAN" terminals.0.name)" 'T1 manifest terminal name'
assert_eq 'A-first' "$(jget "$T1MAN" terminals.0.group)" 'T1 manifest group'
assert_eq 'A' "$(jget "$T1MAN" terminals.0.primary_vps)" 'T1 manifest primary role A'
assert_eq 'B' "$(jget "$T1MAN" terminals.0.backup_vps)" 'T1 manifest backup role B'
assert_eq 'event-ob01-ha.yaml' "$(jget "$T1MAN" terminals.0.output)" 'T1 manifest output name'
assert_eq "$(sha256 "$T1OUT")" "$(jget "$T1MAN" terminals.0.output_sha256)" \
    'T1 manifest SHA-256 matches the delivered file'
assert_eq "$(size_of "$T1OUT")" "$(jget "$T1MAN" terminals.0.output_bytes)" \
    'T1 manifest byte count matches the delivered file'
assert_eq "$(sha256 "$T1/terminals.csv")" "$(jget "$T1MAN" inventory_sha256)" \
    'T1 manifest records the inventory SHA-256'
assert_eq 'tools/mihomo-multi-vps-merge.py' "$(jget "$T1MAN" canonical_validator)" \
    'T1 manifest records the canonical validator'
assert_eq 16 "$("$PY" -c 'import sys;print(len(sys.argv[1]))' "$(jget "$T1MAN" vps_sources.A.fingerprint_sha256_16)")" \
    'T1 manifest records a 16-hex A source fingerprint'
if [ "$(jget "$T1MAN" vps_sources.A.fingerprint_sha256_16)" = \
     "$(jget "$T1MAN" vps_sources.B.fingerprint_sha256_16)" ]; then
    fail 'T1 A and B fingerprints differ'
else
    pass 'T1 A and B source fingerprints differ'
fi
assert_eq 2 "$("$PY" -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["rollback"]["files"]))' "$T1MAN")" \
    'T1 rollback receipt lists the profile and the manifest'
assert_contains "$("$PY" -c 'import json,sys;print(" ".join(json.load(open(sys.argv[1]))["rollback"]["files"]))' "$T1MAN")" \
    'event-ob01-ha.yaml' 'T1 rollback receipt names the profile'
assert_eq 'False' "$(jget "$T1MAN" terminals.0.hy2_hopping.primary)" \
    'T1 manifest records no primary HY2 hopping'
assert_no_secret 'T1 success output and manifest leak nothing'
# Manifest is never credential-bearing: it is JSON, not a profile.
assert_absent "$("$PY" -c 'import sys;print(open(sys.argv[1],encoding="utf-8").read())' "$T1MAN")" \
    '"uuid"' 'T1 manifest carries no uuid field'
if [ "$POSIX_HOST" = "1" ]; then
    assert_eq 600 "$(stat -c '%a' "$T1OUT")" 'T1 profile mode is 0600'
    assert_eq 600 "$(stat -c '%a' "$T1MAN")" 'T1 manifest mode is 0600'
else
    skip 'T1 POSIX permission-bit assertions (NTFS carries no POSIX mode)'
fi

section 'T1b complete HY2 hopping preservation'
HOP_ALL=1
T1H="$TMP/t1hop"
mk_tree "$T1H" 1 1
read -r -a T1HARGS <<< "$(in_args "$T1H" hop-r1)"
expect_ok_lines 1 1 0 hop-r1 'T1b hopping batch succeeds' "${T1HARGS[@]}"
T1HOUT="$T1H/delivery/event-ob01-ha.yaml"
HOP_A_LINE="$(grep '^    ports: ' "$T1H/exports/A/event-ob01-mihomo.yaml")"
HOP_B_LINE="$(grep '^    ports: ' "$T1H/exports/B/event-ob01-mihomo.yaml")"
assert_contains "$(block_of "$T1HOUT" Hysteria2)" "$HOP_A_LINE" \
    'T1b primary HY2 keeps its hopping range'
assert_contains "$(block_of "$T1HOUT" Hysteria2)" '    hop-interval: 30' \
    'T1b primary HY2 keeps hop-interval 30'
assert_contains "$(block_of "$T1HOUT" Backup-Hysteria2)" "$HOP_B_LINE" \
    'T1b backup HY2 keeps its own hopping range'
assert_contains "$(block_of "$T1HOUT" Backup-Hysteria2)" '    hop-interval: 30' \
    'T1b backup HY2 keeps hop-interval 30'
assert_eq 'True' "$(jget "$T1H/delivery/ha-delivery-hop-r1.json" terminals.0.hy2_hopping.primary)" \
    'T1b manifest records primary HY2 hopping'
assert_eq 'True' "$(jget "$T1H/delivery/ha-delivery-hop-r1.json" terminals.0.hy2_hopping.backup)" \
    'T1b manifest records backup HY2 hopping'
HOP_ALL=0

# ------------------------------------------------------- T2 single B-first ---
section 'T2 single B-first terminal'
HOP_ALL=3
T2="$TMP/t2"
mk_tree "$T2" 1 0
read -r -a T2ARGS <<< "$(in_args "$T2")"
expect_ok_lines 1 0 1 test-r1 'T2 one B-first terminal succeeds' "${T2ARGS[@]}"
T2OUT="$T2/delivery/event-ob01-ha.yaml"
T2MAN="$T2/delivery/ha-delivery-test-r1.json"
"$PY" "$MERGE" --name event-ob01 --primary "$T2/exports/B/event-ob01-mihomo.yaml" \
    --backup "$T2/exports/A/event-ob01-mihomo.yaml" --output "$TMP/t2-merge.yaml" >/dev/null
assert_diff "$TMP/t2-merge.yaml" "$T2OUT" 'T2 output is exactly the B-primary merge'
assert_eq "$SERVER_B" "$(block_of "$T2OUT" Reality | awk '/^    server: /{print $2}')" \
    'T2 B-first primary Reality is VPS B'
assert_eq "$SERVER_A" "$(block_of "$T2OUT" Backup-Reality | awk '/^    server: /{print $2}')" \
    'T2 B-first backup Reality is VPS A'
assert_eq 'B' "$(jget "$T2MAN" terminals.0.primary_vps)" 'T2 manifest primary role B'
assert_eq 'A' "$(jget "$T2MAN" terminals.0.backup_vps)" 'T2 manifest backup role A'
assert_contains "$(block_of "$T2OUT" Hysteria2)" \
    "$(grep '^    ports: ' "$T2/exports/B/event-ob01-mihomo.yaml")" \
    'T2 B-primary HY2 keeps its hopping range'
assert_no_secret 'T2 success output leaks nothing'
HOP_ALL=0

# ------------------------------------------------------ T3 two terminals -----
section 'T3 two-terminal mixed batch'
HOP_ALL=0
T3="$TMP/t3"
mk_tree "$T3" 2 1
read -r -a T3ARGS <<< "$(in_args "$T3")"
expect_ok_lines 2 1 1 test-r1 'T3 mixed two-terminal batch succeeds' "${T3ARGS[@]}"
assert_eq 2 "$(count_outputs "$T3/delivery")" 'T3 writes two profiles'
assert_eq 3 "$(count_entries "$T3/delivery")" 'T3 writes two profiles and one manifest'
assert_eq 2 "$(jget "$T3/delivery/ha-delivery-test-r1.json" terminal_count)" \
    'T3 manifest terminal_count'
assert_eq 'event-ob02' "$(jget "$T3/delivery/ha-delivery-test-r1.json" terminals.1.name)" \
    'T3 manifest keeps the inventory order'
assert_eq 'B' "$(jget "$T3/delivery/ha-delivery-test-r1.json" terminals.1.primary_vps)" \
    'T3 second terminal is B-primary'

# ----------------------------------------------------- T4 sixteen terminals ---
section 'T4 sixteen-terminal batch'
HOP_ALL=0
T4="$TMP/t16"
mk_tree "$T4" 16 8
read -r -a T4ARGS <<< "$(in_args "$T4" h16-r1)"
expect_ok_lines 16 8 8 h16-r1 'T4 sixteen terminals succeed' "${T4ARGS[@]}"
assert_eq 16 "$(count_outputs "$T4/delivery")" 'T4 writes sixteen profiles'
assert_eq 8 "$(jget "$T4/delivery/ha-delivery-h16-r1.json" groups.A-first)" \
    'T4 A-first allocation'
assert_eq 8 "$(jget "$T4/delivery/ha-delivery-h16-r1.json" groups.B-first)" \
    'T4 B-first allocation'
T4BAD=$("$PY" - "$T4/delivery/ha-delivery-h16-r1.json" "$T4/delivery" <<'PY'
import hashlib
import json
import os
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
bad = []
for entry in doc["terminals"]:
    path = os.path.join(sys.argv[2], entry["output"])
    data = open(path, "rb").read()
    if hashlib.sha256(data).hexdigest() != entry["output_sha256"]:
        bad.append(entry["name"] + ":sha")
    names = [line[10:] for line in data.decode("utf-8").splitlines()
             if line.startswith("  - name: ")]
    if names[:4] != ["Reality", "Hysteria2", "Backup-Reality",
                     "Backup-Hysteria2"]:
        bad.append(entry["name"] + ":order")
print(",".join(bad))
PY
)
assert_eq '' "$T4BAD" 'T4 every delivered profile matches its manifest hash and node order'

# -------------------------------------------------------- T5 thirty terminals --
section 'T5 thirty-terminal batch'
HOP_ALL=0
LEGACY_ALL=0
T5="$TMP/t30"
mk_tree "$T5" 30 16
read -r -a T5ARGS <<< "$(in_args "$T5" h30-r1)"
expect_ok_lines 30 16 14 h30-r1 'T5 thirty terminals succeed' "${T5ARGS[@]}"
T5OUT="$T5/delivery/ha-delivery-h30-r1.json"
assert_eq 30 "$(count_outputs "$T5/delivery")" 'T5 writes thirty profiles'
assert_eq 31 "$(count_entries "$T5/delivery")" 'T5 writes thirty profiles and one manifest'
assert_eq 30 "$(jget "$T5OUT" terminal_count)" 'T5 manifest terminal_count'
assert_eq 16 "$(jget "$T5OUT" groups.A-first)" 'T5 A-first allocation'
assert_eq 14 "$(jget "$T5OUT" groups.B-first)" 'T5 B-first allocation'
T5VERDICT=$("$PY" - "$T5OUT" "$T5/exports" "$T5/delivery" <<'PY'
import hashlib
import json
import os
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
bad = []
hops = {"A": 0, "B": 0}
for entry in doc["terminals"]:
    name = entry["name"]
    out_path = os.path.join(sys.argv[3], entry["output"])
    data = open(out_path, "rb").read()
    text = data.decode("utf-8")
    if hashlib.sha256(data).hexdigest() != entry["output_sha256"]:
        bad.append(name + ":sha")
    blocks = {}
    current = None
    for line in text.splitlines():
        if line.startswith("  - name: "):
            current = line[10:]
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    nodes = ["Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2"]
    if [key for key in blocks if key in nodes] != nodes:
        bad.append(name + ":order")
    for role, node in (("primary", "Reality"), ("backup", "Backup-Reality")):
        vps = entry[role + "_vps"]
        source = os.path.join(sys.argv[2], vps, name + "-mihomo.yaml")
        source_text = open(source, encoding="utf-8").read()
        server = [line.split(": ", 1)[1] for line in source_text.splitlines()
                  if line.startswith("    server: ")][0]
        seen = [line.split(": ", 1)[1] for line in blocks[node]
                if line.startswith("    server: ")]
        if seen != [server]:
            bad.append(name + ":" + role + ":server")
    for node, hopped in (("Hysteria2", entry["hy2_hopping"]["primary"]),
                         ("Backup-Hysteria2", entry["hy2_hopping"]["backup"])):
        vps = entry["primary_vps"] if node == "Hysteria2" else entry["backup_vps"]
        source_text = open(os.path.join(
            sys.argv[2], vps, name + "-mihomo.yaml"), encoding="utf-8").read()
        ports = [line for line in source_text.splitlines()
                 if line.startswith("    ports: ")]
        block = "\n".join(blocks[node])
        if hopped != bool(ports):
            bad.append(name + ":" + node + ":hop-flag")
        if ports:
            hops[vps] += 1
            if ports[0] not in block or "    hop-interval: 30" not in block:
                bad.append(name + ":" + node + ":hop")
        elif "    ports: " in block:
            bad.append(name + ":" + node + ":unexpected-hop")
    if "    interval: 60" not in text:
        bad.append(name + ":interval")
    if '    up: "300 Mbps"' in text or '    down: "300 Mbps"' in text:
        bad.append(name + ":legacy-bandwidth")
print(",".join(bad) if bad else "ok:%d:%d" % (hops["A"], hops["B"]))
PY
)
case "$T5VERDICT" in
    ok:*) pass "T5 every profile hash/order/server/hopping/60s matches (hops ${T5VERDICT#ok:})" ;;
    *) fail "T5 delivery verdict [$T5VERDICT]" ;;
esac
assert_absent "$("$PY" -c 'import sys;print(open(sys.argv[1],encoding="utf-8").read())' "$T5OUT")" \
    "$SERVER_A" 'T5 manifest records no A server address'
assert_absent "$("$PY" -c 'import sys;print(open(sys.argv[1],encoding="utf-8").read())' "$T5OUT")" \
    "$SERVER_B" 'T5 manifest records no B server address'
assert_absent "$(cat "$T5OUT")" '1111-2222-3333' 'T5 manifest records no UUID'
assert_absent "$(cat "$T5OUT")" 'ha-A-' 'T5 manifest records no password'
assert_absent "$(cat "$T5OUT")" 'proxies:' 'T5 manifest carries no profile body'
assert_no_secret 'T5 success output and manifest leak nothing'

# --------------------------------------------------------- T6 no-clobber ----
section 'T6 no-clobber and case-insensitive collisions'
T6MAN_BEFORE="$(sha256 "$T1MAN")"
expect_code E_OUTPUT_EXISTS 'T6a rerun refuses an existing delivery' "${T1ARGS[@]}"
assert_eq "$T6MAN_BEFORE" "$(sha256 "$T1MAN")" 'T6a failed rerun left the manifest unchanged'
T6B="$TMP/t6b"
mk_tree "$T6B" 1 1
: > "$T6B/delivery/ha-delivery-test-r1.json"
read -r -a T6BARGS <<< "$(in_args "$T6B")"
expect_code E_OUTPUT_EXISTS 'T6b pre-existing manifest name is refused' "${T6BARGS[@]}"
assert_eq 1 "$(count_entries "$T6B/delivery")" 'T6b manifest collision wrote no profile'
T6C="$TMP/t6c"
mk_tree "$T6C" 2 1
: > "$T6C/delivery/event-ob02-ha.yaml"
read -r -a T6CARGS <<< "$(in_args "$T6C")"
expect_code E_OUTPUT_EXISTS 'T6c one existing profile fails the whole batch' "${T6CARGS[@]}"
assert_eq 1 "$(count_entries "$T6C/delivery")" 'T6c no sibling profile was written'
T6D="$TMP/t6d"
mk_tree "$T6D" 1 1
: > "$T6D/delivery/EVENT-OB01-HA.YAML"
read -r -a T6DARGS <<< "$(in_args "$T6D")"
expect_code E_OUTPUT_EXISTS 'T6d case-differing existing profile is a Windows collision' "${T6DARGS[@]}"
assert_eq 0 "$(count_outputs "$T6D/delivery")" 'T6d case collision wrote nothing'
T6E="$TMP/t6e"
mk_tree "$T6E" 1 1
printf 'operator backup\n' > "$T6E/delivery/keep-me.txt"
read -r -a T6EARGS <<< "$(in_args "$T6E")"
expect_ok_lines 1 1 0 test-r1 'T6e unrelated existing file does not block the batch' "${T6EARGS[@]}"
assert_file "$T6E/delivery/keep-me.txt" 'T6e unrelated existing file is preserved'
assert_absent "$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["rollback"]["files"])' "$T6E/delivery/ha-delivery-test-r1.json")" \
    'keep-me.txt' 'T6e rollback receipt does not claim an unrelated file'

# ------------------------------------------------------------ T7 inventory ---
section 'T7 inventory fail-closed gates'
T7="$TMP/t7"
mk_tree "$T7" 2 1
read -r -a T7ARGS <<< "$(in_args "$T7")"
printf 'terminal,group\nevent-ob01,A-first\nevent-ob01,B-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY_DUPLICATE 'T7a duplicate terminal name' "${T7ARGS[@]}"
printf 'terminal,group\nevent-ob01,A-first\nEvent-OB01,B-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY_DUPLICATE 'T7b case-insensitive duplicate name' "${T7ARGS[@]}"
assert_contains "$ERR" 'terminal=Event-OB01' 'T7b duplicate error names the terminal only'
printf 'terminal,group\nevent-ob01,A-first\nevent-ob02,b-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7c unknown group token' "${T7ARGS[@]}"
printf 'terminal,group\nevent-ob01,A-first,extra\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7d extra column' "${T7ARGS[@]}"
printf 'terminal,group\nevent-ob01, A-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7e padded field' "${T7ARGS[@]}"
printf 'terminal,group\nevent-ob01\tA-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7f tab separator' "${T7ARGS[@]}"
printf '\357\273\277terminal,group\nevent-ob01,A-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7g UTF-8 BOM' "${T7ARGS[@]}"
printf 'terminal,group\nevent-ob01,A-first\nevent-ob02,B-first\rX\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7h lone CR inside a row' "${T7ARGS[@]}"
printf 'terminal,group\nevent-0123456789012345678901234567890,A-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7i 33-character terminal name' "${T7ARGS[@]}"
printf 'terminal,group\n-event,A-first\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7j leading separator' "${T7ARGS[@]}"
printf '# only comments\n\n' > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7k empty inventory' "${T7ARGS[@]}"
: > "$T7/terminals.csv"
expect_code E_INVENTORY 'T7l zero-byte inventory' "${T7ARGS[@]}"
"$PY" - "$T7/terminals.csv" 257 <<'PY'
import sys
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as handle:
    handle.write("terminal,group\n")
    for index in range(int(sys.argv[2])):
        handle.write("event-x%03d,A-first\n" % index)
PY
expect_code E_INVENTORY 'T7m over the terminal cap' "${T7ARGS[@]}"
# Accepted forms: comments, blank lines, CRLF and no header; order preserved.
T7B="$TMP/t7b"
mk_tree "$T7B" 2 1
printf 'terminal,group\r\n# A-first event terminal\r\nevent-ob01,A-first\r\n\r\nevent-ob02,B-first\r\n' \
    > "$T7B/terminals.csv"
read -r -a T7BARGS <<< "$(in_args "$T7B")"
expect_ok_lines 2 1 1 test-r1 'T7n CRLF + comments + blank lines accepted' "${T7BARGS[@]}"
assert_eq 'B-first' "$(jget "$T7B/delivery/ha-delivery-test-r1.json" terminals.1.group)" \
    'T7n manifest keeps inventory order'
T7C="$TMP/t7c"
mk_tree "$T7C" 2 1
printf 'event-ob02,B-first\nevent-ob01,A-first\n' > "$T7C/terminals.csv"
read -r -a T7CARGS <<< "$(in_args "$T7C")"
expect_ok_lines 2 1 1 test-r1 'T7o header-less inventory accepted' "${T7CARGS[@]}"
assert_eq 'event-ob02' "$(jget "$T7C/delivery/ha-delivery-test-r1.json" terminals.0.name)" \
    'T7o manifest follows the inventory order, not the name order'

# -------------------------------------------------------------- T8 sources ---
section 'T8 source and batch-identity gates'
T8="$TMP/t8"
mk_tree "$T8" 2 1
read -r -a T8ARGS <<< "$(in_args "$T8")"
rm -f "$T8/exports/B/event-ob02-mihomo.yaml"
expect_code E_SOURCE_MISSING 'T8a missing B source' "${T8ARGS[@]}"
assert_contains "$ERR" 'terminal=event-ob02 vps=B' 'T8a missing-source error names terminal and VPS'
assert_no_secret 'T8a missing-source error leaks nothing'
mk_tree "$T8" 2 1
rm -f "$T8/exports/A/event-ob01-mihomo.yaml"
expect_code E_SOURCE_MISSING 'T8b missing A source' "${T8ARGS[@]}"
assert_contains "$ERR" 'vps=A' 'T8b missing A source is attributed to A'
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob01-mihomo.yaml" <<'PY'
import sys
path = sys.argv[1]
data = open(path, "rb").read()
open(path, "wb").write(data[: len(data) // 2])
PY
expect_code E_SOURCE_NOT_CANONICAL 'T8c truncated export' "${T8ARGS[@]}"
assert_contains "$ERR" 'vps=A' 'T8c truncated A export is attributed to A'
assert_no_secret 'T8c truncated-source error leaks no source bytes'
mk_tree "$T8" 2 1
: > "$T8/exports/B/event-ob02-mihomo.yaml"
expect_code E_SOURCE_NOT_CANONICAL 'T8d empty export' "${T8ARGS[@]}"
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob01-mihomo.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("\nproxies:\n", "\nexternal-controller: 127.0.0.1:9090\nproxies:\n", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
expect_code E_SOURCE_NOT_CANONICAL 'T8e extra top-level key' "${T8ARGS[@]}"
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob01-mihomo.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text.replace("\n", "\r\n"))
PY
expect_code E_SOURCE_NOT_CANONICAL 'T8f CRLF export (not canonical bytes)' "${T8ARGS[@]}"
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob01-mihomo.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
extra = """  - name: Extra
    type: socks5
    server: 192.0.2.55
    port: 1080
"""
open(path, "w", encoding="utf-8", newline="").write(
    text.replace("\nproxy-groups:\n", "\n" + extra + "\nproxy-groups:\n", 1))
PY
expect_code E_SOURCE_NOT_CANONICAL 'T8g extra proxy block' "${T8ARGS[@]}"
mk_tree "$T8" 2 1
cp "$T8/exports/A/event-ob01-mihomo.yaml" "$T8/exports/B/event-ob01-mihomo.yaml"
expect_code E_SOURCE_COLLISION 'T8h same VPS posing as both sources' "${T8ARGS[@]}"
assert_no_secret 'T8h collision error leaks no addresses'
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob01-mihomo.yaml" "$(uuid_a 1)" "$(pw_a 1)" <<'PY'
import sys
path, uuid_a1, pw_a1 = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
text = text.replace("203.0.113.7", "192.0.2.10")
text = text.replace(uuid_a1, "1aaaaaaa-1111-2222-3333-0000000000aa")
text = text.replace(pw_a1, "ha-C-01-rrrrrrrrrrrrrrrrrrrrrrrr")
open(path, "w", encoding="utf-8", newline="").write(text)
PY
expect_code E_SOURCE_MIXED 'T8i A-side source from a third VPS' "${T8ARGS[@]}"
assert_contains "$ERR" 'vps=A' 'T8i mixed A batch is attributed to A'
assert_contains "$ERR" 'distinct=2' 'T8i mixed A batch reports the distinct source count'
assert_no_secret 'T8i mixed-source error leaks no addresses'
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/B/event-ob02-mihomo.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("198.51.100.9", "192.0.2.77")
open(path, "w", encoding="utf-8", newline="").write(text)
PY
expect_code E_SOURCE_MIXED 'T8j B-side source from a third VPS' "${T8ARGS[@]}"
assert_contains "$ERR" 'vps=B' 'T8j mixed B batch is attributed to B'
mk_tree "$T8" 2 1
cp "$T8/exports/A/event-ob02-mihomo.yaml" "$T8/exports/A/event-ob01-mihomo.yaml"
expect_code E_CREDENTIAL_REUSE 'T8k reused credential across terminals on one VPS' "${T8ARGS[@]}"
assert_contains "$ERR" 'detail=uuid' 'T8k reuse is reported as a uuid reuse'
assert_no_secret 'T8k credential-reuse error leaks no credential'
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/A/event-ob02-mihomo.yaml" "$(pw_a 2)" "$(pw_a 1)" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text.replace(old, new))
PY
expect_code E_CREDENTIAL_REUSE 'T8l reused HY2 password across terminals' "${T8ARGS[@]}"
assert_contains "$ERR" 'detail=password' 'T8l reuse is reported as a password reuse'
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/B/event-ob01-mihomo.yaml" "$(uuid_b 1)" "$(uuid_a 1)" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text.replace(old, new))
PY
expect_code E_CREDENTIAL_REUSE 'T8m same UUID on A and B of one terminal' "${T8ARGS[@]}"
mk_tree "$T8" 2 1
"$PY" - "$T8/exports/B/event-ob02-mihomo.yaml" "$(pw_b 2)" "$(pw_a 1)" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text.replace(old, new))
PY
expect_code E_CREDENTIAL_REUSE 'T8n password shared across VPS and terminal' "${T8ARGS[@]}"
if [ "$POSIX_HOST" = "1" ]; then
    mk_tree "$T8" 1 1
    chmod 000 "$T8/exports/A/event-ob01-mihomo.yaml"
    read -r -a T8ARGS <<< "$(in_args "$T8")"
    expect_code E_SOURCE_NOT_CANONICAL 'T8o unreadable source fails closed' "${T8ARGS[@]}"
    assert_contains "$ERR" 'vps=A' 'T8o unreadable source is attributed to A'
    mk_tree "$T8" 1 1
    rm -f "$T8/exports/A/event-ob01-mihomo.yaml"
    ln -s "$T8/exports/B/event-ob01-mihomo.yaml" "$T8/exports/A/event-ob01-mihomo.yaml"
    expect_code E_SOURCE_NOT_CANONICAL 'T8p symlinked source is refused' "${T8ARGS[@]}"
else
    skip 'T8o/T8p POSIX mode and symlink source gates (NTFS path semantics)'
fi

# ---------------------------------------------------------------- T9 paths ---
section 'T9 path conflict gates'
T9="$TMP/t9"
mk_tree "$T9" 1 1
run_batch --inventory "$T9/terminals.csv" --exports "$T9/exports" \
    --output-dir "$T9/exports/A" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T9a output directory is a source directory' \
    || fail "T9a (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T9/terminals.csv" --exports "$T9/exports" \
    --output-dir "$T9/exports/B/inside" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T9b output directory inside a source directory' \
    || fail "T9b (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T9/terminals.csv" --exports "$T9/exports" \
    --output-dir "$T9/missing" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T9c missing output directory is refused' \
    || fail "T9c (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T9/terminals.csv" --exports "$T9/noexports" \
    --output-dir "$T9/delivery" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=exports-root' ] \
    && pass 'T9d missing exports root is refused' \
    || fail "T9d (rc=$RC stderr=[$ERR])"
T9E="$TMP/t9e"
mk_tree "$T9E" 1 1
rm -rf "$T9E/exports/A"
run_batch --inventory "$T9E/terminals.csv" --exports "$T9E/exports" \
    --output-dir "$T9E/delivery" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=exports-A' ] \
    && pass 'T9e missing A source tree is refused' \
    || fail "T9e (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T9" --exports "$T9/exports" \
    --output-dir "$T9/delivery" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_INVENTORY' ] \
    && pass 'T9f inventory path that is a directory is refused' \
    || fail "T9f (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T9/terminals.csv" --exports "$T9/exports" \
    --output-dir "$T9/terminals.csv" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T9g output path that is a file is refused' \
    || fail "T9g (rc=$RC stderr=[$ERR])"
T9H="$TMP/t9h"
mk_tree "$T9H" 1 1
cp "$T9H/terminals.csv" "$T9H/delivery/event-ob01-ha.yaml"
chmod 600 "$T9H/delivery/event-ob01-ha.yaml" 2>/dev/null || true
run_batch --inventory "$T9H/delivery/event-ob01-ha.yaml" --exports "$T9H/exports" \
    --output-dir "$T9H/delivery" --config-version test-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT terminal=event-ob01' ] \
    && pass 'T9h inventory cannot also be a delivery target' \
    || fail "T9h (rc=$RC stderr=[$ERR])"
if [ "$POSIX_HOST" = "1" ]; then
    T9S="$TMP/t9s"
    mk_tree "$T9S" 1 1
    ln -s "$T9S/exports" "$T9S/exports-link"
    run_batch --inventory "$T9S/terminals.csv" --exports "$T9S/exports-link" \
        --output-dir "$T9S/delivery" --config-version test-r1
    [ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-batch: FAIL E_PATH_CONFLICT role=exports-root' ] \
        && pass 'T9i symlinked exports root is refused' \
        || fail "T9i (rc=$RC stderr=[$ERR])"
else
    skip 'T9i symlinked exports root (NTFS reparse semantics)'
fi

# ---------------------------------------------------------- T10 permissions ---
section 'T10 private-directory enforcement'
if [ "$POSIX_HOST" = "1" ]; then
    T10="$TMP/t10"
    mk_tree "$T10" 1 1
    read -r -a T10ARGS <<< "$(in_args "$T10")"
    chmod 755 "$T10/exports"
    expect_code E_INSECURE_PERMISSIONS 'T10a exports root mode 0755 refused' "${T10ARGS[@]}"
    assert_contains "$ERR" 'role=exports-root' 'T10a error names the exports root'
    assert_contains "$ERR" 'mode=755' 'T10a error reports the actual mode'
    chmod 700 "$T10/exports"
    chmod 755 "$T10/exports/A"
    expect_code E_INSECURE_PERMISSIONS 'T10b A source tree mode 0755 refused' "${T10ARGS[@]}"
    assert_contains "$ERR" 'role=exports-A' 'T10b error names the A source tree'
    chmod 700 "$T10/exports/A"
    chmod 644 "$T10/exports/A/event-ob01-mihomo.yaml"
    expect_code E_INSECURE_PERMISSIONS 'T10c source file mode 0644 refused' "${T10ARGS[@]}"
    assert_contains "$ERR" 'role=source-A' 'T10c error names the A source role'
    chmod 600 "$T10/exports/A/event-ob01-mihomo.yaml"
    chmod 640 "$T10/terminals.csv"
    expect_code E_INSECURE_PERMISSIONS 'T10d inventory mode 0640 refused' "${T10ARGS[@]}"
    assert_contains "$ERR" 'role=inventory' 'T10d error names the inventory'
    chmod 600 "$T10/terminals.csv"
    chmod 755 "$T10/delivery"
    expect_code E_INSECURE_PERMISSIONS 'T10e output directory mode 0755 refused' "${T10ARGS[@]}"
    assert_contains "$ERR" 'role=output-dir' 'T10e error names the output directory'
    chmod 700 "$T10/delivery"
    expect_ok_lines 1 1 0 test-r1 'T10f restored modes generate cleanly' "${T10ARGS[@]}"
else
    skip 'T10a-T10f POSIX mode gates (NTFS carries no POSIX mode)'
fi

# Real Windows ACL: a well-known shared directory is refused by reading its
# actual DACL from the kernel. No ACL is modified by this suite.
if [ "$IS_WINDOWS" = "1" ]; then
    PUBLIC_DIR="$(cygpath -w /c/Users/Public 2>/dev/null || printf 'C:\\Users\\Public')"
    T10W="$TMP/t10w"
    mk_tree "$T10W" 1 1
    run_batch --inventory "$T10W/terminals.csv" --exports "$PUBLIC_DIR" \
        --output-dir "$T10W/delivery" --config-version test-r1
    if [ "$RC" -ne 0 ] && [ "${ERR1#ha-batch: FAIL E_INSECURE_PERMISSIONS role=exports-root}" != "$ERR1" ] \
       && [ "${ERR1#*sid=S-1-5-}" != "$ERR1" ]; then
        pass "T10g real broad Windows ACL on the exports root is refused"
    else
        fail "T10g (rc=$RC stderr=[$ERR])"
    fi
    T10W2="$TMP/t10w2"
    mk_tree "$T10W2" 1 1
    read -r -a T10W2ARGS <<< "$(in_args "$T10W2")"
    expect_ok_lines 1 1 0 test-r1 'T10h private Windows ACL passes' "${T10W2ARGS[@]}"
    assert_eq 'windows-acl' "$(jget "$T10W2/delivery/ha-delivery-test-r1.json" permission_gate)" \
        'T10h manifest records the Windows ACL gate'
else
    skip 'T10g/T10h real Windows ACL gates (not a Windows host)'
fi
# The SDDL classifier is platform-independent and unit-tested on every host.
SDDL_VERDICT=$("$PY" - "$TOOL" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("batch", sys.argv[1])
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
user = "S-1-5-21-1-2-3-1001"
cases = [
    ("broad-everyone", "O:%sD:PAI(A;OICI;FA;;;WD)" % user, ["sid=S-1-1-0"]),
    ("broad-users", "O:%sD:PAI(A;OICI;FA;;;BU)" % user, ["sid=S-1-5-32-545"]),
    ("broad-interactive", "O:%sD:PAI(A;OICI;0x1200a9;;;IU)" % user,
     ["sid=S-1-5-4"]),
    ("broad-service", "O:%sD:PAI(A;OICIIO;0x1301ff;;;SU)" % user,
     ["sid=S-1-5-6"]),
    ("broad-domain-users", "O:%sD:PAI(A;OICI;FA;;;S-1-5-21-9-8-7-513)" % user,
     ["sid=S-1-5-21-9-8-7-513"]),
    ("null-dacl", "O:SYD:NO_ACCESS_CONTROL", ["null-dacl"]),
    ("owner-elsewhere", "O:S-1-5-21-9-8-7-1001D:PAI(A;OICI;FA;;;SY)", ["owner="]),
    ("private", "O:%sD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                "(A;OICI;FA;;;%s)" % (user, user), []),
    ("creator-owner", "O:%sD:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)"
                      "(A;OICI;FA;;;%s)" % (user, user), []),
    ("deny-everyone", "O:%sD:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)"
                      "(A;OICI;FA;;;%s)" % (user, user), []),
]
bad = []
for label, sddl, expected in cases:
    problems = batch.sddl_problems(sddl, sddl[2:sddl.index("D:")], user)
    if expected and not any(p.startswith(expected[0]) for p in problems):
        bad.append(label + ":want=" + expected[0] + " got=" + ",".join(problems))
    if not expected and problems:
        bad.append(label + ":unexpected=" + ",".join(problems))
print("ok" if not bad else ";".join(bad))
PY
)
assert_eq 'ok' "$SDDL_VERDICT" 'T10i SDDL classifier: broad/private/null/owner cases'

# --------------------------------------------------------------- T11 usage ---
section 'T11 usage, argv hygiene and tool presence'
T11="$TMP/t11"
mk_tree "$T11" 1 1
run_batch --inventory "$T11/terminals.csv" --exports "$T11/exports" \
    --output-dir "$T11/delivery"
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] && [ -z "$OUT" ] \
    && pass 'T11a missing option -> E_USAGE exit 2' || fail "T11a (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T11/terminals.csv" --exports "$T11/exports" \
    --output-dir "$T11/delivery" --config-version test-r1 \
    --password 'ha-B-01-qqqqqqqqqqqqqqqqqqqqqqqq'
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] \
    && assert_absent "$OUT$ERR" 'qqqqqqqq' 'T11b unknown option never echoes argv' \
    || fail "T11b (rc=$RC stderr=[$ERR])"
run_batch "$T11/terminals.csv"
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] \
    && assert_absent "$OUT$ERR" "$T11" 'T11c bare positional never echoes the path' \
    || fail "T11c (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T11/terminals.csv" --exports "$T11/exports" \
    --output-dir "$T11/delivery" --config-version ../escape
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] \
    && pass 'T11d path-traversal version label refused' || fail "T11d (rc=$RC stderr=[$ERR])"
run_batch --inventory "$T11/terminals.csv" --exports "$T11/exports" \
    --output-dir "$T11/delivery" --config-version ''
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] \
    && pass 'T11e empty version label refused' || fail "T11e (rc=$RC stderr=[$ERR])"
LONGVER="$(printf 'v%.0s' $(seq 1 65))"
run_batch --inventory "$T11/terminals.csv" --exports "$T11/exports" \
    --output-dir "$T11/delivery" --config-version "$LONGVER"
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] \
    && pass 'T11f over-long version label refused' || fail "T11f (rc=$RC stderr=[$ERR])"
run_batch --help
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-batch: FAIL E_USAGE' ] && [ -z "$OUT" ] \
    && pass 'T11g --help stays a silent usage failure' || fail "T11g (rc=$RC out=[$OUT])"
mkdir -p "$TMP/toolonly"
cp "$TOOL" "$TMP/toolonly/"
read -r -a T11ARGS <<< "$(in_args "$T11")"
"$PY" "$TMP/toolonly/mihomo-competition-ha-batch.py" "${T11ARGS[@]}" \
    >"$LOGS/toolonly.out" 2>"$LOGS/toolonly.err"
TOOLONLY_RC=$?
TOOLONLY_ERR="$(tr -d '\r' < "$LOGS/toolonly.err")"
[ "$TOOLONLY_RC" -eq 1 ] && [ "$TOOLONLY_ERR" = 'ha-batch: FAIL E_TOOL_MISSING' ] \
    && pass 'T11h missing canonical merge tool is a fixed failure' \
    || fail "T11h (rc=$TOOLONLY_RC stderr=[$TOOLONLY_ERR])"
assert_absent "$("$PY" -c 'import sys;print(open(sys.argv[1]).read())' "$LOGS/toolonly.err")" \
    'Traceback' 'T11h no traceback without the canonical parser'
assert_eq 0 "$(count_outputs "$T11/delivery")" 'T11 usage failures wrote nothing'

# ------------------------------------------------------------ T12 rollback ---
section 'T12 rollback of this batch''s own files'
ROLLBACK_DRIVER='
import importlib.util
import sys
tool, inventory, exports, delivery, fail_at, mode = sys.argv[1:7]
spec = importlib.util.spec_from_file_location("batch", tool)
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
merge = batch.load_merge_tool()
real = merge.write_output
calls = {"n": 0}
def flaky(payload, path):
    calls["n"] += 1
    if calls["n"] == int(fail_at):
        if mode == "exists":
            raise merge.MergeError("E_OUTPUT_EXISTS")
        raise OSError("injected")
    real(payload, path)
merge.write_output = flaky
if mode == "unlink":
    import os
    real_unlink = batch.os.unlink
    state = {"n": 0}
    def flaky_unlink(path):
        # The atomic writer cleans its own private temp file in a finally
        # block; only the delivery files are the rollback under test.
        if os.path.basename(path).startswith(".mihomo-merge-"):
            return real_unlink(path)
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("injected unlink")
        real_unlink(path)
    batch.os.unlink = flaky_unlink
try:
    batch.generate(inventory, exports, delivery, "test-r1", merge=merge)
    print("res code=NONE removed=0 complete=yes")
except batch.BatchError as exc:
    print("res code=%s removed=%d complete=%s" % (
        exc.code, exc.rollback["removed"],
        "yes" if exc.rollback["complete"] else "no"))
'
rollback_case() { # <root> <fail_at> <mode> ; echoes driver output
    "$PY" -c "$ROLLBACK_DRIVER" "$TOOL" "$1/terminals.csv" "$1/exports" \
        "$1/delivery" "$2" "$3" 2>&1 | tr -d '\r'
}
T12="$TMP/t12"
mk_tree "$T12" 3 2
printf 'operator note\n' > "$T12/delivery/keep-me.txt"
printf 'previous delivery\n' > "$T12/delivery/event-ob99-ha.yaml"
R12="$(rollback_case "$T12" 2 oserror)"
assert_contains "$R12" 'code=E_IO removed=1 complete=yes' \
    'T12a a mid-batch write failure rolls back the created profile'
assert_eq 2 "$(count_entries "$T12/delivery")" 'T12a only the pre-existing files remain'
assert_file "$T12/delivery/keep-me.txt" 'T12a unrelated file preserved'
assert_file "$T12/delivery/event-ob99-ha.yaml" 'T12a existing delivery preserved'
T12B="$TMP/t12b"
mk_tree "$T12B" 3 2
R12B="$(rollback_case "$T12B" 4 oserror)"
assert_contains "$R12B" 'code=E_IO removed=3 complete=yes' \
    'T12b a manifest write failure rolls back every profile'
assert_eq 0 "$(count_entries "$T12B/delivery")" 'T12b the delivery directory is empty again'
T12C="$TMP/t12c"
mk_tree "$T12C" 3 2
R12C="$(rollback_case "$T12C" 1 exists)"
assert_contains "$R12C" 'code=E_OUTPUT_EXISTS removed=0 complete=yes' \
    'T12c a no-clobber failure at write time reports E_OUTPUT_EXISTS'
assert_eq 0 "$(count_entries "$T12C/delivery")" 'T12c nothing was left behind'
T12D="$TMP/t12d"
mk_tree "$T12D" 3 2
R12D="$(rollback_case "$T12D" 2 unlink)"
assert_contains "$R12D" 'code=E_IO removed=0 complete=no' \
    'T12d an incomplete rollback is reported as complete=no'
assert_eq 1 "$(count_entries "$T12D/delivery")" \
    'T12d the file that could not be removed is still listed for the operator'

# -------------------------------------------------------- T13 redaction -----
section 'T13 redaction under failure'
T13="$TMP/t13"
mk_tree "$T13" 2 1
cp "$T13/exports/A/event-ob02-mihomo.yaml" "$T13/exports/A/event-ob01-mihomo.yaml"
read -r -a T13ARGS <<< "$(in_args "$T13")"
expect_code E_CREDENTIAL_REUSE 'T13a credential reuse refused' "${T13ARGS[@]}"
assert_no_secret 'T13a credential error carries no credential, address or YAML'
assert_absent "$ERR" "${T13}" 'T13a credential error echoes no local path'
T13B="$TMP/t13b"
mk_tree "$T13B" 2 1
rm -f "$T13B/exports/B/event-ob02-mihomo.yaml"
read -r -a T13BARGS <<< "$(in_args "$T13B")"
expect_code E_SOURCE_MISSING 'T13b missing source refused' "${T13BARGS[@]}"
assert_no_secret 'T13b missing-source error carries no credential'
for manifest in "$T1MAN" "$T5OUT"; do
    [ -f "$manifest" ] || continue
    assert_absent "$(cat "$manifest")" '3333-' "T13c $(basename "$manifest") carries no UUID"
    assert_absent "$(cat "$manifest")" 'pppppppp' "T13c $(basename "$manifest") carries no password"
    assert_absent "$(cat "$manifest")" 'skip-cert-verify' "T13c $(basename "$manifest") carries no profile body"
done

# ------------------------------------- T14 legacy + single-VPS regression ----
section 'T14 legacy input and single-VPS regression'
HOP_ALL=0
LEGACY_ALL=1
T14="$TMP/t14"
mk_tree "$T14" 1 1
assert_eq 1 "$(grep -c '^    up: "300 Mbps"' "$T14/exports/A/event-ob01-mihomo.yaml")" \
    'T14a fixture really carries the historical bandwidth pair'
read -r -a T14ARGS <<< "$(in_args "$T14")"
expect_ok_lines 1 1 0 test-r1 'T14b legacy canonical export is accepted' "${T14ARGS[@]}"
T14OUT="$T14/delivery/event-ob01-ha.yaml"
assert_absent "$(cat "$T14OUT")" 'up: "300 Mbps"' 'T14b legacy bandwidth omitted from output'
"$PY" "$MERGE" --name event-ob01 --primary "$T14/exports/A/event-ob01-mihomo.yaml" \
    --backup "$T14/exports/B/event-ob01-mihomo.yaml" --output "$TMP/t14-merge.yaml" >/dev/null
assert_diff "$TMP/t14-merge.yaml" "$T14OUT" 'T14c legacy batch output matches the merge tool'
LEGACY_ALL=0
"$PY" "$MERGE" --name event-ob01 --primary "$T1/exports/A/event-ob01-mihomo.yaml" \
    --output "$TMP/t14-single.yaml" >"$LOGS/single.out" 2>"$LOGS/single.err"
assert_eq 0 "$?" 'T14d single-VPS merge still succeeds'
SINGLE_OUT="$(tr -d '\r' < "$LOGS/single.out")"
assert_eq 'merge: OK
mode: single
output: written' "$SINGLE_OUT" 'T14d single-VPS merge contract unchanged'
assert_diff "$T1/exports/A/event-ob01-mihomo.yaml" "$TMP/t14-single.yaml" \
    'T14e single-VPS output is still a byte-for-byte copy of the primary export'
T14F="$TMP/t14f"
mk_tree "$T14F" 1 1
rm -f "$T14F/exports/B/event-ob01-mihomo.yaml"
read -r -a T14FARGS <<< "$(in_args "$T14F")"
expect_code E_SOURCE_MISSING 'T14f batch mode never fabricates a single-VPS HA profile' \
    "${T14FARGS[@]}"
assert_eq 0 "$(count_outputs "$T14F/delivery")" 'T14f the missing-backup batch wrote nothing'

# ------------------------------------------------------ T15 pinned core load ---
section 'T15 pinned-core load harness gates'
T15="$TMP/t15"
mkdir -p "$T15/fake" "$T15/delivery" "$T15/work"
printf 'not a mihomo core\n' > "$T15/fake/core"
FAKE_HASH="$(sha256 "$T15/fake/core")"
run_core_load() { # <args...> ; sets RC / OUT / ERR / ERR1
    RUNS=$((RUNS + 1))
    local log="$LOGS/core$RUNS"
    "$PY" "$CORE_LOAD" "$@" >"$log.out" 2>"$log.err"
    RC=$?
    OUT="$(tr -d '\r' < "$log.out")"
    ERR="$(tr -d '\r' < "$log.err")"
    ERR1="${ERR%%$'\n'*}"
}
cp -R "$T3/delivery/." "$T15/delivery/"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 00 \
    --delivery "$T15/delivery" --workdir "$T15/work"
[ "$RC" -eq 1 ] && [ "$ERR1" = 'core-load: FAIL E_CORE_HASH' ] \
    && pass 'T15a a mismatched core hash is refused' || fail "T15a (rc=$RC stderr=[$ERR])"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/work"
[ "$RC" -eq 1 ] && [ "$ERR1" = 'core-load: FAIL E_CORE_HASH' ] \
    && pass 'T15b a non-core binary is refused before any profile load' \
    || fail "T15b (rc=$RC stderr=[$ERR])"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/missing" --expect-terminals 2
[ "$RC" -eq 2 ] && [ "$ERR1" = 'core-load: FAIL E_USAGE' ] \
    && pass 'T15c missing workdir is a usage failure' || fail "T15c (rc=$RC stderr=[$ERR])"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/work" --expect-terminals 0
[ "$RC" -eq 2 ] && [ "$ERR1" = 'core-load: FAIL E_USAGE' ] \
    && pass 'T15d zero expected terminals is a usage failure' || fail "T15d (rc=$RC stderr=[$ERR])"
rm -f "$T15/delivery/ha-delivery-test-r1.json"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/work"
[ "$RC" -eq 1 ] && [ "$ERR1" = 'core-load: FAIL E_MANIFEST' ] \
    && pass 'T15e a delivery without its manifest is refused' || fail "T15e (rc=$RC stderr=[$ERR])"
cp "$T3/delivery/ha-delivery-test-r1.json" "$T15/delivery/"
printf '\n# tampered\n' >> "$T15/delivery/event-ob01-ha.yaml"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/work"
[ "$RC" -eq 1 ] && [ "$ERR1" = 'core-load: FAIL E_PROFILE_HASH' ] \
    && pass 'T15f a profile that no longer matches the manifest is refused' \
    || fail "T15f (rc=$RC stderr=[$ERR])"
cp "$T3/delivery/event-ob01-ha.yaml" "$T15/delivery/"
run_core_load --mihomo "$T15/fake/core" --expect-sha256 "$FAKE_HASH" \
    --delivery "$T15/delivery" --workdir "$T15/work" --expect-terminals 3
[ "$RC" -eq 1 ] && [ "$ERR1" = 'core-load: FAIL E_MANIFEST' ] \
    && pass 'T15g an unexpected terminal count is refused' || fail "T15g (rc=$RC stderr=[$ERR])"
if [ -n "${HA02_MIHOMO:-}" ] && [ -n "${HA02_MIHOMO_SHA256:-}" ]; then
    T15R="$TMP/t15real"
    mkdir -p "$T15R"
    run_core_load --mihomo "$HA02_MIHOMO" --expect-sha256 "$HA02_MIHOMO_SHA256" \
        --delivery "$T5/delivery" --workdir "$T15R" --expect-terminals 30
    if [ "$RC" -eq 0 ] && [ "${OUT%%$'\n'*}" = 'core-load: OK' ]; then
        pass 'T15h pinned real core loads all thirty delivered profiles'
    else
        fail "T15h real core load (rc=$RC stderr=[$ERR])"
    fi
else
    skip 'T15h real pinned-core load (set HA02_MIHOMO and HA02_MIHOMO_SHA256)'
fi

# ------------------------------------------------------------------ summary --
section 'summary'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
