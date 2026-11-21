#!/usr/bin/env bash
# Issue #48 HA-04 -- fast-probe profile variant contract (issue #92).
#
# Scope: tools/mihomo-competition-ha4-fastprobe.py. It consumes a verified
# HA-03 competition delivery plus the HA-02 delivery and pins file, and writes a
# SECOND artifact per terminal: <name>-ha4f.yaml + ha4-fastprobe-*.json.
# The only edits are the 自动选择 group's `interval: 60` and `timeout: 5000`;
# every other byte (four-node fixed priority, 204 URL/status, lazy:false,
# HY2 pins / skip-cert-verify:false, loopback-only listeners, allow-lan:false)
# must be identical to the HA-03 competition profile.
#
# Generation and --check both run the full HA-03 preflight on the untouched
# HA-03 delivery first (HA-02 source hashes + role/pin mapping + validity
# floor + five-edit security transform). --check then re-derives the expected
# HA-04 bytes from that trusted parent and compares byte-for-byte.
#
# Sandbox only: temporary files, no network, no real credentials (TEST-NET and
# synthetic sentinels), no production. The pinned-core section runs only when
# the operator supplies a hash-pinned Mihomo binary (Linux CI does).
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/mihomo-competition-ha4-fastprobe.py"
HA03="$ROOT/tools/mihomo-competition-ha-profile.py"
HA02="$ROOT/tools/mihomo-competition-ha-batch.py"
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
assert_contains() { case "$1" in *"$2"*) pass "$3" ;; *) fail "$3 (missing [$2] in [$1])" ;; esac; }
assert_file() { [ -f "$1" ] && pass "$2" || fail "$2 (missing $1)"; }

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" --version >/dev/null 2>&1 || { printf '  FAIL no python interpreter\n'; exit 1; }

POSIX_HOST=1
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*|Windows_NT) POSIX_HOST=0 ;; esac
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

# --------------------------------------------------------------- fixtures ---
SERVER_A="203.0.113.7"
SERVER_B="198.51.100.9"
PIN_A="a111111111111111111111111111111111111111111111111111111111111111"
PIN_B="b222222222222222222222222222222222222222222222222222222222222222"
PUBKEY_A="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBKEY_B="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
SHORTID_A="0123456789abcdef"
SHORTID_B="fedcba9876543210"
HOP_ALL=0

uuid_a() { printf 'a1%06d-1111-2222-3333-%012d' "$1" "$1"; }
uuid_b() { printf 'b2%06d-1111-2222-3333-%012d' "$1" "$1"; }
pw_a() { printf 'ha-A-%02d-pppppppppppppppppppppppp' "$1"; }
pw_b() { printf 'ha-B-%02d-qqqqqqqqqqqqqqqqqqqqqqqq' "$1"; }

mk_export() { # <path> <server> <uuid> <password> <pubkey> <shortid> <ports|"">
    local out=$1 server=$2 uuid=$3 password=$4 pubkey=$5 shortid=$6 ports=$7
    local hy_ports="    port: 8444"
    if [ -n "$ports" ]; then
        hy_ports="    port: 8444
    ports: $ports
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
$hy_ports
    password: $password
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

WIN_USER_SID=""
win_current_sid() {
    if [ -z "$WIN_USER_SID" ]; then
        WIN_USER_SID=$(MSYS_NO_PATHCONV=1 /c/WINDOWS/system32/whoami.exe \
            /user /fo csv /nh 2>/dev/null | tr -d '\r' \
            | awk -F'","' '{print $2}' | tr -d '"')
    fi
    printf '%s' "$WIN_USER_SID"
}
win_private_acl() {
    [ "$IS_WINDOWS" = "1" ] || return 0
    local sid path win
    sid=$(win_current_sid)
    if [ -z "$sid" ]; then
        fail 'fixture: could not determine the Windows user SID'
        return 1
    fi
    for path in "$@"; do
        win=$(cygpath -w "$path" 2>/dev/null) || win=$path
        if ! MSYS_NO_PATHCONV=1 icacls "$win" /inheritance:r \
                /grant:r "*$sid:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" \
                "*S-1-5-32-544:(OI)(CI)F" >/dev/null 2>&1; then
            fail "fixture: icacls could not make a path private (rc=$?)"
            return 1
        fi
    done
    return 0
}
win_private_file_acl() {
    [ "$IS_WINDOWS" = "1" ] || return 0
    local sid win
    sid=$(win_current_sid)
    if [ -z "$sid" ]; then
        fail 'fixture: could not determine the Windows user SID'
        return 1
    fi
    win=$(cygpath -w "$1" 2>/dev/null) || win=$1
    MSYS_NO_PATHCONV=1 icacls "$win" /inheritance:r \
        /grant:r "*$sid:F" "*S-1-5-18:F" "*S-1-5-32-544:F" >/dev/null 2>&1
}

mk_tree() { # <dir> <count> <a_first>
    local dir=$1 count=$2 a_first=$3
    rm -rf -- "$dir"
    mkdir -p "$dir/exports/A" "$dir/exports/B" "$dir/delivery" \
        "$dir/competition"
    if [ "$POSIX_HOST" = "1" ]; then
        chmod 700 "$dir" "$dir/exports" "$dir/exports/A" "$dir/exports/B" \
            "$dir/delivery" "$dir/competition"
    fi
    win_private_acl "$dir" "$dir/exports" "$dir/exports/A" \
        "$dir/exports/B" "$dir/delivery" "$dir/competition"
    printf 'terminal,group\n' > "$dir/terminals.csv"
    local i name group hop_a hop_b
    for ((i = 1; i <= count; i++)); do
        name=$(printf 'event-ob%02d' "$i")
        if [ "$i" -le "$a_first" ]; then group=A-first; else group=B-first; fi
        printf '%s,%s\n' "$name" "$group" >> "$dir/terminals.csv"
        hop_a=""
        hop_b=""
        if [ "$HOP_ALL" = "1" ]; then
            hop_a=$(printf '%d-%d' $((40000 + i)) $((40020 + i)))
            hop_b=$(printf '%d-%d' $((41000 + i)) $((41020 + i)))
        else
            [ $((i % 3)) -eq 0 ] && hop_a=$(printf '%d-%d' $((40000 + i)) $((40020 + i)))
            [ $((i % 2)) -eq 0 ] && hop_b=$(printf '%d-%d' $((41000 + i)) $((41020 + i)))
        fi
        mk_export "$dir/exports/A/$name-mihomo.yaml" "$SERVER_A" \
            "$(uuid_a "$i")" "$(pw_a "$i")" "$PUBKEY_A" "$SHORTID_A" "$hop_a"
        mk_export "$dir/exports/B/$name-mihomo.yaml" "$SERVER_B" \
            "$(uuid_b "$i")" "$(pw_b "$i")" "$PUBKEY_B" "$SHORTID_B" "$hop_b"
    done
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$dir/terminals.csv"
}

mk_pins() { # <path> [a_pin] [b_pin]
    local path=$1 a=${2:-$PIN_A} b=${3:-$PIN_B}
    "$PY" - "$path" "$a" "$b" <<'PY'
import json
import sys
path, a, b = sys.argv[1:4]
doc = {"schema": "mihomo-competition-ha-pins/2", "vps": {
    "A": {"fingerprint_sha256": a, "not_before": "2019-01-01T00:00:00Z",
          "not_after": "2030-01-01T00:00:00Z", "source": "synthetic-test"},
    "B": {"fingerprint_sha256": b, "not_before": "2019-01-01T00:00:00Z",
          "not_after": "2030-01-01T00:00:00Z", "source": "synthetic-test"},
}}
with open(path, "w", encoding="utf-8", newline="") as handle:
    json.dump(doc, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$path"
    [ "$IS_WINDOWS" = "1" ] && win_private_file_acl "$path"
}

ha02_args() { # <root> [version]
    printf '%s ' --inventory "$1/terminals.csv" --exports "$1/exports" \
        --output-dir "$1/delivery" --config-version "${2:-ha-r1}"
}
ha03_args() { # <root> [version] [pins]
    printf '%s ' --delivery "$1/delivery" --pins "${3:-$1/pins.json}" \
        --output-dir "$1/competition" --config-version "${2:-comp-r1}"
}
h4_gen_args() { # <root> <outdir> <interval> <timeout> [competition dir]
    printf '%s ' --delivery "${5:-$1/competition}" \
        --ha02-delivery "$1/delivery" --pins "$1/pins.json" \
        --output-dir "$2" --config-version ha-r1 \
        --interval "$3" --timeout "$4"
}
h4_check_args() { # <root> <variant dir> [competition dir]
    printf '%s ' --check --delivery "$2" \
        --source-delivery "${3:-$1/competition}" \
        --ha02-delivery "$1/delivery" --pins "$1/pins.json"
}

# ----------------------------------------------------------------- runner ---
RUNS=0
RC=0
OUT=""
ERR=""
ERR1=""
run_cmd() { # <logname> <command...>
    RUNS=$((RUNS + 1))
    local log="$LOGS/$1-$RUNS"
    shift
    "$@" >"$log.out" 2>"$log.err"
    RC=$?
    OUT="$(tr -d '\r' < "$log.out")"
    ERR="$(tr -d '\r' < "$log.err")"
    ERR1="${ERR%%$'\n'*}"
}
run_ha02() { run_cmd ha02 "$PY" "$HA02" "$@"; }
run_ha03() { run_cmd ha03 "$PY" "$HA03" "$@"; }
run_h4() { run_cmd h4 "$PY" "$TOOL" "$@"; }

expect_ha02_ok() { # <root> <version> <label>
    local root=$1 version=$2 label=$3
    read -r -a args <<< "$(ha02_args "$root" "$version")"
    run_ha02 "${args[@]}"
    [ "$RC" -eq 0 ] && pass "$label" || fail "$label (rc=$RC stderr=[$ERR])"
}
expect_ha03_ok() { # <root> <version> <label>
    local root=$1 version=$2 label=$3
    read -r -a args <<< "$(ha03_args "$root" "$version")"
    run_ha03 "${args[@]}"
    [ "$RC" -eq 0 ] && pass "$label" || fail "$label (rc=$RC stderr=[$ERR])"
}
expect_h4_gen_ok() { # <root> <outdir> <interval> <timeout> <label>
    local root=$1 outdir=$2 interval=$3 timeout=$4 label=$5
    read -r -a args <<< "$(h4_gen_args "$root" "$outdir" "$interval" "$timeout")"
    run_h4 "${args[@]}"
    if [ "$RC" -eq 0 ] && [ -z "$ERR" ]; then
        assert_contains "$OUT" "policy: interval=$interval timeout=$timeout" \
            "$label output policy"
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR])"
    fi
}
expect_h4_code() { # <code> <label> <args...>
    local code=$1 label=$2
    shift 2
    run_h4 "$@"
    if [ "$RC" -ne 0 ] && [ -n "$ERR1" ] \
       && [ "${ERR1#"ha4-fastprobe: FAIL $code"}" != "$ERR1" ] \
       && [ -z "$OUT" ]; then
        pass "$label -> $code"
    else
        fail "$label (rc=$RC want=[$code] stderr=[$ERR] stdout=[$OUT])"
    fi
}

# ------------------------------------------------------------- inspection ---
h4_manifest() { ls "$1"/ha4-fastprobe-*.json 2>/dev/null | head -1; }
group_field() { # <file> <field>
    awk -v f="    $2: " '$0=="  - name: 自动选择"{g=1;next} g && $0==""{exit}
        g && index($0,f)==1{sub(f,"");print;exit}' "$1"
}
line_edit() { # <source> <variant>; prints "ok r=N a=N" (N lines removed/added)
    "$PY" - "$1" "$2" <<'PY'
import difflib
import sys
before = open(sys.argv[1], encoding="utf-8").read().split("\n")
after = open(sys.argv[2], encoding="utf-8").read().split("\n")
ops = [op for op in difflib.SequenceMatcher(None, before, after).get_opcodes()
       if op[0] != "equal"]
removed = sum(i2 - i1 for tag, i1, i2, j1, j2 in ops)
added = sum(j2 - j1 for tag, i1, i2, j1, j2 in ops)
replace_only = all(op[0] == "replace" for op in ops)
print(("ok" if replace_only else "bad") + " r=%d a=%d" % (removed, added))
PY
}
security_invariant() { # <source> <variant>
    "$PY" - "$1" "$2" <<'PY'
import sys
before = open(sys.argv[1], encoding="utf-8").read().split("\n")
after = open(sys.argv[2], encoding="utf-8").read().split("\n")
keep = ("allow-lan:", 'bind-address:', '  listen:', "    fingerprint:",
        "    skip-cert-verify:", "    alpn:", "  - name:")
b = [line for line in before if line.startswith(keep)]
a = [line for line in after if line.startswith(keep)]
print("ok" if a == b else "changed")
PY
}
node_order_ok() { # <variant>
    "$PY" - "$1" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
start = lines.index("  - name: 自动选择")
want = ["    type: fallback", "    proxies:"] + [
    "      - " + n for n in ("Reality", "Hysteria2", "Backup-Reality",
                           "Backup-Hysteria2")]
print("ok" if lines[start + 1:start + 7] == want else "bad")
PY
}
assert_absent_servers() { local text=$1 label=$2
    case "$text" in *"$SERVER_A"*|*"$SERVER_B"*|*"1111-2222-3333"*|*"ha-A-"*|*"ha-B-"*)
        fail "$label (credential/address leaked)" ;;
        *) pass "$label" ;; esac; }

# ------------------------------------------------------------- static gates --
section 'static gates'
"$PY" -m py_compile "$TOOL" && pass 'py_compile tools/mihomo-competition-ha4-fastprobe.py' \
    || fail 'py_compile failed'
assert_file "$ROOT/tests/mihomo-competition-ha4-lab.py" 'operator LAB harness present'
"$PY" -m py_compile "$ROOT/tests/mihomo-competition-ha4-lab.py" \
    && pass 'py_compile tests/mihomo-competition-ha4-lab.py' \
    || fail 'LAB harness py_compile failed'
bash -n "$0" && pass 'bash -n this suite' || fail 'bash -n this suite'
imports="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(sorted(set(re.findall(r"^(?:import|from)\s+([a-zA-Z_][\w]*)",
                                     text, re.M)))))
PY
)"
bad=""
for module in $imports; do
    case "$module" in
        __future__|hashlib|importlib|os|re|sys) ;;
        *) bad="$bad $module" ;;
    esac
done
[ -z "$bad" ] && pass "stdlib allowlist holds (imports: $imports)" \
    || fail "non-allowlisted import(s):$bad"
for module in socket ssl urllib http ftplib smtplib subprocess sched selectors \
              threading multiprocessing sqlite3 yaml base64 argparse; do
    case " $imports " in
        *" $module "*) fail "the HA-04 tool imports $module" ;;
    esac
done
pass 'no network, subprocess, third-party YAML or duplicate CLI parser imported'
for marker in 'HA03_TOOL_NAME' 'BATCH_TOOL_NAME' 'def load_module' \
              'ha03.check' 'ha03.verify_competition_profile' \
              'ha03.check_regular_private_file' 'def overlay' \
              'generic_defaults_preserved' '--ha02-delivery' \
              'not the deterministic fast-probe transform of the source'; do
    grep -qF -- "$marker" "$TOOL" \
        && pass "HA-03 reuse/security contract present [$marker]" \
        || fail "missing [$marker]"
done
for forbidden in 'def read_export' 'def parse_export' 'CANONICAL_PREFIX_LINES' \
                 'def verify_competition_profile'; do
    if grep -qF -- "$forbidden" "$TOOL"; then
        fail "the HA-04 tool duplicates HA-03 internals [$forbidden]"
    fi
done
pass 'no HA-03 canonical parser/invariant duplication'
cli_flags="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(re.findall(r'add_argument\("(--[a-z0-9-]+)"', text)))
PY
)"
assert_eq '--delivery --source-delivery --ha02-delivery --pins --output-dir --config-version --interval --timeout --check' \
    "$cli_flags" 'CLI flags are exactly the documented nine'
for forbidden in uuid password server pubkey force activate enable restart; do
    printf '%s\n' "$cli_flags" | grep -qiE -- "--$forbidden" \
        && fail "the CLI exposes a --$forbidden option" || true
done
pass 'no credential/activation/restart CLI option exists'
grep -qE 'generate_204|interval: [0-9]+|timeout: [0-9]+' "$TOOL" \
    && pass 'probe policy values are explicit constants' \
    || fail 'probe policy constants missing'

# -------------------------------------------------- T1 single A-first ---
section 'T1 single A-first fast-probe variant'
T1="$TMP/t1"
mk_tree "$T1" 1 1
mk_pins "$T1/pins.json"
expect_ha02_ok "$T1" ha-r1 'T1 HA-02 delivery generated'
expect_ha03_ok "$T1" comp-r1 'T1 HA-03 competition delivery generated'
SRC1="$T1/competition/event-ob01-hac.yaml"
SRC1_HASH=$(sha256 "$SRC1")
HA03_MAN="$(ls "$T1/competition"/ha-competition-*.json)"
HA03_MAN_HASH=$(sha256 "$HA03_MAN")
HA02_MAN="$(ls "$T1/delivery"/ha-delivery-*.json)"
HA02_MAN_HASH=$(sha256 "$HA02_MAN")
HA02_P1_HASH=$(sha256 "$T1/delivery/event-ob01-ha.yaml")
mkdir -p "$T1/variant"; win_private_acl "$T1/variant"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$T1/variant"
expect_h4_gen_ok "$T1" "$T1/variant" 3 1000 'T1 HA-04 variant generated'
OUT1="$T1/variant/event-ob01-ha4f.yaml"
MAN1="$(h4_manifest "$T1/variant")"
assert_file "$OUT1" 'T1 variant profile exists'
assert_file "$MAN1" 'T1 variant manifest exists'
assert_eq "$SRC1_HASH" "$(sha256 "$SRC1")" 'T1 HA-03 source profile byte-unchanged'
assert_eq "$HA03_MAN_HASH" "$(sha256 "$HA03_MAN")" 'T1 HA-03 source manifest byte-unchanged'
assert_eq "$HA02_MAN_HASH" "$(sha256 "$HA02_MAN")" 'T1 HA-02 manifest byte-unchanged'
assert_eq "$HA02_P1_HASH" "$(sha256 "$T1/delivery/event-ob01-ha.yaml")" \
    'T1 HA-02 profile byte-unchanged'
assert_eq 'ok r=2 a=2' "$(line_edit "$SRC1" "$OUT1")" 'T1 exactly two deterministic edits'
assert_eq 'ok' "$(security_invariant "$SRC1" "$OUT1")" \
    'T1 security lines, pins, groups and node names unchanged'
assert_eq 'ok' "$(node_order_ok "$OUT1")" 'T1 four-node fixed priority preserved'
assert_eq '3' "$(group_field "$OUT1" interval)" 'T1 interval is the selected 3'
assert_eq '1000' "$(group_field "$OUT1" timeout)" 'T1 timeout is the selected 1000'
assert_eq 'false' "$(group_field "$OUT1" lazy)" 'T1 lazy stays false'
assert_eq '"204"' "$(group_field "$OUT1" expected-status)" \
    'T1 expected-status stays 204'
assert_eq '"https://www.gstatic.com/generate_204"' \
    "$(group_field "$OUT1" url)" 'T1 health URL unchanged'
assert_eq 'mihomo-competition-ha4-fastprobe/1' "$(jget "$MAN1" schema)" 'T1 manifest schema'
assert_eq 'ha-r1' "$(jget "$MAN1" generator.config_version)" 'T1 manifest config version'
assert_eq 'ha-competition-comp-r1.json' "$(jget "$MAN1" canonical_source.profile_manifest)" \
    'T1 manifest records the HA-03 source manifest'
assert_eq "$HA03_MAN_HASH" "$(jget "$MAN1" canonical_source.profile_manifest_sha256)" \
    'T1 manifest binds the HA-03 source manifest SHA-256'
assert_eq 'mihomo-competition-ha-profile/2' "$(jget "$MAN1" canonical_source.profile_schema)" \
    'T1 manifest records the HA-03 profile schema'
assert_eq 'comp-r1' "$(jget "$MAN1" canonical_source.profile_config_version)" \
    'T1 manifest records the HA-03 config version'
assert_eq '3' "$(jget "$MAN1" policy.interval)" 'T1 manifest records interval'
assert_eq '1000' "$(jget "$MAN1" policy.timeout)" 'T1 manifest records timeout'
assert_eq 'False' "$(jget "$MAN1" policy.lazy)" 'T1 manifest records lazy false'
assert_eq '204' "$(jget "$MAN1" policy.expected_status)" 'T1 manifest records expected status'
assert_eq 'True' "$(jget "$MAN1" policy.generic_defaults_preserved)" \
    'T1 manifest records the generic template as preserved'
assert_eq '1' "$(jget "$MAN1" terminal_count)" 'T1 manifest terminal count'
assert_eq 'event-ob01-hac.yaml' "$(jget "$MAN1" terminals.0.source)" \
    'T1 manifest records the HA-03 source file'
assert_eq "$SRC1_HASH" "$(jget "$MAN1" terminals.0.source_sha256)" \
    'T1 manifest binds the source profile SHA-256'
assert_eq "$(sha256 "$OUT1")" "$(jget "$MAN1" terminals.0.output_sha256)" \
    'T1 manifest output SHA-256 matches file'
assert_eq "$(size_of "$OUT1")" "$(jget "$MAN1" terminals.0.output_bytes)" \
    'T1 manifest byte count matches file'
assert_eq 2 "$("$PY" -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["rollback"]["files"]))' "$MAN1")" \
    'T1 rollback receipt lists profile and manifest'
if [ "$POSIX_HOST" = "1" ]; then
    assert_eq 600 "$(stat -c '%a' "$OUT1")" 'T1 variant mode 0600'
    assert_eq 600 "$(stat -c '%a' "$MAN1")" 'T1 manifest mode 0600'
else
    skip 'T1 POSIX mode assertions (NTFS carries no POSIX mode)'
fi
assert_absent_servers "$OUT$ERR" 'T1 success output leaks nothing'
assert_absent_servers "$(cat "$MAN1")" 'T1 manifest carries no address or credential'
run_h4 --check --delivery "$T1/variant" --source-delivery "$T1/competition" \
    --ha02-delivery "$T1/delivery" --pins "$T1/pins.json"
if [ "$RC" -eq 0 ] && [ -z "$ERR" ] \
   && [ "${OUT%%$'\n'*}" = 'ha4-fastprobe: OK' ]; then
    assert_contains "$OUT" 'policy: interval=3 timeout=1000' 'T1 check reports the policy'
    pass 'T1 variant passes --check'
else
    fail "T1 check (rc=$RC stdout=[$OUT] stderr=[$ERR])"
fi
run_ha03 --delivery "$T1/competition" --source-delivery "$T1/delivery" \
    --pins "$T1/pins.json" --check
[ "$RC" -eq 0 ] && [ -z "$ERR" ] \
    && pass 'T1 HA-03 preflight still green on the untouched generic template' \
    || fail "T1 HA-03 preflight (rc=$RC stderr=[$ERR])"
# -------------------------------------------------- T2 single B-first ---
section 'T2 single B-first fast-probe variant'
T2="$TMP/t2"
mk_tree "$T2" 1 0
mk_pins "$T2/pins.json"
expect_ha02_ok "$T2" ha-r1 'T2 HA-02 delivery generated'
expect_ha03_ok "$T2" comp-r1 'T2 HA-03 competition delivery generated'
mkdir -p "$T2/variant"; win_private_acl "$T2/variant"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$T2/variant"
read -r -a A <<< "$(h4_gen_args "$T2" "$T2/variant" 10 5000)"
run_h4 "${A[@]}"
[ "$RC" -eq 0 ] && pass 'T2 B-first variant generated' \
    || fail "T2 generation (rc=$RC stderr=[$ERR])"
OUT2="$T2/variant/event-ob01-ha4f.yaml"
MAN2="$(h4_manifest "$T2/variant")"
assert_eq 'ok' "$(security_invariant "$T2/competition/event-ob01-hac.yaml" "$OUT2")" \
    'T2 B-first pins/roles unchanged from the HA-03 profile'
assert_eq '10' "$(group_field "$OUT2" interval)" 'T2 interval 10 applied'
assert_eq '5000' "$(group_field "$OUT2" timeout)" 'T2 timeout 5000 applied'
assert_eq '10' "$(jget "$MAN2" policy.interval)" 'T2 manifest interval'
assert_eq 'B-first' "$(jget "$MAN2" terminals.0.group)" 'T2 manifest keeps the B-first group'
assert_eq 'B' "$(jget "$MAN2" terminals.0.primary_vps)" 'T2 manifest keeps physical B as primary'

# -------------------------------------------------- T3 full policy matrix ---
section 'T3 3/5/10 s x 1000/2000/5000 ms matrix'
T3="$TMP/t3"
mk_tree "$T3" 2 1
mk_pins "$T3/pins.json"
expect_ha02_ok "$T3" ha-r1 'T3 HA-02 delivery generated'
expect_ha03_ok "$T3" comp-r1 'T3 HA-03 competition delivery generated'
T3_MATRIX=0
for interval in 3 5 10; do
    for timeout in 1000 2000 5000; do
        dir="$T3/variant-i$interval-t$timeout"
        mkdir -p "$dir"; win_private_acl "$dir"
        [ "$POSIX_HOST" = "1" ] && chmod 700 "$dir"
        read -r -a A <<< "$(h4_gen_args "$T3" "$dir" "$interval" "$timeout")"
        run_h4 "${A[@]}"
        T3_MATRIX=$((T3_MATRIX + 1))
        if [ "$RC" -ne 0 ]; then
            fail "T3 i$interval/t$timeout generation (rc=$RC stderr=[$ERR])"
            continue
        fi
        ok=1
        if [ "$timeout" = "5000" ]; then
            want_edit='ok r=1 a=1'
        else
            want_edit='ok r=2 a=2'
        fi
        for f in "$dir"/*-ha4f.yaml; do
            [ "$(group_field "$f" interval)" = "$interval" ] || ok=0
            [ "$(group_field "$f" timeout)" = "$timeout" ] || ok=0
            base=$(basename "$f" -ha4f.yaml)
            [ "$(line_edit "$T3/competition/$base-hac.yaml" "$f")" = "$want_edit" ] \
                || ok=0
        done
        [ "$ok" = "1" ] && pass "T3 i$interval/t$timeout deterministic edit" \
            || fail "T3 i$interval/t$timeout transform"
        run_h4 --check --delivery "$dir" --source-delivery "$T3/competition" \
            --ha02-delivery "$T3/delivery" --pins "$T3/pins.json"
        [ "$RC" -eq 0 ] && pass "T3 i$interval/t$timeout preflight" \
            || fail "T3 i$interval/t$timeout preflight (rc=$RC stderr=[$ERR])"
    done
done
assert_eq 9 "$T3_MATRIX" 'T3 all nine policies generated'

# ------------------------------------------- T4 30-terminal delivery ---
section 'T4 30-terminal fast-probe batch'
T4="$TMP/t4"
mk_tree "$T4" 30 16
mk_pins "$T4/pins.json"
expect_ha02_ok "$T4" ha-r1 'T4 HA-02 delivery generated'
expect_ha03_ok "$T4" comp-r1 'T4 HA-03 competition delivery generated'
mkdir -p "$T4/variant"; win_private_acl "$T4/variant"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$T4/variant"
read -r -a A <<< "$(h4_gen_args "$T4" "$T4/variant" 5 2000)"
run_h4 "${A[@]}"
[ "$RC" -eq 0 ] && pass 'T4 30-terminal variants generated' \
    || fail "T4 generation (rc=$RC stderr=[$ERR])"
assert_eq 30 "$(find "$T4/variant" -maxdepth 1 -name '*-ha4f.yaml' | wc -l | tr -d ' ')" \
    'T4 thirty variant profiles written'
run_h4 --check --delivery "$T4/variant" --source-delivery "$T4/competition" \
    --ha02-delivery "$T4/delivery" --pins "$T4/pins.json"
[ "$RC" -eq 0 ] && pass 'T4 thirty-terminal preflight' \
    || fail "T4 preflight (rc=$RC stderr=[$ERR])"
assert_eq 30 "$(jget "$(h4_manifest "$T4/variant")" terminal_count)" \
    'T4 manifest terminal count'

# ---------------------------------------------------- T5 check negatives ---
section 'T5 --check tamper, file-set and source-binding negatives'
C="$TMP/check"
mk_tree "$C" 2 1
mk_pins "$C/pins.json"
expect_ha02_ok "$C" ha-r1 'T5 HA-02 delivery generated'
expect_ha03_ok "$C" comp-r1 'T5 HA-03 competition delivery generated'
mkdir -p "$C/variant"; win_private_acl "$C/variant"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$C/variant"
read -r -a A <<< "$(h4_gen_args "$C" "$C/variant" 3 1000)"
run_h4 "${A[@]}"
[ "$RC" -eq 0 ] && pass 'T5 baseline variants generated' \
    || fail "T5 generation (rc=$RC stderr=[$ERR])"
CMAN="$(h4_manifest "$C/variant")"
COUT="$C/variant/event-ob01-ha4f.yaml"
SNAP="$TMP/check-snap"
SRC_SNAP="$TMP/check-src-snap"
HA02_SNAP="$TMP/check-ha02-snap"
rm -rf "$SNAP" "$SRC_SNAP" "$HA02_SNAP"
cp -R "$C/variant" "$SNAP"
cp -R "$C/competition" "$SRC_SNAP"
cp -R "$C/delivery" "$HA02_SNAP"
restore_variant() {
    rm -rf "$C/variant"; cp -R "$SNAP" "$C/variant"
    if [ "$POSIX_HOST" = "1" ]; then
        chmod 700 "$C/variant"; chmod 600 "$C/variant"/*
    fi
}
restore_sources() {
    rm -rf "$C/competition" "$C/delivery"
    cp -R "$SRC_SNAP" "$C/competition"
    cp -R "$HA02_SNAP" "$C/delivery"
    if [ "$POSIX_HOST" = "1" ]; then
        chmod 700 "$C/competition" "$C/delivery"
        chmod 600 "$C/competition"/* "$C/delivery"/*
    fi
}
rehash_outputs() {
    "$PY" - "$C/variant" "$CMAN" <<'PY'
import hashlib
import json
import os
import sys
comp, manifest = sys.argv[1:3]
doc = json.load(open(manifest, encoding="utf-8"))
for entry in doc["terminals"]:
    data = open(os.path.join(comp, entry["output"]), "rb").read()
    entry["output_sha256"] = hashlib.sha256(data).hexdigest()
    entry["output_bytes"] = len(data)
json.dump(doc, open(manifest, "w", encoding="utf-8", newline=""),
          sort_keys=True, indent=2)
PY
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$CMAN"
    [ "$IS_WINDOWS" = "1" ] && win_private_file_acl "$CMAN"
}
manifest_edit() {
    "$PY" - "$CMAN" "$1" <<'PY'
import json
import sys
path, code = sys.argv[1], sys.argv[2]
doc = json.load(open(path, encoding="utf-8"))
exec(code)
json.dump(doc, open(path, "w", encoding="utf-8", newline=""),
          sort_keys=True, indent=2)
PY
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$CMAN"
    [ "$IS_WINDOWS" = "1" ] && win_private_file_acl "$CMAN"
}
run_check() { run_h4 "${CHECK_ARGS[@]}"; }
read -r -a CHECK_ARGS <<< "$(h4_check_args "$C" "$C/variant")"
run_check
[ "$RC" -eq 0 ] && pass 'T5a baseline preflight passes' \
    || fail "T5a baseline (rc=$RC stderr=[$ERR])"
restore_variant
"$PY" - "$COUT" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = "mode: rule\n"
if needle not in text:
    raise SystemExit("fixture: mode line missing")
open(path, "w", encoding="utf-8", newline="").write(
    text.replace(needle, needle + 'external-controller: "0.0.0.0:9090"\n', 1))
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha4-fastprobe: FAIL E_TRANSFORM terminal=event-ob01 detail=not the deterministic fast-probe transform of the source' ] \
    && pass 'T5b re-hashed extra controller/listener refused' \
    || fail "T5b (rc=$RC stderr=[$ERR])"
restore_variant
"$PY" - "$COUT" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("    interval: 3\n", "    interval: 5\n", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_TRANSFORM}" != "$ERR1" ] \
    && pass 'T5c re-hashed probe-interval change refused' \
    || fail "T5c (rc=$RC stderr=[$ERR])"
restore_variant
"$PY" - "$COUT" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("allow-lan: false", "allow-lan: true", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL}" != "$ERR1" ] \
    && pass 'T5d re-hashed LAN reopen refused' \
    || fail "T5d (rc=$RC stderr=[$ERR])"
restore_variant
"$PY" - "$COUT" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("    skip-cert-verify: false",
                    "    skip-cert-verify: true", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL}" != "$ERR1" ] \
    && pass 'T5e re-hashed skip-cert-verify true refused' \
    || fail "T5e (rc=$RC stderr=[$ERR])"
restore_variant
manifest_edit 'doc["policy"]["interval"] = 5'
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_TRANSFORM}" != "$ERR1" ] \
    && pass 'T5f manifest policy change cannot pass preflight' \
    || fail "T5f (rc=$RC stderr=[$ERR])"
restore_variant
manifest_edit 'e = doc["terminals"][0]
e["primary_vps"], e["backup_vps"] = e["backup_vps"], e["primary_vps"]
e["group"] = {"A": "A-first", "B": "B-first"}[e["primary_vps"]]'
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY}" != "$ERR1" ] \
    && pass 'T5g manifest role swap refused' \
    || fail "T5g (rc=$RC stderr=[$ERR])"
restore_variant
manifest_edit 'doc["canonical_source"]["profile_manifest_sha256"] = "0" * 64'
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha4-fastprobe: FAIL E_DELIVERY_HASH role=source-manifest' ] \
    && pass 'T5g2 manifest source-manifest hash tamper refused' \
    || fail "T5g2 (rc=$RC stderr=[$ERR])"
restore_variant
cp "$COUT" "$C/variant/extra-ha4f.yaml"
[ "$POSIX_HOST" = "1" ] && chmod 600 "$C/variant/extra-ha4f.yaml"
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY}" != "$ERR1" ] \
    && pass 'T5h extra variant profile refused' \
    || fail "T5h (rc=$RC stderr=[$ERR])"
restore_variant
cp "$COUT" "$C/variant/EXTRA-HA4F.YAML"
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY}" != "$ERR1" ] \
    && pass 'T5i uppercase-suffix extra profile refused' \
    || fail "T5i (rc=$RC stderr=[$ERR])"
restore_variant
if [ "$POSIX_HOST" = "1" ]; then
    cp "$COUT" "$C/variant/EVENT-OB01-HA4F.YAML"
    run_check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY}" != "$ERR1" ] \
        && pass 'T5j actual casefold-duplicate output refused' \
        || fail "T5j (rc=$RC stderr=[$ERR])"
    restore_variant
else
    skip 'T5j actual casefold-duplicate fixture (NTFS cannot hold two such names)'
fi
restore_variant
restore_sources
"$PY" - "$C/competition/event-ob01-hac.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text + "\n# tampered\n")
PY
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha4-fastprobe: FAIL E_DELIVERY_HASH terminal=event-ob01' ] \
    && pass 'T5k tampered HA-03 source refused by the HA-03 chain' \
    || fail "T5k (rc=$RC stderr=[$ERR])"
restore_variant
restore_sources
"$PY" - "$C/delivery/event-ob01-ha.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
open(path, "w", encoding="utf-8", newline="").write(text + "\n# tampered\n")
PY
run_check
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY_HASH}" != "$ERR1" ] \
    && pass 'T5l tampered HA-02 source refused by the HA-03 chain' \
    || fail "T5l (rc=$RC stderr=[$ERR])"
restore_variant
restore_sources
C2="$TMP/check-other"
mk_tree "$C2" 1 1
mk_pins "$C2/pins.json"
expect_ha02_ok "$C2" ha-r1 'T5m second HA-02 delivery generated'
expect_ha03_ok "$C2" comp-r2 'T5m second HA-03 delivery generated'
read -r -a A <<< "$(h4_check_args "$C" "$C/variant" "$C2/competition")"
run_h4 "${A[@]}"
[ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_DELIVERY}" != "$ERR1" ] \
    && pass 'T5m different HA-03 source delivery refused' \
    || fail "T5m (rc=$RC stderr=[$ERR])"
restore_variant
if [ "$POSIX_HOST" = "1" ]; then
    chmod 644 "$C/variant/event-ob02-ha4f.yaml"
    run_check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_INSECURE_PERMISSIONS role=output-file}" != "$ERR1" ] \
        && pass 'T5n 0644 variant output refused with its role' \
        || fail "T5n (rc=$RC stderr=[$ERR])"
    restore_variant
    chmod 644 "$C/pins.json"
    run_check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha4-fastprobe: FAIL E_INSECURE_PERMISSIONS role=pins}" != "$ERR1" ] \
        && pass 'T5o 0644 pins file refused by the HA-03 chain' \
        || fail "T5o (rc=$RC stderr=[$ERR])"
    chmod 600 "$C/pins.json"
else
    skip 'T5n/T5o POSIX per-file mode gates (NTFS carries no POSIX mode)'
fi
restore_variant
expect_h4_code E_USAGE 'T5p --check without --source-delivery refused' \
    --check --delivery "$C/variant" --ha02-delivery "$C/delivery" --pins "$C/pins.json"
expect_h4_code E_USAGE 'T5q generate with --source-delivery refused' \
    --delivery "$C/competition" --source-delivery "$C/competition" \
    --ha02-delivery "$C/delivery" --pins "$C/pins.json" \
    --output-dir "$TMP/unused" --config-version x --interval 3 --timeout 1000
expect_h4_code E_USAGE 'T5r unsupported interval refused' \
    --delivery "$C/competition" --ha02-delivery "$C/delivery" \
    --pins "$C/pins.json" --output-dir "$TMP/unused" \
    --config-version x --interval 4 --timeout 1000
expect_h4_code E_USAGE 'T5s unsupported timeout refused' \
    --delivery "$C/competition" --ha02-delivery "$C/delivery" \
    --pins "$C/pins.json" --output-dir "$TMP/unused" \
    --config-version x --interval 3 --timeout 1500
expect_h4_code E_USAGE 'T5t missing output/version refused' \
    --delivery "$C/competition" --ha02-delivery "$C/delivery" \
    --pins "$C/pins.json" --interval 3 --timeout 1000
expect_h4_code E_PATH_CONFLICT 'T5u output directory equal to the HA-03 delivery refused' \
    --delivery "$C/competition" --ha02-delivery "$C/delivery" \
    --pins "$C/pins.json" --output-dir "$C/competition" \
    --config-version x --interval 3 --timeout 1000
mkdir -p "$C/exists"; win_private_acl "$C/exists"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$C/exists"
: > "$C/exists/EVENT-OB01-HA4F.YAML"
expect_h4_code E_OUTPUT_EXISTS 'T5v case-differing existing variant refused' \
    --delivery "$C/competition" --ha02-delivery "$C/delivery" \
    --pins "$C/pins.json" --output-dir "$C/exists" \
    --config-version x --interval 3 --timeout 1000

# ------------------------------------------------- T6 overlay refusals ---
section 'T6 overlay refuses non-generic source shapes'
UNIT=$("$PY" - "$TOOL" "$C/competition/event-ob01-hac.yaml" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("h4", sys.argv[1])
h4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h4)
good = open(sys.argv[2], "rb").read()
auto = (b"  - name: \xe8\x87\xaa\xe5\x8a\xa8\xe9\x80\x89\xe6\x8b\xa9\n"
        b"    type: fallback\n"
        b"    proxies:\n"
        b"      - Reality\n"
        b"      - Hysteria2\n"
        b"      - Backup-Reality\n"
        b"      - Backup-Hysteria2\n")
bad = []
def case(label, data):
    try:
        h4.overlay(data, 3, 1000)
        bad.append(label + ":accepted")
    except h4.ProfileError as exc:
        if exc.code != "E_TRANSFORM":
            bad.append(label + ":wrong=" + exc.code)
case("lazy-true", good.replace(b"    lazy: false", b"    lazy: true", 1))
case("base-interval-30", good.replace(b"    interval: 60", b"    interval: 30", 1))
case("base-timeout-4000", good.replace(b"    timeout: 5000", b"    timeout: 4000", 1))
case("missing-group", good.replace(
    auto, auto.replace(
        b"  - name: \xe8\x87\xaa\xe5\x8a\xa8\xe9\x80\x89\xe6\x8b\xa9",
        b"  - name: other", 1), 1))
case("reordered-nodes",
     good.replace(auto, auto.replace(
         b"      - Reality\n      - Hysteria2",
         b"      - Hysteria2\n      - Reality", 1), 1))
case("extra-node", good.replace(auto, auto + b"      - Extra\n", 1))
case("crlf", good.replace(b"\n", b"\r\n", 1))
case("no-expected-status", good.replace(b'    expected-status: "204"', b"    note: x", 1))
print("ok" if not bad else ";".join(bad))
PY
)
assert_eq 'ok' "$UNIT" 'T6 overlay refuses non-generic source shapes'

# ----------------------------------------------------------- T7 rollback ---
section 'T7 rollback of a partial variant write'
RB="$TMP/rb"
mk_tree "$RB" 3 2
mk_pins "$RB/pins.json"
expect_ha02_ok "$RB" ha-r1 'T7 HA-02 delivery generated'
expect_ha03_ok "$RB" comp-r1 'T7 HA-03 competition delivery generated'
mkdir -p "$RB/variant"; win_private_acl "$RB/variant"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$RB/variant"
printf 'operator note\n' > "$RB/variant/keep-me.txt"
DRIVER='
import importlib.util
import sys
tool, ha03, delivery, pins, out = sys.argv[1:6]
spec = importlib.util.spec_from_file_location("h4", tool)
h4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h4)
batch = h4.batch_tool()
merge = batch.load_merge_tool()
real = merge.write_output
calls = {"n": 0}
def flaky(payload, path):
    calls["n"] += 1
    if calls["n"] == 2:
        raise OSError("injected")
    real(payload, path)
merge.write_output = flaky
try:
    h4.generate(ha03, delivery, pins, out, "ha-r1", 3, 1000,
                batch=batch, merge=merge)
    print("res code=NONE")
except h4.ProfileError as exc:
    rb = exc.rollback or {"removed": 0, "skipped": 0, "complete": True}
    print("res code=%s removed=%d skipped=%d complete=%s" % (
        exc.code, rb["removed"], rb["skipped"],
        "yes" if rb["complete"] else "no"))
'
RBOUT=$("$PY" -c "$DRIVER" "$TOOL" "$RB/competition" "$RB/delivery" \
    "$RB/pins.json" "$RB/variant" 2>&1 | tr -d '\r')
assert_contains "$RBOUT" 'code=E_IO removed=1 skipped=0 complete=yes' \
    'T7a mid-batch failure rolls back the created variant'
assert_eq 1 "$(find "$RB/variant" -maxdepth 1 -type f | wc -l | tr -d ' ')" \
    'T7a only the pre-existing file remains'
assert_file "$RB/variant/keep-me.txt" 'T7a unrelated file preserved'

# ------------------------------------------------------- T8 pinned core ---
section 'T8 pinned core loads the fast-probe variants'
CORE="${HA04_MIHOMO:-${HA03_MIHOMO:-${HA02_MIHOMO:-}}}"
if [ -n "$CORE" ]; then
    WORK="$TMP/core-work"; mkdir -p "$WORK"
    LOADED=0
    CORE_RC=0
    CORE_FAIL=''
    load_profile() {
        if ! "$CORE" -t -d "$WORK" -f "$1" \
                >"$LOGS/core-$LOADED.out" 2>&1; then
            CORE_RC=1
            CORE_FAIL="$(basename "$1"): $(tail -2 "$LOGS/core-$LOADED.out" | tr '\n' ' ')"
        fi
        LOADED=$((LOADED + 1))
    }
    for f in "$T4/variant"/*-ha4f.yaml; do load_profile "$f"; done
    for f in "$T3"/variant-*/*-ha4f.yaml; do
        case "$f" in
            */event-ob01-ha4f.yaml) load_profile "$f" ;;
        esac
    done
    if [ "$CORE_RC" -eq 0 ]; then
        printf '  core-load: OK profiles=%d\n' "$LOADED"
        pass "T8 pinned core loaded $LOADED fast-probe variants"
    else
        fail "T8 pinned core rejected a fast-probe variant ($CORE_FAIL)"
    fi
else
    skip 'T8 pinned-core fast-probe load (set HA04_MIHOMO/HA03_MIHOMO/HA02_MIHOMO)'
fi

# ------------------------------------------------------------------ summary --
section 'summary'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
