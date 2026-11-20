#!/usr/bin/env bash
# Issue #48 HA-03 -- competition-safe profile transform contract.
#
# Scope: tools/mihomo-competition-ha-profile.py. It consumes one HA-02 delivery
# (manifest + <name>-ha.yaml) and a local pins file, and writes a SECOND,
# independent competition delivery (<name>-hac.yaml + ha-competition-*.json):
# loopback DNS listener, skip-cert-verify false, and the SHA-256 DER pin of the
# physical VPS that the HA-02 manifest assigned to each HY2 node (A/B-first).
# The HA-02 input files are never modified or overwritten.
#
# Sandbox only: temporary files, no network, no real credentials (obvious
# sentinels), no production. The pinned-core section runs only when the operator
# supplies a hash-pinned Mihomo binary (Linux CI does; the Windows job skips it
# as platform-inapplicable because it has no core).
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/mihomo-competition-ha-profile.py"
BATCH="$ROOT/tools/mihomo-competition-ha-batch.py"
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
assert_diff() { if diff -u "$1" "$2" >/dev/null 2>&1; then pass "$3"; else
    fail "$3 (bytes differ)"; diff -u "$1" "$2" | head -20; fi; }

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

# Real NTFS ACL helper: SID-based and fail-closed on Windows.
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

win_grant() {
    [ "$IS_WINDOWS" = "1" ] || return 0
    local win
    win=$(cygpath -w "$1" 2>/dev/null) || win=$1
    MSYS_NO_PATHCONV=1 icacls "$win" /grant "$2" >/dev/null 2>&1
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

mk_pins() { # <path> [a_pin] [b_pin] [a_not_after] [b_not_after] [schema]
    local path=$1 a=${2:-$PIN_A} b=${3:-$PIN_B}
    local an=${4:-2030-01-01T00:00:00Z} bn=${5:-2030-01-01T00:00:00Z}
    local schema=${6:-mihomo-competition-ha-pins/2}
    "$PY" - "$path" "$a" "$b" "$an" "$bn" "$schema" <<'PY'
import json
import sys
path, a, b, an, bn, schema = sys.argv[1:7]
doc = {"schema": schema, "vps": {
    "A": {"fingerprint_sha256": a, "not_before": "2019-01-01T00:00:00Z",
           "not_after": an, "source": "synthetic-test"},
    "B": {"fingerprint_sha256": b, "not_before": "2019-01-01T00:00:00Z",
           "not_after": bn, "source": "synthetic-test"},
}}
with open(path, "w", encoding="utf-8", newline="") as handle:
    json.dump(doc, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
    if [ "$POSIX_HOST" = "1" ]; then chmod 600 "$path"; fi
    if [ "$IS_WINDOWS" = "1" ]; then win_private_file_acl "$path"; fi
}

ha_args() { # <root> [version]
    printf '%s ' --inventory "$1/terminals.csv" --exports "$1/exports" \
        --output-dir "$1/delivery" --config-version "${2:-ha-r1}"
}
profile_args() { # <root> [competition version] [pins]
    printf '%s ' --delivery "$1/delivery" --pins "${3:-$1/pins.json}" \
        --output-dir "$1/competition" --config-version "${2:-comp-r1}"
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
run_batch() { run_cmd batch "$PY" "$BATCH" "$@"; }
run_profile() { run_cmd profile "$PY" "$TOOL" "$@"; }

expect_ha_ok() { # <root> <version> <label>
    local root=$1 version=$2 label=$3
    read -r -a args <<< "$(ha_args "$root" "$version")"
    run_batch "${args[@]}"
    [ "$RC" -eq 0 ] && pass "$label" || fail "$label (rc=$RC stderr=[$ERR])"
}

expect_gen_ok() { # <root> <version> <label>
    local root=$1 version=$2 label=$3
    read -r -a args <<< "$(profile_args "$root" "$version")"
    run_profile "${args[@]}"
    if [ "$RC" -eq 0 ] && [ "$OUT" = "ha-profile: OK
terminals: $(count_terminals "$root")
version: $version
manifest: ha-competition-$version.json" ] && [ -z "$ERR" ]; then
        pass "$label"
    else
        fail "$label (rc=$RC stdout=[$OUT] stderr=[$ERR])"
    fi
}

count_terminals() { "$PY" - "$1/terminals.csv" <<'PY'
import sys
rows = [line for line in open(sys.argv[1], encoding="utf-8").read().splitlines()
        if line and not line.startswith("#") and not line.startswith("terminal,")]
print(len(rows))
PY
}

expect_profile_code() { # <code> <label> <args...>
    local code=$1 label=$2
    shift 2
    run_profile "$@"
    if [ "$RC" -ne 0 ] && [ -n "$ERR1" ] && [ "${ERR1#"ha-profile: FAIL $code"}" != "$ERR1" ] \
       && [ -z "$OUT" ]; then
        pass "$label -> $code"
    else
        fail "$label (rc=$RC want=[$code] stderr=[$ERR] stdout=[$OUT])"
    fi
}

block_pin() { # <file> <node-name>
    awk -v n="  - name: $2" '$0==n{f=1;next} f && $0==""{exit}
        f && /^    fingerprint: /{sub(/^    fingerprint: /,"");print}' "$1"
}

block_skip() { # <file> <node-name>
    awk -v n="  - name: $2" '$0==n{f=1;next} f && $0==""{exit}
        f && /^    skip-cert-verify: /{sub(/^    skip-cert-verify: /,"");print}' "$1"
}

assert_five_edits() { # <input> <output> <label>
    "$PY" - "$1" "$2" "$3" <<'PY'
import difflib
import sys
before = open(sys.argv[1], encoding="utf-8").read().split("\n")
after = open(sys.argv[2], encoding="utf-8").read().split("\n")
ops = [op for op in difflib.SequenceMatcher(None, before, after).get_opcodes()
       if op[0] != "equal"]
removed = sum(i2 - i1 for tag, i1, i2, j1, j2 in ops)
added = sum(j2 - j1 for tag, i1, i2, j1, j2 in ops)
ok = (removed == 5 and added == 7
      and all(tag in ("replace", "insert") for tag, *_ in ops))
print("ok" if ok else "bad ops=%r removed=%d added=%d" % (ops, removed, added))
PY
}

assert_inputs_untouched() { # <root> <label>
    "$PY" - "$1" <<'PY'
import hashlib
import json
import os
import sys
root = sys.argv[1]
manifest = None
for name in os.listdir(os.path.join(root, "delivery")):
    if name.startswith("ha-delivery-") and name.endswith(".json"):
        manifest = os.path.join(root, "delivery", name)
doc = json.load(open(manifest, encoding="utf-8"))
bad = []
for entry in doc["terminals"]:
    path = os.path.join(root, "delivery", entry["output"])
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if digest != entry["output_sha256"]:
        bad.append(entry["name"])
print("ok" if not bad else "changed:" + ",".join(bad))
PY
}

# ------------------------------------------------------------- static gates --
section 'static gates'
"$PY" -m py_compile "$TOOL" && pass 'py_compile tools/mihomo-competition-ha-profile.py' \
    || fail 'py_compile failed'
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
        __future__|datetime|hashlib|importlib|json|os|re|stat|sys|time) ;;
        *) bad="$bad $module" ;;
    esac
done
[ -z "$bad" ] && pass "stdlib allowlist holds (imports: $imports)" \
    || fail "non-allowlisted import(s):$bad"
for module in socket ssl urllib http ftplib smtplib subprocess sched selectors \
              asyncio threading multiprocessing sqlite3 yaml base64 argparse; do
    case " $imports " in
        *" $module "*) fail "the competition tool imports $module" ;;
    esac
done
pass 'no network, subprocess, third-party YAML or duplicate CLI parser imported'
for marker in 'BATCH_TOOL_NAME' 'load_batch_tool' 'load_merge_tool' \
              'CLIENT_NAME_RE' 'check_private_path' 'file_identity' \
              'def is_reparse' 'verify_temp_inheritance' 'batch.rollback' \
              'def verify_competition_profile' \
              'def check_regular_private_file' 'allow-lan: false' \
              'bind-address: "127.0.0.1"' 'required_valid_through'; do
    grep -qF -- "$marker" "$TOOL" \
        && pass "HA-02 reuse/security contract present [$marker]" \
        || fail "missing [$marker]"
done
for forbidden in 'def read_export' 'def parse_export' 'CANONICAL_PREFIX_LINES'; do
    grep -qF -- "$forbidden" "$TOOL" \
        && fail "the competition tool duplicates canonical parser internals [$forbidden]" \
        || true
done
pass 'no canonical parser internals duplicated'
cli_flags="$("$PY" - "$TOOL" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
print(" ".join(re.findall(r'add_argument\("(--[a-z-]+)"', text)))
PY
)"
assert_eq '--delivery --pins --output-dir --config-version --min-validity-days --require-valid-through --check' \
    "$cli_flags" 'CLI flags are exactly the documented seven'
for forbidden in uuid password server pubkey force activate enable; do
    printf '%s\n' "$cli_flags" | grep -qiE -- "--$forbidden" \
        && fail "the CLI exposes a --$forbidden option" || true
done
pass 'no credential/activation/force CLI option exists'
grep -qE 'generate_204|gstatic|interval: [0-9]|timeout: [0-9]|lazy: (true|false)' "$TOOL" \
    && fail 'the tool hardcodes a health-probe parameter' \
    || pass 'the tool never rewrites the #42 probe policy'

# ------------------------------------------------------- T1 single A-first ---
section 'T1 single A-first competition profile'
T1="$TMP/t1"
mk_tree "$T1" 1 1
mk_pins "$T1/pins.json"
expect_ha_ok "$T1" ha-r1 'T1 HA-02 delivery generated'
H1="$(sha256 "$T1/delivery/event-ob01-ha.yaml")"
MAN1="$(sha256 "$T1/delivery/ha-delivery-ha-r1.json")"
expect_gen_ok "$T1" comp-r1 'T1 competition profile generated'
OUT1="$T1/competition/event-ob01-hac.yaml"
MAN="$(ls "$T1/competition"/ha-competition-*.json)"
assert_file "$OUT1" 'T1 competition profile exists'
assert_file "$MAN" 'T1 competition manifest exists'
assert_eq "$H1" "$(sha256 "$T1/delivery/event-ob01-ha.yaml")" \
    'T1 HA-02 profile is byte-unchanged'
assert_eq "$MAN1" "$(sha256 "$T1/delivery/ha-delivery-ha-r1.json")" \
    'T1 HA-02 manifest is byte-unchanged'
assert_eq 'ok' "$(assert_five_edits "$T1/delivery/event-ob01-ha.yaml" "$OUT1" 'T1')" \
    'T1 exactly five deterministic edits'
assert_eq 'false' "$(awk '/^allow-lan: /{sub(/^allow-lan: /,"");print}' "$OUT1")" \
    'T1 allow-lan is false'
assert_eq '127.0.0.1' "$(awk '/^bind-address: /{gsub(/"/,"");sub(/^bind-address: /,"");print}' "$OUT1")" \
    'T1 bind-address is loopback'
assert_eq 0 "$(grep -c 'allow-lan: true' "$OUT1")" 'T1 no allow-lan true remains'
assert_eq 0 "$(grep -c 'bind-address: "\*"' "$OUT1")" 'T1 no wildcard bind remains'
assert_eq '127.0.0.1:53' "$(awk '/^  listen: /{sub(/^  listen: /,"");gsub(/"/,"");print}' "$OUT1")" \
    'T1 DNS listener is loopback only'
assert_eq "$PIN_A" "$(block_pin "$OUT1" Hysteria2)" 'T1 primary HY2 pins VPS A'
assert_eq "$PIN_B" "$(block_pin "$OUT1" Backup-Hysteria2)" 'T1 backup HY2 pins VPS B'
assert_eq 'false' "$(block_skip "$OUT1" Hysteria2)" 'T1 primary HY2 skip-cert-verify false'
assert_eq 'false' "$(block_skip "$OUT1" Backup-Hysteria2)" 'T1 backup HY2 skip-cert-verify false'
assert_eq 0 "$(grep -c 'skip-cert-verify: true' "$OUT1")" 'T1 no skip-cert-verify true remains'
assert_eq 2 "$(grep -c '    fingerprint: ' "$OUT1")" 'T1 exactly two certificate pins'
assert_eq 'mihomo-competition-ha-profile/2' "$(jget "$MAN" schema)" 'T1 manifest schema'
assert_eq 1 "$(jget "$MAN" terminal_count)" 'T1 manifest terminal count'
assert_eq 'A-first' "$(jget "$MAN" terminals.0.group)" 'T1 manifest group'
assert_eq 'A' "$(jget "$MAN" terminals.0.primary_vps)" 'T1 manifest primary role'
assert_eq 'B' "$(jget "$MAN" terminals.0.backup_vps)" 'T1 manifest backup role'
assert_eq "$(sha256 "$OUT1")" "$(jget "$MAN" terminals.0.output_sha256)" \
    'T1 manifest output SHA-256 matches file'
assert_eq "$(size_of "$OUT1")" "$(jget "$MAN" terminals.0.output_bytes)" \
    'T1 manifest byte count matches file'
assert_eq "$H1" "$(jget "$MAN" terminals.0.input_sha256)" \
    'T1 manifest records the HA-02 input hash'
assert_eq "$PIN_A" "$(jget "$MAN" pins.A.fingerprint_sha256)" 'T1 manifest records pin A'
assert_eq "$PIN_B" "$(jget "$MAN" pins.B.fingerprint_sha256)" 'T1 manifest records pin B'
assert_eq '2019-01-01T00:00:00Z' "$(jget "$MAN" pins.A.not_before)" \
    'T1 manifest records certificate not_before'
assert_eq '7' "$(jget "$MAN" validity.min_validity_days)" 'T1 manifest validity control'
assert_eq 'None' "$(jget "$MAN" validity.required_valid_through)" \
    'T1 manifest records no required-valid-through by default'
assert_eq 2 "$("$PY" -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["rollback"]["files"]))' "$MAN")" \
    'T1 rollback receipt lists profile and manifest'
if [ "$POSIX_HOST" = "1" ]; then
    assert_eq 600 "$(stat -c '%a' "$OUT1")" 'T1 competition profile mode 0600'
    assert_eq 600 "$(stat -c '%a' "$MAN")" 'T1 competition manifest mode 0600'
else
    skip 'T1 POSIX mode assertions (NTFS carries no POSIX mode)'
fi
assert_contains "$(cat "$MAN")" "$PIN_A" 'T1 manifest carries the A pin'
assert_absent_servers() { local text=$1 label=$2
    case "$text" in *"$SERVER_A"*|*"$SERVER_B"*|*"1111-2222-3333"*|*"ha-A-"*|*"ha-B-"*)
        fail "$label (credential/address leaked)" ;;
        *) pass "$label" ;; esac; }
assert_absent_servers "$OUT$ERR" 'T1 success output leaks nothing'
assert_absent_servers "$(cat "$MAN")" 'T1 manifest carries no address or credential'

# ------------------------------------------------------- T2 single B-first ---
section 'T2 single B-first competition profile'
T2="$TMP/t2"
mk_tree "$T2" 1 0
mk_pins "$T2/pins.json"
expect_ha_ok "$T2" ha-r1 'T2 HA-02 delivery generated'
expect_gen_ok "$T2" comp-r1 'T2 competition profile generated'
OUT2="$T2/competition/event-ob01-hac.yaml"
assert_eq "$PIN_B" "$(block_pin "$OUT2" Hysteria2)" \
    'T2 B-first primary HY2 pins VPS B'
assert_eq "$PIN_A" "$(block_pin "$OUT2" Backup-Hysteria2)" \
    'T2 B-first backup HY2 pins VPS A'
assert_eq 'B' "$(jget "$(ls "$T2/competition"/ha-competition-*.json)" terminals.0.primary_vps)" \
    'T2 manifest records physical B as primary'

# ------------------------------------------------------- T3..T5 batch counts --
section 'T3/T4/T5 2, 16 and 30 terminal batches'
for spec in "2:1" "16:8" "30:16"; do
    count=${spec%%:*}; afirst=${spec##*:}
    dir="$TMP/b$count"
    mk_tree "$dir" "$count" "$afirst"
    mk_pins "$dir/pins.json"
    expect_ha_ok "$dir" ha-r1 "T$count HA-02 delivery generated"
    expect_gen_ok "$dir" comp-r1 "T$count competition profiles generated"
    assert_eq "$count" "$(find "$dir/competition" -maxdepth 1 -name '*-hac.yaml' | wc -l | tr -d ' ')" \
        "T$count profiles written"
    VERDICT=$("$PY" - "$dir/delivery" "$dir/competition" "$PIN_A" "$PIN_B" <<'PY'
import hashlib
import json
import os
import sys
delivery, competition, pin_a, pin_b = sys.argv[1:5]
manifest = [n for n in os.listdir(competition)
            if n.startswith("ha-competition-") and n.endswith(".json")][0]
doc = json.load(open(os.path.join(competition, manifest), encoding="utf-8"))
bad = []
for entry in doc["terminals"]:
    name = entry["name"]
    before = open(os.path.join(delivery, entry["input"]), "rb").read()
    after = open(os.path.join(competition, entry["output"]), "rb").read()
    if hashlib.sha256(before).hexdigest() != entry["input_sha256"]:
        bad.append(name + ":input-hash")
    if hashlib.sha256(after).hexdigest() != entry["output_sha256"]:
        bad.append(name + ":output-hash")
    text = after.decode("utf-8")
    lines = text.split("\n")
    def block_pin(node):
        start = lines.index("  - name: " + node)
        pins = []
        for line in lines[start + 1:]:
            if line == "":
                break
            if line.startswith("    fingerprint: "):
                pins.append(line.split(": ", 1)[1])
        return pins
    want_primary = pin_a if entry["primary_vps"] == "A" else pin_b
    want_backup = pin_a if entry["backup_vps"] == "A" else pin_b
    if block_pin("Hysteria2") != [want_primary]:
        bad.append(name + ":primary-pin")
    if block_pin("Backup-Hysteria2") != [want_backup]:
        bad.append(name + ":backup-pin")
    if text.count("    skip-cert-verify: false") != 2:
        bad.append(name + ":skip")
    if '  listen: "127.0.0.1:53"' not in lines:
        bad.append(name + ":dns")
    if '  listen: "0.0.0.0:53"' in lines:
        bad.append(name + ":dns-old")
print("ok" if not bad else ",".join(bad))
PY
)
    assert_eq 'ok' "$VERDICT" "T$count every profile maps the right VPS pin"
    assert_eq 'ok' "$(assert_inputs_untouched "$dir")" "T$count HA-02 inputs untouched"
done
T5="$TMP/b30"

# ------------------------------------------------------------------ T6 pins --
section 'T6 pins validity and strict schema'
P="$TMP/pins"
mk_tree "$P" 1 1
mk_pins "$P/pins.json"
expect_ha_ok "$P" ha-r1 'T6 HA-02 delivery generated'
mkdir -p "$P/competition"; win_private_acl "$P/competition"
python_pins() { local path=$1 code=$2
    "$PY" - "$path" "$code" <<'PY'
import json
import sys
path, code = sys.argv[1], sys.argv[2]
doc = json.load(open(path, encoding="utf-8"))
exec(code)
json.dump(doc, open(path, "w", encoding="utf-8", newline=""), sort_keys=True, indent=2)
PY
    [ "$POSIX_HOST" = "1" ] && chmod 600 "$path"
    [ "$IS_WINDOWS" = "1" ] && win_private_file_acl "$path"
}
mk_pins "$P/expired.json" "$PIN_A" "$PIN_B" 2020-01-01T00:00:00Z 2030-01-01T00:00:00Z
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/expired.json")"
expect_profile_code E_PINS_EXPIRED 'T6a expired A pin refused' "${A[@]}"
assert_contains "$ERR" 'vps=A' 'T6a expiry is attributed to VPS A'
NEAR=$(date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
    "$PY" -c 'import datetime;print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
mk_pins "$P/near.json" "$PIN_A" "$PIN_B" "$NEAR" 2030-01-01T00:00:00Z
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/near.json")"
expect_profile_code E_PINS_EXPIRED 'T6b pin inside the validity window refused' "${A[@]}"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/near.json")"
run_profile --delivery "$P/delivery" --pins "$P/near.json" \
    --output-dir "$P/competition" --config-version comp-r1 --min-validity-days 0
[ "$RC" -eq 0 ] && pass 'T6c min-validity-days 0 accepts a near-expiry pin' \
    || fail "T6c (rc=$RC stderr=[$ERR])"
rm -f "$P/competition/"*
mk_pins "$P/through.json" "$PIN_A" "$PIN_B"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/through.json")"
run_profile --delivery "$P/delivery" --pins "$P/through.json" \
    --output-dir "$P/competition" --config-version comp-r1 \
    --require-valid-through 2031-01-01T00:00:00Z
[ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_PINS_EXPIRED vps=A detail=require-valid-through}" = "" ] \
    && pass 'T6c2 pin not covering the required event window refused' \
    || fail "T6c2 (rc=$RC stderr=[$ERR])"
run_profile --delivery "$P/delivery" --pins "$P/through.json" \
    --output-dir "$P/competition" --config-version comp-r1 \
    --require-valid-through 2029-01-01T00:00:00Z
[ "$RC" -eq 0 ] && pass 'T6c3 required event window inside certificate validity accepted' \
    || fail "T6c3 (rc=$RC stderr=[$ERR])"
assert_eq '2029-01-01T00:00:00Z' \
    "$(jget "$(ls "$P/competition"/ha-competition-*.json)" validity.required_valid_through)" \
    'T6c3 manifest records the required valid-through date'
rm -f "$P/competition/"*
cp "$P/pins.json" "$P/future-nb.json"
python_pins "$P/future-nb.json" 'doc["vps"]["A"]["not_before"] = "2030-01-01T00:00:00Z"; doc["vps"]["A"]["not_after"] = "2031-01-01T00:00:00Z"'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/future-nb.json")"
expect_profile_code E_PINS 'T6c4 cert not_before in the future refused' "${A[@]}"
assert_contains "$ERR" 'vps=A' 'T6c4 future not_before is attributed to VPS A'
cp "$P/pins.json" "$P/order.json"
python_pins "$P/order.json" 'doc["vps"]["A"]["not_before"] = "2031-01-01T00:00:00Z"; doc["vps"]["A"]["not_after"] = "2030-01-01T00:00:00Z"'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/order.json")"
expect_profile_code E_PINS 'T6c5 not_after not later than not_before refused' "${A[@]}"
cp "$P/pins.json" "$P/no-nb.json"
python_pins "$P/no-nb.json" 'del doc["vps"]["A"]["not_before"]'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/no-nb.json")"
expect_profile_code E_PINS 'T6c6 missing not_before refused' "${A[@]}"
FL="$TMP/floor"
mk_tree "$FL" 1 1
mk_pins "$FL/pins.json"
expect_ha_ok "$FL" ha-r1 'T6c7 floor HA-02 delivery generated'
read -r -a A <<< "$(profile_args "$FL" comp-r1)"
run_profile --delivery "$FL/delivery" --pins "$FL/pins.json" \
    --output-dir "$FL/competition" --config-version comp-r1 \
    --min-validity-days 30
[ "$RC" -eq 0 ] && pass 'T6c7 delivery recorded with a 30-day floor' \
    || fail "T6c7 (rc=$RC stderr=[$ERR])"
mk_pins "$FL/short.json" "$PIN_A" "$PIN_B" "$NEAR" 2030-01-01T00:00:00Z
run_profile --delivery "$FL/competition" --pins "$FL/short.json" --check \
    --min-validity-days 0
[ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_PINS_EXPIRED}" != "$ERR1" ] \
    && pass 'T6c8 --check cannot lower the recorded validity floor' \
    || fail "T6c8 (rc=$RC stderr=[$ERR])"
rm -f "$P/competition/"*
mk_pins "$P/badpin.json" "$(printf 'a%.0s' $(seq 1 63))" "$PIN_B"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/badpin.json")"
expect_profile_code E_PINS 'T6d 63-hex pin refused' "${A[@]}"
mk_pins "$P/nonhex.json" "$(printf 'z%.0s' $(seq 1 64))" "$PIN_B"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/nonhex.json")"
expect_profile_code E_PINS 'T6e non-hex pin refused' "${A[@]}"
mk_pins "$P/dup.json" "$PIN_A" "$PIN_A"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/dup.json")"
expect_profile_code E_PINS 'T6f identical A/B pins refused' "${A[@]}"
mk_pins "$P/upper.json" "$(printf '%s' "$PIN_A" | tr 'a-f' 'A-F')" "$PIN_B"
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/upper.json")"
run_profile "${A[@]}"
[ "$RC" -eq 0 ] && pass 'T6g uppercase pin accepted' || fail "T6g (rc=$RC stderr=[$ERR])"
assert_eq "$PIN_A" "$(jget "$(ls "$P/competition"/ha-competition-*.json)" pins.A.fingerprint_sha256)" \
    'T6g pin normalised to lowercase in the manifest'
rm -f "$P/competition/"*
mk_pins "$P/schema.json" "$PIN_A" "$PIN_B" 2030-01-01T00:00:00Z 2030-01-01T00:00:00Z wrong/1
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/schema.json")"
expect_profile_code E_PINS 'T6h wrong pin schema refused' "${A[@]}"
cp "$P/pins.json" "$P/extra.json"
python_pins "$P/extra.json" 'doc["extra"] = 1'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/extra.json")"
expect_profile_code E_PINS 'T6i extra pin key refused' "${A[@]}"
cp "$P/pins.json" "$P/missing.json"
python_pins "$P/missing.json" 'del doc["vps"]["B"]'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/missing.json")"
expect_profile_code E_PINS 'T6j missing B pin refused' "${A[@]}"
cp "$P/pins.json" "$P/nosource.json"
python_pins "$P/nosource.json" 'del doc["vps"]["A"]["source"]'
read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/nosource.json")"
expect_profile_code E_PINS 'T6k missing pin source refused' "${A[@]}"
if [ "$POSIX_HOST" = "1" ]; then
    mk_pins "$P/mode.json"; chmod 644 "$P/mode.json"
    read -r -a A <<< "$(profile_args "$P" comp-r1 "$P/mode.json")"
    expect_profile_code E_INSECURE_PERMISSIONS 'T6l 0644 pins file refused' "${A[@]}"
    assert_contains "$ERR" 'role=pins' 'T6l pins permission error names the pins role'
else
    skip 'T6l POSIX pins mode gate (NTFS carries no POSIX mode)'
fi

# -------------------------------------------------------------- T7 delivery --
section 'T7 delivery integrity and path gates'
D="$TMP/delivery-gates"
mk_tree "$D" 2 1
mk_pins "$D/pins.json"
expect_ha_ok "$D" ha-r1 'T7 HA-02 delivery generated'
printf '\n# tampered\n' >> "$D/delivery/event-ob02-ha.yaml"
read -r -a A <<< "$(profile_args "$D")"
expect_profile_code E_DELIVERY_HASH 'T7a tampered HA-02 profile refused' "${A[@]}"
assert_contains "$ERR" 'terminal=event-ob02' 'T7a tamper is attributed to the terminal'
mk_tree "$D" 2 1
mk_pins "$D/pins.json"
expect_ha_ok "$D" ha-r1 'T7 HA-02 delivery regenerated'
mv "$D/delivery/ha-delivery-ha-r1.json" "$D/delivery/other.json"
read -r -a A <<< "$(profile_args "$D")"
expect_profile_code E_DELIVERY 'T7b non-canonical/manifest-less delivery refused' "${A[@]}"
mk_tree "$D" 2 1
mk_pins "$D/pins.json"
expect_ha_ok "$D" ha-r1 'T7 HA-02 delivery regenerated again'
run_profile --delivery "$D/delivery" --pins "$D/pins.json" \
    --output-dir "$D/delivery" --config-version comp-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T7c output directory equal to the delivery refused' \
    || fail "T7c (rc=$RC stderr=[$ERR])"
mkdir -p "$D/delivery/inside"; win_private_acl "$D/delivery/inside"
[ "$POSIX_HOST" = "1" ] && chmod 700 "$D/delivery/inside"
run_profile --delivery "$D/delivery" --pins "$D/pins.json" \
    --output-dir "$D/delivery/inside" --config-version comp-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T7d output directory inside the delivery refused' \
    || fail "T7d (rc=$RC stderr=[$ERR])"
mkdir -p "$D/competition"; win_private_acl "$D/competition"
: > "$D/competition/EVENT-OB01-HAC.YAML"
read -r -a A <<< "$(profile_args "$D")"
expect_profile_code E_OUTPUT_EXISTS 'T7e case-differing existing competition profile refused' "${A[@]}"
rm -f "$D/competition/EVENT-OB01-HAC.YAML"
: > "$D/competition/ha-competition-comp-r1.json"
read -r -a A <<< "$(profile_args "$D")"
expect_profile_code E_OUTPUT_EXISTS 'T7f existing competition manifest refused' "${A[@]}"
rm -f "$D/competition/ha-competition-comp-r1.json"
run_profile --delivery "$D/delivery" --pins "$D/pins.json" \
    --output-dir "$TMP/missing-output" --config-version comp-r1
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PATH_CONFLICT role=output-dir' ] \
    && pass 'T7g missing output directory refused' \
    || fail "T7g (rc=$RC stderr=[$ERR])"
if [ "$POSIX_HOST" = "1" ]; then
    chmod 755 "$D/delivery"
    read -r -a A <<< "$(profile_args "$D")"
    expect_profile_code E_INSECURE_PERMISSIONS 'T7h delivery dir 0755 refused' "${A[@]}"
    assert_contains "$ERR" 'role=delivery-input' 'T7h delivery permission role named'
    chmod 700 "$D/delivery"
    chmod 755 "$D/competition"
    read -r -a A <<< "$(profile_args "$D")"
    expect_profile_code E_INSECURE_PERMISSIONS 'T7i output dir 0755 refused' "${A[@]}"
    chmod 700 "$D/competition"
else
    skip 'T7h/T7i POSIX mode gates (NTFS carries no POSIX mode)'
fi
if [ "$IS_WINDOWS" = "1" ]; then
    mk_tree "$D" 1 1
    mk_pins "$D/pins.json"
    expect_ha_ok "$D" ha-r1 'T7 Windows delivery generated'
    if ! win_grant "$D/delivery" "*S-1-5-32-545:(OI)(CI)R"; then
        fail 'T7j fixture: could not grant BUILTIN\\Users on the delivery'
    else
        read -r -a A <<< "$(profile_args "$D")"
        expect_profile_code E_INSECURE_PERMISSIONS 'T7j other-user grant on the delivery refused' "${A[@]}"
        assert_contains "$ERR" 'role=delivery-input' 'T7j Windows delivery permission role named'
    fi
    mk_tree "$D" 1 1
    mk_pins "$D/pins.json"
    expect_ha_ok "$D" ha-r1 'T7 Windows delivery regenerated'
    if ! MSYS_NO_PATHCONV=1 cmd.exe /c mklink /J \
            "$(cygpath -w "$D/delivery-link")" "$(cygpath -w "$D/delivery")" >/dev/null 2>&1 \
       || [ ! -d "$D/delivery-link" ]; then
        fail 'T7k fixture: could not create a delivery junction'
    else
        run_profile --delivery "$D/delivery-link" --pins "$D/pins.json" \
            --output-dir "$D/competition" --config-version comp-r1
        [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_PATH_CONFLICT role=delivery-input}" != "$ERR1" ] \
            && pass 'T7k junction delivery is refused' \
            || fail "T7k (rc=$RC stderr=[$ERR])"
    fi
    mk_tree "$D" 1 1
    mk_pins "$D/pins.json"
    expect_ha_ok "$D" ha-r1 'T7 Windows delivery regenerated again'
    rm -rf "$D/competition"; mkdir -p "$D/competition-real"
    if ! MSYS_NO_PATHCONV=1 cmd.exe /c mklink /J \
            "$(cygpath -w "$D/competition")" "$(cygpath -w "$D/competition-real")" >/dev/null 2>&1 \
       || [ ! -d "$D/competition" ]; then
        fail 'T7l fixture: could not create an output junction'
    else
        read -r -a A <<< "$(profile_args "$D")"
        expect_profile_code E_PATH_CONFLICT 'T7l junction output directory refused' "${A[@]}"
    fi
else
    skip 'T7j/T7k/T7l native Windows ACL and junction gates (not a Windows host)'
fi

# ------------------------------------------- T7m check-mode security gates ---
section 'T7m --check security, ACL and tamper gates'
C="$TMP/check"
mk_tree "$C" 2 1
mk_pins "$C/pins.json"
expect_ha_ok "$C" ha-r1 'T7m HA-02 delivery generated'
expect_gen_ok "$C" comp-r1 'T7m competition delivery generated'
CMAN="$(ls "$C/competition"/ha-competition-*.json)"
SNAP="$TMP/check-snap"
rm -rf "$SNAP"; cp -R "$C/competition" "$SNAP"
restore_comp() {
    rm -rf "$C/competition"; cp -R "$SNAP" "$C/competition"
    if [ "$POSIX_HOST" = "1" ]; then
        chmod 700 "$C/competition"; chmod 600 "$C/competition"/*
    fi
}
manifest_edit() { # <python code operating on `doc`>
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
rehash_outputs() {
    "$PY" - "$C/competition" "$CMAN" <<'PY'
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
run_check() { run_profile --delivery "$C/competition" --pins "$C/pins.json" --check; }
run_check
[ "$RC" -eq 0 ] && pass 'T7m baseline --check passes' \
    || fail "T7m baseline (rc=$RC stderr=[$ERR])"
if [ "$POSIX_HOST" = "1" ]; then
    mkdir -p "$C/out2"; chmod 700 "$C/out2"
    chmod 644 "$C/delivery/event-ob01-ha.yaml"
    run_profile --delivery "$C/delivery" --pins "$C/pins.json" \
        --output-dir "$C/out2" --config-version comp-r2
    [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=input-profile}" != "$ERR1" ] \
        && pass 'T7n 0644 HA-02 input profile refused with its role' \
        || fail "T7n (rc=$RC stderr=[$ERR])"
    chmod 600 "$C/delivery/event-ob01-ha.yaml"
    chmod 644 "$C/competition/event-ob01-hac.yaml"
    run_check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=output-file}" != "$ERR1" ] \
        && pass 'T7o 0644 competition output refused by --check' \
        || fail "T7o (rc=$RC stderr=[$ERR])"
    restore_comp
    chmod 644 "$CMAN"
    run_check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=manifest-file}" != "$ERR1" ] \
        && pass 'T7p 0644 competition manifest refused by --check' \
        || fail "T7p (rc=$RC stderr=[$ERR])"
    restore_comp
else
    skip 'T7n/T7o/T7p POSIX per-file mode gates (NTFS carries no POSIX mode)'
fi
restore_comp
"$PY" - "$CMAN" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = '  "schema": "mihomo-competition-ha-profile/2",'
if needle not in text:
    raise SystemExit("fixture: schema line missing")
text = text.replace(needle, needle + "\n" + needle, 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_DELIVERY' ] \
    && pass 'T7q duplicate JSON keys in the manifest refused' \
    || fail "T7q (rc=$RC stderr=[$ERR])"
restore_comp
"$PY" - "$C/dup-pins.json" "$C/pins.json" <<'PY'
import sys
src, dest = sys.argv[1:3]
text = open(src, encoding="utf-8").read()
needle = '  "schema": "mihomo-competition-ha-pins/2",'
if needle not in text:
    raise SystemExit("fixture: pins schema line missing")
open(dest, "w", encoding="utf-8", newline="").write(
    text.replace(needle, needle + "\n" + needle, 1))
PY
[ "$POSIX_HOST" = "1" ] && chmod 600 "$C/dup-pins.json"
[ "$IS_WINDOWS" = "1" ] && win_private_file_acl "$C/dup-pins.json"
run_profile --delivery "$C/competition" --pins "$C/dup-pins.json" --check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PINS' ] \
    && pass 'T7r duplicate JSON keys in the pins file refused' \
    || fail "T7r (rc=$RC stderr=[$ERR])"
restore_comp
"$PY" - "$C/competition/event-ob01-hac.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("allow-lan: false", "allow-lan: true", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_TRANSFORM' ] \
    && pass 'T7s re-hashed manifest cannot mask a reopened LAN listener' \
    || fail "T7s (rc=$RC stderr=[$ERR])"
restore_comp
"$PY" - "$C/competition/event-ob01-hac.yaml" "$PIN_A" "$PIN_B" <<'PY'
import sys
path, pin_a, pin_b = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
text = text.replace("    fingerprint: " + pin_a, "    fingerprint: TEMP", 1)
text = text.replace("    fingerprint: " + pin_b, "    fingerprint: " + pin_a, 1)
text = text.replace("    fingerprint: TEMP", "    fingerprint: " + pin_b, 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_TRANSFORM' ] \
    && pass 'T7t re-hashed manifest cannot swap the HY2 pins' \
    || fail "T7t (rc=$RC stderr=[$ERR])"
restore_comp
"$PY" - "$C/competition/event-ob01-hac.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("    skip-cert-verify: false",
                    "    skip-cert-verify: true", 1)
open(path, "w", encoding="utf-8", newline="").write(text)
PY
rehash_outputs
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_TRANSFORM' ] \
    && pass 'T7u re-hashed manifest cannot reintroduce skip-cert-verify true' \
    || fail "T7u (rc=$RC stderr=[$ERR])"
restore_comp
cp "$C/competition/event-ob01-hac.yaml" "$C/competition/extra-hac.yaml"
[ "$POSIX_HOST" = "1" ] && chmod 600 "$C/competition/extra-hac.yaml"
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_DELIVERY' ] \
    && pass 'T7v extra competition profile refused' \
    || fail "T7v (rc=$RC stderr=[$ERR])"
restore_comp
manifest_edit 'doc["terminals"][0]["primary_vps"] = None; doc["terminals"][0]["group"] = None'
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_DELIVERY' ] \
    && pass 'T7w missing primary/null group cannot pass the shape gate' \
    || fail "T7w (rc=$RC stderr=[$ERR])"
restore_comp
manifest_edit 'doc["terminals"][1]["name"] = "Event-OB01"; doc["terminals"][1]["output"] = "Event-OB01-hac.yaml"'
run_check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_DELIVERY' ] \
    && pass 'T7x casefold-duplicate terminal names refused' \
    || fail "T7x (rc=$RC stderr=[$ERR])"
restore_comp
if [ "$POSIX_HOST" = "1" ]; then
    W="$TMP/world-check"
    rm -rf "$W"; mkdir -p "$W"; cp -R "$SNAP" "$W/competition"
    chmod 700 "$W/competition"; chmod 600 "$W/competition"/*
    chmod 777 "$W"
    run_profile --delivery "$W/competition" --pins "$C/pins.json" --check
    [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=delivery-input}" != "$ERR1" ] \
        && pass 'T7y world-writable ancestor refused by --check' \
        || fail "T7y (rc=$RC stderr=[$ERR])"
    chmod 700 "$W"; rm -rf "$W"
else
    skip 'T7y POSIX ancestor-boundary gate (not a POSIX host)'
fi
if [ "$IS_WINDOWS" = "1" ]; then
    restore_comp
    if win_grant "$C/competition/event-ob01-hac.yaml" "*S-1-5-32-545:R"; then
        run_check
        [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=output-file}" != "$ERR1" ] \
            && pass 'T7z other-user grant on an output refused by --check' \
            || fail "T7z (rc=$RC stderr=[$ERR])"
    else
        fail 'T7z fixture: could not grant BUILTIN\\Users on an output'
    fi
    restore_comp
    if win_grant "$C/delivery/event-ob01-ha.yaml" "*S-1-5-32-545:R"; then
        run_profile --delivery "$C/delivery" --pins "$C/pins.json" \
            --output-dir "$C/out-win" --config-version comp-r2
        [ "$RC" -ne 0 ] && [ "${ERR1#ha-profile: FAIL E_INSECURE_PERMISSIONS role=input-profile}" != "$ERR1" ] \
            && pass 'T7z2 other-user grant on an input profile refused' \
            || fail "T7z2 (rc=$RC stderr=[$ERR])"
    else
        fail 'T7z2 fixture: could not grant BUILTIN\\Users on an input'
    fi
else
    skip 'T7z/T7z2 native Windows ACL negatives (not a Windows host)'
fi

# ------------------------------------------------------------- T8 transform ---
section 'T8 transform refuses unexpected input'
UNIT=$("$PY" - "$TOOL" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("profile", sys.argv[1])
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)
pin_a = "a" * 64
pin_b = "b" * 64
good = None
bad = []
cases = {
    "missing-listen": b"proxies:\n  - name: Hysteria2\n    skip-cert-verify: true\n\n",
    "no-skip": b'  listen: "0.0.0.0:53"\nproxy-groups:\n',
    "existing-pin": b'  listen: "0.0.0.0:53"\n  - name: Hysteria2\n    skip-cert-verify: true\n    fingerprint: ' + b"c" * 64 + b"\n\n",
    "crlf": b'  listen: "0.0.0.0:53"\r\n',
    "missing-allow-lan": b'bind-address: "*"\n  listen: "0.0.0.0:53"\n  - name: Hysteria2\n    skip-cert-verify: true\n\n',
}
for label, data in cases.items():
    try:
        profile.transform(data, pin_a, pin_b)
        bad.append(label + ":accepted")
    except profile.ProfileError as exc:
        if exc.code != "E_TRANSFORM":
            bad.append(label + ":wrong=" + exc.code)
print("ok" if not bad else ";".join(bad))
PY
)
assert_eq 'ok' "$UNIT" 'T8 malformed input is refused by the transformer'
run_profile --delivery "$T1/delivery" --pins "$T1/pins.json" \
    --output-dir "$T1/competition" --config-version comp-r1 --help
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-profile: FAIL E_USAGE' ] \
    && pass 'T8b --help stays a silent usage failure' \
    || fail "T8b (rc=$RC stderr=[$ERR])"
run_profile --delivery "$T1/delivery" --pins "$T1/pins.json" \
    --output-dir "$T1/competition" --config-version ../escape
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-profile: FAIL E_USAGE' ] \
    && pass 'T8c path-traversal version refused' \
    || fail "T8c (rc=$RC stderr=[$ERR])"
run_profile --delivery "$T1/delivery" --pins "$T1/pins.json"
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-profile: FAIL E_USAGE' ] \
    && pass 'T8d missing output/version in generate mode refused' \
    || fail "T8d (rc=$RC stderr=[$ERR])"
run_profile --delivery "$T1/delivery" --pins "$T1/pins.json" \
    --output-dir "$T1/competition" --config-version comp-r1 --password leak
if [ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-profile: FAIL E_USAGE' ]; then
    assert_absent_servers "$OUT$ERR" 'T8e unknown option never echoes argv'
else
    fail "T8e (rc=$RC stderr=[$ERR])"
fi
run_profile --delivery "$T1/delivery" --pins "$T1/pins.json" \
    --output-dir "$T1/competition" --config-version comp-r1 \
    --require-valid-through 2031-13-99T99:99:99Z
[ "$RC" -eq 2 ] && [ "$ERR1" = 'ha-profile: FAIL E_USAGE' ] \
    && pass 'T8f malformed require-valid-through refused' \
    || fail "T8f (rc=$RC stderr=[$ERR])"

# --------------------------------------------------------------- T9 check ----
section 'T9 --check preflight'
T9="$TMP/t9"
mk_tree "$T9" 2 1
mk_pins "$T9/pins.json"
expect_ha_ok "$T9" ha-r1 'T9 HA-02 delivery generated'
expect_gen_ok "$T9" comp-r1 'T9 competition profiles generated'
run_profile --delivery "$T9/competition" --pins "$T9/pins.json" --check
if [ "$RC" -eq 0 ] && [ "${OUT%%$'\n'*}" = 'ha-profile: OK' ]; then
    assert_contains "$OUT" 'terminals: 2' 'T9a preflight reports two terminals'
    assert_contains "$OUT" 'pins: valid' 'T9a preflight reports valid pins'
    pass 'T9a valid competition delivery passes preflight'
else
    fail "T9a (rc=$RC stdout=[$OUT] stderr=[$ERR])"
fi
mk_pins "$T9/expired.json" "$PIN_A" "$PIN_B" 2020-01-01T00:00:00Z 2030-01-01T00:00:00Z
run_profile --delivery "$T9/competition" --pins "$T9/expired.json" --check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PINS_EXPIRED vps=A detail=not_after=2020-01-01T00:00:00Z' ] \
    && pass 'T9b expired pin fails preflight' \
    || fail "T9b (rc=$RC stderr=[$ERR])"
mk_pins "$T9/other.json" "$(printf 'c%.0s' $(seq 1 64))" "$PIN_B"
run_profile --delivery "$T9/competition" --pins "$T9/other.json" --check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_PINS vps=A detail=manifest mismatch' ] \
    && pass 'T9c changed pin fails preflight' \
    || fail "T9c (rc=$RC stderr=[$ERR])"
printf '\n# tampered\n' >> "$T9/competition/event-ob01-hac.yaml"
run_profile --delivery "$T9/competition" --pins "$T9/pins.json" --check
[ "$RC" -ne 0 ] && [ "$ERR1" = 'ha-profile: FAIL E_DELIVERY_HASH terminal=event-ob01' ] \
    && pass 'T9d tampered competition output fails preflight' \
    || fail "T9d (rc=$RC stderr=[$ERR])"

# ------------------------------------------------------------- T10 rollback ---
section 'T10 rollback of a partial competition write'
RB="$TMP/rb"
mk_tree "$RB" 3 2
mk_pins "$RB/pins.json"
expect_ha_ok "$RB" ha-r1 'T10 HA-02 delivery generated'
printf 'operator note\n' > "$RB/competition/keep-me.txt"
DRIVER='
import importlib.util
import sys
tool, delivery, pins, out = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("profile", tool)
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)
batch = profile.load_batch_tool()
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
    profile.generate(delivery, pins, out, "comp-r1", 7, None, batch, merge)
    print("res code=NONE")
except profile.ProfileError as exc:
    rb = exc.rollback or {"removed": 0, "skipped": 0, "complete": True}
    print("res code=%s removed=%d skipped=%d complete=%s" % (
        exc.code, rb["removed"], rb["skipped"],
        "yes" if rb["complete"] else "no"))
'
RBOUT=$("$PY" -c "$DRIVER" "$TOOL" "$RB/delivery" "$RB/pins.json" \
    "$RB/competition" 2>&1 | tr -d '\r')
assert_contains "$RBOUT" 'code=E_IO removed=1 skipped=0 complete=yes' \
    'T10a mid-batch failure rolls back the created profile'
assert_eq 1 "$(find "$RB/competition" -maxdepth 1 -type f | wc -l | tr -d ' ')" \
    'T10a only the pre-existing file remains'
assert_file "$RB/competition/keep-me.txt" 'T10a unrelated file preserved'

# ---------------------------------------------------------- T11 core load -----
section 'T11 pinned core loads the competition profiles'
CORE="${HA03_MIHOMO:-${HA02_MIHOMO:-}}"
if [ -n "$CORE" ]; then
    WORK="$TMP/core-work"; mkdir -p "$WORK"
    LOADED=0
    CORE_RC=0
    CORE_FAIL=''
    for profile_file in "$T5/competition"/*-hac.yaml; do
        if ! "$CORE" -t -d "$WORK" -f "$profile_file" \
                >"$LOGS/core-$LOADED.out" 2>&1; then
            CORE_RC=1
            CORE_FAIL="$(basename "$profile_file"): $(tail -2 "$LOGS/core-$LOADED.out" | tr '\n' ' ')"
        fi
        LOADED=$((LOADED + 1))
    done
    if [ "$CORE_RC" -eq 0 ]; then
        printf '  core-load: OK profiles=%d\n' "$LOADED"
        pass "T11 pinned core loaded $LOADED competition profiles"
    else
        fail "T11 pinned core rejected a competition profile ($CORE_FAIL)"
    fi
else
    skip 'T11 pinned-core competition load (set HA03_MIHOMO or HA02_MIHOMO)'
fi

# ------------------------------------------------------------------ summary --
section 'summary'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
