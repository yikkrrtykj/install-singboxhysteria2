#!/usr/bin/env bash
# Phase C regression tests: multi-client management in install.sh.
#
# These tests really EXECUTE the shell functions: the phase-c block is extracted
# from install.sh between its markers, sourced with every external dependency
# pointed at a throwaway sandbox (mock sing-box binary, mock systemctl/pgrep,
# temp state file), and then the actual functions are called.
#
# Nothing here touches /root/sbox: every path is overridden via the SB_* env
# vars that install.sh honours, and the mock binaries only exist under TMP.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$HERE/../install.sh"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() { # assert_rc <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi
}
assert_grep() { # assert_grep <pattern> <file> <label>
    if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi
}
assert_no_grep() {
    if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi
}

section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then pass "shellcheck install.sh"; else fail "shellcheck install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
else
    printf '  SKIP shellcheck 未安装\n'
fi
assert_grep '"name": "legacy"' "$INSTALL_SH" "fresh install stamps the default account as name=legacy"

section "extract phase-c block and prepare sandbox"
awk '/# >>> phase-c client-management >>>/,/# <<< phase-c client-management <<</' \
    "$INSTALL_SH" > "$TMP/phasec.sh"
if grep -q commit_server_config "$TMP/phasec.sh"; then pass "phase-c block extracted"; else fail "phase-c block extraction"; fi

SANDBOX="$TMP/sandbox"
SB_SANDBOX_CONFIG="$SANDBOX/sbconfig_server.json"
SB_SANDBOX_STATE="$SANDBOX/config"
SB_SANDBOX_CLIENTS="$SANDBOX/clients"
export SB_SERVER_CONFIG="$SB_SANDBOX_CONFIG"
export SB_STATE_FILE="$SB_SANDBOX_STATE"
export SB_CLIENTS_DIR="$SB_SANDBOX_CLIENTS"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"

mkdir -p "$SANDBOX" "$TMP/bin"
# Mock sing-box: check validates JSON (fails when the fail-flag file exists);
# generate returns deterministic, unique credentials.
cat > "$SB_SING_BOX_BIN" <<'MOCK'
#!/usr/bin/env bash
set -u
COUNT_FILE="${MOCK_COUNT_FILE:?}"
case "${1:-}" in
  check)
    [ -f "${MOCK_SB_CHECK_FAIL:-/nonexistent}" ] && exit 1
    file=""
    while [ $# -gt 0 ]; do
      case "$1" in -c) file="$2"; shift 2 ;; *) shift ;; esac
    done
    [ -n "$file" ] || exit 1
    jq empty "$file" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  generate)
    n="$(cat "$COUNT_FILE" 2>/dev/null || echo 0)"; n=$((n + 1)); printf '%s\n' "$n" > "$COUNT_FILE"
    case "${2:-}" in
      uuid) printf 'aaaaaaaa-aaaa-aaaa-aaaa-%012d\n' "$n" ;;
      rand) printf 'bbbb%028x\n' "$n" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$SB_SING_BOX_BIN"
export MOCK_COUNT_FILE="$TMP/cred-count"

# Printing helpers identical to install.sh's, but error() records instead of
# exiting so a stray failure cannot silently kill the harness.
info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; EXIT_ON_ERROR=1; }
# Mock the process manager: reload succeeds unless SYSTEMCTL_MODE=reload_fail;
# is-active reports "running" unless SYSTEMCTL_MODE=stopped.
SYSTEMCTL_MODE="ok"
systemctl() {
    case "$1" in
        is-active) [ "$SYSTEMCTL_MODE" = "stopped" ] && return 3; return 0 ;;
        reload) [ "$SYSTEMCTL_MODE" = "reload_fail" ] && return 1; return 0 ;;
    esac
    return 0
}
pgrep() { [ "$SYSTEMCTL_MODE" != "stopped" ]; }
sleep() { return 0; }

# shellcheck source=/dev/null
. "$TMP/phasec.sh"

write_old_config() { # 旧安装形态：Reality/HY2 各一个无名用户
    cat > "$SB_SANDBOX_CONFIG" <<'EOF'
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 18443,
      "users": [
        {"uuid": "OLD-REALITY-UUID", "flow": "xtls-rprx-vision"}
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {"server": "itunes.apple.com", "server_port": 443},
          "private_key": "OLD-KEY",
          "short_id": ["0123abcd"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 18444,
      "users": [
        {"password": "OLD-HY2-PASSWORD"}
      ],
      "tls": {"enabled": true, "alpn": ["h3"]}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
}
write_state_file() {
    cat > "$SB_SANDBOX_STATE" <<'EOF'
SERVER_IP='203.0.113.9'
PUBLIC_KEY='TEST-PUBLIC-KEY'
HY_SERVER_NAME='bing.com'
HY_HOPPING=FALSE
HY_HOPPING_START=
HY_HOPPING_END=
EOF
}
config_names() {
    printf 'reality: %s\n' "$(get_reality_client_names | sort | tr '\n' ',')"
    printf 'hy2: %s\n' "$(get_hy2_client_names | sort | tr '\n' ',')"
}

section "regression C1: legacy migration keeps keys and adds name only"
write_old_config; write_state_file
migrate_legacy_clients > "$TMP/c1.out" 2>&1
assert_rc 0 $? "migrate_legacy_clients on old config"
assert_grep 'OLD-REALITY-UUID' "$SB_SANDBOX_CONFIG" "reality uuid unchanged after migrate"
assert_grep 'OLD-HY2-PASSWORD' "$SB_SANDBOX_CONFIG" "hy2 password unchanged after migrate"
assert_grep '"name": "legacy"' "$SB_SANDBOX_CONFIG" "unnamed user renamed to legacy"
names="$(config_names)"
printf '%s\n' "$names" > "$TMP/c1.names"
assert_grep '^reality: legacy,$' "$TMP/c1.names" "reality exposes exactly [legacy]"
assert_grep '^hy2: legacy,$' "$TMP/c1.names" "hy2 exposes exactly [legacy]"
if audit_client_consistency > "$TMP/c1.audit" 2>&1; then pass "audit OK after migrate"; else fail "audit OK after migrate"; fi

section "regression C2: repeated migrate is a no-op"
before="$(jq -S . "$SB_SANDBOX_CONFIG")"
migrate_legacy_clients > "$TMP/c2.out" 2>&1
assert_rc 0 $? "second migrate returns 0"
assert_grep '无需迁移' "$TMP/c2.out" "second migrate reports no-op"
after="$(jq -S . "$SB_SANDBOX_CONFIG")"
if [ "$before" = "$after" ]; then pass "config unchanged by second migrate"; else fail "config changed by second migrate"; fi
legacy_count="$(grep -c '"name": "legacy"' "$SB_SANDBOX_CONFIG")"
assert_rc 2 "$legacy_count" "exactly one legacy per inbound (2 total)"

section "regression C3: add client appears in BOTH protocols"
add_client "vmix-01" > "$TMP/c3.out" 2>&1
assert_rc 0 $? "add_client vmix-01"
assert_grep 'vmix-01' "$SB_SANDBOX_CONFIG" "vmix-01 present in server config"
r_has="$(get_reality_client_names | grep -cx 'vmix-01')"
h_has="$(get_hy2_client_names | grep -cx 'vmix-01')"
assert_rc 1 "$r_has" "vmix-01 in reality users"
assert_rc 1 "$h_has" "vmix-01 in hy2 users"
new_uuid="$(jq -r '.inbounds[] | select(.tag=="vless-in") | .users[] | select(.name=="vmix-01") | .uuid' "$SB_SANDBOX_CONFIG")"
new_pwd="$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .users[] | select(.name=="vmix-01") | .password' "$SB_SANDBOX_CONFIG")"
if [ "$new_uuid" != "OLD-REALITY-UUID" ] && [ "$new_uuid" != "null" ] && [ -n "$new_uuid" ]; then pass "vmix-01 got its own uuid"; else fail "vmix-01 uuid wrong: $new_uuid"; fi
if [ "$new_pwd" != "OLD-HY2-PASSWORD" ] && [ "$new_pwd" != "null" ] && [ -n "$new_pwd" ]; then pass "vmix-01 got its own password"; else fail "vmix-01 password wrong: $new_pwd"; fi

section "regression C4: duplicate add is rejected"
add_client "vmix-01" > "$TMP/c4.out" 2>&1
assert_rc 1 $? "duplicate add_client vmix-01 rejected"
assert_grep '已存在' "$TMP/c4.out" "duplicate reason stated"
assert_rc 1 "$(get_reality_client_names | grep -cx 'vmix-01')" "still exactly one vmix-01 in reality"

section "regression C5: invalid names are rejected"
for bad in "vmix 01" "../../xxx" "a/b" "" "legacy" "-leading" "$(printf 'a%.0s' {1..33})"; do
    add_client "$bad" > "$TMP/c5.out" 2>&1
    assert_rc 1 $? "invalid name rejected: '$bad'"
done
assert_no_grep 'vmix 01|\.\./|a/b' "$SB_SANDBOX_CONFIG" "no invalid name leaked into config"
assert_rc 2 "$(get_reality_client_names | grep -c .)" "reality still has exactly 2 named users"

section "regression C6: per-client generation uses the client's own credentials"
generate_client_configuration "vmix-01" > "$TMP/c6.out" 2>&1
assert_rc 0 $? "generate_client_configuration vmix-01"
yaml="$SB_SANDBOX_CLIENTS/vmix-01/mihomo.yaml"
if [ -f "$yaml" ]; then pass "mihomo.yaml written"; else fail "mihomo.yaml missing"; fi
assert_grep "uuid: $new_uuid" "$yaml" "YAML uses vmix-01's own uuid"
assert_grep "password: $new_pwd" "$yaml" "YAML uses vmix-01's own password"
assert_no_grep 'OLD-REALITY-UUID|OLD-HY2-PASSWORD' "$yaml" "YAML must NOT contain legacy credentials"
dir_mode="$(stat -c %a "$SB_SANDBOX_CLIENTS/vmix-01")"
file_mode="$(stat -c %a "$yaml")"
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
    # Windows/MSYS chmod is a no-op for NTFS ACLs; the 0700/0600 assertions are
    # only meaningful on a real Linux server.
    printf '  SKIP permission modes on Windows sandbox (dir=%s file=%s)\n' "$dir_mode" "$file_mode"
else
    assert_rc 700 "$dir_mode" "client dir mode 700"
    assert_rc 600 "$file_mode" "client yaml mode 600"
fi

section "regression C7: delete removes from both protocols, then derived files"
if echo y | delete_client "vmix-01" > "$TMP/c7.out" 2>&1; then pass "delete_client vmix-01"; else fail "delete_client vmix-01"; fi
assert_rc 0 "$(get_reality_client_names | grep -cx 'vmix-01')" "vmix-01 gone from reality"
assert_rc 0 "$(get_hy2_client_names | grep -cx 'vmix-01')" "vmix-01 gone from hy2"
if [ ! -e "$SB_SANDBOX_CLIENTS/vmix-01" ]; then pass "derived client dir removed after success"; else fail "derived dir still present"; fi
assert_grep 'OLD-REALITY-UUID' "$SB_SANDBOX_CONFIG" "legacy untouched by delete"

section "regression C8: legacy is reserved and cannot be deleted"
delete_client "legacy" > "$TMP/c8.out" 2>&1
assert_rc 1 $? "delete legacy refused"
assert_grep '保留名称' "$TMP/c8.out" "reserved-name reason stated"
assert_grep 'OLD-REALITY-UUID' "$SB_SANDBOX_CONFIG" "legacy still present"

section "regression C9: inconsistent name sets block destructive operations"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
add_client "vmix-01" >/dev/null 2>&1
add_client "vmix-02" >/dev/null 2>&1
# Break HY2 only: same user count, different name set
jq --arg name "vmix-02" '
  (.inbounds[] | select(.tag=="hy2-in") | .users) |=
    map(if .name == $name then .name = "laptop" else . end)
' "$SB_SANDBOX_CONFIG" > "$SB_SANDBOX_CONFIG.broken" && mv "$SB_SANDBOX_CONFIG.broken" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c9.audit" 2>&1; then fail "audit FAILS on mismatched name sets"; else pass "audit FAILS on mismatched name sets"; fi
assert_grep 'name 集合不一致' "$TMP/c9.audit" "mismatch reason stated"
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
add_client "vmix-03" > "$TMP/c9.add" 2>&1
assert_rc 1 $? "add refused while inconsistent"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "add refused did not touch config"; else fail "add refused mutated config"; fi
echo y | delete_client "vmix-01" > "$TMP/c9.del" 2>&1
if grep -q '禁止破坏性操作' "$TMP/c9.del"; then pass "delete refused while inconsistent"; else fail "delete not blocked while inconsistent"; fi
after_del="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_del" ]; then pass "delete refused did not touch config"; else fail "delete refused mutated config"; fi

section "regression C10: failed sing-box check leaves the live config untouched"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
before_sha="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
: > "$TMP/check-fail"
MOCK_SB_CHECK_FAIL="$TMP/check-fail" add_client "broken-cfg" > "$TMP/c10.out" 2>&1
assert_rc 1 $? "add_client fails when sing-box check rejects the candidate"
after_sha="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_sha" = "$after_sha" ]; then pass "live config sha unchanged after failed check"; else fail "live config was modified by failed check"; fi
assert_no_grep 'broken-cfg' "$SB_SANDBOX_CONFIG" "rejected client never reached the live config"
if ! ls "$SB_SANDBOX_CONFIG".candidate.* >/dev/null 2>&1; then pass "candidate cleaned up"; else fail "candidate file left behind"; fi

section "regression C11: reload failure rolls back to the previous config"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
before_sha="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
SYSTEMCTL_MODE="reload_fail" add_client "vmix-rb" > "$TMP/c11.out" 2>&1
assert_rc 1 $? "add_client fails when reload fails"
after_sha="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_sha" = "$after_sha" ]; then pass "config rolled back after reload failure"; else fail "config NOT rolled back after reload failure"; fi
assert_no_grep 'vmix-rb' "$SB_SANDBOX_CONFIG" "rolled-back client absent from live config"
assert_grep '回滚' "$TMP/c11.out" "rollback explicitly reported"
assert_rc 0 "$(get_reality_client_names | grep -cx 'vmix-rb')" "no vmix-rb in reality after rollback"
assert_rc 0 "$(get_hy2_client_names | grep -cx 'vmix-rb')" "no vmix-rb in hy2 after rollback"
SYSTEMCTL_MODE="ok"

section "regression C12: missing vless-in must FAIL and block add"
write_old_config; write_state_file
jq '.inbounds = [.inbounds[] | select(.tag != "vless-in")]' "$SB_SANDBOX_CONFIG" \
    > "$SB_SANDBOX_CONFIG.tmp" && mv "$SB_SANDBOX_CONFIG.tmp" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c12.audit" 2>&1; then fail "audit passes without vless-in"; else pass "audit FAILS when vless-in missing"; fi
assert_grep '缺少 vless-in' "$TMP/c12.audit" "missing vless-in reason stated"
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
add_client "no-reality" > "$TMP/c12.add" 2>&1
assert_rc 1 $? "add_client blocked without vless-in"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "config unchanged when vless-in missing"; else fail "config mutated without vless-in"; fi

section "regression C13: duplicated vless-in must FAIL"
write_old_config; write_state_file
jq '.inbounds += [.inbounds[] | select(.tag == "vless-in")]' "$SB_SANDBOX_CONFIG" \
    > "$SB_SANDBOX_CONFIG.tmp" && mv "$SB_SANDBOX_CONFIG.tmp" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c13.audit" 2>&1; then fail "audit passes with duplicated vless-in"; else pass "audit FAILS with duplicated vless-in"; fi
assert_grep 'vless-in 入站数量不是 1' "$TMP/c13.audit" "duplicate vless-in reason stated"
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
add_client "dup-reality" > "$TMP/c13.add" 2>&1
assert_rc 1 $? "add_client blocked with duplicated vless-in"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "config unchanged with duplicated vless-in"; else fail "config mutated with duplicated vless-in"; fi

section "regression C14: missing hy2-in must FAIL (symmetric)"
write_old_config; write_state_file
jq '.inbounds = [.inbounds[] | select(.tag != "hy2-in")]' "$SB_SANDBOX_CONFIG" \
    > "$SB_SANDBOX_CONFIG.tmp" && mv "$SB_SANDBOX_CONFIG.tmp" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c14.audit" 2>&1; then fail "audit passes without hy2-in"; else pass "audit FAILS when hy2-in missing"; fi
assert_grep '缺少 hy2-in' "$TMP/c14.audit" "missing hy2-in reason stated"
add_client "no-hy2" > "$TMP/c14.add" 2>&1
assert_rc 1 $? "add_client blocked without hy2-in"

section "regression C15: duplicated hy2-in must FAIL (symmetric)"
write_old_config; write_state_file
jq '.inbounds += [.inbounds[] | select(.tag == "hy2-in")]' "$SB_SANDBOX_CONFIG" \
    > "$SB_SANDBOX_CONFIG.tmp" && mv "$SB_SANDBOX_CONFIG.tmp" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c15.audit" 2>&1; then fail "audit passes with duplicated hy2-in"; else pass "audit FAILS with duplicated hy2-in"; fi
assert_grep 'hy2-in 入站数量不是 1' "$TMP/c15.audit" "duplicate hy2-in reason stated"

section "regression C12b: non-array users must FAIL"
write_old_config; write_state_file
jq '(.inbounds[] | select(.tag == "vless-in") | .users) = {"name": "oops"}' "$SB_SANDBOX_CONFIG" \
    > "$SB_SANDBOX_CONFIG.tmp" && mv "$SB_SANDBOX_CONFIG.tmp" "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c12b.audit" 2>&1; then fail "audit passes with non-array users"; else pass "audit FAILS with non-array users"; fi
assert_grep 'users 不是数组' "$TMP/c12b.audit" "non-array users reason stated"

section "regression C16: rollback reload failure must NOT be reported as recovered"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
# First reload fails AND the rollback reload fails too, while pgrep/systemctl
# keep reporting the process alive: recovery must not be claimed.
SYSTEMCTL_MODE="reload_fail" add_client "vmix-c16" > "$TMP/c16.out" 2>&1
assert_rc 1 $? "add_client fails when first and rollback reload both fail"
assert_no_grep '已回滚并重新加载上一份配置' "$TMP/c16.out" "must NOT claim successful rollback reload"
assert_grep '未能确认恢复' "$TMP/c16.out" "manual-intervention message stated"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "live config restored to backup content"; else fail "live config differs from backup after rollback"; fi
SYSTEMCTL_MODE="ok"

section "regression C17: concurrent add must not lose updates"
if ! command -v flock >/dev/null 2>&1; then
    printf '  SKIP concurrency test: flock unavailable\n'
else
    CONC="$TMP/conc"
    mkdir -p "$CONC"
    # Point the harness at a FRESH sandbox shared by both concurrent children.
    export SB_SERVER_CONFIG="$CONC/sbconfig_server.json"
    export SB_STATE_FILE="$CONC/config"
    export SB_CLIENTS_DIR="$CONC/clients"
    export SB_SING_BOX_BIN="$TMP/mock-sing-box"
    export SB_LOCK_FILE="$CONC/config.lock"
    SB_SANDBOX_CONFIG="$SB_SERVER_CONFIG"
    write_old_config; write_state_file
    migrate_legacy_clients >/dev/null 2>&1
    # Slow mock sing-box: widens the read-modify-write window so an unlocked
    # implementation would deterministically lose one update.
    cat > "$TMP/mock-sing-box-slow" <<MOCK
#!/usr/bin/env bash
set -u
COUNT_FILE="$CONC/cred-count"
case "\${1:-}" in
  check)
    file=""
    while [ \$# -gt 0 ]; do case "\$1" in -c) file="\$2"; shift 2 ;; *) shift ;; esac; done
    jq empty "\$file" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  generate)
    sleep 0.5
    n="\$(cat "\$COUNT_FILE" 2>/dev/null || echo 0)"; n=\$((n + 1)); printf '%s\n' "\$n" > "\$COUNT_FILE"
    case "\${2:-}" in
      uuid) printf 'cccccccc-cccc-cccc-cccc-%012d\n' "\$n" ;;
      rand) printf 'dddd%028x\n' "\$n" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
MOCK
    chmod +x "$TMP/mock-sing-box-slow"
    cat > "$CONC/child.sh" <<'CHILD'
set -u
NAME="$1"; CFG="$2"; GO="$3"; MOCK_SB="$4"; PHASEC="$5"
export SB_SERVER_CONFIG="$CFG/sbconfig_server.json"
export SB_STATE_FILE="$CFG/config"
export SB_CLIENTS_DIR="$CFG/clients"
export SB_SING_BOX_BIN="$MOCK_SB"
export SB_LOCK_FILE="$CFG/config.lock"
info() { :; }; warning() { :; }; hint() { :; }; error() { :; }
. "$PHASEC"
systemctl() { case "$1" in is-active) return 0 ;; reload) return 0 ;; esac; return 0; }
pgrep() { return 0; }
# barrier: start together, then race for the same lock
while [ ! -f "$GO" ]; do sleep 0.05; done
add_client "$NAME"
exit $?
CHILD
    : > "$CONC/stage"
    bash "$CONC/child.sh" client-a "$CONC" "$CONC/go" "$TMP/mock-sing-box-slow" "$TMP/phasec.sh" \
        > "$CONC/a.log" 2>&1 &
    cpid1=$!
    bash "$CONC/child.sh" client-b "$CONC" "$CONC/go" "$TMP/mock-sing-box-slow" "$TMP/phasec.sh" \
        > "$CONC/b.log" 2>&1 &
    cpid2=$!
    # wait until both children are through sourcing and are parked at the barrier
    for _ in $(seq 1 50); do
        [ -d "/proc/$cpid1" ] && [ -d "/proc/$cpid2" ] || break
        sleep 0.1
    done
    sleep 1
    : > "$CONC/go"
    wait "$cpid1"; rc_a=$?
    wait "$cpid2"; rc_b=$?
    if [ "$rc_a" -ne 0 ]; then fail "concurrent add client-a (rc=$rc_a): $(cat "$CONC/a.log" | head -n3 | tr '\n' ' ')"; else pass "concurrent add client-a"; fi
    if [ "$rc_b" -ne 0 ]; then fail "concurrent add client-b (rc=$rc_b): $(cat "$CONC/b.log" | head -n3 | tr '\n' ' ')"; else pass "concurrent add client-b"; fi
    export SB_SERVER_CONFIG="$CONC/sbconfig_server.json"
    export SB_STATE_FILE="$CONC/config"
    export SB_CLIENTS_DIR="$CONC/clients"
    export SB_SING_BOX_BIN="$TMP/mock-sing-box"
    export SB_LOCK_FILE="$CONC/config.lock"
    assert_rc 1 "$(get_reality_client_names | grep -cx 'client-a')" "client-a present in reality"
    assert_rc 1 "$(get_hy2_client_names | grep -cx 'client-a')" "client-a present in hy2"
    assert_rc 1 "$(get_reality_client_names | grep -cx 'client-b')" "client-b present in reality"
    assert_rc 1 "$(get_hy2_client_names | grep -cx 'client-b')" "client-b present in hy2"
    assert_rc 1 "$(get_reality_client_names | grep -cx 'legacy')" "legacy preserved in reality"
    if audit_client_consistency > "$TMP/c17.audit" 2>&1; then pass "final name sets consistent after concurrent adds"; else fail "final name sets inconsistent: $(cat "$TMP/c17.audit" | tr '\n' ' ')"; fi
    if ! ls "$CONC"/sbconfig_server.json.candidate.* >/dev/null 2>&1; then pass "no candidate left behind after concurrent adds"; else fail "candidate residue after concurrent adds"; fi
fi

section "restore main sandbox after C17's dedicated sandbox"
export SB_SERVER_CONFIG="$SB_SANDBOX_CONFIG"
export SB_STATE_FILE="$SB_SANDBOX_STATE"
export SB_CLIENTS_DIR="$SB_SANDBOX_CLIENTS"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"

section "regression C18: missing inbounds entirely must FAIL audit"
printf '{}\n' > "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c18.audit" 2>&1; then fail "audit passes on {}"; else pass "audit FAILS on {}"; fi
assert_grep '缺少 inbounds 字段' "$TMP/c18.audit" "missing inbounds reason stated"
assert_no_grep '一致性检查通过' "$TMP/c18.audit" "must not report a passing audit"
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
add_client "ghost" > "$TMP/c18.add" 2>&1
assert_rc 1 $? "add_client blocked on {}"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "live config SHA unchanged on {}"; else fail "config mutated on {}"; fi

section "regression C19: inbounds=null must FAIL audit"
printf '{"inbounds": null}\n' > "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c19.audit" 2>&1; then fail "audit passes with inbounds=null"; else pass "audit FAILS with inbounds=null"; fi
assert_grep '缺少 inbounds 字段' "$TMP/c19.audit" "null inbounds reported as missing"
add_client "ghost-null" > "$TMP/c19.add" 2>&1
assert_rc 1 $? "add_client blocked with inbounds=null"

section "regression C20: non-array inbounds must FAIL audit"
printf '{"inbounds": {}}\n' > "$SB_SANDBOX_CONFIG"
if audit_client_consistency > "$TMP/c20.audit" 2>&1; then fail "audit passes with inbounds={}]"; else pass "audit FAILS with inbounds={}"; fi
assert_grep 'inbounds 不是数组' "$TMP/c20.audit" "non-array inbounds reason stated"

section "regression C21: jq runtime failure inside audit must fail closed"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
# Wrap jq: fail ONLY the identity-check program (exit 5) while letting the
# structural program and everything else through -- proving the caller checks
# candidate_problems' exit code, not just its stdout.
jq() {
    if [ "${MOCK_JQ_FAIL_IDENTITY:-0}" = "1" ] &&
       [ "${1:-}" = "-r" ] &&
       [[ "${2:-}" == *"name 集合不一致"* ]]; then
        return 5
    fi
    command jq "$@"
}
MOCK_JQ_FAIL_IDENTITY=1 audit_client_consistency > "$TMP/c21.audit" 2>&1
assert_rc 1 $? "audit fail-closed when identity jq errors"
assert_grep '结构审计执行失败' "$TMP/c21.audit" "audit error reason stated"
assert_no_grep '一致性检查通过' "$TMP/c21.audit" "empty stdout must not mean OK"
MOCK_JQ_FAIL_IDENTITY=1 add_client "jq-broken" > "$TMP/c21.add" 2>&1
assert_rc 1 $? "add_client fail-closed when identity jq errors"
candidate="$SB_SANDBOX_CONFIG.c21-candidate"
cp "$SB_SANDBOX_CONFIG" "$candidate"
MOCK_JQ_FAIL_IDENTITY=1 commit_server_config "$candidate" "c21" > "$TMP/c21.commit" 2>&1
assert_rc 1 $? "commit_server_config fail-closed when identity jq errors"
assert_grep '结构审计执行失败' "$TMP/c21.commit" "commit error reason stated"
if [ ! -e "$candidate" ]; then pass "candidate cleaned up after audit failure"; else fail "candidate left behind"; fi
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "live config untouched by failed-audit transaction"; else fail "live config mutated during audit failure"; fi
unset -f jq
unset MOCK_JQ_FAIL_IDENTITY

section "regression C22: migration on bad structure must FAIL"
printf '{}\n' > "$SB_SANDBOX_CONFIG"
before_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
migrate_legacy_clients > "$TMP/c22.out" 2>&1
assert_rc 1 $? "migrate_legacy_clients fails on {}"
assert_no_grep '无需迁移' "$TMP/c22.out" "must not treat {} as nothing-to-migrate"
assert_grep '缺少 inbounds 字段' "$TMP/c22.out" "structure precheck reason stated"
after_add="$(sha256sum "$SB_SANDBOX_CONFIG" | awk '{print $1}')"
if [ "$before_add" = "$after_add" ]; then pass "config unchanged by failed migration"; else fail "config mutated by failed migration"; fi

section "regression C23: locked delete helper itself refuses legacy"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
with_client_lock _delete_client_locked "legacy" > "$TMP/c23.out" 2>&1
assert_rc 1 $? "_delete_client_locked legacy refused"
assert_grep '保留名称' "$TMP/c23.out" "invariant reason stated"
assert_grep 'OLD-REALITY-UUID' "$SB_SANDBOX_CONFIG" "legacy untouched after direct locked call"

section "regression C24: same-second transactions get unique backups"
write_old_config; write_state_file
migrate_legacy_clients >/dev/null 2>&1
bak_before="$(ls -1 "$SB_SANDBOX_CONFIG".bak.* 2>/dev/null | wc -l)"
# two transactions back-to-back: same second, same shell pid
add_client "bak-a" >/dev/null 2>&1
assert_rc 0 $? "bak-a added"
add_client "bak-b" >/dev/null 2>&1
assert_rc 0 $? "bak-b added"
bak_after="$(ls -1 "$SB_SANDBOX_CONFIG".bak.* 2>/dev/null | wc -l)"
assert_rc 2 "$((bak_after - bak_before))" "two same-second transactions produced two distinct backups"
broken=0
for b in "$SB_SANDBOX_CONFIG".bak.*; do
    [ -s "$b" ] || { fail "backup file empty: $b"; broken=1; }
done
[ "$broken" -eq 0 ] && pass "all backup files exist and are non-empty"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
