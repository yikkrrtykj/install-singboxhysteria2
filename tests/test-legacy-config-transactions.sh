#!/usr/bin/env bash
# Legacy config transaction hardening regression suite (L1..L5).
#
# Scope: the legacy CLI mutation paths that used to write /root/sbox durable
# state OUTSIDE the global /root/sbox/config.lock and with shared fixed temp
# files:
#   - process_doko / process_dokoko / process_ssko   (sbconfig_server.json)
#   - modify_singbox                                 (sbconfig_server.json + config)
#   - set_config_value / enable_hy2hopping / disable_hy2hopping (config)
#   - uninstall/reinstall guard (L5, E3 activation hook)
#
# Like the phase-c/d/s0 suites, every test really EXECUTES the shell functions:
# the phase-c + phase-d + legacy blocks are extracted from install.sh and sourced
# with every external dependency pointed at a throwaway sandbox. Nothing touches
# /root/sbox. Linux CI uses the real flock(1); the local Windows shim only exists
# so the concurrency and lock tests can also run on a dev laptop.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$HERE/../install.sh"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
cleanup() { [ -n "${HOLD_PID:-}" ] && kill "$HOLD_PID" 2>/dev/null; rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_grep() { if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi; }
assert_no_grep() { if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
IS_LINUX=1
case "$(uname -s)" in
    MINGW*|MSYS*) IS_LINUX=0 ;;
esac
mode_of() { stat -c %a "$1" 2>/dev/null; }

# --------------------------------------------------------------- static checks --
section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then pass "shellcheck install.sh"; else fail "shellcheck install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
else
    printf '  SKIP shellcheck 未安装\n'
fi
assert_grep '# >>> legacy-config-transaction-hardening >>>' "$INSTALL_SH" "legacy transaction block start marker present"
assert_grep '# <<< legacy-config-transaction-hardening <<<' "$INSTALL_SH" "legacy transaction block end marker present"
# T8 (static): the shared fixed temp filenames are gone from every migrated path.
assert_no_grep 'sbconfig_server\.temp' "$INSTALL_SH" "no fixed sbconfig_server.temp filename"
assert_no_grep 'sbconfig_server\.json\.temp' "$INSTALL_SH" "no fixed sbconfig_server.json.temp filename"
assert_grep 'new_state_candidate_path\(\)' "$INSTALL_SH" "state candidates use a unique mktemp path"
assert_no_grep '^[[:space:]]*sed -i' "$INSTALL_SH" "no sed -i execution remains in install.sh"
# every migrated writer runs under the SAME global lock.
assert_grep 'with_client_lock _modify_singbox_locked' "$INSTALL_SH" "modify_singbox dual-file transaction takes the global lock"
assert_grep 'with_client_lock _process_doko_add_locked' "$INSTALL_SH" "doko add takes the global lock"
assert_grep 'with_client_lock _process_doko_delete_locked' "$INSTALL_SH" "doko delete takes the global lock"
assert_grep 'with_client_lock _process_dokoko_add_locked' "$INSTALL_SH" "dokoko add takes the global lock"
assert_grep 'with_client_lock _process_ssko_add_locked' "$INSTALL_SH" "ssko add takes the global lock"
assert_grep 'with_client_lock _enable_hy2hopping_locked' "$INSTALL_SH" "enable hy2 hopping takes the global lock"
assert_grep 'with_client_lock _disable_hy2hopping_locked' "$INSTALL_SH" "disable hy2 hopping takes the global lock"
assert_grep 'restore_file_atomically' "$INSTALL_SH" "atomic restore primitive exists"
assert_grep 'cmp -s "\$backup" "\$live"' "$INSTALL_SH" "restore verifies the committed file byte-for-byte"
assert_grep '\.restore\.XXXXXX' "$INSTALL_SH" "restore uses a unique same-directory temp path"
assert_no_grep 'cp -a "\$json_bak" "\$cfg"' "$INSTALL_SH" "no direct cp restore onto the live JSON path"
assert_no_grep 'cp -a "\$state_bak" "\$state"' "$INSTALL_SH" "no direct cp restore onto the live state path"
# L5 guard wiring + ordering (guard BEFORE backup/uninstall in the reinstall branch).
assert_grep 'SB_MANAGEMENT_ACTIVE_MARKER' "$INSTALL_SH" "L5 management-active marker interface exists"
assert_grep 'require_management_inactive "重新安装"' "$INSTALL_SH" "reinstall branch checks the L5 guard"
assert_grep 'require_management_inactive "卸载"' "$INSTALL_SH" "uninstall checks the L5 guard"
guard_line="$(grep -n 'require_management_inactive "重新安装"' "$INSTALL_SH" | head -n1 | cut -d: -f1)"
backup_line="$(grep -n 'backup_current_installation || error' "$INSTALL_SH" | head -n1 | cut -d: -f1)"
unin_line="$(grep -n 'if ! uninstall_singbox; then' "$INSTALL_SH" | head -n1 | cut -d: -f1)"
if [ -n "$guard_line" ] && [ -n "$backup_line" ] && [ -n "$unin_line" ] &&
   [ "$guard_line" -lt "$backup_line" ] && [ "$guard_line" -lt "$unin_line" ]; then
    pass "reinstall guard runs before backup/uninstall (guard=$guard_line backup=$backup_line uninstall=$unin_line)"
else
    fail "reinstall guard ordering (guard=$guard_line backup=$backup_line uninstall=$unin_line)"
fi
# T16 (static): no _locked helper ever waits on interactive input.
for fn in _modify_singbox_locked _process_doko_add_locked _process_doko_delete_locked \
          _process_dokoko_add_locked _process_dokoko_delete_locked \
          _process_ssko_add_locked _process_ssko_delete_locked \
          _enable_hy2hopping_locked _disable_hy2hopping_locked; do
    body="$(awk "/^${fn}\\(\\) \\{/,/^\\}/" "$INSTALL_SH")"
    if [ -z "$body" ]; then
        fail "locked helper $fn not found"
    elif printf '%s\n' "$body" | grep -qE '(^|[^A-Za-z_])read([[:space:]]+-[A-Za-z]+)*[[:space:]]+-p([[:space:]]|$)'; then
        fail "$fn must not prompt for interactive input while holding the lock"
    else
        pass "$fn prompts for no interactive input"
    fi
done

# ------------------------------------------------------- extract blocks + sandbox --
section "extract blocks and prepare sandbox"
awk '/# >>> phase-c client-management >>>/,/# <<< legacy-config-transaction-hardening <<</' \
    "$INSTALL_SH" > "$TMP/blocks.sh"
assert_grep 'commit_server_config' "$TMP/blocks.sh" "phase-c block present (shared lock/audit)"
assert_grep '_modify_singbox_locked' "$TMP/blocks.sh" "legacy block extracted (dual-file transaction)"
assert_grep '_process_doko_add_locked' "$TMP/blocks.sh" "legacy block extracted (doko add)"

SANDBOX="$TMP/sandbox"
mkdir -p "$SANDBOX"
export SB_SERVER_CONFIG="$SANDBOX/sbconfig_server.json"
export SB_STATE_FILE="$SANDBOX/config"
export SB_CLIENTS_DIR="$SANDBOX/clients"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"
export SB_HOPPING_SERVICE="$SANDBOX/sing-box-hy2-hopping.service"
export SB_HOPPING_HELPER="$SANDBOX/hy2-hopping.sh"
export SB_MANAGEMENT_ACTIVE_MARKER="$SANDBOX/web-management.active"
export SB_API_SECRET_FILE="$SANDBOX/monitor-api.secret"
export SB_SELF_CERT_KEY="$SANDBOX/self-cert/private.key"
export SB_SELF_CERT_CERT="$SANDBOX/self-cert/cert.pem"
# flock(1) shim: no-op where util-linux flock exists (Linux/CI), enables the lock
# fail-closed + concurrency regressions on platforms without it (e.g. MSYS2).
. "$HERE/lib/mock-flock.sh"

info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; }

# ---------------------------------------------------------------- shared mocks --
export MOCK_COUNT_FILE="$TMP/cred-count"
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
      rand)
        if [ "${4:-}" = "--base64" ]; then printf 'B64PASSWORD%08d\n' "$n"; else printf 'bbbb%028x\n' "$n"; fi ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$SB_SING_BOX_BIN"

SYSTEMCTL_MODE="ok"
RELOAD_COUNT_FILE="$TMP/reload-count"
systemctl() {
    case "${1:-}" in
        is-active) [ "${SYSTEMCTL_MODE:-ok}" = "stopped" ] && return 3; return 0 ;;
        reload)
            case "${SYSTEMCTL_MODE:-ok}" in
                reload_fail) return 1 ;;
                reload_fail_once)
                    local n
                    n="$(cat "$RELOAD_COUNT_FILE" 2>/dev/null || echo 0)"; n=$((n + 1))
                    printf '%s\n' "$n" > "$RELOAD_COUNT_FILE"
                    [ "$n" -eq 1 ] && return 1
                    return 0 ;;
            esac
            return 0 ;;
        enable|disable|daemon-reload) return 0 ;;
        show) printf '4242\n'; return 0 ;;
    esac
    return 0
}
pgrep() { [ "${PGREP_MODE:-found}" = "found" ]; }
iptables() { return 0; }
ip6tables() { return 0; }
generate_port() { echo 12345; }
modify_port() { echo "${1:-0}"; }
curl() { return 0; }

# shellcheck source=/dev/null
. "$TMP/blocks.sh"

write_config() {
    cat > "$SB_SERVER_CONFIG" <<'EOF'
{
  "log": {"level": "info"},
  "route": {"rules": [{"action": "sniff"}]},
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 18443,
      "users": [
        {"name": "legacy", "uuid": "REALITY-UUID-LEGACY", "flow": "xtls-rprx-vision"}
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {"server": "itunes.apple.com", "server_port": 443},
          "private_key": "REALITY-PRIVATE-KEY",
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
        {"name": "legacy", "password": "HY2-PASSWORD-LEGACY"}
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/root/sbox/self-cert/cert.pem",
        "key_path": "/root/sbox/self-cert/private.key"
      }
    }
  ],
  "services": [
    {"type": "api", "tag": "monitor-api", "listen": "127.0.0.1", "listen_port": 9091, "secret": "API-SECRET-LEGACY"}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
}
write_state() {
    cat > "$SB_STATE_FILE" <<'EOF'
SERVER_IP='203.0.113.9'
PUBLIC_KEY='TEST-PUBLIC-KEY'
HY_SERVER_NAME='bing.com'
HY_HOPPING=FALSE
HY_HOPPING_START=
HY_HOPPING_END=
EOF
}
reset_sandbox() {
    rm -f "$SB_SERVER_CONFIG" "$SB_STATE_FILE" "$SB_MANAGEMENT_ACTIVE_MARKER" "$TMP/destructive-hit"
    rm -f "$SB_SERVER_CONFIG".candidate.* "$SB_SERVER_CONFIG".bak.* 2>/dev/null
    rm -f "$SB_STATE_FILE".candidate.* "$SB_STATE_FILE".bak.* 2>/dev/null
    SYSTEMCTL_MODE="ok"; PGREP_MODE="found"
    write_config
    write_state
}
count_json() { jq "$@" "$SB_SERVER_CONFIG" 2>/dev/null; }

# ------------------------------------------------------------ concurrency farm --
cat > "$TMP/child.sh" <<'CHILD'
set -u
BLOCKS="$1"; GO="$2"; CMD="$3"
info() { :; }
warning() { printf '  [warn] %s\n' "$*" >&2; }
hint() { :; }
error() { printf '  [err ] %s\n' "$*" >&2; }
# shellcheck source=/dev/null
. "$BLOCKS"
systemctl() {
    case "${1:-}" in
        is-active) return 0 ;;
        reload) return 0 ;;
        enable|disable|daemon-reload) return 0 ;;
        show) printf '4242\n'; return 0 ;;
    esac
    return 0
}
pgrep() { return 0; }
iptables() { return 0; }
ip6tables() { return 0; }
mv() {
    if [ "${CHILD_SLOW_STATE:-0}" = "1" ]; then
        local last
        eval "last=\"\${$#}\""
        if [ "$last" = "$SB_STATE_FILE" ]; then command sleep 0.4; fi
    fi
    command mv "$@"
}
delete_client_yes() { echo y | delete_client "$1"; }
while [ ! -f "$GO" ]; do command sleep 0.05; done
eval "$CMD"
exit $?
CHILD

NCHILD=0
CHILD_RCS=()
run_concurrent() { # run_concurrent <workspace> <cmd1> <cmd2> ...
    local conc="$1"; shift
    local go="$conc/go"
    mkdir -p "$conc"; rm -f "$go"
    local pids=() p
    NCHILD=0
    for cmd in "$@"; do
        NCHILD=$((NCHILD + 1))
        bash "$TMP/child.sh" "$TMP/blocks.sh" "$go" "$cmd" > "$conc/log$NCHILD" 2>&1 &
        pids+=("$!")
    done
    command sleep 1
    : > "$go"
    CHILD_RCS=()
    local k=0
    for p in "${pids[@]}"; do
        wait "$p"; CHILD_RCS[$k]=$?; k=$((k + 1))
    done
}

# Slow mock: widens the read-modify-write window so an unlocked implementation
# would deterministically lose one update.
cat > "$TMP/mock-sing-box-slow" <<SLOW
#!/usr/bin/env bash
set -u
COUNT_FILE="${MOCK_COUNT_FILE:?}"
case "\${1:-}" in
  check)
    command sleep 0.3
    file=""
    while [ \$# -gt 0 ]; do case "\$1" in -c) file="\$2"; shift 2 ;; *) shift ;; esac; done
    jq empty "\$file" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  generate)
    command sleep 0.3
    n="\$(cat "\$COUNT_FILE" 2>/dev/null || echo 0)"; n=\$((n + 1)); printf '%s\n' "\$n" > "\$COUNT_FILE"
    case "\${2:-}" in
      uuid) printf 'cccccccc-cccc-cccc-cccc-%012d\n' "\$n" ;;
      rand)
        if [ "\${4:-}" = "--base64" ]; then printf 'B64SLOW%08d\n' "\$n"; else printf 'dddd%028x\n' "\$n"; fi ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
SLOW
chmod +x "$TMP/mock-sing-box-slow"

# lock holders (used by the timeout tests). Reuses the exported flock shim when
# real flock is absent.
HOLD_PID=""
hold_lock() {
    SB_LOCK_FILE="$SB_LOCK_FILE" bash -c \
        'exec 9>>"$SB_LOCK_FILE"; flock -w 30 9; touch "$SB_LOCK_FILE.held"; command sleep 30' &
    HOLD_PID=$!
    local _
    for _ in $(seq 1 60); do
        [ -f "$SB_LOCK_FILE.held" ] && break
        command sleep 0.1
    done
    [ -f "$SB_LOCK_FILE.held" ]
}
release_lock() {
    [ -n "$HOLD_PID" ] && kill "$HOLD_PID" 2>/dev/null
    wait "$HOLD_PID" 2>/dev/null
    HOLD_PID=""
    rm -rf -- "$SB_LOCK_FILE".mocklock* "$SB_LOCK_FILE.held"
}

# ================================================================== TEST 1..18 ==

section "T1: process_doko add vs Phase C add_client -> no lost update"
reset_sandbox
export SB_SING_BOX_BIN="$TMP/mock-sing-box-slow"
run_concurrent "$TMP/t1" "with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443" "add_client client-a"
assert_rc 0 "${CHILD_RCS[0]}" "doko add child succeeded"
assert_rc 0 "${CHILD_RCS[1]}" "Phase C add child succeeded"
assert_rc 1 "$(count_json '[.inbounds[] | select(.tag | startswith("direct-in"))] | length')" "exactly one direct-in rule survived"
assert_rc 1 "$(jq -r '[.inbounds[] | select(.tag=="vless-in") | .users[] | select(.name=="client-a")] | length' "$SB_SERVER_CONFIG")" "client-a present in reality"
assert_rc 1 "$(jq -r '[.inbounds[] | select(.tag=="hy2-in") | .users[] | select(.name=="client-a")] | length' "$SB_SERVER_CONFIG")" "client-a present in hy2"
if audit_client_consistency "$SB_SERVER_CONFIG" >"$TMP/t1.audit" 2>&1; then pass "final name sets consistent after concurrent doko add"; else fail "inconsistent: $(tr '\n' ' ' <"$TMP/t1.audit")"; fi
export SB_SING_BOX_BIN="$TMP/mock-sing-box"

section "T2: process_doko delete vs Phase C delete_client -> no resurrection"
reset_sandbox
with_client_lock _process_doko_add_locked 19991 10.0.0.9 443 >/dev/null 2>&1
add_client client-b >/dev/null 2>&1
direct_tag="$(count_json -r '[.inbounds[] | select(.tag | startswith("direct-in"))][0].tag')"
if [ -n "$direct_tag" ] && [ "$direct_tag" != "null" ]; then pass "pre-created direct-in rule ($direct_tag)"; else fail "could not pre-create direct-in rule"; fi
export SB_SING_BOX_BIN="$TMP/mock-sing-box-slow"
run_concurrent "$TMP/t2" "delete_client_yes client-b" "with_client_lock _process_doko_delete_locked $direct_tag"
assert_rc 0 "${CHILD_RCS[0]}" "Phase C delete child succeeded"
assert_rc 0 "${CHILD_RCS[1]}" "doko delete child succeeded"
assert_rc 0 "$(jq -r '[.inbounds[] | select(.tag=="vless-in") | .users[] | select(.name=="client-b")] | length' "$SB_SERVER_CONFIG")" "client-b not resurrected in reality"
assert_rc 0 "$(jq -r '[.inbounds[] | select(.tag=="hy2-in") | .users[] | select(.name=="client-b")] | length' "$SB_SERVER_CONFIG")" "client-b not resurrected in hy2"
assert_rc 0 "$(count_json --arg t "$direct_tag" '[.inbounds[] | select(.tag == $t)] | length')" "direct-in rule not resurrected"
assert_rc 1 "$(jq -r '[.inbounds[] | select(.tag=="vless-in") | .users[] | select(.name=="legacy")] | length' "$SB_SERVER_CONFIG")" "legacy preserved"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"

section "T3: process_dokoko concurrent add -> no duplicate direct-in"
reset_sandbox
export SB_SING_BOX_BIN="$TMP/mock-sing-box-slow"
run_concurrent "$TMP/t3" "with_client_lock _process_dokoko_add_locked 15000 10.1.1.1" "with_client_lock _process_dokoko_add_locked 15001 10.1.1.2"
okc=0
for rc in "${CHILD_RCS[@]}"; do [ "$rc" -eq 0 ] && okc=$((okc + 1)); done
assert_rc 1 "$okc" "exactly one concurrent dokoko add succeeded"
assert_rc 1 "$(count_json -r '[.inbounds[] | select(.tag=="direct-in")] | length')" "exactly one direct-in inbound (no duplicate)"
assert_rc 1 "$(count_json -r '[.route.rules[] | select(.inbound=="direct-in")] | length')" "exactly one direct-in route rule (no duplicate)"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"

section "T4: process_ssko concurrent add -> no duplicate ss-in"
reset_sandbox
export SB_SING_BOX_BIN="$TMP/mock-sing-box-slow"
run_concurrent "$TMP/t4" "with_client_lock _process_ssko_add_locked 16000" "with_client_lock _process_ssko_add_locked 16001"
okc=0
for rc in "${CHILD_RCS[@]}"; do [ "$rc" -eq 0 ] && okc=$((okc + 1)); done
assert_rc 1 "$okc" "exactly one concurrent ssko add succeeded"
assert_rc 1 "$(count_json -r '[.inbounds[] | select(.tag=="ss-in")] | length')" "exactly one ss-in inbound (no duplicate)"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"

section "T5: legacy JSON transaction failure before commit -> live config byte-identical"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
: > "$TMP/check-fail"
MOCK_SB_CHECK_FAIL="$TMP/check-fail" with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >"$TMP/t5.out" 2>&1
assert_rc 1 $? "doko add fails when sing-box check rejects the candidate"
assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "live config byte-identical after failed commit"
if ! ls "$SB_SERVER_CONFIG".candidate.* >/dev/null 2>&1; then pass "no candidate residue"; else fail "candidate residue left behind"; fi

section "T6: invalid candidate rejected before live replace"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
jq() {
    if [ "${MOCK_JQ_FAIL_IDENTITY:-0}" = "1" ] && [ "${1:-}" = "-r" ] && [[ "${2:-}" == *"name 集合不一致"* ]]; then
        return 5
    fi
    command jq "$@"
}
MOCK_JQ_FAIL_IDENTITY=1 with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >"$TMP/t6.out" 2>&1
assert_rc 1 $? "legacy add fail-closed when the candidate audit errors"
assert_grep '结构审计执行失败' "$TMP/t6.out" "candidate audit error reported"
assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "live config untouched by rejected candidate"
unset -f jq

section "T7: reload/health failure -> old config restored"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
SYSTEMCTL_MODE="reload_fail" with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >"$TMP/t7.out" 2>&1
assert_rc 1 $? "doko add fails when reload fails"
assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "live config rolled back after reload failure"
assert_grep '回滚' "$TMP/t7.out" "rollback explicitly reported"
SYSTEMCTL_MODE="ok"

section "T8: fixed temp filenames are no longer used by migrated paths"
assert_no_grep 'sbconfig_server\.temp' "$TMP/blocks.sh" "legacy block never references sbconfig_server.temp"
assert_grep 'new_candidate_path' "$TMP/blocks.sh" "legacy block builds candidates via new_candidate_path"
reset_sandbox
with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >/dev/null 2>&1
if [ ! -e "$SB_SERVER_CONFIG.temp" ] && [ ! -e "$SB_SERVER_CONFIG.json.temp" ]; then pass "no fixed temp file created by a real transaction"; else fail "fixed temp file created"; fi
if ! ls "$SB_SERVER_CONFIG".candidate.* >/dev/null 2>&1; then pass "candidate cleaned up"; else fail "candidate residue"; fi

section "T9: modify_singbox -> JSON + state change together"
reset_sandbox
before_uuid="$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")"
before_pwd="$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")"
before_key="$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")"
before_secret="$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")"
with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t9.out" 2>&1
assert_rc 0 $? "modify_singbox dual-file transaction succeeds"
assert_rc 18500 "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' "$SB_SERVER_CONFIG")" "reality listen_port updated"
assert_rc 18501 "$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' "$SB_SERVER_CONFIG")" "hy2 listen_port updated"
assert_rc "example.org" "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.server_name' "$SB_SERVER_CONFIG")" "reality server_name updated"
assert_rc "example.org" "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.handshake.server' "$SB_SERVER_CONFIG")" "reality handshake server updated"
assert_rc "cert-new.pem" "$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tls.certificate_path' "$SB_SERVER_CONFIG")" "hy2 certificate_path updated"
assert_rc "key-new.pem" "$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tls.key_path' "$SB_SERVER_CONFIG")" "hy2 key_path updated"
assert_rc "HY_SERVER_NAME='new.example.org'" "$(grep '^HY_SERVER_NAME=' "$SB_STATE_FILE")" "state HY_SERVER_NAME updated"
# T17: credentials preserved.
assert_rc "$before_uuid" "$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")" "Reality UUIDs unchanged"
assert_rc "$before_pwd" "$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")" "HY2 passwords unchanged"
assert_rc "$before_key" "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")" "Reality private key unchanged"
assert_rc "$before_secret" "$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")" "service.api.secret unchanged"

section "T10: forced second-artifact replace failure -> both restored"
reset_sandbox
before_json="$(sha "$SB_SERVER_CONFIG")"
before_state="$(sha "$SB_STATE_FILE")"
mv() {
    if [ "${MV_FAIL_STATE:-0}" = "1" ]; then
        local last
        eval "last=\"\${$#}\""
        if [ "$last" = "$SB_STATE_FILE" ]; then return 1; fi
    fi
    command mv "$@"
}
MV_FAIL_STATE=1 with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t10.out" 2>&1
assert_rc 1 $? "transaction fails when the second artifact cannot be replaced"
assert_rc "$before_json" "$(sha "$SB_SERVER_CONFIG")" "JSON restored after second-artifact failure"
assert_rc "$before_state" "$(sha "$SB_STATE_FILE")" "state unchanged after second-artifact failure"
assert_grep '回滚服务端配置' "$TMP/t10.out" "JSON rollback reported"
unset -f mv

section "T10b: rollback restore itself fails -> manual intervention, no false success"
reset_sandbox
before_uuid="$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")"
before_pwd="$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")"
before_key="$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")"
before_secret="$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")"
# real fault injection: the state-candidate replace is forced to fail (entering the
# second-artifact path) AND every restore atomic mv (unique *.restore.* temp) fails.
mv() {
    local a last
    eval "last=\"\${$#}\""
    if [ "${MV_FAIL_STATE:-0}" = "1" ] && [ "$last" = "$SB_STATE_FILE" ]; then return 1; fi
    if [ "${MV_FAIL_RESTORE:-0}" = "1" ]; then
        for a in "$@"; do case "$a" in *.restore.*) return 1 ;; esac; done
    fi
    command mv "$@"
}
MV_FAIL_STATE=1 MV_FAIL_RESTORE=1 with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t10b.out" 2>&1
assert_rc 1 $? "transaction fails and the restore failure is not swallowed"
assert_grep '人工介入' "$TMP/t10b.out" "manual intervention required"
assert_grep '备份保留' "$TMP/t10b.out" "backup retention stated"
assert_no_grep '已回滚并重新加载上一份配置与状态' "$TMP/t10b.out" "must NOT claim a successful rollback"
assert_no_grep '已恢复并校验上一份配置与状态' "$TMP/t10b.out" "must NOT claim a successful restore"
assert_no_grep '恢复成功' "$TMP/t10b.out" "must NOT claim recovery success"
assert_rc 1 "$(ls -1 "$SB_SERVER_CONFIG".bak.* 2>/dev/null | wc -l)" "JSON hardened backup retained after failed restore"
assert_rc 1 "$(ls -1 "$SB_STATE_FILE".bak.* 2>/dev/null | wc -l)" "state hardened backup retained after failed restore"
if ! ls "$SB_SERVER_CONFIG".restore.* "$SB_STATE_FILE".restore.* >/dev/null 2>&1; then pass "no restore temp residue after failed restore"; else fail "restore temp residue after failed restore"; fi
assert_rc "$before_uuid" "$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")" "Reality UUIDs unchanged by failed rollback"
assert_rc "$before_pwd" "$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")" "HY2 passwords unchanged by failed rollback"
assert_rc "$before_key" "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")" "Reality private key unchanged by failed rollback"
assert_rc "$before_secret" "$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")" "service.api.secret unchanged by failed rollback"
unset -f mv

section "T11: reload failure -> both files restored"
reset_sandbox
before_json="$(sha "$SB_SERVER_CONFIG")"
before_state="$(sha "$SB_STATE_FILE")"
: > "$RELOAD_COUNT_FILE"
SYSTEMCTL_MODE="reload_fail_once" with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t11.out" 2>&1
assert_rc 1 $? "transaction fails when the first reload fails"
assert_rc "$before_json" "$(sha "$SB_SERVER_CONFIG")" "JSON restored after reload failure"
assert_rc "$before_state" "$(sha "$SB_STATE_FILE")" "state restored after reload failure"
assert_grep '已回滚并重新加载上一份配置与状态' "$TMP/t11.out" "successful rollback reload reported"
if [ "$IS_LINUX" = "1" ]; then
    assert_rc 600 "$(mode_of "$SB_SERVER_CONFIG")" "restored live JSON mode is 0600"
    assert_rc 600 "$(mode_of "$SB_STATE_FILE")" "restored live state mode is 0600"
else
    printf '  SKIP permission-mode assertions on Windows sandbox\n'
fi
if ! ls "$SB_SERVER_CONFIG".restore.* "$SB_STATE_FILE".restore.* >/dev/null 2>&1; then pass "no atomic-restore temp residue after success"; else fail "restore temp residue after success"; fi
SYSTEMCTL_MODE="ok"

section "T11b: rollback restore failure after reload failure -> manual intervention"
reset_sandbox
before_state="$(sha "$SB_STATE_FILE")"
# real fault injection: only the JSON restore's atomic mv (an arg is the unique
# *.restore.* temp, destination == live JSON) fails; the state restore succeeds.
mv() {
    local a last
    eval "last=\"\${$#}\""
    if [ "${MV_FAIL_RESTORE_JSON:-0}" = "1" ] && [ "$last" = "$SB_SERVER_CONFIG" ]; then
        for a in "$@"; do case "$a" in *.restore.*) return 1 ;; esac; done
    fi
    command mv "$@"
}
SYSTEMCTL_MODE="reload_fail" MV_FAIL_RESTORE_JSON=1 with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t11b.out" 2>&1
assert_rc 1 $? "transaction fails when rollback restore fails after reload failure"
assert_grep '人工介入' "$TMP/t11b.out" "manual intervention required after reload + restore failure"
assert_grep '备份保留' "$TMP/t11b.out" "backup retention stated"
assert_no_grep '已回滚并重新加载上一份配置与状态' "$TMP/t11b.out" "must NOT claim a successful rollback"
assert_no_grep '已恢复并校验上一份配置与状态' "$TMP/t11b.out" "must NOT claim a successful restore"
assert_no_grep '恢复成功' "$TMP/t11b.out" "must NOT claim recovery success"
assert_rc 1 "$(ls -1 "$SB_SERVER_CONFIG".bak.* 2>/dev/null | wc -l)" "JSON hardened backup retained after reload + restore failure"
assert_rc 1 "$(ls -1 "$SB_STATE_FILE".bak.* 2>/dev/null | wc -l)" "state hardened backup retained after reload + restore failure"
assert_rc "$before_state" "$(sha "$SB_STATE_FILE")" "the unfailing state restore still wrote back the previous state"
unset -f mv
SYSTEMCTL_MODE="ok"

section "T12: rollback reload failure clearly reported"
reset_sandbox
before_json="$(sha "$SB_SERVER_CONFIG")"
before_state="$(sha "$SB_STATE_FILE")"
SYSTEMCTL_MODE="reload_fail" with_client_lock _modify_singbox_locked 18500 18501 "example.org" "cert-new.pem" "key-new.pem" "new.example.org" >"$TMP/t12.out" 2>&1
assert_rc 1 $? "transaction fails when commit and rollback reload both fail"
assert_no_grep '已回滚并重新加载上一份配置与状态' "$TMP/t12.out" "must NOT claim a successful rollback reload"
assert_grep '未能确认恢复' "$TMP/t12.out" "manual-intervention message stated"
assert_rc "$before_json" "$(sha "$SB_SERVER_CONFIG")" "JSON restored despite failed rollback reload"
assert_rc "$before_state" "$(sha "$SB_STATE_FILE")" "state restored despite failed rollback reload"
SYSTEMCTL_MODE="ok"

section "T13: HY2 state writer vs modify_singbox -> no state lost update"
reset_sandbox
export CHILD_SLOW_STATE=1
run_concurrent "$TMP/t13" \
    "with_client_lock _modify_singbox_locked 18500 18501 example.org cert-new.pem key-new.pem new.example.org" \
    "with_client_lock _enable_hy2hopping_locked 50000 51000"
export CHILD_SLOW_STATE=0
assert_rc 0 "${CHILD_RCS[0]}" "modify_singbox child succeeded"
assert_rc 0 "${CHILD_RCS[1]}" "enable hy2 hopping child succeeded"
assert_rc "HY_HOPPING=TRUE" "$(grep '^HY_HOPPING=' "$SB_STATE_FILE")" "HY_HOPPING persisted (not lost)"
assert_rc "HY_HOPPING_START=50000" "$(grep '^HY_HOPPING_START=' "$SB_STATE_FILE")" "HY_HOPPING_START persisted (not lost)"
assert_rc "HY_HOPPING_END=51000" "$(grep '^HY_HOPPING_END=' "$SB_STATE_FILE")" "HY_HOPPING_END persisted (not lost)"
assert_rc "HY_SERVER_NAME='new.example.org'" "$(grep '^HY_SERVER_NAME=' "$SB_STATE_FILE")" "modify_singbox state change persisted (not lost)"
assert_rc 18500 "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' "$SB_SERVER_CONFIG")" "JSON change persisted (not lost)"

section "T14: lock unavailable -> no mutation"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
( flock() { return 1; }; with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 ) >"$TMP/t14.out" 2>&1
assert_rc 1 $? "legacy add aborted when the lock cannot be acquired"
assert_grep '操作已中止（fail-closed）' "$TMP/t14.out" "fail-closed reason stated"
assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "config byte-identical after lock failure"
assert_rc 0 "$(ls -1 "$SB_SERVER_CONFIG".bak.* 2>/dev/null | wc -l)" "no backup created by the failed lock attempt"

section "T15: lock timeout -> no mutation"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
if hold_lock; then
    SB_LOCK_TIMEOUT=1 with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >"$TMP/t15.out" 2>&1
    assert_rc 1 $? "legacy add aborted on lock timeout"
    assert_grep '操作已中止（fail-closed）' "$TMP/t15.out" "timeout reason stated"
    assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "config byte-identical after lock timeout"
    assert_rc 0 "$(ls -1 "$SB_SERVER_CONFIG".bak.* 2>/dev/null | wc -l)" "no backup created on timeout"
    release_lock
else
    fail "could not hold the lock for the timeout test"
fi

section "T16: no interactive wait while the lock is held"
reset_sandbox
before="$(sha "$SB_SERVER_CONFIG")"
generate_port() { : > "$TMP/t16.marker"; echo 12345; }
if hold_lock; then
    printf '1\n10.0.0.9\n8443\n0\n' | SB_LOCK_TIMEOUT=1 process_doko >"$TMP/t16.out" 2>&1
    if [ -e "$TMP/t16.marker" ]; then
        pass "interactive gathering ran before the lock was attempted"
    else
        fail "interactive gathering did not run before the lock attempt"
    fi
    assert_grep '操作已中止' "$TMP/t16.out" "lock timeout reported after input gathering"
    assert_rc "$before" "$(sha "$SB_SERVER_CONFIG")" "config untouched while the lock was held"
    release_lock
else
    fail "could not hold the lock for the interactive-wait test"
fi
generate_port() { echo 12345; }

section "T17: credential preservation across legacy writers"
reset_sandbox
before_uuid="$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")"
before_pwd="$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")"
before_key="$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")"
before_secret="$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")"
with_client_lock _process_doko_add_locked 12345 10.0.0.1 8443 >/dev/null 2>&1
with_client_lock _process_dokoko_add_locked 15000 10.1.1.1 >/dev/null 2>&1
with_client_lock _process_ssko_add_locked 16000 >/dev/null 2>&1
with_client_lock _enable_hy2hopping_locked 50000 51000 >/dev/null 2>&1
assert_rc "$before_uuid" "$(jq -c '[.inbounds[] | select(.tag=="vless-in") | .users[] | .uuid]' "$SB_SERVER_CONFIG")" "Reality UUIDs unchanged by doko/dokoko/ssko/hy2"
assert_rc "$before_pwd" "$(jq -c '[.inbounds[] | select(.tag=="hy2-in") | .users[] | .password]' "$SB_SERVER_CONFIG")" "HY2 passwords unchanged by doko/dokoko/ssko/hy2"
assert_rc "$before_key" "$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key' "$SB_SERVER_CONFIG")" "Reality private key unchanged"
assert_rc "$before_secret" "$(jq -r '.services[] | select(.tag=="monitor-api") | .secret' "$SB_SERVER_CONFIG")" "service.api.secret unchanged"

section "T18: uninstall/reinstall management-active guard (L5)"
reset_sandbox
management_is_active; assert_rc 1 $? "management_is_active is false by default (legacy behaviour)"
require_management_inactive "重新安装"; assert_rc 0 $? "guard allows the operation when management is inactive"
: > "$SB_MANAGEMENT_ACTIVE_MARKER"
management_is_active; assert_rc 0 $? "management_is_active true when the marker exists"
require_management_inactive "重新安装"; assert_rc 1 $? "guard refuses reinstall when management is active"
require_management_inactive "卸载"; assert_rc 1 $? "guard refuses uninstall when management is active"
rm -f "$TMP/destructive-hit"
disable_hy2hopping() { : > "$TMP/destructive-hit"; }
systemctl() { : > "$TMP/destructive-hit"; return 0; }
uninstall_singbox >"$TMP/t18.out" 2>&1
assert_rc 1 $? "uninstall refused when management is active"
assert_grep 'Web 管理已启用' "$TMP/t18.out" "management-active reason stated"
assert_grep '已拒绝' "$TMP/t18.out" "refusal stated"
if [ ! -e "$TMP/destructive-hit" ]; then pass "no destructive step reached before the refusal"; else fail "a destructive step ran despite the guard"; fi
unset -f disable_hy2hopping systemctl
rm -f "$SB_MANAGEMENT_ACTIVE_MARKER"
management_is_active; assert_rc 1 $? "management_is_active false again after removing the marker"

section "T19: restore_file_atomically primitive"
reset_sandbox
printf 'ORIGINAL-LIVE\n' > "$SB_SERVER_CONFIG"
printf 'BACKUP-CONTENT\n' > "$TMP/prim.bak"
chmod 0600 "$TMP/prim.bak" 2>/dev/null
restore_file_atomically "$TMP/prim.bak" "$SB_SERVER_CONFIG" >"$TMP/t19.out" 2>&1
assert_rc 0 $? "restore_file_atomically succeeds on a regular backup"
assert_rc "$(sha "$TMP/prim.bak")" "$(sha "$SB_SERVER_CONFIG")" "restored live is byte-identical to the backup"
if [ -f "$TMP/prim.bak" ]; then pass "original hardened backup preserved"; else fail "backup was deleted by restore"; fi
if ! ls "$SB_SERVER_CONFIG".restore.* >/dev/null 2>&1; then pass "no restore temp residue after success"; else fail "restore temp residue after success"; fi
if [ "$IS_LINUX" = "1" ]; then
    assert_rc 600 "$(mode_of "$SB_SERVER_CONFIG")" "restored live mode is 0600"
else
    printf '  SKIP permission-mode assertion on Windows sandbox\n'
fi
restore_file_atomically "$TMP/does-not-exist" "$SB_SERVER_CONFIG" >"$TMP/t19b.out" 2>&1
assert_rc 1 $? "restore fails closed when the backup is missing"
assert_grep '拒绝恢复' "$TMP/t19b.out" "irregular/missing backup reason stated"
# a non-regular backup (a directory) must be rejected fail-closed, portably
restore_file_atomically "$TMP" "$SB_SERVER_CONFIG" >"$TMP/t19d.out" 2>&1
assert_rc 1 $? "restore refuses a non-regular (directory) backup"
assert_grep '拒绝恢复' "$TMP/t19d.out" "non-regular backup reason stated"
ln -sf "$TMP/prim.bak" "$TMP/prim.symlink" 2>/dev/null
if [ "$IS_LINUX" = "1" ]; then
    restore_file_atomically "$TMP/prim.symlink" "$SB_SERVER_CONFIG" >"$TMP/t19c.out" 2>&1
    assert_rc 1 $? "restore refuses a symlink backup"
else
    printf '  SKIP symlink-backup assertion on Windows sandbox (MSYS may copy instead of link)\n'
fi
printf 'second-payload\nline2\n' > "$TMP/prim2.bak"
restore_file_atomically "$TMP/prim2.bak" "$SB_SERVER_CONFIG" >/dev/null 2>&1
assert_rc 0 $? "second restore succeeds"
assert_rc "$(sha "$TMP/prim2.bak")" "$(sha "$SB_SERVER_CONFIG")" "second restore byte-identical"

# ---------------------------------------------------------------------- summary --
printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
