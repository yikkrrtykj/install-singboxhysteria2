#!/usr/bin/env bash
# Phase D regression tests: 1.14.x upgrade transaction + localhost service.api.
#
# Like test-phase-c.sh, every test really EXECUTES the shell functions: the
# phase-c + phase-d blocks are extracted from install.sh and sourced with all
# external dependencies pointed at a throwaway sandbox (mock sing-box binaries,
# mock systemctl/pgrep/ss/curl, fixture GitHub releases, temp paths via the
# SB_* env overrides). Nothing touches /root/sbox.
#
# D17 runs beyond the required D1-D16 matrix: 9091 conflict refusal.
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
assert_rc() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_grep() { if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi; }
assert_no_grep() { if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then pass "shellcheck install.sh"; else fail "shellcheck install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
else
    printf '  SKIP shellcheck 未安装\n'
fi
assert_grep '"type": "api"' "$INSTALL_SH" "fresh install writes the monitor-api service"
assert_grep '"listen": "127.0.0.1"' "$INSTALL_SH" "fresh monitor-api service is loopback-only"
assert_grep '"listen_port": 9091' "$INSTALL_SH" "fresh monitor-api service port is 9091"
assert_grep '"name": "legacy"' "$INSTALL_SH" "fresh install default user stays name=legacy"
assert_no_grep 'releases/latest' "$INSTALL_SH" "no /latest auto-crossing (1.14 selector only)"

section "extract phase-c + phase-d blocks and prepare sandbox"
awk '/# >>> phase-c client-management >>>/,/# <<< phase-d singbox-1.14-api <<</' \
    "$INSTALL_SH" > "$TMP/blocks.sh"
assert_grep 'select_1_14_stable_tag' "$TMP/blocks.sh" "phase-d block extracted (selector)"
assert_grep 'upgrade_singbox_1_14' "$TMP/blocks.sh" "phase-d block extracted (transaction)"
assert_grep 'commit_server_config' "$TMP/blocks.sh" "phase-c block still present (shared lock/audit)"

SANDBOX="$TMP/sandbox"
mkdir -p "$SANDBOX"
export SB_SERVER_CONFIG="$SANDBOX/sbconfig_server.json"
export SB_STATE_FILE="$SANDBOX/config"
export SB_CLIENTS_DIR="$SANDBOX/clients"
export SB_SING_BOX_BIN="$SANDBOX/sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"
export SB_HOPPING_SERVICE="$SANDBOX/sing-box-hy2-hopping.service"

info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; }

# ---------------------------------------------------------------- shared mocks --
cat > "$TMP/mocks.sh" <<'MOCKS'
systemctl() {
    case "${1:-}" in
        is-active) [ "${SYSTEMCTL_MODE:-ok}" != "ok" ] && return 3; return 0 ;;
        show) printf '4242\n'; return 0 ;;
        restart)
            [ -n "${SYSTEMCTL_LOG:-}" ] && printf '%s\n' "restart sing-box" >> "$SYSTEMCTL_LOG"
            case "${RESTART_FAIL_MODE:-none}" in
                all) return 1 ;;
                first)
                    local n
                    n="$(cat "${RESTART_COUNT_FILE:-/nonexistent}" 2>/dev/null || echo 0)"
                    n=$((n + 1)); printf '%s\n' "$n" > "${RESTART_COUNT_FILE:?}"
                    if [ "$n" -eq 1 ]; then return 1; fi
                    ;;
            esac
            return 0 ;;
        reload)
            [ -n "${SYSTEMCTL_LOG:-}" ] && printf '%s\n' "reload ${2:-}" >> "$SYSTEMCTL_LOG"
            return 0 ;;
    esac
    return 0
}
pgrep() { [ "${PGREP_MODE:-found}" = "found" ]; }
sleep() { return 0; }
ss() {
    # the listener set follows the RUNNING binary: the 1.14 mock serves the
    # AFTER fixtures (with the loopback API), the 1.13 mock the pre-upgrade set
    local a="$*" tcp="${SS_TCP:-}" udp="${SS_UDP:-}" v
    v="$("$SB_SING_BOX_BIN" version 2>/dev/null || true)"
    case "$v" in
        *1.14*) tcp="${SS_TCP_AFTER:-$tcp}"; udp="${SS_UDP_AFTER:-$udp}" ;;
    esac
    case "$a" in
        *-lntu*) printf '%s\n%s\n' "$tcp" "$udp" ;;
        *-lnt*) printf '%s\n' "$tcp" ;;
        *-lnu*) printf '%s\n' "$udp" ;;
    esac
    return 0
}
curl() {
    local out="" url=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -o) out="${2:-}"; shift ;;
            http*) url="$1" ;;
        esac
        shift
    done
    if [ -n "$url" ] && [[ "$url" == *api.github.com* ]]; then
        cat "${GITHUB_FIXTURE:?}"
        return 0
    fi
    if [ -n "$out" ]; then
        cp "${FAKE_ARCHIVE:?}" "$out"
        return 0
    fi
    return 0
}
# Simulate a failure of the CONFIG atomic replacement while the binary has
# already been replaced (the mixed-state scenario from the review). The mv
# target is always the LAST argument.
mv() {
    if [ "${MV_FAIL_CONFIG:-0}" = "1" ]; then
        local last
        eval "last=\"\${$#}\""
        if [ "$last" = "${SB_SERVER_CONFIG:-}" ]; then
            return 1
        fi
    fi
    command mv "$@"
}
MOCKS

# ------------------------------------------------------------- mock binaries --
cat > "$TMP/mock-old-sb" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
  version) printf 'sing-box version 1.13.13\nTag: mock-old\n' ;;
  check)
    f=""
    while [ $# -gt 0 ]; do case "$1" in -c) f="$2"; shift 2 ;; *) shift ;; esac; done
    [ -n "$f" ] || exit 1
    jq empty "$f" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  api) exit 0 ;;
  generate)
    n="$(cat "${MOCK_COUNT_FILE:?}" 2>/dev/null || echo 0)"; n=$((n + 1)); printf '%s\n' "$n" > "${MOCK_COUNT_FILE:?}"
    case "${2:-}" in
      uuid) printf '11111111-1111-1111-1111-%012d\n' "$n" ;;
      rand) printf 'aaa%028x\n' "$n" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
MOCK
cat > "$TMP/mock-new-sb" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
  version) printf 'sing-box version 1.14.7\nTag: mock-new\n' ;;
  check)
    [ -f "${SB_NEW_CHECK_FAIL:-/nonexistent}" ] && exit 1
    f=""
    while [ $# -gt 0 ]; do case "$1" in -c) f="$2"; shift 2;; *) shift;; esac; done
    [ -n "$f" ] || exit 1
    jq empty "$f" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  api)
    [ -f "${SB_NEW_API_FAIL:-/nonexistent}" ] && exit 1
    exit 0 ;;
  generate)
    n="$(cat "${MOCK_COUNT_FILE:?}" 2>/dev/null || echo 0)"; n=$((n + 1)); printf '%s\n' "$n" > "${MOCK_COUNT_FILE:?}"
    case "${2:-}" in
      uuid) printf '22222222-2222-2222-2222-%012d\n' "$n" ;;
      rand) printf 'bbb%028x\n' "$n" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$TMP/mock-old-sb" "$TMP/mock-new-sb"

# fake release archive containing the NEW binary (real tar, real extraction)
arch="$(uname -m)"
case "$arch" in x86_64) arch="amd64" ;; aarch64) arch="arm64" ;; armv7l) arch="armv7" ;; esac
PKGDIR="sing-box-1.14.7-linux-${arch}"
mkdir -p "$TMP/pkg/$PKGDIR"
cp "$TMP/mock-new-sb" "$TMP/pkg/$PKGDIR/sing-box"
tar -czf "$TMP/fake.tar.gz" -C "$TMP/pkg" "$PKGDIR"
export FAKE_ARCHIVE="$TMP/fake.tar.gz"

# ------------------------------------------------------------- GH fixtures --
cat > "$TMP/gh-mixed.json" <<'EOF'
[{"tag_name":"v1.15.1","prerelease":false},{"tag_name":"v1.14.3","prerelease":false},{"tag_name":"v1.15.0-alpha.1","prerelease":true},{"tag_name":"v1.14.10","prerelease":false},{"tag_name":"v1.14.2","prerelease":false},{"tag_name":"v1.13.19","prerelease":false},{"tag_name":"v1.14.0-rc.2","prerelease":true},{"tag_name":"v1.14.9-draft","draft":true,"prerelease":false}]
EOF
cat > "$TMP/gh-no114.json" <<'EOF'
[{"tag_name":"v1.15.1","prerelease":false},{"tag_name":"v1.13.19","prerelease":false},{"tag_name":"v1.15.0-alpha.1","prerelease":true}]
EOF
cat > "$TMP/gh-main.json" <<'EOF'
[{"tag_name":"v1.14.7","prerelease":false},{"tag_name":"v1.13.19","prerelease":false}]
EOF

export SYSTEMCTL_MODE="ok"
export RESTART_FAIL_MODE="none"
export PGREP_MODE="found"
export SYSTEMCTL_LOG="$TMP/systemctl.log"
export RESTART_COUNT_FILE="$TMP/restart-count"
: > "$SYSTEMCTL_LOG"
printf '0\n' > "$RESTART_COUNT_FILE"
export GITHUB_FIXTURE="$TMP/gh-main.json"
export MOCK_COUNT_FILE="$TMP/cred-count"
printf '0\n' > "$MOCK_COUNT_FILE"

. "$TMP/mocks.sh"
. "$TMP/blocks.sh"

# ------------------------------------------------------------------ helpers --
write_migrated_config() { # Phase C 已完成形态：legacy + vmix-01，均具名，无 monitor-api service
    cat > "$SB_SERVER_CONFIG" <<'EOF'
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 18443,
      "users": [
        {"name": "legacy", "uuid": "OLD-REALITY-UUID", "flow": "xtls-rprx-vision"},
        {"name": "vmix-01", "uuid": "VMIX-REALITY-UUID", "flow": "xtls-rprx-vision"}
      ],
      "tls": {"enabled": true, "server_name": "itunes.apple.com",
        "reality": {"enabled": true, "handshake": {"server": "itunes.apple.com", "server_port": 443},
          "private_key": "OLD-KEY", "short_id": ["0123abcd"]}}
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 18444,
      "users": [
        {"name": "legacy", "password": "OLD-HY2-PASSWORD"},
        {"name": "vmix-01", "password": "VMIX-HY2-PASSWORD"}
      ],
      "tls": {"enabled": true, "alpn": ["h3"]}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
}
write_old_config() { # 旧无名共享账号（Phase C 未迁移）
    cat > "$SB_SERVER_CONFIG" <<'EOF'
{
  "inbounds": [
    {"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": 18443,
     "users": [{"uuid": "OLD-REALITY-UUID", "flow": "xtls-rprx-vision"}],
     "tls": {"enabled": true, "server_name": "itunes.apple.com",
       "reality": {"enabled": true, "handshake": {"server": "itunes.apple.com", "server_port": 443},
         "private_key": "OLD-KEY", "short_id": ["0123abcd"]}}},
    {"type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": 18444,
     "users": [{"password": "OLD-HY2-PASSWORD"}],
     "tls": {"enabled": true, "alpn": ["h3"]}}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
}
write_state() { # write_state <TRUE|FALSE>
    cat > "$SB_STATE_FILE" <<EOF
SERVER_IP='203.0.113.9'
PUBLIC_KEY='TEST-PUBLIC-KEY'
HY_SERVER_NAME='bing.com'
HY_HOPPING=$1
HY_HOPPING_START=
HY_HOPPING_END=
EOF
}
# Listener fixtures for the mocked `ss`: BEFORE a restart only the two protocol
# listeners exist (no API yet); AFTER a successful restart the loopback API
# listener appears. Every stateful section must (re)initialise these itself --
# never rely on the previous test having restored them (D17 deliberately leaves
# a polluted SS_TCP behind to prove the 9091 conflict path).
reset_listener_fixtures() {
    export SS_TCP="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*"
    export SS_UDP="UNCONN 0 0 0.0.0.0:18444 0.0.0.0:*"
    export SS_TCP_AFTER="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*
LISTEN 0 128 127.0.0.1:9091 0.0.0.0:*"
    export SS_UDP_AFTER="UNCONN 0 0 0.0.0.0:18444 0.0.0.0:*"
}

setup_upgrade_sandbox() {
    write_state FALSE
    write_migrated_config
    cp "$TMP/mock-old-sb" "$SB_SING_BOX_BIN"
    chmod +x "$SB_SING_BOX_BIN"
    # each scenario starts from a clean pre-upgrade state: no old backups
    rm -f "$SANDBOX"/sing-box.bak.* "$SANDBOX"/sbconfig_server.json.bak.*
    reset_listener_fixtures
    export GITHUB_FIXTURE="$TMP/gh-main.json"
    : > "$SYSTEMCTL_LOG"
    printf '0\n' > "$RESTART_COUNT_FILE"
    export RESTART_FAIL_MODE="none"
    export SYSTEMCTL_MODE="ok"
    export PGREP_MODE="found"
    rm -f "$TMP/new-check-fail" "$TMP/new-api-fail"
    : > "$MOCK_COUNT_FILE"
    export SB_NEW_CHECK_FAIL="$TMP/new-check-fail"
    export SB_NEW_API_FAIL="$TMP/new-api-fail"
}

section "D1: 1.14.x stable selector picks the newest stable 1.14.x"
export GITHUB_FIXTURE="$TMP/gh-mixed.json"
tag="$(select_1_14_stable_tag)"
assert_rc 0 $? "selector succeeds on mixed releases"
if [ "$tag" = "v1.14.10" ]; then pass "selector picked v1.14.10 (numeric sort)"; else fail "selector picked '$tag'"; fi
if phase_d_release_tag_is_allowed "v1.14.0"; then pass "v1.14.0 allowed"; else fail "v1.14.0 rejected"; fi
if phase_d_release_tag_is_allowed "v1.15.0"; then fail "v1.15.0 accepted"; else pass "v1.15.0 rejected"; fi
if phase_d_release_tag_is_allowed "v1.15.0-alpha.2"; then fail "alpha accepted"; else pass "alpha rejected"; fi
if phase_d_release_tag_is_allowed "v1.13.19"; then fail "v1.13.19 accepted"; else pass "v1.13.19 rejected"; fi
# pure selector from JSON (no network): numeric patch sort, draft/prerelease skip
sel="$(phase_d_select_release_from_json < "$TMP/gh-mixed.json")"
if [ "$sel" = "v1.14.10" ]; then pass "pure JSON selector picked v1.14.10"; else fail "pure JSON selector picked '$sel'"; fi

section "D2: no stable 1.14.x in releases -> selector refuses"
export GITHUB_FIXTURE="$TMP/gh-no114.json"
if select_1_14_stable_tag > "$TMP/d2.out" 2>&1; then fail "selector accepted non-1.14 target"; else pass "selector refuses without 1.14.x stable"; fi
assert_grep '拒绝 1.13.x / 1.15.x / prerelease' "$TMP/d2.out" "rejection reason stated"
export GITHUB_FIXTURE="$TMP/gh-main.json"

section "D3: API service injection is compliant, idempotent and duplicate-detecting"
setup_upgrade_sandbox
if phase_d_config_structure_problems "$SB_SERVER_CONFIG" > "$TMP/d3.problems"; then pass "no api service -> no problems"; else fail "api audit errored on clean config"; fi
assert_rc 0 "$(wc -c < "$TMP/d3.problems")" "problems empty before injection"
if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then fail "exact before injection"; else pass "not exact before injection"; fi
phase_d_inject_api_service "$SB_SERVER_CONFIG" "$SB_SERVER_CONFIG.injected"
if phase_d_api_service_exact "$SB_SERVER_CONFIG.injected"; then pass "exact after injection (loopback + 9091)"; else fail "not exact after injection"; fi
assert_rc 1 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG.injected" | tr -d '\r')" "exactly one monitor-api service after injection"
phase_d_inject_api_service "$SB_SERVER_CONFIG.injected" "$SB_SERVER_CONFIG.injected2"
if [ "$(jq -S . "$SB_SERVER_CONFIG.injected")" = "$(jq -S . "$SB_SERVER_CONFIG.injected2")" ]; then pass "idempotent: repeated injection changes nothing"; else fail "idempotency broken"; fi
rm -f "$SB_SERVER_CONFIG.injected" "$SB_SERVER_CONFIG.injected2"

section "D4: malformed services field is fail-closed"
setup_upgrade_sandbox
jq '.services = "oops"' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.tmp" && mv "$SB_SERVER_CONFIG.tmp" "$SB_SERVER_CONFIG"
assert_grep 'services 存在但不是数组' <(phase_d_config_structure_problems "$SB_SERVER_CONFIG") "malformed services detected"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d4.out" 2>&1
assert_rc 1 $? "upgrade refused with malformed services"
assert_grep '拒绝自动覆盖' "$TMP/d4.out" "no-auto-overwrite reason stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D4)"; else fail "live mutated (D4)"; fi

section "D5: unsafe API listen/port is fail-closed"
setup_upgrade_sandbox
jq '.services = [{"type":"api","tag":"monitor-api","listen":"0.0.0.0","listen_port":9091}]' \
    "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.tmp" && mv "$SB_SERVER_CONFIG.tmp" "$SB_SERVER_CONFIG"
assert_grep 'monitor-api listen 不是 127.0.0.1' <(phase_d_config_structure_problems "$SB_SERVER_CONFIG") "unsafe listen detected"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d5.out" 2>&1
assert_rc 1 $? "upgrade refused with unsafe API listen"
assert_grep '拒绝自动覆盖' "$TMP/d5.out" "no-auto-overwrite reason stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D5)"; else fail "live mutated (D5)"; fi

section "D6: unnamed legacy account blocks upgrade (Phase C precondition)"
setup_upgrade_sandbox
write_old_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d6.out" 2>&1
assert_rc 1 $? "upgrade refused for unnamed shared account"
assert_grep 'Phase C legacy migration 尚未执行' "$TMP/d6.out" "migration guidance stated"
assert_grep '迁移旧客户端为 legacy' "$TMP/d6.out" "explicit next step stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D6)"; else fail "live mutated (D6)"; fi

section "D7: identity mismatch blocks upgrade"
setup_upgrade_sandbox
jq '(.inbounds[] | select(.tag=="hy2-in") | .users) |= map(select(.name != "vmix-01"))' \
    "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.tmp" && mv "$SB_SERVER_CONFIG.tmp" "$SB_SERVER_CONFIG"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d7.out" 2>&1
assert_rc 1 $? "upgrade refused on identity mismatch"
assert_grep '身份审计未通过' "$TMP/d7.out" "identity audit failure stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D7)"; else fail "live mutated (D7)"; fi

section "D8: manual (non-systemd) process blocks upgrade before any change"
setup_upgrade_sandbox
export SYSTEMCTL_MODE="stopped"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d8.out" 2>&1
assert_rc 1 $? "upgrade refused for manual process"
assert_grep '手工进程运行' "$TMP/d8.out" "manual-process reason stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D8)"; else fail "live mutated (D8)"; fi
export SYSTEMCTL_MODE="ok"

section "D9: candidate binary check failure leaves live untouched"
setup_upgrade_sandbox
: > "$SB_NEW_CHECK_FAIL"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
bak_before="$(ls -1 "$SANDBOX"/*.bak.* 2>/dev/null | wc -l)"
upgrade_singbox_1_14 > "$TMP/d9.out" 2>&1
assert_rc 1 $? "upgrade refused when candidate check fails"
assert_grep 'candidate binary check 未通过' "$TMP/d9.out" "candidate check reason stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D9)"; else fail "live mutated (D9)"; fi
bak_after="$(ls -1 "$SANDBOX"/*.bak.* 2>/dev/null | wc -l)"
assert_rc 0 "$((bak_after - bak_before))" "no backup created when check fails"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "live binary still 1.13.13"

section "D10: restart failure -> double rollback recovers old binary+config"
setup_upgrade_sandbox
export RESTART_FAIL_MODE="first"
upgrade_singbox_1_14 > "$TMP/d10.out" 2>&1
assert_rc 1 $? "upgrade fails when restart fails"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "old binary restored"
assert_rc 0 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "old config restored (no api service)"
assert_grep '已回滚到升级前状态' "$TMP/d10.out" "successful rollback reported"

section "D11: API health failure -> double rollback"
setup_upgrade_sandbox
# the NEW binary comes up WITHOUT the loopback API listener
export SS_TCP_AFTER="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*"
upgrade_singbox_1_14 > "$TMP/d11.out" 2>&1
assert_rc 1 $? "upgrade fails when API listener missing"
assert_grep 'API 127.0.0.1:9091 未监听' "$TMP/d11.out" "api health reason stated"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "old binary restored (D11)"
assert_rc 0 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "old config restored (D11)"
assert_grep '已回滚到升级前状态' "$TMP/d11.out" "successful rollback reported (D11)"

section "D12: rollback restart failure is reported as manual intervention"
setup_upgrade_sandbox
export RESTART_FAIL_MODE="all"
upgrade_singbox_1_14 > "$TMP/d12.out" 2>&1
assert_rc 1 $? "upgrade fails when every restart fails"
assert_grep '回滚后 restart sing-box 失败，请立即人工介入' "$TMP/d12.out" "manual intervention stated"
assert_no_grep '已回滚到升级前状态' "$TMP/d12.out" "must NOT claim successful recovery"
export RESTART_FAIL_MODE="none"

section "D13: successful upgrade preserves every user credential; idempotent"
setup_upgrade_sandbox
users_before="$(jq -Sc '[.inbounds[] | .users] | sort' "$SB_SERVER_CONFIG")"
upgrade_singbox_1_14 > "$TMP/d13.out" 2>&1
assert_rc 0 $? "upgrade succeeds"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.14.7')" "live binary is now 1.14.7"
assert_rc 1 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "exactly one monitor-api service after upgrade"
users_after="$(jq -Sc '[.inbounds[] | .users] | sort' "$SB_SERVER_CONFIG" | tr -d '\r')"
if [ "$users_before" = "$users_after" ]; then pass "all user credentials preserved verbatim"; else fail "users changed by upgrade"; fi
assert_grep 'OLD-REALITY-UUID' "$SB_SERVER_CONFIG" "legacy reality uuid kept"
assert_grep 'VMIX-HY2-PASSWORD' "$SB_SERVER_CONFIG" "vmix-01 hy2 password kept"
bak_bin="$(ls -1 "$SANDBOX"/sing-box.bak.* 2>/dev/null | wc -l)"
bak_cfg="$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)"
assert_rc 1 "$bak_bin" "binary backup created"
assert_rc 1 "$bak_cfg" "config backup created"
upgrade_singbox_1_14 > "$TMP/d13b.out" 2>&1
assert_rc 0 $? "second upgrade (idempotent API) succeeds"
assert_rc 1 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "still exactly one monitor-api service (no duplicate)"

section "D14: API is loopback-only with fixed port"
assert_rc 1 "$(printf '%s' "$(jq -r '.services[]? | select(.tag == "monitor-api") | .listen' "$SB_SERVER_CONFIG" | tr -d '\r')" | grep -cx '127.0.0.1')" "api listen is 127.0.0.1"
assert_rc 1 "$(printf '%s' "$(jq -r '.services[]? | select(.tag == "monitor-api") | .listen_port' "$SB_SERVER_CONFIG" | tr -d '\r')" | grep -cx '9091')" "api port is 9091"
assert_grep '127\.0\.0\.1:9091' <(printf '%s\n' "$SS_TCP_AFTER") "post-restart listener is loopback-only"
assert_no_grep '(0\.0\.0\.0|\[::\]):9091' <(printf '%s\n' "$SS_TCP_AFTER") "no wildcard API listener"

section "D15: hy2 hopping restoration after upgrade and rollback"
setup_upgrade_sandbox
write_state TRUE
rm -f "$SB_HOPPING_SERVICE"
upgrade_singbox_1_14 > "$TMP/d15a.out" 2>&1
assert_rc 1 $? "upgrade rolls back when hopping cannot be restored"
assert_grep '端口跳跃规则未刷新' "$TMP/d15a.out" "hopping failure reason stated"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "rolled back binary after hopping failure"
printf '#!/bin/sh\nexit 0\n' > "$SB_HOPPING_SERVICE"
upgrade_singbox_1_14 > "$TMP/d15b.out" 2>&1
assert_rc 0 $? "upgrade succeeds once hopping service exists"
assert_grep 'reload sing-box-hy2-hopping.service' "$SYSTEMCTL_LOG" "hopping rules refreshed after restart"
write_state FALSE

section "D17: 9091 already occupied blocks the upgrade"
setup_upgrade_sandbox
export SS_TCP="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*
LISTEN 0 128 0.0.0.0:9091 0.0.0.0:*"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
upgrade_singbox_1_14 > "$TMP/d17.out" 2>&1
assert_rc 1 $? "upgrade refused when 9091 occupied"
assert_grep '已被占用' "$TMP/d17.out" "port conflict reason stated"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live untouched (D17)"; else fail "live mutated (D17)"; fi
# NOTE: D17 intentionally leaves SS_TCP polluted (9091 occupied). D16 and every
# later section re-initialise their own fixtures and must not rely on a manual
# restore here.

section "D16: Phase C add and Phase D upgrade share one flock (no lost update)"
# D16 is fully order-independent: D17 deliberately leaves a polluted SS_TCP
# (9091 "occupied") behind, so this section re-initialises every fixture and
# mode itself instead of trusting the previous test's cleanup.
CONC="$TMP/conc"
mkdir -p "$CONC"
export SB_SERVER_CONFIG="$CONC/sbconfig_server.json"
export SB_STATE_FILE="$CONC/config"
export SB_CLIENTS_DIR="$CONC/clients"
export SB_SING_BOX_BIN="$CONC/sing-box"
export SB_LOCK_FILE="$CONC/config.lock"
export SB_HOPPING_SERVICE="$CONC/hy2-hopping.service"
SB_SANDBOX_CONFIG="$SB_SERVER_CONFIG"
write_state FALSE
write_migrated_config
cp "$TMP/mock-old-sb" "$SB_SING_BOX_BIN"
chmod +x "$SB_SING_BOX_BIN"
reset_listener_fixtures
export GITHUB_FIXTURE="$TMP/gh-main.json"
export SYSTEMCTL_MODE="ok"
export PGREP_MODE="found"
export RESTART_FAIL_MODE="none"
: > "$SYSTEMCTL_LOG"
printf '0\n' > "$RESTART_COUNT_FILE"
rm -f "$TMP/new-check-fail" "$TMP/new-api-fail"
export SB_NEW_CHECK_FAIL="$TMP/new-check-fail"
export SB_NEW_API_FAIL="$TMP/new-api-fail"
export MOCK_COUNT_FILE="$CONC/cred-count"
printf '0\n' > "$MOCK_COUNT_FILE"
# fail fast, BEFORE forking, if the fixtures are ever polluted again
assert_no_grep '127\.0\.0\.1:9091' <(printf '%s\n' "$SS_TCP") "D16 pre-upgrade fixture has no API listener"
assert_grep '127\.0\.0\.1:9091' <(printf '%s\n' "$SS_TCP_AFTER") "D16 post-upgrade fixture has loopback API"
if ! command -v flock >/dev/null 2>&1; then
    printf '  SKIP concurrency test: flock unavailable\n'
else
    cat > "$CONC/child.sh" <<'CHILD'
set -u
ROLE="$1"; CFG="$2"; GO="$3"; PHASEC="$4"
export SB_SERVER_CONFIG="$CFG/sbconfig_server.json"
export SB_STATE_FILE="$CFG/config"
export SB_CLIENTS_DIR="$CFG/clients"
export SB_SING_BOX_BIN="$CFG/sing-box"
export SB_LOCK_FILE="$CFG/config.lock"
export SB_HOPPING_SERVICE="$CFG/hy2-hopping.service"
# per-child restart counter and log: the two children must not share state
export SYSTEMCTL_LOG="$CFG/systemctl-$ROLE.log"; : > "$SYSTEMCTL_LOG"
export RESTART_COUNT_FILE="$CFG/restart-count-$ROLE"; printf '0\n' > "$RESTART_COUNT_FILE"
info() { :; }; warning() { :; }; hint() { :; }; error() { :; }
. "$CFG/mocks.sh"
. "$PHASEC"
while [ ! -f "$GO" ]; do command sleep 0.05; done
case "$ROLE" in
    add) add_client "client-x" ;;
    upgrade) upgrade_singbox_1_14 ;;
esac
exit $?
CHILD
    cp "$TMP/mocks.sh" "$CONC/mocks.sh"
    : > "$CONC/stage"
    bash "$CONC/child.sh" add "$CONC" "$CONC/go" "$TMP/blocks.sh" > "$CONC/add.log" 2>&1 &
    cpid1=$!
    bash "$CONC/child.sh" upgrade "$CONC" "$CONC/go" "$TMP/blocks.sh" > "$CONC/up.log" 2>&1 &
    cpid2=$!
    for _ in $(seq 1 50); do [ -d "/proc/$cpid1" ] && [ -d "/proc/$cpid2" ] || break; command sleep 0.1; done
    command sleep 1
    : > "$CONC/go"
    wait "$cpid1"; rc_add=$?
    wait "$cpid2"; rc_up=$?
    assert_rc 0 "$rc_add" "concurrent Phase C add_client client-x"
    assert_rc 0 "$rc_up" "concurrent Phase D upgrade"
    assert_rc 1 "$(get_reality_client_names | grep -cx 'client-x')" "client-x survived in reality"
    assert_rc 1 "$(get_hy2_client_names | grep -cx 'client-x')" "client-x survived in hy2"
    assert_rc 1 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "api service present exactly once"
    assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.14.7')" "binary upgraded to 1.14.7"
    if audit_client_consistency > "$TMP/d16.audit" 2>&1; then pass "final identity audit consistent"; else fail "final audit inconsistent: $(cat "$TMP/d16.audit" | tr '\n' ' ')"; fi
fi
# restore the main sandbox env (D18/D19 re-initialise everything themselves)
export SB_SERVER_CONFIG="$SANDBOX/sbconfig_server.json"
export SB_STATE_FILE="$SANDBOX/config"
export SB_CLIENTS_DIR="$SANDBOX/clients"
export SB_SING_BOX_BIN="$SANDBOX/sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"
export SB_HOPPING_SERVICE="$SANDBOX/sing-box-hy2-hopping.service"

section "D18: config mv failure -> double recovery of binary AND config"
setup_upgrade_sandbox
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
# binary mv succeeds, then the config mv fails -> mixed state must be fully
# recovered (config first, then binary), restarted and re-verified
export MV_FAIL_CONFIG=1
upgrade_singbox_1_14 > "$TMP/d18.out" 2>&1
assert_rc 1 $? "upgrade fails when config mv fails"
assert_grep '执行双恢复' "$TMP/d18.out" "double-recovery stated"
assert_grep '已恢复到升级前状态' "$TMP/d18.out" "recovery verified"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "old binary restored (no new+old mix)"
assert_rc 0 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "old config restored (D18)"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "live pair byte-identical to pre-upgrade (D18)"; else fail "live pair differs (D18)"; fi
assert_grep 'restart sing-box' "$SYSTEMCTL_LOG" "recovery restart actually ran"
bak_bin="$(ls -1 "$SANDBOX"/sing-box.bak.* 2>/dev/null | wc -l)"
bak_cfg="$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)"
assert_rc 1 "$bak_bin" "binary backup kept after recovery"
assert_rc 1 "$bak_cfg" "config backup kept after recovery"
export MV_FAIL_CONFIG=0

section "D19: rollback failure must KEEP backups for manual recovery"
setup_upgrade_sandbox
export RESTART_FAIL_MODE="all"
upgrade_singbox_1_14 > "$TMP/d19.out" 2>&1
assert_rc 1 $? "upgrade fails when every restart fails"
assert_grep '请立即人工介入' "$TMP/d19.out" "manual intervention stated"
bak_bin="$(ls -1 "$SANDBOX"/sing-box.bak.* 2>/dev/null | wc -l)"
bak_cfg="$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)"
if [ "$bak_bin" -ge 1 ] && [ "$bak_cfg" -ge 1 ]; then pass "backups still present after failed rollback (manual recovery possible)"; else fail "backups were deleted after failed rollback (bin=$bak_bin cfg=$bak_cfg)"; fi
broken=0
for b in "$SANDBOX"/*.bak.*; do [ -s "$b" ] || { fail "empty backup: $b"; broken=1; }; done
[ "$broken" -eq 0 ] && pass "all kept backups are non-empty"
assert_rc 1 "$(printf '%s' "$("$SB_SING_BOX_BIN" version)" | grep -c '1.13.13')" "old binary file restored even though restart failed"
export RESTART_FAIL_MODE="none"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
