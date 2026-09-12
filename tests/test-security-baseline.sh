#!/usr/bin/env bash
# S0 security-baseline regression tests (Phase C/D hardening).
#
# Scope (S0-1..S0-4 + credential-preservation gate):
#   - lock fail-closed: missing flock binary, unopenable lock file, timeout;
#     config byte-identical and no artifacts after every lock failure
#   - destructive client-name revalidation inside _delete_client_locked
#   - sensitive-file permission hardening (0600/0700/0644) + backup modes
#   - service.api secret: generation, migration, rerun stability,
#     exact-checker rejection of secret-less monitor-api, derived 0600 file,
#     config-is-authoritative repair, no secret leakage into audit output
#   - credential preservation gate: the canonicalized config EXCLUDING
#     .services is identical across the API-auth migration (Reality/HY2
#     users, keys, ports, cert paths -- semantic preservation, not raw
#     byte-for-byte JSON identity)
#   - existing-install baseline repair: fail-closed on an unrepairable
#     derived secret file, no-op for healthy and pre-Phase-D installs
#
# Like the phase-c/d suites, the tests really EXECUTE the shell functions: the
# phase-c + s0 + phase-d blocks are extracted from install.sh and sourced with
# every external dependency pointed at a throwaway sandbox. Nothing touches
# /root/sbox. Permission MODE assertions are meaningful only on real Linux
# (MSYS chmod/stat are no-ops for NTFS ACLs and are SKIPped there).
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
IS_LINUX=1
case "$(uname -s)" in
    MINGW*|MSYS*) IS_LINUX=0 ;;
esac
mode_of() { stat -c %a "$1" 2>/dev/null; }

section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then pass "shellcheck install.sh"; else fail "shellcheck install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
else
    printf '  SKIP shellcheck 未安装\n'
fi
assert_grep '"secret": "\$monitor_api_secret"' "$INSTALL_SH" "fresh install embeds a generated API secret"
assert_grep 'openssl rand -hex 32' "$INSTALL_SH" "API secret comes from a CSPRNG (256 bit)"
assert_no_grep '^umask 077' "$INSTALL_SH" "no global umask change (scoped hardening only)"
assert_grep 'write_api_secret_file "\$monitor_api_secret" \|\| error' "$INSTALL_SH" "fresh install writes the derived secret file fail-closed"
assert_grep 'harden_sensitive_permissions \|\| error' "$INSTALL_SH" "fresh install hardens permissions fail-closed"
assert_grep '^repair_existing_install_security_baseline\(\)' "$INSTALL_SH" "fail-closed existing-install baseline repair helper exists"
assert_no_grep '单机低并发场景下继续执行' "$INSTALL_SH" "unlocked fallback is gone"
assert_grep 'flock -w "\$SB_LOCK_TIMEOUT" 9' "$INSTALL_SH" "lock acquisition uses a finite timeout"
assert_grep '操作已中止（fail-closed）' "$INSTALL_SH" "lock failure aborts the operation"
assert_grep 'rm -rf -- "\$\{SB_CLIENTS_DIR:\?\}/\$name"' "$INSTALL_SH" "destructive rm uses -- and a non-empty guard"
assert_grep 'chown root:root' "$INSTALL_SH" "derived secret file is forced root:root"
assert_grep '\-\-secret "\$api_secret"' "$INSTALL_SH" "health check authenticates the API call"
assert_grep '未强制认证' "$INSTALL_SH" "health check contains the unauthenticated negative canary"
delete_body="$(awk '/^_delete_client_locked\(\) \{/,/^\}/' "$INSTALL_SH")"
v_line="$(printf '%s\n' "$delete_body" | grep -n 'validate_client_name "\$name"' | head -n1 | cut -d: -f1)"
r_line="$(printf '%s\n' "$delete_body" | grep -n 'RESERVED_CLIENT_NAME' | head -n1 | cut -d: -f1)"
if [ -n "$v_line" ] && [ -n "$r_line" ] && [ "$v_line" -lt "$r_line" ]; then
    pass "locked delete validates name syntax BEFORE the reserved check"
else
    fail "locked delete validates name syntax BEFORE the reserved check (v=$v_line r=$r_line)"
fi
backup_chmod="$(grep -c 'chmod 0600 "\$backup_path" 2>/dev/null\|chmod 0600 "\$backup_cfg" 2>/dev/null' "$INSTALL_SH")"
assert_rc 2 "$backup_chmod" "both backup paths enforce 0600 explicitly"
assert_no_grep '派生文件修复失败，本机 collector 认证可能受影响' "$INSTALL_SH" "fail-open sync warning is gone"
repair_body="$(awk '/^repair_existing_install_security_baseline\(\) \{/,/^\}/' "$INSTALL_SH")"
assert_grep 'harden_sensitive_permissions \|\|' <(printf '%s\n' "$repair_body") "permission repair failure aborts via error()"
assert_grep 'sync_api_secret_file \|\|' <(printf '%s\n' "$repair_body") "derived-file repair failure aborts via error()"
assert_no_grep 'warning' <(printf '%s\n' "$repair_body") "repair helper never warns-and-continues"
if grep -qE '^[[:space:]]*repair_existing_install_security_baseline$' "$INSTALL_SH"; then
    pass "existing-install menu path calls the fail-closed baseline repair"
else
    fail "existing-install menu path calls the fail-closed baseline repair"
fi

section "extract blocks and prepare sandbox"
awk '/# >>> phase-c client-management >>>/,/# <<< phase-d singbox-1.14-api <<</' \
    "$INSTALL_SH" > "$TMP/blocks.sh"
assert_grep 'generate_api_secret' "$TMP/blocks.sh" "s0 block extracted (secret helpers)"
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
export SB_API_SECRET_FILE="$SANDBOX/monitor-api.secret"
export SB_SELF_CERT_KEY="$SANDBOX/self-cert/private.key"
export SB_SELF_CERT_CERT="$SANDBOX/self-cert/cert.pem"
# flock(1) shim: no-op where util-linux flock exists (Linux/CI).
. "$HERE/lib/mock-flock.sh"

info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; }

cat > "$TMP/mocks.sh" <<'MOCKS'
systemctl() {
    case "${1:-}" in
        is-active) [ "${SYSTEMCTL_MODE:-ok}" != "ok" ] && return 3; return 0 ;;
        show) printf '4242\n'; return 0 ;;
        restart) return 0 ;;
        reload) return 0 ;;
    esac
    return 0
}
pgrep() { [ "${PGREP_MODE:-found}" = "found" ]; }
sleep() { return 0; }
ss() {
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
MOCKS

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
    # Emulate service.api auth enforcement: when the live config carries a
    # monitor-api secret, only a call presenting exactly that secret succeeds.
    want_secret="$(jq -r --arg tag "monitor-api" '
      ([(.services // [])[] | select(.tag == $tag)][0].secret // "")
    ' "${SB_SERVER_CONFIG:?}" 2>/dev/null || printf '')"
    got_secret=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --secret) got_secret="${2:-}"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [ -n "$want_secret" ] && [ "$got_secret" != "$want_secret" ]; then
      printf 'rpc error: Unauthenticated\n' >&2
      exit 1
    fi
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

arch="$(uname -m)"
case "$arch" in x86_64) arch="amd64" ;; aarch64) arch="arm64" ;; armv7l) arch="armv7" ;; esac
PKGDIR="sing-box-1.14.7-linux-${arch}"
mkdir -p "$TMP/pkg/$PKGDIR"
cp "$TMP/mock-new-sb" "$TMP/pkg/$PKGDIR/sing-box"
tar -czf "$TMP/fake.tar.gz" -C "$TMP/pkg" "$PKGDIR"
export FAKE_ARCHIVE="$TMP/fake.tar.gz"

cat > "$TMP/gh-main.json" <<'EOF'
[{"tag_name":"v1.14.7","prerelease":false},{"tag_name":"v1.13.19","prerelease":false}]
EOF

export SYSTEMCTL_MODE="ok"
export PGREP_MODE="found"
export GITHUB_FIXTURE="$TMP/gh-main.json"
export MOCK_COUNT_FILE="$TMP/cred-count"
export SS_TCP="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*"
export SS_UDP="UNCONN 0 0 0.0.0.0:18444 0.0.0.0:*"
export SS_TCP_AFTER="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*
LISTEN 0 128 127.0.0.1:9091 0.0.0.0:*"
export SS_UDP_AFTER="UNCONN 0 0 0.0.0.0:18444 0.0.0.0:*"

. "$TMP/mocks.sh"
. "$TMP/blocks.sh"

write_migrated_config() { # Phase C 已完成形态：均具名，无 monitor-api service
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
add_api_service_with_secret() { # add_api_service_with_secret <secret>
    jq --arg secret "$1" '
      .services = ((.services // []) + [{
        "type": "api", "tag": "monitor-api",
        "listen": "127.0.0.1", "listen_port": 9091, "secret": $secret
      }])
    ' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.tmp" && mv -f "$SB_SERVER_CONFIG.tmp" "$SB_SERVER_CONFIG"
}
add_api_service_without_secret() {
    jq '.services = ((.services // []) + [{
        "type": "api", "tag": "monitor-api",
        "listen": "127.0.0.1", "listen_port": 9091
      }])' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.tmp" && mv -f "$SB_SERVER_CONFIG.tmp" "$SB_SERVER_CONFIG"
}
write_state() {
    cat > "$SB_STATE_FILE" <<EOF
SERVER_IP='203.0.113.9'
PUBLIC_KEY='TEST-PUBLIC-KEY'
HY_SERVER_NAME='bing.com'
HY_HOPPING=$1
HY_HOPPING_START=
HY_HOPPING_END=
EOF
}
setup_upgrade_sandbox() {
    write_state FALSE
    write_migrated_config
    cp "$TMP/mock-old-sb" "$SB_SING_BOX_BIN"
    chmod +x "$SB_SING_BOX_BIN"
    rm -f "$SANDBOX"/sing-box.bak.* "$SANDBOX"/sbconfig_server.json.bak.*
    rm -f "$SB_API_SECRET_FILE" "$SB_API_SECRET_FILE".tmp.*
    : > "$MOCK_COUNT_FILE"
    export SYSTEMCTL_MODE="ok"
    export PGREP_MODE="found"
    rm -f "$TMP/new-check-fail" "$TMP/new-api-fail"
    export SB_NEW_CHECK_FAIL="$TMP/new-check-fail"
    export SB_NEW_API_FAIL="$TMP/new-api-fail"
}
config_secret() { read_api_secret_from_config "$SB_SERVER_CONFIG"; }

section "S1: secret generation is 256-bit CSPRNG output"
sec1="$(generate_api_secret)"
assert_rc 0 $? "generate_api_secret succeeds"
if [[ "$sec1" =~ ^[0-9a-f]{64}$ ]]; then pass "secret is 64 hex chars (256 bit)"; else fail "secret malformed: '$sec1'"; fi
sec2="$(generate_api_secret)"
if [ -n "$sec1" ] && [ "$sec1" != "$sec2" ]; then pass "two generations differ"; else fail "two generations identical/empty"; fi
printf '{"services":[{"type":"api","tag":"monitor-api","listen":"127.0.0.1","listen_port":9091}]}' > "$TMP/s1.json"
if [ -z "$(read_api_secret_from_config "$TMP/s1.json")" ]; then pass "secret-less entry reads as empty"; else fail "secret-less entry read as non-empty"; fi
printf '{"services":[{"type":"api","tag":"monitor-api","listen":"127.0.0.1","listen_port":9091,"secret":12345}]}' > "$TMP/s1b.json"
if [ -z "$(read_api_secret_from_config "$TMP/s1b.json")" ]; then pass "non-string secret reads as empty"; else fail "non-string secret read as non-empty"; fi
printf '{"services":[{"type":"api","tag":"monitor-api","listen":"127.0.0.1","listen_port":9091,"secret":""}]}' > "$TMP/s1c.json"
if [ -z "$(read_api_secret_from_config "$TMP/s1c.json")" ]; then pass "empty-string secret reads as empty"; else fail "empty-string secret read as non-empty"; fi
printf '{"services":[{"type":"api","tag":"monitor-api","listen":"127.0.0.1","listen_port":9091,"secret":"abc"}]}' > "$TMP/s1d.json"
if [ "$(read_api_secret_from_config "$TMP/s1d.json")" = "abc" ]; then pass "valid string secret is returned verbatim"; else fail "valid string secret not returned"; fi

section "S2: exact checker rejects secret-less monitor-api"
setup_upgrade_sandbox
add_api_service_without_secret
if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then fail "exact accepted a secret-less monitor-api"; else pass "exact rejects secret-less monitor-api"; fi
assert_grep 'monitor-api' <(jq -c '.services' "$SB_SERVER_CONFIG") "service entry still present (fail-closed, not deletion)"
setup_upgrade_sandbox
add_api_service_with_secret "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then pass "exact accepts entry with non-empty string secret"; else fail "exact rejected a secret-ed monitor-api"; fi

section "S3: migration injects the secret; every credential is preserved"
setup_upgrade_sandbox
fp_before="$(jq -S 'del(.services)' "$SB_SERVER_CONFIG")"
upgrade_singbox_1_14 > "$TMP/s3.out" 2>&1
assert_rc 0 $? "upgrade (API-auth migration) succeeds"
assert_rc 1 "$(jq -r '[.services[]? | select(.tag == "monitor-api")] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "exactly one monitor-api service after migration"
sec3="$(config_secret)"
if [[ "$sec3" =~ ^[0-9a-f]{64}$ ]]; then pass "migrated secret is 64 hex chars"; else fail "migrated secret malformed: '$sec3'"; fi
fp_after="$(jq -S 'del(.services)' "$SB_SERVER_CONFIG")"
if [ "$fp_before" = "$fp_after" ]; then
    pass "credential gate: canonicalized config excluding .services is identical (names/uuids/passwords/keys/ports/cert paths)"
else
    fail "credential gate: non-service config content changed by the migration"
fi
assert_grep 'OLD-REALITY-UUID' "$SB_SERVER_CONFIG" "reality uuid preserved"
assert_grep 'VMIX-HY2-PASSWORD' "$SB_SERVER_CONFIG" "hy2 password preserved"
assert_grep '"listen_port": 18443' "$SB_SERVER_CONFIG" "reality port unchanged"
assert_grep '"listen_port": 18444' "$SB_SERVER_CONFIG" "hy2 port unchanged"
assert_no_grep "$sec3" "$TMP/s3.out" "audit output does not print the secret"
if [ -f "$SB_API_SECRET_FILE" ]; then pass "derived secret file created"; else fail "derived secret file missing"; fi
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$sec3" ]; then pass "derived file matches the config secret"; else fail "derived file content mismatch"; fi
if [ "$IS_LINUX" = "1" ]; then
    assert_rc 600 "$(mode_of "$SB_API_SECRET_FILE")" "derived secret file mode 0600"
else
    printf '  SKIP mode assertions on Windows sandbox (derived file mode=%s)\n' "$(mode_of "$SB_API_SECRET_FILE")"
fi

section "S4: rerun never rotates a configured secret"
sec4_before="$(config_secret)"
derived_before="$(tr -d '\r\n' < "$SB_API_SECRET_FILE")"
upgrade_singbox_1_14 > "$TMP/s4.out" 2>&1
assert_rc 0 $? "second upgrade (idempotent) succeeds"
if [ "$(config_secret)" = "$sec4_before" ]; then pass "config secret stable across rerun"; else fail "config secret rotated on rerun"; fi
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$derived_before" ]; then pass "derived file untouched by rerun"; else fail "derived file rewritten by rerun"; fi
assert_no_grep '不一致' "$TMP/s4.out" "no drift warning on the healthy path"

section "S5: a pre-existing secret is preserved and config wins over the derived file"
setup_upgrade_sandbox
PRESERVED="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
add_api_service_with_secret "$PRESERVED"
printf 'stale-derivative-content\n' > "$SB_API_SECRET_FILE"
upgrade_singbox_1_14 > "$TMP/s5.out" 2>&1
assert_rc 0 $? "upgrade over a pre-existing secret succeeds"
if [ "$(config_secret)" = "$PRESERVED" ]; then pass "pre-existing config secret preserved (no rotation)"; else fail "pre-existing secret was replaced"; fi
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$PRESERVED" ]; then pass "mismatched derived file repaired from config"; else fail "derived file not repaired from config"; fi
assert_grep '不一致' "$TMP/s5.out" "drift repair is announced"
assert_no_grep "$PRESERVED" "$TMP/s5.out" "drift warning does not print the secret"
# healthy rerun afterwards: no warning, no rewrite
upgrade_singbox_1_14 > "$TMP/s5b.out" 2>&1
assert_rc 0 $? "rerun after repair succeeds"
assert_no_grep '不一致' "$TMP/s5b.out" "no drift warning once consistent"

section "S6: missing derived file is regenerated with a warning"
rm -f "$SB_API_SECRET_FILE"
upgrade_singbox_1_14 > "$TMP/s6.out" 2>&1
assert_rc 0 $? "upgrade succeeds with missing derived file"
assert_grep '派生文件缺失' "$TMP/s6.out" "missing derived file announced"
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$(config_secret)" ]; then pass "missing derived file regenerated from config"; else fail "derived file not regenerated"; fi

section "S7: the config lock is fail-closed"
setup_upgrade_sandbox
write_state FALSE
before_sha="$(sha "$SB_SERVER_CONFIG")"
# S7a: flock binary unavailable -> abort without running the mutation
command() {
    if [ "$1" = "-v" ] && [ "$2" = "flock" ]; then return 1; fi
    builtin command "$@"
}
add_client "no-flock" > "$TMP/s7a.out" 2>&1
assert_rc 1 $? "add_client aborted when flock is unavailable"
assert_grep 'flock 不可用' "$TMP/s7a.out" "missing-flock reason stated"
unset -f command
if [ "$before_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config byte-identical after missing-flock abort"; else fail "config mutated without flock"; fi
# S7b: lock file open failure -> abort
rm -f "$SB_LOCK_FILE"
mkdir "$SB_LOCK_FILE"
add_client "no-open" > "$TMP/s7b.out" 2>&1
assert_rc 1 $? "add_client aborted when the lock file cannot be opened"
assert_grep '无法打开配置锁文件' "$TMP/s7b.out" "open-failure reason stated"
rmdir "$SB_LOCK_FILE"
if [ "$before_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config byte-identical after open-failure abort"; else fail "config mutated on open failure"; fi
# S7c: contended lock times out -> abort (finite wait)
holder_pid=""
hold_lock() {
    SB_LOCK_FILE="$SB_LOCK_FILE" bash -c \
        'exec 9>>"$SB_LOCK_FILE"; flock 9; touch "$SB_LOCK_FILE.held"; command sleep 30' &
    holder_pid=$!
    # wait until the holder actually HOLDS the lock: it signals by touching the
    # .held marker only after flock has returned
    for _ in $(seq 1 100); do
        [ -f "$SB_LOCK_FILE.held" ] && break
        kill -0 "$holder_pid" 2>/dev/null || break
        command sleep 0.1
    done
    [ -f "$SB_LOCK_FILE.held" ] || { release_lock; fail "holder never acquired the lock"; return 1; }
}
release_lock() {
    [ -n "$holder_pid" ] && kill "$holder_pid" 2>/dev/null
    wait "$holder_pid" 2>/dev/null
    rm -rf -- "$SB_LOCK_FILE".mocklock.* "$SB_LOCK_FILE.held"
    holder_pid=""
}
hold_lock && {
    SB_LOCK_TIMEOUT=1 add_client "lock-timeout" > "$TMP/s7c.out" 2>&1
    assert_rc 1 $? "add_client aborted on lock timeout"
    assert_grep '获取失败或超时' "$TMP/s7c.out" "timeout reason stated"
    release_lock
}
if [ "$before_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config byte-identical after timeout abort"; else fail "config mutated on lock timeout"; fi
bak_count="$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)"
assert_rc 0 "$bak_count" "no backup created by any failed lock attempt"
if ! ls "$SANDBOX"/sbconfig_server.json.candidate.* >/dev/null 2>&1; then pass "no candidate left behind by failed lock attempts"; else fail "candidate residue after lock failure"; fi
# S7d: once the lock is free the same operation succeeds
add_client "after-timeout" > "$TMP/s7d.out" 2>&1
assert_rc 0 $? "add_client succeeds once the lock is free"
assert_rc 1 "$(get_reality_client_names | grep -cx 'after-timeout')" "after-timeout present in reality"

section "S8: locked delete helper revalidates the client name itself"
setup_upgrade_sandbox
write_state FALSE
mkdir -p "$SB_CLIENTS_DIR/vmix-01"
printf 'keep\n' > "$SB_CLIENTS_DIR/vmix-01/mihomo.yaml"
clients_dir_sha="$(sha "$SB_CLIENTS_DIR/vmix-01/mihomo.yaml")"
for bad in "../x" "../../etc" "a/b" 'a\b' "" "-leading" "$(printf 'a%.0s' $(seq 1 33))" "$(printf 'v\nb')" "vmix 01" ".hidden" ".." "a\$b"; do
    with_client_lock _delete_client_locked "$bad" > "$TMP/s8.out" 2>&1
    assert_rc 1 $? "locked delete rejected: '$(printf '%s' "$bad" | tr '\n' '@')'"
done
if [ "$clients_dir_sha" = "$(sha "$SB_CLIENTS_DIR/vmix-01/mihomo.yaml")" ]; then pass "filesystem untouched by rejected deletes"; else fail "filesystem mutated by rejected delete"; fi
if [ -d "$SB_CLIENTS_DIR" ]; then pass "clients dir survived traversal attempts"; else fail "clients dir deleted via traversal"; fi
echo y | delete_client "../x" > "$TMP/s8b.out" 2>&1
assert_rc 1 $? "outer delete_client also rejected for illegal name"
assert_grep 'locked helper 二次防护' "$TMP/s8b.out" "inner revalidation is the last line of defence"
add_client "vmix-03" > /dev/null 2>&1
assert_rc 0 $? "valid add works before valid delete"
echo y | delete_client "vmix-03" > "$TMP/s8c.out" 2>&1
assert_rc 0 $? "valid delete still works"
assert_rc 0 "$(get_reality_client_names | grep -cx 'vmix-03')" "vmix-03 gone from reality"
assert_rc 0 "$(get_hy2_client_names | grep -cx 'vmix-03')" "vmix-03 gone from hy2"
assert_grep 'OLD-REALITY-UUID' "$SB_SERVER_CONFIG" "legacy untouched by valid delete"

section "S9: permission hardening helper"
PERMBOX="$TMP/permbox"
mkdir -p "$PERMBOX/clients/dev-01" "$PERMBOX/self-cert"
: > "$PERMBOX/sbconfig_server.json"; : > "$PERMBOX/config"; : > "$PERMBOX/monitor-api.secret"
: > "$PERMBOX/self-cert/private.key"; : > "$PERMBOX/self-cert/cert.pem"
: > "$PERMBOX/clients/dev-01/mihomo.yaml"; : > "$PERMBOX/BLOCKED-target"
save_env="$SB_SERVER_CONFIG|$SB_STATE_FILE|$SB_CLIENTS_DIR|$SB_API_SECRET_FILE|$SB_SELF_CERT_KEY|$SB_SELF_CERT_CERT"
SB_SERVER_CONFIG="$PERMBOX/sbconfig_server.json"
SB_STATE_FILE="$PERMBOX/config"
SB_CLIENTS_DIR="$PERMBOX/clients"
SB_API_SECRET_FILE="$PERMBOX/monitor-api.secret"
SB_SELF_CERT_KEY="$PERMBOX/self-cert/private.key"
SB_SELF_CERT_CERT="$PERMBOX/self-cert/cert.pem"
if [ "$IS_LINUX" = "1" ]; then
    chmod 0644 "$PERMBOX/sbconfig_server.json" "$PERMBOX/config" "$PERMBOX/monitor-api.secret" \
               "$PERMBOX/self-cert/private.key" "$PERMBOX/clients/dev-01/mihomo.yaml"
    chmod 0600 "$PERMBOX/self-cert/cert.pem"
    chmod 0755 "$PERMBOX/clients" "$PERMBOX/clients/dev-01"
    harden_sensitive_permissions
    assert_rc 0 $? "harden_sensitive_permissions succeeds"
    assert_rc 600 "$(mode_of "$PERMBOX/sbconfig_server.json")" "server config 0600"
    assert_rc 600 "$(mode_of "$PERMBOX/config")" "state file 0600"
    assert_rc 600 "$(mode_of "$PERMBOX/monitor-api.secret")" "derived secret 0600"
    assert_rc 600 "$(mode_of "$PERMBOX/self-cert/private.key")" "private key 0600"
    assert_rc 644 "$(mode_of "$PERMBOX/self-cert/cert.pem")" "public cert 0644"
    assert_rc 700 "$(mode_of "$PERMBOX/clients")" "clients dir 0700"
    assert_rc 700 "$(mode_of "$PERMBOX/clients/dev-01")" "client dir 0700"
    assert_rc 600 "$(mode_of "$PERMBOX/clients/dev-01/mihomo.yaml")" "client yaml 0600"
    # missing files are skipped without error
    rm -f "$PERMBOX/config"
    harden_sensitive_permissions
    assert_rc 0 $? "missing sensitive file is skipped, not an error"
    # chmod failure is fail-closed: re-point the state file at a path the
    # chmod override refuses, so the helper's own loop hits the failure
    SB_STATE_FILE="$PERMBOX/BLOCKED-state"
    touch "$PERMBOX/BLOCKED-state"
    chmod() { if [[ "${2:-}" == *BLOCKED* ]]; then return 1; fi; command chmod "$@"; }
    harden_sensitive_permissions > "$TMP/s9.out" 2>&1
    assert_rc 1 $? "chmod failure fails closed"
    assert_grep '拒绝继续' "$TMP/s9.out" "chmod failure reason stated"
    unset -f chmod
    rm -f "$PERMBOX/BLOCKED-state"
else
    harden_sensitive_permissions
    assert_rc 0 $? "harden_sensitive_permissions succeeds (Windows rc path)"
    printf '  SKIP mode assertions on Windows sandbox\n'
fi
restore_env="${save_env%%|*}"
rest="${save_env#*|}"
SB_SERVER_CONFIG="$restore_env"
SB_STATE_FILE="${rest%%|*}"; rest="${rest#*|}"
SB_CLIENTS_DIR="${rest%%|*}"; rest="${rest#*|}"
SB_API_SECRET_FILE="${rest%%|*}"; rest="${rest#*|}"
SB_SELF_CERT_KEY="${rest%%|*}"; rest="${rest#*|}"
SB_SELF_CERT_CERT="${rest%%|*}"

section "S10: backups are 0600 even when the live config was 0644"
setup_upgrade_sandbox
write_state FALSE
migrate_legacy_clients >/dev/null 2>&1
if [ "$IS_LINUX" = "1" ]; then
    chmod 0644 "$SB_SERVER_CONFIG"
    add_client "mode-check" > /dev/null 2>&1
    assert_rc 0 $? "add_client with 0644 live config"
    newest_bak="$(ls -1t "$SANDBOX"/sbconfig_server.json.bak.* | head -n1)"
    assert_rc 600 "$(mode_of "$newest_bak")" "backup of a 0644 config forced to 0600"
    assert_rc 600 "$(mode_of "$SB_SERVER_CONFIG")" "live config is 0600 after commit"
    # chmod failure on the backup aborts the transaction before any mutation
    chmod() { if [[ "${2:-}" == *.bak.* ]]; then return 1; fi; command chmod "$@"; }
    pre_sha="$(sha "$SB_SERVER_CONFIG")"
    add_client "bak-blocked" > "$TMP/s10.out" 2>&1
    assert_rc 1 $? "transaction aborted when the backup cannot be hardened"
    if [ "$pre_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "live config untouched when backup hardening fails"; else fail "live config mutated despite backup chmod failure"; fi
    unset -f chmod
else
    add_client "mode-check-win" > /dev/null 2>&1
    assert_rc 0 $? "add_client works (Windows)"
    printf '  SKIP mode assertions on Windows sandbox\n'
fi

section "S11: migration output never leaks credentials"
setup_upgrade_sandbox
upgrade_singbox_1_14 > "$TMP/s11.out" 2>&1
assert_rc 0 $? "upgrade for leak scan succeeds"
leak="$(jq -r '[(.services // [])[] | select(.tag == "monitor-api")][0].secret' "$SB_SERVER_CONFIG")"
assert_no_grep "$leak" "$TMP/s11.out" "API secret absent from all upgrade output"
assert_no_grep 'OLD-KEY|OLD-HY2-PASSWORD|OLD-REALITY-UUID' "$TMP/s11.out" "user credentials absent from upgrade output"

section "S12: existing-install baseline repair is fail-closed"
# error() must be observable: record the invocation instead of the harness
# default. In the real installer error() exits, so ERROR_CALLED=1 + rc!=0
# means the interactive menu is never reached.
ERROR_CALLED=0
error() { printf '  [err ] %s\n' "$*"; ERROR_CALLED=1; return 1; }
GOOD="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# S12a: healthy install -> repair succeeds, nothing rewritten, no warnings
setup_upgrade_sandbox
add_api_service_with_secret "$GOOD"
printf '%s\n' "$GOOD" > "$SB_API_SECRET_FILE"
repair_existing_install_security_baseline > "$TMP/s12a.out" 2>&1
assert_rc 0 $? "healthy repair succeeds"
assert_no_grep '不一致|缺失' "$TMP/s12a.out" "no drift/missing warning on the healthy path"
assert_no_grep "$GOOD" "$TMP/s12a.out" "no secret in repair output"
if [ "$(config_secret)" = "$GOOD" ]; then pass "config secret untouched (no rotation)"; else fail "config secret changed by repair"; fi
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$GOOD" ]; then pass "derived file untouched on the healthy path"; else fail "derived file rewritten on the healthy path"; fi

# S12b: stale derived file -> repaired from the config, config unchanged
printf 'stale-secret\n' > "$SB_API_SECRET_FILE"
repair_existing_install_security_baseline > "$TMP/s12b.out" 2>&1
assert_rc 0 $? "stale derived file repaired successfully"
assert_grep '不一致' "$TMP/s12b.out" "drift repair announced"
assert_no_grep "$GOOD" "$TMP/s12b.out" "drift warning carries no secret"
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$GOOD" ]; then pass "derived file restored from config"; else fail "derived file not restored"; fi
if [ "$(config_secret)" = "$GOOD" ]; then pass "config unchanged by repair"; else fail "config mutated by repair"; fi

# S12c: forced write failure -> installer aborts, menu NOT entered
printf 'stale-secret\n' > "$SB_API_SECRET_FILE"
fp_before="$(jq -S 'del(.services)' "$SB_SERVER_CONFIG")"
write_api_secret_file() { return 1; }
ERROR_CALLED=0
repair_existing_install_security_baseline > "$TMP/s12c.out" 2>&1
assert_rc 1 $? "repair aborts when the derived file cannot be written"
if [ "$ERROR_CALLED" = "1" ]; then pass "error() invoked (real installer exits: menu NOT entered)"; else fail "no abort signal on repair failure"; fi
assert_grep '修复失败' "$TMP/s12c.out" "abort reason stated"
assert_no_grep "$GOOD" "$TMP/s12c.out" "abort output prints no secret"
unset -f write_api_secret_file
if [ "$(config_secret)" = "$GOOD" ]; then pass "config secret unchanged by the failed repair"; else fail "config secret changed by the failed repair"; fi
if [ "$(jq -S 'del(.services)' "$SB_SERVER_CONFIG")" = "$fp_before" ]; then
    pass "Reality/HY2 credentials unchanged by the failed repair"
else
    fail "Reality/HY2 credentials changed by the failed repair"
fi

# S12d: pre-Phase-D config (no valid secret) must NOT lock the menu
setup_upgrade_sandbox
write_migrated_config
rm -f "$SB_API_SECRET_FILE"
ERROR_CALLED=0
repair_existing_install_security_baseline > "$TMP/s12d.out" 2>&1
assert_rc 0 $? "no-secret config: repair is a no-op (menu stays reachable)"
assert_no_grep '修复失败' "$TMP/s12d.out" "no failure reported without a configured secret"

# restore the harness-default error() behaviour
ERROR_CALLED=0
error() { printf '  [err ] %s\n' "$*"; }

printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
