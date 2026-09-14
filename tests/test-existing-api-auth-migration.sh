#!/usr/bin/env bash
# Narrow existing-server service.api authentication migration regression tests.
#
# Scope (X1..X18): old servers already running a structurally compliant
# localhost service.api (tag monitor-api, 127.0.0.1:9091) WITHOUT a secret:
#   - classification: exact / needed / absent / structural / unreadable
#   - explicit [y/N] confirmation gathered OUTSIDE config.lock (default NO)
#   - declined -> byte-identical config, no anchor, no restart
#   - approved -> ONLY monitor-api.secret changes semantically; binary, state
#     file, Reality/HY2 credentials and all unrelated fields are preserved
#   - idempotency: rerun preserves the secret byte-for-byte, no rotation, no
#     extra restart; anchor converges from the config
#   - failure semantics: candidate check / backup / live replace / anchor /
#     restart / health / rollback failures each behave fail-closed
#   - lock timeout and concurrency: zero mutation / single secret, no rotation
#   - no secret leakage into stdout/stderr
#   - fresh install path unchanged
#
# Like the phase-c/d suites, the tests really EXECUTE the shell functions: the
# phase-c + s0 + migration + phase-d blocks are extracted from install.sh and
# sourced with every external dependency pointed at a throwaway sandbox.
# Nothing touches /root/sbox. Permission MODE assertions are meaningful only
# on real Linux (MSYS chmod/stat are no-ops for NTFS ACLs and are SKIPped).
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$HERE/../install.sh"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
cleanup() { [ "${KEEP_TMP:-0}" = "1" ] || rm -rf -- "$TMP"; }
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
OUTDIR="$TMP/outs"
mkdir -p "$OUTDIR"

section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then pass "shellcheck install.sh"; else fail "shellcheck install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
else
    printf '  SKIP shellcheck 未安装\n'
fi
assert_grep '^existing_api_auth_classify\(\)' "$INSTALL_SH" "classification helper exists"
assert_grep '^maybe_migrate_existing_api_auth\(\)' "$INSTALL_SH" "public migration wrapper exists"
assert_grep '^_migrate_existing_api_auth_locked\(\)' "$INSTALL_SH" "locked migration helper exists"
assert_grep '^_rollback_existing_api_auth\(\)' "$INSTALL_SH" "rollback helper exists"
assert_grep 'with_client_lock _migrate_existing_api_auth_locked' "$INSTALL_SH" "migration runs under the global config lock"
assert_grep 'restore_file_atomically "\$backup_cfg" "\$SB_SERVER_CONFIG"' "$INSTALL_SH" "rollback uses the hardened atomic restore primitive"
assert_grep 'generate_api_secret' "$INSTALL_SH" "secret comes from the existing CSPRNG contract"
assert_grep '"secret": "\$monitor_api_secret"' "$INSTALL_SH" "fresh install path still embeds a generated API secret (X18)"
assert_grep 'openssl rand -hex 32' "$INSTALL_SH" "fresh install CSPRNG unchanged (X18)"
assert_grep 'malformed-secret' "$INSTALL_SH" "malformed secret shape is a distinct refused classification (narrow migration never overwrites unknown credential types)"
assert_grep 'rm -f -- "\$SB_API_SECRET_FILE"' "$INSTALL_SH" "no-anchor rollback uses a checked rm -f --"
assert_grep '无法删除迁移新建的 monitor-api.secret' "$INSTALL_SH" "anchor removal failure escalates to MANUAL INTERVENTION (never a claimed successful rollback)"
assert_rc 0 "$(grep -c 'maybe_migrate_existing_api_auth || true' "$INSTALL_SH")" "no swallow-failure wiring: '|| true' is banned (failures MUST abort the existing-install flow)"
assert_rc 1 "$(grep -cE '^[[:space:]]*maybe_migrate_existing_api_auth$' "$INSTALL_SH")" "migration entry point wired exactly once, bare (existing-install path only, X18)"
# The fresh-install flow must never call the migration wrapper.
if awk '/^monitor_api_secret=/{fresh=1} fresh && /maybe_migrate_existing_api_auth/{bad=1} END{exit bad?1:0}' "$INSTALL_SH"; then
    pass "fresh-install block never calls the migration wrapper (X18)"
else
    fail "fresh-install block calls the migration wrapper (X18)"
fi

section "extract blocks and prepare sandbox"
awk '/# >>> phase-c client-management >>>/,/# <<< phase-d singbox-1.14-api <<</' \
    "$INSTALL_SH" > "$TMP/blocks.sh"
# restore_file_atomically lives in the legacy-hardening block (AFTER the
# phase-d marker); append it so the migration's rollback primitive is real.
awk '/^restore_file_atomically\(\) \{/,/^\}/' "$INSTALL_SH" >> "$TMP/blocks.sh"
assert_grep 'existing_api_auth_classify' "$TMP/blocks.sh" "migration block extracted"
assert_grep 'phase_d_health_ok' "$TMP/blocks.sh" "phase-d block still present (shared health primitive)"
assert_grep 'generate_api_secret' "$TMP/blocks.sh" "s0 block still present (shared secret primitives)"

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
        reload) return 0 ;;
    esac
    return 0
}
pgrep() { return 1; }
sleep() { return 0; }
# The listener set is static across this migration: Reality TCP + HY2 UDP +
# the pre-existing loopback API listener (the old server ALREADY serves 9091
# on 127.0.0.1 without auth). Wildcard 9091 is never in the fixture, so the
# health check's no-wildcard assertion is meaningful.
ss() {
    local tcp="LISTEN 0 128 0.0.0.0:18443 0.0.0.0:*
LISTEN 0 128 127.0.0.1:9091 0.0.0.0:*"
    local udp="UNCONN 0 0 0.0.0.0:18444 0.0.0.0:*"
    case "$*" in
        *-lntu*) printf '%s\n%s\n' "$tcp" "$udp" ;;
        *-lnt*) printf '%s\n' "$tcp" ;;
        *-lnu*) printf '%s\n' "$udp" ;;
    esac
    return 0
}
# Targeted failure injection for the atomic-replace / atomic-restore mocks:
#   MV_FAIL_MODE=commit   -> live config replace fails (candidate source)
#   MV_FAIL_MODE=restore  -> rollback restore mv fails (.restore. source)
mv() {
    if [ -n "${MV_FAIL_MODE:-}" ]; then
        local a src="" last="${@: -1}"
        for a in "$@"; do
            case "$a" in
                -*) ;;                 # flags
                *) [ -z "$src" ] && src="$a" ;;
            esac
        done
        if [ "$last" = "${SB_SERVER_CONFIG:-}" ]; then
            case "$MV_FAIL_MODE" in
                commit) case "$src" in *.restore.*|*.bak.*) ;; *) return 1 ;; esac ;;
                restore) case "$src" in *.restore.*) return 1 ;; esac ;;
            esac
        fi
    fi
    command mv "$@"
}
# CP_FAIL_BAK=1 -> backing up the live config fails (target is a config backup)
cp() {
    if [ "${CP_FAIL_BAK:-0}" = "1" ]; then
        local tgt="${@: -1}"
        case "$tgt" in
            "${SB_SERVER_CONFIG}".bak.*) return 1 ;;
        esac
    fi
    command cp "$@"
}
MOCKS

# ------------------------------------------------------------- mock binary --
# Old server: sing-box 1.14.0 ALREADY running (the binary must never change).
cat > "$TMP/mock-sb" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
  version) printf 'sing-box version 1.14.0\nTag: mock-existing\n' ;;
  check)
    [ -f "${SB_CHECK_FAIL:-/nonexistent}" ] && exit 1
    f=""
    while [ $# -gt 0 ]; do case "$1" in -c) f="$2"; shift 2;; *) shift;; esac; done
    [ -n "$f" ] || exit 1
    jq empty "$f" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  api)
    # Emulate service.api auth enforcement: when the live config carries a
    # monitor-api secret, only a call presenting exactly that secret succeeds.
    # SB_API_FAIL simulates a runtime where even the correct secret fails.
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
    if [ -n "$want_secret" ]; then
        [ -f "${SB_API_FAIL:-/nonexistent}" ] && exit 1
        if [ "$got_secret" != "$want_secret" ]; then
            printf 'rpc error: Unauthenticated\n' >&2
            exit 1
        fi
    fi
    exit 0 ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$TMP/mock-sb"

. "$TMP/mocks.sh"
. "$TMP/blocks.sh"

# Targeted failure injection: RM_FAIL_ANCHOR=1 makes deleting the migration's
# own anchor fail (used by X12c). Everything else falls through to real rm.
rm() {
    if [ "${RM_FAIL_ANCHOR:-0}" = "1" ] && [ "$#" -gt 0 ]; then
        local a
        for a in "$@"; do
            [ -n "${SB_API_SECRET_FILE:-}" ] && [ "$a" = "$SB_API_SECRET_FILE" ] && return 1
        done
    fi
    command rm "$@"
}

# ------------------------------------------------------------------ helpers --
# Existing-install shape: Phase C identity model intact, Reality/HY2 creds, a
# non-monitor-api service that must survive untouched, and a compliant
# monitor-api service with NO secret (or with "$2" when given).
write_existing_config() { # write_existing_config [api_secret]
    local api_secret="${1:-}"
    local api_extra=""
    [ -n "$api_secret" ] && api_extra=", \"secret\": \"$api_secret\""
    cat > "$SB_SERVER_CONFIG" <<EOF
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
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "services": [
    {"type": "api", "tag": "monitor-api", "listen": "127.0.0.1", "listen_port": 9091${api_extra}},
    {"type": "ss", "tag": "ss-unlock", "listen": "127.0.0.1", "listen_port": 10808, "method": "2022-blake3-aes-256-gcm", "password": "SS-UNLOCK-PASSWORD"}
  ]
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

reset_sandbox() { # fresh per-scenario fixtures; listener set is static here
    write_state
    printf '0\n' > "$RESTART_COUNT_FILE"
    : > "$SYSTEMCTL_LOG"
    export RESTART_FAIL_MODE="none"
    export SYSTEMCTL_MODE="ok"
    export MV_FAIL_MODE=""
    export CP_FAIL_BAK=0
    rm -f "$SB_CHECK_FAIL" "$SB_API_FAIL" "$SB_HOPPING_SERVICE"
    rm -rf "$SB_API_SECRET_FILE"
    rm -f "$SANDBOX"/sbconfig_server.json.bak.* "$SANDBOX"/sbconfig_server.json.candidate.* "$SANDBOX"/monitor-api.secret.bak.*
    cp "$TMP/mock-sb" "$SB_SING_BOX_BIN"
    chmod +x "$SB_SING_BOX_BIN"
}

answer_file() { # answer_file <text> -> path with the operator's stdin
    printf '%s\n' "$1" > "$TMP/answer"
    printf '%s' "$TMP/answer"
}

register_secret() { # remember every generated secret for the leak sweep
    local s
    s="$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' "$SB_SERVER_CONFIG" 2>/dev/null | tr -d '\r')"
    [ -n "$s" ] && printf '%s\n' "$s" >> "$TMP/secrets.list"
    return 0
}

export SYSTEMCTL_LOG="$TMP/systemctl.log"
export RESTART_COUNT_FILE="$TMP/restart-count"
export SB_CHECK_FAIL="$TMP/check-fail"
export SB_API_FAIL="$TMP/api-fail"
: > "$TMP/secrets.list"

# ============================================================================
section "X1: exact API + valid secret -> no prompt, no mutation, no restart"
reset_sandbox
write_existing_config "1111111111111111111111111111111111111111111111111111111111111111"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x1.out" 2>&1
assert_rc 0 $? "wrapper succeeds on an exact config"
assert_no_grep '检测到旧版 service.api' "$OUTDIR/x1.out" "no confirmation prompt (X1)"
assert_no_grep '已配置认证（无需迁移）' "$OUTDIR/x1.out" "no spurious idempotent-restart message"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config untouched (X1)"; else fail "config mutated (X1)"; fi
if [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "binary untouched (X1)"; else fail "binary mutated (X1)"; fi
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restarts (X1)"
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE" 2>/dev/null)" = "1111111111111111111111111111111111111111111111111111111111111111" ]; then
    pass "anchor converged from config; configured secret never rotated (X1)"
else
    fail "anchor not converged from the authoritative config (X1)"
fi

section "X2: missing secret + operator says NO -> byte-identical, no anchor, zero restart"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"; st_sha="$(sha "$SB_STATE_FILE")"
maybe_migrate_existing_api_auth < "$(answer_file n)" > "$OUTDIR/x2.out" 2>&1
assert_rc 0 $? "wrapper succeeds (declined)"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config byte-identical (X2)"; else fail "config mutated (X2)"; fi
if [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "binary/state unchanged (X2)"; else fail "binary mutated (X2)"; fi
if [ "$st_sha" = "$(sha "$SB_STATE_FILE")" ]; then pass "state file unchanged (X2)"; else fail "state file mutated (X2)"; fi
assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "no anchor created (X2)"
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X2)"
assert_grep '未做任何修改' "$OUTDIR/x2.out" "decline acknowledged"
assert_grep 'Monitor v2 部署前必须先完成该认证迁移' "$OUTDIR/x2.out" "Monitor v2 requirement warned"

section "X2b: default (empty input) is NO"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
maybe_migrate_existing_api_auth < /dev/null > "$OUTDIR/x2b.out" 2>&1
assert_rc 0 $? "wrapper succeeds on empty input"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config byte-identical (X2b)"; else fail "config mutated (X2b)"; fi
assert_grep '已取消' "$OUTDIR/x2b.out" "default NO honoured"
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X2b)"

section "X3: missing secret + YES -> only monitor-api.secret changes semantically"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"; st_sha="$(sha "$SB_STATE_FILE")"
users_before="$(jq -Sc '[.inbounds[] | .users] | sort' "$SB_SERVER_CONFIG" | tr -d '\r')"
cp "$SB_SERVER_CONFIG" "$TMP/x3pre.json"   # pre-migration snapshot for semantic diff
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x3.out" 2>&1
assert_rc 0 $? "migration succeeds"
if [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then pass "binary SHA unchanged (X3)"; else fail "binary changed (X3)"; fi
if [ "$st_sha" = "$(sha "$SB_STATE_FILE")" ]; then pass "/root/sbox/config state SHA unchanged (X3)"; else fail "state file changed (X3)"; fi
# 1. canonicalized config excluding .services identical
if [ "$(jq -Sc 'del(.services)' "$TMP/x3pre.json" | tr -d '\r')" = \
     "$(jq -Sc 'del(.services)' "$SB_SERVER_CONFIG" | tr -d '\r')" ]; then
    pass "canonicalized config excluding .services identical"
else
    fail "fields outside .services changed"
fi
# 2. all services other than monitor-api identical
if [ "$(jq -Sc --arg tag monitor-api '[.services[]? | select(.tag != $tag)]' "$TMP/x3pre.json" | tr -d '\r')" = \
     "$(jq -Sc --arg tag monitor-api '[.services[]? | select(.tag != $tag)]' "$SB_SERVER_CONFIG" | tr -d '\r')" ]; then
    pass "all non-monitor-api services identical"
else
    fail "unrelated services changed"
fi
# 3. monitor-api excluding .secret identical
if [ "$(jq -Sc --arg tag monitor-api '[.services[]? | select(.tag == $tag) | del(.secret)]' "$TMP/x3pre.json" | tr -d '\r')" = \
     "$(jq -Sc --arg tag monitor-api '[.services[]? | select(.tag == $tag) | del(.secret)]' "$SB_SERVER_CONFIG" | tr -d '\r')" ]; then
    pass "monitor-api excluding .secret identical"
else
    fail "monitor-api fields other than secret changed"
fi
users_after="$(jq -Sc '[.inbounds[] | .users] | sort' "$SB_SERVER_CONFIG" | tr -d '\r')"
if [ "$users_before" = "$users_after" ]; then pass "Reality/HY2 credentials preserved verbatim"; else fail "users changed"; fi
assert_grep 'OLD-REALITY-UUID' "$SB_SERVER_CONFIG" "reality uuid kept"
assert_grep 'VMIX-HY2-PASSWORD' "$SB_SERVER_CONFIG" "hy2 password kept"
assert_grep 'SS-UNLOCK-PASSWORD' "$SB_SERVER_CONFIG" "unrelated ss service preserved"
assert_rc 1 "$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)] | length' "$SB_SERVER_CONFIG" | tr -d '\r')" "exactly one monitor-api"
migrated="$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' "$SB_SERVER_CONFIG" | tr -d '\r')"
if [[ "$migrated" =~ ^[0-9a-f]{64}$ ]]; then pass "secret is a 256-bit hex value"; else fail "secret invalid: '$migrated'"; fi
assert_rc 1 "$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0] | del(.secret) | tojson' "$SB_SERVER_CONFIG" | grep -c 'monitor-api' )" "monitor-api entry otherwise unchanged"
assert_rc 1 "$(printf '%s' "$(jq -r '.services[]? | select(.tag == "monitor-api") | .listen' "$SB_SERVER_CONFIG")" | grep -cx '127.0.0.1')" "listen still loopback-only"
assert_rc 1 "$(printf '%s' "$(jq -r '.services[]? | select(.tag == "monitor-api") | .listen_port' "$SB_SERVER_CONFIG")" | grep -cx '9091')" "port still 9091"
assert_rc 1 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "derived anchor created"
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE")" = "$migrated" ]; then pass "anchor matches config secret (config is source of truth)"; else fail "anchor/config mismatch"; fi
if [ "$IS_LINUX" = "1" ]; then
    assert_rc 1 "$(printf '%s' "$(mode_of "$SB_API_SECRET_FILE")" | grep -cx '600')" "anchor mode 0600 (Linux)"
else
    printf '  SKIP mode assertion on MSYS\n'
fi
assert_rc 1 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "exactly one controlled restart"
# authenticated API succeeds, unauthenticated API is rejected (mock enforcement)
if "$SB_SING_BOX_BIN" api --url "http://127.0.0.1:9091" --secret "$migrated" connection list >/dev/null 2>&1; then
    pass "authenticated API call succeeds"
else
    fail "authenticated API call failed"
fi
if "$SB_SING_BOX_BIN" api --url "http://127.0.0.1:9091" connection list >/dev/null 2>&1; then
    fail "unauthenticated API call was accepted"
else
    pass "unauthenticated API call rejected"
fi
assert_grep '认证迁移完成' "$OUTDIR/x3.out" "success reported"
register_secret

section "X4: rerun after success -> secret stable, no restart"
migrated_sha="$migrated"
restarts_before="$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x4.out" 2>&1
assert_rc 0 $? "rerun succeeds"
now="$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' "$SB_SERVER_CONFIG" | tr -d '\r')"
if [ "$now" = "$migrated_sha" ]; then pass "secret preserved byte-for-byte (no rotation)"; else fail "secret rotated on rerun"; fi
assert_rc 0 "$(( $(grep -c 'restart sing-box' "$SYSTEMCTL_LOG") - restarts_before ))" "no unnecessary restart (X4)"
assert_no_grep '认证迁移完成' "$OUTDIR/x4.out" "exact state is a silent no-op (no restart message)"

section "X5: valid config secret + missing/stale anchor -> anchor repaired, no rotation, no restart"
reset_sandbox
write_existing_config "2222222222222222222222222222222222222222222222222222222222222222"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x5a.out" 2>&1
assert_rc 0 $? "exact wrapper no-op ok"
rm -f "$SB_API_SECRET_FILE"
restarts_before="$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x5.out" 2>&1
assert_rc 0 $? "anchor repair succeeds"
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE" 2>/dev/null)" = "2222222222222222222222222222222222222222222222222222222222222222" ]; then
    pass "anchor repaired from config (no rotation)"
else
    fail "anchor not repaired from config"
fi
assert_rc 0 "$(( $(grep -c 'restart sing-box' "$SYSTEMCTL_LOG") - restarts_before ))" "no restart for anchor repair"
# stale anchor content is also overwritten from the config
printf 'stale\n' > "$SB_API_SECRET_FILE"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x5b.out" 2>&1
if [ "$(tr -d '\r\n' < "$SB_API_SECRET_FILE" 2>/dev/null)" = "2222222222222222222222222222222222222222222222222222222222222222" ]; then
    pass "stale anchor converged from config"
else
    fail "stale anchor not converged"
fi

section "X6: structural monitor-api mismatch -> refuses, no mutation"
reset_sandbox
write_existing_config
jq '.services[0].listen = "0.0.0.0"' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.t" && mv -f "$SB_SERVER_CONFIG.t" "$SB_SERVER_CONFIG"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x6.out" 2>&1
assert_rc 0 $? "wrapper reports and continues"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then
    pass "zero mutation (X6)"
else
    fail "mutated on structural mismatch (X6)"
fi
assert_grep 'Phase D 修复/升级路径' "$OUTDIR/x6.out" "Phase D path reported"
assert_no_grep '认证迁移完成' "$OUTDIR/x6.out" "no migration attempted"
assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "no anchor created (X6)"
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X6)"

section "X7: duplicate monitor-api -> refuses, no mutation"
reset_sandbox
write_existing_config
jq '.services += [{"type":"api","tag":"monitor-api","listen":"127.0.0.1","listen_port":9091}]' \
    "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.t" && mv -f "$SB_SERVER_CONFIG.t" "$SB_SERVER_CONFIG"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x7.out" 2>&1
assert_rc 0 $? "wrapper reports and continues"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "zero mutation (X7)"; else fail "mutated on duplicate (X7)"; fi
assert_grep 'Phase D 修复/升级路径' "$OUTDIR/x7.out" "Phase D path reported (X7)"
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X7)"

section "X7b: monitor-api absent entirely -> refuses to reinvent, no mutation"
reset_sandbox
write_existing_config
jq '.services = [.services[1]]' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.t" && mv -f "$SB_SERVER_CONFIG.t" "$SB_SERVER_CONFIG"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x7b.out" 2>&1
assert_rc 0 $? "wrapper reports and continues"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "zero mutation (X7b)"; else fail "mutated on absent api (X7b)"; fi
assert_grep 'Phase D 修复/升级路径' "$OUTDIR/x7b.out" "Phase D path reported (X7b)"
assert_no_grep '检测到旧版 service.api' "$OUTDIR/x7b.out" "no prompt for absent api"

section "X7c: secret-shape contract (finalized): ONLY the absent secret key auto-migrates"
# The explicitly approved narrow-migration shape is a MISSING secret: the
# "secret" KEY ABSENT on the monitor-api entry -- nothing to overwrite. A
# PRESENT key with an unusable value ("", null, number, boolean, object,
# array) is MALFORMED: it is never treated as missing and never overwritten;
# the narrow migration refuses and points to Phase D. The lock re-check
# enforces the same rule against a concurrent shape change between prompt
# and lock.

# X7c-0: secret KEY absent -> promptable, approved migration works
reset_sandbox
write_existing_config
jq 'del(.services[0].secret)' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.t" && mv -f "$SB_SERVER_CONFIG.t" "$SB_SERVER_CONFIG"
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x7c0.out" 2>&1
assert_rc 0 $? "absent secret key migrates when approved"
migrated="$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' "$SB_SERVER_CONFIG" | tr -d '\r')"
if [[ "$migrated" =~ ^[0-9a-f]{64}$ ]]; then pass "absent secret key replaced by a valid generated secret"; else fail "absent secret key not migrated: '$migrated'"; fi
assert_rc 1 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "exactly one controlled restart (X7c-0)"
register_secret

# X7c-1..6: PRESENT but malformed secret values ("", null, number, boolean,
# object, array) -> refuse, zero mutation, no prompt, no anchor, no restart,
# Phase D reported. Malformed is NEVER classified as missing/overwritten.
for shape in '""' 'null' '12345' 'true' '{"boss":1}' '["a","b"]'; do
    reset_sandbox
    write_existing_config
    jq --argjson v "$shape" '.services[0].secret = $v' "$SB_SERVER_CONFIG" > "$SB_SERVER_CONFIG.t" \
        && mv -f "$SB_SERVER_CONFIG.t" "$SB_SERVER_CONFIG"
    cfg_sha="$(sha "$SB_SERVER_CONFIG")"; bin_sha="$(sha "$SB_SING_BOX_BIN")"
    maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x7c-shape.out" 2>&1
    assert_rc 0 $? "malformed secret ($shape) is a refusal, not an error"
    assert_no_grep '检测到旧版 service.api' "$OUTDIR/x7c-shape.out" "no prompt for malformed secret ($shape)"
    assert_grep 'Phase D 修复/升级路径' "$OUTDIR/x7c-shape.out" "Phase D path reported for malformed secret ($shape)"
    if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ] && [ "$bin_sha" = "$(sha "$SB_SING_BOX_BIN")" ]; then
        pass "zero mutation for malformed secret ($shape)"
    else
        fail "mutated on malformed secret ($shape)"
    fi
    assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "no anchor created for malformed secret ($shape)"
    assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart for malformed secret ($shape)"
done

section "X8: candidate sing-box check failure -> no live mutation"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
: > "$SB_CHECK_FAIL"
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x8.out" 2>&1
assert_rc 1 $? "migration fails closed"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "live config untouched (X8)"; else fail "live mutated (X8)"; fi
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X8)"
assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "no anchor created (X8)"
assert_grep 'candidate sing-box check 未通过' "$OUTDIR/x8.out" "check failure reason stated"

section "X9: backup failure -> no live mutation"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
export CP_FAIL_BAK=1
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x9.out" 2>&1
assert_rc 1 $? "migration fails closed"
export CP_FAIL_BAK=0
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "live config untouched (X9)"; else fail "live mutated (X9)"; fi
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X9)"
assert_grep '备份当前配置失败' "$OUTDIR/x9.out" "backup failure reason stated"
assert_rc 0 "$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)" "no stray backup left behind"

section "X10: live replace failure -> correct failure, backup preserved"
reset_sandbox
write_existing_config
export MV_FAIL_MODE=commit
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x10.out" 2>&1
assert_rc 1 $? "migration fails closed on replace failure"
export MV_FAIL_MODE=""
assert_grep '原子替换 config 失败' "$OUTDIR/x10.out" "replace failure reason stated"
assert_rc 1 "$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)" "backup preserved"
if jq -e --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret == null' "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
    pass "live config still the pre-migration one"
else
    fail "live config unexpectedly has a secret"
fi
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart (X10)"
assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "no anchor created (X10)"

section "X11: anchor write failure -> config rollback verified"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
# Inject the failure portably: a subshell-scoped write_api_secret_file that
# always fails (MSYS mv would otherwise move the tmp file INTO a directory).
(
    write_api_secret_file() { return 1; }
    maybe_migrate_existing_api_auth < "$(answer_file y)"
) > "$OUTDIR/x11.out" 2>&1
assert_rc 1 $? "migration fails closed on anchor failure"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config rolled back byte-identical (X11)"; else fail "config not restored (X11)"; fi
assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "no restart needed (runtime never left the old config)"
assert_grep '已回滚 config' "$OUTDIR/x11.out" "rollback stated"

section "X12: restart failure -> rollback config + runtime verification"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
export RESTART_FAIL_MODE=first
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x12.out" 2>&1
assert_rc 1 $? "migration fails when the first restart fails"
export RESTART_FAIL_MODE=none
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config restored byte-identical (X12)"; else fail "config not restored (X12)"; fi
assert_rc 0 "$([ -f "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "newly-created anchor removed on rollback"
assert_grep '已回滚到迁移前状态' "$OUTDIR/x12.out" "successful rollback reported"
assert_grep 'restart sing-box' "$SYSTEMCTL_LOG" "rollback restart actually ran"

section "X12b: every restart fails -> MANUAL INTERVENTION, never claims success"
reset_sandbox
write_existing_config
export RESTART_FAIL_MODE=all
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x12b.out" 2>&1
assert_rc 1 $? "migration fails when every restart fails"
export RESTART_FAIL_MODE=none
assert_grep '请立即人工介入' "$OUTDIR/x12b.out" "manual intervention stated"
assert_no_grep '已回滚到迁移前状态' "$OUTDIR/x12b.out" "must NOT claim successful recovery"
assert_rc 1 "$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)" "backups kept for manual recovery"

section "X12c: no-anchor pre-state + anchor removal failure -> MANUAL INTERVENTION"
# The pre-state had NO anchor; rollback must remove the derived file created
# by the migration with a checked rm. A failed removal is escalated (nonzero,
# MANUAL INTERVENTION) and NEVER reported as a successful rollback.
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
export RESTART_FAIL_MODE=all
export RM_FAIL_ANCHOR=1
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x12c.out" 2>&1
assert_rc 1 $? "migration fails when anchor removal fails"
assert_rc 1 "$([ -e "$SB_API_SECRET_FILE" ] || [ -L "$SB_API_SECRET_FILE" ] && echo 1 || echo 0)" "anchor NOT removed (removal refused)"
assert_grep '无法删除迁移新建的 monitor-api.secret' "$OUTDIR/x12c.out" "removal failure escalated to MANUAL INTERVENTION"
assert_no_grep '已回滚到迁移前状态' "$OUTDIR/x12c.out" "never claims successful rollback"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config still restored (anchor failure does not block the config rollback)"; else fail "config not restored (X12c)"; fi
unset RM_FAIL_ANCHOR
export RESTART_FAIL_MODE=none

section "X13: post-restart auth health failure -> rollback verified"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
: > "$SB_API_FAIL"   # correct-secret API call fails after restart
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x13.out" 2>&1
assert_rc 1 $? "migration fails when auth health fails"
if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "config restored byte-identical (X13)"; else fail "config not restored (X13)"; fi
assert_grep '已回滚到迁移前状态' "$OUTDIR/x13.out" "successful rollback reported (X13)"

section "X14: rollback restore failure -> MANUAL INTERVENTION REQUIRED"
reset_sandbox
write_existing_config
export RESTART_FAIL_MODE=all
export MV_FAIL_MODE=restore
maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x14.out" 2>&1
assert_rc 1 $? "migration fails when rollback restore fails"
export RESTART_FAIL_MODE=none
export MV_FAIL_MODE=""
assert_grep '回滚 config 恢复失败，请立即人工介入' "$OUTDIR/x14.out" "restore failure escalated to manual intervention"
assert_no_grep '已回滚到迁移前状态' "$OUTDIR/x14.out" "never claims success"
assert_rc 1 "$(ls -1 "$SANDBOX"/sbconfig_server.json.bak.* 2>/dev/null | wc -l)" "backup preserved (X14)"

section "X15: config.lock unavailable -> zero mutation"
reset_sandbox
write_existing_config
cfg_sha="$(sha "$SB_SERVER_CONFIG")"
holder_pid=""
# Contended-lock semantics are exercised with the REAL flock on Linux/CI
# (same scope as the S7c/T15/T16 regressions); the shim + local FS
# interceptors on dev laptops make the holder race flaky, so skip there.
hold_lock() {
    # Same portable holder pattern as the S0/legacy suites (works with the
    # util-linux flock on Linux/CI and the shim elsewhere).
    SB_LOCK_FILE="$SB_LOCK_FILE" bash -c \
        'exec 9>>"$SB_LOCK_FILE"; flock 9; touch "$SB_LOCK_FILE.held"; command sleep 30' &
    holder_pid=$!
    local i
    for i in $(seq 1 50); do
        [ -f "$SB_LOCK_FILE.held" ] && break
        kill -0 "$holder_pid" 2>/dev/null || break
        command sleep 0.1
    done
    [ -f "$SB_LOCK_FILE.held" ]
}
release_lock() {
    [ -n "$holder_pid" ] && kill "$holder_pid" 2>/dev/null
    wait "$holder_pid" 2>/dev/null
    rm -rf -- "$SB_LOCK_FILE".mocklock.* "$SB_LOCK_FILE.held"
    holder_pid=""
}
if [ "$IS_LINUX" = "1" ] && hold_lock; then
    SB_LOCK_TIMEOUT=1 maybe_migrate_existing_api_auth < "$(answer_file y)" > "$OUTDIR/x15.out" 2>&1
    assert_rc 1 $? "migration fails closed on lock timeout"
    release_lock
    if [ "$cfg_sha" = "$(sha "$SB_SERVER_CONFIG")" ]; then pass "zero mutation on lock timeout (X15)"; else fail "mutated without the lock (X15)"; fi
    assert_rc 0 "$(grep -c 'restart sing-box' "$SYSTEMCTL_LOG")" "zero restart without the lock (X15)"
    assert_grep '配置锁' "$OUTDIR/x15.out" "lock failure reason stated"
else
    release_lock 2>/dev/null
    printf '  SKIP: real-flock contention test runs on Linux CI only\n'
fi

section "X16: concurrent migrations -> one secret, no rotation, one restart"
reset_sandbox
write_existing_config
# Same Linux-CI-only scope as X15: real flock serialization is the contract
# under test, and the MSYS shim/FS interceptors make child races flaky.
if [ "$IS_LINUX" = "1" ]; then
    CONC="$TMP/conc"
    mkdir -p "$CONC"
    cp "$TMP/mocks.sh" "$CONC/mocks.sh"
    cp "$TMP/mock-sb" "$CONC/sing-box"
    chmod +x "$CONC/sing-box"
    cp "$SB_SERVER_CONFIG" "$CONC/sbconfig_server.json"
    cat > "$CONC/child.sh" <<'CHILD'
set -u
ROLE="$1"; DIR="$2"; GO="$3"; BLOCKS="$4"
export SB_SERVER_CONFIG="$DIR/sbconfig_server.json"
export SB_STATE_FILE="$DIR/config"
export SB_CLIENTS_DIR="$DIR/clients"
export SB_SING_BOX_BIN="$DIR/sing-box"
export SB_LOCK_FILE="$DIR/config.lock"
export SB_HOPPING_SERVICE="$DIR/hy2-hopping.service"
export SB_API_SECRET_FILE="$DIR/monitor-api.secret"
export SB_SELF_CERT_KEY="$DIR/self-cert/private.key"
export SB_SELF_CERT_CERT="$DIR/self-cert/cert.pem"
export SYSTEMCTL_LOG="$DIR/systemctl-$ROLE.log"; : > "$SYSTEMCTL_LOG"
export RESTART_COUNT_FILE="$DIR/restart-count-$ROLE"; printf '0\n' > "$RESTART_COUNT_FILE"
info() { :; }; warning() { :; }; hint() { :; }; error() { :; }
. "$DIR/mocks.sh"
. "$BLOCKS"
printf 'y\n' > "$DIR/answer-$ROLE"
while [ ! -f "$GO" ]; do command sleep 0.05; done
maybe_migrate_existing_api_auth < "$DIR/answer-$ROLE"
exit $?
CHILD
    : > "$CONC/go"
    bash "$CONC/child.sh" a "$CONC" "$CONC/go" "$TMP/blocks.sh" > "$CONC/a.log" 2>&1 &
    pid_a=$!
    bash "$CONC/child.sh" b "$CONC" "$CONC/go" "$TMP/blocks.sh" > "$CONC/b.log" 2>&1 &
    pid_b=$!
    for _ in $(seq 1 50); do [ -d "/proc/$pid_a" ] && [ -d "/proc/$pid_b" ] || break; command sleep 0.1; done
    command sleep 1
    : > "$CONC/go"
    wait "$pid_a"; rc_a=$?
    wait "$pid_b"; rc_b=$?
    assert_rc 0 "$rc_a" "concurrent migration child a"
    assert_rc 0 "$rc_b" "concurrent migration child b"
    conc_secret="$(jq -r --arg tag monitor-api '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' "$CONC/sbconfig_server.json" | tr -d '\r')"
    if [[ "$conc_secret" =~ ^[0-9a-f]{64}$ ]]; then pass "exactly one valid secret generated"; else fail "no valid secret after concurrency race"; fi
    if [ "$(tr -d '\r\n' < "$CONC/monitor-api.secret" 2>/dev/null)" = "$conc_secret" ]; then
        pass "anchor matches the single generated secret"
    else
        fail "anchor lost/rotated after concurrency race"
    fi
    total_restarts=$(( $(grep -c 'restart sing-box' "$CONC/systemctl-a.log" 2>/dev/null) + $(grep -c 'restart sing-box' "$CONC/systemctl-b.log" 2>/dev/null) ))
    assert_rc 1 "$total_restarts" "exactly one controlled restart across both invocations"
    printf '%s\n' "$conc_secret" >> "$TMP/secrets.list"
else
    printf '  SKIP concurrency test: runs on Linux CI with real flock only\n'
fi

section "X17: no secret leakage in stdout/stderr/test logs"
leak=0
while IFS= read -r s; do
    [ -n "$s" ] || continue
    if grep -rF -l "$s" "$OUTDIR" >/dev/null 2>&1; then
        fail "secret leaked into captured output"
        leak=1
        break
    fi
done < "$TMP/secrets.list"
[ "$leak" -eq 0 ] && pass "no generated secret appears in any captured stdout/stderr"
if grep -rqE '(^|[^0-9a-f])[0-9a-f]{64}([^0-9a-f]|$)' "$OUTDIR" 2>/dev/null; then
    fail "a 64-hex string leaked into captured output"
else
    pass "no 64-hex string in any captured output"
fi

section "X18: fresh install path remains unchanged"
assert_grep 'monitor_api_secret="\$\(generate_api_secret\)"' "$INSTALL_SH" "fresh install still generates its own secret"
assert_grep '"secret": "\$monitor_api_secret"' "$INSTALL_SH" "fresh install still embeds the secret in the service entry"
assert_grep 'write_api_secret_file "\$monitor_api_secret"' "$INSTALL_SH" "fresh install still writes the derived anchor fail-closed"
if grep -qE '^[[:space:]]*repair_existing_install_security_baseline$' "$INSTALL_SH"; then
    pass "existing-install baseline call unchanged (S0 contract)"
else
    fail "existing-install baseline call was altered"
fi

printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
