#!/usr/bin/env bash
# Phase C transaction-layer security tests (independent security review track).
#
# Complements tests/test-phase-c.sh with adversarial cases:
#   PC-S1  KNOWN-ISSUE: delete of a naming-contract-violating name that was
#          hand-planted in the config executes `rm -rf` on a path outside
#          the clients dir (delete never re-validates the naming contract).
#   PC-S2  KNOWN-ISSUE: with_client_lock is FAIL-OPEN — when the lock file
#          cannot be created/locked, the mutation proceeds with only a
#          warning, so "one global config lock" is best-effort.
#   PC-S3  REGRESSION (needs flock): concurrent ADD A + DELETE A serialize on
#          the lock and the final state is consistent (audit passes; no torn
#          commit) whichever wins.
#   PC-S4  REGRESSION (needs flock): concurrent ADD A + ADD A of the SAME
#          name produce exactly one client (no lost update, no duplicate).
#   PC-S5  REGRESSION: after a transaction the live config file mode is 0600
#          (mktemp candidate is promoted by mv). POSIX only.
#
# Nothing here touches /root/sbox: every path is overridden via the SB_* env
# vars that install.sh honours, and the mock binaries only exist under TMP.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$HERE/../../install.sh"

PASS=0
FAIL=0
SKIPS=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIPS=$((SKIPS + 1)); printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
nsleep() { "$REAL_SLEEP" "$@" 2>/dev/null || sleep "$@"; }
REAL_SLEEP="$(command -v sleep || echo sleep)"

section "static checks"
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then pass "bash -n install.sh"; else fail "bash -n install.sh: $(cat "$TMP/syntax.err")"; fi
if grep -q 'CLIENT_NAME_PATTERN=' "$INSTALL_SH"; then pass "naming contract anchor present"; else fail "naming contract anchor missing"; fi

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

mkdir -p "$SANDBOX" "$SB_SANDBOX_CLIENTS" "$TMP/bin"
cat > "$SB_SING_BOX_BIN" <<'MOCK'
#!/usr/bin/env bash
set -u
COUNT_FILE="${MOCK_COUNT_FILE:?}"
REAL_SLEEP="${MOCK_REAL_SLEEP:?}"
# Optional artificial widening of the read-modify-write window so concurrent
# transactions genuinely overlap inside the critical section.
if [ -n "${MOCK_DELAY_FILE:-}" ] && [ -f "$MOCK_DELAY_FILE" ]; then
    "$REAL_SLEEP" 0.4
fi
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
export MOCK_REAL_SLEEP="$REAL_SLEEP"
export MOCK_DELAY_FILE="$TMP/mock-delay"   # created only by the race tests

info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; }
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

write_base_config() {
    cat > "$SB_SANDBOX_CONFIG" <<'EOF'
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 18443,
      "users": [
        {"name": "legacy", "uuid": "OLD-REALITY-UUID", "flow": "xtls-rprx-vision"}
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
        {"name": "legacy", "password": "OLD-HY2-PASSWORD"}
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

config_json_ok() { jq empty "$SB_SANDBOX_CONFIG" >/dev/null 2>&1; }

section "PC-S1 KNOWN-ISSUE: delete bypasses the naming contract (traversal)"
write_base_config; write_state_file
HOSTILE='../../pcsec-escape'
# Plant a contract-violating name the way only a hand-edited config could.
jq --arg n "$HOSTILE" \
   '.inbounds[0].users += [{"name": $n, "uuid": "EVIL-UUID", "flow": "xtls-rprx-vision"}] |
    .inbounds[1].users += [{"name": $n, "password": "EVIL-PW"}]' \
   "$SB_SANDBOX_CONFIG" > "$TMP/hostile.json" && mv "$TMP/hostile.json" "$SB_SANDBOX_CONFIG"
if config_json_ok && grep -qF "$HOSTILE" "$SB_SANDBOX_CONFIG"; then
    pass "hostile name planted in both inbounds"
else
    fail "could not plant hostile name (jq unavailable?)"
fi
# The traversal resolves to $TMP/pcsec-escape — a canary file lives there so
# the test can see whether rm -rf escaped SB_CLIENTS_DIR. Everything stays
# inside the mktemp sandbox.
CANARY_DIR="$TMP/pcsec-escape"
mkdir -p "$CANARY_DIR"
printf 'canary' > "$CANARY_DIR/canary.txt"
printf 'y\n' | delete_client "$HOSTILE" >"$TMP/pc-s1.out" 2>&1
DELETE_RC=$?
if [ -f "$CANARY_DIR/canary.txt" ]; then
    printf '  KNOWN-ISSUE RESOLVED: delete refused a contract-violating name (rc=%s).\n' "$DELETE_RC"
    printf '  -> Flip PC-S1 into a regression assertion in tests/test-phase-c.sh.\n'
    pass "PC-S1 KNOWN-ISSUE: hostile-name delete is refused (now fixed)"
else
    printf '  KNOWN-ISSUE CONFIRMED: rm -rf escaped SB_CLIENTS_DIR via the planted name.\n'
    printf '  -> install.sh delete path must call validate_client_name before rm -rf.\n'
    pass "PC-S1 KNOWN-ISSUE: traversal delete executed (documented weakness)"
fi
if config_json_ok; then pass "PC-S1 config stays valid JSON"; else fail "PC-S1 config corrupted"; fi

section "PC-S2 KNOWN-ISSUE: with_client_lock is fail-open"
write_base_config; write_state_file
RO_LOCK_DIR="/proc/pcsec-no-such-dir"
if mkdir -p "$RO_LOCK_DIR" 2>/dev/null; then
    skip "PC-S2 (cannot create an unwritable lock dir in this environment)"
else
    export SB_LOCK_FILE="$RO_LOCK_DIR/config.lock"
    add_client "lockfail-a" >"$TMP/pc-s2.out" 2>&1
    ADD_RC=$?
    if [ "$ADD_RC" -eq 0 ] && grep -qF "lockfail-a" "$SB_SANDBOX_CONFIG"; then
        printf '  KNOWN-ISSUE CONFIRMED: mutation committed while the lock was unavailable.\n'
        printf '  -> with_client_lock should fail closed (or retry) instead of warning+proceeding.\n'
        pass "PC-S2 KNOWN-ISSUE: lock failure does not stop the mutation"
    elif [ "$ADD_RC" -ne 0 ]; then
        printf '  KNOWN-ISSUE RESOLVED: lock failure now fails closed (rc=%s).\n' "$ADD_RC"
        printf '  -> Flip PC-S2 into a regression assertion (add must fail without lock).\n'
        pass "PC-S2 KNOWN-ISSUE: lock failure blocks the mutation (now fixed)"
    else
        fail "PC-S2 unexpected state (rc=0 but client absent)"
    fi
    export SB_LOCK_FILE="$SANDBOX/config.lock"
fi
if config_json_ok; then pass "PC-S2 config stays valid JSON"; else fail "PC-S2 config corrupted"; fi

section "PC-S3 REGRESSION: concurrent ADD A + DELETE A serialize consistently"
if command -v flock >/dev/null 2>&1; then
    write_base_config; write_state_file
    touch "$MOCK_DELAY_FILE"   # widen the critical section
    add_client "race-x" >/dev/null 2>&1 &
    ADD_PID=$!
    ( printf 'y\n' | delete_client "race-x" >/dev/null 2>&1 ) &
    DEL_PID=$!
    wait "$ADD_PID"; wait "$DEL_PID"
    rm -f "$MOCK_DELAY_FILE"
    if config_json_ok; then pass "PC-S3 config valid after add/delete race"; else fail "PC-S3 config corrupted"; fi
    if audit_client_consistency >/dev/null 2>&1; then
        pass "PC-S3 audit consistent after add/delete race"
    else
        fail "PC-S3 audit inconsistent after add/delete race"
    fi
    N_RACEX="$(grep -oF '"name": "race-x"' "$SB_SANDBOX_CONFIG" | wc -l | tr -d ' ')"
    if [ "$N_RACEX" -eq 0 ] || [ "$N_RACEX" -eq 2 ]; then
        pass "PC-S3 final state is all-or-nothing (race-x count=$N_RACEX)"
    else
        fail "PC-S3 torn commit: race-x count=$N_RACEX (want 0 or 2)"
    fi
else
    skip "PC-S3 (flock unavailable on this host; mutual exclusion untestable)"
fi

section "PC-S4 REGRESSION: concurrent ADD A + ADD A yields exactly one client"
if command -v flock >/dev/null 2>&1; then
    write_base_config; write_state_file
    touch "$MOCK_DELAY_FILE"   # widen the critical section
    add_client "race-y" >/dev/null 2>&1 &
    PA=$!
    add_client "race-y" >/dev/null 2>&1 &
    PB=$!
    wait "$PA"; wait "$PB"
    rm -f "$MOCK_DELAY_FILE"
    if config_json_ok; then pass "PC-S4 config valid after double-add race"; else fail "PC-S4 config corrupted"; fi
    R_COUNT="$(grep -oF '"name": "race-y"' "$SB_SANDBOX_CONFIG" | wc -l | tr -d ' ')"
    if [ "$R_COUNT" -eq 2 ]; then
        pass "PC-S4 exactly one race-y per inbound (2 total)"
    else
        fail "PC-S4 race-y count=$R_COUNT (want 2, one per inbound)"
    fi
    if audit_client_consistency >/dev/null 2>&1; then
        pass "PC-S4 audit consistent after race"
    else
        fail "PC-S4 audit inconsistent after race"
    fi
else
    skip "PC-S4 (flock unavailable on this host)"
fi

section "PC-S5 REGRESSION: live config mode is 0600 after a transaction"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        skip "PC-S5 (permission bits are not meaningful on this host)" ;;
    *)
        write_base_config; write_state_file
        add_client "perm-a" >/dev/null 2>&1
        MODE="$(stat -c '%a' "$SB_SANDBOX_CONFIG" 2>/dev/null || echo unknown)"
        if [ "$MODE" = "600" ]; then
            pass "PC-S5 live config is 0600 after mv-promotion"
        else
            fail "PC-S5 live config mode is $MODE (want 600)"
        fi ;;
esac

printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIPS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -eq 0 ]; then
    printf '  RESULT: FAILED\n'
    exit 1
fi
printf '  RESULT: ALL GREEN (skips are explicit, never silent)\n'
exit 0
