#!/usr/bin/env bash
# Regression suite: fresh-install Linux TCP BBR/fq default + UDP buffer floor.
#
# HERMETIC BY DEFAULT. install.sh is never sourced as a whole: the marked
# "# >>> network-tuning >>>" block is extracted, sysctl/modprobe are mocked as
# shell functions over a throwaway state directory, and every managed path is
# overridden via NETWORK_SYSCTL_FILE / NETWORK_TUNING_RECORD_ROOT. No real
# kernel setting and no real /etc/sysctl.d file is touched.
#
# OPTIONAL LIVE GATE (Linux, root, DISPOSABLE HOST ONLY):
#   sudo env SB_NET_REQUIRE_LIVE=1 SB_NET_LIVE_DISPOSABLE=1 \
#       bash tests/test-network-tuning.sh
# The live gate applies/rolls back REAL net.ipv4/net.core values and replays
# the persisted boot file. It refuses to run unless the caller explicitly
# confirms a disposable host (SB_NET_LIVE_DISPOSABLE=1) AND the process is
# either a GitHub Actions runner (GITHUB_ACTIONS=true) or carries the explicit
# SB_NET_LIVE_LOCAL_DISPOSABLE=1 confirmation for a throwaway local VM. It
# captures every original value first, restores on success AND on abnormal exit
# (best effort), and CI runs it only on a GitHub-hosted ephemeral runner that is
# destroyed after the job. A network namespace cannot be used for the full gate
# because net.core.default_qdisc is NOT netns-scoped and a fresh netns does not
# expose /proc/sys/net/core/default_qdisc at all. "Ubuntu kernel without BBR"
# cannot be produced on a BBR-capable runner, so that case is covered
# hermetically only; the same is true for write/apply partial-failure
# injection.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
INSTALL_SH="$ROOT/install.sh"
SELF="$HERE/test-network-tuning.sh"

PASS=0
FAIL=0
SKIP=0
TMP="$(mktemp -d)"
LIVE_RESTORE_NEEDED=0
cleanup() {
    if [ "$LIVE_RESTORE_NEEDED" = "1" ] && [ -n "${NET_ORIG_CC:-}" ]; then
        network_restore_state >/dev/null 2>&1 || true
    fi
    rm -rf -- "$TMP"
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() { # <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi
}
assert_eq() { # <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected '$1', got '$2')"; fi
}
assert_file_grep() { # <pattern> <file> <label>
    if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi
}
assert_file_no_grep() {
    if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi
}
assert_exists() { if [ -e "$1" ]; then pass "$2"; else fail "$2 (missing: $1)"; fi; }
assert_missing() { if [ -e "$1" ]; then fail "$2 (unexpected: $1)"; else pass "$2"; fi; }

# ---------------------------------------------------------------------------
section "static checks"
# ---------------------------------------------------------------------------
if bash -n "$INSTALL_SH" 2>"$TMP/install-syntax.err"; then
    pass "bash -n install.sh"
else
    fail "bash -n install.sh: $(cat "$TMP/install-syntax.err")"
fi
if bash -n "$SELF" 2>"$TMP/self-syntax.err"; then
    pass "bash -n tests/test-network-tuning.sh"
else
    fail "bash -n tests/test-network-tuning.sh: $(cat "$TMP/self-syntax.err")"
fi

awk '/^# >>> network-tuning >>>/{flag=1} flag{print} /^# <<< network-tuning <<< /{flag=0}' \
    "$INSTALL_SH" > "$TMP/network.sh"
if grep -q '^network_capture_state() {' "$TMP/network.sh" &&
   grep -q '^apply_fresh_install_network_defaults() {' "$TMP/network.sh"; then
    pass "network-tuning block extracted"
else
    fail "network-tuning block extraction"
fi
for fn in network_sysctl_read read_sysctl_number larger_number network_bbr_available \
          network_tuning_opt_out network_capture_state network_restore_state \
          read_managed_sysctl_value network_unmanaged_file_keys \
          network_warn_if_rewriting_managed_file write_network_sysctl \
          configure_udp_buffers enable_bbr apply_fresh_install_network_defaults \
          apply_udp_buffer_floor_only maybe_apply_fresh_install_network_defaults \
          show_network_tuning_summary; do
    if grep -qE "^${fn}\(\)" "$TMP/network.sh"; then
        pass "function present: $fn"
    else
        fail "function missing from network-tuning block: $fn"
    fi
done

# Every managed path/binary must be injectable, or the suite could not run
# without touching the real host.
for needle in \
    'NETWORK_SYSCTL_FILE="${NETWORK_SYSCTL_FILE:-' \
    'NETWORK_TUNING_RECORD_ROOT="${NETWORK_TUNING_RECORD_ROOT:-' \
    'SYSCTL_BIN="${SYSCTL_BIN:-' \
    'MODPROBE_BIN="${MODPROBE_BIN:-'; do
    if grep -qF "$needle" "$INSTALL_SH"; then
        pass "injectable: $needle"
    else
        fail "missing injectable override: $needle"
    fi
done
if grep -qF 'mkdir -p /etc/sysctl.d' "$INSTALL_SH"; then
    fail "hardcoded /etc/sysctl.d mkdir must be gone"
else
    pass "no hardcoded /etc/sysctl.d mkdir"
fi

# Optional optimization must never be fatal and must never auto-promote TCP
# just because the live congestion control already is bbr.
if grep -q 'error "' "$TMP/network.sh"; then
    fail "network-tuning block must not call fatal error()"
else
    pass "network-tuning block never calls fatal error()"
fi
if grep -q 'current_cc' "$TMP/network.sh"; then
    fail "write path must not auto-promote from the live congestion control"
else
    pass "no cc==bbr auto-promote in the network-tuning block"
fi

assert_eq 1 "$(grep -c '^maybe_apply_fresh_install_network_defaults() {' "$INSTALL_SH")" \
    "exactly one fresh-install gate definition"
assert_eq 1 "$(grep -c '^maybe_apply_fresh_install_network_defaults$' "$INSTALL_SH")" \
    "exactly one fresh-install gate call site"
assert_eq 1 "$(grep -c '^show_network_tuning_summary() {' "$INSTALL_SH")" \
    "exactly one install-summary definition"
assert_eq 1 "$(grep -cE '^[[:space:]]*show_network_tuning_summary$' "$INSTALL_SH")" \
    "exactly one install-summary call site"
assert_eq 1 "$(grep -c '^enable_bbr() {' "$INSTALL_SH")" \
    "menu 5 manual BBR entry point preserved"
assert_eq 1 "$(grep -c '^configure_udp_buffers() {' "$INSTALL_SH")" \
    "configure_udp_buffers preserved as a single definition"
if [ "$(grep -c 'configure_udp_buffers' "$INSTALL_SH")" -ge 3 ]; then
    pass "configure_udp_buffers is reused by the new paths"
else
    fail "configure_udp_buffers is not reused by the new paths"
fi
if awk '/^[[:space:]]*5\)[[:space:]]*$/{getline; print}' "$INSTALL_SH" | grep -q 'enable_bbr'; then
    pass "menu item 5 still calls enable_bbr"
else
    fail "menu item 5 no longer calls enable_bbr"
fi
if grep -A5 '^if has_any_installation_marker; then' "$INSTALL_SH" |
   grep -q 'FRESH_INSTALL="FALSE"'; then
    pass "existing-install/rerun/menu path marks FRESH_INSTALL=FALSE"
else
    fail "existing-install path does not mark FRESH_INSTALL=FALSE"
fi

# Documentation + CI wiring are part of the issue's acceptance criteria.
if grep -qF 'network-tuning.before-install' "$ROOT/docs/hysteria2-bbr.md"; then
    pass "docs describe the captured-state record path"
else
    fail "docs/hysteria2-bbr.md does not document the captured-state record"
fi
if grep -qF 'SB_SKIP_NETWORK_TUNING=1' "$ROOT/docs/hysteria2-bbr.md" &&
   grep -qF 'SB_SKIP_NETWORK_TUNING=1' "$ROOT/README.md"; then
    pass "docs/README document the SB_SKIP_NETWORK_TUNING=1 opt-out value"
else
    fail "documented opt-out value SB_SKIP_NETWORK_TUNING=1 is missing from docs+README"
fi
if grep -qF 'REINSTALL_FALLTHROUGH="TRUE"' "$INSTALL_SH" &&
   [ "$(grep -cF 'REINSTALL_FALLTHROUGH="TRUE"' "$INSTALL_SH")" -eq 1 ]; then
    pass "menu-1 reinstall marks REINSTALL_FALLTHROUGH for UDP-only handling"
else
    fail "menu-1 reinstall does not mark REINSTALL_FALLTHROUGH exactly once"
fi
if grep -qF 'tests/test-network-tuning.sh' "$ROOT/.github/workflows/tests.yml" &&
   grep -qF 'bash -n tests/test-network-tuning.sh' "$ROOT/.github/workflows/tests.yml"; then
    pass "CI registers the suite (bash -n and execution)"
else
    fail "CI does not register tests/test-network-tuning.sh"
fi

# Upgrade/update flows must never call the new default or the manual writer.
if awk '/^update_singbox\(\) \{/,/^}/' "$INSTALL_SH" |
   grep -qE 'write_network_sysctl|enable_bbr|apply_fresh_install_network_defaults|configure_udp_buffers'; then
    fail "update_singbox must not touch the network-tuning paths"
else
    pass "update_singbox does not touch the network-tuning paths"
fi

# ---------------------------------------------------------------------------
section "prepare hermetic sysctl/modprobe mocks"
# ---------------------------------------------------------------------------
MOCK_STATE="$TMP/mock-sysctl"
MOCK_CALLS="$TMP/sysctl-calls.log"
mock_path() { printf '%s/%s' "$MOCK_STATE" "${1//./_}"; }
mock_set() { printf '%s\n' "$2" > "$(mock_path "$1")"; }
mock_get() { cat "$(mock_path "$1")" 2>/dev/null || true; }
mock_reset() {
    rm -rf -- "$MOCK_STATE"
    mkdir -p -- "$MOCK_STATE"
    : > "$MOCK_CALLS"
    mock_set net.ipv4.tcp_congestion_control "${1:-cubic}"
    mock_set net.core.default_qdisc "${2:-fq_codel}"
    mock_set net.core.rmem_max "${3:-212992}"
    mock_set net.core.wmem_max "${4:-212992}"
    mock_set net.ipv4.tcp_available_congestion_control "${5:-reno cubic}"
    SYSCTL_FAIL_KEYS=""
    SYSCTL_P_PARTIAL_KEYS=""
    SYSCTL_P_RC=0
    SYSCTL_READ_FAIL=0
    MODPROBE_RC=0
    MODPROBE_EFFECT=0
}

sysctl() {
    printf 'sysctl %s\n' "$*" >> "$MOCK_CALLS"
    case "${1:-}" in
        -n)
            [ "${SYSCTL_READ_FAIL:-0}" = "1" ] && return 1
            local key="${2:-}" path value
            path="$(mock_path "$key")"
            [ -f "$path" ] || return 1
            value="$(cat "$path")"
            [ -n "$value" ] || return 1
            printf '%s\n' "$value"
            ;;
        -w)
            local pair="${2:-}" key value path
            key="${pair%%=*}"
            value="${pair#*=}"
            [ "$key" != "$pair" ] || return 1
            if [ -n "${SYSCTL_FAIL_KEYS:-}" ]; then
                case " $SYSCTL_FAIL_KEYS " in *" $key "*) return 1 ;; esac
            fi
            path="$(mock_path "$key")"
            [ -d "$MOCK_STATE" ] || return 1
            printf '%s\n' "$value" > "$path" || return 1
            ;;
        -p)
            local file="${2:-}" line key value partial=0
            [ -f "$file" ] || return 1
            while IFS= read -r line; do
                case "$line" in
                    ""|\#*) continue ;;
                esac
                key="$(printf '%s' "$line" | cut -d'=' -f1 | tr -d '[:space:]')"
                value="$(printf '%s' "$line" | cut -d'=' -f2- | tr -d '[:space:]')"
                [ -n "$key" ] || continue
                if [ -n "${SYSCTL_FAIL_KEYS:-}" ]; then
                    case " $SYSCTL_FAIL_KEYS " in *" $key "*) partial=1; continue ;; esac
                fi
                if [ -n "${SYSCTL_P_PARTIAL_KEYS:-}" ]; then
                    case " $SYSCTL_P_PARTIAL_KEYS " in *" $key "*) partial=1; continue ;; esac
                fi
                printf '%s\n' "$value" > "$(mock_path "$key")"
            done < "$file"
            [ "$partial" -eq 0 ] || return 1
            return "${SYSCTL_P_RC:-0}"
            ;;
        *)
            return 1
            ;;
    esac
}

modprobe() {
    printf 'modprobe %s\n' "$*" >> "$MOCK_CALLS"
    if [ "${MODPROBE_EFFECT:-0}" = "1" ]; then
        local current
        current="$(mock_get net.ipv4.tcp_available_congestion_control)"
        case " $current " in
            *" bbr "*) : ;;
            *) mock_set net.ipv4.tcp_available_congestion_control "${current:-reno cubic} bbr" ;;
        esac
    fi
    return "${MODPROBE_RC:-0}"
}

info() { printf '  [info] %s\n' "$*"; }
warning() { printf '  [warn] %s\n' "$*"; }
hint() { printf '  [hint] %s\n' "$*"; }
error() { printf '  [err ] %s\n' "$*"; return 1; }

export NETWORK_SYSCTL_FILE="$TMP/etc/sysctl.d/99-sing-box-network.conf"
export NETWORK_TUNING_RECORD_ROOT="$TMP/sbox"
export SYSCTL_BIN="sysctl"
export MODPROBE_BIN="modprobe"
export FRESH_INSTALL="TRUE"
export SB_SKIP_NETWORK_TUNING="FALSE"
# shellcheck source=/dev/null
. "$TMP/network.sh"

reset_case() { # [cc] [qdisc] [rmem] [wmem] [available]
    mock_reset "${1:-cubic}" "${2:-fq_codel}" "${3:-212992}" "${4:-212992}" "${5:-reno cubic}"
    rm -rf -- "${TMP:?}/sbox" "${TMP:?}/etc"
    FRESH_INSTALL="TRUE"
    SB_SKIP_NETWORK_TUNING="FALSE"
}
record_dir_count() {
    find "$TMP/sbox" -mindepth 1 -maxdepth 1 -type d \
        -name 'network-tuning.before-install.*' 2>/dev/null | wc -l
}
latest_record_dir() {
    find "$TMP/sbox" -mindepth 1 -maxdepth 1 -type d \
        -name 'network-tuning.before-install.*' 2>/dev/null | LC_ALL=C sort | tail -n 1
}

# ---------------------------------------------------------------------------
section "F1 fresh install with BBR support applies BBR/fq/UDP floor"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f1.out" 2>&1
assert_rc 0 $? "fresh apply returns success"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "runtime TCP congestion control becomes bbr"
assert_eq fq "$(mock_get net.core.default_qdisc)" "runtime default qdisc becomes fq"
assert_eq 16777216 "$(mock_get net.core.rmem_max)" "runtime rmem_max raised to the 16 MiB floor"
assert_eq 16777216 "$(mock_get net.core.wmem_max)" "runtime wmem_max raised to the 16 MiB floor"
assert_exists "$NETWORK_SYSCTL_FILE" "managed persistence file written"
assert_file_grep '^net\.core\.rmem_max = 16777216$' "$NETWORK_SYSCTL_FILE" "file persists rmem floor"
assert_file_grep '^net\.core\.wmem_max = 16777216$' "$NETWORK_SYSCTL_FILE" "file persists wmem floor"
assert_file_grep '^net\.core\.default_qdisc = fq$' "$NETWORK_SYSCTL_FILE" "file persists qdisc=fq"
assert_file_grep '^net\.ipv4\.tcp_congestion_control = bbr$' "$NETWORK_SYSCTL_FILE" "file persists TCP bbr"
assert_file_grep 'Linux TCP BBR 已启用并持久化' "$TMP/f1.out" "apply reports the actual TCP state"
assert_file_grep 'UDP 接收缓冲上限' "$TMP/f1.out" "apply reports the UDP buffer state"
assert_eq 1 "$(record_dir_count)" "exactly one captured-state record created"
record="$(latest_record_dir)"
assert_file_grep '^result=applied$' "$record/state" "record result=applied"
assert_file_grep '^file_present=FALSE$' "$record/state" "record file_present=FALSE"
assert_file_grep '^tcp_congestion_control=cubic$' "$record/state" "record captures original cc"
assert_file_grep '^default_qdisc=fq_codel$' "$record/state" "record captures original qdisc"
assert_file_grep '^rmem_max=212992$' "$record/state" "record captures original rmem"
assert_file_grep '^captured_at=' "$record/state" "record has capture timestamp"

# ---------------------------------------------------------------------------
section "F2 larger existing UDP buffers are never lowered"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 67108864 33554432 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f2.out" 2>&1
assert_rc 0 $? "fresh apply with larger buffers returns success"
assert_eq 67108864 "$(mock_get net.core.rmem_max)" "larger runtime rmem_max preserved"
assert_eq 33554432 "$(mock_get net.core.wmem_max)" "larger runtime wmem_max preserved"
assert_file_grep '^net\.core\.rmem_max = 67108864$' "$NETWORK_SYSCTL_FILE" "larger rmem persisted"
assert_file_grep '^net\.core\.wmem_max = 33554432$' "$NETWORK_SYSCTL_FILE" "larger wmem persisted"

# A larger value persisted by an EARLIER managed file also wins over a stale
# low runtime value (fresh install replay / maintenance edge case).
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
mkdir -p -- "$(dirname -- "$NETWORK_SYSCTL_FILE")"
cat > "$NETWORK_SYSCTL_FILE" <<'EOF'
# previously persisted by an operator
net.core.rmem_max = 41943040
net.core.wmem_max = 25165824
EOF
maybe_apply_fresh_install_network_defaults > "$TMP/f2b.out" 2>&1
assert_rc 0 $? "fresh apply over an existing managed file returns success"
assert_eq 41943040 "$(mock_get net.core.rmem_max)" "persisted larger rmem not lowered in the new file"
assert_eq 25165824 "$(mock_get net.core.wmem_max)" "persisted larger wmem not lowered in the new file"
assert_file_grep '^net\.core\.rmem_max = 41943040$' "$NETWORK_SYSCTL_FILE" "new file keeps persisted rmem"
record="$(latest_record_dir)"
assert_exists "$record/99-sing-box-network.conf" "previous managed file captured before mutation"
assert_file_grep '^file_present=TRUE$' "$record/state" "record marks the previous file as present"

# ---------------------------------------------------------------------------
section "F3 kernel without BBR: TCP/qdisc untouched, UDP floor still applied"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic"
MODPROBE_RC=1
maybe_apply_fresh_install_network_defaults > "$TMP/f3.out" 2>&1
assert_rc 0 $? "unsupported BBR still returns success (install continues)"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "unsupported BBR leaves congestion control unchanged"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "unsupported BBR leaves qdisc unchanged"
assert_eq 16777216 "$(mock_get net.core.rmem_max)" "unsupported BBR still applies the UDP rmem floor"
assert_eq 16777216 "$(mock_get net.core.wmem_max)" "unsupported BBR still applies the UDP wmem floor"
assert_file_grep '不支持 TCP BBR' "$TMP/f3.out" "unsupported BBR is reported accurately"
assert_file_no_grep 'tcp_congestion_control' "$NETWORK_SYSCTL_FILE" "unsupported kernel writes no TCP persistence line"
assert_file_no_grep 'default_qdisc' "$NETWORK_SYSCTL_FILE" "unsupported kernel writes no qdisc persistence line"
record="$(latest_record_dir)"
assert_file_grep '^result=skipped-unsupported-bbr$' "$record/state" "record result=skipped-unsupported-bbr"

# Built-in BBR: modprobe fails but the algorithm is already available.
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
MODPROBE_RC=1
maybe_apply_fresh_install_network_defaults > "$TMP/f3b.out" 2>&1
assert_rc 0 $? "built-in BBR path returns success"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "built-in BBR is used when already available"

# Capability list unreadable while BBR is the live algorithm: BBR must NOT be
# misclassified as unsupported (that would drop its persisted BBR line).
reset_case bbr fq 212992 212992 "reno cubic bbr"
rm -f "$(mock_path net.ipv4.tcp_available_congestion_control)"
maybe_apply_fresh_install_network_defaults > "$TMP/f3c.out" 2>&1
assert_rc 0 $? "unreadable capability list with live bbr still succeeds"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "live bbr preserved when capability list is unreadable"
assert_file_grep '^net\.ipv4\.tcp_congestion_control = bbr$' "$NETWORK_SYSCTL_FILE" "persisted bbr line kept when capability list is unreadable"
assert_file_no_grep '不支持 TCP BBR' "$TMP/f3c.out" "live bbr is not misreported as unsupported"

# ---------------------------------------------------------------------------
section "F4 pre-existing BBR and custom qdisc are preserved"
# ---------------------------------------------------------------------------
reset_case bbr cake 212992 212992 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f4.out" 2>&1
assert_rc 0 $? "pre-existing BBR returns success"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "pre-existing BBR stays bbr"
assert_eq cake "$(mock_get net.core.default_qdisc)" "custom qdisc cake is not replaced by fq"
assert_file_no_grep 'default_qdisc' "$NETWORK_SYSCTL_FILE" "custom qdisc is not persisted as fq"
assert_file_grep '^net\.ipv4\.tcp_congestion_control = bbr$' "$NETWORK_SYSCTL_FILE" "pre-existing BBR is persisted"
assert_file_grep '自定义 qdisc=cake' "$TMP/f4.out" "preserved custom qdisc is reported"
record="$(latest_record_dir)"
assert_file_grep '^result=already-enabled$' "$record/state" "record result=already-enabled"

reset_case bbr fq 212992 212992 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f4b.out" 2>&1
assert_rc 0 $? "pre-existing BBR+fq is idempotent"
assert_eq fq "$(mock_get net.core.default_qdisc)" "pre-existing fq stays fq"
assert_file_grep '^net\.core\.default_qdisc = fq$' "$NETWORK_SYSCTL_FILE" "qdisc fq persisted"
record="$(latest_record_dir)"
assert_file_grep '^result=already-enabled$' "$record/state" "pre-existing BBR+fq result=already-enabled"

# ---------------------------------------------------------------------------
section "F5 partial apply failure restores runtime and persistence"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SYSCTL_P_PARTIAL_KEYS="net.ipv4.tcp_congestion_control"
maybe_apply_fresh_install_network_defaults > "$TMP/f5.out" 2>&1
assert_rc 0 $? "partial sysctl apply is non-fatal (install continues)"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "partial failure restores original congestion control"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "partial failure restores original qdisc"
assert_eq 212992 "$(mock_get net.core.rmem_max)" "partial failure restores original rmem"
assert_eq 212992 "$(mock_get net.core.wmem_max)" "partial failure restores original wmem"
assert_missing "$NETWORK_SYSCTL_FILE" "partial failure removes the managed file it created"
assert_file_grep '已自动恢复安装前' "$TMP/f5.out" "partial failure reports the rollback"
record="$(latest_record_dir)"
assert_file_grep '^result=rolled-back$' "$record/state" "record result=rolled-back"

# sysctl -p hard failure (permission/denied) takes the same rollback path.
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SYSCTL_P_RC=1
maybe_apply_fresh_install_network_defaults > "$TMP/f5b.out" 2>&1
assert_rc 0 $? "sysctl -p failure is non-fatal"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "sysctl -p failure restores original cc"
assert_missing "$NETWORK_SYSCTL_FILE" "sysctl -p failure removes the managed file it created"

# An EXISTING managed file must be restored byte-for-byte on failure.
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
mkdir -p -- "$(dirname -- "$NETWORK_SYSCTL_FILE")"
cat > "$NETWORK_SYSCTL_FILE" <<'EOF'
# handled by the operator
net.core.rmem_max = 33554432
net.ipv4.tcp_congestion_control = cubic
EOF
cp -a "$NETWORK_SYSCTL_FILE" "$TMP/f5-original.conf"
SYSCTL_P_RC=1
maybe_apply_fresh_install_network_defaults > "$TMP/f5c.out" 2>&1
assert_rc 0 $? "rollback over an existing managed file is non-fatal"
if cmp -s "$TMP/f5-original.conf" "$NETWORK_SYSCTL_FILE"; then
    pass "existing managed file restored byte-for-byte after failure"
else
    fail "existing managed file was not restored exactly"
fi
assert_eq 212992 "$(mock_get net.core.rmem_max)" "failed apply restores the original runtime buffer value"
assert_file_grep '^net\.core\.rmem_max = 33554432$' "$NETWORK_SYSCTL_FILE" "restored file keeps the previously persisted larger buffer"

# ---------------------------------------------------------------------------
section "F5d incomplete rollback is reported truthfully (never as success)"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SYSCTL_P_RC=1
SYSCTL_FAIL_KEYS="net.ipv4.tcp_congestion_control net.core.default_qdisc net.core.rmem_max net.core.wmem_max"
maybe_apply_fresh_install_network_defaults > "$TMP/f5d.out" 2>&1
assert_rc 0 $? "unrecoverable rollback is still non-fatal"
assert_file_grep '回滚未完全成功' "$TMP/f5d.out" "manual-recovery warning is emitted"
assert_file_grep 'sysctl -w net.ipv4.tcp_congestion_control=' "$TMP/f5d.out" "manual-recovery command is printed"
record="$(latest_record_dir)"
assert_file_grep '^result=rollback-incomplete$' "$record/state" "record result=rollback-incomplete"
show_network_tuning_summary > "$TMP/f5d.summary" 2>&1
assert_file_grep '回滚未完成' "$TMP/f5d.summary" "install summary reports incomplete rollback"
assert_file_no_grep '已自动恢复安装前' "$TMP/f5d.summary" "install summary does not claim a successful rollback"

# ---------------------------------------------------------------------------
section "F5e rewriting the managed file never drops unrelated lines silently"
# ---------------------------------------------------------------------------
reset_case bbr cake 212992 212992 "reno cubic bbr"
mkdir -p -- "$(dirname -- "$NETWORK_SYSCTL_FILE")"
cat > "$NETWORK_SYSCTL_FILE" <<'EOF'
kernel.sched_autogroup_enabled = 1
net.core.default_qdisc = cake
net.core.rmem_max = 33554432
EOF
cp -a "$NETWORK_SYSCTL_FILE" "$TMP/f5e-original.conf"
maybe_apply_fresh_install_network_defaults > "$TMP/f5e.out" 2>&1
assert_rc 0 $? "apply over a file with unmanaged lines succeeds"
assert_file_grep '不管理的配置行' "$TMP/f5e.out" "unmanaged lines are reported before rewrite"
assert_file_grep 'kernel.sched_autogroup_enabled' "$TMP/f5e.out" "discarded unmanaged key is named"
assert_file_grep 'net.core.default_qdisc=cake 不再由本次写入保留' "$TMP/f5e.out" "dropped persisted custom qdisc is reported"
record="$(latest_record_dir)"
if cmp -s "$TMP/f5e-original.conf" "$record/99-sing-box-network.conf"; then
    pass "exact previous managed file is recoverable from the record"
else
    fail "record does not preserve the exact previous managed file"
fi

# ---------------------------------------------------------------------------
section "F6 unwritable persistence path still keeps the installer alive"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
mkdir -p -- "$TMP/etc"
: > "$TMP/etc/sysctl.d" # parent of the managed file is a regular file
maybe_apply_fresh_install_network_defaults > "$TMP/f6.out" 2>&1
assert_rc 0 $? "persistence write failure does not abort the installer"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "persistence failure restores original cc"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "persistence failure restores original qdisc"
assert_missing "$NETWORK_SYSCTL_FILE" "persistence failure leaves no managed file behind"
record="$(latest_record_dir)"
assert_file_grep '^result=rolled-back$' "$record/state" "persistence failure record result=rolled-back"

# ---------------------------------------------------------------------------
section "F7 capture failure / opt-out never touch sysctl"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SYSCTL_READ_FAIL=1
maybe_apply_fresh_install_network_defaults > "$TMP/f7.out" 2>&1
assert_rc 0 $? "capture failure is non-fatal"
assert_missing "$NETWORK_SYSCTL_FILE" "capture failure writes no persistence file"
assert_file_grep '无法读取当前网络参数' "$TMP/f7.out" "capture failure is reported"
assert_eq 0 "$(record_dir_count)" "capture failure records nothing (no state could be captured)"

reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SB_SKIP_NETWORK_TUNING="1"
maybe_apply_fresh_install_network_defaults > "$TMP/f7b.out" 2>&1
assert_rc 0 $? "documented opt-out value 1 is non-fatal"
assert_missing "$NETWORK_SYSCTL_FILE" "opt-out=1 writes no persistence file"
assert_eq "" "$(cat "$MOCK_CALLS")" "opt-out=1 makes no sysctl/modprobe call"
assert_file_grep 'SB_SKIP_NETWORK_TUNING' "$TMP/f7b.out" "opt-out=1 is reported"
SB_SKIP_NETWORK_TUNING="FALSE"

reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SB_SKIP_NETWORK_TUNING="TRUE"
maybe_apply_fresh_install_network_defaults > "$TMP/f7c.out" 2>&1
assert_rc 0 $? "legacy opt-out value TRUE is accepted"
assert_missing "$NETWORK_SYSCTL_FILE" "opt-out=TRUE writes no persistence file"
assert_eq "" "$(cat "$MOCK_CALLS")" "opt-out=TRUE makes no sysctl/modprobe call"
SB_SKIP_NETWORK_TUNING="FALSE"

# ---------------------------------------------------------------------------
section "F8 non-fresh rerun/update/reinstall never migrates TCP/qdisc"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
FRESH_INSTALL="FALSE"
maybe_apply_fresh_install_network_defaults > "$TMP/f8.out" 2>&1
assert_rc 0 $? "non-fresh skip returns success"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "non-fresh skip leaves cc unchanged"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "non-fresh skip leaves qdisc unchanged"
assert_missing "$NETWORK_SYSCTL_FILE" "non-fresh skip writes no persistence file"
assert_eq "" "$(cat "$MOCK_CALLS")" "non-fresh skip makes no sysctl/modprobe call"
assert_file_grep '非全新安装' "$TMP/f8.out" "non-fresh skip is reported"
FRESH_INSTALL="TRUE"

# Menu-1 reinstall falls through to the fresh-install code after uninstalling.
# It must still guarantee the UDP floor, but must never touch TCP/qdisc.
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
FRESH_INSTALL="FALSE"
export REINSTALL_FALLTHROUGH="TRUE"
maybe_apply_fresh_install_network_defaults > "$TMP/f8b.out" 2>&1
assert_rc 0 $? "menu-1 reinstall UDP-only path returns success"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "reinstall keeps congestion control unchanged"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "reinstall keeps qdisc unchanged"
assert_eq 16777216 "$(mock_get net.core.rmem_max)" "reinstall still applies the UDP floor"
assert_file_grep '重新安装' "$TMP/f8b.out" "reinstall path is reported"
assert_file_no_grep 'tcp_congestion_control' "$NETWORK_SYSCTL_FILE" "reinstall writes no TCP persistence line"
assert_file_no_grep 'default_qdisc' "$NETWORK_SYSCTL_FILE" "reinstall writes no qdisc persistence line"
record="$(latest_record_dir)"
assert_file_grep '^result=udp-floor-applied$' "$record/state" "reinstall record result=udp-floor-applied"
export REINSTALL_FALLTHROUGH="FALSE"
FRESH_INSTALL="TRUE"

# ---------------------------------------------------------------------------
section "F9 repeated fresh apply is idempotent and creates unique records"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f9a.out" 2>&1
assert_rc 0 $? "first fresh apply succeeds"
first_sha="$(sha256sum "$NETWORK_SYSCTL_FILE" | awk '{print $1}')"
maybe_apply_fresh_install_network_defaults > "$TMP/f9b.out" 2>&1
assert_rc 0 $? "second fresh apply succeeds"
second_sha="$(sha256sum "$NETWORK_SYSCTL_FILE" | awk '{print $1}')"
assert_eq "$first_sha" "$second_sha" "repeated apply produces byte-identical persistence file"
assert_eq 1 "$(grep -c 'tcp_congestion_control = bbr' "$NETWORK_SYSCTL_FILE")" "no duplicated TCP line"
assert_eq 2 "$(record_dir_count)" "each apply gets its own timestamped captured-state record"
assert_file_no_grep '已自动恢复安装前' "$TMP/f9b.out" "idempotent second apply does not roll back"

# ---------------------------------------------------------------------------
section "F10 menu 5 manual BBR entry point (enable_bbr)"
# ---------------------------------------------------------------------------
reset_case cubic cake 212992 212992 "reno cubic bbr"
enable_bbr > "$TMP/f10.out" 2>&1
assert_rc 0 $? "menu 5 enable_bbr succeeds with BBR available"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "menu 5 enables TCP bbr"
assert_eq cake "$(mock_get net.core.default_qdisc)" "menu 5 preserves a custom qdisc"
assert_file_no_grep 'default_qdisc' "$NETWORK_SYSCTL_FILE" "menu 5 does not persist fq over a custom qdisc"
assert_file_grep '自定义 qdisc=cake' "$TMP/f10.out" "menu 5 reports the preserved qdisc"
assert_file_grep '安装前网络参数已记录' "$TMP/f10.out" "menu 5 points at the captured-state record"

reset_case cubic fq_codel 212992 212992 "reno cubic"
MODPROBE_RC=1
enable_bbr > "$TMP/f10b.out" 2>&1
assert_rc 1 $? "menu 5 reports BBR unsupported with rc=1"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "unsupported menu 5 leaves cc unchanged"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "unsupported menu 5 leaves qdisc unchanged"
assert_eq 16777216 "$(mock_get net.core.rmem_max)" "unsupported menu 5 still applies the UDP floor"
assert_file_grep '不支持 TCP BBR' "$TMP/f10b.out" "unsupported menu 5 is reported"

reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
SYSCTL_P_RC=1
enable_bbr > "$TMP/f10c.out" 2>&1
assert_rc 1 $? "menu 5 apply failure returns rc=1"
assert_eq cubic "$(mock_get net.ipv4.tcp_congestion_control)" "menu 5 failure restores original cc"
assert_eq fq_codel "$(mock_get net.core.default_qdisc)" "menu 5 failure restores original qdisc"
assert_missing "$NETWORK_SYSCTL_FILE" "menu 5 failure removes the managed file it created"

# ---------------------------------------------------------------------------
section "F11 reboot persistence is replayed from the managed file"
# ---------------------------------------------------------------------------
reset_case cubic fq_codel 212992 212992 "reno cubic bbr"
maybe_apply_fresh_install_network_defaults > "$TMP/f11a.out" 2>&1
assert_rc 0 $? "persistence setup apply succeeds"
assert_file_grep '^net\.ipv4\.tcp_congestion_control = bbr$' "$NETWORK_SYSCTL_FILE" "managed file contains bbr for boot replay"
# Simulate a reboot: the kernel comes back with distro defaults, then the boot
# sysctl service replays the managed file.
mock_set net.ipv4.tcp_congestion_control cubic
mock_set net.core.default_qdisc fq_codel
mock_set net.core.rmem_max 212992
mock_set net.core.wmem_max 212992
sysctl -p "$NETWORK_SYSCTL_FILE" >/dev/null 2>&1
assert_rc 0 $? "managed file replays successfully"
assert_eq bbr "$(mock_get net.ipv4.tcp_congestion_control)" "replay restores bbr after simulated reboot"
assert_eq fq "$(mock_get net.core.default_qdisc)" "replay restores fq after simulated reboot"
assert_eq 16777216 "$(mock_get net.core.rmem_max)" "replay restores the UDP floor after simulated reboot"

# ---------------------------------------------------------------------------
section "LIVE gate: real kernel on an explicitly disposable host"
# ---------------------------------------------------------------------------
if [ "${SB_NET_REQUIRE_LIVE:-0}" != "1" ]; then
    skip "live kernel gate not requested (set SB_NET_REQUIRE_LIVE=1 on an explicitly disposable host)"
elif [ "$(uname -s)" != "Linux" ]; then
    fail "live gate requested on a non-Linux host"
elif [ "$(id -u)" != "0" ]; then
    fail "live gate requested without root"
elif [ "${SB_NET_LIVE_DISPOSABLE:-0}" != "1" ]; then
    fail "refusing live sysctl writes: only an explicitly disposable host may be modified (SB_NET_LIVE_DISPOSABLE=1 required)"
elif [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "${SB_NET_LIVE_LOCAL_DISPOSABLE:-0}" != "1" ]; then
    fail "refusing live sysctl writes outside CI: set GITHUB_ACTIONS=true (CI runner) or SB_NET_LIVE_LOCAL_DISPOSABLE=1 (throwaway local VM only)"
else
    unset -f sysctl modprobe
    export NETWORK_SYSCTL_FILE="$TMP/live/sysctl.d/99-sing-box-network.conf"
    export NETWORK_TUNING_RECORD_ROOT="$TMP/live-sbox"
    SYSCTL_BIN="$(command -v sysctl || true)"
    if [ -z "$SYSCTL_BIN" ]; then
        for candidate in /usr/sbin/sysctl /sbin/sysctl /usr/bin/sysctl; do
            if [ -x "$candidate" ]; then SYSCTL_BIN="$candidate"; break; fi
        done
    fi
    export SYSCTL_BIN
    if command -v modprobe >/dev/null 2>&1; then
        MODPROBE_BIN="$(command -v modprobe)"
    else
        MODPROBE_BIN="modprobe"
    fi
    export MODPROBE_BIN
    export FRESH_INSTALL="TRUE"
    export SB_SKIP_NETWORK_TUNING="FALSE"
    # shellcheck source=/dev/null
    . "$TMP/network.sh"

    printf '  [live] sysctl=%q kernel=%q uid=%q\n' "$SYSCTL_BIN" "$(uname -r)" "$(id -u)"
    printf '  [live] raw cc rc=%s out=%q\n' \
        "$("$SYSCTL_BIN" -n net.ipv4.tcp_congestion_control >/dev/null 2>&1; echo $?)" \
        "$("$SYSCTL_BIN" -n net.ipv4.tcp_congestion_control 2>&1)"
    printf '  [live] raw qdisc rc=%s out=%q\n' \
        "$("$SYSCTL_BIN" -n net.core.default_qdisc >/dev/null 2>&1; echo $?)" \
        "$("$SYSCTL_BIN" -n net.core.default_qdisc 2>&1)"

    live_orig_cc="$(network_sysctl_read net.ipv4.tcp_congestion_control || true)"
    live_orig_qdisc="$(network_sysctl_read net.core.default_qdisc || true)"
    live_orig_rmem="$(network_sysctl_read net.core.rmem_max || true)"
    live_orig_wmem="$(network_sysctl_read net.core.wmem_max || true)"
    if [ -z "$live_orig_cc" ] || [ -z "$live_orig_qdisc" ]; then
        fail "live gate could not read the real sysctl state (cc='$live_orig_cc' qdisc='$live_orig_qdisc' rmem='$live_orig_rmem' wmem='$live_orig_wmem')"
    else
        LIVE_RESTORE_NEEDED=1
        maybe_apply_fresh_install_network_defaults > "$TMP/live-apply.out" 2>&1
        assert_rc 0 $? "live apply returns success"
        # The apply itself loads tcp_bbr, so the capability list must be
        # re-read AFTER the apply; the pre-apply list does not include a
        # not-yet-loaded module.
        live_available_after="$(network_sysctl_read net.ipv4.tcp_available_congestion_control || true)"
        if printf '%s\n' "$live_available_after" | grep -qw bbr; then
            pass "live kernel advertises TCP BBR after the module load"
            assert_eq bbr "$(network_sysctl_read net.ipv4.tcp_congestion_control)" "live runtime cc is bbr"
            if network_qdisc_replaceable "$live_orig_qdisc"; then
                assert_eq fq "$(network_sysctl_read net.core.default_qdisc)" "live runtime default qdisc is fq"
            else
                assert_eq "$live_orig_qdisc" "$(network_sysctl_read net.core.default_qdisc)" "live custom qdisc preserved"
            fi
            live_rmem="$(network_sysctl_read net.core.rmem_max)"
            live_wmem="$(network_sysctl_read net.core.wmem_max)"
            if [ "${live_rmem:-0}" -ge 16777216 ] && [ "${live_wmem:-0}" -ge 16777216 ]; then
                pass "live UDP buffers are at least 16 MiB"
            else
                fail "live UDP buffers below 16 MiB (rmem=$live_rmem wmem=$live_wmem)"
            fi
            assert_exists "$NETWORK_SYSCTL_FILE" "live managed persistence file exists"
            assert_file_grep '^net\.ipv4\.tcp_congestion_control = bbr$' "$NETWORK_SYSCTL_FILE" "live file persists bbr"
            network_restore_state > "$TMP/live-restore.out" 2>&1
            assert_rc 0 $? "live rollback restores the original state"
            assert_eq "$live_orig_cc" "$(network_sysctl_read net.ipv4.tcp_congestion_control)" "live rollback restores original cc"
            assert_eq "$live_orig_qdisc" "$(network_sysctl_read net.core.default_qdisc)" "live rollback restores original qdisc"
            assert_eq "$live_orig_rmem" "$(network_sysctl_read net.core.rmem_max)" "live rollback restores original rmem"
            assert_eq "$live_orig_wmem" "$(network_sysctl_read net.core.wmem_max)" "live rollback restores original wmem"
            assert_missing "$NETWORK_SYSCTL_FILE" "live rollback removes the file it created"
            LIVE_RESTORE_NEEDED=0
            # Re-apply, then simulate a reboot and replay the persistence file.
            maybe_apply_fresh_install_network_defaults > "$TMP/live-reapply.out" 2>&1
            assert_rc 0 $? "live re-apply succeeds"
            LIVE_RESTORE_NEEDED=1
            "$SYSCTL_BIN" -w "net.ipv4.tcp_congestion_control=$live_orig_cc" >/dev/null 2>&1
            "$SYSCTL_BIN" -w "net.core.default_qdisc=$live_orig_qdisc" >/dev/null 2>&1
            "$SYSCTL_BIN" -w "net.core.rmem_max=$live_orig_rmem" >/dev/null 2>&1
            "$SYSCTL_BIN" -w "net.core.wmem_max=$live_orig_wmem" >/dev/null 2>&1
            "$SYSCTL_BIN" -p "$NETWORK_SYSCTL_FILE" >/dev/null 2>&1
            assert_rc 0 $? "live persistence replay succeeds"
            assert_eq bbr "$(network_sysctl_read net.ipv4.tcp_congestion_control)" "live replay restores bbr"
            live_expected_rmem="$live_orig_rmem"
            [ "${live_expected_rmem:-0}" -lt 16777216 ] && live_expected_rmem=16777216
            assert_eq "$live_expected_rmem" "$(network_sysctl_read net.core.rmem_max)" "live replay restores the expected UDP floor"
        else
            pass "live kernel does not advertise BBR even after the module load (unsupported-kernel live path)"
            assert_eq "$live_orig_cc" "$(network_sysctl_read net.ipv4.tcp_congestion_control)" "live unsupported path leaves cc unchanged"
            assert_eq "$live_orig_qdisc" "$(network_sysctl_read net.core.default_qdisc)" "live unsupported path leaves qdisc unchanged"
            live_rmem="$(network_sysctl_read net.core.rmem_max)"
            if [ "${live_rmem:-0}" -ge 16777216 ]; then
                pass "live unsupported path still applies the UDP floor"
            else
                fail "live unsupported path did not apply the UDP floor"
            fi
        fi
    fi
    if [ "$LIVE_RESTORE_NEEDED" = "1" ]; then
        network_restore_state > "$TMP/live-final-restore.out" 2>&1 || true
        LIVE_RESTORE_NEEDED=0
    fi
    rm -rf -- "$TMP/live" "$TMP/live-sbox"
fi

printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
