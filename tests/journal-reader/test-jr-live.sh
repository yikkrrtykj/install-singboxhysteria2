#!/usr/bin/env bash
# sbox-journal-reader LIVE gates (issue #33 P2, PR-2A) -- Ubuntu matrix only.
#
# Everything here needs REAL systemd + REAL journalctl and therefore runs
# exclusively on the three-baseline compatibility lane under
# SBOX_JR_REQUIRE_LIVE=1: a skipped live gate is a hard FAIL, never a SKIP.
# Contract coverage:
#   L2  C5/T32 tail-cursor telemetry against the real journal: the
#       `^cursor: (\S+)$` extraction works, real cursors pass the SAME
#       opaque validator the reader uses, and the observed cursor length
#       stays under the 4096-byte bound (an ASSUMPTION probe, not a pin).
#   L3  --after-cursor round-trip: journalctl accepts an opaque cursor it
#       never produced itself in this process (no format assumptions).
#   L4  one real Reader cycle against the real journal in throwaway dirs:
#       C1 recipe leaves committed valid + pending/scratch absent, state
#       files are 0600, every ev file validates through the strict schema,
#       and NO raw journal text crosses the exchange boundary.
#   L5  rendered unit template: systemd-analyze verify with the same
#       fail-closed rc contract as the production-unit step in tests.yml
#       (UNRELATED_NOISE allowlist), plus security --offline where the
#       baseline supports it.
# PR-2A DARK: this script touches NO production host, creates no sbox-jr
# identity, installs nothing persistent beyond a disposable runner mock of
# sing-box.service (needed only so After= resolves), and removes it.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/../.." && pwd)"
REQUIRE_LIVE="${SBOX_JR_REQUIRE_LIVE:-0}"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
assert_eq() { [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }

gate() {
    if [ "$REQUIRE_LIVE" = "1" ]; then
        fail "$1 (required LIVE cannot skip)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nSBOX_JR_LIVE=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nSBOX_JR_LIVE=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

printf '===== SBOX-JOURNAL-READER LIVE (PR-2A) =====\n'
[ "$(uname -s 2>/dev/null)" = "Linux" ] || gate 'non-Linux host'
[ -d /run/systemd/system ] || gate 'systemd is not PID 1'
[ "$(id -u)" = "0" ] || gate 'root required for real journal + verify'
[ -n "$PY" ] || gate 'python3 missing'
for tool in journalctl systemd-analyze getent; do
    command -v "$tool" >/dev/null 2>&1 || gate "$tool missing"
done
command -v systemctl >/dev/null 2>&1 || gate 'systemctl missing'

TMP="$(mktemp -d /tmp/sbjr-live.XXXXXX)"
SBX_STUB_CREATED=0
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ "$SBX_STUB_CREATED" = "1" ]; then
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -rf -- "$TMP"
    exit "$rc"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM

# Disposable runner mock so After=sing-box.service resolves in verify; never
# started, never enabled, removed on exit. If a REAL sing-box is present the
# script uses it as-is and removes nothing.
if [ ! -e /etc/systemd/system/sing-box.service ] && ! systemctl list-unit-files sing-box.service --no-legend 2>/dev/null | grep -q sing-box; then
    cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=mock sing-box (sbox-jr live verify only)
[Service]
Type=exec
ExecStart=/bin/sleep infinity
UNIT
    SBX_STUB_CREATED=1
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

export PYTHONPATH="$ROOT/monitor-v2"

# ---------------------------------------------------------------------------
printf -- '--- L2: real tail-cursor telemetry (C5 / T32)\n'
extract_cursor() {
    journalctl "$@" --show-cursor 2>/dev/null \
        | grep -E '^cursor: [^[:space:]]+$' \
        | sed -e 's/^cursor: //' -e 's/[[:space:]]*$//' | tail -n1
}
CURSORS=""
for scope in "-n 0" "-n 0 -u systemd-journald.service"; do
    # shellcheck disable=SC2086
    cur="$(extract_cursor $scope -o json)"
    if [ -z "$cur" ]; then
        fail "tail cursor via 'journalctl $scope --show-cursor' (C5 regex matched nothing)"
        continue
    fi
    "$PY" - "$cur" <<'PYV' && pass "tail cursor passes the opaque validator (D5): $scope" || fail "tail cursor rejected by validator: $scope"
import sys
from journal_reader.cursor import validate_cursor
sys.exit(0 if validate_cursor(sys.argv[1]) else 1)
PYV
    nbytes="$(printf '%s' "$cur" | wc -c | tr -d ' ')"
    if [ "$nbytes" -lt 4096 ]; then
        pass "T32 assumption probe: observed cursor length $nbytes < 4096 bound"
    else
        fail "T32: real cursor hit the 4096-byte bound (length $nbytes) -- validator bound needs review"
    fi
    CURSORS="$CURSORS
$cur"
done

# ---------------------------------------------------------------------------
printf -- '--- L3: --after-cursor accepts the opaque cursor verbatim\n'
FIRST_CUR="$(printf '%s\n' "$CURSORS" | grep -v '^$' | head -n1)"
if [ -z "$FIRST_CUR" ]; then
    fail "no validated cursor available for --after-cursor round-trip"
else
    if journalctl -u systemd-journald.service --after-cursor "$FIRST_CUR" \
        -n 10 --output-format json >/dev/null 2>&1; then
        pass "journalctl accepted the opaque cursor verbatim in --after-cursor (no format assumption)"
    else
        fail "journalctl rejected our own validated cursor in --after-cursor (source contract broken)"
    fi
fi

# ---------------------------------------------------------------------------
printf -- '--- L4: one real Reader cycle against the real journal\n'
SD="$TMP/state"; OD="$TMP/out"; mkdir -p "$SD" "$OD"
CYCLE_LOG="$TMP/cycle.out"; CYCLE_ERR="$TMP/cycle.err"
if ! "$PY" - "$SD" "$OD" >"$CYCLE_LOG" 2>"$CYCLE_ERR" <<'PYC'
import json, os, sys
from journal_reader import state
from journal_reader.reader import Reader
from journal_reader.schema import parse_exchange_text

sd, od = sys.argv[1], sys.argv[2]
rd = Reader(state_dir=sd, out_dir=od, unit="systemd-journald.service")
r1 = rd.run_cycle()
c1 = state.load_committed(sd)
assert c1 is not None and state.validate_committed(c1), "committed missing/invalid after cycle 1"
assert state.load_pending(sd) is None, "pending survived the C1 recipe"
assert not [n for n in os.listdir(sd) if ".tmp-" in n], "scratch leaked into state dir"
assert not [n for n in os.listdir(od) if ".tmp-" in n], "scratch leaked into out dir"
assert oct(os.stat(os.path.join(sd, "committed")).st_mode & 0o777) == "0o600", "committed not 0600"
for name in os.listdir(od):
    if not name.startswith("ev-"):
        continue
    seq = int(name[3:-6])
    body = open(os.path.join(od, name)).read()
    assert parse_exchange_text(body, seq) is None, "real ev file failed strict schema"
    assert '"MESSAGE"' not in body and '"PRIORITY"' not in body, "raw journal field crossed boundary"
r2 = rd.run_cycle()
c2 = state.load_committed(sd)
if r2 == "empty":
    assert c2 == c1, "empty cycle moved committed"
    assert os.path.exists(os.path.join(od, "hb")), "empty cycle skipped heartbeat"
assert r1 in ("committed", "empty") and r2 in ("committed", "empty")
print("cycle1=%s cycle2=%s seq=%s boundary=%s" % (r1, r2, c1["seq"], c1["boundary"]))
PYC
then
    fail "real Reader cycle: $(tail -n 3 "$CYCLE_ERR" | tr '\n' ' ')"
else
    pass "two real cycles completed: $(cat "$CYCLE_LOG")"
    if grep -Eq 'cycle1=(committed|empty) cycle2=(committed|empty)' "$CYCLE_LOG"; then
        pass "cycle results are within the D1 outcome set"
    else
        fail "cycle results outside D1 outcome set"
    fi
    if grep -q 'boundary=' "$CYCLE_LOG"; then
        pass "committed carries the durable D2 boundary field"
    else
        fail "D2 boundary field missing"
    fi
fi

# ---------------------------------------------------------------------------
printf -- '--- L5: rendered unit template passes systemd-analyze\n'
UNIT_IN="$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in"
RENDERED="$TMP/singbox-journal-reader.service"
mkdir -p "$TMP/libexec" "$TMP/data"
cp "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader" "$TMP/libexec/sbox-journal-reader"
chmod 0755 "$TMP/libexec/sbox-journal-reader"
# `bin` is an existing, non-root, resolvable user on every baseline: verify
# can resolve the identity and security --offline scores a non-root service
# (the real install renders sbox-jr, created only by PR-2B activation).
sed -e 's|@SBJR_USER@|bin|g' \
    -e 's|@SBJR_GROUP@|bin|g' \
    -e 's|@SBJR_WATCHED_UNIT@|sing-box.service|g' \
    -e "s|@SBJR_LIBEXEC@|$TMP/libexec|g" \
    -e "s|@SBJR_DATA_ROOT@|$TMP/data|g" \
    "$UNIT_IN" > "$RENDERED"
if grep -q '@SBJR_' "$RENDERED"; then
    fail "rendered unit still contains placeholders"
else
    pass "all five @SBJR_@ placeholders rendered"
fi
vrc=0
systemd-analyze verify "$RENDERED" 2>&1 | tee "$TMP/verify.log" || vrc=$?
if grep -E 'singbox-journal-reader\.service' "$TMP/verify.log" \
   | grep -Eqi 'unknown key|unsupported|not supported|failed|error|not executable|no such file'; then
    fail "systemd rejected or ignored a directive in the reader unit template"
else
    pass "no reader-unit-attributed diagnostics from systemd-analyze verify"
fi
UNRELATED_NOISE_RE='netplan-ovs-cleanup\.service: Failed to open |Unknown key name .RestartMode.|Support for option CPUAccounting= has been removed'
if [ "$vrc" -ne 0 ]; then
    unrelated="$(grep -v 'singbox-journal-reader\.service' "$TMP/verify.log" | grep -Ec "$UNRELATED_NOISE_RE" || true)"
    unclassified="$(grep -v 'singbox-journal-reader\.service' "$TMP/verify.log" \
                     | grep -Ev "$UNRELATED_NOISE_RE" | grep -Ev '^[[:space:]]*$' || true)"
    if [ -n "$unclassified" ]; then
        fail "verify rc=$vrc with UNCLASSIFIED diagnostics (fail-closed): $(printf '%s\n' "$unclassified" | head -n 5)"
    elif [ "$unrelated" -eq 0 ]; then
        fail "verify rc=$vrc with EMPTY diagnostics (fail-closed hard gate)"
    else
        pass "verify rc=$vrc fully classified as unrelated runner-unit noise ($unrelated lines)"
    fi
fi
if systemd-analyze security --help >"$TMP/security-help.log" 2>&1 \
   && grep -q -- '--offline' "$TMP/security-help.log"; then
    if systemd-analyze security --offline=yes "$RENDERED" >"$TMP/security.log" 2>&1; then
        pass "systemd-analyze security --offline accepts the reader unit"
    else
        fail "systemd-analyze security --offline rejected the reader unit: $(tail -n 5 "$TMP/security.log")"
    fi
else
    pass "security --offline unsupported on this baseline; verify is the enforced gate (documented contract)"
fi

# ---------------------------------------------------------------------------
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf 'SBOX_JR_LIVE=FAIL\n'; exit 1
fi
printf 'SBOX_JR_LIVE=PASS\n'; exit 0
