#!/usr/bin/env bash
# sbox-journal-reader LIVE gates (issue #33 P2, PR-2A) -- Ubuntu matrix only.
#
# Everything here needs REAL systemd + REAL journalctl and therefore runs
# exclusively on the three-baseline compatibility lane under
# SBOX_JR_REQUIRE_LIVE=1: a skipped live gate is a hard FAIL, never a SKIP.
# Contract coverage:
#   L2  C5/T32 tail-cursor telemetry against the real journal: the
#       source-verified `-- cursor: <opaque>` framing parses (journalctl
#       prints via "-- cursor:", see journalctl-show.c), real cursors pass
#       the SAME opaque validator the reader uses, and the observed cursor
#       length stays under the 4096-byte bound (an ASSUMPTION probe, not a
#       pin). The cursor value is never echoed into a PASS/FAIL message.
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
#   L6  B9/R7 permission proof: a CI-only DISPOSABLE exact-shape reader
#       identity (sbox-jr: nologin, /nonexistent, primary sbox-jr,
#       supplementary systemd-journal and nothing else) is created on the
#       runner and every journal read -- tail cursor, --after-cursor and a
#       full Reader cycle -- is re-proven THROUGH THAT IDENTITY via
#       runuser. Root journalctl never stands in for this proof; there is
#       no root fallback. The identity is deleted on the spot.
# PR-2A DARK: this script touches NO production host and installs nothing
# persistent: only a disposable runner mock of sing-box.service (needed so
# After= resolves in verify) and the disposable L6 identity are created,
# and both are removed on the spot / at exit.
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
L6_CREATED=0
l6_teardown() {
    if [ "$L6_CREATED" = "1" ]; then
        userdel sbox-jr >/dev/null 2>&1 || true
        groupdel sbox-jr >/dev/null 2>&1 || true
        L6_CREATED=0
    fi
}
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ "$SBX_STUB_CREATED" = "1" ]; then
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    l6_teardown
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
# Source-verified framing (systemd prints '-- cursor: %s'): parse the REAL
# form only here -- the bare 'cursor:' fixture form is exercised offline.
# The cursor value lives in a 0600 file, never in argv/env, and is never
# echoed into a PASS/FAIL message.
extract_cursor() {
    journalctl "$@" --show-cursor 2>/dev/null \
        | grep -E '^-- cursor: [^[:space:]]+$' \
        | sed -e 's/^-- cursor: //' -e 's/[[:space:]]*$//' | tail -n1
}
CURSORS=""
for scope in "-n 0" "-n 0 -u systemd-journald.service"; do
    # shellcheck disable=SC2086
    cur="$(extract_cursor $scope -o json)"
    if [ -z "$cur" ]; then
        fail "tail cursor via 'journalctl $scope --show-cursor' (real '-- cursor:' framing matched nothing)"
        continue
    fi
    CURFILE="$TMP/cur.$$"
    (umask 077; printf '%s' "$cur" > "$CURFILE")
    if "$PY" -c 'import sys
from journal_reader.cursor import validate_cursor
value = open(sys.argv[1]).read()
sys.exit(0 if validate_cursor(value) else 1)' "$CURFILE"; then
        pass "tail cursor passes the opaque validator (D5): $scope"
    else
        fail "tail cursor rejected by validator (D5): $scope"
    fi
    rm -f "$CURFILE"
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
rd.startup()
su, su_ok = state.load_committed(sd)
assert su_ok and su is not None and state.validate_committed(su), \
    "committed missing/invalid after startup"
sp, sp_ok = state.load_pending(sd)
assert sp_ok and sp is None, "pending survived the startup recipe"
r1 = rd.run_cycle()
c1, ok1 = state.load_committed(sd)
assert ok1 and c1 is not None and state.validate_committed(c1), "committed missing/invalid after cycle 1"
p1, p1_ok = state.load_pending(sd)
assert p1_ok and p1 is None, "pending survived the C1 recipe"
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
c2, ok2 = state.load_committed(sd)
assert ok2 and c2 is not None, "committed unreadable after cycle 2"
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
printf -- '--- L6: B9/R7 permission proof via a disposable exact-shape identity\n'
L6_USER="sbox-jr"
L6_GROUP="sbox-jr"
L6_JGROUP="systemd-journal"
L6_OK=1
for tool in runuser useradd usermod groupadd userdel groupdel; do
    command -v "$tool" >/dev/null 2>&1 || { fail "L6 prerequisite missing: $tool"; L6_OK=0; }
done
if [ "$L6_OK" = "1" ]; then
    if getent passwd "$L6_USER" >/dev/null 2>&1; then
        # R7 semantics on the runner itself: an existing divergent identity
        # invalidates this proof -- it is never repaired here, and the
        # shape assertions below catch exactly that.
        if ! getent group "$L6_JGROUP" >/dev/null 2>&1; then
            fail "existing $L6_USER but no $L6_JGROUP group on this baseline"
            L6_OK=0
        fi
    else
        groupadd --system "$L6_GROUP" \
            || fail "groupadd $L6_GROUP failed"
        if useradd --system --gid "$L6_GROUP" --home-dir /nonexistent \
               --no-create-home --shell /usr/sbin/nologin "$L6_USER"; then
            L6_CREATED=1
        else
            fail "useradd $L6_USER failed"
            L6_OK=0
        fi
        if [ "$L6_OK" = "1" ]; then
            usermod -aG "$L6_JGROUP" "$L6_USER" || { fail "usermod -aG failed"; L6_OK=0; }
        fi
    fi
fi
if [ "$L6_OK" = "1" ]; then
    # Exact-shape assertions -- the same rules sbmon_sboxjr_validate_identity
    # enforces before any production mutation.
    L6_PW="$(getent passwd "$L6_USER")"
    L6_SHELL="$(printf '%s\n' "$L6_PW" | cut -d: -f7)"
    L6_HOME="$(printf '%s\n' "$L6_PW" | cut -d: -f6)"
    L6_GID="$(printf '%s\n' "$L6_PW" | cut -d: -f4)"
    L6_PRIM="$(getent group "$L6_GID" | cut -d: -f1)"
    case "$L6_SHELL" in
        /usr/sbin/nologin|/sbin/nologin) pass "L6 identity shell is nologin ($L6_SHELL)" ;;
        *) fail "L6 identity shell not nologin: $L6_SHELL"; L6_OK=0 ;;
    esac
    if [ "$L6_HOME" = "/nonexistent" ]; then
        pass "L6 identity home is /nonexistent"
    else
        fail "L6 identity home not /nonexistent: $L6_HOME"; L6_OK=0
    fi
    if [ "$L6_PRIM" = "$L6_GROUP" ]; then
        pass "L6 identity primary group is $L6_GROUP"
    else
        fail "L6 identity primary group is $L6_PRIM"; L6_OK=0
    fi
    L6_WANT="$(printf '%s\n' "$L6_GROUP" "$L6_JGROUP" | LC_ALL=C sort -u | tr '\n' ' ')"
    L6_GOT="$(id -nG "$L6_USER" | tr ' ' '\n' | grep -v '^$' | LC_ALL=C sort -u | tr '\n' ' ')"
    assert_eq "$L6_WANT" "$L6_GOT" "L6 exact group set (no extras, nothing missing)"
fi
if [ "$L6_OK" = "1" ]; then
    # THE permission proof proper: every read below happens AS sbox-jr
    # through runuser. Root output is never substituted for it.
    L6_TAIL="$(runuser -u "$L6_USER" -- journalctl -n 0 --show-cursor -o json 2>/dev/null \
        | grep -E '^-- cursor: [^[:space:]]+$' | sed -e 's/^-- cursor: //' | tail -n1)"
    if [ -n "$L6_TAIL" ]; then
        pass "tail cursor with real '-- cursor:' framing parses under $L6_USER (C5, no root fallback)"
    else
        fail "$L6_USER could not obtain a tail cursor (permission model not proven)"
        L6_OK=0
    fi
    if [ "$L6_OK" = "1" ]; then
        if runuser -u "$L6_USER" -- journalctl -u systemd-journald.service \
               --after-cursor "$L6_TAIL" -n 10 --output-format json >/dev/null 2>&1; then
            pass "$L6_USER performed an --after-cursor follow read on the real journal"
        else
            fail "$L6_USER --after-cursor read rejected"
        fi
        L6_N="$(runuser -u "$L6_USER" -- journalctl -u systemd-journald.service \
            -n 5 --output-format json 2>/dev/null | grep -c '"__CURSOR"' || true)"
        if [ "${L6_N:-0}" -ge 1 ]; then
            pass "$L6_USER decoded real journal entries (group read, not root)"
        else
            fail "$L6_USER read produced no decodable entries"
        fi
    fi
    # One FULL Reader cycle as the reader identity: C5 source selection,
    # C1 recipe, 0600 state files and the R4 key all under sbox-jr only.
    L6D="$TMP/l6"; SD6="$L6D/state"; OD6="$L6D/out"
    mkdir -p "$SD6" "$OD6"
    chown "$L6_USER:$L6_GROUP" "$L6D" "$SD6" "$OD6"
    chmod 0755 "$L6D"; chmod 0700 "$SD6"; chmod 0750 "$OD6"
    L6_OUT="$TMP/l6.out"; L6_ERR="$TMP/l6.err"
    if runuser -u "$L6_USER" -- env PYTHONPATH="$ROOT/monitor-v2" \
            "$PY" - "$SD6" "$OD6" >"$L6_OUT" 2>"$L6_ERR" <<'PY6'
import os, sys
from journal_reader import state
from journal_reader.fingerprint import load_or_create_key
from journal_reader.reader import Reader

sd, od = sys.argv[1], sys.argv[2]
rd = Reader(state_dir=sd, out_dir=od, unit="systemd-journald.service")
rd.startup()
r = rd.run_cycle()
c, ok = state.load_committed(sd)
assert ok and c is not None and state.validate_committed(c), "committed invalid after L6 cycle"
p, pok = state.load_pending(sd)
assert pok and p is None, "pending survived L6 cycle"
key = load_or_create_key(sd)
assert len(key) == 32, "hmac key not 32 bytes"
assert oct(os.stat(os.path.join(sd, "hmac.key")).st_mode & 0o777) == "0o600", "hmac.key not 0600"
assert oct(os.stat(os.path.join(sd, "committed")).st_mode & 0o777) == "0o600", "committed not 0600"
print("l6cycle=%s seq=%s" % (r, c["seq"]))
PY6
    then
        pass "full Reader cycle ran AS $L6_USER: $(cat "$L6_OUT")"
    else
        fail "Reader cycle under $L6_USER failed: $(tail -n 3 "$L6_ERR" | tr '\n' ' ')"
    fi
    l6_teardown
    if getent passwd "$L6_USER" >/dev/null 2>&1; then
        fail "L6 identity not removed after proof"
    else
        pass "disposable L6 identity removed (no residue on the runner)"
    fi
fi

# ---------------------------------------------------------------------------
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf 'SBOX_JR_LIVE=FAIL\n'; exit 1
fi
printf 'SBOX_JR_LIVE=PASS\n'; exit 0
