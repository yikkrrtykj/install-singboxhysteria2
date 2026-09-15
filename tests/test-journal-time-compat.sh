#!/usr/bin/env bash
# Journal time compatibility regression tests (Ubuntu 22.04/24.04/26.04).
#
# Real VPS canary finding (Ubuntu 22.04, 2026-09-14): journalctl --since
# rejected the raw RFC3339 timestamp 2026-09-14T15:51:50Z. The canonical
# fix is tests/lib/journal-time.sh: internal canary timestamps stay
# RFC3339/UTC; they are normalized to local "YYYY-MM-DD HH:MM:SS" with
# Python datetime BEFORE journalctl --since ever sees them.
#
# These tests run against the default python3 of the platform (CI matrix
# covers each supported Ubuntu LTS default interpreter) and never invoke
# journalctl itself.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/journal-time.sh
source "$HERE/lib/journal-time.sh"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

assert_eq() { # assert_eq <want> <got> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$1', got '$2')"; fi
}
assert_rc() { # assert_rc <expected-nonzero:0/1> <rc> <label>
    if [ "$1" = 0 ] && [ "$2" = 0 ]; then pass "$3"; return; fi
    if [ "$1" != 0 ] && [ "$2" != 0 ]; then pass "$3"; return; fi
    fail "$3 (expected rc-$( [ "$1" = 0 ] && echo zero || echo nonzero ), got rc=$2)"
}

# TZ-dependent cases only run where the TZ environment variable actually
# drives timezone resolution for that zone. The probe uses GNU date as an
# INDEPENDENT implementation (not the Python code under test); on platforms
# without tzdata (e.g. Windows) the named-zone cases are skipped with a
# banner instead of failing. Expected offsets are the fixed zone rules for
# the 2026-09-14T15:51:50Z instant (September = EDT, -0400).
tz_instant_ok() { # tz_instant_ok <zone> <expected-offset>
    local z
    # NO -u here: `date -u` would display in UTC and +%z would always be
    # +0000, making every named-zone probe fail (SKIP on Linux CI). Without
    # -u, TZ drives the display offset and the probe really checks that the
    # zone resolves on this platform.
    z="$(TZ="$1" date -d '2026-09-14 15:51:50 UTC' +%z 2>/dev/null || true)"
    [ "$z" = "$2" ]
}

section "raw RFC3339 UTC -> normalized (the exact VPS canary failure input)"
if tz_instant_ok UTC +0000; then
    out="$(TZ=UTC journal_time_normalize_jctl '2026-09-14T15:51:50Z')"
    assert_eq '2026-09-14 15:51:50' "$out" "TZ=UTC: 2026-09-14T15:51:50Z -> 2026-09-14 15:51:50"

    out="$(TZ=UTC journal_time_normalize_jctl '2026-09-14T15:51:50.250Z')"
    assert_eq '2026-09-14 15:51:50' "$out" "TZ=UTC: fractional seconds accepted"

    out="$(TZ=UTC journal_time_normalize_jctl '2026-09-14T23:51:50+08:00')"
    assert_eq '2026-09-14 15:51:50' "$out" "TZ=UTC: explicit +08:00 offset converted"
else
    printf '  SKIP TZ=UTC cases (TZ not honored on this platform)\n'
fi

if tz_instant_ok Asia/Shanghai +0800; then
    out="$(TZ=Asia/Shanghai journal_time_normalize_jctl '2026-09-14T15:51:50Z')"
    assert_eq '2026-09-14 23:51:50' "$out" "TZ=Asia/Shanghai: UTC 15:51:50 -> local 23:51:50"
else
    printf '  SKIP TZ=Asia/Shanghai case (tzdata zone not resolvable on this platform)\n'
fi

if tz_instant_ok America/New_York -0400; then
    out="$(TZ=America/New_York journal_time_normalize_jctl '2026-09-14T15:51:50Z')"
    assert_eq '2026-09-14 11:51:50' "$out" "TZ=America/New_York: UTC 15:51:50 -> local 11:51:50 (DST)"
else
    printf '  SKIP TZ=America/New_York case (tzdata zone not resolvable on this platform)\n'
fi

section "output shape: journalctl never receives raw RFC3339"
out="$(TZ=UTC journal_time_normalize_jctl '2026-09-14T15:51:50Z' 2>/dev/null)" || out="__rc_fail__"
if [ "$out" != "__rc_fail__" ]; then
    case "$out" in
        *T*|*Z*) fail "output still contains RFC3339 markers: $out" ;;
        *)       pass "output has no 'T'/'Z' RFC3339 markers" ;;
    esac
    assert_eq '19' "${#out}" "output shape is 'YYYY-MM-DD HH:MM:SS'"
else
    fail "normalization unexpectedly failed"
fi

section "idempotence: already-normalized input passes through unchanged"
out="$(TZ=UTC journal_time_normalize_jctl '2026-09-14 15:51:50')"
assert_eq '2026-09-14 15:51:50' "$out" "normalized input passthrough"
again="$(TZ=UTC journal_time_normalize_jctl "$out")"
assert_eq "$out" "$again" "normalize(normalize(x)) == normalize(x)"

section "fail-closed diagnostics on invalid input"
journal_time_normalize_jctl '' >/dev/null 2>&1;        assert_rc 1 $? "empty input rejected"
journal_time_normalize_jctl '   ' >/dev/null 2>&1;     assert_rc 1 $? "whitespace-only input rejected"
journal_time_normalize_jctl 'not-a-time' >/dev/null 2>&1; assert_rc 1 $? "garbage input rejected"
journal_time_normalize_jctl '2026-09-14' >/dev/null 2>&1; assert_rc 1 $? "bare date (no time) rejected"
journal_time_normalize_jctl '2026-13-40T99:99:99Z' >/dev/null 2>&1; assert_rc 1 $? "out-of-range RFC3339 rejected"
journal_time_normalize_jctl '2026-09-14 25:00:00' >/dev/null 2>&1; assert_rc 1 $? "invalid wall-clock rejected"

err="$(journal_time_normalize_jctl '2026-09-14T15:51:50Z' 2>&1 >/dev/null)"
if [ -z "${SBMON_PYTHON3:-}" ]; then
    # no python override: the happy path's stderr must be empty
    if [ -z "$err" ]; then pass "no stderr noise on valid input"; else fail "unexpected stderr: $err"; fi
fi
err="$(journal_time_normalize_jctl 'bogus' 2>&1 >/dev/null)"
case "$err" in
    *"not a valid"*) pass "invalid input prints a clear diagnostic" ;;
    "")              fail "invalid input produced no diagnostic" ;;
    *)               pass "invalid input produced a diagnostic" ;;
esac

section "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
