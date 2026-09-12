#!/usr/bin/env bash
# Monitor v2 E1 -- REAL Linux integration test against the production-grade
# sing-box 1.14 service.api (127.0.0.1:9091).
#
# READ-ONLY: the collector never mutates configuration, never opens ports and
# never touches credentials. Output is redacted: no UUID/password, no raw
# public IPs (source presence is reported as a boolean only).
#
# Three-state exit contract (a mistyped gate variable is a FAIL, never PASS):
#   EXIT_PASS=0          phase 1 + phase 2 gates all green
#   EXIT_FAIL=1          structural failure, hard gate failure, config error
#   EXIT_INCONCLUSIVE=2  phase 1 healthy but NO real client lifecycle was
#                        observed in the window (never counted as PASS)
#
# SKIP logic: without /root/sbox/sing-box + a live service.api listener this
# test reports SKIP and exits 0 (run it on the VPS).
#
# The service.api initial reset replays ~1000 historically closed connections
# and cumulative totals never reset, so NEITHER "recently_closed > 0" NOR
# "uplink_total > 0" proves anything about the test window. Phase 2 therefore
# captures a short BASELINE snapshot first (collector --once) and the verdict
# (monitor-v2/lifecycle_gate.py) only accepts baseline -> final DELTAS: a
# traffic delta for real bytes and a recent-closed ID delta for a NEW
# CLOSED/finalize. active_connections > 0 is never accepted as a substitute
# for closure evidence.
#
# Environment:
#   EXPECT_USER     hard gate: this API USER must appear in devices, else
#                   FAIL. An empty devices dict with a named USER is a FAIL,
#                   never an INCONCLUSIVE -- the operator named the USER.
#   EXPECT_INBOUND  optional hard gate: vless-in (Reality) / hy2-in (HY2).
#                   NOT just a presence check: it binds EVERY piece of
#                   evidence -- the traffic delta AND the closed-id delta --
#                   to that USER + INBOUND scope (traffic reads only
#                   devices[USER]["protocols"][INBOUND], closures only
#                   recent_connections rows carried by that inbound), so a
#                   sibling protocol's historical totals or closures can
#                   never make the canary pass. Lets Reality and HY2 run as
#                   separate production canaries.
#   REQUIRE_CLOSED  1 = a NEW CLOSED/finalize beyond baseline is REQUIRED,
#                       else FAIL: no CLOSED/finalize evidence observed.
#                   0 = closed evidence stays informational; the connection
#                       may still be active at window end.
#
# STRICT CANARY: setting ANY gate (EXPECT_USER / EXPECT_INBOUND /
# REQUIRE_CLOSED=1) makes a missing sing-box binary or an unreachable
# service.api a FAIL (exit 1) -- a production canary must never answer a
# broken environment with SKIP (exit 0). Only the gate-free observational
# run SKIPs off-VPS.
set -uo pipefail

EXIT_PASS=0
EXIT_FAIL=1
EXIT_INCONCLUSIVE=2

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
SING_BOX_BIN="${SING_BOX_BIN:-/root/sbox/sing-box}"
API_URL="${API_URL:-http://127.0.0.1:9091}"
PY="${PYTHON:-python3}"
LIFECYCLE_WINDOW="${LIFECYCLE_WINDOW:-20}"
EXPECT_USER="${EXPECT_USER:-}"
EXPECT_INBOUND="${EXPECT_INBOUND:-}"
REQUIRE_CLOSED="${REQUIRE_CLOSED:-0}"

fail_out() {
    printf '\nRESULT: FAIL\n'
    printf '  reason: %s\n' "$*"
    printf '  exit=1\n'
    exit "$EXIT_FAIL"
}

# Configuration is validated BEFORE anything else -- even before the SKIP
# checks -- so a mistyped gate variable can never look like a green run.
case "$REQUIRE_CLOSED" in
    0|1) : ;;
    *)
        echo "configuration error: REQUIRE_CLOSED must be 0 or 1 (got '$REQUIRE_CLOSED')"
        exit "$EXIT_FAIL"
        ;;
esac
case "$EXPECT_INBOUND" in
    ""|vless-in|hy2-in) : ;;
    *)
        echo "configuration error: EXPECT_INBOUND must be empty, vless-in or hy2-in (got '$EXPECT_INBOUND')"
        exit "$EXIT_FAIL"
        ;;
esac

# Strict canary: any gate turns a broken environment into a FAIL, never a
# SKIP -- "SKIP exit 0" must never masquerade as a canary result.
STRICT_CANARY=0
if [ -n "$EXPECT_USER" ] || [ -n "$EXPECT_INBOUND" ] || [ "$REQUIRE_CLOSED" = "1" ]; then
    STRICT_CANARY=1
fi

if [ ! -x "$SING_BOX_BIN" ]; then
    if [ "$STRICT_CANARY" = "1" ]; then
        fail_out "strict canary requires $SING_BOX_BIN (binary not found; run on the VPS)"
    fi
    echo "SKIP: $SING_BOX_BIN not present (integration test must run on the server)"
    exit "$EXIT_PASS"
fi
# The probe follows --url / API_URL (same endpoint the collectors will use).
if ! "$PY" -c 'import socket, sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname or "127.0.0.1"
port = u.port or 9091
s = socket.socket(); s.settimeout(2)
try:
    s.connect((host, int(port)))
except OSError:
    sys.exit(1)
finally:
    s.close()' "$API_URL" 2>/dev/null; then
    if [ "$STRICT_CANARY" = "1" ]; then
        fail_out "strict canary requires service.api at $API_URL (unreachable; is sing-box running?)"
    fi
    echo "SKIP: service.api not reachable at $API_URL (is sing-box running with service.api enabled?)"
    exit "$EXIT_PASS"
fi

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
FAIL=0
TAB="$(printf '\t')"
check() { if [ "$1" = "OK" ]; then printf '  PASS %s\n' "$2"; else FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$2" "$1"; fi; }

echo "== phase 1: structural (6s) =="
"$PY" "$ROOT/monitor-v2/collector.py" --url "$API_URL" --duration 6 --pretty \
    >"$TMP/out.json" 2>"$TMP/err.txt"
rc=$?
check "$([ "$rc" -eq 0 ] && echo OK || echo "rc=$rc")" "collector exits cleanly"
if [ "$rc" -ne 0 ]; then
    sed 's/^/    stderr: /' "$TMP/err.txt"
    fail_out "phase 1 collector failed (rc=$rc)"
fi
"$PY" -c 'import json, sys
snap = json.load(open(sys.argv[1]))
raw = json.dumps(snap)
def emit(name, ok):
    print("OK" if ok else "BAD", name)
emit("stream is healthy (stale=false)", snap.get("stale") is False)
emit("stream delivered batches", snap.get("batch_count", 0) >= 1)
emit("all state fields present", all(k in snap for k in ("active_connections", "recently_closed", "skipped_events", "duplicate_events", "identity_conflicts", "devices")))
emit("no OFFLINE anywhere", "OFFLINE" not in raw)
emit("no Tunnel Down anywhere", "Tunnel Down" not in raw)
emit("devices dict present", isinstance(snap.get("devices"), dict))
emit("no credential material leaked", "uuid" not in raw and "password" not in raw)
' "$TMP/out.json" > "$TMP/checks.txt"
while read -r status name; do
    check "$status" "$name"
done < "$TMP/checks.txt"
if [ "$FAIL" -gt 0 ]; then
    fail_out "phase 1 structural checks failed"
fi

echo ""
echo "== phase 2: lifecycle (${LIFECYCLE_WINDOW}s) =="
if [ "$REQUIRE_CLOSED" = "1" ]; then
    echo "  REQUIRE_CLOSED=1: a NEW CLOSED/finalize beyond baseline is required"
fi

# Baseline BEFORE any traffic prompt: the reset replay makes bare
# recently_closed>0 and cumulative totals worthless as evidence, and an
# early "drive a client now" hint would leak in-window traffic into the
# baseline (baseline == final hides the very delta the gate needs).
echo "  Capturing baseline. DO NOT start client traffic yet."
"$PY" "$ROOT/monitor-v2/collector.py" --url "$API_URL" --once --pretty \
    >"$TMP/baseline.json" 2>"$TMP/base.err.txt"
brc=$?
if [ "$brc" -ne 0 ]; then
    sed 's/^/    stderr: /' "$TMP/base.err.txt"
    fail_out "baseline snapshot failed (rc=$brc)"
fi
"$PY" -c 'import json, sys
b = json.load(open(sys.argv[1]))
print("  baseline: devices=%d recently_closed=%d (historical replay included)"
      % (len(b.get("devices") or {}), b.get("recently_closed") or 0))' \
    "$TMP/baseline.json"

echo "  BASELINE CAPTURED"
echo "  Start client traffic NOW:"
if [ -n "$EXPECT_USER" ]; then
    echo "    USER=$EXPECT_USER"
else
    echo "    USER=any (no EXPECT_USER gate)"
fi
if [ -n "$EXPECT_INBOUND" ]; then
    echo "    INBOUND=$EXPECT_INBOUND"
fi
echo "    1. connect the real production node"
echo "    2. generate a small amount of traffic"
echo "    3. stop/close the connection before the window ends"
echo "  Starting observation window in 2 seconds..."
sleep 2

"$PY" "$ROOT/monitor-v2/collector.py" --url "$API_URL" --duration "$LIFECYCLE_WINDOW" --pretty \
    >"$TMP/life.json" 2>"$TMP/life.err.txt"
lrc=$?
check "$([ "$lrc" -eq 0 ] && echo OK || echo "rc=$lrc")" "lifecycle collector exits cleanly"
if [ "$lrc" -ne 0 ]; then
    sed 's/^/    stderr: /' "$TMP/life.err.txt"
    fail_out "lifecycle collector failed (rc=$lrc)"
fi

"$PY" "$ROOT/monitor-v2/lifecycle_gate.py" \
    --baseline "$TMP/baseline.json" \
    --final "$TMP/life.json" \
    --expect-user "$EXPECT_USER" \
    --expect-inbound "$EXPECT_INBOUND" \
    --require-closed "$REQUIRE_CLOSED" >"$TMP/gate.txt"
grc=$?

while IFS="$TAB" read -r status name; do
    case "$status" in
        PASS) printf '  PASS %s\n' "$name" ;;
        FAIL) FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$name" ;;
        INFO) printf '  INFO %s\n' "$name" ;;
    esac
done < "$TMP/gate.txt"

case "$grc" in
    "$EXIT_PASS")
        printf '\nRESULT: PASS\n'
        printf '  exit=0\n'
        exit "$EXIT_PASS"
        ;;
    "$EXIT_INCONCLUSIVE")
        printf '\nRESULT: INCONCLUSIVE\n'
        printf '  exit=2\n'
        exit "$EXIT_INCONCLUSIVE"
        ;;
    *)
        reason="$(awk -F"$TAB" '$1 == "REASON" { print $2; exit }' "$TMP/gate.txt")"
        printf '\nRESULT: FAIL\n'
        printf '  reason: %s\n' "${reason:-lifecycle gate failed}"
        printf '  exit=1\n'
        exit "$EXIT_FAIL"
        ;;
esac
