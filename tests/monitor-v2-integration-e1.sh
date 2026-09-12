#!/usr/bin/env bash
# Monitor v2 E1 -- REAL Linux integration test against the production-grade
# sing-box 1.14 service.api (127.0.0.1:9091).
#
# READ-ONLY: the collector never mutates configuration, never opens ports and
# never touches credentials. Output is redacted: no UUID/password, no raw
# public IPs (source presence is reported as a boolean only).
#
# SKIP logic: without /root/sbox/sing-box + a live service.api listener this
# test reports SKIP and exits 0 (run it on the VPS).
#
# Two phases:
#   phase 1 structural: stream connects, stays healthy, state fields present
#   phase 2 lifecycle : drives the collector over a window while a REAL
#                       Reality/HY2 client makes traffic, then verifies
#                       USER / INBOUND / lifecycle / uplink+downlink movement
#                       and closure evidence. With no traffic at all the
#                       lifecycle phase reports INCONCLUSIVE (not PASS).
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
SING_BOX_BIN="${SING_BOX_BIN:-/root/sbox/sing-box}"
API_URL="${API_URL:-http://127.0.0.1:9091}"
PY="${PYTHON:-python3}"
LIFECYCLE_WINDOW="${LIFECYCLE_WINDOW:-20}"
EXPECT_USER="${EXPECT_USER:-}"

if [ ! -x "$SING_BOX_BIN" ]; then
    echo "SKIP: $SING_BOX_BIN not present (integration test must run on the server)"
    exit 0
fi
if ! "$PY" -c 'import socket,sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("127.0.0.1", 9091))
except OSError:
    sys.exit(1)
finally:
    s.close()' 2>/dev/null; then
    echo "SKIP: service.api not reachable on 127.0.0.1:9091 (is sing-box running with service.api enabled?)"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
FAIL=0
check() { if [ "$1" = "OK" ]; then printf '  PASS %s\n' "$2"; else FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$2" "$1"; fi; }

echo "== phase 1: structural (6s) =="
"$PY" "$ROOT/monitor-v2/collector.py" --url "$API_URL" --duration 6 --pretty \
    >"$TMP/out.json" 2>"$TMP/err.txt"
rc=$?
check "$([ "$rc" -eq 0 ] && echo OK || echo "rc=$rc")" "collector exits cleanly"
if [ "$rc" -ne 0 ]; then
    sed 's/^/    stderr: /' "$TMP/err.txt"
    exit 1
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

echo ""
echo "== phase 2: lifecycle (${LIFECYCLE_WINDOW}s) =="
if [ -n "$EXPECT_USER" ]; then
    echo "  expecting USER=$EXPECT_USER (drive a client connection now)"
else
    echo "  no EXPECT_USER set; observing whatever client traffic occurs"
fi
"$PY" "$ROOT/monitor-v2/collector.py" --url "$API_URL" --duration "$LIFECYCLE_WINDOW" --pretty \
    >"$TMP/life.json" 2>"$TMP/life.err.txt"
lrc=$?
check "$([ "$lrc" -eq 0 ] && echo OK || echo "rc=$lrc")" "lifecycle collector exits cleanly"

"$PY" -c 'import json, os, sys
snap = json.load(open(sys.argv[1]))
expect_user = os.environ.get("EXPECT_USER", "")
lines = []
devices = snap.get("devices") or {}

def info(name):
    lines.append(("INFO", name))

def verdict(name, ok):
    lines.append(("OK" if ok else "BAD", name))

if not devices and snap.get("recently_closed", 0) == 0:
    info("INCONCLUSIVE: no client traffic observed in this window; "
         "drive a Reality/HY2 connection (stable client) and re-run")
else:
    names = sorted(devices)
    verdict("at least one DEVICE seen: " + ",".join(names), True)
    proto_ok = all(
        set(d.get("protocols") or {}) <= {"vless-in", "hy2-in"}
        for d in devices.values())
    verdict("INBOUND values stay within vless-in / hy2-in", proto_ok)
    moved = any(
        (p.get("uplink_total", 0) + p.get("downlink_total", 0)) > 0
        for d in devices.values() for p in (d.get("protocols") or {}).values())
    verdict("uplink/downlink totals moved for at least one protocol", moved)
    lifecycle = (snap.get("active_connections", 0) > 0
                 or snap.get("recently_closed", 0) > 0)
    verdict("lifecycle evidence present (active and/or recently closed)", lifecycle)
    source_present = any(
        bool(conn.get("source"))
        for d in devices.values() for conn in (d.get("recent_connections") or [])) \
        or any(bool(d.get("recent_sources")) for d in devices.values())
    info("SOURCE_PRESENT=%s (raw source is never printed)" % ("true" if source_present else "false"))
    if snap.get("recently_closed", 0) > 0:
        info("closure evidence: recently_closed=%d (CLOSED/finalize observed)" % snap["recently_closed"])
    elif snap.get("active_connections", 0) > 0:
        info("connections still active at window end; close the client to observe CLOSED/finalize")
    if expect_user:
        verdict("EXPECT_USER %s present" % expect_user, expect_user in devices)
    print("\n".join("%s\t%s" % (s, n) for s, n in lines))
' "$TMP/life.json" > "$TMP/life-checks.txt"
while IFS=$'\t' read -r status name; do
    if [ "$status" = "INFO" ]; then
        printf '  INFO %s\n' "$name"
    else
        check "$status" "$name"
    fi
done < "$TMP/life-checks.txt"

printf '\n  result: FAILURES=%d\n' "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
