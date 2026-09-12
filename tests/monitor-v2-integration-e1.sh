#!/usr/bin/env bash
# Monitor v2 E1 -- REAL Linux integration test against the production-grade
# sing-box 1.14 service.api (127.0.0.1:9091).
#
# READ-ONLY: the collector never mutates configuration, never opens ports and
# never touches credentials. Output is redacted: no UUID/password, no raw
# public IPs (only counts / names / statuses).
#
# SKIP logic: without /root/sbox/sing-box + a live service.api listener this
# test reports SKIP and exits 0 (run it on the VPS).
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
SING_BOX_BIN="${SING_BOX_BIN:-/root/sbox/sing-box}"
API_URL="${API_URL:-http://127.0.0.1:9091}"
PY="${PYTHON:-python3}"

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

echo "== E1 integration: real service.api event stream =="
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

printf '  devices: %s\n' "$("$PY" -c 'import json,sys
snap = json.load(open(sys.argv[1]))
for name, dev in sorted(snap["devices"].items()):
    print("%s status=%s protocols=%s" % (name, dev["status"], ",".join(sorted(dev["protocols"]))))' "$TMP/out.json")"
printf '\n  result: FAILURES=%d\n' "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
