#!/usr/bin/env bash
# Monitor v2 Phase E1 regression tests: API-first collector.
#
# Every test really executes monitor-v2/collector.py functions (imported via
# PYTHONPATH) against synthetic fixtures; T9 additionally exercises the real
# urllib API adapter + CLI end-to-end against a throwaway loopback HTTP server
# serving a fixture file. No database, no network beyond 127.0.0.1.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
COLLECTOR="$ROOT/monitor-v2/collector.py"
PY="${PYTHON:-python3}"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() {
    # NOTE: never reference a variable inside the same local statement that
    # declares it (set -u expands all words before any assignment happens).
    local want="$1" got="$2" label="${3:-}"
    if [ -z "$label" ]; then label="rc == $want"; fi
    if [ "$want" = "$got" ]; then pass "$label"; else fail "$label (expected rc=$want, got rc=$got)"; fi
}
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if printf '%s' "$2" | grep -qF "$1"; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if printf '%s' "$2" | grep -qF "$1"; then fail "$3 (forbidden: $1)"; else pass "$3"; fi; }

section "static checks"
if "$PY" -m py_compile "$COLLECTOR" 2>"$TMP/py.err"; then pass "py_compile collector.py"; else fail "py_compile collector.py: $(cat "$TMP/py.err")"; fi
[ -f "$ROOT/monitor-v2/README.md" ] && pass "architecture README present" || fail "architecture README missing"

# pyrun '<python code>' -- run a snippet with monitor-v2 on the path;
# the snippet must print a JSON document on stdout.
pyrun() {
    PYTHONPATH="$ROOT/monitor-v2" "$PY" -c "$1"
}

snap_field() { # snap_field <json> <python-expr> -> evaluated field
    printf '%s' "$1" | PYTHONPATH="$ROOT/monitor-v2" "$PY" -c \
        'import json,sys; snap=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"
}

section "T1: same USER + different inbound -> ONE device, two protocols"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([
  {"id": "r1", "user": "vmix-01", "inbound": "vless-in", "source": "1.1.1.1:5", "rate": 10, "total": 100},
  {"id": "h1", "user": "vmix-01", "inbound": "hy2-in", "source": "1.1.1.1:5", "rate": 20, "total": 200},
], 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_rc 0 $?
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "1" "one device for one USER"
assert_eq "$(snap_field "$snap" 'sorted(snap["devices"]["vmix-01"]["protocols"])')" "['hy2-in', 'vless-in']" "two protocols under the device"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["vless-in"]["total"]')" "100.0" "vless-in protocol total"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["hy2-in"]["total"]')" "200.0" "hy2-in protocol total"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["status"]')" "ACTIVE" "device status ACTIVE"

section "T2: different USER + same source IP -> two devices"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([
  {"id": "a1", "user": "vmix-01", "inbound": "vless-in", "source": "203.0.113.9:5000", "rate": 1, "total": 10},
  {"id": "a2", "user": "vmix-02", "inbound": "vless-in", "source": "203.0.113.9:5000", "rate": 2, "total": 20},
], 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'sorted(snap["devices"])')" "['vmix-01', 'vmix-02']" "source IP is NOT an identity: two devices"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["total"]')" "10.0" "vmix-01 keeps its own total"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-02"]["total"]')" "20.0" "vmix-02 keeps its own total"

section "T3: HY2 multiple connections sharing one source endpoint -> not merged"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([
  {"id": "h1", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "rate": 1, "total": 11},
  {"id": "h2", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "rate": 2, "total": 22},
  {"id": "h3", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "rate": 4, "total": 44},
], 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "1" "shared QUIC endpoint stays one device"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["active_connections"]')" "3" "three logical connections counted"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["total"]')" "77.0" "totals summed without merging identities"

section "T4: connection id disappears -> cumulative total never decreases"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([{"id": "A", "user": "legacy", "inbound": "vless-in", "rate": 5, "total": 100}], 1000)
s1 = t.snapshot(1000)
t.poll([], 1001)
s2 = t.snapshot(1001)
t.poll([], 5000)
s3 = t.snapshot(5000)
print(json.dumps({"s1": s1, "s2": s2, "s3": s3}))
')"
assert_eq "$(snap_field "$snap" 'snap["s1"]["devices"]["legacy"]["total"]')" "100.0" "total while active"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["total"]')" "100.0" "total kept after row disappeared"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["recent_connections"][0]["id"]')" "A" "finalized row visible in recent cache"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["status"]')" "RECENT ACTIVITY" "RECENT ACTIVITY after row disappeared"
assert_eq "$(snap_field "$snap" 'snap["s3"]["devices"]["legacy"]["total"]')" "100.0" "total still banked after cache TTL pruning"
assert_eq "$(snap_field "$snap" 'snap["s3"]["devices"]["legacy"]["status"]')" "IDLE" "IDLE once nothing is recent"

section "T5: id reappears / new id -> no double counting"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([{"id": "A", "user": "legacy", "inbound": "vless-in", "rate": 1, "total": 100}], 1000)
t.poll([], 1001)
t.poll([{"id": "A", "user": "legacy", "inbound": "vless-in", "rate": 1, "total": 150}], 1002)
s_react = t.snapshot(1002)
t.poll([
  {"id": "A", "user": "legacy", "inbound": "vless-in", "rate": 1, "total": 150},
  {"id": "B", "user": "legacy", "inbound": "vless-in", "rate": 1, "total": 50},
], 1003)
s_new = t.snapshot(1003)
print(json.dumps({"react": s_react, "new": s_new}))
')"
assert_eq "$(snap_field "$snap" 'snap["react"]["devices"]["legacy"]["total"]')" "150.0" "reactivated id continues its lifecycle (not 250)"
assert_eq "$(snap_field "$snap" 'snap["new"]["devices"]["legacy"]["total"]')" "200.0" "new id B adds exactly once (150+50)"
assert_eq "$(snap_field "$snap" 'snap["new"]["devices"]["legacy"]["active_connections"]')" "2" "two active lifecycles"

section "T6: zero connections -> collector healthy, honest status only"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([{"id": "A", "user": "legacy", "inbound": "vless-in", "rate": 1, "total": 10}], 1000)
t.poll([], 1001)
s = t.snapshot(1001)
print(json.dumps({"snap": s, "raw": json.dumps(s)}))
')"
assert_eq "$(snap_field "$snap" 'snap["snap"]["poll_count"]')" "2" "collector keeps running with zero connections"
assert_contains '"status"' "$snap" "device still reported with a status"
assert_not_contains 'OFFLINE' "$snap" "never emits OFFLINE"
assert_not_contains 'Tunnel Down' "$snap" "never emits Tunnel Down"
assert_eq "$(snap_field "$snap" 'snap["snap"]["devices"]["legacy"]["status"]')" "RECENT ACTIVITY" "honest status only"

section "T7: malformed API rows -> skipped, never pollute"
snap="$(pyrun '
import json
from collector import Tracker
t = Tracker()
t.poll([
  "not-a-dict",
  42,
  {},
  {"id": ""},
  {"id": "no-user"},
  {"id": "no-inbound", "user": "u"},
  {"id": "ok", "user": "legacy", "inbound": "vless-in", "rate": "300", "total": "400"},
], 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'snap["skipped_rows"]')" "6" "six malformed rows skipped"
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "1" "only the valid row created state"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["total"]')" "400.0" "numeric strings tolerated"

section "T8: API unavailable -> keep last state + stale flag"
snap="$(pyrun '
import json
import collector
calls = {"n": 0}
def fake(url, path, timeout, secret):
    if calls["n"] == 0:
        calls["n"] += 1
        return [{"id": "c1", "user": "legacy", "inbound": "vless-in", "rate": 5, "total": 100}]
    raise RuntimeError("connection refused")
collector.fetch_connections = fake
c = collector.Collector(url="http://127.0.0.1:9091")
s1 = c.poll_once(now=1000)
s2 = c.poll_once(now=1003)
print(json.dumps({"s1": s1, "s2": s2}))
')"
assert_eq "$(snap_field "$snap" 'snap["s1"]["stale"]')" "False" "first poll healthy"
assert_eq "$(snap_field "$snap" 'snap["s2"]["stale"]')" "True" "second poll marked stale"
assert_contains 'connection refused' "$snap" "last error preserved for debugging"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["total"]')" "100.0" "last state fully preserved while stale"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["status"]')" "ACTIVE" "stale poll does not invent state transitions"

section "T9: real API adapter + CLI end-to-end over loopback HTTP"
WWW="$TMP/www"
mkdir -p "$WWW"
cp "$ROOT/monitor-v2/fixtures/connections-sample.json" "$WWW/connections"
PORT=$(( 18900 + (RANDOM % 100) ))
( cd "$WWW" && exec "$PY" -m http.server "$PORT" --bind 127.0.0.1 ) > "$TMP/http.log" 2>&1 &
HTTP_PID=$!
http_ready=0
for _ in $(seq 1 20); do
    if "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null; then http_ready=1; break; fi
    command sleep 0.2
done
if [ "$http_ready" -eq 1 ]; then
    pass "loopback fixture HTTP server ready on $PORT"
    if out="$("$PY" "$COLLECTOR" --url "http://127.0.0.1:$PORT" --once --pretty 2>"$TMP/t9.err")"; then
        pass "CLI --once end-to-end against real HTTP adapter"
        assert_contains '"vmix-01"' "$out" "CLI output contains vmix-01 device"
        assert_eq "$(printf '%s' "$out" | PYTHONPATH="$ROOT/monitor-v2" "$PY" -c 'import json,sys; snap=json.load(sys.stdin); print(snap["stale"])')" "False" "CLI snapshot not stale"
        assert_eq "$(printf '%s' "$out" | PYTHONPATH="$ROOT/monitor-v2" "$PY" -c 'import json,sys; snap=json.load(sys.stdin); print(len(snap["devices"]))')" "2" "CLI snapshot has both devices"
    else
        fail "CLI --once failed: $(head -n3 "$TMP/t9.err" | tr '\n' ' ')"
    fi
else
    fail "loopback fixture HTTP server did not start"
fi
kill "$HTTP_PID" 2>/dev/null
wait "$HTTP_PID" 2>/dev/null

printf '\n== summary ==\n'
printf '  pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
