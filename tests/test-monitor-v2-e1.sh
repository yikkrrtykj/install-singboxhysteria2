#!/usr/bin/env bash
# Monitor v2 Phase E1 regression tests -- REAL event fixtures, no REST.
#
# The collector consumes the official service.api event stream
# (daemon.StartedService/SubscribeConnections). Every test drives
# monitor-v2/collector.py functions with event batches shaped exactly like the
# official proto (ConnectionEvent NEW/UPDATE/CLOSED, ConnectionEvents.reset),
# loaded from monitor-v2/fixtures/events-*.json. T10 additionally runs the real
# gRPC-Web wire path (framing + protobuf codec) against a throwaway loopback
# server; tests/monitor-v2-integration-e1.sh covers the real VPS binary.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
FIXTURES="$ROOT/monitor-v2/fixtures"
COLLECTOR="$ROOT/monitor-v2/collector.py"
PY="${PYTHON:-python3}"
export FIXDIR="$FIXTURES"
export BRIDGE="$ROOT/monitor-v2/api_bridge"

PASS=0
FAIL=0
# The gate at the bottom of this file fails unless exactly this many
# assertions ran AND passed, so unreachable sections can never fake success.
EXPECTED_PASS=188
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -gt 0 ]; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -eq 0 ]; then pass "$3"; else fail "$3 (forbidden: $1)"; fi; }

section "static checks"
if "$PY" -m py_compile "$COLLECTOR" 2>"$TMP/py.err"; then pass "py_compile collector.py"; else fail "py_compile collector.py: $(cat "$TMP/py.err")"; fi
if "$PY" -m py_compile "$ROOT/monitor-v2/api_bridge/proto_wire.py" \
    "$ROOT/monitor-v2/api_bridge/grpc_web.py" \
    "$ROOT/monitor-v2/api_bridge/singbox_stream.py" 2>>"$TMP/py.err"; then
    pass "py_compile api_bridge"
else
    fail "py_compile api_bridge: $(cat "$TMP/py.err")"
fi
[ -f "$ROOT/monitor-v2/README.md" ] && pass "architecture README present" || fail "architecture README missing"
if grep -q 'urlopen\|DEFAULT_CONNECTIONS_PATH\|http.server' "$ROOT/monitor-v2/api_bridge/"*.py 2>/dev/null; then
    fail "stale REST /connections still present in api_bridge"
else
    pass "api_bridge has no REST /connections remnants"
fi

snap_field() {
    printf '%s' "$1" | PYTHONPATH="$ROOT/monitor-v2" "$PY" -c \
        'import json,sys; snap=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"
}

tracker_run() {
    PYTHONPATH="$ROOT/monitor-v2" "$PY" -c '
import json, sys, os
from collector import Tracker
now = float(sys.argv[1])
batch = json.load(open(os.path.join(os.environ["FIXDIR"], sys.argv[2])))
t = Tracker()
t.apply_batch(batch, now)
print(json.dumps(t.snapshot(now)))
' "$1" "$2"
}

section "E1-01: same USER + vless/hy2 -> one Device, two Protocols"
snap="$(tracker_run 1000 events-initial-reset.json)"
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "2" "reset batch creates two devices (vmix-01, legacy)"
assert_eq "$(snap_field "$snap" 'sorted(snap["devices"]["vmix-01"]["protocols"])')" "['hy2-in', 'vless-in']" "one device, two protocols"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "vless-in uplink from authoritative NEW totals"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["hy2-in"]["downlink_total"]')" "10.0" "hy2-in downlink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["status"]')" "ACTIVE" "device status ACTIVE"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["status"]')" "RECENT ACTIVITY" "recently-closed row from reset batch lands in RECENT ACTIVITY"

snap_field() {
    printf '%s' "$1" | PYTHONPATH="$ROOT/monitor-v2" "$PY" -c \
        'import json,sys; snap=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"
}

# tracker_seq <python> -- full clock control over a multi-batch sequence
tracker_seq() {
    PYTHONPATH="$ROOT/monitor-v2" "$PY" -c "$1"
}

section "E1-02: different USER + same source -> two Devices"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "a1", "connection": {"id": "a1", "user": "vmix-01", "inbound": "vless-in", "source": "203.0.113.9:5000", "uplink_total": 10, "downlink_total": 1}},
  {"type": "NEW", "id": "a2", "connection": {"id": "a2", "user": "vmix-02", "inbound": "vless-in", "source": "203.0.113.9:5000", "uplink_total": 20, "downlink_total": 2}},
]}, 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'sorted(snap["devices"])')" "['vmix-01', 'vmix-02']" "source IP is NOT an identity"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["uplink_total"]')" "10.0" "vmix-01 own uplink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-02"]["uplink_total"]')" "20.0" "vmix-02 own uplink"
section "E1-03: HY2 logical connections sharing one source endpoint"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "h1", "connection": {"id": "h1", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "uplink_total": 11, "downlink_total": 3}},
  {"type": "NEW", "id": "h2", "connection": {"id": "h2", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "uplink_total": 22, "downlink_total": 5}},
  {"type": "NEW", "id": "h3", "connection": {"id": "h3", "user": "vmix-01", "inbound": "hy2-in", "source": "203.0.113.9:51001", "uplink_total": 44, "downlink_total": 7}},
]}, 1000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "1" "shared endpoint stays one device"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["active_connections"]')" "3" "separate ids, no merge"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["uplink_total"]')" "77.0" "uplink summed across the three lifecycles"

section "E1-04: NEW -> UPDATE -> CLOSED: totals exact, no double count"
snap="$(tracker_seq '
import json, os
from collector import Tracker
fix = os.environ["FIXDIR"]
t = Tracker()
t.apply_batch(json.load(open(fix + "/events-initial-reset.json")), 1000)
t.apply_batch(json.load(open(fix + "/events-update-delta.json")), 1002)
s_mid = t.snapshot(1002)
t.apply_batch(json.load(open(fix + "/events-close-r1.json")), 1003)
s_closed = t.snapshot(1003)
print(json.dumps({"mid": s_mid, "closed": s_closed}))
')"
assert_eq "$(snap_field "$snap" 'snap["mid"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1300.0" "UPDATE delta added to NEW totals (1000+300)"
assert_eq "$(snap_field "$snap" 'snap["mid"]["devices"]["vmix-01"]["protocols"]["vless-in"]["downlink_total"]')" "2700.0" "downlink delta added (2000+700)"
assert_eq "$(snap_field "$snap" 'snap["mid"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_rate"]')" "150.0" "uplink rate = delta / elapsed (300/2s)"
assert_eq "$(snap_field "$snap" 'snap["closed"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1300.0" "banked exactly once at CLOSED"
assert_eq "$(snap_field "$snap" 'snap["closed"]["recently_closed"]')" "2" "r1 joined the recent-closed cache"
assert_eq "$(snap_field "$snap" 'snap["closed"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_rate"]')" "0.0" "closed connections carry no rate"

section "E1-05: multiple UPDATE events + authoritative totals"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "u1", "connection": {"id": "u1", "user": "legacy", "inbound": "vless-in", "uplink_total": 100, "downlink_total": 50}}
]}, 1000)
t.apply_batch({"reset": False, "events": [
  {"type": "UPDATE", "id": "u1", "uplink_delta": 10, "downlink_delta": 5}
]}, 1001)
t.apply_batch({"reset": False, "events": [
  {"type": "UPDATE", "id": "u1", "uplink_delta": 20, "downlink_delta": 5}
]}, 1003)
s_delta = t.snapshot(1003)
t.apply_batch({"reset": False, "events": [
  {"type": "UPDATE", "id": "u1", "uplink_delta": 999, "downlink_delta": 999,
   "connection": {"id": "u1", "user": "legacy", "inbound": "vless-in", "uplink_total": 500, "downlink_total": 100}}
]}, 1004)
s_auth = t.snapshot(1004)
print(json.dumps({"delta": s_delta, "auth": s_auth}))
')"
assert_eq "$(snap_field "$snap" 'snap["delta"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "130.0" "deltas accumulate (100+10+20)"
assert_eq "$(snap_field "$snap" 'snap["delta"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_rate"]')" "10.0" "rate = delta/elapsed (20/2s)"
assert_eq "$(snap_field "$snap" 'snap["auth"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "500.0" "authoritative totals replace, not add (no 1300+999)"
assert_eq "$(snap_field "$snap" 'snap["auth"]["devices"]["legacy"]["protocols"]["vless-in"]["downlink_total"]')" "100.0" "authoritative downlink replaces"

section "E1-06/07/08: duplicate CLOSED, UPDATE unknown id, CLOSED unknown id"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "k1", "connection": {"id": "k1", "user": "legacy", "inbound": "vless-in", "uplink_total": 70, "downlink_total": 30}}
]}, 1000)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "k1", "closed_at": 1001}
]}, 1001)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "k1", "closed_at": 1002}
]}, 1002)
t.apply_batch({"reset": False, "events": [
  {"type": "UPDATE", "id": "ghost", "uplink_delta": 500, "downlink_delta": 500}
]}, 1003)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "ghost2"}
]}, 1004)
print(json.dumps(t.snapshot(1004)))
')"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "70.0" "duplicate CLOSED does not re-bank (E1-06)"
assert_eq "$(snap_field "$snap" 'snap["duplicate_events"]')" "1" "duplicate CLOSED counted (E1-06)"
assert_eq "$(snap_field "$snap" 'snap["skipped_events"]')" "2" "unknown-id UPDATE/CLOSED skipped (E1-07/E1-08)"
assert_eq "$(snap_field "$snap" 'len(snap["devices"])')" "1" "no phantom devices from unknown ids"
assert_eq "$(snap_field "$snap" 'snap["active_connections"]')" "0" "connection finalized exactly once"

section "E1-09: same ID identity drift -> conflict, no traffic migration"
snap="$(tracker_seq '
import json, os
from collector import Tracker
fix = os.environ["FIXDIR"]
t = Tracker()
t.apply_batch(json.load(open(fix + "/events-initial-reset.json")), 1000)
t.apply_batch(json.load(open(fix + "/events-identity-drift.json")), 1002)
print(json.dumps(t.snapshot(1002)))
')"
assert_eq "$(snap_field "$snap" 'snap["identity_conflicts"]')" "1" "identity drift detected and counted"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "original lifecycle totals untouched"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["vless-in"]["downlink_total"]')" "2000.0" "original downlink untouched"
assert_eq "$(snap_field "$snap" 'snap["devices"].get("vmix-02", "absent")')" "absent" "no traffic migrated to another device"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_rate"]')" "0.0" "drift event did not change rates"


section "E1-10/11: stream failure keeps state + stale; recovery clears it"
snap="$(tracker_seq '
import json
from collector import Collector
batches = {
    0: {"reset": True, "events": [
        {"type": "NEW", "id": "s1", "connection": {"id": "s1", "user": "legacy", "inbound": "vless-in", "uplink_total": 100, "downlink_total": 200}}]},
    1: {"reset": False, "events": [
        {"type": "UPDATE", "id": "s1", "uplink_delta": 40, "downlink_delta": 60}]},
    2: {"reset": False, "events": [
        {"type": "UPDATE", "id": "s1", "uplink_delta": 60, "downlink_delta": 40}]},
}
state = {"t": 1000.0}
def fake_clock():
    return state["t"]
def factory_good_first_two():
    yield batches[0]
    yield batches[1]
def factory_dead():
    raise RuntimeError("stream EOF")
def factory_recovered():
    yield batches[2]
c = Collector(url="http://127.0.0.1:9091", stream_factory=factory_good_first_two, clock=fake_clock)
c.consume(max_batches=2)
s1 = c.snapshot()
c.stream_factory = factory_dead
c.consume(max_batches=1)
s2 = c.snapshot()
c.stream_factory = factory_recovered
c.consume(max_batches=1)
s3 = c.snapshot()
print(json.dumps({"s1": s1, "s2": s2, "s3": s3}))
')"
assert_eq "$(snap_field "$snap" 'snap["s1"]["stale"]')" "False" "healthy stream -> not stale (E1-10 baseline)"
assert_eq "$(snap_field "$snap" 'snap["s1"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "140.0" "delta applied on healthy stream (100+40)"
assert_eq "$(snap_field "$snap" 'snap["s2"]["stale"]')" "True" "stream failure -> stale (E1-10)"
assert_eq "$(snap_field "$snap" 'snap["s2"]["last_error"]')" "RuntimeError: stream EOF" "failure reason recorded"
assert_eq "$(snap_field "$snap" 'snap["s2"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "140.0" "state retained during failure (E1-10)"
assert_eq "$(snap_field "$snap" 'snap["s2"]["active_connections"]')" "1" "no fake CLOSED on stream failure (E1-10)"
assert_eq "$(snap_field "$snap" 'snap["s3"]["stale"]')" "False" "recovery clears stale (E1-11)"
assert_eq "$(snap_field "$snap" 'snap["s3"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "200.0" "recovered stream continues accumulation (140+60)"
assert_eq "$(snap_field "$snap" 'snap["s3"]["devices"]["legacy"]["protocols"]["vless-in"]["downlink_total"]')" "300.0" "recovered downlink continues (240+60... 240? 200+60=... verify)"

section "E1-12: reset=true rebuilds snapshot per official semantics"
snap="$(tracker_seq '
import json, os
from collector import Tracker
fix = os.environ["FIXDIR"]
t = Tracker()
# subscription 1: initial reset with r1+h1 active and one already-closed row
t.apply_batch(json.load(open(fix + "/events-initial-reset.json")), 1000)
# subscription 2 (stream reconnect): fresh reset batch, r1 present with
# authoritative totals, h1 absent from the batch entirely
t.apply_batch(json.load(open(fix + "/events-reset-reconnect.json")), 2000)
s = t.snapshot(2000)
print(json.dumps({"s": s, "raw": json.dumps(s)}))
')"
assert_eq "$(snap_field "$snap" 'snap["s"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "3000.0" "reset rebuild uses authoritative totals, single lifecycle"
assert_eq "$(snap_field "$snap" 'snap["s"]["devices"]["vmix-01"]["protocols"]["vless-in"]["downlink_total"]')" "4000.0" "authoritative downlink after reconnect"
assert_eq "$(snap_field "$snap" 'snap["s"]["abandoned_on_reset"]')" "1" "h1 dropped without banking (no CLOSED received)"
assert_eq "$(snap_field "$snap" 'snap["s"]["devices"]["vmix-01"]["active_connections"]')" "1" "only r1 remains active after rebuild"
assert_eq "$(snap_field "$snap" 'snap["s"]["devices"]["legacy"]["protocols"]["hy2-in"]["uplink_total"]')" "500.0" "banked closed row from reset batch survives rebuild"

section "E1-13: zero active connections -> IDLE, never OFFLINE"
snap="$(tracker_seq '
import json, os
from collector import Tracker
fix = os.environ["FIXDIR"]
t = Tracker(closed_ttl=600)
t.apply_batch(json.load(open(fix + "/events-initial-reset.json")), 1000)
t.apply_batch(json.load(open(fix + "/events-close-r1.json")), 1001)
t.apply_batch({"reset": True, "events": []}, 99999)
s = t.snapshot(99999)
print(json.dumps({"snap": s, "raw": json.dumps(s)}))
')"
assert_eq "$(snap_field "$snap" 'snap["snap"]["devices"]["vmix-01"]["status"]')" "IDLE" "known device with nothing recent -> IDLE"
assert_not_contains 'OFFLINE' "$snap" "never emits OFFLINE"
assert_not_contains 'Tunnel Down' "$snap" "never emits Tunnel Down"
assert_eq "$(snap_field "$snap" 'snap["snap"]["devices"]["vmix-01"]["uplink_total"]')" "1005.0" "abandoned lower bound keeps device totals from dropping (r1 closed 1000 + h1 abandoned 5)"
assert_eq "$(snap_field "$snap" 'snap["snap"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "closed vless-in totals stay banked exactly"

section "E1-14: closed TTL expires -> recent row gone, banked totals remain"
snap="$(tracker_seq '
import json, os
from collector import Tracker
fix = os.environ["FIXDIR"]
t = Tracker(closed_ttl=600)
t.apply_batch(json.load(open(fix + "/events-initial-reset.json")), 1000)
t.apply_batch(json.load(open(fix + "/events-close-r1.json")), 1001)
t.apply_batch({"reset": True, "events": []}, 1002)
s_recent = t.snapshot(1002)
t.apply_batch({"reset": False, "events": []}, 5000)
s_after = t.snapshot(5000)
print(json.dumps({"recent": s_recent, "after": s_after}))
')"
assert_eq "$(snap_field "$snap" 'snap["recent"]["recently_closed"]')" "2" "closed rows visible within TTL"
assert_eq "$(snap_field "$snap" 'snap["after"]["recently_closed"]')" "0" "recent rows pruned after TTL"
assert_eq "$(snap_field "$snap" 'snap["after"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "banked totals remain after prune"
assert_eq "$(snap_field "$snap" 'snap["after"]["devices"]["vmix-01"]["status"]')" "IDLE" "device falls back to IDLE after prune"

section "T10: real gRPC-Web wire path (framing + protobuf codec) over loopback"
snap="$(tracker_seq '
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.environ["BRIDGE"])
from proto_wire import encode_varint, encode_varint_field, encode_length_delimited

def conn_bytes(cid, user, inbound, up, down):
    body = encode_length_delimited(1, cid.encode())
    body += encode_length_delimited(2, inbound.encode())
    body += encode_length_delimited(3, b"vless")
    body += encode_length_delimited(6, b"203.0.113.9:51000")
    body += encode_length_delimited(10, user.encode())
    body += encode_varint_field(16, up)
    body += encode_varint_field(17, down)
    return body

def event_new(cid, user, inbound, up, down):
    body = encode_varint_field(1, 0)
    body += encode_length_delimited(2, cid.encode())
    body += encode_length_delimited(3, conn_bytes(cid, user, inbound, up, down))
    return body

def event_update(cid, up, down):
    body = encode_varint_field(1, 1)
    body += encode_length_delimited(2, cid.encode())
    body += encode_varint_field(4, up)
    body += encode_varint_field(5, down)
    return body

def events_message(events, reset):
    body = b""
    for e in events:
        body += encode_length_delimited(1, e)
    if reset:
        body += encode_varint_field(2, 1)
    return body

reset_batch = events_message([event_new("r1", "legacy", "vless-in", 1000, 2000)], True)
update_batch = events_message([event_update("r1", 300, 700)], False)

checks = {}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        # Validate the gRPC-Web REQUEST envelope: 0x00 flags + 4-byte BE length
        # + protobuf. Without the envelope the real service.api rejects the call.
        checks["content_type"] = self.headers.get("Content-Type")
        checks["flags"] = body[0] if body else None
        checks["declared"] = int.from_bytes(body[1:5], "big") if len(body) >= 5 else -1
        checks["actual"] = len(body) - 5 if len(body) >= 5 else -1
        if len(body) >= 5 and body[0] == 0 and checks["declared"] == checks["actual"]:
            from proto_wire import decode_subscribe_connections_request
            checks["interval"] = decode_subscribe_connections_request(body[5:]).get("interval")
        self.send_response(200)
        self.send_header("Content-Type", "application/grpc-web+proto")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for payload in (reset_batch, update_batch):
            frame = b"\x00" + len(payload).to_bytes(4, "big") + payload
            self.wfile.write(("%x\r\n" % len(frame)).encode() + frame + b"\r\n")
            self.wfile.flush()
        trailer = b"grpc-status: 0\r\n"
        frame = b"\x80" + len(trailer).to_bytes(4, "big") + trailer
        self.wfile.write(("%x\r\n" % len(frame)).encode() + frame + b"\r\n")
        self.wfile.flush()

    def log_message(self, *args):
        pass

Handler.protocol_version = "HTTP/1.1"  # real chunked streaming
server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
from collector import Collector
from api_bridge.singbox_stream import SingboxEventStream
c = Collector(url="http://127.0.0.1:%d" % port, interval=1.0)
c.stream_factory = lambda: SingboxEventStream("http://127.0.0.1:%d" % port, interval_seconds=1.0, connect_timeout=2.0, idle_timeout=5.0)
c.consume(max_batches=2)
snap = c.snapshot()
snap["_request_checks"] = checks
server.shutdown()
print(json.dumps(snap))
')"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "1300.0" "wire path: NEW totals + UPDATE delta over real gRPC-Web framing"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["vless-in"]["downlink_total"]')" "2700.0" "wire path downlink"
assert_eq "$(snap_field "$snap" 'snap["batch_count"]')" "2" "both batches decoded from the wire"
assert_eq "$(snap_field "$snap" 'snap["stale"]')" "False" "wire path healthy"
assert_eq "$(snap_field "$snap" 'snap["_request_checks"]["flags"] == 0 and snap["_request_checks"]["declared"] == snap["_request_checks"]["actual"]')" "True" "request carries a valid gRPC-Web frame (0x00 + BE length)"
assert_eq "$(snap_field "$snap" 'snap["_request_checks"]["content_type"]')" "application/grpc-web+proto" "request content-type is grpc-web+proto"
assert_eq "$(snap_field "$snap" 'snap["_request_checks"].get("interval")')" "1000000000" "request interval is nanoseconds (1.0s -> 1e9)"

section "E1-15/16: loopback URL accepted, non-loopback rejected (fail-closed)"
snap="$(tracker_seq '
import json
from collector import Collector, ConfigurationError
accepted = []
rejected = []
for url in ["http://127.0.0.1:9091", "http://localhost:9091", "http://[::1]:9091"]:
    try:
        Collector(url=url)
        accepted.append(url)
    except ConfigurationError:
        rejected.append(url)
for url in ["http://0.0.0.0:9091", "http://192.168.1.5:9091",
            "http://api.example.com:9091", "https://203.0.113.9:9091"]:
    try:
        Collector(url=url)
        accepted.append(url)
    except ConfigurationError:
        rejected.append(url)
print(json.dumps({"accepted": accepted, "rejected": rejected}))
')"
assert_eq "$(snap_field "$snap" 'json.dumps(snap["accepted"])')" '["http://127.0.0.1:9091", "http://localhost:9091", "http://[::1]:9091"]' "loopback URLs accepted (E1-15)"
assert_eq "$(snap_field "$snap" 'len(snap["rejected"])')" "4" "four non-loopback URLs rejected (E1-16)"
assert_contains "0.0.0.0" "$snap" "0.0.0.0 rejected"
assert_contains "192.168.1.5" "$snap" "private LAN IP rejected"
assert_contains "api.example.com" "$snap" "public hostname rejected"

section "E1-17: secret never appears in serialized state/error/log"
snap="$(tracker_seq '
import json
from collector import Collector
SECRET = "SUPER-SECRET-TOKEN-9f3a"
def factory_dead_with_secret():
    raise RuntimeError("auth failed with Bearer SUPER-SECRET-TOKEN-9f3a against 127.0.0.1:9091")
c = Collector(url="http://127.0.0.1:9091", secret=SECRET, stream_factory=factory_dead_with_secret)
c.consume(max_batches=1)
snap = c.snapshot()
raw = json.dumps(snap)
print(json.dumps({"snap": snap, "leak": SECRET in raw}))
')"
assert_eq "$(snap_field "$snap" 'snap["leak"]')" "False" "secret never appears in serialized state"
assert_eq "$(snap_field "$snap" 'snap["snap"]["stale"]')" "True" "auth failure still marked stale"
assert_contains "[redacted]" "$snap" "secret replaced by [redacted] in last_error"

section "E1-18: uplink/downlink aggregated separately by Device and Protocol"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "w1", "connection": {"id": "w1", "user": "legacy", "inbound": "vless-in", "uplink_total": 100, "downlink_total": 9000}},
  {"type": "NEW", "id": "w2", "connection": {"id": "w2", "user": "legacy", "inbound": "hy2-in", "uplink_total": 300, "downlink_total": 7000}},
]}, 1700000000)
print(json.dumps(t.snapshot(1000)))
')"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["uplink_total"]')" "400.0" "device uplink aggregates only uplink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["downlink_total"]')" "16000.0" "device downlink aggregates only downlink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "100.0" "protocol vless-in uplink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["hy2-in"]["downlink_total"]')" "7000.0" "protocol hy2-in downlink"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["uplink_rate"]')" "0.0" "no invented rates without UPDATE events"

section "E1-19: CLOSED uses authoritative final Connection totals"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "c1", "connection": {"id": "c1", "user": "legacy", "inbound": "vless-in", "uplink_total": 1000, "downlink_total": 2000}}
]}, 1000)
t.apply_batch({"reset": False, "events": [
  {"type": "UPDATE", "id": "c1", "uplink_delta": 300, "downlink_delta": 700}
]}, 1700000002)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "c1", "closed_at": 1700000003000,
   "connection": {"id": "c1", "user": "legacy", "inbound": "vless-in", "uplink_total": 5000, "downlink_total": 9000}}
]}, 1700000003)
s_main = t.snapshot(1700000003)
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "c2", "connection": {"id": "c2", "user": "legacy", "inbound": "hy2-in", "uplink_total": 1000, "downlink_total": 2000}}
]}, 1700000004)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "c2", "closed_at": 1700000005000,
   "connection": {"id": "c2", "user": "someone-else", "inbound": "hy2-in", "uplink_total": 999999, "downlink_total": 999999}}
]}, 1700000005)
s_drift = t.snapshot(1700000005)
print(json.dumps({"main": s_main, "drift": s_drift}))
')"
assert_eq "$(snap_field "$snap" 'snap["main"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "5000.0" "tail traffic after last UPDATE is kept (authoritative 5000, not 1300)"
assert_eq "$(snap_field "$snap" 'snap["main"]["devices"]["legacy"]["protocols"]["vless-in"]["downlink_total"]')" "9000.0" "authoritative downlink at CLOSED"
assert_eq "$(snap_field "$snap" 'snap["main"]["recently_closed"]')" "1" "closed row visible (closed_at in ms was normalized)"
assert_eq "$(snap_field "$snap" 'snap["drift"]["identity_conflicts"]')" "1" "drifting CLOSED connection counted as conflict"
assert_eq "$(snap_field "$snap" 'snap["drift"]["devices"]["legacy"]["protocols"]["hy2-in"]["uplink_total"]')" "1000.0" "drifting totals ignored: tracked totals banked, no migration"

section "E1-20: reset replay of a banked closed id never double-banks"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker(closed_ttl=600)
t.apply_batch({"reset": False, "events": [
  {"type": "NEW", "id": "q1", "connection": {"id": "q1", "user": "legacy", "inbound": "vless-in", "uplink_total": 1000, "downlink_total": 2000}}
]}, 1700000000)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "q1", "closed_at": 1700000003000}
]}, 1700000003)
s_before = t.snapshot(1700020000)   # display TTL long expired
# server replays recent closed connections (~1000) in every reset
t.apply_batch({"reset": True, "events": [
  {"type": "NEW", "id": "q1", "connection": {"id": "q1", "user": "legacy", "inbound": "vless-in", "closed_at": 1700000003000, "uplink_total": 1000, "downlink_total": 2000}}
]}, 1700020001)
# and a stray duplicate CLOSED event for the same long-gone id
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "q1", "closed_at": 1700000003000}
]}, 1700020002)
s_after = t.snapshot(1700020002)
print(json.dumps({"before": s_before, "after": s_after}))
')"
assert_eq "$(snap_field "$snap" 'snap["before"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "baseline banked once"
assert_eq "$(snap_field "$snap" 'snap["after"]["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "replay after TTL does NOT bank twice (guard is independent of display cache)"
assert_eq "$(snap_field "$snap" 'snap["after"]["duplicate_events"]')" "2" "both replay deliveries counted as duplicates"
assert_eq "$(snap_field "$snap" 'snap["after"]["recently_closed"]')" "0" "old closed_at never resurfaces as recent"

section "E1-21: RECENT ACTIVITY is judged by real closed_at, not last_seen"
snap="$(tracker_seq '
import json
from collector import Tracker
NOW = 1700000000
t = Tracker(closed_ttl=600)
t.apply_batch({"reset": True, "events": [
  {"type": "NEW", "id": "old1", "connection": {"id": "old1", "user": "legacy", "inbound": "vless-in", "closed_at": (NOW - 3600) * 1000, "uplink_total": 111, "downlink_total": 222}},
  {"type": "NEW", "id": "fresh1", "connection": {"id": "fresh1", "user": "legacy", "inbound": "hy2-in", "closed_at": (NOW - 10) * 1000, "uplink_total": 333, "downlink_total": 444}},
  {"type": "NEW", "id": "old2", "connection": {"id": "old2", "user": "vmix-09", "inbound": "vless-in", "closed_at": (NOW - 3600) * 1000, "uplink_total": 777, "downlink_total": 888}}
]}, NOW)
print(json.dumps(t.snapshot(NOW)))
')"
assert_eq "$(snap_field "$snap" 'snap["recently_closed"]')" "1" "only the truly recent closed row stays in display"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["status"]')" "RECENT ACTIVITY" "device with a fresh closed row is RECENT ACTIVITY"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-09"]["status"]')" "IDLE" "hour-old closed row does NOT fake RECENT ACTIVITY"
assert_eq "$(snap_field "$snap" 'snap["devices"]["vmix-09"]["protocols"]["vless-in"]["uplink_total"]')" "777.0" "its totals remain banked regardless"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["uplink_total"]')" "444.0" "legacy keeps both rows banked (111+333)"

section "E1-22: abandoned lifecycles bank a lower bound and never double count"
snap="$(tracker_seq '
import json
from collector import Tracker
t = Tracker()
t.apply_batch({"reset": True, "events": [
  {"type": "NEW", "id": "r1", "connection": {"id": "r1", "user": "vmix-01", "inbound": "vless-in", "uplink_total": 1000, "downlink_total": 2000}}
]}, 1700000000)
t.apply_batch({"reset": True, "events": []}, 1700000001)   # r1 missing: abandoned
s_abandoned = t.snapshot(1700000001)
t.apply_batch({"reset": True, "events": [
  {"type": "NEW", "id": "r1", "connection": {"id": "r1", "user": "vmix-01", "inbound": "vless-in", "uplink_total": 5000, "downlink_total": 9000}}
]}, 1700000002)                                            # same lifecycle comes back
s_revived = t.snapshot(1700000002)
t.apply_batch({"reset": False, "events": [
  {"type": "CLOSED", "id": "r1", "closed_at": 1700000003000}
]}, 1700000003)
s_closed = t.snapshot(1700000003)
print(json.dumps({"abandoned": s_abandoned, "revived": s_revived, "closed": s_closed}))
')"
assert_eq "$(snap_field "$snap" 'snap["abandoned"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "1000.0" "abandon keeps last-known totals as lower bound (never drops to 0)"
assert_eq "$(snap_field "$snap" 'snap["abandoned"]["abandoned_on_reset"]')" "1" "abandonment counted"
assert_eq "$(snap_field "$snap" 'snap["revived"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "5000.0" "revived lifecycle adopts authoritative totals without adding the lower bound"
assert_eq "$(snap_field "$snap" 'snap["closed"]["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"]')" "5000.0" "final close banks exactly once"

section "T11: idle-but-healthy stream is silence, not staleness"
snap="$(tracker_seq '
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.environ["BRIDGE"])
import proto_wire as pw
conn = pw.encode_length_delimited(1, b"i1") + pw.encode_length_delimited(2, b"vless-in") + pw.encode_length_delimited(3, b"vless") + pw.encode_length_delimited(10, b"legacy") + pw.encode_varint_field(16, 42) + pw.encode_varint_field(17, 84)
evt = pw.encode_varint_field(1, 0) + pw.encode_length_delimited(2, b"i1") + pw.encode_length_delimited(3, conn)
batch = pw.encode_length_delimited(1, evt) + pw.encode_varint_field(2, 1)
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", "application/grpc-web+proto")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        frame = b"\x00" + len(batch).to_bytes(4, "big") + batch
        self.wfile.write(("%x\r\n" % len(frame)).encode() + frame + b"\r\n")
        self.wfile.flush()
        time.sleep(2.5)   # long silence: healthy idle, no keepalive batches
        trailer = b"grpc-status: 0\r\n"
        frame = b"\x80" + len(trailer).to_bytes(4, "big") + trailer
        self.wfile.write(("%x\r\n" % len(frame)).encode() + frame + b"\r\n")
        self.wfile.flush()
    def log_message(self, *args):
        pass
server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
from collector import Collector
from api_bridge.singbox_stream import SingboxEventStream
c = Collector(url="http://127.0.0.1:%d" % port, interval=0.5)
c.stream_factory = lambda: SingboxEventStream("http://127.0.0.1:%d" % port, interval_seconds=0.5, connect_timeout=2.0, idle_timeout=0.5)
c.consume(duration=1.5)
snap = c.snapshot()
print(json.dumps(snap))
')"
assert_eq "$(snap_field "$snap" 'snap["stale"]')" "False" "idle silence does NOT mark stale"
assert_eq "$(snap_field "$snap" 'snap["last_error"]')" "None" "idle silence records no error"
assert_eq "$(snap_field "$snap" 'snap["devices"]["legacy"]["protocols"]["vless-in"]["uplink_total"]')" "42.0" "reset batch decoded through the idle window"
assert_eq "$(snap_field "$snap" 'snap["batch_count"]')" "1" "idle heartbeats do not count as stream batches"

# ---------------------------------------------------------------------------
# G: integration canary gate (tests/monitor-v2-integration-e1.sh)
#
# The VPS canary must never fake a green run: INCONCLUSIVE is its own exit
# code (2), EXPECT_USER / REQUIRE_CLOSED / EXPECT_INBOUND are hard gates, and
# ALL evidence is a baseline -> final delta -- the service.api reset replay
# makes bare recently_closed>0 and cumulative totals worthless. The verdict
# logic lives in monitor-v2/lifecycle_gate.py so it is verified here with
# synthetic snapshots instead of waiting for a VPS.

GATE="$ROOT/monitor-v2/lifecycle_gate.py"
INTEG="$ROOT/tests/monitor-v2-integration-e1.sh"

section "G1: integration gate -- static contract"
if bash -n "$INTEG" 2>"$TMP/bashn.err"; then
    pass "integration script parses (bash -n)"
else
    fail "bash -n integration: $(cat "$TMP/bashn.err")"
fi
INTEG_SRC="$(cat "$INTEG")"
GATE_SRC="$(cat "$GATE")"
assert_contains "EXIT_PASS=0" "$INTEG_SRC" "integration declares EXIT_PASS=0"
assert_contains "EXIT_FAIL=1" "$INTEG_SRC" "integration declares EXIT_FAIL=1"
assert_contains "EXIT_INCONCLUSIVE=2" "$INTEG_SRC" "integration declares EXIT_INCONCLUSIVE=2"
assert_contains "REQUIRE_CLOSED" "$INTEG_SRC" "integration wires REQUIRE_CLOSED"
assert_contains "EXPECT_USER" "$INTEG_SRC" "integration wires EXPECT_USER"
assert_contains "EXPECT_INBOUND" "$INTEG_SRC" "integration wires EXPECT_INBOUND"
assert_contains "configuration error" "$INTEG_SRC" "invalid gate config is a configuration error"
assert_contains "baseline.json" "$INTEG_SRC" "integration captures a pre-window baseline"
assert_contains "lifecycle_gate.py" "$INTEG_SRC" "integration delegates verdicts to the gate evaluator"
assert_contains "no CLOSED/finalize evidence observed" "$INTEG_SRC" "integration carries the CLOSED fail reason"
assert_contains "recent_connections" "$GATE_SRC" "gate uses recent_connections ids (closed-id delta)"
assert_contains "uplink_total" "$GATE_SRC" "gate compares uplink totals (traffic delta)"
assert_contains "downlink_total" "$GATE_SRC" "gate compares downlink totals (traffic delta)"
assert_contains "EXIT_INCONCLUSIVE = 2" "$GATE_SRC" "gate evaluator declares the three-state contract"
assert_contains "expected USER was not observed" "$GATE_SRC" "gate hard-fails on a missing EXPECT_USER"
if "$PY" -m py_compile "$GATE" 2>>"$TMP/py.err"; then
    pass "py_compile lifecycle_gate.py"
else
    fail "py_compile lifecycle_gate.py: $(cat "$TMP/py.err")"
fi

section "G2: gate evaluator -- synthetic baseline/final verdicts (cases A-K)"
snap="$(PYTHONPATH="$ROOT/monitor-v2" "$PY" -c '
import json
from lifecycle_gate import (ConfigurationError, evaluate,
                            parse_expect_inbound, parse_require_closed)

def device(up, down, protos=("vless-in",), recent=(), active=0):
    status = "ACTIVE" if active else ("RECENT ACTIVITY" if recent else "IDLE")
    return {
        "status": status,
        "protocols": {p: {"active_connections": active,
                          "uplink_total": float(up),
                          "downlink_total": float(down)} for p in protos},
        "active_connections": active,
        "uplink_total": float(up), "downlink_total": float(down),
        "recent_sources": ["203.0.113.9:51000"] if recent else [],
        "recent_connections": [
            {"id": cid, "inbound": "vless-in", "source": "203.0.113.9:51000",
             "uplink_total": 0.0, "downlink_total": 0.0} for cid in recent],
    }

def snap(devices=(), stale=False):
    return {
        "stale": stale, "last_error": None, "batch_count": 1,
        "active_connections": sum(d[1]["active_connections"] for d in devices),
        "recently_closed": sum(len(d[1]["recent_connections"]) for d in devices),
        "devices": {name: dev for name, dev in devices},
    }

out = {}
empty = snap()
legacy_base = snap([("legacy", device(100, 50, recent=("old1",)))])

# case A: no traffic at all, no EXPECT_USER -> INCONCLUSIVE (exit 2)
r = evaluate(empty, snap(), "", "", False)
out["A_verdict"] = r["verdict"]; out["A_exit"] = r["exit"]

# case A2: devices present but pure historical replay -> INCONCLUSIVE
r = evaluate(legacy_base, snap([("legacy", device(100, 50, recent=("old1",)))]),
             "", "", False)
out["A2_verdict"] = r["verdict"]

# case B: EXPECT_USER=legacy, devices empty -> FAIL (never INCONCLUSIVE)
r = evaluate(empty, snap(), "legacy", "", False)
out["B_verdict"] = r["verdict"]; out["B_reason"] = r["reason"]

# case B2: EXPECT_USER set, other devices seen, legacy missing -> FAIL
r = evaluate(empty, snap([("vmix-01", device(10, 5))]), "legacy", "", False)
out["B2_verdict"] = r["verdict"]

# case C: legacy gains traffic, REQUIRE_CLOSED=0 -> PASS (exit 0)
r = evaluate(legacy_base,
             snap([("legacy", device(250, 80, recent=("old1",), active=1))]),
             "legacy", "", False)
out["C_verdict"] = r["verdict"]; out["C_exit"] = r["exit"]

# case C2: only downlink moves -> the traffic delta still counts
r = evaluate(snap([("legacy", device(100, 50))]),
             snap([("legacy", device(100, 55, active=1))]), "legacy", "", False)
out["C2_verdict"] = r["verdict"]

# case D: traffic moved but REQUIRE_CLOSED=1 and no new closed id -> FAIL
r = evaluate(legacy_base,
             snap([("legacy", device(250, 80, recent=("old1",), active=1))]),
             "legacy", "", True)
out["D_verdict"] = r["verdict"]; out["D_reason"] = r["reason"]

# case D2: closed ids replayed unchanged never satisfy REQUIRE_CLOSED
r = evaluate(snap([("legacy", device(100, 50, recent=("old1", "old2")))]),
             snap([("legacy", device(250, 80, recent=("old1", "old2")))]),
             "legacy", "", True)
out["D2_verdict"] = r["verdict"]; out["D2_reason"] = r["reason"]

# case E: traffic + a NEW closed id -> PASS with REQUIRE_CLOSED=1 (exit 0)
r = evaluate(legacy_base,
             snap([("legacy", device(250, 80, recent=("old1", "new9")))]),
             "legacy", "", True)
out["E_verdict"] = r["verdict"]; out["E_exit"] = r["exit"]

# case E2: new closed id but zero traffic delta -> the traffic gate still fails
r = evaluate(legacy_base,
             snap([("legacy", device(100, 50, recent=("old1", "new9")))]),
             "legacy", "", True)
out["E2_verdict"] = r["verdict"]

# case F: EXPECT_INBOUND gate -- missing tag FAILs, present tag passes
r = evaluate(snap([("legacy", device(100, 50))]),
             snap([("legacy", device(250, 80, active=1))]),
             "legacy", "hy2-in", False)
out["F_verdict"] = r["verdict"]
r = evaluate(snap([("legacy", device(100, 50))]),
             snap([("legacy", device(250, 80, protos=("vless-in", "hy2-in"), active=1))]),
             "legacy", "hy2-in", False)
out["F2_verdict"] = r["verdict"]

# case G: an unexpected inbound tag fails the vless-in/hy2-in allowlist
r = evaluate(snap([("legacy", device(100, 50, protos=("vless-in", "socks-in")))]),
             snap([("legacy", device(250, 80, protos=("vless-in", "socks-in"), active=1))]),
             "legacy", "", False)
out["G_verdict"] = r["verdict"]

# case H: stale final snapshot -> FAIL even with a traffic delta
r = evaluate(snap([("legacy", device(100, 50))]),
             snap([("legacy", device(250, 80))], stale=True),
             "legacy", "", False)
out["H_verdict"] = r["verdict"]

# case I: stale baseline -> FAIL before anything else
r = evaluate(snap(stale=True), snap([("legacy", device(250, 80))]),
             "legacy", "", False)
out["I_verdict"] = r["verdict"]

# case J: gate configuration errors
try:
    parse_require_closed("2"); out["J_verdict"] = "NO-ERROR"
except ConfigurationError:
    out["J_verdict"] = "ConfigurationError"
try:
    parse_require_closed(2); out["J2_verdict"] = "NO-ERROR"
except ConfigurationError:
    out["J2_verdict"] = "ConfigurationError"
try:
    parse_expect_inbound("trojan-in"); out["J3_verdict"] = "NO-ERROR"
except ConfigurationError:
    out["J3_verdict"] = "ConfigurationError"
out["J4_verdict"] = str(parse_require_closed("1") is True
                        and parse_require_closed("0") is False)

# case K: without EXPECT_USER, real in-window activity is judged, not skipped
r = evaluate(empty, snap([("legacy", device(0, 5, recent=("new1",)))]),
             "", "", False)
out["K_verdict"] = r["verdict"]; out["K_exit"] = r["exit"]

# case K2: a new closed id with zero traffic still fails the traffic gate
r = evaluate(empty, snap([("legacy", device(0, 0, recent=("new1",)))]),
             "", "", False)
out["K2_verdict"] = r["verdict"]

print(json.dumps(out))
')"
assert_eq "$(snap_field "$snap" 'snap["A_verdict"]')" "INCONCLUSIVE" "case A: no traffic, no EXPECT_USER -> INCONCLUSIVE"
assert_eq "$(snap_field "$snap" 'snap["A_exit"]')" "2" "case A exits 2 (INCONCLUSIVE is never PASS)"
assert_eq "$(snap_field "$snap" 'snap["A2_verdict"]')" "INCONCLUSIVE" "case A2: replay-only devices, zero delta -> INCONCLUSIVE"
assert_eq "$(snap_field "$snap" 'snap["B_verdict"]')" "FAIL" "case B: EXPECT_USER + empty devices -> FAIL (never INCONCLUSIVE)"
assert_eq "$(snap_field "$snap" 'snap["B_reason"]')" "EXPECT_USER legacy not observed" "case B reason names the missing USER"
assert_eq "$(snap_field "$snap" 'snap["B2_verdict"]')" "FAIL" "case B2: EXPECT_USER missing among other devices -> FAIL"
assert_eq "$(snap_field "$snap" 'snap["C_verdict"]')" "PASS" "case C: new traffic, REQUIRE_CLOSED=0 -> PASS"
assert_eq "$(snap_field "$snap" 'snap["C_exit"]')" "0" "case C exits 0"
assert_eq "$(snap_field "$snap" 'snap["C2_verdict"]')" "PASS" "case C2: downlink-only movement counts as traffic delta"
assert_eq "$(snap_field "$snap" 'snap["D_verdict"]')" "FAIL" "case D: REQUIRE_CLOSED=1 without a new closed id -> FAIL"
assert_contains "no CLOSED/finalize evidence observed" "$snap" "case D reason is the CLOSED evidence failure"
assert_eq "$(snap_field "$snap" 'snap["D2_verdict"]')" "FAIL" "case D2: replayed closed ids alone never satisfy REQUIRE_CLOSED"
assert_contains "no CLOSED/finalize evidence observed" "$snap" "case D2 reason is the CLOSED evidence failure"
assert_eq "$(snap_field "$snap" 'snap["E_verdict"]')" "PASS" "case E: traffic + new closed id -> PASS"
assert_eq "$(snap_field "$snap" 'snap["E_exit"]')" "0" "case E exits 0"
assert_eq "$(snap_field "$snap" 'snap["E2_verdict"]')" "FAIL" "case E2: new closed id without traffic still fails the traffic gate"
assert_eq "$(snap_field "$snap" 'snap["F_verdict"]')" "FAIL" "case F: EXPECT_INBOUND=hy2-in not observed -> FAIL"
assert_eq "$(snap_field "$snap" 'snap["F2_verdict"]')" "PASS" "case F2: EXPECT_INBOUND=hy2-in observed -> PASS"
assert_eq "$(snap_field "$snap" 'snap["G_verdict"]')" "FAIL" "case G: unexpected inbound tag fails the allowlist"
assert_eq "$(snap_field "$snap" 'snap["H_verdict"]')" "FAIL" "case H: stale final -> FAIL even with traffic"
assert_eq "$(snap_field "$snap" 'snap["I_verdict"]')" "FAIL" "case I: stale baseline -> FAIL"
assert_eq "$(snap_field "$snap" 'snap["J_verdict"]')" "ConfigurationError" "case J: REQUIRE_CLOSED=2 is a configuration error"
assert_eq "$(snap_field "$snap" 'snap["J2_verdict"]')" "ConfigurationError" "case J2: REQUIRE_CLOSED=2 (int) is a configuration error"
assert_eq "$(snap_field "$snap" 'snap["J3_verdict"]')" "ConfigurationError" "case J3: EXPECT_INBOUND=trojan-in is a configuration error"
assert_eq "$(snap_field "$snap" 'snap["J4_verdict"]')" "True" "case J4: REQUIRE_CLOSED 1/0 parse to True/False"
assert_eq "$(snap_field "$snap" 'snap["K_verdict"]')" "PASS" "case K: no EXPECT_USER, real in-window activity -> PASS"
assert_eq "$(snap_field "$snap" 'snap["K_exit"]')" "0" "case K exits 0"
assert_eq "$(snap_field "$snap" 'snap["K2_verdict"]')" "FAIL" "case K2: zero-traffic window (id only) still fails the traffic gate"

section "G3: integration script -- configuration gate runs before SKIP"
integ_out="$(REQUIRE_CLOSED=2 bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "REQUIRE_CLOSED=2 -> configuration error exits 1"
assert_contains "configuration error" "$integ_out" "REQUIRE_CLOSED=2 reported as a configuration error"
assert_not_contains "SKIP" "$integ_out" "gate config validated BEFORE the environment SKIP"
integ_out="$(EXPECT_INBOUND=trojan-in bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "EXPECT_INBOUND=trojan-in -> configuration error exits 1"
assert_contains "configuration error" "$integ_out" "EXPECT_INBOUND=trojan-in reported as a configuration error"
integ_out="$(SING_BOX_BIN=/nonexistent-sing-box REQUIRE_CLOSED=1 EXPECT_USER=legacy bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "gates set + missing binary -> strict canary FAIL (never SKIP)"
assert_contains "strict canary" "$integ_out" "strict gate run reports the strict canary failure"

section "G4: gate evaluator CLI -- file inputs and exit codes"
printf '%s' '{"stale": false, "recently_closed": 1, "active_connections": 0, "devices": {"legacy": {"status": "RECENT ACTIVITY", "uplink_total": 100, "downlink_total": 50, "protocols": {"vless-in": {}}, "active_connections": 0, "recent_connections": [{"id": "old1", "inbound": "vless-in", "source": "203.0.113.9:51000", "uplink_total": 0.0, "downlink_total": 0.0}]}}}' > "$TMP/gate-base.json"
printf '%s' '{"stale": false, "recently_closed": 1, "active_connections": 1, "devices": {"legacy": {"status": "ACTIVE", "uplink_total": 250, "downlink_total": 80, "protocols": {"vless-in": {}}, "active_connections": 1, "recent_connections": [{"id": "old1", "inbound": "vless-in", "source": "203.0.113.9:51000", "uplink_total": 0.0, "downlink_total": 0.0}]}}}' > "$TMP/gate-final.json"
"$PY" "$GATE" --baseline "$TMP/gate-base.json" --final "$TMP/gate-final.json" \
    --expect-user legacy --require-closed 0 >"$TMP/gate-cli.txt" 2>&1
assert_eq "$?" "0" "CLI: traffic delta without REQUIRE_CLOSED exits 0"
assert_contains "traffic delta observed" "$(cat "$TMP/gate-cli.txt")" "CLI: check lines are replayed by the integration script"
"$PY" "$GATE" --baseline "$TMP/gate-base.json" --final "$TMP/gate-final.json" \
    --expect-user legacy --require-closed 1 >"$TMP/gate-cli2.txt" 2>&1
assert_eq "$?" "1" "CLI: REQUIRE_CLOSED=1 without new closed ids exits 1"
"$PY" "$GATE" --baseline "$TMP/gate-base.json" --final "$TMP/gate-base.json" \
    --require-closed 0 >"$TMP/gate-cli3.txt" 2>&1
assert_eq "$?" "2" "CLI: nothing observed in-window exits 2 (INCONCLUSIVE)"
"$PY" "$GATE" --baseline "$TMP/gate-base.json" --final "$TMP/gate-final.json" \
    --require-closed 2 >/dev/null 2>&1
assert_eq "$?" "1" "CLI: REQUIRE_CLOSED=2 is a configuration error (exit 1)"

section "G5: inbound-scoped evidence -- USER + INBOUND (cases L1-L4 + combo)"
snap="$(PYTHONPATH="$ROOT/monitor-v2" "$PY" -c '
import json
from lifecycle_gate import evaluate, scope_recent_ids, scope_totals

def duo(vless_up, vless_down, hy2_up, hy2_down,
        vless_recent=(), hy2_recent=(), vless_active=0, hy2_active=0):
    def proto(up, down, active):
        return {"active_connections": active,
                "uplink_total": float(up), "downlink_total": float(down)}
    recents = ([{"id": cid, "inbound": "vless-in", "source": "203.0.113.9:51000",
                 "uplink_total": 0.0, "downlink_total": 0.0}
                for cid in vless_recent]
               + [{"id": cid, "inbound": "hy2-in", "source": "203.0.113.9:51001",
                   "uplink_total": 0.0, "downlink_total": 0.0}
                  for cid in hy2_recent])
    status = "ACTIVE" if (vless_active or hy2_active) else \
        ("RECENT ACTIVITY" if recents else "IDLE")
    return {
        "status": status,
        "protocols": {"vless-in": proto(vless_up, vless_down, vless_active),
                      "hy2-in": proto(hy2_up, hy2_down, hy2_active)},
        "active_connections": vless_active + hy2_active,
        "uplink_total": float(vless_up + hy2_up),
        "downlink_total": float(vless_down + hy2_down),
        "recent_sources": ["203.0.113.9:51000", "203.0.113.9:51001"] if recents else [],
        "recent_connections": recents,
    }

def snap(devices=(), stale=False):
    return {
        "stale": stale, "last_error": None, "batch_count": 1,
        "active_connections": sum(d[1]["active_connections"] for d in devices),
        "recently_closed": sum(len(d[1]["recent_connections"]) for d in devices),
        "devices": {name: dev for name, dev in devices},
    }

out = {}
base = snap([("legacy", duo(100, 50, 200, 60))])

# scope helper contract itself (the user asked these signatures explicitly)
out["S_totals_hy2"] = str(scope_totals(base, "legacy", "hy2-in"))
out["S_totals_user"] = str(scope_totals(base, "legacy", ""))
hy2_final = snap([("legacy", duo(100, 50, 260, 66, vless_recent=("v1",), hy2_recent=("h9",)))])
out["S_ids_hy2"] = json.dumps(sorted(scope_recent_ids(hy2_final, "legacy", "hy2-in")))
out["S_ids_all"] = json.dumps(sorted(scope_recent_ids(hy2_final, "legacy", "")))

# L1: EXPECT_INBOUND=hy2-in but only vless-in grew traffic -> FAIL
final = snap([("legacy", duo(1100, 50, 200, 60, vless_recent=("v1",)))])
r = evaluate(base, final, "legacy", "hy2-in", True)
out["L1_verdict"] = r["verdict"]; out["L1_reason"] = r["reason"]

# L2: only a vless-in CLOSED, no traffic anywhere -> FAIL
final = snap([("legacy", duo(100, 50, 200, 60, vless_recent=("v1",)))])
r = evaluate(base, final, "legacy", "hy2-in", True)
out["L2_verdict"] = r["verdict"]; out["L2_reason"] = r["reason"]

# L2b: hy2 traffic grows, but the ONLY new closed id is vless-in -> FAIL
# (a sibling-protocol closure must never satisfy the hy2 REQUIRE_CLOSED gate)
final = snap([("legacy", duo(100, 50, 260, 66, vless_recent=("v1",)))])
r = evaluate(base, final, "legacy", "hy2-in", True)
out["L2b_verdict"] = r["verdict"]; out["L2b_reason"] = r["reason"]
out["L2b_closed_fail"] = any(
    status == "FAIL" and text.startswith("no CLOSED/finalize evidence observed")
    for status, text in r["lines"])

# L3: hy2-in traffic delta + hy2-in new CLOSED -> PASS
final = snap([("legacy", duo(100, 50, 260, 66, hy2_recent=("h9",)))])
r = evaluate(base, final, "legacy", "hy2-in", True)
out["L3_verdict"] = r["verdict"]; out["L3_exit"] = r["exit"]

# L4: vless-in traffic delta + vless-in new CLOSED -> PASS
final = snap([("legacy", duo(1100, 55, 200, 60, vless_recent=("v1",)))])
r = evaluate(base, final, "legacy", "vless-in", True)
out["L4_verdict"] = r["verdict"]; out["L4_exit"] = r["exit"]

# combo: same USER owns both protocols; vless-in did +1000 bytes and closed
# id v1 while hy2-in did NOTHING in the window
combo = snap([("legacy", duo(1100, 50, 200, 60, vless_recent=("v1",)))])
r = evaluate(base, combo, "legacy", "hy2-in", True)
out["C_hy2_verdict"] = r["verdict"]; out["C_hy2_reason"] = r["reason"]
r = evaluate(base, combo, "legacy", "vless-in", True)
out["C_vless_verdict"] = r["verdict"]; out["C_vless_exit"] = r["exit"]

print(json.dumps(out))
')"
assert_eq "$(snap_field "$snap" 'snap["S_totals_hy2"]')" "(200.0, 60.0)" "scope_totals(hy2-in) reads ONLY the hy2-in protocol totals"
assert_eq "$(snap_field "$snap" 'snap["S_totals_user"]')" "(300.0, 110.0)" "scope_totals without inbound keeps the USER aggregate"
assert_eq "$(snap_field "$snap" 'snap["S_ids_hy2"]')" '["h9"]' "scope_recent_ids(hy2-in) drops the vless-in closure"
assert_eq "$(snap_field "$snap" 'snap["S_ids_all"]')" '["h9", "v1"]' "scope_recent_ids without inbound keeps both closures"
assert_eq "$(snap_field "$snap" 'snap["L1_verdict"]')" "FAIL" "L1: EXPECT_INBOUND=hy2-in with only vless-in traffic -> FAIL"
assert_contains "no traffic delta beyond baseline" "$snap" "L1 fails the hy2-scoped traffic gate"
assert_contains "uplink 200->200" "$snap" "L1 delta numbers are hy2-in scoped (vless growth invisible)"
assert_eq "$(snap_field "$snap" 'snap["L2_verdict"]')" "FAIL" "L2: only a vless-in CLOSED, no traffic -> FAIL"
assert_contains "no traffic delta beyond baseline" "$snap" "L2 fails the hy2-scoped traffic gate"
assert_eq "$(snap_field "$snap" 'snap["L2b_verdict"]')" "FAIL" "L2b: hy2 traffic but only a vless-in CLOSED -> FAIL"
assert_contains "no lifecycle evidence observed" "$snap" "L2b hy2 scope shows no lifecycle of its own"
assert_eq "$(snap_field "$snap" 'snap["L2b_closed_fail"]')" "True" "L2b: vless-in closure cannot satisfy the hy2 REQUIRE_CLOSED gate"
assert_eq "$(snap_field "$snap" 'snap["L3_verdict"]')" "PASS" "L3: hy2-in traffic + hy2-in CLOSED -> PASS"
assert_eq "$(snap_field "$snap" 'snap["L3_exit"]')" "0" "L3 exits 0"
assert_eq "$(snap_field "$snap" 'snap["L4_verdict"]')" "PASS" "L4: vless-in traffic + vless-in CLOSED -> PASS"
assert_eq "$(snap_field "$snap" 'snap["L4_exit"]')" "0" "L4 exits 0"
assert_eq "$(snap_field "$snap" 'snap["C_hy2_verdict"]')" "FAIL" "combo: vless-in growth cannot make the hy2-in canary pass"
assert_contains "uplink 200->200" "$snap" "combo reason shows hy2-in scoped zero delta"
assert_eq "$(snap_field "$snap" 'snap["C_vless_verdict"]')" "PASS" "combo: same evidence passes the vless-in canary"
assert_eq "$(snap_field "$snap" 'snap["C_vless_exit"]')" "0" "combo vless-in exits 0"

section "G6: strict canary environment gating (L5-L8) -- no SKIP for gated runs"
printf '#!/usr/bin/env true\n' > "$TMP/dummy-sing-box"
chmod +x "$TMP/dummy-sing-box"
DEAD_URL="http://127.0.0.1:1"
integ_out="$(SING_BOX_BIN=/nonexistent-sing-box bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "0" "L5: no gates + no sing-box -> SKIP exit 0"
assert_contains "SKIP" "$integ_out" "L5 reports SKIP"
integ_out="$(SING_BOX_BIN=/nonexistent-sing-box EXPECT_USER=legacy bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "L6: EXPECT_USER + no sing-box -> FAIL exit 1"
assert_contains "strict canary" "$integ_out" "L6 reports the strict canary failure"
integ_out="$(SING_BOX_BIN=/nonexistent-sing-box EXPECT_INBOUND=hy2-in bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "L7: EXPECT_INBOUND + no sing-box -> FAIL exit 1"
assert_contains "strict canary" "$integ_out" "L7 reports the strict canary failure"
integ_out="$(SING_BOX_BIN="$TMP/dummy-sing-box" REQUIRE_CLOSED=1 API_URL="$DEAD_URL" bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "1" "L8: REQUIRE_CLOSED=1 + API unreachable -> FAIL exit 1"
assert_contains "strict canary" "$integ_out" "L8 reports the strict canary failure"
integ_out="$(SING_BOX_BIN="$TMP/dummy-sing-box" API_URL="$DEAD_URL" bash "$INTEG" 2>&1)"
integ_rc=$?
assert_eq "$integ_rc" "0" "no gates + dummy binary + API unreachable -> SKIP exit 0"
assert_contains "SKIP" "$integ_out" "observational run still SKIPs on a dead API"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d (expected pass=%d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '  RESULT: FAILED (failures, or a section did not run)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
