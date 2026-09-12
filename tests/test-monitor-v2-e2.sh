#!/usr/bin/env bash
# Monitor v2 Phase E2 regression tests -- read-only web dashboard + access control.
#
# Every HTTP assertion runs against a REAL loopback server (stdlib
# http.server + the SnapshotBroker) with the client socket bound to a
# controlled 127.0.0.x source address, so the whitelist gate is exercised
# exactly as a remote caller would hit it. "Non-whitelisted IP" tests use
# source addresses like 127.0.0.5 (the loopback implicit-allow covers ONLY
# 127.0.0.1/::1). CLI assertions run the real webapp.py subprocess.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-python3}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export WEBAPP="$ROOT/monitor-v2/webapp.py"
export STATIC_DIR="$ROOT/monitor-v2/web/static"

PASS=0
FAIL=0
# The gate at the bottom fails unless exactly this many assertions ran AND
# passed, so unreachable sections can never fake success.
EXPECTED_PASS=182
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if printf '%s' "$2" | grep -qF "$1"; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if printf '%s' "$2" | grep -qF "$1"; then fail "$3 (forbidden: $1)"; else pass "$3"; fi; }

section "static checks"
WEB_PY="$ROOT/monitor-v2/web/__init__.py $ROOT/monitor-v2/web/access.py $ROOT/monitor-v2/web/auth.py $ROOT/monitor-v2/web/broker.py $ROOT/monitor-v2/web/recovery.py $ROOT/monitor-v2/web/server.py $ROOT/monitor-v2/web/storage.py $ROOT/monitor-v2/webapp.py"
if "$PY" -m py_compile $WEB_PY 2>"$TMP/py.err"; then
    pass "py_compile web backend"
else
    fail "py_compile web backend: $(cat "$TMP/py.err")"
fi
if node --check "$ROOT/monitor-v2/web/static/app.js" 2>"$TMP/js.err" 2>&1; then
    pass "node --check app.js"
else
    fail "node --check app.js: $(cat "$TMP/js.err")"
fi
STATIC_SRC="$(cat "$ROOT/monitor-v2/web/static/index.html" "$ROOT/monitor-v2/web/static/app.js" "$ROOT/monitor-v2/web/static/style.css")"
SERVER_SRC="$(cat $WEB_PY)"
assert_not_contains 'OFFLINE' "$STATIC_SRC" "frontend never shows OFFLINE"
assert_not_contains 'Tunnel Down' "$STATIC_SRC" "frontend never shows Tunnel Down"
assert_not_contains 'OFFLINE' "$SERVER_SRC" "backend never emits OFFLINE"
assert_not_contains 'Tunnel Down' "$SERVER_SRC" "backend never emits Tunnel Down"
assert_not_contains 'sbconfig' "$SERVER_SRC" "web code never touches sbconfig_server.json"
XFF_READS="$(printf %s "$SERVER_SRC" | grep -E 'headers\.get\("X-(Forwarded-For|Real-IP)' || true)"
assert_eq "$XFF_READS" "" "server never reads X-Forwarded-For / X-Real-IP"
EXTERNAL_REFS="$(printf '%s' "$STATIC_SRC" | grep -oE 'https?://[^"'"'"' )<>]+' | grep -v 'www.w3.org' || true)"
assert_eq "$EXTERNAL_REFS" "" "static assets are fully local (no CDN/external URLs)"
CLOSE_REFS="$(printf '%s' "$SERVER_SRC" | grep -iE 'close.?connection|DELETE.*connections|connections.*close' | grep -v 'close_connection\|close its own generator\|browser disconnect\|ConnectionResetError\|BrokenPipeError\|_drain\|Connection: close\|close_connection =' || true)"
assert_eq "$CLOSE_REFS" "" "no close-connection endpoint anywhere in the server"

# -- shared python harness ---------------------------------------------------
cat > "$TMP/e2_harness.py" <<'HARNESS_EOF'
#!/usr/bin/env python3
"""Phase E2 harness: real loopback servers, controlled source addresses."""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import http.client

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
STATIC_DIR = os.environ["STATIC_DIR"]

from collector import Collector
from web.access import AccessPolicy, host_entry_for_ip, parse_network
from web.auth import AuthStore
from web.broker import SnapshotBroker
from web.server import MonitorWebApp, build_server

PASSWORD = "test-password-e2-1"
NEW_PASSWORD = "new-password-e2-2"
RECOVERY_KEY = "recovery-key-e2-test-9"


def raises_value_error(func, value):
    try:
        func(value)
    except ValueError:
        return True
    except Exception:
        return False
    return False


def make_stack(data_dir, *, password=None, recovery=None, whitelist=(),
               poll=0.2, url="http://127.0.0.1:1", session_ttl=3600.0,
               batches=None):
    policy = AccessPolicy(data_dir)
    for entry in whitelist:
        policy.add(entry)
    auth = None
    if password is not None or recovery is not None:
        auth = AuthStore(data_dir, session_ttl=session_ttl)
        if password is not None:
            auth.set_password(password)
        if recovery is not None:
            auth.set_recovery_key(recovery)

    def factory():
        for batch in (batches or []):
            yield batch
        raise RuntimeError("stream EOF")

    collector = Collector(url=url, stream_factory=factory)
    broker = SnapshotBroker(collector, poll_seconds=poll)
    broker.start()
    app = MonitorWebApp(broker=broker, access=policy,
                        static_dir=STATIC_DIR, auth=auth)
    srv = build_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.35)
    return {"srv": srv, "port": port, "policy": policy, "auth": auth,
            "broker": broker, "data_dir": data_dir}


def req(port, source, method, path, headers=None, body=None, timeout=5.0):
    s = socket.socket()
    s.bind((source, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.sock = s
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return {"status": resp.status,
            "headers": {k.lower(): v for k, v in resp.getheaders()},
            "body": data.decode("utf-8", "replace")}


def json_body(payload):
    return json.dumps(payload).encode("utf-8")


def login(port, source, password=PASSWORD, extra=None):
    headers = {"Content-Type": "application/json"}
    if extra:
        headers.update(extra)
    return req(port, source, "POST", "/api/v1/login", headers,
               json_body({"password": password}))


def cookie_of(response):
    return response["headers"].get("set-cookie", "").split(";")[0]


RESET_BATCH = {"reset": True, "events": [
    {"type": "NEW", "id": "c1", "connection": {
        "id": "c1", "user": "legacy", "inbound": "vless-in",
        "inbound_type": "vless", "network": "tcp",
        "source": "203.0.113.9:51000", "destination": "example.com:443",
        "created_at": 1700000000000,
        "uplink_total": 100, "downlink_total": 200}}]}


def group_whitelist():
    out = {}
    out["invalid_cidr_33"] = raises_value_error(parse_network, "10.0.0.0/33")
    out["invalid_garbage"] = raises_value_error(parse_network, "not-an-ip")
    out["invalid_empty"] = raises_value_error(parse_network, "   ")
    out["invalid_ipv6_slash_129"] = raises_value_error(
        parse_network, "2001:db8::1/129")
    out["valid_host4"] = parse_network("1.2.3.4") == "1.2.3.4/32"
    out["valid_cidr4"] = parse_network("10.10.10.99/24") == "10.10.10.0/24"
    out["valid_host6"] = parse_network("2001:db8::1") == "2001:db8::1/128"
    out["valid_cidr6"] = parse_network("2001:db8::5/64") == "2001:db8::/64"

    policy = AccessPolicy(tempfile.mkdtemp())
    out["default_empty"] = policy.entries() == ()
    out["loopback_implicit"] = policy.is_allowed("127.0.0.1")
    out["loopback6_implicit"] = policy.is_allowed("::1")
    out["public_denied_default"] = not policy.is_allowed("203.0.113.9")
    out["other_127_denied_default"] = not policy.is_allowed("127.0.0.5")

    persist_dir = tempfile.mkdtemp()
    policy_p = AccessPolicy(persist_dir)
    policy_p.add("203.0.113.9")
    out["host_add_canonical"] = policy_p.entries() == ("203.0.113.9/32",)
    out["host_allowed_after_add"] = policy_p.is_allowed("203.0.113.9")
    out["host_persisted"] = AccessPolicy(persist_dir).is_allowed("203.0.113.9")

    cidr = AccessPolicy(tempfile.mkdtemp())
    cidr.add("10.10.10.0/24")
    out["cidr_member_allowed"] = cidr.is_allowed("10.10.10.77")
    out["cidr_outside_denied"] = not cidr.is_allowed("10.10.11.77")
    out["cidr_persisted"] = AccessPolicy(
        cidr.data_dir).entries() == ("10.10.10.0/24",)

    v6 = AccessPolicy(tempfile.mkdtemp())
    v6.add("2001:db8::/64")
    out["v6_member_allowed"] = v6.is_allowed("2001:db8::5")
    out["v6_outside_denied"] = not v6.is_allowed("2001:db9::5")
    out["v6_mapped_v4_host"] = v6.is_allowed("::ffff:203.0.113.9") is False
    host4 = AccessPolicy(tempfile.mkdtemp())
    host4.add("203.0.113.9/32")
    out["v4_mapped_of_whitelisted"] = host4.is_allowed("::ffff:203.0.113.9")
    out["host_entry_v6"] = host_entry_for_ip("2001:db8::1") == "2001:db8::1/128"
    out["host_entry_v4"] = host_entry_for_ip("1.2.3.4") == "1.2.3.4/32"
    out["covers_inside"] = cidr.covers("10.10.10.0/24", "10.10.10.3")
    out["covers_outside"] = not cidr.covers("10.10.10.0/24", "10.10.11.3")
    out["remove_works"] = cidr.remove("10.10.10.0/24") \
        and cidr.entries() == ()
    out["remove_missing_false"] = not cidr.remove("10.10.10.0/24")
    out["corrupt_file_fails_closed"] = _corrupt_fails_closed()
    return out


def _corrupt_fails_closed():
    directory = tempfile.mkdtemp()
    with open(os.path.join(directory, "access.json"), "w") as handle:
        handle.write('{"whitelist": ["10.9.9.0/24", "garbage!!", 3]}')
    policy = AccessPolicy(directory)
    return policy.entries() == ("10.9.9.0/24",) \
        and not policy.is_allowed("203.0.113.9")


def group_gate():
    out = {}
    stack = make_stack(tempfile.mkdtemp())
    port = stack["port"]
    out["root_loopback_200"] = req(port, "127.0.0.1", "GET", "/")["status"] == 200
    out["static_js_200"] = req(port, "127.0.0.1", "GET",
                               "/static/app.js")["status"] == 200
    out["nonwhitelisted_root_403"] = req(port, "127.0.0.5", "GET",
                                         "/")["status"] == 403
    out["nonwhitelisted_session_403"] = req(port, "127.0.0.5", "GET",
                                            "/api/v1/session")["status"] == 403
    out["nonwhitelisted_snapshot_403"] = req(
        port, "127.0.0.5", "GET", "/api/v1/snapshot")["status"] == 403
    out["nonwhitelisted_stream_403"] = req(port, "127.0.0.5", "GET",
                                           "/api/v1/stream")["status"] == 403
    out["nonwhitelisted_login_403"] = req(
        port, "127.0.0.5", "POST", "/api/v1/login",
        {"Content-Type": "application/json"},
        json_body({"password": "x"}))["status"] == 403
    spoof = req(port, "127.0.0.5", "GET", "/",
                {"X-Forwarded-For": "127.0.0.1"})
    out["xff_cannot_bypass"] = spoof["status"] == 403
    spoof2 = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                 {"X-Forwarded-For": "1.2.3.4",
                  "X-Real-IP": "::1"})
    out["xff_and_realip_cannot_bypass"] = spoof2["status"] == 403
    out["recovery_page_exempt_200"] = req(port, "127.0.0.5", "GET",
                                          "/recovery")["status"] == 200
    rec = req(port, "127.0.0.5", "POST", "/api/v1/recovery",
              {"Content-Type": "application/json"},
              json_body({"key": "whatever"}))
    out["recovery_api_exempt_reaches_handler"] = rec["status"] == 503
    headers = req(port, "127.0.0.1", "GET", "/")["headers"]
    out["csp_header"] = headers.get("content-security-policy") == \
        "default-src 'self'"
    out["nosniff_header"] = headers.get("x-content-type-options") == "nosniff"
    out["referrer_header"] = headers.get("referrer-policy") == "no-referrer"
    out["frame_deny_header"] = headers.get("x-frame-options") == "DENY"
    out["no_store_header"] = "no-store" in headers.get("cache-control", "")
    denied_headers = req(port, "127.0.0.5", "GET", "/")["headers"]
    out["csp_on_403"] = denied_headers.get(
        "content-security-policy") == "default-src 'self'"
    out["traversal_404"] = req(port, "127.0.0.1", "GET",
                               "/static/../webapp.py")["status"] == 404
    out["unknown_path_404"] = req(port, "127.0.0.1", "GET",
                                  "/nope")["status"] == 404

    stack2 = make_stack(tempfile.mkdtemp(), whitelist=["127.0.0.5/32"])
    port2 = stack2["port"]
    out["whitelisted_root_200"] = req(port2, "127.0.0.5", "GET",
                                      "/")["status"] == 200
    info = json.loads(req(port2, "127.0.0.5", "GET",
                          "/api/v1/session")["body"])
    out["session_info_current_ip"] = info["current_ip"] == "127.0.0.5"
    out["session_info_unauthenticated"] = info["authenticated"] is False
    out["session_info_snapshot_still_gated"] = req(
        port2, "127.0.0.5", "GET", "/api/v1/snapshot")["status"] == 401
    return out


def group_auth():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]
    wrong = login(port, "127.0.0.5", "definitely-wrong")
    out["wrong_login_401"] = wrong["status"] == 401
    out["no_cookie_on_failed_login"] = "set-cookie" not in wrong["headers"]
    good = login(port, "127.0.0.5")
    out["good_login_200"] = good["status"] == 200
    set_cookie = good["headers"].get("set-cookie", "")
    out["cookie_httponly"] = "HttpOnly" in set_cookie
    out["cookie_secure"] = "Secure" in set_cookie
    out["cookie_samesite_strict"] = "SameSite=Strict" in set_cookie
    cookie = cookie_of(good)
    out["snapshot_unauthenticated_401"] = req(
        port, "127.0.0.5", "GET", "/api/v1/snapshot")["status"] == 401
    snap_resp = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                    {"Cookie": cookie})
    out["snapshot_authenticated_200"] = snap_resp["status"] == 200
    out["password_never_returned"] = PASSWORD not in snap_resp["body"]
    session_resp = req(port, "127.0.0.5", "GET", "/api/v1/session",
                       {"Cookie": cookie})
    out["session_info_authenticated"] = json.loads(
        session_resp["body"])["authenticated"] is True
    with open(os.path.join(stack["data_dir"], "auth.json")) as handle:
        auth_raw = handle.read()
    out["auth_hash_only_scrypt"] = "scrypt" in auth_raw \
        and "salt" in auth_raw
    out["auth_no_plaintext"] = PASSWORD not in auth_raw
    out["access_json_exists"] = os.path.exists(
        os.path.join(stack["data_dir"], "access.json"))

    stack_x = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         whitelist=["127.0.0.5/32"], session_ttl=0.4)
    cookie_x = cookie_of(login(stack_x["port"], "127.0.0.5"))
    time.sleep(0.9)
    out["expired_session_401"] = req(
        stack_x["port"], "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie_x})["status"] == 401

    stack_r = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         whitelist=["127.0.0.5/32", "127.0.0.6/32"])
    statuses = [login(stack_r["port"], "127.0.0.6", "bad-%d" % i)["status"]
                for i in range(6)]
    out["rate_limit_first_five_401"] = statuses[:5] == [401] * 5
    out["rate_limit_sixth_429"] = statuses[5] == 429

    stack_p = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         whitelist=["127.0.0.5/32"])
    port_p = stack_p["port"]
    cookie_a = cookie_of(login(port_p, "127.0.0.5"))
    cookie_b = cookie_of(login(port_p, "127.0.0.5"))
    change = {"Content-Type": "application/json"}
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            dict(change, Cookie=cookie_a),
            json_body({"current_password": "wrong",
                       "new_password": NEW_PASSWORD}))
    out["pw_change_wrong_current_403"] = r["status"] == 403
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            dict(change, Cookie=cookie_a),
            json_body({"current_password": PASSWORD,
                       "new_password": "short"}))
    out["pw_change_too_short_400"] = r["status"] == 400
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            dict(change, Cookie=cookie_a),
            json_body({"current_password": PASSWORD,
                       "new_password": NEW_PASSWORD}))
    out["pw_change_ok_200"] = r["status"] == 200
    out["other_session_invalidated"] = req(
        port_p, "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie_b})["status"] == 401
    out["own_session_kept"] = req(
        port_p, "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie_a})["status"] == 200
    out["new_password_accepted"] = login(
        port_p, "127.0.0.5", NEW_PASSWORD)["status"] == 200
    out["old_password_rejected"] = login(
        port_p, "127.0.0.5", PASSWORD)["status"] == 401
    return out


def group_stream():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"], poll=0.2,
                       batches=[RESET_BATCH])
    port = stack["port"]
    out["stream_unauthenticated_401"] = req(
        port, "127.0.0.5", "GET", "/api/v1/stream")["status"] == 401
    cookie = cookie_of(login(port, "127.0.0.5"))
    s = socket.socket()
    s.bind(("127.0.0.5", 0))
    s.settimeout(5.0)
    s.connect(("127.0.0.1", port))
    s.sendall(("GET /api/v1/stream HTTP/1.1\r\nHost: monitor\r\n"
               "Cookie: %s\r\n\r\n" % cookie).encode())
    buf = ""
    deadline = time.time() + 6
    while time.time() < deadline and "event: snapshot" not in buf:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk.decode("utf-8", "replace")
    s.close()
    out["stream_200_ok"] = buf.startswith("HTTP/1.1 200")
    out["stream_content_type_sse"] = "text/event-stream" in buf
    out["stream_retry_hint"] = "retry:" in buf
    out["stream_snapshot_event"] = "event: snapshot" in buf
    data_lines = [line[6:] for line in buf.splitlines()
                  if line.startswith("data: ")]
    out["stream_data_is_e1_snapshot"] = bool(data_lines) and \
        "devices" in json.loads(data_lines[-1]) and \
        "connections" in json.loads(data_lines[-1])
    version_before = stack["broker"].snapshot_json()[0]
    time.sleep(1.2)
    version_after = stack["broker"].snapshot_json()[0]
    out["sse_disconnect_publisher_continues"] = version_after > version_before
    out["collector_thread_alive"] = \
        stack["broker"]._consumer_thread.is_alive()
    out["snapshot_after_disconnect_200"] = req(
        port, "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie})["status"] == 200
    snap = json.loads(req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                          {"Cookie": cookie})["body"])
    rows = snap.get("connections", [])
    c1 = [row for row in rows if row["id"] == "c1"]
    out["connections_rows_present"] = len(c1) == 1 \
        and c1[0]["state"] == "ACTIVE" \
        and c1[0]["user"] == "legacy" \
        and c1[0]["inbound"] == "vless-in" \
        and c1[0]["destination"] == "example.com:443" \
        and c1[0]["uplink_total"] == 100.0
    out["snapshot_totals_untouched"] = \
        snap["devices"]["legacy"]["uplink_total"] == 100.0
    return out


def group_stale():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"], poll=0.15,
                       batches=[RESET_BATCH])
    port = stack["port"]
    time.sleep(0.9)  # consume the reset batch, then the stream dies
    cookie = cookie_of(login(port, "127.0.0.5"))
    snap = json.loads(req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                          {"Cookie": cookie})["body"])
    out["stale_flag_true"] = snap["stale"] is True
    out["stale_api_status"] = snap["api_status"] == "STALE"
    out["stale_web_status_healthy"] = snap["web_status"] == "HEALTHY"
    out["stale_state_preserved"] = \
        snap["devices"]["legacy"]["uplink_total"] == 100.0 \
        and snap["devices"]["legacy"]["downlink_total"] == 200.0
    out["stale_active_preserved"] = snap["active_connections"] == 1
    out["stale_no_fake_closed"] = "closed_at" not in json.dumps(
        snap["connections"]) or all(
            row["closed_at"] is None
            for row in snap["connections"] if row["state"] == "ACTIVE")
    out["stale_last_error_recorded"] = isinstance(
        snap.get("last_error"), str) and "EOF" in snap["last_error"]
    out["stale_last_success_recorded"] = bool(snap.get("last_success_at"))
    out["monitor_started_at_present"] = bool(
        snap.get("monitor_started_at"))
    out["snapshot_generated_at_present"] = bool(
        snap.get("snapshot_generated_at"))
    out["collector_uptime_present"] = isinstance(
        snap.get("collector_uptime_seconds"), (int, float))

    dead = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                      whitelist=["127.0.0.5/32"],
                      url="http://127.0.0.1:1")
    time.sleep(0.7)
    cookie_d = cookie_of(login(dead["port"], "127.0.0.5"))
    snap_d = json.loads(req(dead["port"], "127.0.0.5", "GET",
                            "/api/v1/snapshot",
                            {"Cookie": cookie_d})["body"])
    out["unreachable_api_stale"] = snap_d["stale"] is True
    out["unreachable_api_empty_not_invented"] = \
        snap_d["devices"] == {} and snap_d["active_connections"] == 0
    return out


def group_recovery():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY)
    port = stack["port"]
    out["recovery_page_nonwhitelisted_200"] = req(
        port, "127.0.0.6", "GET", "/recovery")["status"] == 200
    wrong = req(port, "127.0.0.6", "POST", "/api/v1/recovery",
                {"Content-Type": "application/json"},
                json_body({"key": "wrong-key"}))
    out["recovery_wrong_key_403"] = wrong["status"] == 403
    ok = req(port, "127.0.0.6", "POST", "/api/v1/recovery",
             {"Content-Type": "application/json"},
             json_body({"key": RECOVERY_KEY, "ip": "9.9.9.9",
                        "entry": "9.9.9.0/24"}))
    body = json.loads(ok["body"])
    out["recovery_ok_200"] = ok["status"] == 200
    out["recovery_adds_caller_only"] = body["entry"] == "127.0.0.6/32"
    out["recovery_ignores_supplied_ip"] = body["ip"] == "127.0.0.6"
    out["recovery_no_session_cookie"] = "set-cookie" not in ok["headers"]
    out["recovery_success_message"] = \
        "IP added. Please login normally." in ok["body"]
    out["recovery_whitelist_updated"] = \
        stack["policy"].entries() == ("127.0.0.6/32",)
    out["recovery_cannot_view_snapshot"] = req(
        port, "127.0.0.6", "GET", "/api/v1/snapshot")["status"] == 401
    out["recovery_cannot_view_whitelist"] = req(
        port, "127.0.0.6", "GET", "/api/v1/whitelist")["status"] == 401
    out["recovery_cannot_change_password"] = req(
        port, "127.0.0.6", "POST", "/api/v1/password",
        {"Content-Type": "application/json"},
        json_body({"current_password": "x",
                   "new_password": "y1234567"}))["status"] == 401
    again = req(port, "127.0.0.6", "POST", "/api/v1/recovery",
                {"Content-Type": "application/json"},
                json_body({"key": RECOVERY_KEY}))
    out["recovery_idempotent_200"] = again["status"] == 200

    stack_l = make_stack(tempfile.mkdtemp(), recovery=RECOVERY_KEY)
    statuses = [req(stack_l["port"], "127.0.0.7", "POST", "/api/v1/recovery",
                    {"Content-Type": "application/json"},
                    json_body({"key": "bad-%d" % i}))["status"]
                for i in range(4)]
    out["recovery_rate_limit"] = statuses == [403, 403, 403, 429]

    stack_r = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         recovery=RECOVERY_KEY,
                         whitelist=["127.0.0.5/32"])
    cookie = cookie_of(login(stack_r["port"], "127.0.0.5"))
    rot = {"Content-Type": "application/json", "Cookie": cookie}
    r = req(stack_r["port"], "127.0.0.5", "POST", "/api/v1/recovery/rotate",
            rot, json_body({"current_password": "wrong"}))
    out["rotate_wrong_password_403"] = r["status"] == 403
    r = req(stack_r["port"], "127.0.0.5", "POST", "/api/v1/recovery/rotate",
            rot, json_body({"current_password": PASSWORD}))
    out["rotate_ok_200"] = r["status"] == 200
    new_key = json.loads(r["body"]).get("recovery_key", "")
    out["rotate_new_key_differs"] = bool(new_key) and new_key != RECOVERY_KEY
    old = req(stack_r["port"], "127.0.0.8", "POST", "/api/v1/recovery",
              {"Content-Type": "application/json"},
              json_body({"key": RECOVERY_KEY}))
    out["rotate_old_key_rejected"] = old["status"] == 403
    new = req(stack_r["port"], "127.0.0.8", "POST", "/api/v1/recovery",
              {"Content-Type": "application/json"},
              json_body({"key": new_key}))
    out["rotate_new_key_adds_caller"] = new["status"] == 200 \
        and json.loads(new["body"])["entry"] == "127.0.0.8/32"
    return out


def group_endpoints():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"], batches=[RESET_BATCH])
    port = stack["port"]
    cookie = cookie_of(login(port, "127.0.0.5"))
    authed = {"Content-Type": "application/json", "Cookie": cookie}
    out["no_config_endpoint"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/config", authed,
                                    json_body({"anything": True}))["status"] == 404
    out["no_close_endpoint_delete"] = req(port, "127.0.0.5", "DELETE",
                                          "/api/v1/connections/abc",
                                          authed)["status"] == 404
    out["no_close_endpoint_post"] = req(port, "127.0.0.5", "POST",
                                        "/api/v1/connections/abc/close",
                                        authed)["status"] == 404
    out["no_reload_endpoint"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/reload", authed)["status"] == 404
    out["no_clients_endpoint"] = req(port, "127.0.0.5", "POST",
                                     "/api/v1/clients", authed,
                                     json_body({"user": "x"}))["status"] == 404
    out["unknown_get_404"] = req(port, "127.0.0.5", "GET",
                                 "/api/v1/nope")["status"] == 404
    snap_raw = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                   {"Cookie": cookie})["body"]
    out["no_offline_label"] = "OFFLINE" not in snap_raw
    out["no_tunnel_down_label"] = "Tunnel Down" not in snap_raw
    out["no_client_manager_fields"] = "password" not in json.dumps(
        list(json.loads(snap_raw).get("devices", {})))

    out["wl_add_invalid_400"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/whitelist", authed,
                                    json_body({"entry": "10.0.0.0/33"}))["status"] == 400
    out["wl_add_ok_200"] = req(port, "127.0.0.5", "POST", "/api/v1/whitelist",
                               authed,
                               json_body({"entry": "198.51.100.0/24"}))["status"] == 200
    out["wl_add_persisted"] = "198.51.100.0/24" in stack["policy"].entries()
    out["wl_remove_missing_404"] = req(port, "127.0.0.5", "POST",
                                       "/api/v1/whitelist/remove", authed,
                                       json_body({"entry": "203.0.113.1/32"}))["status"] == 404
    out["wl_remove_own_needs_confirm"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.5/32"}))["status"] == 409
    out["wl_remove_own_confirmed_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.5/32", "confirm": True}))["status"] == 200
    out["wl_remove_applied"] = req(port, "127.0.0.5", "GET",
                                   "/api/v1/whitelist",
                                   {"Cookie": cookie})["status"] == 403
    return out


GROUPS = {
    "whitelist": group_whitelist,
    "gate": group_gate,
    "auth": group_auth,
    "stream": group_stream,
    "stale": group_stale,
    "recovery": group_recovery,
    "endpoints": group_endpoints,
}

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        results = GROUPS[name]()
    except Exception as exc:  # noqa: BLE001 - surface harness errors as JSON
        results = {"_harness_error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(results, sort_keys=True))
HARNESS_EOF

run_group() {
    GROUP="$1"
    PYTHONPATH="$ROOT/monitor-v2" "$PY" "$TMP/e2_harness.py" "$GROUP" \
        > "$TMP/out-$GROUP.json" 2> "$TMP/err-$GROUP.log"
    if ! "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' \
        "$TMP/out-$GROUP.json" 2>/dev/null; then
        printf '{"_harness_error": "harness did not produce JSON"}' \
            > "$TMP/out-$GROUP.json"
        printf 'harness stderr:\n%s\n' "$(tail -5 "$TMP/err-$GROUP.log")" >&2
    fi
}

result() {
    "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$TMP/out-$GROUP.json" "$1" 2>/dev/null || printf 'EVAL-ERROR'
}

check() { assert_eq "$(result "$1")" "True" "$2"; }

section "W1: whitelist model (unit level)"
run_group "whitelist"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["invalid_cidr_33"]' "10.0.0.0/33 rejected"
check 'd["invalid_garbage"]' "garbage entry rejected"
check 'd["invalid_empty"]' "empty entry rejected"
check 'd["invalid_ipv6_slash_129"]' "/129 rejected"
check 'd["valid_host4"]' "1.2.3.4 canonicalizes to /32"
check 'd["valid_cidr4"]' "IPv4 CIDR canonicalized"
check 'd["valid_host6"]' "2001:db8::1 canonicalizes to /128"
check 'd["valid_cidr6"]' "IPv6 CIDR canonicalized"
check 'd["default_empty"]' "default whitelist is EMPTY"
check 'd["loopback_implicit"]' "127.0.0.1 implicitly allowed"
check 'd["loopback6_implicit"]' "::1 implicitly allowed"
check 'd["public_denied_default"]' "public IP denied by default"
check 'd["other_127_denied_default"]' "other 127.x addresses NOT implicitly allowed"
check 'd["host_add_canonical"]' "host entry stored as /32"
check 'd["host_allowed_after_add"]' "added host allowed"
check 'd["host_persisted"]' "whitelist persisted to access.json"
check 'd["cidr_member_allowed"]' "IPv4 CIDR member allowed"
check 'd["cidr_outside_denied"]' "IPv4 CIDR outsider denied"
check 'd["cidr_persisted"]' "CIDR persisted"
check 'd["v6_member_allowed"]' "IPv6 CIDR member allowed"
check 'd["v6_outside_denied"]' "IPv6 CIDR outsider denied"
check 'd["v6_mapped_v4_host"]' "IPv4-mapped wrapper does not sneak past a v6 net"
check 'd["v4_mapped_of_whitelisted"]' "IPv4-mapped IPv6 matches its v4 host entry"
check 'd["host_entry_v6"]' "recovery-style entry for v6 is /128"
check 'd["host_entry_v4"]' "recovery-style entry for v4 is /32"
check 'd["covers_inside"]' "covers() detects own-IP removals"
check 'd["covers_outside"]' "covers() ignores unrelated IPs"
check 'd["remove_works"]' "whitelist entry removable"
check 'd["remove_missing_false"]' "removing a missing entry reports False"
check 'd["corrupt_file_fails_closed"]' "corrupt access.json fails closed"

section "W2: HTTP gate order (whitelist first, real sockets)"
run_group "gate"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["root_loopback_200"]' "loopback reaches the shell"
check 'd["static_js_200"]' "local static assets served"
check 'd["nonwhitelisted_root_403"]' "non-whitelisted IP -> 403 on /"
check 'd["nonwhitelisted_session_403"]' "non-whitelisted IP -> 403 on session info"
check 'd["nonwhitelisted_snapshot_403"]' "non-whitelisted IP -> 403 on snapshot"
check 'd["nonwhitelisted_stream_403"]' "non-whitelisted IP -> 403 on SSE"
check 'd["nonwhitelisted_login_403"]' "non-whitelisted IP -> 403 even before login"
check 'd["xff_cannot_bypass"]' "X-Forwarded-For cannot bypass the whitelist"
check 'd["xff_and_realip_cannot_bypass"]' "X-Forwarded-For + X-Real-IP cannot bypass"
check 'd["recovery_page_exempt_200"]' "/recovery page is the whitelist exception"
check 'd["recovery_api_exempt_reaches_handler"]' "recovery API exempt (503 = unconfigured, not 403)"
check 'd["csp_header"]' "CSP: default-src 'self'"
check 'd["nosniff_header"]' "X-Content-Type-Options: nosniff"
check 'd["referrer_header"]' "Referrer-Policy: no-referrer"
check 'd["frame_deny_header"]' "X-Frame-Options: DENY"
check 'd["no_store_header"]' "Cache-Control: no-store"
check 'd["csp_on_403"]' "security headers present on denials too"
check 'd["traversal_404"]' "static path traversal blocked"
check 'd["unknown_path_404"]' "unknown paths 404"
check 'd["whitelisted_root_200"]' "whitelisted IP reaches the shell"
check 'd["session_info_current_ip"]' "session info reports the socket peer IP"
check 'd["session_info_unauthenticated"]' "session info shows unauthenticated"
check 'd["session_info_snapshot_still_gated"]' "whitelisted but unauthenticated -> 401 on snapshot"

section "W3: admin authentication"
run_group "auth"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["wrong_login_401"]' "invalid login fails"
check 'd["no_cookie_on_failed_login"]' "no cookie on failed login"
check 'd["good_login_200"]' "valid login succeeds"
check 'd["cookie_httponly"]' "cookie is HttpOnly"
check 'd["cookie_secure"]' "cookie is Secure"
check 'd["cookie_samesite_strict"]' "cookie is SameSite=Strict"
check 'd["snapshot_unauthenticated_401"]' "snapshot requires login"
check 'd["snapshot_authenticated_200"]' "session cookie opens the snapshot"
check 'd["password_never_returned"]' "password never returned in responses"
check 'd["session_info_authenticated"]' "session info reflects the login"
check 'd["auth_hash_only_scrypt"]' "auth.json stores a scrypt hash"
check 'd["auth_no_plaintext"]' "auth.json has NO plaintext password"
check 'd["access_json_exists"]' "access.json in the data dir"
check 'd["expired_session_401"]' "expired session rejected"
check 'd["rate_limit_first_five_401"]' "five bad logins -> 401"
check 'd["rate_limit_sixth_429"]' "sixth bad login -> 429 (IP rate limit)"
check 'd["pw_change_wrong_current_403"]' "password change re-verifies current password"
check 'd["pw_change_too_short_400"]' "password change enforces minimum length"
check 'd["pw_change_ok_200"]' "password change succeeds"
check 'd["other_session_invalidated"]' "password change invalidates other sessions"
check 'd["own_session_kept"]' "password change keeps the caller logged in"
check 'd["new_password_accepted"]' "new password authenticates"
check 'd["old_password_rejected"]' "old password rejected afterwards"

section "W4: SSE stream"
run_group "stream"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["stream_unauthenticated_401"]' "SSE requires a session"
check 'd["stream_200_ok"]' "SSE answers 200"
check 'd["stream_content_type_sse"]' "Content-Type: text/event-stream"
check 'd["stream_retry_hint"]' "SSE carries the reconnect hint"
check 'd["stream_snapshot_event"]' "SSE pushes snapshot events"
check 'd["stream_data_is_e1_snapshot"]' "SSE payload is the E1 snapshot (devices+connections)"
check 'd["sse_disconnect_publisher_continues"]' "browser disconnect does not stop the broker"
check 'd["collector_thread_alive"]' "collector thread survives client disconnects"
check 'd["snapshot_after_disconnect_200"]' "snapshot endpoint healthy after disconnect"
check 'd["connections_rows_present"]' "snapshot carries per-connection rows from E1"
check 'd["snapshot_totals_untouched"]' "totals come from E1 unchanged"

section "W5: stale semantics inherited from E1"
run_group "stale"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["stale_flag_true"]' "stream failure -> stale=true in the web snapshot"
check 'd["stale_api_status"]' "API chip degrades to STALE"
check 'd["stale_web_status_healthy"]' "web itself stays HEALTHY while stale"
check 'd["stale_state_preserved"]' "last state preserved (totals NOT zeroed)"
check 'd["stale_active_preserved"]' "active connections preserved (no fake CLOSED)"
check 'd["stale_no_fake_closed"]' "active rows never gain a closed_at"
check 'd["stale_last_error_recorded"]' "last_error surfaced (redacted) for the banner"
check 'd["stale_last_success_recorded"]' "last successful API event recorded"
check 'd["monitor_started_at_present"]' "monitor_started_at present"
check 'd["snapshot_generated_at_present"]' "snapshot_generated_at present"
check 'd["collector_uptime_present"]' "collector uptime present"
check 'd["unreachable_api_stale"]' "unreachable service.api -> stale"
check 'd["unreachable_api_empty_not_invented"]' "no devices invented when none were seen"

section "W6: recovery flow"
run_group "recovery"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["recovery_page_nonwhitelisted_200"]' "recovery page reachable without whitelist"
check 'd["recovery_wrong_key_403"]' "wrong recovery key rejected"
check 'd["recovery_ok_200"]' "correct recovery key accepted"
check 'd["recovery_adds_caller_only"]' "recovery adds ONLY the caller IP (/32)"
check 'd["recovery_ignores_supplied_ip"]' "client-supplied target IP ignored"
check 'd["recovery_no_session_cookie"]' "recovery never creates an admin session"
check 'd["recovery_success_message"]' "success message points back to login"
check 'd["recovery_whitelist_updated"]' "whitelist gained exactly the caller host entry"
check 'd["recovery_cannot_view_snapshot"]' "recovery cannot view the dashboard"
check 'd["recovery_cannot_view_whitelist"]' "recovery cannot view the whitelist"
check 'd["recovery_cannot_change_password"]' "recovery cannot change the password"
check 'd["recovery_idempotent_200"]' "repeated recovery with the same key stays 200"
check 'd["recovery_rate_limit"]' "recovery failures rate-limited (3x403 then 429)"
check 'd["rotate_wrong_password_403"]' "rotation re-verifies the password"
check 'd["rotate_ok_200"]' "rotation issues a new key"
check 'd["rotate_new_key_differs"]' "new key differs from the old one"
check 'd["rotate_old_key_rejected"]' "old key invalid after rotation"
check 'd["rotate_new_key_adds_caller"]' "new key adds the caller (/32)"

section "W7: read-only surface (no mutation endpoints)"
run_group "endpoints"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["no_config_endpoint"]' "no /api/v1/config endpoint"
check 'd["no_close_endpoint_delete"]' "no DELETE connection endpoint"
check 'd["no_close_endpoint_post"]' "no close-connection endpoint"
check 'd["no_reload_endpoint"]' "no reload endpoint"
check 'd["no_clients_endpoint"]' "no client management endpoint"
check 'd["unknown_get_404"]' "unknown API paths 404"
check 'd["no_offline_label"]' "snapshot JSON never contains OFFLINE"
check 'd["no_tunnel_down_label"]' "snapshot JSON never contains Tunnel Down"
check 'd["no_client_manager_fields"]' "no device names carry credential fields"
check 'd["wl_add_invalid_400"]' "invalid CIDR rejected at the API"
check 'd["wl_add_ok_200"]' "valid CIDR accepted"
check 'd["wl_add_persisted"]' "whitelist add persisted"
check 'd["wl_remove_missing_404"]' "removing unknown entry 404"
check 'd["wl_remove_own_needs_confirm"]' "removing own IP requires confirm"
check 'd["wl_remove_own_confirmed_200"]' "own-IP removal works with confirm"
check 'd["wl_remove_applied"]' "removed entry actually gates the caller again"

section "W8: setup + serve CLI (real subprocesses)"
SETUP_DIR="$TMP/cli-setup"
CLI_OUT="$(SSH_CONNECTION='203.0.113.9 55222 198.51.100.5 22' \
    "$PY" "$WEBAPP" setup --data-dir "$SETUP_DIR" --password 'cli-password-7' \
    --assume-yes 2>"$TMP/cli-err.log")"
assert_eq "$?" "0" "setup exits 0"
assert_contains "Current SSH client detected: 203.0.113.9" "$CLI_OUT" "setup detects the SSH client IP"
assert_contains "203.0.113.9/32" "$CLI_OUT" "setup offers+adds the /32 host entry"
assert_contains "Recovery key (shown ONCE" "$CLI_OUT" "setup prints the one-time recovery key"
assert_not_contains "cli-password-7" "$CLI_OUT" "setup never echoes the password"
RECOVERY_COUNT="$(printf '%s' "$CLI_OUT" | grep -cE '^    [A-Za-z0-9_-]{30,}$')"
assert_eq "$RECOVERY_COUNT" "1" "recovery key printed exactly once"
if grep -q '"whitelist": \[' "$SETUP_DIR/access.json" && \
   grep -q '203.0.113.9/32' "$SETUP_DIR/access.json"; then
    pass "access.json holds the SSH host entry"
else
    fail "access.json holds the SSH host entry"
fi
if grep -q 'scrypt' "$SETUP_DIR/auth.json" && \
   ! grep -q 'cli-password-7' "$SETUP_DIR/auth.json"; then
    pass "auth.json holds only the scrypt hash"
else
    fail "auth.json holds only the scrypt hash"
fi
CLI_OUT2="$(SSH_CONNECTION='203.0.113.9 55222 198.51.100.5 22' \
    "$PY" "$WEBAPP" setup --data-dir "$SETUP_DIR" \
    --password 'other-password-9' --assume-yes 2>/dev/null)"
assert_contains "already whitelisted" "$CLI_OUT2" "second setup is idempotent (whitelist)"
assert_contains "already configured" "$CLI_OUT2" "second setup is idempotent (password+recovery)"
SHORT_RC=0
"$PY" "$WEBAPP" setup --data-dir "$TMP/cli-short" --password short \
    --assume-yes >/dev/null 2>&1 || SHORT_RC=$?
assert_eq "$SHORT_RC" "2" "too-short password is a configuration error (exit 2)"

SERVE_DIR="$TMP/cli-serve"
SSH_CONNECTION='127.0.0.2 22 127.0.0.1 22' \
    "$PY" "$WEBAPP" setup --data-dir "$SERVE_DIR" --password 'serve-password-3' \
    --assume-yes >/dev/null 2>&1
SERVE_PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
"$PY" "$WEBAPP" serve --listen 127.0.0.1 --port "$SERVE_PORT" \
    --url http://127.0.0.1:1 --data-dir "$SERVE_DIR" \
    > "$TMP/serve.log" 2>&1 &
SERVE_PID=$!
SERVE_OK=0
for _ in $(seq 1 40); do
    if grep -q 'listening on' "$TMP/serve.log" 2>/dev/null; then SERVE_OK=1; break; fi
    sleep 0.25
done
assert_eq "$SERVE_OK" "1" "loopback serve starts (localhost canary form)"
assert_contains "loopback" "$(cat "$TMP/serve.log")" "serve reports loopback mode"
CURL_ROOT="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SERVE_PORT/")"
assert_eq "$CURL_ROOT" "200" "curl GET / on the real server -> 200"
CURL_SNAP="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SERVE_PORT/api/v1/snapshot")"
assert_eq "$CURL_SNAP" "401" "snapshot without login -> 401"
CURL_LOGIN="$(curl -s -D - -o /dev/null -X POST "http://127.0.0.1:$SERVE_PORT/api/v1/login" \
    -H 'Content-Type: application/json' -d '{"password": "serve-password-3"}')"
assert_contains "200 OK" "$CURL_LOGIN" "curl login succeeds on the real server"
assert_contains "HttpOnly" "$CURL_LOGIN" "real server sets HttpOnly"
assert_contains "SameSite=Strict" "$CURL_LOGIN" "real server sets SameSite=Strict"
SERVE_COOKIE="$(printf '%s' "$CURL_LOGIN" | grep -i '^set-cookie:' | head -1 | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1)"
CURL_STALE=""
for _ in $(seq 1 40); do
    CURL_STALE="$(curl -s -H "Cookie: $SERVE_COOKIE" "http://127.0.0.1:$SERVE_PORT/api/v1/snapshot")"
    if printf %s "$CURL_STALE" | grep -qF '"stale": true'; then break; fi
    sleep 0.5
done
assert_contains '"stale": true' "$CURL_STALE" "dead service.api -> dashboard shows stale=true"
assert_contains '"api_status": "STALE"' "$CURL_STALE" "api_status STALE for the banner"
kill "$SERVE_PID" 2>/dev/null
wait "$SERVE_PID" 2>/dev/null

REMOTE_PORT="$(expr "$SERVE_PORT" + 7)"
REMOTE_RC=0
"$PY" "$WEBAPP" serve --listen 127.0.0.2 --port "$REMOTE_PORT" \
    --data-dir "$SERVE_DIR" >/dev/null 2>&1 || REMOTE_RC=$?
assert_eq "$REMOTE_RC" "2" "remote listener without full config REFUSES to start"
REMOTE_MSG="$(SINGBOX_MONITOR_DATA_DIR="$TMP/empty-remote" "$PY" "$WEBAPP" serve \
    --listen 127.0.0.2 --port "$REMOTE_PORT" 2>&1 || true)"
assert_contains "refusing to start remote listener" "$REMOTE_MSG" "refusal is explicit"
assert_contains "TLS is not configured" "$REMOTE_MSG" "refusal names the missing TLS"
assert_contains "the IP whitelist is empty" "$REMOTE_MSG" "refusal names the empty whitelist"
assert_contains "the admin password is not configured" "$REMOTE_MSG" "refusal names the missing password"
assert_contains "the recovery key is not configured" "$REMOTE_MSG" "refusal names the missing recovery key"

if [ -x "$(command -v openssl)" ]; then
    pass "openssl available for self-signed TLS"
    mkdir -p "$TMP/tls"
    (cd "$TMP/tls" && MSYS_NO_PATHCONV=1 openssl req -x509 \
        -newkey rsa:2048 -keyout monitor.key -out monitor.crt -days 2 \
        -nodes -subj "/CN=monitor.local" >/dev/null 2>&1)
    TLS_PORT="$(expr "$SERVE_PORT" + 13)"
    "$PY" "$WEBAPP" serve --listen 127.0.0.2 --port "$TLS_PORT" \
        --tls-cert "$TMP/tls/monitor.crt" --tls-key "$TMP/tls/monitor.key" \
        --url http://127.0.0.1:1 --data-dir "$SERVE_DIR" \
        > "$TMP/serve-tls.log" 2>&1 &
    TLS_PID=$!
    TLS_OK=0
    for _ in $(seq 1 40); do
        if grep -q 'listening on' "$TMP/serve-tls.log" 2>/dev/null; then TLS_OK=1; break; fi
        sleep 0.25
    done
    assert_eq "$TLS_OK" "1" "remote listener starts with full configuration"
    assert_contains "remote+TLS" "$(cat "$TMP/serve-tls.log")" "remote mode reports remote+TLS"
    TLS_CODE="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.2:$TLS_PORT/")"
    assert_eq "$TLS_CODE" "200" "HTTPS (self-signed) serves the shell"
    TLS_403="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.2:$TLS_PORT/api/v1/snapshot")"
    assert_eq "$TLS_403" "401" "HTTPS snapshot still requires login"
    kill "$TLS_PID" 2>/dev/null
    wait "$TLS_PID" 2>/dev/null
else
    fail "openssl available for self-signed TLS (environment problem)"
fi

printf '\n== summary ==\n'
printf '  pass=%d fail=%d (expected pass=%d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '  RESULT: FAILED (failures, or a section did not run)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
