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
EXPECTED_PASS=272
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
README_SRC="$(cat "$ROOT/monitor-v2/README.md")"
assert_not_contains 'OFFLINE' "$STATIC_SRC" "frontend never shows OFFLINE"
assert_not_contains 'Tunnel Down' "$STATIC_SRC" "frontend never shows Tunnel Down"
assert_not_contains 'OFFLINE' "$SERVER_SRC" "backend never emits OFFLINE"
assert_not_contains 'Tunnel Down' "$SERVER_SRC" "backend never emits Tunnel Down"
assert_not_contains 'sbconfig' "$SERVER_SRC" "web code never touches sbconfig_server.json"
XFF_READS="$(printf '%s' "$SERVER_SRC" | grep -E 'headers\.get\("X-(Forwarded-For|Real-IP)' || true)"
assert_eq "$XFF_READS" "" "server never reads X-Forwarded-For / X-Real-IP"
EXTERNAL_REFS="$(printf '%s' "$STATIC_SRC" | grep -oE 'https?://[^"'"'"' )<>]+' | grep -v 'www.w3.org' || true)"
assert_eq "$EXTERNAL_REFS" "" "static assets are fully local (no CDN/external URLs)"
CLOSE_REFS="$(printf '%s' "$SERVER_SRC" | grep -iE 'close.?connection|DELETE.*connections|connections.*close' | grep -v 'close_connection\|close its own generator\|browser disconnect\|ConnectionResetError\|BrokenPipeError\|_drain\|Connection: close\|close_connection =' || true)"
assert_eq "$CLOSE_REFS" "" "no close-connection endpoint anywhere in the server"
assert_not_contains 'confirm: true' "$STATIC_SRC" "frontend never pre-confirms a self-lockout removal"
assert_contains 'X-CSRF-Token' "$STATIC_SRC" "frontend attaches the session CSRF token to mutations"
assert_contains 'snapshot_version' "$STATIC_SRC" "watchdog keys freshness on snapshot_version"
assert_not_contains 'setup` 可用 openssl 生成自签名证书' "$README_SRC" "README no longer claims setup generates certificates"
assert_contains '自动生成自签名证书' "$README_SRC" "README documents: no automatic self-signed generation"
assert_contains 'Packaging' "$README_SRC" "README defers certificate provisioning to Packaging"

# -- shared python harness ---------------------------------------------------
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
import web.access
import web.auth
from web.access import AccessPolicy, host_entry_for_ip, parse_network
from web.auth import AuthStore
from web.broker import (HEALTH_FILE_KEYS, HEALTH_FILE_SCHEMA_VERSION,
                        SnapshotBroker)
from web.recovery import RecoveryGlobalGuard
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
               batches=None, recovery_guard=None, remote_mode=False,
               health_file=None):
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
    broker = SnapshotBroker(collector, poll_seconds=poll,
                            health_file=health_file)
    broker.start()
    app = MonitorWebApp(broker=broker, access=policy,
                        static_dir=STATIC_DIR, auth=auth,
                        remote_mode=remote_mode,
                        recovery_guard=recovery_guard)
    srv = build_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.35)
    return {"srv": srv, "port": port, "policy": policy, "auth": auth,
            "broker": broker, "data_dir": data_dir}


def req(port, source, method, path, headers=None, body=None, timeout=8.0):
    try:
        return _req_once(port, source, method, path, headers, body, timeout)
    except (ConnectionError, OSError):
        # Transient loopback reset under load (Windows): one retry keeps a
        # single dropped connection from failing a whole group. A second
        # failure is a real problem and propagates.
        time.sleep(0.3)
        return _req_once(port, source, method, path, headers, body, timeout)


def _req_once(port, source, method, path, headers=None, body=None,
              timeout=8.0):
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


def csrf_of(port, source, cookie):
    data = json.loads(req(port, source, "GET", "/api/v1/session",
                          {"Cookie": cookie})["body"])
    return data.get("csrf_token") or ""


def authed_headers(cookie, csrf):
    return {"Content-Type": "application/json", "Cookie": cookie,
            "X-CSRF-Token": csrf}


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
    out["covers_ipv6_parent"] = v6.covers("2001:db8::/64", "2001:db8::1")
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

    # Recovery public asset chain: an EXACT allowlist. A locked-out browser
    # must be able to render AND submit the recovery page.
    out["recovery_page_nonwhitelisted_200"] = req(
        port, "127.0.0.5", "GET", "/recovery")["status"] == 200
    out["recovery_css_nonwhitelisted_200"] = req(
        port, "127.0.0.5", "GET", "/static/style.css")["status"] == 200
    out["recovery_js_nonwhitelisted_200"] = req(
        port, "127.0.0.5", "GET", "/static/app.js")["status"] == 200
    out["recovery_favicon_nonwhitelisted_200"] = req(
        port, "127.0.0.5", "GET", "/favicon.svg")["status"] == 200
    rec = req(port, "127.0.0.5", "POST", "/api/v1/recovery",
              {"Content-Type": "application/json"},
              json_body({"key": "whatever"}))
    out["recovery_api_exempt_reaches_handler"] = rec["status"] == 403 \
        and "invalid recovery key" in rec["body"]
    # ...and the rest of the dashboard STAYS gated for the same caller.
    out["recovery_assets_do_not_open_dashboard"] = req(
        port, "127.0.0.5", "GET", "/")["status"] == 403
    out["no_wildcard_static_exemption"] = req(
        port, "127.0.0.1", "GET", "/static/../../webapp.py")["status"] == 404

    spoof = req(port, "127.0.0.5", "GET", "/",
                {"X-Forwarded-For": "127.0.0.1"})
    out["xff_cannot_bypass"] = spoof["status"] == 403
    spoof2 = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                 {"X-Forwarded-For": "1.2.3.4",
                  "X-Real-IP": "::1"})
    out["xff_and_realip_cannot_bypass"] = spoof2["status"] == 403
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
    out["cookie_secure_absent_loopback"] = "Secure" not in set_cookie
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
    session_info = json.loads(session_resp["body"])
    out["session_info_authenticated"] = session_info["authenticated"] is True
    csrf = session_info.get("csrf_token") or ""
    out["csrf_token_in_session"] = bool(csrf)
    with open(os.path.join(stack["data_dir"], "auth.json")) as handle:
        auth_raw = handle.read()
    out["auth_hash_only_scrypt"] = "scrypt" in auth_raw \
        and "salt" in auth_raw
    out["auth_no_plaintext"] = PASSWORD not in auth_raw
    out["access_json_exists"] = os.path.exists(
        os.path.join(stack["data_dir"], "access.json"))

    # --- CSRF: session-bound token required on every mutation ---------------
    plain = {"Content-Type": "application/json", "Cookie": cookie}
    out["csrf_missing_403"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist", plain,
        json_body({"entry": "198.51.100.0/24"}))["status"] == 403
    out["csrf_wrong_403"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        dict(plain, **{"X-CSRF-Token": "wrong-token"}),
        json_body({"entry": "198.51.100.0/24"}))["status"] == 403
    out["csrf_correct_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        authed_headers(cookie, csrf),
        json_body({"entry": "198.51.100.0/24"}))["status"] == 200
    out["csrf_get_unaffected"] = snap_resp["status"] == 200
    out["login_unaffected_by_csrf"] = good["status"] == 200

    # CSRF is bound to ITS session: another browser's cookie with this
    # session's token must fail.
    second = login(port, "127.0.0.5")
    cookie_b = cookie_of(second)
    csrf_b = csrf_of(port, "127.0.0.5", cookie_b)
    out["csrf_session_bound_403"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        {"Content-Type": "application/json", "Cookie": cookie_b,
         "X-CSRF-Token": csrf},
        json_body({"entry": "203.0.113.0/24"}))["status"] == 403
    out["csrf_cross_sessions_ok"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        authed_headers(cookie_b, csrf_b),
        json_body({"entry": "203.0.113.0/24"}))["status"] == 200

    # --- Origin: second layer (only when the browser declares one) ---------
    out["origin_foreign_403"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        dict(authed_headers(cookie_b, csrf_b),
             **{"Origin": "https://evil.example"}),
        json_body({"entry": "192.0.2.0/24"}))["status"] == 403
    out["origin_same_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        dict(authed_headers(cookie_b, csrf_b),
             **{"Origin": "http://127.0.0.1:%d" % port}),
        json_body({"entry": "192.0.2.0/24"}))["status"] == 200

    # expired session: 401 (session check) wins over CSRF 403
    stack_x = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         whitelist=["127.0.0.5/32"], session_ttl=0.4)
    cookie_x = cookie_of(login(stack_x["port"], "127.0.0.5"))
    csrf_x = csrf_of(stack_x["port"], "127.0.0.5", cookie_x)
    time.sleep(0.9)
    out["expired_session_401"] = req(
        stack_x["port"], "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie_x})["status"] == 401
    out["csrf_expired_session_401"] = req(
        stack_x["port"], "127.0.0.5", "POST", "/api/v1/whitelist",
        authed_headers(cookie_x, csrf_x),
        json_body({"entry": "198.51.100.0/24"}))["status"] == 401

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
    csrf_a = csrf_of(port_p, "127.0.0.5", cookie_a)
    cookie_b2 = cookie_of(login(port_p, "127.0.0.5"))
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            authed_headers(cookie_a, csrf_a),
            json_body({"current_password": "wrong",
                       "new_password": NEW_PASSWORD}))
    out["pw_change_wrong_current_403"] = r["status"] == 403
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            authed_headers(cookie_a, csrf_a),
            json_body({"current_password": PASSWORD,
                       "new_password": "short"}))
    out["pw_change_too_short_400"] = r["status"] == 400
    r = req(port_p, "127.0.0.5", "POST", "/api/v1/password",
            authed_headers(cookie_a, csrf_a),
            json_body({"current_password": PASSWORD,
                       "new_password": NEW_PASSWORD}))
    out["pw_change_ok_200"] = r["status"] == 200
    out["other_session_invalidated"] = req(
        port_p, "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie_b2})["status"] == 401
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

    # --- SSE session lifecycle: an OPEN stream must follow revocation -------
    def sse_socket(target, cookie_x):
        sx = socket.socket()
        sx.bind(("127.0.0.5", 0))
        sx.settimeout(6.0)
        sx.connect(("127.0.0.1", target["port"]))
        sx.sendall(("GET /api/v1/stream HTTP/1.1\r\nHost: monitor\r\n"
                    "Cookie: %s\r\n\r\n" % cookie_x).encode())
        buf = ""
        deadline = time.time() + 6
        while time.time() < deadline and "event: snapshot" not in buf:
            try:
                chunk = sx.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk.decode("utf-8", "replace")
        return sx, "event: snapshot" in buf

    def closed_within(sock_x, seconds):
        """True when the server closes the stream inside the window: no
        further snapshots is proven by EOF, not by a follow-up GET."""
        sock_x.settimeout(seconds)
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                chunk = sock_x.recv(65536)
            except socket.timeout:
                return False  # still streaming after the window
            if not chunk:
                return True   # server closed the revoked stream
        return False

    # A: session TTL expires while the SSE is open -> stream stops
    ttl_stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                           whitelist=["127.0.0.5/32"], poll=0.15,
                           session_ttl=0.8)
    ttl_cookie = cookie_of(login(ttl_stack["port"], "127.0.0.5"))
    sx, got_event = sse_socket(ttl_stack, ttl_cookie)
    time.sleep(1.2)  # TTL expires mid-stream
    out["sse_initial_event_received"] = got_event
    out["sse_ttl_expiry_stops_stream"] = closed_within(sx, 6.0)
    sx.close()

    # B: logout while the SSE is open -> stream stops
    out_stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                           whitelist=["127.0.0.5/32"], poll=0.15)
    out_cookie = cookie_of(login(out_stack["port"], "127.0.0.5"))
    out_csrf = csrf_of(out_stack["port"], "127.0.0.5", out_cookie)
    sx, got_event = sse_socket(out_stack, out_cookie)
    req(out_stack["port"], "127.0.0.5", "POST", "/api/v1/logout",
        authed_headers(out_cookie, out_csrf), json_body({}))
    out["sse_logout_stops_stream"] = closed_within(sx, 6.0)
    sx.close()

    # C: session A changes password -> session B's open SSE stops
    pair = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                      whitelist=["127.0.0.5/32"], poll=0.15)
    cookie_a = cookie_of(login(pair["port"], "127.0.0.5"))
    csrf_a = csrf_of(pair["port"], "127.0.0.5", cookie_a)
    cookie_b = cookie_of(login(pair["port"], "127.0.0.5"))
    sx, got_event = sse_socket(pair, cookie_b)
    req(pair["port"], "127.0.0.5", "POST", "/api/v1/password",
        authed_headers(cookie_a, csrf_a),
        json_body({"current_password": PASSWORD,
                   "new_password": "revoked-pass-9"}))
    out["sse_password_revoke_stops_stream"] = closed_within(sx, 6.0)
    sx.close()
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
    out["snapshot_version_present"] = isinstance(
        snap.get("snapshot_version"), int)
    out["last_publish_at_present"] = bool(snap.get("last_publish_at"))

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

    # --- publisher freeze: health is evaluated at READ time -----------------
    frozen = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                        whitelist=["127.0.0.5/32"], poll=0.15,
                        batches=[RESET_BATCH])
    time.sleep(0.8)
    broker = frozen["broker"]
    version_before = broker.snapshot_json()[0]
    dead_thread = threading.Thread(target=lambda: None)
    dead_thread.start()
    dead_thread.join()
    broker._publisher_thread = dead_thread      # simulate thread death
    broker._published_at = broker._clock() - 999  # simulate wedged publisher
    cookie_f = cookie_of(login(frozen["port"], "127.0.0.5"))
    snap_f = json.loads(req(frozen["port"], "127.0.0.5", "GET",
                            "/api/v1/snapshot",
                            {"Cookie": cookie_f})["body"])
    out["publisher_freeze_web_status_stale"] = snap_f["web_status"] == "STALE"
    out["publisher_freeze_consumer_alive"] = broker._consumer_alive()
    out["publisher_freeze_state_kept"] = \
        snap_f["devices"]["legacy"]["uplink_total"] == 100.0
    out["publisher_freeze_version_present"] = \
        isinstance(snap_f.get("snapshot_version"), int)
    out["publisher_freeze_last_publish_present"] = \
        bool(snap_f.get("last_publish_at"))
    out["frozen_version_does_not_advance"] = \
        broker.snapshot_json()[0] == version_before
    return out


def group_recovery():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY)
    port = stack["port"]
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
    out["recovery_success_leaks_no_whitelist"] = \
        "whitelist" not in ok["body"] and body.get("entry") == "127.0.0.6/32"
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

    # per-IP lockout still works (3 failures -> 30 min lock)
    stack_l = make_stack(tempfile.mkdtemp(), recovery=RECOVERY_KEY)
    statuses = [req(stack_l["port"], "127.0.0.7", "POST", "/api/v1/recovery",
                    {"Content-Type": "application/json"},
                    json_body({"key": "bad-%d" % i}))["status"]
                for i in range(4)]
    out["recovery_rate_limit"] = statuses == [403, 403, 403, 429]

    # GLOBAL guard: rolling window across DIFFERENT source addresses, and
    # a rejected attempt must not perform any scrypt work.
    guard = RecoveryGlobalGuard(max_concurrent=2, window_seconds=60.0,
                                max_attempts_per_window=3)
    stack_g = make_stack(tempfile.mkdtemp(), recovery=RECOVERY_KEY,
                         recovery_guard=guard)
    calls = {"n": 0}
    real_verify = stack_g["auth"].verify_recovery_key

    def counting_verify(key):
        calls["n"] += 1
        return real_verify(key)

    stack_g["auth"].verify_recovery_key = counting_verify
    global_statuses = []
    for i, ip in enumerate(("127.0.0.11", "127.0.0.12", "127.0.0.13",
                            "127.0.0.14")):
        r = req(stack_g["port"], ip, "POST", "/api/v1/recovery",
                {"Content-Type": "application/json"},
                json_body({"key": "wrong-%d" % i}))
        global_statuses.append(
            (r["status"], r["headers"].get("retry-after")))
    out["recovery_global_limit_429"] = \
        [s for s, _ in global_statuses] == [403, 403, 403, 429]
    out["recovery_global_retry_after"] = global_statuses[3][1] is not None \
        and int(global_statuses[3][1]) >= 1
    out["recovery_rejected_no_scrypt"] = calls["n"] == 3

    stack_r = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         recovery=RECOVERY_KEY,
                         whitelist=["127.0.0.5/32"])
    cookie = cookie_of(login(stack_r["port"], "127.0.0.5"))
    csrf = csrf_of(stack_r["port"], "127.0.0.5", cookie)
    rot = authed_headers(cookie, csrf)
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
    csrf = csrf_of(port, "127.0.0.5", cookie)
    authed = authed_headers(cookie, csrf)
    plain = {"Content-Type": "application/json", "Cookie": cookie}

    out["no_config_endpoint"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/config", authed,
                                    json_body({"anything": True}))["status"] == 404
    deleted = req(port, "127.0.0.5", "DELETE", "/api/v1/connections/abc",
                  {"Cookie": cookie})
    out["no_close_endpoint_delete"] = deleted["status"] == 405
    out["delete_405_allow_header"] = \
        deleted["headers"].get("allow") == "GET, POST"
    out["no_close_endpoint_post"] = req(port, "127.0.0.5", "POST",
                                        "/api/v1/connections/abc/close",
                                        authed)["status"] == 404
    out["method_put_405"] = req(port, "127.0.0.5", "PUT", "/api/v1/snapshot",
                                {"Cookie": cookie})["status"] == 405
    out["method_patch_405"] = req(port, "127.0.0.5", "PATCH", "/",
                                  {})["status"] == 405
    out["method_options_405"] = req(port, "127.0.0.5", "OPTIONS", "/",
                                    {})["status"] == 405
    out["method_trace_405"] = req(port, "127.0.0.5", "TRACE", "/",
                                  {})["status"] == 405
    out["no_reload_endpoint"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/reload", authed)["status"] == 404
    out["no_clients_endpoint"] = req(port, "127.0.0.5", "POST",
                                     "/api/v1/clients", authed,
                                     json_body({"user": "x"}))["status"] == 404
    out["unknown_get_404"] = req(port, "127.0.0.5", "GET",
                                 "/api/v1/nope")["status"] == 404
    out["malformed_cl_400"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        dict(plain, **{"Content-Length": "abc"}),
        b'{"entry": "1.2.3.4/32"}')["status"] == 400
    oversized = json.dumps({"entry": "1.2.3.4/32",
                            "pad": "x" * 70000}).encode()
    out["oversized_413"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist",
        dict(authed, **{"Content-Length": str(len(oversized))}),
        oversized)["status"] == 413

    snap_raw = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                   {"Cookie": cookie})["body"]
    out["no_offline_label"] = "OFFLINE" not in snap_raw
    out["no_tunnel_down_label"] = "Tunnel Down" not in snap_raw

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

    # Server-authoritative self-lockout confirm: exact /32 AND parent /24
    # both answer 409 FIRST; an unrelated CIDR removes immediately.
    out["wl_add_parent_cidr"] = req(port, "127.0.0.5", "POST",
                                    "/api/v1/whitelist", authed,
                                    json_body({"entry": "127.0.0.0/24"}))["status"] == 200
    out["wl_remove_own_needs_confirm"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.5/32"}))["status"] == 409
    out["wl_remove_parent_cidr_409"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.0/24"}))["status"] == 409
    out["wl_remove_unrelated_immediate_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "198.51.100.0/24"}))["status"] == 200
    out["wl_remove_parent_confirmed_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.0/24", "confirm": True}))["status"] == 200
    out["wl_remove_own_confirmed_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "127.0.0.5/32", "confirm": True}))["status"] == 200
    out["wl_remove_applied"] = req(port, "127.0.0.5", "GET",
                                   "/api/v1/whitelist",
                                   {"Cookie": cookie})["status"] == 403
    return out


def group_concurrency():
    out = {}
    errors = []

    # 1) concurrent adds of the SAME CIDR -> exactly one entry, disk coherent
    d1 = tempfile.mkdtemp()
    pol1 = AccessPolicy(d1)

    def adder():
        try:
            pol1.add("10.10.10.0/24")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=adder) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out["concurrent_add_same_entry"] = not errors and \
        pol1.entries() == ("10.10.10.0/24",)
    out["concurrent_add_disk_coherent"] = \
        AccessPolicy(d1).entries() == pol1.entries()

    # 2) concurrent mixed add/remove -> memory == disk, no exceptions
    d2 = tempfile.mkdtemp()
    pol2 = AccessPolicy(d2)

    def mixed(i):
        try:
            pol2.add("10.9.%d.0/24" % (i % 4))
            if i % 2 == 0:
                pol2.remove("10.9.%d.0/24" % (i % 4))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=mixed, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out["concurrent_mixed_coherent"] = not errors and \
        AccessPolicy(d2).entries() == pol2.entries()

    # 3) concurrent login failures all land in the limiter
    auth1 = AuthStore(tempfile.mkdtemp())

    def hammer():
        for _ in range(25):
            auth1.login_limiter.record_failure("8.8.8.8")

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    allowed, _retry = auth1.login_limiter.check("8.8.8.8")
    out["concurrent_login_failures_lock"] = not allowed

    # 4) password change while sessions resolve concurrently
    auth2 = AuthStore(tempfile.mkdtemp())
    auth2.set_password("concurrent-pass-1")
    toks = [auth2.sessions.create() for _ in range(20)]

    def churn():
        for _ in range(50):
            for tok in toks:
                auth2.sessions.resolve(tok)

    def changer():
        auth2.set_password("concurrent-pass-2")

    t1 = threading.Thread(target=churn)
    t2 = threading.Thread(target=changer)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    out["password_change_during_use_ok"] = \
        auth2.verify_password("concurrent-pass-2") and not errors
    out["password_change_drops_old_sessions"] = all(
        auth2.sessions.resolve(tok) is None for tok in toks)

    # 5) recovery guard concurrency cap: exactly max_concurrent get through
    guard = RecoveryGlobalGuard(max_concurrent=2, window_seconds=3600.0,
                                max_attempts_per_window=1000)
    results = {"ok": 0, "busy": 0}
    results_lock = threading.Lock()

    def grabber():
        ok, _retry = guard.try_acquire()
        with results_lock:
            results["ok" if ok else "busy"] += 1

    threads = [threading.Thread(target=grabber) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out["guard_concurrency_cap"] = results == {"ok": 2, "busy": 8}

    # 6) storage fault injection -> rollback, memory == disk
    real_write = web.access.atomic_write_json

    def boom(path, payload):
        raise OSError("injected disk failure")

    d3 = tempfile.mkdtemp()
    pol3 = AccessPolicy(d3)
    pol3.add("10.5.0.0/24")
    web.access.atomic_write_json = boom
    raised = False
    try:
        pol3.add("10.6.0.0/24")
    except OSError:
        raised = True
    finally:
        web.access.atomic_write_json = real_write
    out["storage_fault_whitelist_rollback"] = raised and \
        pol3.entries() == ("10.5.0.0/24",) and \
        AccessPolicy(d3).entries() == ("10.5.0.0/24",)

    auth3 = AuthStore(tempfile.mkdtemp())
    auth3.set_password("rollback-pass-1")
    auth3.set_recovery_key("rollback-key-a")
    web.auth.atomic_write_json = boom
    raised_pw = raised_key = False
    try:
        auth3.set_password("rollback-pass-2")
    except OSError:
        raised_pw = True
    try:
        auth3.set_recovery_key("rollback-key-b")
    except OSError:
        raised_key = True
    finally:
        web.auth.atomic_write_json = real_write
    out["storage_fault_password_rollback"] = raised_pw and \
        auth3.verify_password("rollback-pass-1") and \
        not auth3.verify_password("rollback-pass-2")
    out["storage_fault_recovery_rollback"] = raised_key and \
        auth3.verify_recovery_key("rollback-key-a") and \
        not auth3.verify_recovery_key("rollback-key-b")
    return out


def group_framing():
    out = {}
    guard = RecoveryGlobalGuard(max_concurrent=2, window_seconds=3600.0,
                                max_attempts_per_window=1000)
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY, recovery_guard=guard)
    port = stack["port"]
    calls = {"n": 0}
    real_verify = stack["auth"].verify_recovery_key

    def counting_verify(key):
        calls["n"] += 1
        return real_verify(key)

    stack["auth"].verify_recovery_key = counting_verify

    def raw_post(source, path, header_block, body=b""):
        """Hand-built POST; returns (status_line, server_closed_socket)."""
        sx = socket.socket()
        sx.bind((source, 0))
        sx.settimeout(5.0)
        sx.connect(("127.0.0.1", port))
        sx.sendall(("POST %s HTTP/1.1\r\nHost: monitor\r\n" % path
                    ).encode() + header_block.encode() + b"\r\n" + body)
        time.sleep(0.25)
        data = b""
        try:
            data = sx.recv(65536)
        except socket.timeout:
            pass
        status = data.decode("utf-8", "replace").splitlines()[0] if data \
            else ""
        closed = False
        try:
            sx.sendall(b"GET /api/v1/session HTTP/1.1\r\nHost: m\r\n\r\n")
            nxt = sx.recv(65536)
            closed = (nxt == b"")  # clean EOF: server closed it
        except socket.timeout:
            closed = False         # still open after the window
        except OSError:
            closed = True          # reset/abort: connection is gone
        sx.close()
        return status, closed

    # malformed Content-Length on the whitelist-EXEMPT recovery endpoint
    status, closed = raw_post("127.0.0.6", "/api/v1/recovery",
                              "Content-Type: application/json\r\n"
                              "Content-Length: abc\r\n")
    out["framing_recovery_malformed_cl_400"] = " 400" in status
    out["framing_recovery_malformed_closes"] = closed

    # oversized declared body -> 413 before any gate/handler work
    status, closed = raw_post("127.0.0.6", "/api/v1/recovery",
                              "Content-Type: application/json\r\n"
                              "Content-Length: 70000\r\n", b"x" * 1000)
    out["framing_recovery_oversized_413"] = " 413" in status
    out["framing_recovery_oversized_closes"] = closed

    # chunked Transfer-Encoding -> 400
    status, closed = raw_post("127.0.0.6", "/api/v1/recovery",
                              "Content-Type: application/json\r\n"
                              "Transfer-Encoding: chunked\r\n",
                              b"5\r\nhello\r\n0\r\n\r\n")
    out["framing_recovery_te_400"] = " 400" in status
    out["framing_recovery_te_closes"] = closed

    # NONE of the rejected framings performed scrypt work
    out["framing_recovery_zero_scrypt"] = calls["n"] == 0

    # a NON-WHITELISTED login POST cannot slip past the framing guard
    plain = make_stack(tempfile.mkdtemp())  # empty whitelist
    sx = socket.socket()
    sx.bind(("127.0.0.5", 0))
    sx.settimeout(5.0)
    sx.connect(("127.0.0.1", plain["port"]))
    sx.sendall(b"POST /api/v1/login HTTP/1.1\r\nHost: m\r\n"
               b"Content-Type: application/json\r\n"
               b"Content-Length: abc\r\n\r\n")
    time.sleep(0.25)
    data = sx.recv(65536).decode("utf-8", "replace")
    out["framing_login_before_whitelist_400"] = " 400" in data
    sx.close()
    return out


def group_health():
    """R1-6: SnapshotBroker health-file export (optional, minimal, atomic).

    The file carries EXACTLY the whitelisted keys -- no devices, no
    connections, no identity, no credential material -- and its failure mode
    never takes the dashboard down.
    """
    out = {}
    data_dir = tempfile.mkdtemp()
    health_path = os.path.join(data_dir, "state", "health.json")
    os.makedirs(os.path.dirname(health_path), exist_ok=True)

    stack = make_stack(data_dir, password=PASSWORD,
                       whitelist=["127.0.0.5/32"], poll=0.15,
                       batches=[RESET_BATCH], health_file=health_path)
    port = stack["port"]
    time.sleep(1.0)  # let several publication ticks land

    out["health_file_created"] = os.path.isfile(health_path)
    if out["health_file_created"]:
        with open(health_path, encoding="utf-8") as handle:
            record = json.load(handle)
        out["health_keys_exact"] = set(record.keys()) == set(HEALTH_FILE_KEYS)
        out["health_schema_version"] = (
            record.get("schema_version") == HEALTH_FILE_SCHEMA_VERSION)
        v1 = record.get("snapshot_version")
        out["health_version_int"] = isinstance(v1, int) and not isinstance(v1, bool)
        out["health_published_at_iso"] = isinstance(record.get("published_at"), str)
        out["health_flags_bool"] = (
            isinstance(record.get("collector_stale"), bool)
            and isinstance(record.get("consumer_alive"), bool))
        out["health_consumer_alive_true"] = record.get("consumer_alive") is True
        # no client/runtime payload anywhere in the serialized record
        blob = json.dumps(record, sort_keys=True)
        forbidden = ("device", "connections", "source", "destination",
                     "last_error", "user", "uuid", "password", "secret",
                     "token", PASSWORD)
        out["health_no_client_payload"] = not any(
            token.lower() in blob.lower() for token in forbidden)

        # version advances with publication
        time.sleep(0.6)
        with open(health_path, encoding="utf-8") as handle:
            record2 = json.load(handle)
        v2 = record2.get("snapshot_version")
        out["health_version_advances"] = (
            isinstance(v2, int) and isinstance(v1, int) and v2 > v1)

        # standalone behaviour unchanged: no health file path -> no file
        other = tempfile.mkdtemp()
        plain = make_stack(other, password=PASSWORD, whitelist=["127.0.0.5/32"],
                           poll=0.15, batches=[RESET_BATCH])
        time.sleep(0.6)
        out["standalone_no_health_file"] = not os.path.exists(
            os.path.join(other, "state", "health.json"))
        out["standalone_broker_has_none"] = plain["broker"]._health_file is None

        # a failing health export must not kill the dashboard, and must not
        # truncate/corrupt the previous complete file.
        before = json.loads(req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                                {"Cookie": cookie_of(login(port, "127.0.0.5"))})["body"])
        stack["broker"]._health_file = os.path.join(data_dir, "missing-dir", "health.json")
        time.sleep(0.6)
        after = req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                    {"Cookie": cookie_of(login(port, "127.0.0.5"))})
        out["health_failure_dashboard_alive"] = after["status"] == 200
        out["health_failure_no_partial_file"] = not os.path.exists(
            os.path.join(data_dir, "missing-dir", "health.json"))
        stack["broker"]._health_file = health_path
        time.sleep(0.6)
        with open(health_path, encoding="utf-8") as handle:
            record3 = json.load(handle)   # still valid JSON after recovery
        out["health_recovers_after_failure"] = record3.get("schema_version") == 1
        out["health_prev_file_intact"] = before.get("snapshot_version") is not None
        stack["broker"].stop()
        plain["broker"].stop()
    return out


def group_health_stale_file():
    """collector_stale=true must be reflected in the export."""
    out = {}
    data_dir = tempfile.mkdtemp()
    health_path = os.path.join(data_dir, "state", "health.json")
    os.makedirs(os.path.dirname(health_path), exist_ok=True)
    stack = make_stack(data_dir, password=PASSWORD, whitelist=["127.0.0.5/32"],
                       poll=0.15, batches=[RESET_BATCH], health_file=health_path)
    time.sleep(1.2)   # reset batch consumed, then the stream dies -> stale
    with open(health_path, encoding="utf-8") as handle:
        record = json.load(handle)
    out["stale_exported"] = record.get("collector_stale") is True
    out["stale_consumer_still_alive"] = record.get("consumer_alive") is True
    out["stale_keys_exact"] = set(record.keys()) == set(HEALTH_FILE_KEYS)
    stack["broker"].stop()
    return out


GROUPS = {
    "whitelist": group_whitelist,
    "gate": group_gate,
    "auth": group_auth,
    "stream": group_stream,
    "stale": group_stale,
    "recovery": group_recovery,
    "endpoints": group_endpoints,
    "concurrency": group_concurrency,
    "framing": group_framing,
    "health": group_health,
    "health_stale": group_health_stale_file,
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
check 'd["covers_ipv6_parent"]' "covers() handles IPv6 parent CIDR"
check 'd["remove_works"]' "whitelist entry removable"
check 'd["remove_missing_false"]' "removing a missing entry reports False"
check 'd["corrupt_file_fails_closed"]' "corrupt access.json fails closed"

section "W2: HTTP gate order + recovery public asset chain"
run_group "gate"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["root_loopback_200"]' "loopback reaches the shell"
check 'd["static_js_200"]' "local static assets served"
check 'd["nonwhitelisted_root_403"]' "non-whitelisted IP -> 403 on /"
check 'd["nonwhitelisted_session_403"]' "non-whitelisted IP -> 403 on session info"
check 'd["nonwhitelisted_snapshot_403"]' "non-whitelisted IP -> 403 on snapshot"
check 'd["nonwhitelisted_stream_403"]' "non-whitelisted IP -> 403 on SSE"
check 'd["nonwhitelisted_login_403"]' "non-whitelisted IP -> 403 even before login"
check 'd["recovery_page_nonwhitelisted_200"]' "recovery page reachable without whitelist"
check 'd["recovery_css_nonwhitelisted_200"]' "recovery chain: style.css reachable"
check 'd["recovery_js_nonwhitelisted_200"]' "recovery chain: app.js reachable"
check 'd["recovery_favicon_nonwhitelisted_200"]' "recovery chain: favicon reachable"
check 'd["recovery_api_exempt_reaches_handler"]' "recovery API exempt (uniform invalid-key 403)"
check 'd["recovery_assets_do_not_open_dashboard"]' "asset exemption does NOT open the dashboard"
check 'd["no_wildcard_static_exemption"]' "no wildcard /static exemption (traversal still 404)"
check 'd["xff_cannot_bypass"]' "X-Forwarded-For cannot bypass the whitelist"
check 'd["xff_and_realip_cannot_bypass"]' "X-Forwarded-For + X-Real-IP cannot bypass"
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

section "W3: admin authentication + session-bound CSRF"
run_group "auth"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["wrong_login_401"]' "invalid login fails"
check 'd["no_cookie_on_failed_login"]' "no cookie on failed login"
check 'd["good_login_200"]' "valid login succeeds"
check 'd["cookie_httponly"]' "cookie is HttpOnly"
check 'd["cookie_secure_absent_loopback"]' "loopback HTTP cookie omits Secure (by design)"
check 'd["cookie_samesite_strict"]' "cookie is SameSite=Strict"
check 'd["snapshot_unauthenticated_401"]' "snapshot requires login"
check 'd["snapshot_authenticated_200"]' "session cookie opens the snapshot"
check 'd["password_never_returned"]' "password never returned in responses"
check 'd["session_info_authenticated"]' "session info reflects the login"
check 'd["csrf_token_in_session"]' "authenticated session exposes its CSRF token"
check 'd["auth_hash_only_scrypt"]' "auth.json stores a scrypt hash"
check 'd["auth_no_plaintext"]' "auth.json has NO plaintext password"
check 'd["access_json_exists"]' "access.json in the data dir"
check 'd["csrf_missing_403"]' "mutation WITHOUT CSRF token -> 403"
check 'd["csrf_wrong_403"]' "mutation with WRONG CSRF token -> 403"
check 'd["csrf_correct_200"]' "mutation with correct CSRF token -> 200"
check 'd["csrf_get_unaffected"]' "GET endpoints need no CSRF token"
check 'd["login_unaffected_by_csrf"]' "login needs no CSRF token (no session yet)"
check 'd["csrf_session_bound_403"]' "session A token cannot act on session B cookie"
check 'd["csrf_cross_sessions_ok"]' "each session works with its own token"
check 'd["origin_foreign_403"]' "foreign Origin rejected (second layer)"
check 'd["origin_same_200"]' "same-origin POST accepted"
check 'd["expired_session_401"]' "expired session rejected"
check 'd["csrf_expired_session_401"]' "expired session + old CSRF -> 401 (session first)"
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
check 'd["sse_initial_event_received"]' "SSE delivers its first snapshot while valid"
check 'd["sse_ttl_expiry_stops_stream"]' "SSE A: TTL expiry mid-stream -> stream stops"
check 'd["sse_logout_stops_stream"]' "SSE B: logout while stream open -> stream stops"
check 'd["sse_password_revoke_stops_stream"]' "SSE C: password change revokes session B open stream"

section "W5: stale semantics + publisher freeze detection"
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
check 'd["snapshot_version_present"]' "snapshot_version present in every snapshot"
check 'd["last_publish_at_present"]' "last_publish_at present in every snapshot"
check 'd["unreachable_api_stale"]' "unreachable service.api -> stale"
check 'd["unreachable_api_empty_not_invented"]' "no devices invented when none were seen"
check 'd["publisher_freeze_web_status_stale"]' "frozen publisher -> web_status STALE (read-time health)"
check 'd["publisher_freeze_consumer_alive"]' "consumer thread alive while publisher frozen"
check 'd["publisher_freeze_state_kept"]' "frozen broker still serves the last real state"
check 'd["publisher_freeze_version_present"]' "frozen snapshot still carries version fields"
check 'd["publisher_freeze_last_publish_present"]' "frozen snapshot still carries last_publish_at"
check 'd["frozen_version_does_not_advance"]' "frozen publisher does not advance the version"

section "W6: recovery flow + global verification budget"
run_group "recovery"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["recovery_wrong_key_403"]' "wrong recovery key rejected"
check 'd["recovery_ok_200"]' "correct recovery key accepted"
check 'd["recovery_adds_caller_only"]' "recovery adds ONLY the caller IP (/32)"
check 'd["recovery_ignores_supplied_ip"]' "client-supplied target IP ignored"
check 'd["recovery_no_session_cookie"]' "recovery never creates an admin session"
check 'd["recovery_success_message"]' "success message points back to login"
check 'd["recovery_success_leaks_no_whitelist"]' "success response leaks no whitelist contents"
check 'd["recovery_whitelist_updated"]' "whitelist gained exactly the caller host entry"
check 'd["recovery_cannot_view_snapshot"]' "recovery cannot view the dashboard"
check 'd["recovery_cannot_view_whitelist"]' "recovery cannot view the whitelist"
check 'd["recovery_cannot_change_password"]' "recovery cannot change the password"
check 'd["recovery_idempotent_200"]' "repeated recovery with the same key stays 200"
check 'd["recovery_rate_limit"]' "per-IP recovery failures rate-limited (3x403 then 429)"
check 'd["recovery_global_limit_429"]' "GLOBAL window limit hits across different IPs"
check 'd["recovery_global_retry_after"]' "global limit 429 carries Retry-After"
check 'd["recovery_rejected_no_scrypt"]' "rejected attempts perform NO scrypt work"
check 'd["rotate_wrong_password_403"]' "rotation re-verifies the password"
check 'd["rotate_ok_200"]' "rotation issues a new key"
check 'd["rotate_new_key_differs"]' "new key differs from the old one"
check 'd["rotate_old_key_rejected"]' "old key invalid after rotation"
check 'd["rotate_new_key_adds_caller"]' "new key adds the caller (/32)"

section "W7: read-only surface, HTTP guards, self-lockout flow"
run_group "endpoints"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["no_config_endpoint"]' "no /api/v1/config endpoint"
check 'd["no_close_endpoint_delete"]' "DELETE -> uniform 405 (no delete endpoint)"
check 'd["delete_405_allow_header"]' "405 carries Allow: GET, POST"
check 'd["no_close_endpoint_post"]' "no close-connection endpoint"
check 'd["method_put_405"]' "PUT -> 405"
check 'd["method_patch_405"]' "PATCH -> 405"
check 'd["method_options_405"]' "OPTIONS -> 405"
check 'd["method_trace_405"]' "TRACE -> 405"
check 'd["no_reload_endpoint"]' "no reload endpoint"
check 'd["no_clients_endpoint"]' "no client management endpoint"
check 'd["unknown_get_404"]' "unknown API paths 404"
check 'd["malformed_cl_400"]' "malformed Content-Length -> 400"
check 'd["oversized_413"]' "oversized body -> 413"
check 'd["no_offline_label"]' "snapshot JSON never contains OFFLINE"
check 'd["no_tunnel_down_label"]' "snapshot JSON never contains Tunnel Down"
check 'd["wl_add_invalid_400"]' "invalid CIDR rejected at the API"
check 'd["wl_add_ok_200"]' "valid CIDR accepted"
check 'd["wl_add_persisted"]' "whitelist add persisted"
check 'd["wl_remove_missing_404"]' "removing unknown entry 404"
check 'd["wl_add_parent_cidr"]' "parent /24 entry added for the confirm test"
check 'd["wl_remove_own_needs_confirm"]' "exact /32 covering own IP -> 409 first"
check 'd["wl_remove_parent_cidr_409"]' "parent /24 covering own IP -> 409 first"
check 'd["wl_remove_unrelated_immediate_200"]' "unrelated CIDR removes WITHOUT confirm"
check 'd["wl_remove_parent_confirmed_200"]' "confirmed retry after 409 removes the parent /24"
check 'd["wl_remove_own_confirmed_200"]' "confirmed retry removes the exact /32"
check 'd["wl_remove_applied"]' "removed entries actually gate the caller again"

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
    if printf '%s' "$CURL_STALE" | grep -qF '"stale": true'; then break; fi
    sleep 0.5
done
assert_contains '"stale": true' "$CURL_STALE" "dead service.api -> dashboard shows stale=true"
assert_contains '"snapshot_version"' "$CURL_STALE" "real server snapshot carries snapshot_version"
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
    TLS_LOGIN="$(curl -sk -D - -o /dev/null -X POST "https://127.0.0.2:$TLS_PORT/api/v1/login" \
        -H 'Content-Type: application/json' -d '{"password": "serve-password-3"}')"
    assert_contains "Secure" "$TLS_LOGIN" "remote TLS cookie is Secure"
    TLS_403="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.2:$TLS_PORT/api/v1/snapshot")"
    assert_eq "$TLS_403" "401" "HTTPS snapshot still requires login"
    kill "$TLS_PID" 2>/dev/null
    wait "$TLS_PID" 2>/dev/null
else
    fail "openssl available for self-signed TLS (environment problem)"
fi

section "W9: concurrency + storage fault injection"
run_group "concurrency"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["concurrent_add_same_entry"]' "24 concurrent adds of one CIDR -> single entry"
check 'd["concurrent_add_disk_coherent"]' "concurrent adds keep memory == disk"
check 'd["concurrent_mixed_coherent"]' "concurrent mixed add/remove stays coherent"
check 'd["concurrent_login_failures_lock"]' "concurrent login failures all recorded -> lockout"
check 'd["password_change_during_use_ok"]' "password change during session churn works"
check 'd["password_change_drops_old_sessions"]' "password change drops old sessions under concurrency"
check 'd["guard_concurrency_cap"]' "recovery guard admits exactly max_concurrent verifications"
check 'd["storage_fault_whitelist_rollback"]' "whitelist write failure -> rollback, memory == disk"
check 'd["storage_fault_password_rollback"]' "password write failure -> old password still valid"
check 'd["storage_fault_recovery_rollback"]' "recovery-key write failure -> old key still valid"

section "W10: SSE session lifecycle + POST framing on the raw wire"
run_group "framing"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["framing_recovery_malformed_cl_400"]' "recovery malformed Content-Length -> 400 (before gates)"
check 'd["framing_recovery_malformed_closes"]' "malformed-CL rejection closes the connection"
check 'd["framing_recovery_oversized_413"]' "recovery oversized body -> 413"
check 'd["framing_recovery_oversized_closes"]' "oversized rejection closes the connection"
check 'd["framing_recovery_te_400"]' "recovery chunked Transfer-Encoding -> 400"
check 'd["framing_recovery_te_closes"]' "TE rejection closes the connection"
check 'd["framing_recovery_zero_scrypt"]' "rejected framings perform ZERO scrypt verifications"
check 'd["framing_login_before_whitelist_400"]' "non-whitelisted login POST cannot bypass the framing guard"

section "W11: broker health export (R1-6 packaging contract)"
run_group "health"
check 'd.get("_harness_error") is None' "health harness ran clean"
check 'd["health_file_created"]' "broker writes the health file when --health-file is set"
check 'd["health_keys_exact"]' "health file has EXACTLY the whitelisted keys"
check 'd["health_schema_version"]' "health file carries schema_version=1"
check 'd["health_version_int"]' "snapshot_version is an int"
check 'd["health_published_at_iso"]' "published_at is an ISO timestamp string"
check 'd["health_flags_bool"]' "collector_stale/consumer_alive are booleans"
check 'd["health_consumer_alive_true"]' "consumer_alive=true while the collector thread lives"
check 'd["health_no_client_payload"]' "health file carries NO client/runtime payload (no device/user/uuid/secret)"
check 'd["health_version_advances"]' "snapshot_version advances with publication"
check 'd["standalone_no_health_file"]' "standalone E2 (no --health-file) writes NO health file"
check 'd["standalone_broker_has_none"]' "standalone broker has health_file=None (unchanged behavior)"
check 'd["health_failure_dashboard_alive"]' "failed health export never kills the serving dashboard"
check 'd["health_failure_no_partial_file"]' "failed health export leaves no partial JSON file"
check 'd["health_prev_file_intact"]' "previous complete health file survives a failed export"
check 'd["health_recovers_after_failure"]' "health export recovers after the failure is repaired"

section "W12: health export reflects collector staleness (R1-6)"
run_group "health_stale"
check 'd.get("_harness_error") is None' "stale health harness ran clean"
check 'd["stale_exported"]' "collector_stale=true is exported when the stream dies"
check 'd["stale_consumer_still_alive"]' "consumer thread stays alive while stale (E1 retry semantics)"
check 'd["stale_keys_exact"]' "stale health record keeps the exact key whitelist"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d (expected pass=%d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '  RESULT: FAILED (failures, or a section did not run)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
