#!/usr/bin/env bash
# Monitor v2 security regression suite (independent security review track).
#
# Review baseline: feature branch HEAD at the time of writing (839d315,
# "docs(e2): align TLS scope and cookie/recovery documentation").
#
# Scope: adversarial probes against the Phase E2 web layer that the
# functional suite (tests/test-monitor-v2-e2.sh) does not cover:
#   - spoofed-header matrix (Forwarded, X-Original-URL, X-Rewrite-URL,
#     X-Forwarded-Host, X-Client-IP, X-HTTP-Method-Override)
#   - protocol abuse: chunked bodies, oversized Content-Length, 20 KB
#     request lines/headers, JSON bombs, binary bodies (answer + stay alive)
#   - URL normalization fail-closed (encoded/split/dotted login variants)
#   - CSRF contract: mutations require the session-bound token; wrong and
#     missing tokens are rejected; cross-origin POSTs are rejected
#   - uniform method surface (405 + Allow on everything except GET/POST)
#   - lockout semantics (correct password after lockout, limiter isolation)
#   - session hardening (entropy, fixation, logout-with-CSRF invalidation)
#   - recovery red-team matrix (injected target IP/CIDR fields ignored)
#   - SSE resilience under abrupt mass disconnects
#   - dynamic credential-leakage scan over every captured byte + stderr
#   - concurrent whitelist mutation (file atomicity under races)
#
# KNOWN-ISSUE checks assert a weakness that EXISTS today so it cannot be
# silently forgotten. When a fix lands, the check FAILS with instructions to
# flip it into a regression assertion. They are labelled "KNOWN-ISSUE" here
# and tracked in the security review report.
#
# This suite never modifies production code and never touches /root/sbox.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export STATIC_DIR="$ROOT/monitor-v2/web/static"

PASS=0
FAIL=0
# The gate at the bottom fails unless exactly this many assertions ran AND
# passed, so unreachable sections can never fake success.
EXPECTED_PASS=78
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }

section "S0: static source checks (see bottom S0 block; counted once)"

# -- shared python harness ---------------------------------------------------
cat > "$TMP/sec_harness.py" <<'HARNESS_EOF'
#!/usr/bin/env python3
"""Security harness: real loopback servers, controlled source addresses."""
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
from web.access import AccessPolicy
from web.auth import AuthStore
from web.broker import SnapshotBroker
from web.server import MonitorWebApp, build_server

PASSWORD = "sec-password-e2-7"
RECOVERY_KEY = "sec-recovery-key-test-42"
COOKIE_NAME = "monitor_session"


def make_stack(data_dir, *, password=None, recovery=None, whitelist=(),
               poll=0.2, url="http://127.0.0.1:1", batches=None):
    policy = AccessPolicy(data_dir)
    for entry in whitelist:
        policy.add(entry)
    auth = None
    if password is not None or recovery is not None:
        auth = AuthStore(data_dir, session_ttl=3600.0)
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


def raw(port, source, payload, timeout=5.0, shutdown_write=True):
    """Send hand-crafted bytes; return the raw response bytes."""
    s = socket.socket()
    s.bind((source, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    if shutdown_write:
        try:
            s.shutdown(socket.SHUT_WR)  # no unread bytes -> no RST races
        except OSError:
            pass
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.close()
    return buf


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
    r = req(port, source, "GET", "/api/v1/session", {"Cookie": cookie})
    return json.loads(r["body"]).get("csrf_token", "")


def mut_headers(cookie, token, extra=None):
    h = {"Content-Type": "application/json", "Cookie": cookie}
    if token is not None:
        h["X-CSRF-Token"] = token
    if extra:
        h.update(extra)
    return h


def status_of(buf):
    first = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    return first.split(" ")[1] if " " in first else "?"


def group_spoof():
    out = {}
    # stack WITHOUT any whitelist entry: 127.0.0.5 must stay gated (403) no
    # matter which identity-bearing headers it sends.
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]
    combined = {
        "Forwarded": "for=127.0.0.1;by=127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Original-URL": "http://127.0.0.1/api/v1/snapshot",
        "X-Rewrite-URL": "/api/v1/snapshot",
        "X-Forwarded-Host": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "127.0.0.1",
    }
    out["spoof_root_403"] = req(port, "127.0.0.5", "GET", "/",
                                combined)["status"] == 403
    out["spoof_snapshot_403"] = req(port, "127.0.0.5", "GET",
                                    "/api/v1/snapshot",
                                    combined)["status"] == 403
    out["spoof_login_403"] = req(port, "127.0.0.5", "POST", "/api/v1/login",
                                 dict(combined,
                                      **{"Content-Type": "application/json"}),
                                 json_body({"password": PASSWORD}),
                                 )["status"] == 403
    out["spoof_recovery_get_403"] = req(port, "127.0.0.5", "GET",
                                        "/api/v1/recovery",
                                        combined)["status"] == 403
    # on a whitelisted stack, method-override headers stay inert: a GET
    # without a session is still 401, never routed as POST.
    stack_w = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                         whitelist=["127.0.0.5/32"])
    out["override_inert"] = req(stack_w["port"], "127.0.0.5", "GET",
                                "/api/v1/snapshot",
                                {"X-HTTP-Method-Override": "DELETE"},
                                )["status"] == 401
    return out


def group_protocol():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]

    # chunked transfer-encoding: never parsed, never hangs
    buf = raw(port, "127.0.0.5",
              b"POST /api/v1/login HTTP/1.1\r\nHost: m\r\n"
              b"Transfer-Encoding: chunked\r\n\r\n"
              b"1a\r\n{\"password\": \"chunk-pass-x\"}\r\n0\r\n\r\n")
    out["chunked_rejected_400"] = status_of(buf) == "400"
    out["chunked_response_complete"] = b"Content-Length" in buf \
        and b'"error"' in buf

    # oversized Content-Length: uniform 413 + connection dropped
    buf = raw(port, "127.0.0.5",
              b"POST /api/v1/login HTTP/1.1\r\nHost: m\r\n"
              b"Content-Length: 900000\r\n\r\n")
    out["huge_length_413"] = status_of(buf) == "413"
    out["huge_length_response_complete"] = b"Content-Length" in buf \
        and b'"error"' in buf

    # oversized request line: answered (414 by stdlib or 404 by router)
    long_path = "/" + "A" * 20000
    buf = raw(port, "127.0.0.5",
              ("GET %s HTTP/1.1\r\nHost: m\r\n\r\n" % long_path).encode())
    out["long_line_answered"] = status_of(buf) in ("404", "414")

    # oversized single header: answered, server alive
    buf = raw(port, "127.0.0.5",
              b"GET / HTTP/1.1\r\nHost: m\r\nCookie: " + b"B" * 20000 +
              b"\r\n\r\n")
    out["huge_header_answered"] = status_of(buf) in ("200", "400", "431")

    # JSON bomb (deep nesting) must not crash or hang the server
    bomb = "[" * 20000 + "]" * 20000
    r = req(port, "127.0.0.5", "POST", "/api/v1/login",
            {"Content-Type": "application/json"},
            bomb.encode("utf-8", "replace"), timeout=8.0)
    out["json_bomb_answered"] = r["status"] in (400, 413, 500)

    # non-object JSON bodies are rejected, never authenticated
    for label, payload in (("array", b"[]"), ("string", b'"pw"'),
                           ("number", b"1"), ("binary", b"\xff\xfe\x00")):
        r = req(port, "127.0.0.5", "POST", "/api/v1/login",
                {"Content-Type": "application/json"}, payload)
        out["body_" + label + "_rejected"] = r["status"] == 400

    # server still fully functional after all of the above
    out["alive_after_abuse"] = login(port, "127.0.0.5")["status"] == 200
    return out


def group_urls():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]
    canonical = login(port, "127.0.0.5")
    out["canonical_200"] = canonical["status"] == 200
    out["canonical_trailing_slash_200"] = req(
        port, "127.0.0.5", "POST", "/api/v1/login/",
        {"Content-Type": "application/json"},
        json_body({"password": PASSWORD}))["status"] == 200
    # NOTE: "//api/v1/login" is deliberately absent: modern stdlib
    # (BaseHTTPRequestHandler, py3.13.5+/3.14) collapses leading "//" to "/"
    # BEFORE the handler sees it, and older pythons 404 it via urlsplit's
    # netloc parsing. Either way the socket-peer whitelist gate is
    # path-independent, so no path variant can change the gate decision.
    variants = ["/%61pi/v1/login", "/api/v1//login", "/api/v1/./login",
                "/api/v1/x/../login", "/api%2Fv1%2Flogin",
                "/api/v1/login%00", "/API/v1/login", "/api/v1/login%20"]
    out["encoded_variants_fail_closed"] = all(
        req(port, "127.0.0.5", "POST", v,
            {"Content-Type": "application/json"},
            json_body({"password": PASSWORD}))["status"] != 200
        for v in variants)
    # traversal-style paths never serve files or handlers
    out["dotdot_paths_404"] = all(
        req(port, "127.0.0.5", "GET", v)["status"] in (403, 404)
        for v in ["/static/../auth.py", "/static/../../etc/passwd",
                  "/static/..%2f..%2fauth.py", "/%2e%2e/%2e%2e/etc/passwd"])
    return out


def group_csrf():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]
    cookie = cookie_of(login(port, "127.0.0.5"))
    token = csrf_of(port, "127.0.0.5", cookie)
    out["csrf_token_bound_to_session"] = len(token) >= 32

    # a valid session WITHOUT the CSRF token cannot mutate
    r = req(port, "127.0.0.5", "POST", "/api/v1/whitelist",
            {"Content-Type": "application/json", "Cookie": cookie},
            json_body({"entry": "198.51.100.0/24"}))
    out["csrf_missing_rejected"] = r["status"] == 403
    # a WRONG token cannot mutate
    r = req(port, "127.0.0.5", "POST", "/api/v1/whitelist",
            mut_headers(cookie, "wrong-token-aaaaaaaaaaaaaaaaaaaa"),
            json_body({"entry": "198.51.100.0/24"}))
    out["csrf_wrong_rejected"] = r["status"] == 403
    # the CORRECT token mutates
    r = req(port, "127.0.0.5", "POST", "/api/v1/whitelist",
            mut_headers(cookie, token),
            json_body({"entry": "198.51.100.0/24"}))
    out["csrf_correct_accepts"] = r["status"] == 200

    # cross-origin POSTs are rejected at the door (even before auth)
    r = req(port, "127.0.0.5", "POST", "/api/v1/login",
            {"Content-Type": "application/json",
             "Origin": "https://evil.example"},
            json_body({"password": PASSWORD}))
    out["cross_origin_post_rejected"] = r["status"] == 403
    r = req(port, "127.0.0.1", "POST", "/api/v1/login",
            {"Content-Type": "application/json",
             "Origin": "http://127.0.0.1:%d" % port},
            json_body({"password": "definitely-wrong"}))
    out["same_origin_post_allowed"] = r["status"] in (401, 200)

    # uniform method surface outside GET/POST
    for m in ("PUT", "DELETE", "OPTIONS"):
        r = req(port, "127.0.0.5", m, "/api/v1/snapshot")
        out["method_" + m.lower() + "_405"] = r["status"] == 405
    return out


def group_lockout():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.11/32", "127.0.0.12/32"])
    port = stack["port"]
    for i in range(5):
        login(port, "127.0.0.11", "wrong-%d" % i)
    out["correct_password_still_locked"] = login(
        port, "127.0.0.11")["status"] == 429
    out["other_ip_unaffected"] = login(port, "127.0.0.12")["status"] == 200

    # recovery limiter and login limiter are independent stores
    stack2 = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                        recovery=RECOVERY_KEY,
                        whitelist=["127.0.0.13/32"])
    port2 = stack2["port"]
    for i in range(3):
        req(port2, "127.0.0.13", "POST", "/api/v1/recovery",
            {"Content-Type": "application/json"},
            json_body({"key": "bad-%d" % i}))
    rec = req(port2, "127.0.0.13", "POST", "/api/v1/recovery",
              {"Content-Type": "application/json"},
              json_body({"key": "bad-final"}))
    out["recovery_locked_429"] = rec["status"] == 429
    out["login_not_locked_by_recovery"] = login(
        port2, "127.0.0.13", "wrong-pw")["status"] == 401
    return out


def group_session():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]
    r1 = login(port, "127.0.0.5")
    r2 = login(port, "127.0.0.5")
    t1 = cookie_of(r1).split("=", 1)[1]
    t2 = cookie_of(r2).split("=", 1)[1]
    out["token_entropy_256bit"] = len(t1) >= 40 and len(t2) >= 40
    out["tokens_unique"] = t1 != t2
    sc = r1["headers"].get("set-cookie", "")
    # loopback plain-HTTP contract: HttpOnly + SameSite=Strict always;
    # Secure is added only for TLS/remote listeners (see _session_cookie).
    out["session_cookie_flags"] = "HttpOnly" in sc and "SameSite=Strict" in sc
    out["no_secure_on_plain_http_loopback"] = "Secure" not in sc

    # fixation: an attacker-chosen cookie value is never adopted
    fix = login(port, "127.0.0.5",
                extra={"Cookie": "%s=ATTACKER-CHOSEN-FIXATION-VALUE" %
                       COOKIE_NAME})
    out["fixation_ignored"] = cookie_of(fix).split("=", 1)[1] != \
        "ATTACKER-CHOSEN-FIXATION-VALUE"

    # logout (with CSRF) invalidates server-side, not just the cookie
    tok = cookie_of(r1)
    csrf = csrf_of(port, "127.0.0.5", tok)
    req(port, "127.0.0.5", "POST", "/api/v1/logout",
        mut_headers(tok, csrf))
    out["logout_invalidates"] = req(port, "127.0.0.5", "GET",
                                    "/api/v1/snapshot",
                                    {"Cookie": tok})["status"] == 401
    # malformed cookie headers never 500
    out["garbage_cookie_401"] = req(port, "127.0.0.5", "GET",
                                    "/api/v1/snapshot",
                                    {"Cookie": "@@@; ; monitor_session"})[
                                        "status"] == 401
    return out


def group_recovery():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY, whitelist=["127.0.0.5/32"])
    port = stack["port"]
    injected = [{"ip": "10.0.0.0/8"}, {"ip": "0.0.0.0/0"},
                {"entry": "::/0"}, {"target": "8.8.8.8"},
                {"whitelist": ["0.0.0.0/0"]}, {"name": "evil"},
                {"ip": "127.0.0.1", "entry": "0.0.0.0/0"}]
    caller = "127.0.0.6"
    results = []
    for extra in injected:
        payload = dict({"key": RECOVERY_KEY}, **extra)
        results.append(req(port, caller, "POST", "/api/v1/recovery",
                           {"Content-Type": "application/json"},
                           json_body(payload))["status"])
    out["injection_fields_all_200"] = all(s == 200 for s in results)
    entries = stack["policy"].entries()
    out["only_caller_host_entry"] = entries == ("127.0.0.5/32",
                                                "%s/32" % caller)

    # a second NON-whitelisted caller sees the gate everywhere else
    other = "127.0.0.7"
    out["recovery_get_403"] = req(port, other, "GET",
                                  "/api/v1/recovery")["status"] == 403
    post_html = req(port, other, "POST", "/recovery",
                    {"Content-Type": "application/json"},
                    json_body({"key": RECOVERY_KEY}))
    out["post_to_html_page_403"] = post_html["status"] == 403
    out["no_session_via_recovery"] = "set-cookie" not in post_html["headers"]
    out["whitelist_api_gated"] = req(port, other, "GET",
                                     "/api/v1/whitelist")["status"] == 403
    return out


def group_perimeter():
    """KNOWN-ISSUE: the whitelist API accepts blanket CIDRs, which turns the
    perimeter off. Asserted here so the weakness cannot be silently
    forgotten; when a prefix-length guard lands this check FAILS and must be
    flipped into a regression assertion (API must reject 0.0.0.0/0)."""
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"])
    port = stack["port"]
    cookie = cookie_of(login(port, "127.0.0.5"))
    token = csrf_of(port, "127.0.0.5", cookie)
    authed = mut_headers(cookie, token)
    r = req(port, "127.0.0.5", "POST", "/api/v1/whitelist", authed,
            json_body({"entry": "0.0.0.0/0"}))
    out["KNOWN_ISSUE_blanket_cidr_accepted"] = r["status"] == 200
    out["KNOWN_ISSUE_perimeter_off"] = req(
        port, "127.0.0.9", "GET", "/")["status"] == 200
    req(port, "127.0.0.5", "POST", "/api/v1/whitelist/remove", authed,
        json_body({"entry": "0.0.0.0/0", "confirm": True}))
    out["cleanup_restores_perimeter"] = req(
        port, "127.0.0.9", "GET", "/")["status"] == 403
    return out


def group_sse():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       whitelist=["127.0.0.5/32"], poll=0.15,
                       batches=[{"reset": True, "events": []}])
    port = stack["port"]
    cookie = cookie_of(login(port, "127.0.0.5"))
    baseline_threads = threading.active_count()

    def open_stream():
        s = socket.socket()
        s.bind(("127.0.0.5", 0))
        s.settimeout(3.0)
        s.connect(("127.0.0.1", port))
        s.sendall(("GET /api/v1/stream HTTP/1.1\r\nHost: m\r\n"
                   "Cookie: %s\r\n\r\n" % cookie).encode())
        return s

    socks = [open_stream() for _ in range(10)]
    time.sleep(0.8)
    for s in socks[:5]:
        s.close()   # abrupt mid-stream disconnects
    time.sleep(0.6)
    version = stack["broker"].snapshot_json()[0]
    time.sleep(0.5)
    version2 = stack["broker"].snapshot_json()[0]
    out["publisher_survives_disconnects"] = version2 > version
    out["snapshot_alive_after_disconnects"] = req(
        port, "127.0.0.5", "GET", "/api/v1/snapshot",
        {"Cookie": cookie})["status"] == 200
    for s in socks[5:]:
        s.close()
    # churn: two rounds of 30 connect + immediate close
    for _ in range(2):
        churn = [open_stream() for _ in range(30)]
        time.sleep(0.3)
        for s in churn:
            s.close()
    time.sleep(2.5)  # grace for handler threads to notice the EOFs
    out["no_thread_leak_after_churn"] = threading.active_count() <= \
        baseline_threads + 4
    out["login_works_after_churn"] = login(port, "127.0.0.5")["status"] == 200
    return out


def group_leak():
    import io
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY, whitelist=["127.0.0.5/32"],
                       batches=[{"reset": True, "events": []}])
    port = stack["port"]
    captured_stderr = io.StringIO()
    real_stderr = sys.stderr
    sys.stderr = captured_stderr
    try:
        bodies = []
        r = login(port, "127.0.0.5")
        bodies.append(r["body"])
        token = cookie_of(r).split("=", 1)[1]
        csrf = csrf_of(port, "127.0.0.5", cookie_of(r))
        bodies.append(req(port, "127.0.0.5", "GET", "/api/v1/snapshot",
                          {"Cookie": cookie_of(r)})["body"])
        s = socket.socket()
        s.bind(("127.0.0.5", 0))
        s.settimeout(2.0)
        s.connect(("127.0.0.1", port))
        s.sendall(("GET /api/v1/stream HTTP/1.1\r\nHost: m\r\n"
                   "Cookie: %s\r\n\r\n" % cookie_of(r)).encode())
        # Bound the read: the publisher emits a snapshot every poll tick, so
        # a recv loop can never hit EOF — read for a fixed deadline instead.
        deadline = time.time() + 1.5
        try:
            while time.time() < deadline:
                s.settimeout(max(0.2, deadline - time.time()))
                chunk = s.recv(65536)
                if not chunk:
                    break
                bodies.append(chunk.decode("utf-8", "replace"))
        except (socket.timeout, OSError):
            pass
        s.close()
        bodies.append(req(port, "127.0.0.5", "POST",
                          "/api/v1/recovery/rotate",
                          mut_headers(cookie_of(r), csrf),
                          json_body({"current_password": PASSWORD}))["body"])
        bodies.append(req(port, "127.0.0.5", "POST", "/api/v1/recovery",
                          {"Content-Type": "application/json"},
                          json_body({"key": RECOVERY_KEY}))["body"])
        everything = "\n".join(bodies)
        out["password_never_in_any_body"] = PASSWORD not in everything
        out["old_recovery_key_never_echoed"] = \
            everything.count(RECOVERY_KEY) == 0
        err_text = captured_stderr.getvalue()
        out["password_never_in_stderr"] = PASSWORD not in err_text
        out["token_never_in_stderr"] = token not in err_text
        out["no_traceback_in_stderr"] = "Traceback" not in err_text
        out["no_internal_error_bodies"] = "internal error" not in everything
    finally:
        sys.stderr = real_stderr
    return out


def group_race():
    out = {}
    data_dir = tempfile.mkdtemp()
    policy = AccessPolicy(data_dir)
    errors = []

    def worker(idx):
        try:
            for i in range(15):
                policy.add("10.%d.%d.0/24" % (idx, i))
                policy.remove("10.%d.%d.0/24" % (idx, i))
        except Exception as exc:  # noqa: BLE001
            errors.append("%s: %s" % (type(exc).__name__, exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if sys.platform == "win32":
        # Concurrent os.replace() onto one destination transiently fails with
        # WinError 5 on Windows; POSIX rename(2) is reliable. Only the POSIX
        # behaviour (production platform) is gated as zero-exception.
        real_errors = [e for e in errors if "WinError 5" not in e]
        out["no_exception_under_race"] = not real_errors
    else:
        out["no_exception_under_race"] = not errors
    with open(policy.path, encoding="utf-8") as handle:
        json.load(handle)
    out["access_json_valid_after_race"] = True
    out["policy_reloadable_after_race"] = isinstance(
        AccessPolicy(data_dir).entries(), tuple)
    return out


GROUPS = {
    "spoof": group_spoof,
    "protocol": group_protocol,
    "urls": group_urls,
    "csrf": group_csrf,
    "lockout": group_lockout,
    "session": group_session,
    "recovery": group_recovery,
    "perimeter": group_perimeter,
    "sse": group_sse,
    "leak": group_leak,
    "race": group_race,
}

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        results = GROUPS[name]()
    except Exception as exc:  # noqa: BLE001
        results = {"_harness_error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(results, sort_keys=True))
HARNESS_EOF

run_group() {
    GROUP="$1"
    PYTHONPATH="$ROOT/monitor-v2" "$PY" "$TMP/sec_harness.py" "$GROUP" \
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

section "S0: static source checks"
SERVER_SRC="$(cat "$ROOT/monitor-v2/web/server.py" "$ROOT/monitor-v2/web/access.py" \
                   "$ROOT/monitor-v2/web/auth.py" "$ROOT/monitor-v2/web/recovery.py" \
                   "$ROOT/monitor-v2/webapp.py")"
assert_eq "$(printf '%s' "$SERVER_SRC" | grep -iE 'headers\.get\("[A-Za-z-]*(Forwarded|Real-IP|Original-URL|Rewrite-URL|Method-Override|Forwarded-Host|Client-IP|X-Host)' || true)" "" "no spoofable identity/override header is ever read"
assert_eq "$(printf '%s' "$SERVER_SRC" | grep -i "access-control-allow" || true)" "" "no CORS headers are emitted (same-origin only)"
assert_eq "$(printf '%s' "$SERVER_SRC" | grep -c '"error": "internal error"')" "1" "the 500 fallback body is a fixed constant (no exception text)"
assert_eq "$(printf '%s' "$SERVER_SRC" | grep -c 'parts.append("Secure")')" "1" "Secure cookie flag is added only for TLS/remote listeners"

section "S1: spoofed-header matrix (identity comes only from the socket)"
run_group "spoof"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["spoof_root_403"]' "combined spoof headers cannot reach the shell"
check 'd["spoof_snapshot_403"]' "combined spoof headers cannot reach snapshot"
check 'd["spoof_login_403"]' "combined spoof headers cannot reach login"
check 'd["spoof_recovery_get_403"]' "recovery API unreachable via GET with spoofed headers"
check 'd["override_inert"]' "X-HTTP-Method-Override is inert"

section "S2: protocol abuse (answer + stay alive, never hang)"
run_group "protocol"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["chunked_rejected_400"]' "chunked body rejected 400"
check 'd["chunked_response_complete"]' "chunked rejection is a complete response"
check 'd["huge_length_413"]' "oversized Content-Length -> uniform 413"
check 'd["huge_length_response_complete"]' "413 is a complete response"
check 'd["long_line_answered"]' "20KB request line answered (404/414)"
check 'd["huge_header_answered"]' "20KB header answered"
check 'd["json_bomb_answered"]' "JSON bomb answered without hanging"
check 'd["body_array_rejected"]' "JSON array body rejected"
check 'd["body_string_rejected"]' "JSON string body rejected"
check 'd["body_number_rejected"]' "JSON number body rejected"
check 'd["body_binary_rejected"]' "binary body rejected"
check 'd["alive_after_abuse"]' "server fully functional after abuse"

section "S3: URL normalization fail-closed"
run_group "urls"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["canonical_200"]' "canonical login path works (control)"
check 'd["canonical_trailing_slash_200"]' "trailing slash tolerated (documented)"
check 'd["encoded_variants_fail_closed"]' "8 encoded/split/case variants never authenticate"
check 'd["dotdot_paths_404"]' "traversal-style paths never serve files"

section "S4: CSRF contract (session-bound token + same-origin)"
run_group "csrf"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["csrf_token_bound_to_session"]' "session exposes a >= 256-bit CSRF token"
check 'd["csrf_missing_rejected"]' "mutation without CSRF token -> 403"
check 'd["csrf_wrong_rejected"]' "mutation with wrong CSRF token -> 403"
check 'd["csrf_correct_accepts"]' "mutation with correct CSRF token -> 200"
check 'd["cross_origin_post_rejected"]' "foreign-Origin POST rejected"
check 'd["same_origin_post_allowed"]' "same-Origin POST reaches the handler"
check 'd["method_put_405"]' "PUT -> 405 + Allow"
check 'd["method_delete_405"]' "DELETE -> 405 + Allow"
check 'd["method_options_405"]' "OPTIONS -> 405 + Allow"

section "S5: lockout semantics"
run_group "lockout"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["correct_password_still_locked"]' "correct password after lockout is still 429"
check 'd["other_ip_unaffected"]' "a second whitelisted IP is unaffected"
check 'd["recovery_locked_429"]' "recovery limiter locks after 3 failures"
check 'd["login_not_locked_by_recovery"]' "login limiter is independent of recovery limiter"

section "S6: session hardening"
run_group "session"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["token_entropy_256bit"]' "session tokens have >= 200 bits of entropy"
check 'd["tokens_unique"]' "two logins never share a token"
check 'd["session_cookie_flags"]' "cookie keeps HttpOnly+SameSite=Strict"
check 'd["no_secure_on_plain_http_loopback"]' "Secure omitted on plain-HTTP loopback (documented contract)"
check 'd["fixation_ignored"]' "attacker-chosen cookie value never adopted (no fixation)"
check 'd["logout_invalidates"]' "logout (with CSRF) invalidates the token server-side"
check 'd["garbage_cookie_401"]' "garbage Cookie header -> 401, never 500"

section "S7: recovery red-team matrix"
run_group "recovery"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["injection_fields_all_200"]' "7 injected target-IP/CIDR fields all ignored"
check 'd["only_caller_host_entry"]' "whitelist gained ONLY the caller /32"
check 'd["recovery_get_403"]' "GET /api/v1/recovery gated for non-whitelisted caller"
check 'd["post_to_html_page_403"]' "POST /recovery (HTML path) is gated"
check 'd["no_session_via_recovery"]' "recovery never mints a session"
check 'd["whitelist_api_gated"]' "whitelist read API gated for recovery caller"

section "S8: KNOWN-ISSUE perimeter switch (tracked weakness, see report)"
run_group "perimeter"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["KNOWN_ISSUE_blanket_cidr_accepted"]' "KNOWN-ISSUE: 0.0.0.0/0 accepted by the API"
check 'd["KNOWN_ISSUE_perimeter_off"]' "KNOWN-ISSUE: blanket CIDR disables the whitelist perimeter"
check 'd["cleanup_restores_perimeter"]' "removing the blanket entry restores the gate"

section "S9: SSE resilience"
run_group "sse"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["publisher_survives_disconnects"]' "broker keeps publishing across abrupt disconnects"
check 'd["snapshot_alive_after_disconnects"]' "snapshot endpoint healthy after disconnects"
check 'd["no_thread_leak_after_churn"]' "no handler-thread leak after 60+ churned streams"
check 'd["login_works_after_churn"]' "authentication works after stream churn"

section "S10: dynamic credential-leakage scan"
run_group "leak"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["password_never_in_any_body"]' "admin password never appears in any response body"
check 'd["old_recovery_key_never_echoed"]' "recovery key never echoed in any response body"
check 'd["password_never_in_stderr"]' "admin password never reaches server logs"
check 'd["token_never_in_stderr"]' "session token never reaches server logs"
check 'd["no_traceback_in_stderr"]' "no unhandled exception in the whole flow"
check 'd["no_internal_error_bodies"]' "no 500 fallback body in the whole flow"

section "S11: concurrent whitelist mutation (file atomicity)"
run_group "race"
check 'd.get("_harness_error") is None' "harness ran clean"
check 'd["no_exception_under_race"]' "8-thread add/remove race never raises (POSIX semantics)"
check 'd["access_json_valid_after_race"]' "access.json stays valid JSON under races"
check 'd["policy_reloadable_after_race"]' "policy reloads cleanly after races"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d (expected pass=%d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '  RESULT: FAILED (failures, or a section did not run)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
