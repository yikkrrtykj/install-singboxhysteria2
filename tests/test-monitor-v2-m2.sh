#!/usr/bin/env bash
# E3 M2 web adapter -- contract suite (broker / RPC client / auth extension /
# HTTP adapter). The real assertions live in the embedded Python harness; the
# driver only counts results and owns the exit-status contract.
#
# Covers the M2 frozen test list (docs/e3-m2-web-adapter-design.md §14 T-1):
#   20-thread status single-flight -> exactly 1 helper RPC (and list likewise)
#   half-open concurrency -> exactly 1 status probe
#   breaker is status-driven: list/mutation failures never move the counter
#   a mutation caller timeout (result_unknown) never poisons the breaker
#   helper.degraded is never fabricated by a transport failure
#   stale active=true -> management_active() False, always
#   stepup_fp grant / reuse / rotation / five revocations / never to browser
#   Idempotency-Key header contract (no body key; replay reuses the header)
#   deny-by-default whitelist: lock.path and error.backup never surface
#   error mapping per rev5 §2.6 with retriable passthrough
#   AF_UNIX framing + caller budgets (POSIX-only half; explicit SKIP elsewhere)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$ROOT/tests/.m2-harness.$$.py"

printf '===== E3 M2 WEB ADAPTER =====\n'

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    printf '  SKIP python3 unavailable\n'
    printf '\nPASS=0 FAIL=0 SKIP=1\nE3_M2_WEB=SKIP\n'
    exit 0
fi

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
assert_eq(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }

# shellcheck disable=SC2016
cat > "$HARNESS" <<'HARNESS_EOF'
#!/usr/bin/env python3
"""M2 contract harness. Prints one JSON object of name -> bool to stdout."""
import http.client
import json
import os
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
STATIC_DIR = os.environ["STATIC_DIR"]

from web.auth import AuthStore, SessionStore  # noqa: E402
from web.e3_broker import (BrokerUnavailable, E3Broker,  # noqa: E402
                           STALE, UNAVAILABLE)
from web.e3rpc import E3RpcClient, RpcTransportError  # noqa: E402
from web.server import MonitorWebApp, build_server  # noqa: E402

SOURCE = "127.0.0.6"
PASSWORD = "m2-admin-password-01"
UUID_SHAPED_SECRET = "m2-should-never-leak-uuid-0001"

AF_UNIX_OK = hasattr(socket, "AF_UNIX")


class FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeClient:
    """Scriptable stand-in for E3RpcClient. Script items are verdict dicts
    or exceptions. Optional block/release events expose in-RPC state for the
    single-flight and half-open concurrency tests."""

    def __init__(self):
        self.mutex = threading.Lock()
        self.script = []
        self.calls = []            # op names, one per RPC
        self.entered = threading.Event()
        self.release = threading.Event()

    def record(self, item):
        self.script.append(item)

    def reset_script(self):
        self.script = []

    def call(self, op, payload=None, actor=None):
        with self.mutex:
            self.calls.append(op)
        if self.release.is_set() is False and self.script \
                and self.script[0] == "BLOCK":
            self.script.pop(0)
            self.entered.set()
            self.release.wait(10)
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return {"ok": True, "v": "e3-rpc/1", "request_id": "helper-rid",
                "data": {}}


def new_broker(client, clock, **kw):
    kw.setdefault("status_ttl", 2.0)
    kw.setdefault("list_ttl", 5.0)
    return E3Broker(client, clock=clock, **kw)


def ok_status(active=False, degraded=False):
    return {"ok": True, "v": "e3-rpc/1", "request_id": "helper-status-rid",
            "data": {"management_state": "active" if active else "inactive",
                     "management_active": active,
                     "helper": {"degraded": degraded, "reconcile": "clean"},
                     "lock": {"path": "/root/sbox/config.lock",
                              "acquirable": True},
                     "last_transaction": {"generation": 1, "op": "client.add",
                                          "outcome": "ok", "ended_at": "t",
                                          "leaked_field": "x"}}}


# --------------------------------------------------------------- broker groups --
def group_broker_basics():
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    r = broker.status()
    out["first_status_is_fresh"] = r["transport"] == "fresh"
    out["one_call_so_far"] = len(client.calls) == 1
    r = broker.status()
    out["second_status_within_ttl_no_new_call"] = (
        r["transport"] == "fresh" and len(client.calls) == 1)
    clock.advance(2.0)
    broker.status()
    out["expired_ttl_triggers_exactly_one_refresh"] = len(client.calls) == 2
    out["management_active_false_when_inactive"] = \
        broker.management_active() is False

    client.reset_script()
    client.record(ok_status(active=True))
    clock.advance(2.0)
    broker.status()
    out["management_active_true_when_fresh_active"] = \
        broker.management_active() is True
    clock.advance(1.0)
    out["management_active_true_within_ttl"] = \
        broker.management_active() is True
    clock.advance(2.0)
    out["management_active_false_after_ttl_without_refresh"] = \
        broker.management_active() is False
    return out


def threads_barrier(n, target):
    barrier = threading.Barrier(n)
    results = []

    def run():
        barrier.wait(10)
        results.append(target())

    ts = [threading.Thread(target=run) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(15)
    return results


def group_single_flight():
    out = {}
    # 20 threads, expired TTL, one BLOCKed RPC: exactly one helper call.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    broker.status()                       # seed the cache
    clock.advance(2.5)                    # expire it (past the 2s ttl)
    client.record("BLOCK")
    client.record(ok_status())
    results = threads_barrier(20, broker.status)
    out["status_20_threads_all_answered"] = len(results) == 20
    out["status_20_threads_one_rpc"] = len(client.calls) == 2
    out["status_transport_fresh_after_race"] = \
        all(r["transport"] == "fresh" for r in results)

    # ...and the same for the list cache.
    clock2 = FakeClock()
    client2 = FakeClient()
    broker2 = new_broker(client2, clock2)
    client2.record({"ok": True, "data": {"clients": [], "truncated": False}})
    broker2.list_clients()
    clock2.advance(5.5)
    client2.record("BLOCK")
    client2.record({"ok": True, "data": {"clients": [], "truncated": False}})
    results2 = threads_barrier(20, broker2.list_clients)
    out["list_20_threads_all_answered"] = len(results2) == 20
    out["list_20_threads_one_rpc"] = len(client2.calls) == 2

    # A burst of failures shares ONE attempt per TTL window (no fan-out).
    clock3 = FakeClock()
    client3 = FakeClient()
    broker3 = new_broker(client3, clock3)
    for _ in range(25):
        client3.record(RpcTransportError("read", "helper gone"))
    results3 = threads_barrier(20, broker3.status)
    out["failure_burst_one_rpc"] = len(client3.calls) == 1
    out["failure_burst_all_unavailable"] = \
        all(r["transport"] == "unavailable" for r in results3)
    return out


def group_breaker():
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    for _ in range(3):
        client.record(RpcTransportError("read", "down"))
    for i in range(3):
        clock.advance(2.5)
        broker.status()
    out["three_status_failures_open_breaker"] = \
        broker.breaker_state() == "open"
    calls_before = len(client.calls)
    clock.advance(0.1)
    r = broker.status()
    out["open_breaker_no_new_attempt"] = len(client.calls) == calls_before
    out["open_breaker_serves_unavailable_without_snapshot"] = \
        r["transport"] == "unavailable" and r["payload"] is None

    # Mutations are refused while open -- zero RPC, breaker untouched.
    try:
        broker.mutate("client.add", payload={"idempotency_key": "k" * 16})
        out["open_breaker_refuses_mutation"] = False
    except BrokerUnavailable:
        out["open_breaker_refuses_mutation"] = \
            len(client.calls) == calls_before

    # Half-open: exactly one probe after the cooldown; concurrent requests
    # never add a second one.
    clock.advance(10.5)
    client.record("BLOCK")
    client.record(RpcTransportError("read", "still down"))
    winner_started = threading.Event()

    def probe():
        winner_started.wait(5)
        return broker.status()

    t = threading.Thread(target=probe)
    t.start()
    winner_started.set()   # the single flight will enter and block
    time.sleep(0.2)        # let the prober reach the blocked RPC
    others = [threading.Thread(target=broker.status) for _ in range(8)]
    for o in others:
        o.start()
    client.release.set()
    t.join(15)
    for o in others:
        o.join(15)
    out["half_open_concurrency_one_probe"] = \
        len(client.calls) == calls_before + 1
    out["failed_probe_reopens_breaker"] = broker.breaker_state() == "open"
    client.release.clear()

    # Success closes the breaker and resets the counter.
    clock.advance(10.5)
    client.record(ok_status(active=True))
    broker.status()
    out["half_open_success_closes"] = broker.breaker_state() == "closed"
    out["success_resets_management_active"] = \
        broker.management_active() is True
    return out


def group_breaker_isolation():
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    # One failed status refresh -> 1 failure, breaker still closed.
    client.record(RpcTransportError("read", "down"))
    broker.status()
    out["one_failure_keeps_closed"] = broker.breaker_state() == "closed"

    # A list transport failure must NOT move the breaker counter.
    client.record(RpcTransportError("connect", "down"))
    clock.advance(5.5)
    broker.list_clients()
    clock.advance(2.5)
    client.record(RpcTransportError("read", "down"))
    broker.status()  # second status failure -> counter now 2, still closed
    out["list_failure_did_not_count"] = broker.breaker_state() == "closed"

    # A mutation caller timeout (result_unknown) must NOT poison the breaker.
    client.record(RpcTransportError("read", "budget gone"))
    try:
        broker.mutate("client.add", payload={"idempotency_key": "k" * 16})
        out["mutation_timeout_raised"] = False
    except RpcTransportError as exc:
        out["mutation_timeout_raised"] = True
        out["mutation_timeout_is_uncertain"] = exc.uncertain is True
    out["mutation_timeout_left_breaker_closed"] = \
        broker.breaker_state() == "closed"
    # The next status attempt is the 3rd failure -> open.
    clock.advance(2.5)
    client.record(RpcTransportError("read", "down"))
    broker.status()
    out["third_status_failure_opens"] = broker.breaker_state() == "open"
    return out


def group_stale_and_degraded():
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record(ok_status(active=True))
    broker.status()
    clock.advance(3.0)                      # TTL expired
    client.record(RpcTransportError("read", "down"))
    r = broker.status()
    out["expired_active_serves_stale_transport"] = r["transport"] == "stale"
    out["stale_payload_still_has_the_fields"] = \
        r["payload"]["data"]["management_active"] is True
    out["stale_active_never_trusted"] = broker.management_active() is False

    # helper.degraded is only ever what a REAL response said.
    clock2 = FakeClock()
    client2 = FakeClient()
    broker2 = new_broker(client2, clock2)
    client2.record(ok_status(degraded=True))
    broker2.status()
    snap = broker2.helper_degraded()
    out["degraded_observed_from_real_response"] = (
        snap["degraded"] is True and snap["transport"] == "fresh")
    clock2.advance(3.0)
    client2.record(RpcTransportError("read", "down"))
    broker2.status()
    snap = broker2.helper_degraded()
    out["stale_degraded_still_labeled_stale"] = (
        snap["degraded"] is True and snap["transport"] == "stale")

    # A transport failure never FABRICATES degraded: with no snapshot at all
    # the answer is unavailable + degraded=False (not "degraded").
    clock3 = FakeClock()
    client3 = FakeClient()
    broker3 = new_broker(client3, clock3)
    client3.record(RpcTransportError("connect", "down"))
    broker3.status()
    snap = broker3.helper_degraded()
    out["unreachable_is_not_degraded"] = (
        snap["degraded"] is False and snap["transport"] == "unavailable")
    return out


# ---------------------------------------------------------- auth extension --
def group_auth_lifecycle():
    out = {}
    clock = FakeClock()
    store = SessionStore(clock=clock)
    token = store.create()
    creds = store.step_up_credentials(token)
    out["no_stepup_before_grant"] = creds == {"active": False, "fp": None}

    store.grant_step_up(token)
    c1 = store.step_up_credentials(token)
    c1b = store.step_up_credentials(token)
    out["grant_sets_active_fp"] = c1["active"] is True
    out["fp_is_16_hex"] = (isinstance(c1["fp"], str)
                           and len(c1["fp"]) == 16
                           and all(ch in "0123456789abcdef" for ch in c1["fp"]))
    out["fp_reused_within_window"] = c1["fp"] == c1b["fp"]

    # A new grant MUST rotate the fingerprint.
    clock.advance(1.0)
    store.grant_step_up(token)
    c2 = store.step_up_credentials(token)
    out["regrant_rotates_fp"] = c2["fp"] != c1["fp"]

    # Revocation 1+4: session expiry clears everything.
    clock.advance(400.0)   # window gone
    out["expired_window_cleared"] = \
        store.step_up_credentials(token) == {"active": False, "fp": None}

    # Revocation 2: password change (revoke_all_step_ups, sessions survive).
    clock2 = FakeClock()
    tmp = tempfile.mkdtemp()
    auth = AuthStore(tmp, clock=clock2)
    auth.set_password(PASSWORD)
    t1 = auth.sessions.create()
    t2 = auth.sessions.create()
    auth.sessions.grant_step_up(t1)
    auth.sessions.grant_step_up(t2)
    auth.set_password("m2-other-password-2", keep_session=t1)
    out["password_change_clears_fp_caller"] = \
        auth.sessions.step_up_credentials(t1)["fp"] is None
    out["password_change_clears_fp_others"] = \
        auth.sessions.step_up_credentials(t2)["fp"] is None
    out["password_change_keeps_sessions"] = \
        auth.sessions.resolve(t1) is not None

    # Revocation 3: recovery rotate behaves the same.
    auth.sessions.grant_step_up(t1)
    auth.set_recovery_key("m2-recovery-key-0001")
    out["recovery_rotate_clears_fp"] = \
        auth.sessions.step_up_credentials(t1)["fp"] is None

    # Revocation 5: logout (session drop).
    t3 = store.create()
    store.grant_step_up(t3)
    store.drop(t3)
    out["logout_clears_stepup"] = \
        store.step_up_credentials(t3) == {"active": False, "fp": None}

    # Web restart: a fresh store knows nothing (memory-only).
    out["restart_clears_everything"] = \
        SessionStore(clock=clock).step_up_credentials("anything") == \
        {"active": False, "fp": None}
    return out


# ------------------------------------------------------------ HTTP adapter --
class M2Stack:
    def __init__(self, e3_broker=None):
        tmp = tempfile.mkdtemp()
        self.data_dir = tmp
        from web.access import AccessPolicy
        from web.broker import SnapshotBroker
        from collector import Collector
        policy = AccessPolicy(tmp)
        policy.add(SOURCE + "/32")
        self.auth = AuthStore(tmp)
        self.auth.set_password(PASSWORD)

        def factory():
            raise RuntimeError("stream EOF")

        collector = Collector(url="http://127.0.0.1:1", stream_factory=factory)
        snap_broker = SnapshotBroker(collector, poll_seconds=0.2)
        snap_broker.start()
        self.app = MonitorWebApp(broker=snap_broker, access=policy,
                                 static_dir=STATIC_DIR, auth=self.auth,
                                 e3_broker=e3_broker)
        self.srv = build_server(self.app, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.3)

    def stop(self):
        self.srv.shutdown()


def req(port, method, path, headers=None, body=None, timeout=8.0):
    s = socket.socket()
    s.bind((SOURCE, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.sock = s
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return {"status": resp.status, "body": data.decode("utf-8", "replace"),
            "headers": {k.lower(): v for k, v in resp.getheaders()}}


def login(port, password=PASSWORD):
    r = req(port, "POST", "/api/v1/login", {"Content-Type": "application/json"},
            json.dumps({"password": password}))
    set_cookie = r["headers"].get("set-cookie", "")
    cookie = set_cookie.split(";", 1)[0] if set_cookie else None
    return cookie


def session_info(port, cookie=None):
    r = req(port, "GET", "/api/v1/session", {"Cookie": cookie} if cookie else {})
    return json.loads(r["body"])


def step_up(port, cookie, csrf, password=PASSWORD):
    return req(port, "POST", "/api/v1/step-up",
               {"Content-Type": "application/json", "Cookie": cookie,
                "X-CSRF-Token": csrf},
               json.dumps({"password": password}))


def mutate(port, path, cookie, csrf, headers=None, body=None):
    h = {"Content-Type": "application/json", "Cookie": cookie,
         "X-CSRF-Token": csrf}
    h.update(headers or {})
    return req(port, "POST", path, h, body if body is not None else
               json.dumps({}))


def group_http_adapter():
    out = {}
    # Without a broker everything fails closed before any dispatch.
    stack = M2Stack(e3_broker=None)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    r = req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
    out["no_broker_status_503"] = r["status"] == 503
    out["no_broker_status_code"] = \
        json.loads(r["body"]).get("code") == "e3_unavailable"
    step_up(port, cookie, csrf)
    r = mutate(port, "/api/v1/management/activate", cookie, csrf)
    out["no_broker_mutation_503"] = r["status"] == 503
    out["no_broker_mutation_never_success"] = \
        json.loads(r["body"]).get("ok") is False
    stack.stop()

    # With a scripted broker: read surface.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    step_up(port, cookie, csrf)
    info = session_info(port, cookie)
    out["session_stepup_fp_never_disclosed"] = \
        "stepup_fp" not in info and "step_up_granted_at" not in info

    client.record(ok_status(active=True))
    r = req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
    body = json.loads(r["body"])
    data = body.get("data", {})
    out["status_200_ok"] = r["status"] == 200 and body.get("ok") is True
    out["status_transport_reported"] = body.get("transport") == "fresh"
    out["status_as_of_iso"] = isinstance(body.get("as_of"), str) \
        and body["as_of"].endswith("Z")
    out["status_lock_path_stripped"] = "path" not in data.get("lock", {})
    out["status_lock_acquirable_kept"] = \
        data.get("lock", {}).get("acquirable") is True
    out["status_helper_whitelisted"] = \
        set(data.get("helper", {}).keys()) <= {"degraded", "reconcile"}
    out["status_last_tx_whitelisted"] = \
        set(data.get("last_transaction", {}).keys()) <= {
            "generation", "op", "outcome", "ended_at"}
    out["status_leaked_field_dropped"] = \
        "leaked_field" not in data.get("last_transaction", {})
    out["status_management_active_from_broker"] = \
        body.get("management_active") is True

    # list
    client.record({"ok": True, "request_id": "helper-list-rid",
                   "data": {"clients": [
                       {"name": "legacy", "protocols": ["reality", "hy2"],
                        "reserved": True, "mutable": False,
                        "source": "untracked", "sneaky": 1},
                       {"name": "vmix-01", "protocols": ["reality", "hy2"],
                        "reserved": False, "mutable": True,
                        "source": "untracked"}],
                       "truncated": False}})
    r = req(port, "GET", "/api/v1/clients", {"Cookie": cookie})
    body = json.loads(r["body"])
    clients = body.get("data", {}).get("clients", [])
    out["list_200"] = r["status"] == 200
    out["list_client_keys_whitelisted"] = (
        clients and all(set(c.keys()) <= {
            "name", "protocols", "reserved", "mutable", "source"}
            for c in clients))
    out["list_legacy_reserved"] = any(
        c["name"] == "legacy" and c["reserved"] for c in clients)

    # mutations: the Idempotency-Key contract
    client.record({"ok": True, "request_id": "helper-add-rid",
                   "idempotency": {"key_fp": "a" * 16, "replayed": False,
                                   "generation": 1},
                   "data": {"name": "vmix-02", "protocols": ["reality", "hy2"],
                            "mutable": True, "source": "untracked",
                            "yaml_available": False,
                            "credential_delivery": "cli",
                            "uuid": UUID_SHAPED_SECRET,
                            "password": UUID_SHAPED_SECRET},
                   "warnings": []})
    good_headers = {"Idempotency-Key": "m2-key-0000000000000001"}
    good_body = json.dumps({"name": "vmix-02"})
    r = mutate(port, "/api/v1/clients/add", cookie, csrf, {}, good_body)
    out["add_without_header_400"] = (
        r["status"] == 400
        and json.loads(r["body"]).get("code") == "invalid_idempotency_key")
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               good_headers, json.dumps({"name": "vmix-02",
                                         "idempotency_key": "k" * 16}))
    out["add_body_key_rejected_400"] = (
        r["status"] == 400
        and json.loads(r["body"]).get("code") == "invalid_idempotency_key")
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               {"Idempotency-Key": "short"}, good_body)
    out["add_bad_header_400"] = r["status"] == 400
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               good_headers, json.dumps({"name": "legacy"}))
    out["add_legacy_403"] = (
        r["status"] == 403
        and json.loads(r["body"]).get("code") == "E_RESERVED_NAME")
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               good_headers, json.dumps({"name": "../vmix"}))
    out["add_bad_name_400"] = r["status"] == 400
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               good_headers, good_body)
    body = json.loads(r["body"])
    out["add_happy_200"] = r["status"] == 200 and body.get("ok") is True
    out["add_idempotency_passthrough"] = (
        body.get("idempotency", {}).get("replayed") is False)
    out["add_credentials_never_returned"] = \
        UUID_SHAPED_SECRET not in r["body"]
    out["add_credential_delivery_cli"] = \
        body.get("data", {}).get("credential_delivery") == "cli"
    out["add_whitelisted_data_keys"] = set(body.get("data", {}).keys()) <= {
        "name", "protocols", "mutable", "source", "yaml_available",
        "credential_delivery", "warnings"}
    replay_headers = {"Idempotency-Key": "m2-key-0000000000000001"}
    client.record({"ok": True, "request_id": "helper-add-rid2",
                   "idempotency": {"key_fp": "a" * 16, "replayed": True,
                                   "generation": 1},
                   "data": {"name": "vmix-02", "protocols": ["reality"],
                            "mutable": True, "source": "untracked",
                            "yaml_available": False,
                            "credential_delivery": "cli"},
                   "warnings": []})
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               replay_headers, good_body)
    out["replay_same_header_accepted"] = (
        r["status"] == 200
        and json.loads(r["body"]).get("idempotency", {}).get("replayed")
        is True)

    # error mapping: code + retriable passthrough, backup never surfaces
    client.record({"ok": False, "request_id": "helper-err-rid",
                   "error": {"code": "E_DUPLICATE_NAME", "stage": "revalidate",
                             "retriable": False, "detail": "dup",
                             "backup": "/root/sbox/x.bak"}})
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000002"},
               json.dumps({"name": "vmix-02"}))
    body = json.loads(r["body"])
    out["duplicate_409"] = r["status"] == 409
    out["error_retriable_passthrough"] = body.get("retriable") is False
    out["error_backup_stripped"] = "backup" not in r["body"] \
        and "/root/sbox" not in r["body"]
    client.record({"ok": False, "request_id": "helper-rlbk-rid",
                   "error": {"code": "E_ROLLED_BACK", "stage": "health",
                             "retriable": True, "detail": "rolled back"}})
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000003"},
               json.dumps({"name": "vmix-03"}))
    out["rolled_back_503_retriable"] = (
        r["status"] == 503
        and json.loads(r["body"]).get("retriable") is True)

    # delete: confirm + fresh preflight
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000004"},
               json.dumps({"name": "vmix-01"}))
    out["delete_without_confirm_400"] = (
        r["status"] == 400
        and json.loads(r["body"]).get("code") == "confirm_mismatch")
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000004"},
               json.dumps({"name": "vmix-01", "confirm": "other"}))
    out["delete_confirm_mismatch_400"] = r["status"] == 400

    calls_before = len(client.calls)
    client.record(RpcTransportError("connect", "down"))
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000004"},
               json.dumps({"name": "vmix-01", "confirm": "vmix-01"}))
    out["delete_preflight_fail_503"] = (
        r["status"] == 503
        and json.loads(r["body"]).get("code") == "list_unavailable")
    out["delete_preflight_fail_never_dispatched"] = \
        "client.delete" not in client.calls[calls_before:]

    # fresh preflight bypasses the cache: a forced list happens even though
    # the display cache is fresh, and an unknown name is refused locally.
    client.record({"ok": True, "data": {"clients": [
        {"name": "vmix-01", "protocols": ["reality", "hy2"],
         "reserved": False, "mutable": True, "source": "untracked"}],
        "truncated": False}})
    client.record({"ok": True, "request_id": "helper-del-rid",
                   "data": {"deleted": True, "derived_cleanup": True,
                            "warnings": []}})
    calls_before = len(client.calls)
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000004"},
               json.dumps({"name": "vmix-01", "confirm": "vmix-01"}))
    out["delete_happy_200"] = r["status"] == 200
    out["delete_preflight_was_forced_fresh"] = \
        client.calls[calls_before:].count("client.list") == 1
    out["delete_then_dispatched"] = \
        client.calls[calls_before:].count("client.delete") == 1
    calls_before = len(client.calls)
    client.record({"ok": True, "data": {"clients": [], "truncated": False}})
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000005"},
               json.dumps({"name": "ghost", "confirm": "ghost"}))
    out["delete_absent_from_fresh_list_404"] = r["status"] == 404
    out["delete_absent_never_dispatched"] = \
        "client.delete" not in client.calls[calls_before:]

    # result_unknown: post-send timeout -> 504 uncertain, breaker untouched
    clock.advance(30.0)
    client.record(RpcTransportError("read", "budget exhausted"))
    r = mutate(port, "/api/v1/clients/add", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000006"},
               json.dumps({"name": "vmix-09"}))
    body = json.loads(r["body"])
    out["add_timeout_result_unknown_504"] = (
        r["status"] == 504 and body.get("code") == "result_unknown")
    out["add_timeout_uncertain_flag"] = body.get("uncertain") is True
    out["add_timeout_recovery_same_key_only"] = "SAME Idempotency-Key" \
        in body.get("recovery", "")
    out["add_timeout_breaker_untouched"] = broker.breaker_state() == "closed"
    clock.advance(30.0)
    client.record(RpcTransportError("read", "budget exhausted"))
    r = mutate(port, "/api/v1/management/activate", cookie, csrf)
    body = json.loads(r["body"])
    out["activate_timeout_result_unknown_504"] = (
        r["status"] == 504 and body.get("uncertain") is True)
    out["activate_timeout_status_first_recovery"] = \
        "management/status" in body.get("recovery", "")
    out["activate_timeout_breaker_untouched"] = \
        broker.breaker_state() == "closed"

    # connect failure -> definitive non-dispatch
    client.record(RpcTransportError("connect", "refused"))
    r = mutate(port, "/api/v1/management/activate", cookie, csrf)
    body = json.loads(r["body"])
    out["connect_failure_503_e3_unavailable"] = (
        r["status"] == 503 and body.get("code") == "e3_unavailable")

    # breaker open refuses mutations with zero dispatch
    for _ in range(2):
        clock.advance(2.5)
        client.record(RpcTransportError("read", "down"))
        broker.status()
    clock.advance(2.5)
    client.record(RpcTransportError("read", "down"))
    broker.status()
    out["breaker_now_open"] = broker.breaker_state() == "open"
    calls_before = len(client.calls)
    r = mutate(port, "/api/v1/management/activate", cookie, csrf)
    body = json.loads(r["body"])
    out["open_breaker_mutation_503"] = (
        r["status"] == 503 and body.get("code") == "e3_unavailable")
    out["open_breaker_zero_dispatch"] = len(client.calls) == calls_before

    # status while open still serves the last snapshot (the uncertain-query
    # channel), labeled with its transport state.
    r = req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
    body = json.loads(r["body"])
    out["open_breaker_status_still_serves_snapshot"] = (
        r["status"] == 200 and body.get("transport") == "stale"
        and body.get("data", {}).get("management_state") is not None)
    stack.stop()
    return out


# --------------------------------------------------------- transport (POSIX) --
class MockHelper(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            header = b""
            while len(header) < 4:
                chunk = self.request.recv(4 - len(header))
                if not chunk:
                    return
                header += chunk
            (length,) = struct.unpack(">I", header)
            payload = b""
            while len(payload) < length:
                chunk = self.request.recv(length - len(payload))
                if not chunk:
                    return
                payload += chunk
            request = json.loads(payload.decode("utf-8"))
            if MOCK_MODE.get("slow"):
                time.sleep(0.6)
            if MOCK_MODE.get("empty_frame"):
                self.request.sendall(struct.pack(">I", 0))
                return
            body = json.dumps({
                "ok": True, "v": "e3-rpc/1",
                "request_id": request.get("request_id"),
                "op": request.get("op"), "data": {}}).encode("utf-8")
            self.request.sendall(struct.pack(">I", len(body)) + body)
        except OSError:
            pass


MOCK_MODE = {}


if AF_UNIX_OK:
    class MockHelperServer(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True
else:
    MockHelperServer = None


def group_rpc_transport(tmpdir):
    out = {}
    if not AF_UNIX_OK:
        return {"transport_af_unix_unavailable_skip": True}
    path = os.path.join(tmpdir, "mock.sock")
    if os.path.exists(path):
        os.unlink(path)
    server = MockHelperServer(path, MockHelper)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        client = E3RpcClient(socket_path=path)
        v1 = client.call("management.status")
        rid1 = v1.get("request_id")
        v2 = client.call("management.status")
        rid2 = v2.get("request_id")
        out["framing_roundtrip_ok"] = v1.get("ok") is True
        out["request_id_web_prefixed"] = str(rid1).startswith("web-")
        out["request_id_fresh_per_attempt"] = rid1 != rid2
        out["op_carried"] = v1.get("op") == "management.status"

        MOCK_MODE["slow"] = True   # hold the response 0.6s > the 0.2s budget
        slow = E3RpcClient(socket_path=path,
                           budgets={"management.status": 0.2})
        try:
            slow.call("management.status")
            out["budget_exhaustion_raises"] = False
        except RpcTransportError as exc:
            out["budget_exhaustion_raises"] = True
            out["budget_exhaustion_is_uncertain"] = exc.uncertain is True
        finally:
            MOCK_MODE["slow"] = False

        dead = os.path.join(tmpdir, "absent.sock")
        absent = E3RpcClient(socket_path=dead)
        try:
            absent.call("management.status")
            out["connect_refusal_raises"] = False
        except RpcTransportError as exc:
            out["connect_refusal_raises"] = exc.stage == "connect"
            out["connect_refusal_not_uncertain"] = exc.uncertain is False

        MOCK_MODE["empty_frame"] = True
        try:
            client.call("management.status")
            out["empty_frame_raises"] = False
        except RpcTransportError as exc:
            out["empty_frame_raises"] = exc.stage == "frame"
        MOCK_MODE["empty_frame"] = False
    finally:
        server.shutdown()
        server.server_close()
        if os.path.exists(path):
            os.unlink(path)
    return out


def main():
    out = {}
    out.update(group_broker_basics())
    out.update(group_single_flight())
    out.update(group_breaker())
    out.update(group_breaker_isolation())
    out.update(group_stale_and_degraded())
    out.update(group_auth_lifecycle())
    out.update(group_http_adapter())
    with tempfile.TemporaryDirectory() as tmpdir:
        out.update(group_rpc_transport(tmpdir))
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
HARNESS_EOF

section_py(){ printf '  -- %s --\n' "$1"; }

"$PY" -m py_compile "$ROOT/monitor-v2/web/e3rpc.py" \
    "$ROOT/monitor-v2/web/e3_broker.py" "$ROOT/monitor-v2/web/auth.py" \
    "$ROOT/monitor-v2/web/server.py" "$ROOT/monitor-v2/webapp.py" 2>"$HARNESS.cerr" \
    || { fail 'py_compile of the M2 modules'; cat "$HARNESS.cerr"; }
[ -s "$HARNESS.cerr" ] && fail 'compile diagnostics above' \
    || pass 'M2 modules compile'

section_py 'running the contract harness'
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export STATIC_DIR="$ROOT/monitor-v2/web/static"
"$PY" "$HARNESS" > "$HARNESS.out" 2>"$HARNESS.err"
rc=$?
if [ "$rc" -ne 0 ] || ! "$PY" -c "import json,sys; json.load(open(sys.argv[1]))" "$HARNESS.out" 2>/dev/null; then
    fail 'harness crashed (see stderr below)'
    sed 's/^/    | /' "$HARNESS.err" | head -25
    cp "$HARNESS.out" /tmp/suite-out.json 2>/dev/null
cp "$HARNESS.checks" /tmp/suite-checks.txt 2>/dev/null
rm -f "$HARNESS" "$HARNESS.out" "$HARNESS.err" "$HARNESS.cerr" "$HARNESS.checks"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nE3_M2_WEB=FAIL\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

CHECKS=$("$PY" - "$HARNESS.out" <<'CHECK_EOF'
import json, sys
data = json.load(open(sys.argv[1]))
for name in sorted(data):
    if data[name] == "SKIP":
        print("SKIPNAME|%s" % name)
        continue
    print("%s|%s" % (name, "PASS" if data[name] is True else "FAIL"))
CHECK_EOF
)
# tr: a Windows-host python writes CRLF; strip it so the
# verdict comparison is exact on every platform.
printf '%s\n' "$CHECKS" | tr -d "\r" > "$HARNESS.checks"
skip_count=0
while IFS='|' read -r name verdict; do
    if [ "$name" = "SKIPNAME" ]; then
        skip_count=$((skip_count+1))
        skip "$verdict (POSIX-only; not exercisable on this host)"
        continue
    fi
    if [ "$verdict" = "PASS" ]; then
        pass "$name"
    else
        fail "$name"
    fi
done < "$HARNESS.checks"

cp "$HARNESS.out" /tmp/suite-out.json 2>/dev/null
cp "$HARNESS.checks" /tmp/suite-checks.txt 2>/dev/null
rm -f "$HARNESS" "$HARNESS.out" "$HARNESS.err" "$HARNESS.cerr" "$HARNESS.checks"
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M2_WEB=FAIL\n'; exit 1; }
printf 'E3_M2_WEB=PASS\n'
