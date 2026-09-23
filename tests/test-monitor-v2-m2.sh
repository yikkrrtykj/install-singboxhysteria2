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
from web.e3_broker import (BrokerUnavailable, E3Broker, FRESH,  # noqa: E402
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
        self.actors = []           # the actor dict of each mutation RPC
        self.entered = threading.Event()
        self.release = threading.Event()

    def record(self, item):
        self.script.append(item)

    def reset_script(self):
        self.script = []

    def call(self, op, payload=None, actor=None):
        if getattr(self, 'on_call', None):
            self.on_call()
        with self.mutex:
            self.calls.append(op)
            self.actors.append(actor)
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


# ------------------------------------------------------- B1/B2 groups --
def group_verdict_semantics():
    """B1: a helper ok:false verdict is a SEMANTIC answer on a working
    transport -- no cache write, no breaker movement, helper error mapping."""
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record({"ok": False, "request_id": "helper-e1",
                   "error": {"code": "E_INTERNAL", "stage": "parse",
                             "retriable": False, "detail": "boom"}})
    r = broker.status()
    out["status_verdict_error_surfaced"] = (
        r["verdict_error"] is not None
        and r["verdict_error"]["code"] == "E_INTERNAL")
    out["status_verdict_no_payload"] = r["payload"] is None
    out["semantic_error_never_opens_breaker"] = broker.breaker_state() == "closed"
    # repeat: three semantic errors still never trip the transport breaker
    for _ in range(2):
        client.record({"ok": False, "request_id": "x",
                       "error": {"code": "E_INTERNAL", "stage": "parse",
                                 "retriable": False, "detail": "d"}})
        clock.advance(2.5)
        broker.status()
    out["semantic_errors_leave_breaker_closed"] = \
        broker.breaker_state() == "closed"
    # the last-known-good cache is untouched: a later success still lands
    client.record(ok_status(active=True))
    clock.advance(2.5)
    r = broker.status()
    out["cache_recoverable_after_semantic_errors"] = (
        r["transport"] == "fresh" and r["payload"]["ok"] is True)

    # list semantics
    clock2 = FakeClock()
    client2 = FakeClient()
    broker2 = new_broker(client2, clock2)
    client2.record({"ok": False, "request_id": "helper-lk",
                    "error": {"code": "E_LOCK", "stage": "lock",
                              "retriable": True, "detail": "busy"}})
    r = broker2.list_clients(force=True)
    out["list_verdict_error_surfaced"] = (
        r["verdict_error"] is not None
        and r["verdict_error"]["code"] == "E_LOCK")

    # a semantic error must NOT overwrite an existing good cache
    clock3 = FakeClock()
    client3 = FakeClient()
    broker3 = new_broker(client3, clock3)
    good = {"ok": True, "data": {"clients": [{"name": "keep-me"}]}}
    client3.record(good)
    broker3.list_clients()
    clock3.advance(5.5)
    client3.record({"ok": False, "request_id": "x",
                    "error": {"code": "E_CONFIG_INCONSISTENT", "stage": "lock",
                              "retriable": False, "detail": "bad live"}})
    r = broker3.list_clients()
    out["semantic_error_keeps_last_good_cache"] = (
        r["verdict_error"] is not None
        and r["payload"] is None)
    # and the old good payload is still there for a stale display
    r2 = broker3.list_clients()
    out["last_good_cache_not_overwritten"] = (
        r2["transport"] == "stale"
        and r2["payload"]["data"]["clients"][0]["name"] == "keep-me")

    # B1-final: a semantic verdict ENDS the transport-failure streak.
    clock4 = FakeClock()
    client4 = FakeClient()
    broker4 = new_broker(client4, clock4)

    def transport_fail():
        client4.record(RpcTransportError("read", "down"))

    def semantic_error():
        client4.record({"ok": False, "request_id": "s",
                        "error": {"code": "E_INTERNAL", "stage": "parse",
                                  "retriable": False, "detail": "boom"}})

    transport_fail(); clock4.advance(2.5); broker4.status()   # failure 1
    transport_fail(); clock4.advance(2.5); broker4.status()   # failure 2
    semantic_error(); clock4.advance(2.5); broker4.status()   # resets streak
    transport_fail(); clock4.advance(2.5); r = broker4.status()  # only fail 1
    out["semantic_verdict_ends_failure_streak"] = (
        broker4.breaker_state() == "closed")

    # ...and a half-open probe that meets a semantic answer also closes.
    transport_fail(); clock4.advance(2.5); broker4.status()   # failure 2
    transport_fail(); clock4.advance(2.5); broker4.status()   # failure 3 -> open
    clock4.advance(10.5)                                      # cooldown over
    semantic_error()                                          # probe answer
    broker4.status()
    out["half_open_semantic_probe_closes"] = \
        broker4.breaker_state() == "closed"
    return out



def group_add_without_stepup():
    """Product UX contract: client.add needs session + CSRF, not password
    step-up. Destructive client.delete remains step-up gated."""
    out = {}
    client = FakeClient()
    broker = new_broker(client, FakeClock())
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]

    client.record({
        "ok": True, "request_id": "helper-add-no-stepup",
        "idempotency": {"key_fp": "a" * 16, "replayed": False,
                        "generation": 1},
        "data": {"name": "vmix-no-stepup",
                 "protocols": ["reality", "hy2"],
                 "mutable": True, "source": "untracked",
                 "yaml_available": False,
                 "credential_delivery": "cli"},
        "warnings": []})
    r = mutate(
        port, "/api/v1/clients/add", cookie, csrf,
        {"Idempotency-Key": "m2-no-stepup-key-00000001"},
        json.dumps({"name": "vmix-no-stepup"}))
    body = json.loads(r["body"])
    out["add_without_stepup_200"] = (
        r["status"] == 200 and body.get("ok") is True)
    out["add_without_stepup_dispatched_once"] =         client.calls.count("client.add") == 1
    actor = client.actors[-1] or {}
    out["add_actor_session_fp_present"] =         isinstance(actor.get("session_fp"), str) and len(actor["session_fp"]) == 16
    out["add_actor_has_no_stepup_fp"] = "stepup_fp" not in actor

    calls_before = len(client.calls)
    r = mutate(
        port, "/api/v1/clients/delete", cookie, csrf,
        {"Idempotency-Key": "m2-delete-stepup-key-0001"},
        json.dumps({"name": "vmix-no-stepup",
                    "confirm": "vmix-no-stepup"}))
    body = json.loads(r["body"])
    out["delete_without_stepup_still_401"] = (
        r["status"] == 401 and body.get("error") == "reauth_required")
    out["delete_without_stepup_zero_rpc"] = len(client.calls) == calls_before

    stack.stop()
    return out

def group_actor_freeze():
    """B2: the step-up fingerprint is captured at the GATE; a revocation
    racing the dispatch never strips the actor from the audit."""
    out = {}
    client = FakeClient()
    broker = new_broker(client, FakeClock())
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    step_up(port, cookie, csrf)
    fp1 = stack.auth.sessions.step_up_credentials(
        _token_of(stack, cookie))["fp"]

    # the fake client triggers the revocation from INSIDE the dispatch, i.e.
    # after the gate has passed and while the request is in flight
    client.on_call = lambda: \
        stack.auth.sessions.revoke_all_step_ups()
    client.record({
        "ok": True, "data": {"clients": [
            {"name": "vmix-01", "protocols": ["reality", "hy2"],
             "reserved": False, "mutable": True, "source": "untracked"}],
        "truncated": False}})
    client.record(
        {"ok": True, "request_id": "helper-race-rid",
         "idempotency": {"key_fp": "b" * 16, "replayed": False,
                         "generation": 1},
         "data": {"deleted": True, "derived_cleanup": True,
                  "warnings": []}})
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-race-key-000000000001"},
               json.dumps({"name": "vmix-01", "confirm": "vmix-01"}))
    out["race_delete_reaches_helper"] = \
        json.loads(r["body"]).get("ok") is True
    dispatched = client.actors[-1] or {}
    out["race_actor_stepup_fp_frozen"] = \
        dispatched.get("stepup_fp") == fp1
    out["race_actor_session_fp_present"] = \
        isinstance(dispatched.get("session_fp"), str)
    out["fp_after_revoke_is_none"] = \
        stack.auth.sessions.step_up_credentials(
            _token_of(stack, cookie))["fp"] is None
    stack.stop()
    return out


def _token_of(stack, cookie):
    # the session token equals the cookie value (bearer token)
    return cookie.split("=", 1)[1] if "=" in cookie else cookie


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

    # B1: helper semantic verdicts map through the error table on a FRESH
    # stack -- never disguised as snapshots, never as e3_unavailable, and
    # never a breaker input.
    client = FakeClient()
    broker = new_broker(client, FakeClock())
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    step_up(port, cookie, csrf)

    client.record({"ok": False, "request_id": "e1",
                   "error": {"code": "E_INTERNAL", "stage": "parse",
                             "retriable": False, "detail": "boom"}})
    r = req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
    body = json.loads(r["body"])
    out["status_semantic_500"] = (
        r["status"] == 500 and body.get("code") == "E_INTERNAL")
    out["status_semantic_never_opens_breaker"] = \
        broker.breaker_state() == "closed"

    client.record({"ok": False, "request_id": "e2",
                   "error": {"code": "E_LOCK", "stage": "lock",
                             "retriable": True, "detail": "busy"}})
    r = req(port, "GET", "/api/v1/clients", {"Cookie": cookie})
    out["list_lock_423"] = r["status"] == 423

    broker._clock.advance(5.5)   # past the list attempt throttle (5s)
    client.record({"ok": False, "request_id": "e3",
                   "error": {"code": "E_CONFIG_INCONSISTENT", "stage": "lock",
                             "retriable": False, "detail": "bad"}})
    r = req(port, "GET", "/api/v1/clients", {"Cookie": cookie})
    out["list_config_409"] = r["status"] == 409

    # delete preflight E_LOCK -> 423 with the helper semantics, zero
    # client.delete dispatches
    calls_before = len(client.calls)
    client.record({"ok": False, "request_id": "e4",
                   "error": {"code": "E_LOCK", "stage": "lock",
                             "retriable": True, "detail": "busy"}})
    r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
               {"Idempotency-Key": "m2-key-0000000000000007"},
               json.dumps({"name": "vmix-01", "confirm": "vmix-01"}))
    body = json.loads(r["body"])
    out["delete_preflight_lock_423"] = (
        r["status"] == 423 and body.get("code") == "E_LOCK")
    out["delete_preflight_lock_no_dispatch"] = \
        "client.delete" not in client.calls[calls_before:]
    stack.stop()
    return out


# ------------------------------------------------------------- M4 export --
def _export_verdict(n=1):
    return {"ok": True, "request_id": "helper-export-rid%d" % n,
            "data": {"format": "mihomo-yaml",
                     "filename": "vmix-01-mihomo.yaml",
                     "content": "proxies:\n  - uuid: %s%d\n"
                                % (UUID_SHAPED_SECRET, n)}}


def _export_status(**over):
    """A fresh, fully open export gate; `over` replaces top-level data keys
    or, for helper/lock, merges into the nested dict (None = drop the key)."""
    base = ok_status(active=True)
    data = base["data"]
    for key, value in over.items():
        if key in ("helper", "lock") and value is not None:
            data[key] = dict(data[key], **value)
        elif value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return base


def _gate_refused(broker, client):
    """True iff export_client raised BrokerUnavailable with ZERO
    client.export RPCs. A management.status refresh is allowed -- proving
    freshness IS the gate; only the credential-carrying dispatch must not
    happen."""
    before = len(client.calls)
    try:
        broker.export_client("vmix-01")
        return False
    except BrokerUnavailable:
        return "client.export" not in client.calls[before:]


def group_export_broker():
    """The FRESH-only export gate: every unsatisfied condition must refuse
    with zero client.export RPCs -- the response would carry credentials."""
    out = {}

    # happy path first: actor passthrough + the gate really opens when the
    # FRESH status says active / not degraded / clean / lock acquirable.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    actor = {"session_fp": "0" * 16, "stepup_fp": "1" * 16}
    client.record(_export_status())
    client.record(_export_verdict(1))
    v = broker.export_client("vmix-01", actor=actor)
    out["export_happy_dispatches"] = v.get("ok") is True
    out["export_gate_fresh_open_uses_two_rpc"] = \
        client.calls == ["management.status", "client.export"]
    out["export_actor_passthrough"] = client.actors[-1] == actor

    # the export RESULT is never cached: a second export inside the status
    # TTL re-dispatches and renders afresh, and the broker holds no
    # reference to the first bytes.
    client.record(_export_verdict(2))
    v2 = broker.export_client("vmix-01")
    out["export_never_cached_second_dispatch"] = \
        client.calls.count("client.export") == 2 \
        and v2["data"]["content"] != v["data"]["content"]
    out["export_second_within_ttl_skips_status_refresh"] = \
        client.calls == ["management.status", "client.export", "client.export"]
    out["export_result_not_in_any_cache"] = (
        broker._status_cache["payload"] is not v
        and broker._status_cache["payload"] is not v2
        and broker._list_cache is None)

    # G1: breaker open -> zero export RPC even with a perfect cached status.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock, breaker_failures=1)
    client.record(RpcTransportError("read", "down"))
    broker.status()                      # one failure opens the breaker
    out["export_breaker_state_open"] = broker.breaker_state() == "open"
    out["export_gate_breaker_open_zero_rpc"] = _gate_refused(broker, client)

    # G2: stale status (refresh fails) -> refuse, never serve stale truth.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record(_export_status())
    broker.status()                      # fresh active snapshot cached
    clock.advance(2.5)                   # TTL expired
    client.record(RpcTransportError("read", "down"))
    before = len(client.calls)
    out["export_gate_stale_zero_rpc"] = _gate_refused(broker, client)
    out["export_gate_stale_attempted_status_only"] = \
        client.calls[before:] == ["management.status"]

    # G3: unavailable status (never any snapshot, refresh fails) -> refuse.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record(RpcTransportError("connect", "down"))
    out["export_gate_unavailable_zero_rpc"] = _gate_refused(broker, client)

    # G4-G8: fresh-but-unhealthy verdicts. Each must close the gate.
    cases = {
        "export_gate_inactive": {"management_active": False},
        "export_gate_degraded": {"helper": {"degraded": True}},
        "export_gate_reconcile": {"helper": {"reconcile": "diverged"}},
        "export_gate_lock_unacquirable": {"lock": {"acquirable": False}},
        "export_gate_missing_helper": {"helper": None},
        "export_gate_missing_lock": {"lock": None},
    }
    for name, over in cases.items():
        clock = FakeClock()
        client = FakeClient()
        broker = new_broker(client, clock)
        client.record(_export_status(**over))
        out[name] = _gate_refused(broker, client)

    # G9: a helper VERDICT error on status (transport worked, semantics did
    # not) is a refusal too -- there is no snapshot to trust.
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record({"ok": False, "request_id": "e",
                   "error": {"code": "E_INTERNAL", "stage": "probe",
                             "retriable": False, "detail": "boom"}})
    out["export_gate_status_verdict_zero_rpc"] = _gate_refused(broker, client)

    # a transport failure of the EXPORT itself propagates untouched (the
    # caller maps it; the broker never retries).
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record(_export_status())
    client.record(RpcTransportError("read", "budget"))
    try:
        broker.export_client("vmix-01")
        out["export_transport_error_propagates"] = False
    except RpcTransportError as exc:
        out["export_transport_error_propagates"] = exc.stage == "read" \
            and client.calls.count("client.export") == 1
    return out


def group_export_http():
    """POST /api/v1/clients/export end to end: gate order, the file-response
    headers, and the rule that the YAML bytes ship to exactly one consumer --
    the authenticated browser -- and land in no cache, log or JSON envelope."""
    out = {}
    YAML_FIXTURE = ("mixed-port: 7897\nproxies:\n"
                    "  - name: Reality\n    uuid: %s\n"
                    "  - name: Hysteria2\n    password: %s\n\n"
                    % (UUID_SHAPED_SECRET, "super-secret-hy2-fixture"))

    def export(port, cookie, csrf, headers=None, body=None):
        return mutate(port, "/api/v1/clients/export", cookie, csrf,
                      headers, body if body is not None
                      else json.dumps({"name": "vmix-01"}))

    # no broker at all -> 503, fail closed
    stack = M2Stack(e3_broker=None)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    step_up(port, cookie, csrf)
    r = export(port, cookie, csrf)
    out["export_no_broker_503"] = r["status"] == 503
    stack.stop()

    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]

    # GET is never a delivery verb for credentials
    r = req(port, "GET", "/api/v1/clients/export", {"Cookie": cookie})
    out["export_get_405"] = r["status"] == 405 \
        and "content-disposition" not in r["headers"] \
        and YAML_FIXTURE not in r["body"]
    # no session -> 401 before anything else
    r = req(port, "POST", "/api/v1/clients/export",
            {"Content-Type": "application/json"},
            json.dumps({"name": "vmix-01"}))
    out["export_no_session_401"] = r["status"] == 401
    out["export_no_session_zero_rpc"] = "client.export" not in client.calls
    # session but no step-up -> the ONLY 401 the UI replays on
    r = export(port, cookie, csrf)
    body = json.loads(r["body"])
    out["export_no_stepup_401_reauth"] = (
        r["status"] == 401 and body.get("error") == "reauth_required")
    out["export_no_stepup_zero_rpc"] = "client.export" not in client.calls
    step_up(port, cookie, csrf)

    # body validation happens BEFORE any dispatch (free refusals). R5: the
    # RPC count is sampled around EACH bad request individually -- a single
    # before/after over the whole block would not prove any one specific
    # rejected request dispatched nothing.
    def bad_request(label, code, body=None, headers=None):
        before = len(client.calls)
        r = export(port, cookie, csrf, headers,
                   body if body is not None
                   else json.dumps({"name": "vmix-01"}))
        out[label + "_400"] = (
            r["status"] == 400 and
            json.loads(r["body"]).get("code") == code)
        out[label + "_zero_rpc"] = len(client.calls) == before
        return r

    bad_request("export_header_key", "invalid_idempotency_key",
                headers={"Idempotency-Key": "m2-key-0000000000000009"})
    bad_request("export_body_key", "invalid_idempotency_key",
                body=json.dumps({"name": "vmix-01",
                                 "idempotency_key": "k" * 16}))
    bad_request("export_bad_name", "invalid_name",
                body=json.dumps({"name": "../x"}))
    # R5 exact shape: one and only one key, "name". Extras, omissions,
    # non-object JSON and malformed JSON are all 400 invalid_request_body.
    bad_request("export_extra_field", "invalid_request_body",
                body=json.dumps({"name": "vmix-01", "extra": 1}))
    bad_request("export_missing_name", "invalid_request_body",
                body=json.dumps({"other": 1}))
    bad_request("export_non_object", "invalid_request_body",
                body=json.dumps(["vmix-01"]))
    bad_request("export_malformed", "invalid_request_body",
                body="{not json")
    bad_request("export_empty_body", "invalid_request_body", body="")
    calls_before = len(client.calls)

    # the gate: breaker open -> 503 e3_unavailable, zero export RPC
    broker._state = "open"
    r = export(port, cookie, csrf)
    body = json.loads(r["body"])
    out["export_breaker_open_503"] = (
        r["status"] == 503 and body.get("code") == "e3_unavailable")
    out["export_breaker_open_zero_rpc"] = \
        "client.export" not in client.calls[calls_before:]
    broker._state = "closed"

    # fresh-but-inactive gate -> 503, still zero export RPCs
    calls_before = len(client.calls)
    client.record(_export_status(management_active=False))
    r = export(port, cookie, csrf)
    out["export_inactive_503"] = r["status"] == 503
    out["export_inactive_zero_rpc"] = \
        "client.export" not in client.calls[calls_before:]

    # happy path: the sanctioned file response (clock past the TTL so the
    # gate must REFRESH -- the refused inactive snapshot is still cached)
    clock.advance(2.5)
    client.record(_export_status())
    client.record({"ok": True, "request_id": "helper-exp-h1",
                   "data": {"format": "mihomo-yaml",
                            "filename": "vmix-01-mihomo.yaml",
                            "content": YAML_FIXTURE}})
    r = export(port, cookie, csrf, None, json.dumps({"name": "legacy"}))
    out["export_happy_200"] = r["status"] == 200
    out["export_body_is_the_exact_yaml"] = r["body"] == YAML_FIXTURE
    h = r["headers"]
    out["export_content_type_yaml"] = \
        h.get("content-type") == "application/x-yaml; charset=utf-8"
    out["export_disposition_attachment_named"] = h.get("content-disposition") \
        == 'attachment; filename="legacy-mihomo.yaml"'
    out["export_no_store"] = h.get("cache-control") == \
        "no-store, no-cache, must-revalidate"
    out["export_pragma_no_cache"] = h.get("pragma") == "no-cache"
    out["export_expires_zero"] = h.get("expires") == "0"
    out["export_nosniff"] = h.get("x-content-type-options") == "nosniff"
    out["export_content_length"] = \
        h.get("content-length") == str(len(YAML_FIXTURE.encode("utf-8")))
    out["export_csp_present"] = "content-security-policy" in h
    # the one and only place the YAML exists on this stack
    out["export_yaml_delivered_exactly_once"] = \
        r["body"].count(YAML_FIXTURE) == 1
    # every failure answer stays JSON + fail-closed headers, never YAML
    r = export(port, cookie, csrf, None, json.dumps({"name": "../x"}))
    hh = r["headers"]
    out["export_error_stays_json"] = (
        hh.get("content-type") == "application/json"
        and hh.get("cache-control") == "no-store"
        and hh.get("x-content-type-options") == "nosniff"
        and "content-disposition" not in hh)

    # helper verdict maps through the error table -- JSON, non-secret
    clock.advance(2.5)
    client.record(_export_status())
    client.record({"ok": False, "request_id": "helper-exp-e1",
                   "error": {"code": "E_NOT_FOUND", "stage": "revalidate",
                             "retriable": False, "detail": "客户端 'x' 不存在",
                             "backup": "/root/sbox/y.bak"}})
    r = export(port, cookie, csrf)
    body = json.loads(r["body"])
    out["export_not_found_maps"] = r["status"] == 404 \
        and body.get("code") == "E_NOT_FOUND"
    out["export_error_no_backup_path"] = "/root/sbox" not in r["body"]
    out["export_error_is_not_the_yaml"] = UUID_SHAPED_SECRET not in r["body"]

    # transport: connect failure = definitive non-dispatch 503; post-send
    # timeout = 504 result_unknown, UNCERTAIN but a read (never sets a
    # pending mutation retry -- the UI just re-clicks Download).
    clock.advance(30.0)
    client.record(_export_status())
    client.record(RpcTransportError("read", "budget exhausted"))
    r = export(port, cookie, csrf)
    body = json.loads(r["body"])
    out["export_timeout_504_uncertain"] = (
        r["status"] == 504 and body.get("uncertain") is True
        and body.get("code") == "result_unknown")
    clock.advance(30.0)
    client.record(_export_status())
    client.record(RpcTransportError("connect", "refused"))
    r = export(port, cookie, csrf)
    out["export_connect_503"] = r["status"] == 503

    # oversized payload from a misbehaving helper -> 502, nothing ships
    clock.advance(2.5)
    client.record(_export_status())
    client.record({"ok": True, "request_id": "helper-exp-big",
                   "data": {"format": "mihomo-yaml",
                            "filename": "vmix-01-mihomo.yaml",
                            "content": "x" * 49153}})
    r = export(port, cookie, csrf)
    body = json.loads(r["body"])
    out["export_oversized_502"] = r["status"] == 502 \
        and "x" * 1024 not in r["body"]

    # wrong format / empty content -> 502 E_INTERNAL, never a download
    clock.advance(2.5)
    client.record(_export_status())
    client.record({"ok": True, "request_id": "helper-exp-fmt",
                   "data": {"format": "singbox-json",
                            "filename": "vmix-01.json", "content": "{}"}})
    r = export(port, cookie, csrf)
    out["export_bad_format_502"] = r["status"] == 502 \
        and "content-disposition" not in r["headers"]

    # the YAML lands NOWHERE else: no later JSON answer can serve it.
    clock.advance(2.5)
    client.record(_export_status())
    client.record(_export_verdict(9))
    r2 = export(port, cookie, csrf)
    out["export_later_answer_is_the_next_file"] = \
        UUID_SHAPED_SECRET + "9" in r2["body"] and YAML_FIXTURE not in r2["body"]
    stack.stop()
    return out


# ------------------------------------------- 0.1.3 post-mutation convergence --
def group_post_mutation_invalidation():
    """Broker-level A-F: invalidate_after_client_mutation must expire BOTH
    caches and re-open the attempt throttles immediately (no TTL/watchdog
    wait), while an in-flight pre-mutation refresh can never repopulate the
    invalidated cache (generation epochs). Breaker, single-flight and the
    fresh-only writable gate keep their exact semantics."""
    out = {}

    # A. status cache bypass after a confirmed mutation (< TTL elapsed).
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    client.record(ok_status(active=True))
    broker.status()                                  # RPC 1: fresh seed
    out["A_seed_fresh_one_rpc"] = len(client.calls) == 1
    broker.invalidate_after_client_mutation()
    out["A_stale_active_never_trusted"] = \
        broker.management_active() is False          # gate stays fail-closed
    client.record(ok_status(active=True))
    r = broker.status()                              # RPC 2 IMMEDIATELY
    out["A_immediate_refetch_is_fresh"] = (
        len(client.calls) == 2 and r["transport"] == "fresh")
    broker.status()
    out["A_ttl_cache_still_intact_after_refetch"] = len(client.calls) == 2

    # B. list cache bypass (same, 5s TTL never waited out).
    clock2 = FakeClock()
    client2 = FakeClient()
    broker2 = new_broker(client2, clock2)
    LIST1 = {"ok": True, "request_id": "B1",
             "data": {"clients": [{"name": "a"}], "truncated": False}}
    LIST2 = {"ok": True, "request_id": "B2",
             "data": {"clients": [{"name": "a"}, {"name": "b"}],
                      "truncated": False}}
    client2.record(LIST1)
    broker2.list_clients()
    broker2.invalidate_after_client_mutation()
    client2.record(LIST2)
    r = broker2.list_clients()
    out["B_immediate_refetch_is_fresh"] = (
        len(client2.calls) == 2 and r["transport"] == "fresh"
        and r["payload"] is LIST2)

    # C. a recent attempt stamp must not block the post-mutation refresh:
    # first the throttle SUPPRESSES a within-TTL retry, then invalidation
    # re-opens it.
    clock3 = FakeClock()
    client3 = FakeClient()
    broker3 = new_broker(client3, clock3)
    client3.record(RpcTransportError("read", "down"))
    broker3.status()                                 # attempt stamped now
    broker3.status()
    out["C_throttle_suppresses_before"] = len(client3.calls) == 1
    client3.record(ok_status(active=True))
    broker3.invalidate_after_client_mutation()
    r = broker3.status()
    out["C_throttle_reset_allows_refetch"] = (
        len(client3.calls) == 2 and r["transport"] == "fresh")

    # D. in-flight STATUS race: the RPC began on the pre-mutation world;
    # invalidation lands while it is blocked; its answer must never become
    # the authoritative cache, and the next read must obtain a real
    # post-invalidation snapshot.
    clock4 = FakeClock()
    client4 = FakeClient()
    broker4 = new_broker(client4, clock4)
    OLD = {"ok": True, "request_id": "OLD-STATUS",
           "data": {"management_state": "inactive",
                    "management_active": False,
                    "helper": {"degraded": False, "reconcile": "clean"},
                    "lock": {"acquirable": True}}}
    NEW = {"ok": True, "request_id": "NEW-STATUS",
           "data": {"management_state": "active",
                    "management_active": True,
                    "helper": {"degraded": False, "reconcile": "clean"},
                    "lock": {"acquirable": True}}}
    client4.record(ok_status(active=True))
    broker4.status()                                 # seed
    clock4.advance(2.5)                              # expire it
    client4.record("BLOCK")
    t = threading.Thread(target=broker4.status)
    t.start()
    client4.entered.wait(5)                          # old RPC is in flight
    broker4.invalidate_after_client_mutation()       # confirmed mutation
    client4.record(OLD)                              # the answer it will meet
    client4.release.set()
    t.join(15)
    client4.release.clear()
    cache = broker4._status_cache
    out["D_old_rpc_never_published"] = \
        cache is None or cache["payload"].get("request_id") != "OLD-STATUS"
    client4.record(NEW)
    r = broker4.status()
    out["D_next_read_gets_post_invalidation_rpc"] = (
        r["transport"] == "fresh"
        and r["payload"].get("request_id") == "NEW-STATUS")
    out["D_gate_writable_again_only_after_fresh_proof"] = \
        broker4.management_active() is True

    # E. in-flight LIST race: identical contract for client.list.
    clock5 = FakeClock()
    client5 = FakeClient()
    broker5 = new_broker(client5, clock5)
    LOLD = {"ok": True, "request_id": "OLD-LIST",
            "data": {"clients": [], "truncated": False}}
    LNEW = {"ok": True, "request_id": "NEW-LIST",
            "data": {"clients": [{"name": "fresh-01"}], "truncated": False}}
    client5.record({"ok": True, "request_id": "L0",
                    "data": {"clients": [], "truncated": False}})
    broker5.list_clients()
    clock5.advance(5.5)
    client5.record("BLOCK")
    t = threading.Thread(target=broker5.list_clients)
    t.start()
    client5.entered.wait(5)
    broker5.invalidate_after_client_mutation()
    client5.record(LOLD)
    client5.release.set()
    t.join(15)
    client5.release.clear()
    lcache = broker5._list_cache
    out["E_old_list_never_published"] = \
        lcache is None or lcache["payload"].get("request_id") != "OLD-LIST"
    client5.record(LNEW)
    r = broker5.list_clients()
    out["E_next_read_gets_post_invalidation_rpc"] = (
        r["transport"] == "fresh"
        and r["payload"].get("request_id") == "NEW-LIST")

    # F. WITHOUT invalidation every existing semantic is untouched: the 20
    # concurrent expired-TTL readers still share exactly one RPC, and a
    # within-TTL burst still performs none.
    clock6 = FakeClock()
    client6 = FakeClient()
    broker6 = new_broker(client6, clock6)
    client6.record(ok_status())                      # seed
    broker6.status()
    clock6.advance(2.5)
    client6.record("BLOCK")
    client6.record(ok_status())
    results = threads_barrier(20, broker6.status)
    out["F_single_flight_unchanged"] = (
        len(client6.calls) == 2 and len(results) == 20
        and all(r["transport"] == "fresh" for r in results))
    broker6.status()
    broker6.status()
    out["F_ttl_cache_unchanged"] = len(client6.calls) == 2

    # Invalidation is idempotent and breaker-neutral by construction.
    broker6.invalidate_after_client_mutation()
    broker6.invalidate_after_client_mutation()
    out["F_repeated_invalidation_breaker_untouched"] = \
        broker6.breaker_state() == "closed"
    return out


def group_http_post_mutation_invalidation():
    """Server placement (§4/§10): invalidate_after_client_mutation runs
    EXACTLY ONCE per confirmed client.add/client.delete success, BEFORE the
    HTTP answer, and ZERO times for failures, uncertain outcomes, exports
    and plain reads."""
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    inv = {"n": 0}
    _orig = broker.invalidate_after_client_mutation

    def spy():
        inv["n"] += 1
        return _orig()

    broker.invalidate_after_client_mutation = spy
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    cookie = login(port)
    csrf = session_info(port, cookie)["csrf_token"]
    step_up(port, cookie, csrf)
    seq = {"k": 0}

    def nextkey():
        seq["k"] += 1
        return "conv-key-%012d" % seq["k"]

    try:
        # confirmed add success -> exactly one invalidation, and the next
        # status read refetches even though no TTL has elapsed.
        n0 = inv["n"]
        client.record({"ok": True, "request_id": "conv-add-1", "data": {}})
        r = mutate(port, "/api/v1/clients/add", cookie, csrf,
                   {"Idempotency-Key": nextkey()},
                   json.dumps({"name": "conv-01"}))
        out["add_success_200"] = r["status"] == 200
        out["add_success_invalidates_exactly_once"] = inv["n"] == n0 + 1
        status_before = client.calls.count("management.status")
        client.record(ok_status(active=True))
        r = req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
        out["add_success_next_status_refetches_within_ttl"] = (
            client.calls.count("management.status") == status_before + 1
            and json.loads(r["body"]).get("transport") == "fresh")

        # confirmed delete success (preflight + delete) -> exactly one.
        n0 = inv["n"]
        client.record({"ok": True, "request_id": "conv-list-1",
                       "data": {"clients": [
                           {"name": "conv-01", "protocols": ["Reality"],
                            "mutable": True}], "truncated": False}})
        client.record({"ok": True, "request_id": "conv-del-1", "data": {}})
        r = mutate(port, "/api/v1/clients/delete", cookie, csrf,
                   {"Idempotency-Key": nextkey()},
                   json.dumps({"name": "conv-01", "confirm": "conv-01"}))
        out["delete_success_200"] = r["status"] == 200
        out["delete_success_invalidates_exactly_once"] = inv["n"] == n0 + 1

        # helper semantic error -> zero.
        n0 = inv["n"]
        client.record({"ok": False, "request_id": "conv-add-2",
                       "error": {"code": "E_LOCK", "stage": "lock",
                                 "retriable": True, "detail": "busy"}})
        r = mutate(port, "/api/v1/clients/add", cookie, csrf,
                   {"Idempotency-Key": nextkey()},
                   json.dumps({"name": "conv-02"}))
        out["semantic_error_http_423"] = r["status"] == 423
        out["semantic_error_invalidates_zero"] = inv["n"] == n0

        # post-send budget exhaustion (result_unknown / uncertain) -> zero.
        n0 = inv["n"]
        client.record(RpcTransportError("read", "budget gone"))
        r = mutate(port, "/api/v1/clients/add", cookie, csrf,
                   {"Idempotency-Key": nextkey()},
                   json.dumps({"name": "conv-03"}))
        body = json.loads(r["body"])
        out["uncertain_http_504"] = r["status"] == 504 \
            and body.get("uncertain") is True
        out["uncertain_invalidates_zero"] = inv["n"] == n0

        # connect refusal (definitively NOT dispatched) -> zero.
        n0 = inv["n"]
        client.record(RpcTransportError("connect", "helper gone"))
        r = mutate(port, "/api/v1/clients/add", cookie, csrf,
                   {"Idempotency-Key": nextkey()},
                   json.dumps({"name": "conv-03"}))
        out["not_dispatched_http_503"] = r["status"] == 503
        out["not_dispatched_invalidates_zero"] = inv["n"] == n0

        # client.export (a READ) -> zero, even when it succeeds. The
        # gate needs a fresh active status: advance past the TTL so the
        # gate must REFRESH (and prove a refusal-free healthy snapshot).
        clock.advance(2.5)
        n0 = inv["n"]
        client.record(ok_status(active=True))
        client.record({"ok": True, "request_id": "conv-exp-1",
                       "data": {"format": "mihomo-yaml",
                                "filename": "conv-03-mihomo.yaml",
                                "content": "mixed-port: 7897\n"}})
        r = req(port, "POST", "/api/v1/clients/export",
                {"Content-Type": "application/json", "Cookie": cookie,
                 "X-CSRF-Token": csrf}, json.dumps({"name": "conv-03"}))
        out["export_success_200"] = r["status"] == 200
        out["export_invalidates_zero"] = inv["n"] == n0

        # plain reads (status + list) -> zero.
        clock.advance(2.5)
        n0 = inv["n"]
        client.record(ok_status(active=True))
        req(port, "GET", "/api/v1/management/status", {"Cookie": cookie})
        client.record({"ok": True, "data": {"clients": [],
                                            "truncated": False}})
        req(port, "GET", "/api/v1/clients", {"Cookie": cookie})
        out["reads_invalidate_zero"] = inv["n"] == n0
    finally:
        stack.stop()
    return out


def group_status_force():
    """0.1.4 status(force=True): defeats the TTL fast path and the attempt
    throttle, but NEVER the single-flight lock, the 0.1.3 epoch rule or an
    OPEN breaker."""
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)

    # -- TTL bypass ---------------------------------------------------------
    broker.status()                                   # seed (one RPC)
    n = len(client.calls)
    r = broker.status()
    out["force_non_force_within_ttl_still_shares_cache"] = (
        r["transport"] == "fresh" and len(client.calls) == n)
    client.record(ok_status(active=True))
    r = broker.status(force=True)
    out["force_bypasses_ttl_exactly_one_new_call"] = (
        len(client.calls) == n + 1 and r["transport"] == "fresh")
    data = r["payload"].get("data", {})
    out["force_result_is_the_new_snapshot"] = data.get("management_active") is True

    # -- attempt-throttle bypass -------------------------------------------
    clock.advance(2.5)                                # cache now stale
    client.reset_script()
    client.record(RuntimeError("stream EOF"))
    r = broker.status()                               # fails -> throttle arms
    out["plain_read_after_failed_attempt_is_throttled"] = (
        r["transport"] == "stale" and len(client.calls) == n + 2)
    client.record(ok_status())
    r = broker.status(force=True)
    out["force_bypasses_attempt_throttle"] = (
        len(client.calls) == n + 3 and r["transport"] == "fresh")

    # -- open breaker is NEVER bypassed ------------------------------------
    # Trip it: three failures, each separated past the throttle window.
    for i in range(3):
        clock.advance(2.5)
        client.reset_script()
        client.record(RuntimeError("stream EOF"))
        broker.status()
    out["breaker_open_after_three_failures"] = broker.breaker_state() == "open"
    n = len(client.calls)
    r = broker.status(force=True)                     # inside the cooldown
    out["force_does_not_bypass_open_breaker"] = (
        len(client.calls) == n and r["transport"] == "stale")
    # An ELAPSED cooldown still arms exactly one half-open probe: force may
    # dispatch then (that is the breaker's own defined transition, not a
    # bypass).
    clock.advance(10.1)
    client.reset_script()
    client.record(ok_status())
    r = broker.status(force=True)
    out["force_performs_half_open_probe_after_cooldown"] = (
        len(client.calls) == n + 1 and r["transport"] == "fresh"
        and broker.breaker_state() == "closed")

    # -- epoch rules still apply to forced reads ----------------------------
    clock.advance(2.5)                                # force the next refresh
    client.reset_script()
    client.record("BLOCK")
    client.record(dict(ok_status(), request_id="OLD-FORCED"))
    box = {}

    def forced():
        box["r"] = broker.status(force=True)

    t = threading.Thread(target=forced)
    t.start()
    client.entered.wait(5)                            # RPC is in flight
    broker.invalidate_after_client_mutation()         # confirmed mutation
    client.release.set()
    t.join(10)
    client.release.clear()
    out["forced_pre_invalidation_result_is_not_fresh"] = (
        box["r"]["transport"] != "fresh")
    cached = broker._status_cache
    out["forced_pre_invalidation_never_published"] = not (
        isinstance(cached, dict) and isinstance(cached.get("payload"), dict)
        and cached["payload"].get("request_id") == "OLD-FORCED")

    # -- single-flight is kept under force ----------------------------------
    clock.advance(2.5)
    client.reset_script()
    client.record("BLOCK")
    client.record(ok_status())
    holder = threading.Thread(target=lambda: broker.status(force=True))
    holder.start()
    client.entered.wait(5)
    n = len(client.calls)                             # only the holder so far
    results = threads_barrier(3, lambda: broker.status(force=True))
    holder.join(10)
    client.release.clear()
    # every waiter owns its own forced refresh (force never shares a cached
    # winner) -- but at most ONE RPC is ever inside the client at a time:
    # the flight lock serialized all four.
    out["force_keeps_single_flight"] = (
        len(client.calls) == n + 3
        and all(r["transport"] == "fresh" for r in results))
    return out


def group_http_convergence_endpoint():
    """GET /api/v1/clients/convergence: session-gated, GET-only read that
    force-refreshes status THEN list and answers ok ONLY when both are
    fresh; everything else fails closed (503 / helper verdict table)."""
    out = {}
    clock = FakeClock()
    client = FakeClient()
    broker = new_broker(client, clock)
    inv = {"n": 0}
    _orig = broker.invalidate_after_client_mutation

    def spy():
        inv["n"] += 1
        return _orig()

    broker.invalidate_after_client_mutation = spy
    stack = M2Stack(e3_broker=broker)
    port = stack.port
    try:
        # -- session gate ----------------------------------------------------
        r = req(port, "GET", "/api/v1/clients/convergence", {})
        out["convergence_anonymous_401"] = r["status"] == 401
        cookie = login(port)
        csrf = session_info(port, cookie)["csrf_token"]

        # -- both fresh: one atomic sanitized envelope ----------------------
        client.record(ok_status(active=True))
        client.record({"ok": True, "request_id": "cv-list-1",
                       "data": {"clients": [
                           {"name": "legacy", "mutable": False,
                            "source": "untracked", "secret": "x"}],
                           "truncated": False, "leaked_field": "nope"}})
        inv0 = inv["n"]
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        body = json.loads(r["body"])
        st = body.get("status") or {}
        cl = body.get("clients") or {}
        out["convergence_200_all_fresh"] = (
            r["status"] == 200 and body.get("ok") is True
            and st.get("transport") == "fresh"
            and cl.get("transport") == "fresh")
        out["convergence_status_sanitized"] = (
            st.get("data", {}).get("management_state") == "active"
            and "path" not in st.get("data", {}).get("lock", {})
            and "leaked_field" not in st.get("data", {})
            and "secret" not in st.get("data", {})
            and st.get("management_active") is True
            and isinstance(st.get("monitor_running"), bool))
        client0 = cl.get("data", {}).get("clients", [{}])[0]
        out["convergence_clients_sanitized"] = (
            client0.get("name") == "legacy" and "secret" not in client0
            and cl.get("data", {}).get("truncated") is False)
        out["convergence_is_read_only"] = inv["n"] == inv0
        out["convergence_no_mutation_rpc"] = "client.add" not in client.calls

        # -- GET-only surface -----------------------------------------------
        r = req(port, "POST", "/api/v1/clients/convergence",
                {"Content-Type": "application/json", "Cookie": cookie,
                 "X-CSRF-Token": csrf}, "{}")
        out["convergence_post_405"] = r["status"] == 405

        # -- status refresh fails -> 503, never a half-answer ---------------
        clock.advance(2.5)
        client.reset_script()
        client.record(RuntimeError("stream EOF"))
        n_status = client.calls.count("management.status")
        n_list = client.calls.count("client.list")
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        body = json.loads(r["body"])
        out["convergence_status_failure_503"] = (
            r["status"] == 503 and body.get("ok") is False
            and body.get("code") == "e3_unavailable")
        out["convergence_status_failure_skips_list"] = (
            client.calls.count("client.list") == n_list)

        # -- list fails after a fresh status -> still 503 (all-or-nothing) ---
        clock.advance(2.5)
        client.reset_script()
        client.record(ok_status(active=True))
        client.record(RuntimeError("stream EOF"))
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        out["convergence_list_failure_503"] = r["status"] == 503

        # -- helper semantic verdict keeps its own mapping (not 200) --------
        clock.advance(2.5)
        client.reset_script()
        client.record({"ok": False, "request_id": "cv-lock",
                       "error": {"code": "E_LOCK", "stage": "lock",
                                 "retriable": True, "detail": "busy"}})
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        out["convergence_verdict_maps_through_error_table"] = (
            r["status"] == 423 and json.loads(r["body"]).get("code") == "E_LOCK")

        # -- open breaker is not bypassed through the endpoint --------------
        for i in range(3):
            clock.advance(2.5)
            client.reset_script()
            client.record(RuntimeError("stream EOF"))
            broker.status()
        out["convergence_breaker_open_setup"] = broker.breaker_state() == "open"
        n_status = client.calls.count("management.status")
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        out["convergence_never_bypasses_open_breaker"] = (
            r["status"] == 503
            and client.calls.count("management.status") == n_status)
        clock.advance(10.1)                           # heal via half-open
        client.reset_script()
        client.record(ok_status(active=True))
        broker.status()

        # -- the integration point: right after a confirmed add, with NO
        # clock movement at all, one convergence read returns fresh truth.
        step_up(port, cookie, csrf)
        client.reset_script()
        client.record({"ok": True, "request_id": "cv-add", "data": {}})
        r = mutate(port, "/api/v1/clients/add", cookie, csrf,
                   {"Idempotency-Key": "conv-key-%016d" % 77},
                   json.dumps({"name": "cv-07"}))
        out["convergence_after_add_precondition"] = r["status"] == 200
        client.reset_script()
        client.record(ok_status(active=True))
        client.record({"ok": True, "request_id": "cv-list-2",
                       "data": {"clients": [
                           {"name": "legacy", "mutable": False},
                           {"name": "cv-07", "mutable": True}],
                           "truncated": False}})
        r = req(port, "GET", "/api/v1/clients/convergence", {"Cookie": cookie})
        body = json.loads(r["body"])
        names = [c.get("name") for c in
                 body.get("clients", {}).get("data", {}).get("clients", [])]
        out["convergence_fresh_immediately_after_add_no_ttl_wait"] = (
            r["status"] == 200
            and body.get("status", {}).get("transport") == "fresh"
            and body.get("clients", {}).get("transport") == "fresh"
            and "cv-07" in names)
    finally:
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

        # M4: client.export travels the SAME framing with its name+actor;
        # the frozen 20s budget is per-op and no retry ever happens.
        out["export_budget_frozen_20s"] = \
            E3RpcClient().budgets.get("client.export") == 20.0
        ve = client.call("client.export", payload={"name": "vmix-01"},
                         actor={"session_fp": "0" * 16})
        out["export_wire_op_carried"] = ve.get("ok") is True \
            and ve.get("op") == "client.export"
        rid_e1 = ve.get("request_id")
        rid_e2 = client.call("client.export", payload={"name": "vmix-01"}
                             ).get("request_id")
        out["export_request_id_fresh_per_attempt"] = rid_e1 != rid_e2

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
    out.update(group_verdict_semantics())
    out.update(group_add_without_stepup())
    out.update(group_actor_freeze())
    out.update(group_stale_and_degraded())
    out.update(group_auth_lifecycle())
    out.update(group_http_adapter())
    out.update(group_export_broker())
    out.update(group_export_http())
    out.update(group_post_mutation_invalidation())
    out.update(group_http_post_mutation_invalidation())
    out.update(group_status_force())
    out.update(group_http_convergence_endpoint())
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

section_py 'B3/B4 static UI contracts'
# grep against FILES, not pipes: with pipefail, `printf | grep -q` can die of
# SIGPIPE the moment grep matches, flipping a true assertion to false (this
# exact race failed the Linux CI while passing locally).
APP_FILE="$ROOT/monitor-v2/web/static/app.js"
INDEX_FILE="$ROOT/monitor-v2/web/static/index.html"
if grep -qF 'function e3Writable' "$APP_FILE"; then
    pass 'B4: the single writable gate (e3Writable) exists'
else
    fail 'B4: the single writable gate (e3Writable) is missing'
fi
if grep -qF 'setPendingRetry' "$APP_FILE"; then
    pass 'B3: the pending uncertain-retry mechanism exists'
else
    fail 'B3: the pending uncertain-retry mechanism is missing'
fi
if grep -qF 'idempotencyKey: p.idempotencyKey' "$APP_FILE"; then
    pass 'B3: the explicit retry reuses the stored Idempotency-Key'
else
    fail 'B3: the explicit retry does not reuse the stored key'
fi
LOAD_FN="$(sed -n '/function loadE3Clients/,/^  }/p' "$APP_FILE")"
if printf '%s' "$LOAD_FN" | grep -qF 'data.transport'; then
    fail 'B4: loadE3Clients still references the undefined data variable'
else
    pass 'B4: the loadE3Clients failure branch is ReferenceError-free'
fi
if grep -qF 'e3-retry-btn' "$INDEX_FILE"; then
    pass 'B3: the explicit retry button is present in the UI'
else
    fail 'B3: the explicit retry button is missing'
fi

# B3-final: while a pending uncertain operation exists, the ordinary
# entrances are locked. Proven as control-flow ORDER inside each handler:
# the fail-safe guard must run BEFORE any key generation, which makes a
# normal click a zero-dispatch no-op (no request, no new key).
GUARD='if (state.e3PendingRetry || state.e3Mutation) return;'
ADD_FN="$(sed -n '/function addClient/,/^  }/p' "$APP_FILE")"
if printf '%s\n' "$ADD_FN" | grep -qF 'apiWithStepUp("/api/v1/clients/add"'; then
    fail 'UX: client.add still uses password step-up'
elif printf '%s\n' "$ADD_FN" | grep -qF 'api("/api/v1/clients/add"'; then
    pass 'UX: client.add uses session+CSRF without password step-up'
else
    fail 'UX: client.add dispatch route not found'
fi
DEL_FN="$(sed -n '/function deleteClient/,/^  }/p' "$APP_FILE")"
guard_before_keygen() { # <fn-body-file> -> rc 0 when guard precedes keygen
    FN="$1"
    g="$(grep -nF "$GUARD" "$FN" | head -1 | cut -d: -f1)"
    k="$(grep -nF 'newIdempotencyKey()' "$FN" | head -1 | cut -d: -f1)"
    [ -n "$g" ] && [ -n "$k" ] && [ "$g" -lt "$k" ]
}
printf '%s\n' "$ADD_FN" > "$ROOT/tests/.m2-add.$$"
printf '%s\n' "$DEL_FN" > "$ROOT/tests/.m2-del.$$"
if guard_before_keygen "$ROOT/tests/.m2-add.$$" \
        && guard_before_keygen "$ROOT/tests/.m2-del.$$"; then
    pass 'B3-final + 0.1.5 single-flight: the pending/mutation guard precedes key generation in add AND delete (ordinary click = zero dispatch, zero new keys)'
else
    fail 'B3-final: the pending-or-mutation guard is missing or ordered after key generation'
fi
rm -f "$ROOT/tests/.m2-add.$$" "$ROOT/tests/.m2-del.$$"
N_LOCK="$(grep -cF 'var writable = e3Writable() && !state.e3PendingRetry;' "$APP_FILE")"
if [ "$N_LOCK" -eq 2 ]; then
    pass 'B3-final: pending locks the controls in renderE3Controls AND renderE3Clients'
else
    fail "B3-final: expected the pending lock in exactly 2 render paths (got $N_LOCK)"
fi

section_py 'running the contract harness'
section_py 'executing the UI behavior regression'
if node "$ROOT/tests/test-monitor-v2-ui.cjs" > "$HARNESS.ui" 2>&1; then
    while IFS= read -r name; do
        pass "$name"
    done < "$HARNESS.ui"
else
    fail 'UI behavior regression failed'
    cat "$HARNESS.ui"
fi
rm -f "$HARNESS.ui"
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
