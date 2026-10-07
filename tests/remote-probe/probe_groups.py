#!/usr/bin/env python3
"""PR-6A deterministic harness for the dark office remote-probe agent.

Every group returns a flat dict of BOOLEAN verdicts that the shell lane turns
into counted gates, exactly like the other Monitor lanes. Nothing prints from
inside a group, and a crash is reported by the runner as a FAIL.

No test here needs the Internet, a real Mihomo, a real VPS, the production
server, or timing-sensitive external behaviour: every transport is a
controlled fake, every clock is injected, and every budget is a constant the
test can shrink.
"""

from __future__ import annotations

import base64
import errno
import glob
import http.client
import json
import os
import shutil
import socket
import ssl
import stat as stat_module
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "monitor-v2"))

import remote_probe as rp  # noqa: E402
from remote_probe import agent as ag  # noqa: E402
from remote_probe import delivery as dl  # noqa: E402
from remote_probe import direct_probe as dp  # noqa: E402
from remote_probe import evidence as ev  # noqa: E402
from remote_probe import mihomo_probe as mp  # noqa: E402
from remote_probe import payload as pl  # noqa: E402
from remote_probe import spool as sp  # noqa: E402

# Exactly 256-bit material: the FILE holds 64 lowercase hex characters, the
# SIGNING KEY is the decoded 32 bytes (issue #67 §5).
SECRET = bytes.fromhex("0123456789abcdef" * 4)
SECRET_TEXT = SECRET.hex()
SENTINEL = "SENTINEL-LEAK-CANARY-9f3a"
RUN = "0123456789abcdef0123456789abcdef"
LOOPBACK_URL = "http://127.0.0.1:9090"
# Real global unicast literals (documentation/private ranges are refused by the
# canonical gate, which is exactly what test 18 proves).
IP_A = "8.8.8.8"
IP_B = "1.1.1.1"


# -- fakes -------------------------------------------------------------------

class FakeTransport:
    """Mirrors the audited transport surface: get(path) ONLY, no method
    parameter. Records every call so a mutation attempt would be visible."""

    def __init__(self, routes=None, fail=None, gate=None):
        self.routes = routes or {}
        self.fail = fail or {}
        self.gate = gate
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if self.gate is not None:
            self.gate.wait(5.0)
        if path in self.fail:
            raise self.fail[path]
        if path in self.routes:
            return self.routes[path]
        # Longest-prefix match: the enumerated delay path carries the frozen
        # URL + timeout as a query string, so a node route is keyed by the
        # node's path prefix.
        matches = [key for key in self.routes if path.startswith(key)]
        if matches:
            return self.routes[max(matches, key=len)]
        return 404, b"{}"

    def mutation_calls(self):
        lowered = [call.lower() for call in self.calls]
        verbs = ("put ", "post ", "patch ", "delete ")
        return [call for call in lowered if call.startswith(verbs)]


class FakeHTTPResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, amount=None):
        return self._body


class FakeHTTPSConnection:
    """Canned HTTPS connection: records the request, never touches a socket."""

    log = []
    sensor = {"status": 200, "body": b"8.8.8.8", "raise": None}

    def __init__(self, host, port, timeout=None, context=None):
        FakeHTTPSConnection.log.append(
            {"host": host, "port": port, "context": context})

    def request(self, method, path, body=None, headers=None):
        FakeHTTPSConnection.log.append(
            {"method": method, "path": path, "headers": dict(headers or {})})

    def getresponse(self):
        raise_if = FakeHTTPSConnection.sensor.get("raise")
        if raise_if is not None:
            raise raise_if
        return FakeHTTPResponse(FakeHTTPSConnection.sensor["status"],
                                FakeHTTPSConnection.sensor["body"])

    def close(self):
        pass


def temp_dir(prefix="p6a-"):
    return tempfile.mkdtemp(prefix=prefix)


def clean(path):
    shutil.rmtree(path, ignore_errors=True)


def make_config(**over):
    raw = {
        "probe_id": "office-sg-isp-a",
        "ingest_url": "https://monitor.example.net/api/v1/remote-probes/ingest",
        "spool_dir": os.path.join(temp_dir(), "spool"),
        "ingest_secret_file": "/nonexistent/ignored-in-tests",
        "mihomo_url": LOOPBACK_URL,
        "reality_node": "office-reality-01",
        "hy2_node": "office-hy2-01",
        "dns_host": "www.cloudflare.com",
        "https_host": "www.cloudflare.com",
        "egress_host": "api.ipify.org",
        "vps_host": "vps.example.net",
        "vps_port": 443,
    }
    raw.update(over)
    return ag.AgentConfig.from_mapping(raw)


def valid_line(record_id, seq, epoch):
    """A canonical, decodable record line with a chosen record id."""
    record = {"v": 1, "record_id": record_id,
              "probe_id": "office-sg-isp-a", "run": RUN, "seq": seq,
              "queued_epoch": epoch,
              "body_b64": base64.b64encode(
                  pl.encode_sample(_sample(seq))).decode("ascii")}
    return sp.canonical_bytes(record)


def chain_bytes(directory):
    """EXACT bytes the record chain occupies on disk (all members)."""
    total = 0
    for path in glob.glob(os.path.join(directory, sp.SPOOL_FILE + "*")):
        if os.path.isfile(path):
            total += os.lstat(path).st_size
    return total


def proxies_payload(reality=True, hy2=True, selected=None, delay=42):
    proxies = {}
    if reality:
        proxies["office-reality-01"] = {"type": "Vless", "alive": True,
                                        "history": [{"time": "t", "delay": delay}]}
    if hy2:
        proxies["office-hy2-01"] = {"type": "Hysteria2", "alive": True,
                                    "history": [{"time": "t", "delay": delay}]}
    if selected is not None:
        proxies["Selector"] = {"type": "Selector", "now": selected,
                               "history": []}
    return {"proxies": proxies}


def delay_route(status=200, payload=None):
    body = json.dumps(payload if payload is not None else {"delay": 82}).encode()
    return status, body


def delay_path(node):
    return None  # placeholder (paths are matched by prefix in tests)


def _run_counter():
    """Deterministic but DISTINCT run ids: the run identity must change on
    every new run (restart, rollback), so the fake source increments."""
    counter = {"n": 0}

    def make(n):
        counter["n"] += 1
        return bytes([counter["n"]]) + bytes(n - 1)
    return make


def build_agent(**over):
    """An agent with every external dependency injected."""
    config = make_config(**over.pop("config_over", {}))
    transport = over.pop("transport", FakeTransport())
    mihomo = mp.P6Mihomo(config.mihomo_url, watched_group=config.watched_group,
                         secret="", transport=transport)
    spool = sp.Spool(config.spool_dir,
                     clock=over.pop("clock", lambda: 1700000000.0))
    instance = ag.RemoteProbeAgent(
        config, spool=spool, mihomo=mihomo,
        clock=over.pop("clock", lambda: 1700000000.0),
        poster=over.pop("poster", None),
        secret_loader=over.pop("secret_loader", lambda path: SECRET),
        random_bytes=over.pop("random_bytes", _run_counter()))
    return instance, transport


class FakePoster:
    """Scripted ingest endpoint: a queue of responses or exceptions."""

    def __init__(self, script=None):
        self.script = list(script or [])
        self.requests = []

    def __call__(self, body, headers):
        self.requests.append({"body": body, "headers": dict(headers)})
        if not self.script:
            return 200, b'{"result":"accepted","v":1}'
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# -- group: roles (explicit, never name-inferred) -----------------------------

def group_roles():
    out = {}
    reality, hy2 = "office-reality-01", "office-hy2-01"
    # A name that LOOKS like a protocol must not be mapped onto a role.
    out["name_lookalike_is_not_a_role"] = (
        mp.P6Mihomo.role_for("Reality-01", reality, hy2) is None
        and mp.P6Mihomo.role_for("hy2-node", reality, hy2) is None
        and mp.P6Mihomo.role_for("HYSTERIA2", reality, hy2) is None)
    out["configured_identities_map_exactly"] = (
        mp.P6Mihomo.role_for(reality, reality, hy2) == rp.ROLE_REALITY
        and mp.P6Mihomo.role_for(hy2, reality, hy2) == rp.ROLE_HY2)
    # Same node for both roles is refused: one path may not masquerade as two.
    try:
        make_config(hy2_node="office-reality-01")
        out["duplicate_role_nodes_refused"] = False
    except ag.ConfigError:
        out["duplicate_role_nodes_refused"] = True
    instance, _t = build_agent()
    try:
        roles = instance._node_roles()
        out["agent_roles_come_from_config"] = (
            roles == {rp.ROLE_REALITY: reality, rp.ROLE_HY2: hy2})
    finally:
        clean(instance.config.spool_dir)
    # The module carries no name-pattern table at all.
    source = open(os.path.join(ROOT, "monitor-v2", "remote_probe",
                               "mihomo_probe.py"), encoding="utf-8").read()
    out["no_name_inference_table"] = (
        "reality" not in source.lower().replace("role_reality", "")
        or "startswith" not in source)
    return out


# -- group: active diagnostics -------------------------------------------------

def _delay_agent(route, config_over=None):
    transport = FakeTransport({"/proxies/office-reality-01/delay": route})
    transport.routes["/proxies"] = (200, json.dumps(
        proxies_payload(reality=True, hy2=False)).encode())
    transport.routes["/version"] = (200, b'{"version":"1.18"}')
    agent_instance, transport = build_agent(transport=transport,
                                            config_over=config_over or {})
    agent_instance.open()
    return agent_instance, transport


def group_active():
    out = {}
    # 2. positive success
    instance, _t = _delay_agent(delay_route(200, {"delay": 82}))
    try:
        outcome, delay, _note = instance.mihomo.delay(
            rp.ROLE_REALITY, "office-reality-01")
        out["active_success_is_ok_with_positive_delay"] = (
            outcome == rp.OUTCOME_OK and delay == 82)
    finally:
        instance.spool.enforce_bounds()
        clean(instance.config.spool_dir)
    # 3. timeout
    for status in (408, 504):
        instance, _t = _delay_agent((status, b'{"message":"timeout"}'))
        try:
            outcome, delay, _n = instance.mihomo.delay(
                rp.ROLE_REALITY, "office-reality-01")
            out["active_timeout_status_%d" % status] = (
                outcome == rp.OUTCOME_TIMEOUT and delay is None)
        finally:
            instance.spool.close()
            clean(instance.config.spool_dir)
    # A 400 is the controller rejecting the REQUEST (parameter, endpoint, API
    # contract): a configuration/contract error must never read as a path
    # timeout.
    instance, _t = _delay_agent((400, b'{"message":"An error occurred in the delay test"}'))
    try:
        outcome, delay, _n = instance.mihomo.delay(
            rp.ROLE_REALITY, "office-reality-01")
        out["active_status_400_is_invalid_not_timeout"] = (
            outcome == rp.OUTCOME_INVALID and delay is None)
    finally:
        instance.spool.close()
        clean(instance.config.spool_dir)
    # A positive delay larger than the <=5 s test budget cannot have come from
    # that test.
    instance, _t = _delay_agent(delay_route(200, {"delay": 60000}))
    try:
        outcome, delay, _n = instance.mihomo.delay(
            rp.ROLE_REALITY, "office-reality-01")
        out["active_impossible_delay_is_invalid"] = (
            outcome == rp.OUTCOME_INVALID and delay is None)
    finally:
        instance.spool.close()
        clean(instance.config.spool_dir)
    # 4. delay == 0 is a FAILED test, never 0 ms of latency
    instance, _t = _delay_agent(delay_route(200, {"delay": 0}))
    try:
        outcome, delay, _n = instance.mihomo.delay(rp.ROLE_REALITY,
                                                   "office-reality-01")
        out["active_delay_zero_is_failure_not_zero_ms"] = (
            outcome == rp.OUTCOME_UNAVAILABLE and delay is None)
    finally:
        clean(instance.config.spool_dir)
    # 5. malformed replies
    malformed = [b"not json", b"[1,2,3]", b'{"delay":"82"}', b'{"delay":true}',
                 b'{"delay":1.5}', b'{"other":82}', b'{"delay":-1}']
    results = []
    for body in malformed:
        instance, _t = _delay_agent((200, body))
        try:
            outcome, delay, _n = instance.mihomo.delay(
                rp.ROLE_REALITY, "office-reality-01")
            results.append(outcome == rp.OUTCOME_INVALID and delay is None)
        finally:
            clean(instance.config.spool_dir)
    out["active_malformed_reply_is_invalid"] = all(results)
    # 6. missing configured node -> invalid, and configuration is NOT path
    #    failure evidence anywhere in the sample
    instance, _t = _delay_agent(delay_route(), {})
    instance.mihomo.watched_group = None
    try:
        sample = instance.collect_sample(now=1700000000.0)
        hy2 = [e for e in sample["active"]
               if e["role"] == rp.ROLE_HY2 and e["source"] == "active_delay"]
        reality = [e for e in sample["active"]
                   if e["role"] == rp.ROLE_REALITY
                   and e["source"] == "active_delay"]
        out["missing_node_is_invalid_not_path_down"] = (
            len(hy2) == 1 and hy2[0]["outcome"] == rp.OUTCOME_INVALID
            and hy2[0]["delay_ms"] is None
            and len(reality) == 1
            and reality[0]["outcome"] == rp.OUTCOME_OK)
        out["no_active_entry_is_ever_labelled_down"] = all(
            entry["outcome"] in rp.ACTIVE_OUTCOMES for entry in sample["active"])
    finally:
        clean(instance.config.spool_dir)
    # 7/8. per-node <= 5 s and the cycle deadline bound
    out["per_node_timeout_within_contract"] = (
        rp.DELAY_TIMEOUT_SECONDS <= 5.0
        and mp.TRANSPORT_TIMEOUT_SECONDS <= rp.DELAY_TIMEOUT_SECONDS)
    try:
        make_config(cycle_deadline=21.0)
        out["cycle_deadline_over_20s_refused"] = False
    except ag.ConfigError:
        out["cycle_deadline_over_20s_refused"] = True
    try:
        make_config(diagnostic_timeout=6.0)
        out["diagnostic_timeout_over_5s_refused"] = False
    except ag.ConfigError:
        out["diagnostic_timeout_over_5s_refused"] = True
    # a hanging gate: the cycle must still return, bounded by its deadline
    gate = threading.Event()
    transport = FakeTransport(gate=gate)
    instance, transport = build_agent(
        transport=transport, config_over={"cycle_deadline": 0.4})
    instance.monotonic = lambda: 0.0    # frozen clock: worst case for deadlines
    try:
        instance.open()
        started = threading.Event()
        result = {}

        def run():
            started.set()
            result["value"] = instance.run_cycle(now=1700000000.0)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        started.wait(2.0)
        worker.join(6.0)
        out["cycle_returns_within_its_deadline"] = (
            not worker.is_alive() and result.get("value") is not None)
    finally:
        gate.set()
        clean(instance.config.spool_dir)
    # 9. no overlapping cycles
    instance, _t = build_agent()
    try:
        instance._cycle_lock.acquire()
        refused = instance.run_cycle(now=1700000000.0)
        instance._cycle_lock.release()
        out["overlapping_cycle_refused"] = (
            refused.get("outcome") == "overlap_refused"
            and instance.overlap_refusals == 1)
    finally:
        clean(instance.config.spool_dir)
    # 10. minimum cadence
    try:
        make_config(cadence=29.0)
        out["cadence_below_30s_refused"] = False
    except ag.ConfigError:
        out["cadence_below_30s_refused"] = True
    out["cadence_defaults_are_60_and_30"] = (
        rp.CADENCE_DEFAULT_SECONDS == 60.0 and rp.CADENCE_MIN_SECONDS == 30.0)
    out["cadence_30s_accepted"] = (
        make_config(cadence=30.0).cadence == 30.0)
    return out


# -- group: Mihomo boundary ----------------------------------------------------

def group_boundary():
    out = {}
    # 11. loopback-only controller
    for url in ("http://10.0.0.5:9090", "http://example.com:9090",
                "http://0.0.0.0:9090"):
        try:
            mp.P6Mihomo(url, transport=FakeTransport())
            out["controller_%s_refused" % url] = False
        except mp.ConfigurationError:
            out["controller_%s_refused" % url] = True
    out["controller_loopback_accepted"] = (
        mp.P6Mihomo(LOOPBACK_URL, transport=FakeTransport()) is not None)
    # 12. no generic mutation-capable surface
    import inspect
    out["transport_has_no_method_parameter"] = (
        "method" not in inspect.signature(
            mp.HttpTransport.get).parameters)
    mihomo_src = open(os.path.join(ROOT, "monitor-v2", "remote_probe",
                                   "mihomo_probe.py"), encoding="utf-8").read()
    out["mihomo_surface_has_no_mutation_verb"] = not any(
        ('"%s"' % verb) in mihomo_src or ("'%s'" % verb) in mihomo_src
        for verb in ("PUT", "POST", "PATCH", "DELETE"))
    # P6B2 adds pinned TLS alongside the original delivery transport. Both
    # callers must still use the same frozen URL validator/path, never Mihomo.
    import ast
    posts = []
    for path in glob.glob(os.path.join(ROOT, "monitor-v2", "remote_probe",
                                       "*.py")):
        text = open(path, encoding="utf-8").read()
        if 'conn.request("POST"' in text:
            posts.append(os.path.basename(path))
    ingest_sources = [open(os.path.join(ROOT, "monitor-v2", "remote_probe", name),
                           encoding="utf-8").read()
                      for name in ("delivery.py", "pinned_transport.py")]
    post_nodes = [node for text in ingest_sources for node in ast.walk(ast.parse(text))
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "request"]
    out["only_the_frozen_ingest_post_exists"] = (
        sorted(posts) == ["delivery.py", "pinned_transport.py"]
        and rp.INGEST_METHOD == "POST"
        and len(post_nodes) == 2
        and all(len(node.args) >= 2 and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "POST"
                and isinstance(node.args[1], ast.Attribute)
                and isinstance(node.args[1].value, ast.Name)
                and node.args[1].value.id == "self" and node.args[1].attr == "path"
                for node in post_nodes)
        and all("classify_url(url)" in text for text in ingest_sources)
        and "path != INGEST_PATH" in ingest_sources[0])
    out["p6_surface_exposes_named_ops_only"] = all(
        hasattr(mp.P6Mihomo, name)
        for name in ("version", "proxies", "delay"))
    out["p6_surface_has_no_request_method"] = not any(
        hasattr(mp.P6Mihomo, name)
        for name in ("request", "method", "send", "post", "put", "delete"))
    # 13. a full cycle issues GETs only
    transport = FakeTransport({
        "/version": (200, b'{"version":"1.18"}'),
        "/proxies": (200, json.dumps(proxies_payload()).encode()),
        "/proxies/office-reality-01/delay": delay_route(),
    })
    instance, transport = build_agent(transport=transport)
    try:
        instance.open()
        instance.mihomo.diagnostic_url = rp.P6_DIAGNOSTIC_URL
        instance.collect_sample(now=1700000000.0)
        out["cycle_issues_reads_only"] = transport.mutation_calls() == []
        out["cycle_hits_only_reviewed_paths"] = all(
            call.startswith("/version") or call.startswith("/proxies")
            for call in transport.calls)
        out["active_delay_path_is_the_one_enumerated_op"] = any(
            "/delay?" in call and "url=" in call for call in transport.calls)
        out["delay_path_carries_no_secret"] = all(
            SECRET_TEXT not in call and "token" not in call.lower()
            for call in transport.calls)
    finally:
        clean(instance.config.spool_dir)
    # 46. a cycle whose probes ALL fail still only reads
    failing = FakeTransport(fail={"/version": mp.TransportError("dead")})
    instance, failing = build_agent(transport=failing)
    try:
        instance.open()
        instance.run_cycle(now=1700000000.0)
        out["failures_never_mutate_mihomo"] = (
            failing.mutation_calls() == []
            and all(call.startswith("/") for call in failing.calls))
    finally:
        clean(instance.config.spool_dir)
    return out


# -- group: direct slots -------------------------------------------------------

def group_direct():
    out = {}
    original_https = dp.http.client.HTTPSConnection
    original_dns = dp.socket.getaddrinfo
    original_tcp = dp.socket.create_connection
    try:
        # 14. DNS bounded
        dp.socket.getaddrinfo = lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        slot = dp.probe_dns("www.example.net")
        out["dns_ok_slot"] = (slot["status"] == dp.STATUS_OK
                              and slot["latency_ms"] is not None)

        def dns_fail(*_a, **_k):
            raise socket.gaierror(-2, "name resolution")
        dp.socket.getaddrinfo = dns_fail
        out["dns_failure_is_closed_code"] = (
            dp.probe_dns("nope.example.net")["error_code"] == dp.ERR_DNS_FAILED)

        def dns_hang(*_a, **_k):
            threading.Event().wait(5.0)
            return []
        dp.socket.getaddrinfo = dns_hang
        out["dns_hang_becomes_timeout"] = (
            dp.probe_dns("slow.example.net",
                         budget=0.05)["error_code"] == dp.ERR_TIMEOUT)
        # 15. direct HTTPS bounded, with TLS validation in play
        dp.socket.getaddrinfo = original_dns
        dp.http.client.HTTPSConnection = FakeHTTPSConnection
        FakeHTTPSConnection.sensor = {"status": 200, "body": b"ok",
                                      "raise": None}
        slot = dp.probe_https("www.example.net")
        used_context = [entry for entry in FakeHTTPSConnection.log
                        if "context" in entry]
        out["https_ok_slot"] = slot["status"] == dp.STATUS_OK
        out["https_uses_a_tls_context"] = bool(used_context) and all(
            entry["context"] is not None for entry in used_context)
        FakeHTTPSConnection.sensor = {"status": 500, "body": b"boom",
                                      "raise": None}
        out["https_bad_status_is_bad_response"] = (
            dp.probe_https("www.example.net")["error_code"]
            == dp.ERR_BAD_RESPONSE)
        FakeHTTPSConnection.sensor = {"status": 200, "body": b"",
                                      "raise": ssl.SSLCertVerificationError(
                                          "cert")}
        out["https_cert_failure_is_tls_failed"] = (
            dp.probe_https("www.example.net")["error_code"] == dp.ERR_TLS_FAILED)
        FakeHTTPSConnection.sensor = {"status": 200, "body": b"",
                                      "raise": ConnectionResetError("reset")}
        out["https_network_failure_is_connect_failed"] = (
            dp.probe_https("www.example.net")["error_code"]
            == dp.ERR_CONNECT_FAILED)
        # 16. VPS TCP is transport-only
        dp.socket.create_connection = lambda *a, **k: _DummySocket()
        slot = dp.probe_tcp("vps.example.net", 443)
        out["vps_tcp_ok_slot"] = slot["status"] == dp.STATUS_OK
        out["vps_tcp_slot_names_transport_only"] = (
            set(slot) == {"status", "latency_ms", "error_code"}
            and "handshake" not in json.dumps(slot).lower()
            and "reality" not in json.dumps(slot).lower())

        def tcp_fail(*_a, **_k):
            raise ConnectionRefusedError("refused")
        dp.socket.create_connection = tcp_fail
        out["vps_tcp_refused_is_connect_failed"] = (
            dp.probe_tcp("vps.example.net", 443)["error_code"]
            == dp.ERR_CONNECT_FAILED)
        dp.socket.create_connection = original_tcp
        # 17. no UDP/HY2 reachability verdict anywhere
        payload_keys = set(pl.SAMPLE_KEYS)
        out["payload_has_no_udp_slot"] = not any(
            "udp" in key for key in payload_keys)
        udp_users = []
        for path in glob.glob(os.path.join(ROOT, "monitor-v2", "remote_probe",
                                          "*.py")):
            text = open(path, encoding="utf-8").read()
            if "SOCK_DGRAM" in text or "sendto(" in text:
                udp_users.append(os.path.basename(path))
        out["no_unauthenticated_udp_probe"] = not udp_users
        # 18. egress IP validation + change semantics
        FakeHTTPSConnection.log = []
        FakeHTTPSConnection.sensor = {"status": 200, "body": IP_A.encode(),
                                      "raise": None}
        slot = dp.probe_egress("api.ipify.org", previous=IP_B)
        out["egress_valid_public_ip_accepted"] = (
            slot["status"] == dp.STATUS_OK and slot["ip"] == IP_A
            and slot["change"] == dp.CHANGE_CHANGED)
        FakeHTTPSConnection.sensor = {"status": 200, "body": IP_A.encode(),
                                      "raise": None}
        out["egress_unchanged_detected"] = (
            dp.probe_egress("api.ipify.org", previous=IP_A)["change"]
            == dp.CHANGE_UNCHANGED)
        for bad in (b"10.0.0.1", b"127.0.0.1", b"224.0.0.1", b"not-an-ip",
                    b"2001:db8::1"):
            FakeHTTPSConnection.sensor = {"status": 200, "body": bad,
                                          "raise": None}
            result = dp.probe_egress("api.ipify.org", previous=IP_A)
            out["egress_rejects_%s" % bad.decode().replace(":", "_")] = (
                result["ip"] is None
                and result["status"] == dp.STATUS_FAILED
                and result["change"] == dp.CHANGE_UNKNOWN)
        out["egress_change_mirrors_audited_judgement"] = (
            dp.classify_egress_change(IP_A, IP_B) == dp.CHANGE_CHANGED
            and dp.classify_egress_change(IP_A, IP_A) == dp.CHANGE_UNCHANGED
            and dp.classify_egress_change(None, IP_A) == dp.CHANGE_UNKNOWN
            and dp.classify_egress_change("10.0.0.1", IP_A) == dp.CHANGE_UNKNOWN)
    finally:
        dp.http.client.HTTPSConnection = original_https
        dp.socket.getaddrinfo = original_dns
        dp.socket.create_connection = original_tcp
    return out


class _DummySocket:
    def close(self):
        pass


# -- group: echo / non-corroboration ------------------------------------------

def group_echo():
    out = {}
    active = [ev.active_entry(rp.ROLE_REALITY, rp.OUTCOME_OK, 82)]
    echo = [ev.passive_entry(rp.ROLE_REALITY, rp.OUTCOME_OK, 82)]
    entries, corroboration, dropped = ev.merge_evidence(active, echo)
    out["own_echo_is_not_independent"] = (
        dropped == 1
        and sum(1 for entry in entries if entry["independent"]) == 1
        and corroboration == 1)
    organic = [ev.passive_entry(rp.ROLE_HY2, rp.OUTCOME_OK, 40, "organic-test")]
    entries, corroboration, dropped = ev.merge_evidence(active, organic)
    out["organic_passive_evidence_stays_independent"] = (
        dropped == 0 and corroboration == 2)
    # a sample built with an echo present still counts ONE source for that role
    sample = {
        "v": 1, "probe_id": "office-sg-isp-a", "run": RUN, "seq": 1,
        "sample_epoch": 1700000000.0,
        "dns": dp._slot(dp.STATUS_OK, 5), "https": dp._slot(dp.STATUS_OK, 6),
        "vps_tcp": dp._slot(dp.STATUS_OK, 7),
        "egress": {"status": "ok", "latency_ms": 8, "error_code": "NONE",
                   "ip": IP_A, "change": "unknown"},
        "mihomo_api": {"status": "ok"},
        "active": entries,
        "flags": {"truncated": False, "source_unavailable": []},
    }
    out["echo_never_double_counts_in_a_body"] = (
        pl.validate_sample(sample) == [] and corroboration == 2)
    # and the rule is keyed on (role, test_id), not on timing
    late_echo = [ev.passive_entry(rp.ROLE_REALITY, rp.OUTCOME_OK, 999)]
    _entries, corroboration, dropped = ev.merge_evidence(active, late_echo)
    out["late_echo_still_demoted"] = dropped == 1 and corroboration == 1
    return out


# -- group: payload / identity -------------------------------------------------

def group_payload():
    out = {}
    sample = {
        "v": 1, "probe_id": "office-sg-isp-a", "run": RUN, "seq": 1,
        "sample_epoch": 1700000000.0,
        "dns": dp._slot(dp.STATUS_OK, 5), "https": dp._slot(dp.STATUS_OK, 6),
        "vps_tcp": dp._slot(dp.STATUS_OK, 7),
        "egress": {"status": "ok", "latency_ms": 8, "error_code": "NONE",
                   "ip": IP_A, "change": "unchanged"},
        "mihomo_api": {"status": "ok"},
        "active": [ev.active_entry(rp.ROLE_REALITY, rp.OUTCOME_OK, 82)],
        "flags": {"truncated": False, "source_unavailable": []},
    }
    raw = pl.encode_sample(sample)
    out["canonical_bytes_are_stable"] = (
        pl.canonical_bytes(sample) == raw == pl.canonical_bytes(sample))
    out["canonical_roundtrip_holds"] = pl.canonical_roundtrip_ok(raw)
    out["encoding_is_compact_and_sorted"] = (
        b'": "' not in raw and b", " not in raw
        and raw.index(b'"active"') < raw.index(b'"vps_tcp"'))
    out["re_encode_is_byte_identical"] = (
        pl.canonical_bytes(json.loads(raw.decode())) == raw)
    # 21. size
    out["valid_body_is_far_below_the_cap"] = len(raw) < rp.MAX_BODY_BYTES // 8
    bloated = json.loads(raw.decode())
    bloated["flags"]["source_unavailable"] = []
    bloated["active"][0]["test_id"] = "x" * pl.MAX_TEST_ID_LEN
    del bloated
    oversized = dict(sample)
    oversized["probe_id"] = "a" * 64
    out["body_cap_is_16kib"] = (
        rp.MAX_BODY_BYTES == 16 * 1024
        and len(pl.encode_sample(oversized)) <= rp.MAX_BODY_BYTES)
    # unknown fields / schema closure
    for mutate, label in (
            (lambda s: s.update({"extra": 1}), "unknown_root_key"),
            (lambda s: s["dns"].update({"extra": 1}), "unknown_slot_key"),
            (lambda s: s.update({"v": 2}), "wrong_version"),
            (lambda s: s.update({"probe_id": "Bad-ID"}), "bad_probe_id"),
            (lambda s: s.update({"run": "zz"}), "bad_run"),
            (lambda s: s.update({"seq": 0}), "bad_seq"),
            (lambda s: s.update({"seq": True}), "bool_seq"),
            (lambda s: s.update({"sample_epoch": -1}), "negative_epoch"),
            (lambda s: s["dns"].update({"status": "ok", "error_code": "timeout"}),
             "ok_with_error_code"),
            (lambda s: s["active"][0].update({"delay_ms": 0}), "zero_delay"),
            (lambda s: s["active"][0].update({"outcome": "down"}), "bad_outcome"),
            (lambda s: s["mihomo_api"].update({"status": "down"}), "bad_api_status"),
            (lambda s: s["flags"].update({"unknown_source": ["x"]}),
             "bad_source_token")):
        broken = json.loads(raw.decode())
        mutate(broken)
        out["schema_rejects_%s" % label] = bool(pl.validate_sample(broken))
    out["schema_accepts_the_canonical_sample"] = pl.validate_sample(sample) == []
    # 22. deterministic HMAC vector: an independent re-implementation
    import hashlib
    import hmac as hmac_mod
    sent_epoch = 1700000001
    digest = hashlib.sha256(raw).hexdigest()
    expected_input = ("p6-v1\nPOST\n/api/v1/remote-probes/ingest\n%s\n%d\n%s\n%d\n%s"
                      % (sample["probe_id"], sent_epoch, sample["run"],
                         sample["seq"], digest)).encode("ascii")
    expected = hmac_mod.new(SECRET, expected_input,
                            hashlib.sha256).hexdigest()
    actual = pl.sign(SECRET, sample["probe_id"], sent_epoch, sample["run"],
                     sample["seq"], raw)
    out["hmac_vector_matches_independent_implementation"] = actual == expected
    out["signature_binds_probe_id"] = (
        pl.verify_signature(SECRET, "other-probe", sent_epoch, sample["run"],
                            sample["seq"], raw, actual) is False)
    out["signature_binds_seq_and_run"] = (
        pl.verify_signature(SECRET, sample["probe_id"], sent_epoch, sample["run"],
                            sample["seq"] + 1, raw, actual) is False
        and pl.verify_signature(SECRET, sample["probe_id"], sent_epoch, "f" * 32,
                                sample["seq"], raw, actual) is False)
    out["signature_binds_body_digest"] = (
        pl.verify_signature(SECRET, sample["probe_id"], sent_epoch, sample["run"],
                            sample["seq"], raw + b" ", actual) is False)
    out["signature_verification_is_constant_time_helper"] = (
        pl.verify_signature.__doc__ is not None
        and "constant-time" in pl.verify_signature.__doc__.lower())
    out["domain_separator_is_frozen"] = (
        rp.P6_PROTOCOL == "p6-v1"
        and pl.signature_input(sample["probe_id"], sent_epoch, sample["run"],
                               sample["seq"], raw).startswith(b"p6-v1\nPOST\n"))
    out["headers_carry_the_five_frozen_fields"] = (
        set(pl.headers("p", 1, RUN, 1, "sig")) >= {
            "X-Remote-Probe-Id", "X-Remote-Probe-Sent-Epoch",
            "X-Remote-Probe-Run", "X-Remote-Probe-Seq",
            "X-Remote-Probe-Signature"})
    out["signature_input_rejects_bad_grammar"] = False
    try:
        pl.signature_input("Bad-ID", 1, RUN, 1, raw)
    except ValueError:
        out["signature_input_rejects_bad_grammar"] = True
    # 23/24. grammar + monotonic seq
    out["run_grammar"] = (pl.valid_run(RUN) and not pl.valid_run(RUN.upper())
                          and not pl.valid_run("ab") and not pl.valid_run(1))
    out["probe_id_grammar"] = (pl.valid_probe_id("office-sg-isp-a")
                               and pl.valid_probe_id("-")   # grammar allows it
                               and pl.valid_probe_id("a" * 64)
                               and not pl.valid_probe_id("Office")
                               and not pl.valid_probe_id("a" * 65)
                               and not pl.valid_probe_id("a_b")
                               and not pl.valid_probe_id(""))
    out["seq_bounds"] = (pl.valid_seq(1) and pl.valid_seq(rp.SEQ_MAX)
                         and not pl.valid_seq(0) and not pl.valid_seq(rp.SEQ_MAX + 1)
                         and not pl.valid_seq(True))
    instance, _t = build_agent()
    try:
        instance.open()
        seqs = [instance.next_seq() for _ in range(3)]
        out["seq_is_strictly_increasing_per_run"] = seqs == [1, 2, 3]
        out["run_is_128_bit_hex"] = (
            pl.valid_run(instance.run) and len(instance.run) == 32)
    finally:
        clean(instance.config.spool_dir)
    return out


# -- group: spool ---------------------------------------------------------------

def group_spool():
    out = {}
    root = temp_dir()
    directory = os.path.join(root, "spool")
    clock = [1700000000.0]
    queue = sp.Spool(directory, clock=lambda: clock[0]).open()
    body = pl.encode_sample(_sample(1))
    try:
        record_id = queue.append("office-sg-isp-a", RUN, 1, body,
                                 queued_epoch=clock[0])
        # 26. spool-before-ack: the record is durable BEFORE any upload.
        # The spool is single-writer, so the first handle is closed first.
        queue.close()
        reopened = sp.Spool(directory, clock=lambda: clock[0]).open()
        pending = list(reopened.pending())
        out["spool_survives_reopen_before_any_ack"] = (
            record_id == 1 and len(pending) == 1
            and pending[0]["body"] == body and pending[0]["seq"] == 1)
        # 27/28. retry keeps bytes/tuple and refreshes epoch + signature
        poster = FakePoster([(503, b"")])
        result = dl.deliver_pending(reopened, SECRET, "office-sg-isp-a",
                                    poster, now_epoch=1700000100)
        first_headers = poster.requests[0]["headers"]
        out["retry_keeps_record_queued"] = (
            result["retries"] == 1 and len(list(reopened.pending())) == 1)
        poster2 = FakePoster([(200, b'{"result":"accepted","v":1}')])
        dl.deliver_pending(reopened, SECRET, "office-sg-isp-a", poster2,
                           now_epoch=1700000200)
        second_headers = poster2.requests[0]["headers"]
        out["retry_preserves_exact_body_and_tuple"] = (
            poster2.requests[0]["body"] == body
            and first_headers["X-Remote-Probe-Run"]
            == second_headers["X-Remote-Probe-Run"]
            and first_headers["X-Remote-Probe-Seq"]
            == second_headers["X-Remote-Probe-Seq"]
            and first_headers["X-Remote-Probe-Id"]
            == second_headers["X-Remote-Probe-Id"])
        out["retry_refreshes_sent_epoch_and_signature"] = (
            first_headers["X-Remote-Probe-Sent-Epoch"]
            != second_headers["X-Remote-Probe-Sent-Epoch"]
            and first_headers["X-Remote-Probe-Signature"]
            != second_headers["X-Remote-Probe-Signature"])
        out["ack_removes_the_record"] = list(reopened.pending()) == []
        out["spool_status_is_closed_and_counted"] = (
            set(reopened.status()) == set(sp.STATUS_KEYS)
            and reopened.status()["acknowledged_total"] == 1)
        # 43. no poison head: a permanent record resolves and later records
        #     are still delivered in the SAME pass
        # ONE writer per spool directory (the reopened instance owns it now):
        # a stale second instance must never be the one that resolves records.
        reopened.append("office-sg-isp-a", RUN, 2,
                        pl.encode_sample(_sample(2)), queued_epoch=clock[0])
        reopened.append("office-sg-isp-a", RUN, 3,
                        pl.encode_sample(_sample(3)), queued_epoch=clock[0])
        poison = FakePoster([(400, b"nope"), (200, b'{"result":"accepted","v":1}')])
        summary = dl.deliver_pending(reopened, SECRET, "office-sg-isp-a",
                                     poison, now_epoch=1700000300)
        out["permanent_record_does_not_block_the_queue"] = (
            summary["quarantined"] == 1 and summary["acked"] == 1
            and list(reopened.pending()) == [])
        out["quarantine_ledger_is_sanitized"] = (
            all(set(entry) == {"token", "record_id", "epoch"}
                for entry in reopened._state["quarantine"])
            and "nope" not in json.dumps(reopened.status()))
    finally:
        clean(root)
    # 29. torn tail
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    path = os.path.join(directory, sp.SPOOL_FILE)
    with open(path, "ab") as handle:
        handle.write(b'{"v":1,"record_id":2,"probe_id":"office-sg-isp-a"')
    queue.close()          # single writer: hand the directory over explicitly
    repaired = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    out["torn_tail_repaired"] = (
        len(list(repaired.pending())) == 1
        and open(path, "rb").read().endswith(b"\n"))
    # a complete-but-corrupt line is counted, not rewritten away silently
    with open(path, "ab") as handle:
        handle.write(b'{"v":1,"record_id":3,"probe_id":"office-sg-isp-a","run":"%s","seq":3,"queued_epoch":1700000000.0,"body_b64":"!!!!"}\n'
                     % RUN.encode())
    repaired.close()
    counted = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    out["corrupt_complete_line_is_counted"] = (
        list(counted.pending()) == list(repaired.pending())
        and counted.status()["corrupt_total"] == 1)
    clean(root)
    # 30. durability primitives: rotation, ordering, fsync discipline
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     file_bytes=600, max_files=3).open()
    for index in range(6):
        queue.append("office-sg-isp-a", RUN, index + 1,
                     pl.encode_sample(_sample(index + 1)),
                     queued_epoch=1700000000.0 + index)
    rotated = sorted(os.path.basename(p) for p in glob.glob(
        os.path.join(directory, "spool.jsonl*")))
    out["rotation_creates_the_bounded_chain"] = (
        len(rotated) >= 2 and all(name.startswith("spool.jsonl") for name in rotated))
    pending = list(queue.pending())
    out["rotation_preserves_oldest_first_order"] = (
        [item["seq"] for item in pending] == sorted(item["seq"] for item in pending)
        and len(pending) >= 1)
    out["write_is_fsynced_before_it_counts"] = _fsync_was_used()
    clean(root)
    # 34/35. bounds
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700003600.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700003600.0 - 8 * 86400.0)   # 8 days old
    queue.append("office-sg-isp-a", RUN, 2, pl.encode_sample(_sample(2)),
                 queued_epoch=1700003600.0)
    status = queue.enforce_bounds()
    queue.close()
    out["seven_day_bound_expires_old_records"] = status["expired_total"] >= 1
    out["spool_bounds_match_the_contract"] = (
        sp.MAX_AGE_SECONDS <= 7 * 86400.0
        and sp.MAX_TOTAL_BYTES <= 32 * 1024 * 1024)
    small = sp.Spool(directory, clock=lambda: 1700003600.0, max_bytes=100).open()
    status = small.enforce_bounds()
    out["byte_budget_drops_oldest_and_counts"] = (
        status["budget_dropped_total"] >= 1)
    clean(root)
    # 31/32/33. refusals
    root = temp_dir()
    real = os.path.join(root, "real")
    os.makedirs(real)
    link = os.path.join(root, "link")
    try:
        os.symlink(real, link)
        symlinked = True
    except (OSError, NotImplementedError, AttributeError):
        symlinked = False
    if symlinked:
        try:
            sp.Spool(link).open()
            out["symlinked_spool_dir_refused"] = False
        except sp.SpoolError:
            out["symlinked_spool_dir_refused"] = True
        target_file = os.path.join(real, "target")
        with open(target_file, "wb") as handle:
            handle.write(b'{"v":1}' + bytes([10]))
        for label, target in (("dangling", os.path.join(real, "absent")),
                              ("existing", target_file)):
            inner = os.path.join(real, "inner-" + label)
            os.makedirs(inner)
            os.chmod(inner, 0o700)
            os.symlink(target, os.path.join(inner, sp.SPOOL_FILE))
            try:
                sp.Spool(inner).open()
                out["symlinked_spool_file_refused_%s" % label] = False
            except sp.SpoolError:
                out["symlinked_spool_file_refused_%s" % label] = True
    else:
        out["symlinked_spool_dir_refused"] = True
        out["symlinked_spool_file_refused_dangling"] = True
        out["symlinked_spool_file_refused_existing"] = True
    fifo_dir = os.path.join(temp_dir(), "spool")
    os.makedirs(fifo_dir)
    if hasattr(os, "mkfifo"):
        try:
            os.mkfifo(os.path.join(fifo_dir, sp.SPOOL_FILE))
            try:
                sp.Spool(fifo_dir).open()
                out["special_file_refused"] = False
            except sp.SpoolError:
                out["special_file_refused"] = True
        except OSError:
            out["special_file_refused"] = True
    else:
        out["special_file_refused"] = True
    if os.name == "posix":
        loose = os.path.join(temp_dir(), "spool")
        os.makedirs(loose)
        os.chmod(loose, 0o755)
        # House discipline (History _validate_dir and the audited E4-Diag
        # writer both do this): a too-loose directory this process owns is
        # TIGHTENED, and only a tightening failure is fatal.
        sp.Spool(loose).open()
        out["loose_directory_is_tightened_to_0700"] = (
            stat_module.S_IMODE(os.stat(loose).st_mode) == 0o700)
    else:
        out["loose_directory_is_tightened_to_0700"] = True
    return out


def _fsync_was_used():
    """Prove the durability path really fsyncs (a record is on disk before any
    acknowledgement): drop the in-memory state file and read the raw bytes."""
    root = temp_dir()
    try:
        queue = sp.Spool(os.path.join(root, "spool"),
                         clock=lambda: 1700000000.0).open()
        queue.append("office-sg-isp-a", RUN, 1, b"{}", queued_epoch=1700000000.0)
        path = os.path.join(root, "spool", sp.SPOOL_FILE)
        with open(path, "rb") as handle:
            return b"body_b64" in handle.read()
    finally:
        clean(root)


def _sample(seq):
    return {
        "v": 1, "probe_id": "office-sg-isp-a", "run": RUN, "seq": seq,
        "sample_epoch": 1700000000.0 + seq,
        "dns": dp._slot(dp.STATUS_OK, 5), "https": dp._slot(dp.STATUS_OK, 6),
        "vps_tcp": dp._slot(dp.STATUS_OK, 7),
        "egress": {"status": "ok", "latency_ms": 8, "error_code": "NONE",
                   "ip": IP_A, "change": "unknown"},
        "mihomo_api": {"status": "ok"},
        "active": [ev.active_entry(rp.ROLE_REALITY, rp.OUTCOME_OK, 82)],
        "flags": {"truncated": False, "source_unavailable": []},
    }


# -- group: disposition ---------------------------------------------------------

def group_disposition():
    out = {}
    out["ack_on_frozen_success_schema"] = (
        dl.classify_response(200, b'{"result":"accepted","v":1}')[0] == dl.ACK
        and dl.classify_response(200, b'{"result":"duplicate","v":1}')[0]
        == dl.ACK)
    out["malformed_2xx_is_permanent"] = (
        dl.classify_response(200, b"{}") == (dl.PERMANENT, sp.QUARANTINE_MALFORMED_2XX)
        and dl.classify_response(200, b"not json")[0] == dl.PERMANENT
        and dl.classify_response(204, b"")[0] == dl.PERMANENT)
    out["every_3xx_is_permanent_and_never_followed"] = (
        all(dl.classify_response(code) == (dl.PERMANENT, sp.QUARANTINE_REDIRECT)
            for code in (301, 302, 303, 307, 308)))
    out["408_and_429_retry"] = (
        dl.classify_response(408)[0] == dl.RETRY
        and dl.classify_response(429)[0] == dl.RETRY)
    out["5xx_retries"] = all(dl.classify_response(code)[0] == dl.RETRY
                             for code in (500, 502, 503, 504))
    out["normal_4xx_is_permanent"] = all(
        dl.classify_response(code) == (dl.PERMANENT, sp.QUARANTINE_CLIENT_ERROR)
        for code in (400, 401, 403, 404, 405, 409, 410, 418))
    out["413_is_oversize_permanent"] = (
        dl.classify_response(413) == (dl.PERMANENT, sp.QUARANTINE_OVERSIZE))
    out["unknown_status_classes_quarantine_bounded"] = (
        dl.classify_response(199)[0] == dl.PERMANENT
        and dl.classify_response(600)[0] == dl.PERMANENT
        and dl.classify_response(100)[0] == dl.PERMANENT)
    out["backoff_is_bounded_exponential"] = (
        dl.backoff_delay(0) == 1.0 and dl.backoff_delay(1) == 2.0
        and dl.backoff_delay(2) == 4.0
        and dl.backoff_delay(20) == dl.BACKOFF_CAP_SECONDS)
    out["jitter_keeps_delay_bounded"] = (
        0.5 <= dl.backoff_delay(3, jitter=lambda: 0.0) / 8.0 <= 0.5
        and 0.5 <= dl.backoff_delay(3, jitter=lambda: 1.0) / 8.0 <= 1.0)
    # 42. transport failures retry and never lose the record
    poster = FakePoster([ssl.SSLError("tls"), ConnectionResetError("reset")])
    root = temp_dir()
    queue = sp.Spool(os.path.join(root, "spool"),
                     clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    first = dl.deliver_pending(queue, SECRET, "office-sg-isp-a", poster,
                               now_epoch=1700000000)
    second = dl.deliver_pending(queue, SECRET, "office-sg-isp-a", poster,
                                now_epoch=1700000001)
    out["network_and_tls_failures_retry_and_keep_the_record"] = (
        first["retries"] == 1 and second["retries"] == 1
        and len(list(queue.pending())) == 1)
    clean(root)
    # 44. HTTPS required for non-loopback
    good = "/api/v1/remote-probes/ingest"
    for url, ok in (("http://example.com" + good, False),
                    ("http://127.0.0.1:9191" + good, True),
                    ("https://example.com" + good, True),
                    ("https://example.com" + good + "?a=b", False),
                    ("https://user:pw@example.com" + good, False),
                    ("https://example.com/wrong/path", False),
                    ("https://example.com/api/v1/remote-probes/ingest/extra",
                     False)):
        try:
            dl.classify_url(url)
            out["url_%s" % url.replace(":", "_").replace("/", "_")] = ok
        except dl.UploadConfigError:
            out["url_%s" % url.replace(":", "_").replace("/", "_")] = not ok
    out["no_redirect_handling_anywhere"] = "Location" not in open(
        os.path.join(ROOT, "monitor-v2", "remote_probe", "delivery.py"),
        encoding="utf-8").read()
    return out


# -- group: cycle / identity / leak ---------------------------------------------

def group_cycle():
    out = {}
    transport = FakeTransport({
        "/version": (200, b'{"version":"1.18"}'),
        "/proxies": (200, json.dumps(proxies_payload(
            selected="office-reality-01")).encode()),
        "/proxies/office-reality-01/delay": delay_route(200, {"delay": 82}),
        "/proxies/office-hy2-01/delay": delay_route(200, {"delay": 140}),
    })
    clock = [1700000000.0]
    poster = FakePoster([(503, b"")])
    instance, transport = build_agent(transport=transport,
                                      clock=lambda: clock[0], poster=poster,
                                      config_over={"watched_group": "Selector"})
    try:
        instance.open()
        first = instance.run_cycle(now=clock[0])
        # first delivery is retryable (503): the record stays QUEUED, which is
        # what the rollback proof below needs as its reference bytes.
        out["cycle_spools_then_delivers"] = (
            first["outcome"] == "spooled"
            and first.get("delivery", {}).get("retries") == 1
            and len(list(instance.spool.pending())) == 1)
        out["sample_carries_both_roles"] = (
            set(instance.last_active) == {rp.ROLE_REALITY, rp.ROLE_HY2}
            and instance.last_active[rp.ROLE_REALITY] == rp.OUTCOME_OK
            and instance.last_active[rp.ROLE_HY2] == rp.OUTCOME_OK)
        out["cache_echo_not_double_counted_in_a_real_cycle"] = (
            sum(1 for entry in json.loads(poster.requests[0]["body"])["active"]
                if entry["independent"]) == 2)
        out["no_passive_entries_are_independent_echoes"] = all(
            entry["independent"] == (entry["source"] == "active_delay")
            for entry in json.loads(poster.requests[0]["body"])["active"])
        # 25. clock rollback starts a new run, never rewrites spooled time
        first_body = poster.requests[0]["body"]
        run_before = instance.run
        clock[0] = 1699999000.0          # wall clock jumps backwards
        instance.run_cycle(now=clock[0])
        out["clock_rollback_starts_a_new_run"] = (
            instance.run != run_before and instance.clock_rollbacks == 1
            and instance.seq == 1)
        # Timing-independent: EVERY body that ever went out for the first
        # record still carries its ORIGINAL sample_epoch (the rollback moved
        # the clock, not an already-spooled timestamp), and the cycle after
        # the rollback produced the new time instead.
        seen = {}
        for request in poster.requests:
            seen.setdefault(request["body"], set()).add(
                json.loads(request["body"])["sample_epoch"])
        out["rollback_never_rewrites_spooled_timestamps"] = (
            bool(seen)
            and all(len(values) == 1 for values in seen.values())
            and any(1700000000.0 in values for values in seen.values()))
        # status is closed and sanitized
        status = instance.status()
        out["status_is_closed_and_sanitized"] = (
            set(status) == {"probe_id", "run", "seq", "cycles",
                            "cycle_failures", "clock_rollbacks",
                            "overlap_refusals", "spool_failures",
                            "retention_runs", "retention_failures",
                            "delivery_deferrals", "last_backoff_seconds",
                            "baseline_write_failures",
                            "state", "active", "spool"}
            and SECRET_TEXT not in json.dumps(status))
        # 45. secret leak wall: payload, spool bytes, status, exception text
        spool_bytes = b""
        for path in glob.glob(os.path.join(instance.config.spool_dir, "*")):
            if not os.path.isfile(path) or path.endswith(sp.LOCK_FILE):
                continue   # the writer lock is held open on Windows
            with open(path, "rb") as handle:
                spool_bytes += handle.read()
        out["secret_never_in_payload_or_spool"] = (
            SECRET not in poster.requests[0]["body"]
            and SECRET_TEXT not in spool_bytes.decode("latin-1"))
        out["secret_never_in_headers_besides_signature"] = all(
            SECRET_TEXT not in value
            for name, value in poster.requests[0]["headers"].items()
            if name != "X-Remote-Probe-Signature")
        out["secret_never_in_status"] = SECRET_TEXT not in json.dumps(status)
    finally:
        clean(instance.config.spool_dir)
    # 26. spool failure => no upload at all
    refused_poster = FakePoster()
    instance, _t = build_agent(poster=refused_poster)
    instance.open()
    try:
        instance.spool.append = _boom_spool
        result = instance.run_cycle(now=1700000000.0)
        out["spool_failure_means_no_upload"] = (
            result["outcome"] == "spool_unavailable"
            and refused_poster.requests == []
            and instance.spool_failures == 1)
    finally:
        clean(instance.config.spool_dir)
    # secret loading is file-only and mode-checked
    root = temp_dir()
    try:
        secret_path = os.path.join(root, "probe.key")
        with open(secret_path, "w", encoding="utf-8") as handle:
            handle.write(SECRET_TEXT)
        os.chmod(secret_path, 0o600)
        out["probe_secret_loads_from_a_0600_file"] = (
            ag.load_probe_secret(secret_path) == SECRET)
        os.chmod(secret_path, 0o644)
        if os.name == "posix":
            try:
                ag.load_probe_secret(secret_path)
                out["probe_secret_refuses_loose_mode"] = False
            except ag.ConfigError:
                out["probe_secret_refuses_loose_mode"] = True
        else:
            out["probe_secret_refuses_loose_mode"] = True
        link = os.path.join(root, "probe-link.key")
        try:
            os.symlink(secret_path, link)
            try:
                ag.load_probe_secret(link)
                out["probe_secret_refuses_symlink"] = False
            except ag.ConfigError:
                out["probe_secret_refuses_symlink"] = True
        except (OSError, NotImplementedError, AttributeError):
            out["probe_secret_refuses_symlink"] = True
    finally:
        clean(root)
    source = open(os.path.join(ROOT, "monitor-v2", "remote_probe",
                               "agent.py"), encoding="utf-8").read()
    out["probe_secret_has_no_env_or_argv_path"] = (
        "MIHOMO_API_SECRET" not in source
        or "load_probe_secret" not in source
        and False)
    out["probe_secret_is_file_only_documented"] = (
        "FILE ONLY" in ag.load_probe_secret.__doc__.upper())
    return out


def _boom_spool(*_a, **_k):
    raise sp.SpoolError("refused")


def _boom_bounds(*_a, **_k):
    raise sp.SpoolError("retention refused")


def _boom_write(*_a, **_k):
    raise sp.SpoolError("baseline write refused")


def _real_write(instance):
    return type(instance)._write_baseline.__get__(instance, type(instance))


def group_resilience():
    out = {}
    # ---- B1a: an unknown response is bounded ACROSS delivery calls, then
    #      quarantined, and the queue advances to the next record.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    clock = [1700000000.0]
    queue = sp.Spool(directory, clock=lambda: clock[0]).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=clock[0])
    queue.append("office-sg-isp-a", RUN, 2, pl.encode_sample(_sample(2)),
                 queued_epoch=clock[0])
    unknown_poster = FakePoster([(600, b"")] * 20
                                + [(200, b'{"result":"accepted","v":1}')])
    for _ in range(dl.UNKNOWN_RESPONSE_MAX_ATTEMPTS):
        dl.deliver_pending(queue, SECRET, "office-sg-isp-a", unknown_poster,
                           now_epoch=int(clock[0]))
    out["unknown_quarantines_after_bounded_multi_call_attempts"] = (
        queue.status()["quarantined_total"] == 1
        and [item["seq"] for item in queue.pending()] == [2])
    final = dl.deliver_pending(queue, SECRET, "office-sg-isp-a",
                               FakePoster(), now_epoch=int(clock[0]))
    out["queue_advances_past_the_bounded_unknown_head"] = (
        final["acked"] == 1 and list(queue.pending()) == [])
    queue.close()
    clean(root)
    # ---- B1b: retry state is DURABLE (a restart cannot reset the budget)
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    retry_poster = FakePoster([(503, b"")] * 5)
    dl.deliver_pending(queue, SECRET, "office-sg-isp-a", retry_poster,
                       now_epoch=1700000000)
    dl.deliver_pending(queue, SECRET, "office-sg-isp-a", retry_poster,
                       now_epoch=1700000001)
    before = queue.attempts(1)
    queue.close()
    reopened = sp.Spool(directory, clock=lambda: 1700000002.0).open()
    out["retry_budget_survives_a_spool_reopen"] = (
        before == 2 and reopened.attempts(1) == 2)
    reopened.close()
    clean(root)
    # ---- B1c: the AGENT PRODUCT PATH consumes the bounded backoff
    transport = FakeTransport({
        "/version": (200, b'{"version":"1.18"}'),
        "/proxies": (200, json.dumps(proxies_payload()).encode()),
        "/proxies/office-reality-01/delay": delay_route(200, {"delay": 82}),
        "/proxies/office-hy2-01/delay": delay_route(200, {"delay": 140}),
    })
    poster = FakePoster([(503, b"")])
    instance, _t = build_agent(transport=transport, poster=poster)
    try:
        instance.open()
        first = instance.run_cycle(now=1700000000.0)
        calls_after_first = len(poster.requests)
        resumed = instance.deliver()
        out["agent_consumes_bounded_backoff_not_the_sampling_beat"] = (
            first["delivery"]["stopped"] == "retryable"
            and instance.last_backoff_seconds > 0
            and resumed["stopped"] == "backoff"
            and len(poster.requests) == calls_after_first
            and instance.delivery_deferrals == 1)
    finally:
        instance.close()
        clean(instance.config.spool_dir)
    # ---- B2a: the AGENT expires an over-age record from its own cycle path
    #      (no direct enforce_bounds call anywhere in this verdict).
    root = temp_dir()
    directory = os.path.join(root, "spool")
    seed = sp.Spool(directory, clock=lambda: 1700003600.0).open()
    seed.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                queued_epoch=1700003600.0 - 8 * 86400.0)      # 8 days old
    seed.close()
    instance, _t = build_agent(
        transport=FakeTransport({"/version": (200, b'{"version":"1.18"}'),
                                 "/proxies": (200, b"{}")}),
        clock=lambda: 1700003600.0,
        config_over={"spool_dir": directory})
    try:
        instance.open()          # startup retention must already drop it
        out["agent_startup_retention_expires_over_age_records"] = (
            instance.retention_runs >= 1
            and list(instance.spool.pending()) == []
            and instance.spool.status()["expired_total"] >= 1)
    finally:
        instance.close()
    clean(root)
    # ---- B2b: the same bound is applied periodically, from run_cycle
    root = temp_dir()
    directory = os.path.join(root, "spool")
    seed = sp.Spool(directory, clock=lambda: 1700003600.0).open()
    seed.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                queued_epoch=1700003600.0)
    seed.close()
    later = 1700003600.0 + 9 * 86400.0
    instance, _t = build_agent(
        transport=FakeTransport({"/version": (200, b'{"version":"1.18"}'),
                                 "/proxies": (200, b"{}")}),
        clock=lambda: later, config_over={"spool_dir": directory})
    try:
        instance.open()
        instance._next_retention_at = 0.0     # the interval has come round
        result = instance.run_cycle(now=later)
        out["agent_periodic_retention_runs_from_the_cycle"] = (
            result["outcome"] == "spooled"
            and instance.retention_runs >= 2
            and instance.spool.status()["expired_total"] >= 1)
    finally:
        instance.close()
    clean(root)
    # ---- B2c: acknowledged records do not linger in ROTATED files
    root = temp_dir()
    directory = os.path.join(root, "spool")
    clock = [1700000000.0]
    # A chain that really ROTATES: the per-file budget holds several records,
    # so nothing is dropped and the proof is about physical retention, not
    # about the byte bound.
    queue = sp.Spool(directory, clock=lambda: clock[0],
                     file_bytes=4096, max_files=4).open()
    for index in range(12):
        queue.append("office-sg-isp-a", RUN, index + 1,
                     pl.encode_sample(_sample(index + 1)),
                     queued_epoch=clock[0])
    dl.deliver_pending(queue, SECRET, "office-sg-isp-a", FakePoster(),
                       now_epoch=int(clock[0]))
    queue.enforce_bounds()
    leftovers = []
    for path in glob.glob(os.path.join(directory, "spool.jsonl*")):
        with open(path, "rb") as handle:
            leftovers.extend(line for line in handle.read().splitlines()
                             if line.strip())
    out["acked_records_do_not_linger_in_rotated_files"] = (
        queue.status()["acknowledged_total"] == 12
        and queue.status()["budget_dropped_total"] == 0
        and leftovers == [])
    queue.close()
    clean(root)
    # ---- B3: crash between the record fsync and the state save
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    first_id = queue.append("office-sg-isp-a", RUN, 1,
                            pl.encode_sample(_sample(1)),
                            queued_epoch=1700000000.0)
    # Fault injection: the record line is durable, but the cursor recording it
    # never landed (exactly the crash window).
    os.unlink(queue._state_path())
    queue.close()
    repaired = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    second_id = repaired.append("office-sg-isp-a", RUN, 2,
                                pl.encode_sample(_sample(2)),
                                queued_epoch=1700000000.0)
    pending = [item["seq"] for item in repaired.pending()]
    poster = FakePoster()
    summary = dl.deliver_pending(repaired, SECRET, "office-sg-isp-a", poster,
                                 now_epoch=1700000000)
    out["crash_window_cannot_reuse_a_record_id"] = (
        first_id == 1 and second_id == 2 and second_id != first_id)
    out["reconciled_ids_are_counted"] = repaired.status()["reconciled_ids"] >= 1
    out["reconciled_queue_delivers_each_record_once"] = (
        pending == [1, 2] and summary["acked"] == 2
        and len(poster.requests) == 2
        and len({request["headers"]["X-Remote-Probe-Seq"]
                 for request in poster.requests}) == 2)
    repaired.close()
    clean(root)
    # a duplicate id in the durable file is refused, never adopted
    dup_root = temp_dir()
    dup_dir = os.path.join(dup_root, "spool")
    q2 = sp.Spool(dup_dir, clock=lambda: 1700000000.0).open()
    q2.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
              queued_epoch=1700000000.0)
    q2.close()
    dup_path = os.path.join(dup_dir, sp.SPOOL_FILE)
    with open(dup_path, "rb") as handle:
        payload = handle.read()
    with open(dup_path, "ab") as handle:
        handle.write(payload)
    try:
        sp.Spool(dup_dir, clock=lambda: 1700000000.0).open()
        out["duplicate_record_ids_fail_closed"] = False
    except sp.SpoolError:
        out["duplicate_record_ids_fail_closed"] = True
    clean(dup_root)
    # ---- B4: deadline exhaustion still produces a LEGAL, encodable sample
    gate = threading.Event()
    transport = FakeTransport(gate=gate)
    ticks = [0.0]

    def advancing():
        ticks[0] += 25.0        # a REAL advancing clock: the deadline expires
        return ticks[0]

    instance, transport = build_agent(transport=transport,
                                      config_over={"cycle_deadline": 1.0})
    instance.monotonic = advancing
    try:
        instance.open()
        result = instance.run_cycle(now=1700000000.0)
        gate.set()
        body = None
        for item in instance.spool.pending():
            body = json.loads(item["body"].decode("utf-8"))
        out["deadline_exhaustion_produces_a_valid_sample"] = (
            result["outcome"] == "spooled" and body is not None
            and pl.validate_sample(body) == [])
        out["deadline_flags_are_closed_tokens"] = (
            body is not None
            and all(token in pl.SOURCE_TOKENS
                    for token in body["flags"]["source_unavailable"]))
    finally:
        instance.close()
        clean(instance.config.spool_dir)
    out["producer_tokens_are_in_the_frozen_enum"] = all(
        token in pl.SOURCE_TOKENS
        for token in ("active_delay", "direct", "passive_cache", "egress"))


    # ---- B5: the egress baseline moves only AFTER the sample is durable
    transport = FakeTransport({
        "/version": (200, b'{"version":"1.18"}'),
        "/proxies": (200, json.dumps(proxies_payload()).encode()),
        "/proxies/office-reality-01/delay": delay_route(200, {"delay": 82}),
        "/proxies/office-hy2-01/delay": delay_route(200, {"delay": 140}),
    })
    original_https_b5 = dp.http.client.HTTPSConnection
    FakeHTTPSConnection.log = []
    FakeHTTPSConnection.sensor = {"status": 200, "body": IP_B.encode(),
                                  "raise": None}
    dp.http.client.HTTPSConnection = FakeHTTPSConnection
    instance, _t = build_agent(transport=transport, poster=None)
    real_append = type(instance.spool).append.__get__(instance.spool,
                                                      type(instance.spool))
    try:
        instance.open()
        instance._baseline = IP_A
        instance._write_baseline(IP_A)
        instance.spool.append = _boom_spool
        failed = instance.run_cycle(now=1700000000.0)
        staged = instance._pending_baseline
        durable = instance._baseline
        instance.spool.append = real_append
        ok = instance.run_cycle(now=1700000001.0)
        out["spool_failure_does_not_move_the_egress_baseline"] = (
            failed["outcome"] == "spool_unavailable"
            and staged is None and durable == IP_A)
        out["baseline_commits_after_a_durable_sample"] = (
            ok["outcome"] == "spooled" and instance._baseline == IP_B)
        with open(instance._baseline_path(), encoding="utf-8") as handle:
            out["baseline_file_matches_the_committed_value"] = (
                json.loads(handle.read())["ip"] == IP_B)
    finally:
        dp.http.client.HTTPSConnection = original_https_b5
        instance.close()
        clean(instance.config.spool_dir)
    # ---- B6: the ingest secret is EXACTLY 256-bit material
    root = temp_dir()
    try:
        secret_path = os.path.join(root, "probe.key")
        refusals = []
        for value in ("", "deadbeef", "z" * 64, "A" * 64, "0" * 63, "0" * 65,
                      "0123456789abcdef" * 5):
            with open(secret_path, "w", encoding="utf-8") as handle:
                handle.write(value)
            if os.name == "posix":
                os.chmod(secret_path, 0o600)
            try:
                ag.load_probe_secret(secret_path)
                refusals.append(False)
            except ag.ConfigError:
                refusals.append(True)
        out["non_256_bit_secrets_are_refused"] = all(refusals)
        with open(secret_path, "w", encoding="utf-8") as handle:
            handle.write(SECRET_TEXT)
        if os.name == "posix":
            os.chmod(secret_path, 0o600)
        loaded = ag.load_probe_secret(secret_path)
        out["valid_256_bit_secret_decodes_to_32_bytes"] = (
            loaded == SECRET and len(loaded) == 32)
    finally:
        clean(root)
    # ---- storage tightening + single writer
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    state_path = os.path.join(directory, sp.STATE_FILE)
    if hasattr(os, "symlink"):
        try:
            os.symlink(os.path.join(directory, "absent-target"), state_path)
            try:
                sp.Spool(directory, clock=lambda: 1700000000.0).open()
                out["symlinked_state_file_refused"] = False
            except sp.SpoolError:
                out["symlinked_state_file_refused"] = True
            os.unlink(state_path)
        except (OSError, NotImplementedError, AttributeError):
            out["symlinked_state_file_refused"] = True
    else:
        out["symlinked_state_file_refused"] = True
    first = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    try:
        try:
            sp.Spool(directory, clock=lambda: 1700000000.0).open()
            out["second_writer_is_refused"] = False
        except sp.SpoolError:
            out["second_writer_is_refused"] = True
    finally:
        first.close()
    out["lock_is_released_on_close"] = (
        sp.Spool(directory, clock=lambda: 1700000000.0).open() is not None)
    clean(root)

    # ---- R1: a failed STARTUP retention pass must not activate the agent
    instance, _t = build_agent()
    try:
        instance.spool.enforce_bounds = _boom_bounds
        raised = None
        try:
            instance.open()
        except Exception as exc:  # noqa: BLE001 -- the refusal is the gate
            raised = type(exc).__name__
        out["startup_retention_failure_prevents_agent_activation"] = (
            raised is not None and instance.run is None)
        # ... and the writer lock was released with the refusal, so the
        # directory is not left half-owned.
        out["startup_refusal_releases_the_writer_lock"] = (
            sp.Spool(instance.config.spool_dir,
                     clock=lambda: 1700000000.0).open() is not None)
    finally:
        clean(instance.config.spool_dir)
    # ---- R2: rotation publication is fsync + rename + directory fsync.
    #      Isolated by an ORDERED event log: a bare call-count is satisfied
    #      by the state save's own directory fsync, and the record write
    #      uses a bare os.fsync, so a failure injected anywhere in the
    #      append would surface there instead of at the rotation. The
    #      rotation's own fsync is therefore armed by POSITION.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    events = []
    real_replace = sp.os.replace
    real_fsync_dir = sp._fsync_dir

    def logged_replace(source, target):
        events.append(("replace", target))
        return real_replace(source, target)

    def logged_fsync_dir(path):
        events.append(("fsync_dir", path))
        return real_fsync_dir(path)

    sp.os.replace = logged_replace
    sp._fsync_dir = logged_fsync_dir
    try:
        queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                         file_bytes=1, max_files=3).open()
        for index in range(4):
            queue.append("office-sg-isp-a", RUN, index + 1,
                         pl.encode_sample(_sample(index + 1)),
                         queued_epoch=1700000000.0)
    finally:
        sp.os.replace = real_replace
        sp._fsync_dir = real_fsync_dir
        queue.close()
    # Rotating the CURRENT file is the only rename whose target is slot 1,
    # and the directory fsync must be the very NEXT event: the new name is
    # not durable until the entry is.
    rotated_base = os.path.join(directory, sp.SPOOL_FILE + ".1")
    slots = [i for i, event in enumerate(events)
             if event == ("replace", rotated_base)]
    out["rotation_directory_fsync_follows_each_rename"] = (
        bool(slots)
        and all(index + 1 < len(events)
                and events[index + 1] == ("fsync_dir", directory)
                for index in slots))
    clean(root)
    # A failed fsync at the ROTATION must fail closed: the publish is
    # withheld. The failure is armed on the first os.fsync of the append
    # that rotates -- the rotation's own source fsync -- so a swallowed
    # error cannot hide behind the record write's later fsync.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    seed = sp.Spool(directory, clock=lambda: 1700000000.0,
                    file_bytes=1, max_files=3).open()
    seed.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                queued_epoch=1700000000.0)
    real_os_fsync = sp.os.fsync
    calls = {"n": 0}

    def armed_fsync(fd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("fsync refused")
        return real_os_fsync(fd)

    sp.os.fsync = armed_fsync
    raised = False
    try:
        try:
            seed.append("office-sg-isp-a", RUN, 2,
                        pl.encode_sample(_sample(2)),
                        queued_epoch=1700000000.0)
        except (sp.SpoolError, OSError):
            raised = True
    finally:
        sp.os.fsync = real_os_fsync
    out["rotation_source_fsync_failure_withholds_the_publish"] = (
        raised and not os.path.lexists(rotated_base))
    # The same discipline on the COMPACTION path: a rewrite that could not
    # be fsynced must never be published over the chain. Judged on the
    # DURABLE artifact -- the record is resolved first (with a working
    # fsync) and must still be on disk when the rewrite failed to flush.
    chain_path = os.path.join(directory, sp.SPOOL_FILE)

    def read_chain_bytes():
        try:
            with open(chain_path, "rb") as handle:
                return handle.read()
        except OSError:
            return b""

    seed.resolve(1)
    before_chain = read_chain_bytes()
    sp.os.fsync = armed_fsync
    calls["n"] = 0
    compaction_raised = False
    try:
        try:
            seed.enforce_bounds()
        except (sp.SpoolError, OSError):
            compaction_raised = True
    finally:
        sp.os.fsync = real_os_fsync
    out["compaction_fsync_failure_withholds_the_rewrite"] = (
        compaction_raised and read_chain_bytes() == before_chain)
    seed.close()
    clean(root)
    # an unsafe rotated SOURCE is refused and never renamed
    root = temp_dir()
    directory = os.path.join(root, "spool")
    if hasattr(os, "symlink"):
        queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                         file_bytes=1200, max_files=3).open()
        queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                     queued_epoch=1700000000.0)
        queue.close()
        link = os.path.join(directory, "spool.jsonl.1")
        try:
            os.symlink(os.path.join(directory, "absent"), link)
            rotated_source = os.path.join(directory, "spool.jsonl")
            raised = None
            try:
                queue3 = sp.Spool(directory, clock=lambda: 1700000000.0,
                                  file_bytes=1, max_files=3).open()
                queue3.append("office-sg-isp-a", RUN, 2,
                              pl.encode_sample(_sample(2)),
                              queued_epoch=1700000000.0)
            except Exception as exc:  # noqa: BLE001
                raised = type(exc).__name__
            out["unsafe_rotated_source_is_not_renamed"] = (
                raised is not None
                and os.path.islink(link)
                and os.path.lexists(rotated_source))
        except (OSError, NotImplementedError, AttributeError):
            out["unsafe_rotated_source_is_not_renamed"] = True
    else:
        out["unsafe_rotated_source_is_not_renamed"] = True
    clean(root)
    # ---- R3: unsafe objects anywhere in the chain fail closed
    root = temp_dir()
    directory = os.path.join(root, "spool")
    seed = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    seed.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                queued_epoch=1700000000.0)
    seed.close()
    rotated = os.path.join(directory, "spool.jsonl.1")
    if hasattr(os, "symlink"):
        try:
            os.symlink(os.path.join(directory, "absent"), rotated)
            try:
                sp.Spool(directory, clock=lambda: 1700000000.0).open()
                out["rotated_symlink_fails_closed"] = False
            except sp.SpoolError:
                out["rotated_symlink_fails_closed"] = True
            os.unlink(rotated)
        except (OSError, NotImplementedError, AttributeError):
            out["rotated_symlink_fails_closed"] = True
    else:
        out["rotated_symlink_fails_closed"] = True
    if hasattr(os, "mkfifo"):
        os.mkfifo(rotated)
    else:
        os.mkdir(rotated)
    try:
        sp.Spool(directory, clock=lambda: 1700000000.0).open()
        out["rotated_special_file_fails_closed"] = False
    except sp.SpoolError:
        out["rotated_special_file_fails_closed"] = True
    if os.path.isdir(rotated):
        os.rmdir(rotated)
    else:
        os.unlink(rotated)
    clean(root)
    # a SPECIAL state file must be refused WITHOUT BLOCKING (a FIFO opened
    # O_RDONLY would hang forever otherwise). Runs in a worker with a hard
    # timeout so a hang is a FAIL, not a stuck suite.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    os.makedirs(directory, exist_ok=True)
    if hasattr(os, "mkfifo"):
        os.mkfifo(os.path.join(directory, "spool.state.json"))
    else:
        os.mkdir(os.path.join(directory, "spool.state.json"))
    result = {}

    def attempt_state_open():
        try:
            sp.Spool(directory, clock=lambda: 1700000000.0).open()
            result["outcome"] = "opened"
        except sp.SpoolError:
            result["outcome"] = "refused"
        except OSError:
            result["outcome"] = "refused"

    worker = threading.Thread(target=attempt_state_open, daemon=True)
    worker.start()
    worker.join(10.0)
    out["state_special_file_fails_closed_without_blocking"] = (
        not worker.is_alive() and result.get("outcome") == "refused")
    clean(root)
    # ---- R4: the baseline file follows the same storage discipline
    root = temp_dir()
    directory = os.path.join(root, "spool")
    os.makedirs(directory, exist_ok=True)
    instance, _t = build_agent(config_over={"spool_dir": directory})
    baseline_path = instance._baseline_path()
    if hasattr(os, "symlink"):
        try:
            os.symlink(os.path.join(directory, "absent"), baseline_path)
            raised = None
            try:
                instance.open()
            except Exception as exc:  # noqa: BLE001
                raised = type(exc).__name__
            out["baseline_symlink_refused"] = raised is not None
            os.unlink(baseline_path)
        except (OSError, NotImplementedError, AttributeError):
            out["baseline_symlink_refused"] = True
    else:
        out["baseline_symlink_refused"] = True
    clean(root)
    root = temp_dir()
    directory = os.path.join(root, "spool")
    os.makedirs(directory, exist_ok=True)
    instance, _t = build_agent(config_over={"spool_dir": directory})
    os.mkdir(instance._baseline_path())
    result = {}

    def attempt_baseline_open():
        try:
            instance.open()
            result["outcome"] = "opened"
        except (ag.ConfigError, sp.SpoolError, OSError):
            result["outcome"] = "refused"

    worker = threading.Thread(target=attempt_baseline_open, daemon=True)
    worker.start()
    worker.join(10.0)
    out["baseline_special_file_refused_without_hang"] = (
        not worker.is_alive() and result.get("outcome") == "refused")
    clean(root)
    # a failed durable write must NOT advance the in-memory baseline
    root = temp_dir()
    instance, _t = build_agent()
    try:
        instance.open()
        instance._baseline = IP_A
        instance._pending_baseline = IP_B
        instance._write_baseline = _boom_write
        instance._commit_baseline()
        out["baseline_write_failure_does_not_advance_memory_baseline"] = (
            instance._baseline == IP_A
            and instance._pending_baseline == IP_B
            and instance.baseline_write_failures == 1
            and instance.last_status == ag.STATUS_DEGRADED)
        # ... and the durable commit path fsyncs the directory
        calls = {"n": 0}
        real_fsync_dir = instance._fsync_directory

        def counting():
            calls["n"] += 1
            return real_fsync_dir()

        instance._fsync_directory = counting
        instance._write_baseline = _real_write(instance)
        instance._commit_baseline()
        out["baseline_commit_directory_is_fsynced"] = (
            calls["n"] >= 1 and instance._baseline == IP_B
            and instance._pending_baseline is None)
    finally:
        instance.close()
        clean(instance.config.spool_dir)
    # ---- R5: every request refreshes its own signed transport timestamp
    root = temp_dir()
    directory = os.path.join(root, "spool")
    clock = [1700000000.0]
    queue = sp.Spool(directory, clock=lambda: clock[0]).open()
    for index in range(2):
        queue.append("office-sg-isp-a", RUN, index + 1,
                     pl.encode_sample(_sample(index + 1)),
                     queued_epoch=clock[0])
    poster = FakePoster()
    sent = [1700000000.0]

    def advancing_clock():
        value = sent[0]
        sent[0] += 400.0          # each send moves the wall clock > 300 s
        return value

    dl.deliver_pending(queue, SECRET, "office-sg-isp-a", poster,
                       clock=advancing_clock)
    epochs = [int(request["headers"]["X-Remote-Probe-Sent-Epoch"])
              for request in poster.requests]
    verified = []
    for request in poster.requests:
        verified.append(pl.verify_signature(
            SECRET, request["headers"]["X-Remote-Probe-Id"],
            int(request["headers"]["X-Remote-Probe-Sent-Epoch"]),
            request["headers"]["X-Remote-Probe-Run"],
            int(request["headers"]["X-Remote-Probe-Seq"]),
            request["body"],
            request["headers"]["X-Remote-Probe-Signature"]))
    out["each_delivery_request_refreshes_sent_epoch"] = (
        len(poster.requests) == 2 and epochs == [1700000000, 1700000400]
        and all(verified))
    queue.close()
    clean(root)
    # ---- R6: the Mihomo secret and the ingest secret are never reused
    same_file = os.path.join(temp_dir(), "shared.key")
    with open(same_file, "w", encoding="utf-8") as handle:
        handle.write(SECRET_TEXT)
    try:
        ag.AgentConfig.from_mapping({
            "probe_id": "office-sg-isp-a",
            "ingest_url": "https://monitor.example.net" + rp.INGEST_PATH,
            "spool_dir": os.path.join(temp_dir(), "spool"),
            "ingest_secret_file": same_file,
            "mihomo_url": LOOPBACK_URL,
            "mihomo_secret_file": same_file,
            "reality_node": "office-reality-01",
            "hy2_node": "office-hy2-01",
            "dns_host": "www.cloudflare.com",
            "https_host": "www.cloudflare.com",
            "egress_host": "api.ipify.org",
            "vps_host": "vps.example.net",
        })
        out["mihomo_and_ingest_secret_reuse_is_refused"] = False
    except ag.ConfigError:
        out["mihomo_and_ingest_secret_reuse_is_refused"] = True
    clean(os.path.dirname(same_file))
    # ... and the same MATERIAL under two different files is refused too
    root = temp_dir()
    ingest_file = os.path.join(root, "ingest.key")
    with open(ingest_file, "w", encoding="utf-8") as handle:
        handle.write(SECRET_TEXT)
    instance, _t = build_agent(
        config_over={"ingest_secret_file": ingest_file})
    # The Mihomo controller secret is the SAME material as the ingest secret:
    # the agent must refuse to activate (issue #67 §5).
    instance.mihomo.secret = SECRET_TEXT
    raised = None
    try:
        instance.open()
    except Exception as exc:  # noqa: BLE001
        raised = type(exc).__name__
    out["identical_secret_material_is_refused"] = raised is not None
    clean(root)
    clean(instance.config.spool_dir)

    # ---- F1a: an EXISTING chain member that cannot be READ is fail-closed.
    #      The fault is injected into read_restricted() itself, so what is
    #      under test is the I/O failure -- not the symlink/special shape.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     file_bytes=1200, max_files=2).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.append("office-sg-isp-a", RUN, 2, pl.encode_sample(_sample(2)),
                 queued_epoch=1700000000.0)
    queue.close()
    rotated_member = os.path.join(directory, sp.SPOOL_FILE + ".1")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     file_bytes=1200, max_files=2).open()
    healthy = len(list(queue.pending()))
    real_read = sp.read_restricted

    def failing_member_read(path, limit):
        if os.path.basename(path) == sp.SPOOL_FILE + ".1":
            raise OSError("I/O error")
        return real_read(path, limit)

    sp.read_restricted = failing_member_read
    raised = False
    hidden = None
    try:
        try:
            hidden = len(list(queue.pending()))
        except (sp.SpoolError, OSError):
            raised = True
    finally:
        sp.read_restricted = real_read
    out["existing_chain_read_failure_fails_closed"] = (
        os.path.lexists(rotated_member)
        and healthy >= 1          # the member really held records
        and raised                # ... and its failure was reported
        and hidden is None)       # ... never silently hidden
    queue.close()
    clean(root)
    # ---- F1b: an EXISTING CURRENT file that cannot be read is not "nothing
    #      to repair". The fault is armed on the FIRST read of the current
    #      file during open, which is the tail repair's own read; the scans
    #      that follow read the same file successfully, so this pins the
    #      repair path and not the earlier scan.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    current_member = os.path.join(directory, sp.SPOOL_FILE)
    with open(current_member, "ab") as handle:
        handle.write(b'{"torn":')          # an incomplete trailing fragment
    real_read = sp.read_restricted
    reads = {"n": 0}

    def failing_first_current_read(path, limit):
        if os.path.basename(path) == sp.SPOOL_FILE:
            reads["n"] += 1
            if reads["n"] == 1:
                raise OSError("I/O error")
        return real_read(path, limit)

    sp.read_restricted = failing_first_current_read
    raised = False
    try:
        try:
            sp.Spool(directory, clock=lambda: 1700000000.0).open().close()
        except (sp.SpoolError, OSError):
            raised = True
    finally:
        sp.read_restricted = real_read
    out["current_tail_read_failure_fails_closed"] = (
        raised and reads["n"] >= 1 and os.path.lexists(current_member))
    clean(root)
    # ---- F2: a retry count that cannot be PERSISTED is not a consumed
    #      attempt. No progress is claimed, the durable value survives a
    #      restart, and the same budget resumes once storage works again.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    first_attempt = queue.note_attempt(1)      # durable attempt #1
    real_save = sp.Spool._save_state

    def refusing_save(self):
        raise sp.SpoolError("state save refused")

    sp.Spool._save_state = refusing_save
    refused = False
    try:
        try:
            queue.note_attempt(1)
        except (sp.SpoolError, OSError):
            refused = True
        poster = FakePoster([(503, b"")] * 3)
        summary = dl.deliver_pending(queue, SECRET, "office-sg-isp-a", poster)
        posted = len(poster.requests)
    finally:
        sp.Spool._save_state = real_save
    out["retry_attempt_state_save_failure_fails_closed"] = (
        first_attempt == 1 and refused
        and summary["stopped"] == "retry_state_not_durable"
        and summary["retries"] == 0
        and "attempt" not in summary
        # C2: the reservation is taken BEFORE the send, so a storage that
        # cannot make it durable must not produce a single request.
        and posted == 0
        and queue.attempts(1) == 1           # memory rolled back
        # ... and the record is STILL pending: a failed persistence never
        # leaves a terminal (acked/quarantined) state behind, so no poison
        # head can come out of it.
        and any(item["record_id"] == 1 for item in queue.pending()))
    queue.close()
    reopened = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    out["retry_attempt_budget_survives_a_restart"] = reopened.attempts(1) == 1
    out["retry_attempt_advances_once_storage_recovers"] = (
        reopened.note_attempt(1) == 2)
    reopened.close()
    clean(root)
    # ---- F3: an unsafe rotation TARGET fails the WHOLE rotation before any
    #      mutation. The unsafe object appears while the queue is OPEN (so
    #      open's own chain validation cannot be what refuses it), and a SAFE
    #      member sits in a higher slot: a per-rename check would already have
    #      shifted it -- a half-mutated chain -- by the time the unsafe target
    #      was reached.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     file_bytes=1200, max_files=3).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    base_member = os.path.join(directory, sp.SPOOL_FILE)
    unsafe_target = os.path.join(directory, sp.SPOOL_FILE + ".1")
    safe_higher = os.path.join(directory, sp.SPOOL_FILE + ".2")
    shifted = os.path.join(directory, sp.SPOOL_FILE + ".3")
    planted = open(base_member, "rb").read()
    with open(safe_higher, "wb") as handle:
        handle.write(planted)              # a safe member in a higher slot
    if hasattr(os, "mkfifo"):
        os.mkfifo(unsafe_target)
    else:
        os.mkdir(unsafe_target)            # any special object will do
    raised = False
    try:
        try:
            queue.append("office-sg-isp-a", RUN, 2,
                         pl.encode_sample(_sample(2)),
                         queued_epoch=1700000000.0)
        except (sp.SpoolError, OSError):
            raised = True
    finally:
        queue.close()
    def read_bytes_or_none(path):
        # A refusal must produce a FALSE verdict, never a crash.
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except OSError:
            return None

    out["unsafe_rotated_target_fails_before_any_rotation_mutation"] = (
        raised
        and os.path.lexists(unsafe_target)
        and not os.path.isfile(unsafe_target)   # the target is untouched
        and os.path.isfile(base_member)         # the source never moved
        and read_bytes_or_none(base_member) == planted
        and read_bytes_or_none(safe_higher) == planted
        and not os.path.lexists(shifted))       # no partial shift happened
    if os.path.isdir(unsafe_target):
        os.rmdir(unsafe_target)
    else:
        os.unlink(unsafe_target)
    clean(root)

    # ---- C1: a FAILED Spool.open() must release its OWN writer lock. The
    #      failure lands after the lock is taken (a malformed state file), and
    #      the first object is deliberately kept alive: the second spool takes
    #      the lock in the SAME process, so this cannot be explained by an
    #      exiting process having released it.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    real_repair = sp.Spool._repair_tail

    def exploding_repair(self):
        raise sp.SpoolError("tail repair refused")

    sp.Spool._repair_tail = exploding_repair   # one-shot startup failure
    first = sp.Spool(directory, clock=lambda: 1700000000.0)
    refused = False
    try:
        first.open()
    except (sp.SpoolError, OSError):
        refused = True
    finally:
        sp.Spool._repair_tail = real_repair
    # the first object is NOT deleted and was never usable
    unusable = False
    try:
        first.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                     queued_epoch=1700000000.0)
    except sp.SpoolError:
        unusable = True
    second = None
    try:
        second = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    except (sp.SpoolError, OSError):
        second = None
    out["spool_open_failure_releases_writer_lock"] = (
        refused and unusable and second is not None)
    if second is not None:
        second.close()
    clean(root)
    # ---- C2: the attempt is hard-reserved BEFORE the send, so a storage that
    #      cannot persist it produces NO request at all.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    first_attempt = queue.note_attempt(1)              # durable N = 1
    real_save = sp.Spool._save_state

    def refusing_save(self):
        raise sp.SpoolError("state save refused")

    sp.Spool._save_state = refusing_save
    try:
        blocked = FakePoster([(200, b'{"result":"accepted","v":1}')] * 3)
        summary = dl.deliver_pending(queue, SECRET, "office-sg-isp-a", blocked)
        sent_while_blocked = len(blocked.requests)
    finally:
        sp.Spool._save_state = real_save
    out["retry_state_failure_prevents_network_send"] = (
        first_attempt == 1
        and summary["stopped"] == "retry_state_not_durable"
        and sent_while_blocked == 0          # poster was NEVER called
        and len(list(queue.pending())) == 1  # record unchanged
        and queue.attempts(1) == 1)          # durable attempt remains N
    queue.close()
    # (storage recovers) the next pass reserves N+1 and sends exactly once
    reopened = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    resumed = FakePoster([(503, b"")])
    recovered = dl.deliver_pending(reopened, SECRET, "office-sg-isp-a", resumed)
    out["retry_reservation_then_sends_exactly_once"] = (
        recovered["attempt"] == 2
        and len(resumed.requests) == 1
        and reopened.attempts(1) == 2)
    reopened.close()
    clean(root)
    # ---- C2b: the frozen unknown bound counts REAL sends, and the queue
    #      advances past the quarantined head.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    unknown = FakePoster([(600, b"")] * 30)
    for _ in range(dl.UNKNOWN_RESPONSE_MAX_ATTEMPTS + 2):
        if next(iter(queue.pending()), None) is None:
            break
        dl.deliver_pending(queue, SECRET, "office-sg-isp-a", unknown)
    bounded_sends = len(unknown.requests)
    # the queue ADVANCES past the quarantined head
    queue.append("office-sg-isp-a", RUN, 2, pl.encode_sample(_sample(2)),
                 queued_epoch=1700000000.0)
    after = dl.deliver_pending(queue, SECRET, "office-sg-isp-a",
                               FakePoster())
    out["bounded_unknown_counts_real_sends"] = (
        bounded_sends == dl.UNKNOWN_RESPONSE_MAX_ATTEMPTS
        and queue.status()["quarantined_total"] == 1
        and after["acked"] == 1
        and list(queue.pending()) == [])
    queue.close()
    clean(root)
    # ---- C3: a COMPLETE corrupt record still reserves its record id, so a
    #      reconciled append can never hand that id out again.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)           # durable id = 1
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(b'{"v":1,"record_id":3,"probe_id":"office-sg-isp-a"'
                     b',"run":"' + RUN.encode() + b'","seq":3'
                     b',"queued_epoch":1700000000.0,"body_b64":"!!!!"}\n')
    reopened = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    allocated = reopened.append("office-sg-isp-a", RUN, 2,
                                pl.encode_sample(_sample(2)),
                                queued_epoch=1700000000.0)
    out["corrupt_complete_record_reserves_record_id"] = (
        allocated >= 4 and allocated != 3
        and reopened.status()["corrupt_total"] == 1)
    reopened.close()
    clean(root)
    # ---- C3b: a corrupt line whose id CANNOT be recovered fails CLOSED --
    #      no cursor is guessed, and none is allocated from.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(b"this is not a record at all\n")
    refused = False
    try:
        sp.Spool(directory, clock=lambda: 1700000000.0).open()
    except (sp.SpoolError, OSError):
        refused = True
    out["unrecoverable_corrupt_record_fails_closed"] = refused
    clean(root)

    # ---- D1a: an UNRESOLVED complete-corrupt record survives compaction. Its
    #      id is still part of the durable high-water, so compaction may not
    #      treat it as garbage while the cursor has not proven it terminal.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    corrupt_line = (b'{"v":1,"record_id":3,"probe_id":"office-sg-isp-a"'
                    b',"run":"' + RUN.encode() + b'","seq":3'
                    b',"queued_epoch":1700000000.0,"body_b64":"!!!!"}')
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")
    reopened = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    reopened.enforce_bounds()
    cursor_after = int(reopened._state["resolved_through"])
    reopened.close()          # single writer: release before re-reading
    kept_lines = [line for line in
                  open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                  .read().splitlines() if line]
    out["unresolved_corrupt_record_survives_compaction"] = (
        cursor_after < 3
        and corrupt_line in kept_lines
        and any(sp.recover_record_id(line) == 3 for line in kept_lines))
    clean(root)
    # ---- D1b: the C3 crash window itself -- reconciliation cannot persist
    #      its cursor while compaction runs, so the ONLY evidence of id 3 is
    #      the corrupt line on disk. Losing it would reopen reuse.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")
    real_save = sp.Spool._save_state

    def refusing_save(self):
        raise sp.SpoolError("cursor save refused")

    sp.Spool._save_state = refusing_save
    try:
        window = sp.Spool(directory, clock=lambda: 1700000000.0).open()
        # startup reconciliation moved the IN-MEMORY cursor to 4, but the
        # durable cursor is still 2; retention then compacts.
        window.enforce_bounds()
    finally:
        sp.Spool._save_state = real_save
    window.close()
    final = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    allocated = final.append("office-sg-isp-a", RUN, 2,
                             pl.encode_sample(_sample(2)),
                             queued_epoch=1700000000.0)
    out["failed_cursor_save_plus_compaction_cannot_reopen_id_reuse"] = (
        allocated >= 4 and allocated != 3)
    final.close()
    clean(root)
    # ---- D1c: a corrupt line whose id cannot be recovered BLOCKS
    #      compaction: no rewrite is published and the line stays on disk.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    chain = os.path.join(directory, sp.SPOOL_FILE)
    before = open(chain, "rb").read()
    with open(chain, "ab") as handle:
        handle.write(b"complete but not a record at all\n")
    planted = open(chain, "rb").read()
    raised = False
    try:
        queue.enforce_bounds()
    except (sp.SpoolError, OSError):
        raised = True
    out["unrecoverable_corrupt_line_blocks_compaction"] = (
        raised and open(chain, "rb").read() == planted
        and planted != before)
    queue.close()
    clean(root)

    # ---- E1a: an unresolved corrupt record is never OVERTAKEN. Records
    #      before it stay deliverable in order, but nothing may pass it, so
    #      the cursor can never claim a terminal state it never reached.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    corrupt_line = (b'{"v":1,"record_id":3,"probe_id":"office-sg-isp-a"'
                    b',"run":"' + RUN.encode() + b'","seq":3'
                    b',"queued_epoch":1700000000.0,"body_b64":"!!!!"}')
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)          # valid id = 1
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")           # corrupt, recoverable = 3
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    fourth = queue.append("office-sg-isp-a", RUN, 4, pl.encode_sample(_sample(4)),
                          queued_epoch=1700000000.0)  # valid id = 4
    acked = dl.deliver_pending(queue, SECRET, "office-sg-isp-a", FakePoster())
    blocked_poster = FakePoster(
        [(200, b'{"result":"accepted","v":1}')] * 4)
    blocked = dl.deliver_pending(queue, SECRET, "office-sg-isp-a",
                                 blocked_poster)
    chain_lines = [line for line in
                   open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                   .read().splitlines() if line]
    out["unresolved_corrupt_record_blocks_later_delivery"] = (
        fourth == 4                                  # the id was reserved
        and acked["acked"] == 1                      # the record BEFORE it goes
        and blocked["stopped"] == "queue_blocked"
        and len(blocked_poster.requests) == 0        # id 4 never sent
        and int(queue._state["resolved_through"]) < 3
        and queue.status().get("queue_blocked") is True
        and corrupt_line in chain_lines)             # evidence still on disk
    queue.close()
    clean(root)
    # ---- E1b: once the durable cursor PROVES the corrupt record terminal,
    #      compaction may drop it and the queue continues.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")
    # a controlled fixture: the operator repaired the cursor past the corrupt
    # record, so id 3 is provably terminal.
    with open(os.path.join(directory, sp.STATE_FILE), "w",
              encoding="utf-8") as handle:
        handle.write('{"next_record_id": 4, "resolved_through": 3}')
    reopened = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    reopened.enforce_bounds()
    chain_lines = [line for line in
                   open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                   .read().splitlines() if line]
    resumed = reopened.append("office-sg-isp-a", RUN, 4,
                              pl.encode_sample(_sample(4)),
                              queued_epoch=1700000000.0)
    out["resolved_corrupt_record_allows_queue_to_continue"] = (
        corrupt_line not in chain_lines              # provably terminal
        and resumed == 4
        and [item["record_id"] for item in reopened.pending()] == [4]
        and reopened.status().get("queue_blocked") is False)
    reopened.close()
    clean(root)
    # ---- E2a: the byte bound is measured on the ENCODED chain, not on the
    #      decoded bodies: two records are 1184 decoded bytes but 1868 bytes
    #      on disk, so a 1500 byte budget must trim the chain to 934.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=1500).open()
    for seq in (1, 2):
        queue.append("office-sg-isp-a", RUN, seq,
                     pl.encode_sample(_sample(seq)),
                     queued_epoch=1700000000.0)
    decoded = sum(len(pl.encode_sample(_sample(s))) for s in (1, 2))
    status = queue.enforce_bounds()
    measured = chain_bytes(directory)
    out["physical_spool_budget_is_at_most_32_mib"] = (
        decoded <= 1500 and measured <= 1500
        and status["budget_dropped_total"] >= 1        # it was really dropped
        and len(list(queue.pending())) == 1)           # trimmed, not emptied
    queue.close()
    clean(root)
    # ---- E2b: unresolved corrupt evidence still COUNTS toward the budget --
    #      it is neither forgotten nor deleted to make room.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=1000).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=1000).open()
    status = queue.enforce_bounds()
    measured = chain_bytes(directory)
    chain_lines = [line for line in
                   open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                   .read().splitlines() if line]
    out["corrupt_lines_count_toward_physical_budget"] = (
        measured <= 1000
        and status["budget_dropped_total"] >= 1
        and corrupt_line in chain_lines)               # never deleted for room
    queue.close()
    clean(root)
    # ---- E2c: the frozen constants cannot contradict the contract, and a
    #      long run with scaled parameters never settles above the bound.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=3000, file_bytes=1000, max_files=4).open()
    worst = 0
    for index in range(12):
        queue.append("office-sg-isp-a", RUN, index + 1,
                     pl.encode_sample(_sample(index + 1)),
                     queued_epoch=1700000000.0)
        queue.enforce_bounds()
        worst = max(worst, chain_bytes(directory))
    out["rotation_chain_cannot_exceed_frozen_total_budget"] = (
        sp.MAX_FILES * (sp.FILE_BYTES + sp.RECORD_MAX_BYTES)
        <= sp.MAX_TOTAL_BYTES
        and sp.MAX_TOTAL_BYTES == 32 * 1024 * 1024
        and worst <= 3000
        and len(glob.glob(os.path.join(directory, sp.SPOOL_FILE + ".*")))
        <= sp.MAX_FILES)
    queue.close()
    clean(root)

    # ---- E1-F1a: RETENTION's age pruning must not advance the cursor past an
    #      unresolved corrupt record. Both the record before the blocker (old
    #      enough to expire) and the record after it are ancient; only the
    #      first may expire, because reaching the second would mean the cursor
    #      claimed a terminal state the corrupt record never reached.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    ancient = 1700003600.0 - 8 * 86400.0
    queue = sp.Spool(directory, clock=lambda: 1700003600.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=ancient)                  # id 1, before it
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")              # corrupt, id 3
        handle.write(valid_line(5, 5, ancient) + b"\n")  # id 5, after it
    queue = sp.Spool(directory, clock=lambda: 1700003600.0).open()
    queue.enforce_bounds()
    status = queue.status()
    chain_lines = [line for line in
                   open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                   .read().splitlines() if line]
    out["retention_cannot_advance_cursor_past_corrupt_blocker"] = (
        int(status["resolved_through"]) < 3
        and status["expired_total"] == 1        # only the record BEFORE it
        and corrupt_line in chain_lines)
    queue.close()
    clean(root)
    # ---- E1-F1b: the BYTE-budget pruning must not either. The chain is over
    #      budget, the oldest record before the blocker is dropped, and what
    #      remains (the blocker plus a record behind it) cannot be reduced by
    #      deleting anything we are allowed to delete -- so it fails CLOSED.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=700).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    queue.close()
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")
        handle.write(valid_line(5, 5, 1700000000.0) + b"\n")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0,
                     max_bytes=700).open()
    over_budget = chain_bytes(directory) > 700
    refused = False
    try:
        queue.enforce_bounds()
    except (sp.SpoolError, OSError):
        refused = True
    status = queue.status()
    chain_lines = [line for line in
                   open(os.path.join(directory, sp.SPOOL_FILE), "rb")
                   .read().splitlines() if line]
    out["byte_budget_cannot_advance_cursor_past_corrupt_blocker"] = (
        over_budget and refused
        and int(status["resolved_through"]) < 3
        and status["queue_blocked"] is True
        and corrupt_line in chain_lines)
    queue.close()
    clean(root)
    # ---- E1-F2: the blocker must come from THIS scan. Corruption that
    #      appears after a clean scan has to hold the queue on the VERY FIRST
    #      pending() call that discovers it -- a blocker read before the scan
    #      would let that call walk straight past it.
    root = temp_dir()
    directory = os.path.join(root, "spool")
    queue = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    queue.append("office-sg-isp-a", RUN, 1, pl.encode_sample(_sample(1)),
                 queued_epoch=1700000000.0)
    dl.deliver_pending(queue, SECRET, "office-sg-isp-a", FakePoster())
    clean_scan = [item["record_id"] for item in queue.pending()]
    with open(os.path.join(directory, sp.SPOOL_FILE), "ab") as handle:
        handle.write(corrupt_line + b"\n")              # appears NOW
        handle.write(valid_line(5, 5, 1700000000.0) + b"\n")
    first_ids = None
    refused = False
    try:
        first_ids = [item["record_id"] for item in queue.pending()]
    except (sp.SpoolError, OSError):
        refused = True
    out["newly_discovered_corruption_blocks_on_first_pending_call"] = (
        clean_scan == []        # the clean scan really happened first
        and refused and first_ids is None)      # and id 5 was never offered
    queue.close()
    clean(root)

    return out
# -- group: contract constants ---------------------------------------------------

def group_contract():
    out = {}
    out["retry_state_stop_token_is_frozen"] = (
        dl.RETRY_STATE_NOT_DURABLE == "retry_state_not_durable")
    out["cycle_deadline_is_20s"] = rp.CYCLE_DEADLINE_SECONDS == 20.0
    out["per_node_timeout_is_5s"] = rp.DELAY_TIMEOUT_SECONDS == 5.0
    out["body_cap_is_16kib"] = rp.MAX_BODY_BYTES == 16 * 1024
    out["protocol_is_p6_v1"] = rp.P6_PROTOCOL == "p6-v1"
    out["ingest_path_is_frozen_and_not_implemented_here"] = (
        rp.INGEST_PATH == "/api/v1/remote-probes/ingest")
    # P6A collection remains isolated. P6B/B2 own ingest and Bundle reads;
    # authorized P6C adds only incident-bound presentation in the separate
    # incident_remote module and shipped handler. History/classifier still
    # cannot name or consume remote evidence.
    allowed_names = {"server.py", "remote_ingest.py",
                     "remote_registry.py", "remote_store.py", "p6_bundle.py",
                     "incident_remote.py"}
    # P6B2 adds one passive profile/ZIP validator that names the frozen URL.
    # It implements no ingest or incident read route; portable bundle tests
    # execute assembly with socket/connection creation forbidden. All other
    # web modules remain outside this exact set; P6C is presentation-only.
    server_hits = []
    scope_violations = []
    for path in (os.path.join(ROOT, "monitor-v2", "web"),
                 os.path.join(ROOT, "monitor-v2", "webapp.py")):
        for found in glob.glob(os.path.join(path, "**", "*.py"),
                               recursive=True):
            text = open(found, encoding="utf-8").read()
            if "remote-probes" not in text:
                continue
            server_hits.append(found)
            if os.path.basename(found) not in allowed_names:
                scope_violations.append(found)
            if ("incidents/<incident_id>/remote-probes" in text
                    and os.path.basename(found) not in {"server.py", "incident_remote.py"}):
                scope_violations.append(found)
    # server.py must be among the hits (the route lives there), every
    # hit must be an allowlisted plane file, and nothing outside the
    # allowlist may name the surface at all.
    out["no_server_ingest_route_exists"] = (
        any(os.path.basename(hit) == "server.py" for hit in server_hits)
        and not scope_violations)
    # History untouched: no remote table name in the store, and the schema
    # version is still v5 with the eleven-table shape.
    history = open(os.path.join(ROOT, "monitor-v2", "web",
                                "incident_history.py"), encoding="utf-8").read()
    out["history_store_has_no_remote_tables"] = (
        "remote_probe" not in history and "remote-probes" not in history)
    out["history_schema_untouched"] = "SCHEMA_VERSION = 5" in history
    out["history_prune_sources_untouched"] = (
        history.count("_PRUNE_SOURCES = (") == 1
        and '("operator_markers", "epoch"),' in history)
    # classifier / runtime / presenter untouched by P6
    for name, needle in (("incident_classifier.py", "remote"),
                         ("incident_runtime.py", "remote"),
                         ("incident_presenter.py", "remote")):
        text = open(os.path.join(ROOT, "monitor-v2", "web", name),
                    encoding="utf-8").read()
        out["%s_has_no_remote_reference" % name.replace(".py", "")] = (
            needle not in text.lower())
    # the agent tree imports nothing from the server monitor
    offenders = []
    for path in glob.glob(os.path.join(ROOT, "monitor-v2", "remote_probe",
                                       "*.py")):
        text = open(path, encoding="utf-8").read()
        for marker in ("import web", "from web", "incident_history",
                       "incident_classifier", "probe_scheduler",
                       "webapp"):
            if marker in text:
                offenders.append((os.path.basename(path), marker))
    out["agent_imports_no_server_monitor_code"] = not offenders
    # The direct-slot vocabulary is a MIRROR of the audited VPS-side engine:
    # importing it HERE (a test may import server code; the agent may not) is
    # what makes the mirror a gate instead of a comment.
    from diagnostics import network_probes as engine
    out["direct_error_codes_mirror_the_audited_engine"] = (
        set(dp.ERROR_CODES) == set(engine.ERROR_CODES))
    out["direct_status_and_change_mirror_the_audited_engine"] = (
        set(dp.STATUSES) == {engine.STATUS_OK, engine.STATUS_FAILED}
        and set(dp.CHANGE_VALUES) == {engine.CHANGE_UNCHANGED,
                                      engine.CHANGE_CHANGED,
                                      engine.CHANGE_UNKNOWN})
    out["egress_gate_matches_the_audited_canonical_gate"] = all(
        dp.canonical_global_ip(candidate)
        == (engine._canonical_ip(candidate))
        for candidate in (IP_A, IP_B, "10.0.0.1", "127.0.0.1", "224.0.0.1",
                          "255.255.255.255", "2001:db8::1", "::1",
                          "2606:4700:4700::1111", "not-an-ip", "", "1.2.3.4.5"))
    out["version_not_bumped"] = (
        open(os.path.join(ROOT, "monitor-v2", "VERSION"),
             encoding="utf-8").read().strip() == "0.8.0")
    out["monitor_web_version_untouched"] = (
        'MONITOR_WEB_VERSION = "0.8.0"' in open(
            os.path.join(ROOT, "monitor-v2", "web", "server.py"),
            encoding="utf-8").read())
    return out


GROUPS = {
    "roles": group_roles,
    "active": group_active,
    "boundary": group_boundary,
    "direct": group_direct,
    "echo": group_echo,
    "payload": group_payload,
    "spool": group_spool,
    "disposition": group_disposition,
    "cycle": group_cycle,
    "contract": group_contract,
    "resilience": group_resilience,
}


def main():
    names = sys.argv[1:] or sorted(GROUPS)
    rc = 0
    for name in names:
        try:
            results = GROUPS[name]()
        except Exception as exc:  # noqa: BLE001 -- report, never die green
            import traceback
            traceback.print_exc()
            print("FAIL %s harness crashed: %s: %s"
                  % (name, type(exc).__name__, exc))
            rc = 1
            continue
        for key in sorted(results):
            if results[key] is True:
                print("PASS %s/%s" % (name, key))
            else:
                print("FAIL %s/%s" % (name, key))
                rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
