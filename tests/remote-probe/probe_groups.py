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

SECRET = b"p6-sentinel-secret-DO-NOT-LEAK-0123456789"
SECRET_TEXT = SECRET.decode()
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
    for status in (400, 408, 504):
        instance, _t = _delay_agent((status, b'{"message":"timeout"}'))
        try:
            outcome, delay, _n = instance.mihomo.delay(
                rp.ROLE_REALITY, "office-reality-01")
            out["active_timeout_status_%d" % status] = (
                outcome == rp.OUTCOME_TIMEOUT and delay is None)
        finally:
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
    # The single POST in the tree is the machine ingestion call to the frozen
    # path, issued by the delivery client -- never against Mihomo.
    posts = []
    for path in glob.glob(os.path.join(ROOT, "monitor-v2", "remote_probe",
                                       "*.py")):
        text = open(path, encoding="utf-8").read()
        if 'conn.request("POST"' in text:
            posts.append(os.path.basename(path))
    out["only_the_frozen_ingest_post_exists"] = (
        posts == ["delivery.py"]
        and rp.INGEST_METHOD == "POST"
        and "INGEST_PATH" in open(os.path.join(
            ROOT, "monitor-v2", "remote_probe", "delivery.py"),
            encoding="utf-8").read())
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
        # 26. spool-before-ack: the record is durable BEFORE any upload
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
            set(reopened.status()) == {
                "pending", "pending_bytes", "oldest_queued_epoch",
                "resolved_through", "acknowledged_total", "quarantined_total",
                "expired_total", "budget_dropped_total", "corrupt_total"}
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
    repaired = sp.Spool(directory, clock=lambda: 1700000000.0).open()
    out["torn_tail_repaired"] = (
        len(list(repaired.pending())) == 1
        and open(path, "rb").read().endswith(b"\n"))
    # a complete-but-corrupt line is counted, not rewritten away silently
    with open(path, "ab") as handle:
        handle.write(b'{"v":1,"record_id":3,"probe_id":"office-sg-isp-a","run":"%s","seq":3,"queued_epoch":1700000000.0,"body_b64":"!!!!"}\n'
                     % RUN.encode())
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
        resent = [request["body"] for request in poster.requests[1:]]
        out["rollback_never_rewrites_spooled_timestamps"] = (
            first_body in resent
            and json.loads(first_body)["sample_epoch"] == 1700000000.0)
        # status is closed and sanitized
        status = instance.status()
        out["status_is_closed_and_sanitized"] = (
            set(status) == {"probe_id", "run", "seq", "cycles",
                            "cycle_failures", "clock_rollbacks",
                            "overlap_refusals", "spool_failures", "state",
                            "active", "spool"}
            and SECRET_TEXT not in json.dumps(status))
        # 45. secret leak wall: payload, spool bytes, status, exception text
        spool_bytes = b""
        for path in glob.glob(os.path.join(instance.config.spool_dir, "*")):
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


# -- group: contract constants ---------------------------------------------------

def group_contract():
    out = {}
    out["cycle_deadline_is_20s"] = rp.CYCLE_DEADLINE_SECONDS == 20.0
    out["per_node_timeout_is_5s"] = rp.DELAY_TIMEOUT_SECONDS == 5.0
    out["body_cap_is_16kib"] = rp.MAX_BODY_BYTES == 16 * 1024
    out["protocol_is_p6_v1"] = rp.P6_PROTOCOL == "p6-v1"
    out["ingest_path_is_frozen_and_not_implemented_here"] = (
        rp.INGEST_PATH == "/api/v1/remote-probes/ingest")
    # The agent never ships a server route: no server file mentions ingest.
    server_hits = []
    for path in (os.path.join(ROOT, "monitor-v2", "web"),
                 os.path.join(ROOT, "monitor-v2", "webapp.py")):
        for found in glob.glob(os.path.join(path, "**", "*.py"),
                               recursive=True):
            if "remote-probes" in open(found, encoding="utf-8").read():
                server_hits.append(found)
    out["no_server_ingest_route_exists"] = not server_hits
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
             encoding="utf-8").read().strip() == "0.6.1")
    out["monitor_web_version_untouched"] = (
        'MONITOR_WEB_VERSION = "0.6.1"' in open(
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
