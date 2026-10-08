"""Issue #48: hermetic policy/controller/profile/upload tests; no live host."""
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover.policy import Policy, Confirmation, Engine, Ownership, NODES, AUTO, GROUP, OUTER
from quality_failover.controller import Controller, Passive, alive
from quality_failover.runtime import Budget, Runner
from quality_failover.config import client, read_json
from quality_failover.receiver import Server
from quality_failover.transport import Probe, endpoint, UploadTimeout, decode_json

def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

CLI = module("mihomo-quality-failover.py", "quality_cli")
MERGE = module("mihomo-multi-vps-merge.py", "merge_fixture")
GOOD = Confirmation(12, endpoint_ready=True)
BAD = Confirmation(1, endpoint_ready=True)


def configuration(dual=False):
    return {"v": 1, "controller": "http://127.0.0.1:19091",
            "controller_secret": "synthetic-controller-secret-only",
            "control_enabled": False, "cycle_seconds": 5,
            "probe_interval_seconds": 30, "probe_bytes_per_minute": 2097152,
            "churn_connections": 3, "paths": [
                {"name": name, "listener_port": 19200 + index,
                 "endpoint": "https://127.0.0.1:19443", "token": "a" * 32,
                 "ca_file": None, "payload_bytes": 524288, "rate_mbps": 20,
                 "timeout_seconds": 6, "policy": {
                     "fail_mbps": 4, "recover_mbps": 8, "hold_seconds": 30,
                     "freshness_seconds": 90, "fail_samples": 2, "recover_samples": 3}}
                for index, name in enumerate(NODES if dual else NODES[:2])]}


def snapshot(nodes=NODES[:2]):
    result = {OUTER: {"type": "Selector", "now": GROUP},
              GROUP: {"type": "Fallback", "now": nodes[0], "fixed": "", "hidden": True,
                      "all": list(nodes)},
              AUTO: {"type": "Fallback", "fixed": "", "now": nodes[0], "all": list(nodes)}}
    for name in nodes:
        result[name] = {"alive": True, "history": [{"time":
            datetime.now(timezone.utc).isoformat(), "delay": 50}]}
    return result


def export(path, backup=False, hopping=False):
    server = "198.51.100.2" if backup else "203.0.113.1"
    uuid = "22222222-2222-4222-8222-222222222222" if backup else "11111111-1111-4111-8111-111111111111"
    password = "synthetic-backup-password" if backup else "synthetic-primary-password"
    hop = ["    ports: 40000-40100", "    hop-interval: 30"] if hopping else []
    lines = list(MERGE.CANONICAL_PREFIX_LINES) + ["proxies:",
        "  - name: Reality", "    type: vless", f"    server: {server}",
        "    port: 8443", f"    uuid: {uuid}", "    network: tcp",
        "    udp: true", "    tls: true", "    flow: xtls-rprx-vision",
        "    servername: www.example.com", "    client-fingerprint: chrome",
        "    reality-opts:", "      public-key: " + "A" * 43,
        "      short-id: 0123456789abcdef", "",
        "  - name: Hysteria2", "    type: hysteria2", f"    server: {server}",
        "    port: 8444", *hop, f"    password: {password}",
        '    up: "300 Mbps"', '    down: "300 Mbps"', "    sni: www.example.com",
        "    skip-cert-verify: true", "    alpn:", "      - h3", "", "",
        "proxy-groups:", *MERGE.GROUPS_SINGLE_OUTER, "", *MERGE.GROUPS_SINGLE_AUTO,
        "", "", "rules:", "  - GEOIP,LAN,DIRECT", "  - GEOIP,CN,DIRECT",
        "  - MATCH,节点选择", "", ""]
    path.write_bytes("\n".join(lines).encode())


class PolicyTests(unittest.TestCase):
    def engine(self, dual=False):
        return Engine({name: Policy(4, 8, hold_seconds=30)
                       for name in (NODES if dual else NODES[:2])})

    def test_reachable_but_upload_degraded(self):
        e = self.engine()
        e.update(0, {"Reality": (True, BAD), "Hysteria2": (True, GOOD)})
        self.assertIsNone(e.target(0, "Reality"))
        e.update(5, {"Reality": (True, None), "Hysteria2": (True, None)})
        e.update(30, {"Reality": (True, BAD), "Hysteria2": (True, GOOD)})
        self.assertEqual(e.paths["Reality"].state, "DEGRADED")
        self.assertEqual(e.target(30, "Reality"), "Hysteria2")

    def test_hy2_down_reality_healthy(self):
        e = self.engine()
        e.update(0, {"Reality": (True, GOOD), "Hysteria2": (False, None)})
        self.assertIsNone(e.target(0, "Reality"))
        self.assertEqual(e.target(0, "Hysteria2"), "Reality")

    def test_quality_is_symmetric(self):
        e = self.engine()
        for at in (0, 30):
            e.update(at, {"Reality": (True, GOOD), "Hysteria2": (True, BAD)})
        self.assertEqual(e.paths["Hysteria2"].state, "DEGRADED")
        self.assertEqual(e.target(30, "Hysteria2"), "Reality")

    def test_two_primary_failures_require_verified_backup(self):
        e = self.engine(True)
        e.update(0, {"Reality": (False, None), "Hysteria2": (False, None),
                     "Backup-Reality": (True, None), "Backup-Hysteria2": (True, GOOD)})
        self.assertEqual(e.target(0, "Reality"), "Backup-Hysteria2")

    def test_primary_recovery_preference(self):
        e = self.engine(True)
        for at in (0, 30):
            e.update(at, {name: (True, BAD if name in NODES[:2] else GOOD) for name in NODES})
        self.assertEqual(e.target(30, "Reality"), "Backup-Reality")
        for at in (60, 90, 120):
            e.update(at, {name: (True, GOOD) for name in NODES})
        self.assertEqual(e.target(120, "Backup-Reality"), "Reality")

    def test_hold_down_and_multiple_recovery_checks(self):
        e = self.engine()
        for at in (0, 30):
            e.update(at, {"Reality": (True, BAD), "Hysteria2": (True, GOOD)})
        for at in (31, 32):
            e.update(at, {"Reality": (True, GOOD), "Hysteria2": (True, GOOD)})
            self.assertEqual(e.paths["Reality"].state, "DEGRADED")
        e.update(60, {"Reality": (True, GOOD), "Hysteria2": (True, GOOD)})
        self.assertEqual(e.paths["Reality"].state, "UP")

    def test_missing_evidence_does_not_bypass_hold(self):
        e = self.engine()
        e.update(0, {"Reality": (False, None), "Hysteria2": (True, GOOD)})
        e.update(10, {"Reality": (None, None), "Hysteria2": (True, GOOD)})
        e.update(40, {"Reality": (True, GOOD), "Hysteria2": (True, GOOD)})
        self.assertIsNone(e.target(40, "Hysteria2"))

    def test_middle_band_breaks_consecutive_recovery(self):
        e = self.engine()
        e.update(0, {"Reality": (False, None)})
        for at, confirm in ((30, GOOD), (60, Confirmation(6, endpoint_ready=True)), (90, GOOD), (120, GOOD)):
            e.update(at, {"Reality": (True, confirm)})
        self.assertFalse(e.paths["Reality"].usable(120, e.policies["Reality"]))

    def test_low_upload_demand_not_bad(self):
        e = self.engine()
        for at in range(0, 120, 5):
            e.update(at, {"Reality": (True, None), "Hysteria2": (True, None)})
        self.assertEqual(e.paths["Reality"].state, "UP")
        self.assertIsNone(e.target(120, "Reality"))

    def test_stale_alternative_not_selected(self):
        e = self.engine()
        e.update(0, {"Hysteria2": (True, GOOD)})
        e.update(100, {"Reality": (False, None), "Hysteria2": (True, None)})
        self.assertIsNone(e.target(100, "Reality"))

    def test_unavailable_sink_does_not_degrade(self):
        e = self.engine()
        for at in (0, 30, 60):
            e.update(at, {"Reality": (True, Confirmation(timed_out=True)), "Hysteria2": (True, GOOD)})
        self.assertEqual(e.paths["Reality"].state, "UP")

    def test_authenticated_upload_timeout_is_bad_after_two(self):
        e = self.engine()
        for at in (0, 30):
            e.update(at, {"Reality": (True, Confirmation(timed_out=True, endpoint_ready=True)),
                          "Hysteria2": (True, GOOD)})
        self.assertEqual(e.target(30, "Reality"), "Hysteria2")

    def test_unknown_is_not_down(self):
        e = self.engine()
        e.update(0, {})
        self.assertEqual(e.paths["Reality"].state, "UNKNOWN")
        self.assertIsNone(e.target(0, "Reality"))

    def test_invalid_and_backward_clock_rejected(self):
        e = self.engine()
        e.update(10, {})
        for now in (9, True, float("nan"), float("inf"), -1):
            with self.subTest(now=now), self.assertRaises(ValueError):
                e.update(now, {})

    def test_invalid_policy_and_confirmation(self):
        for args in ((8, 4), (True, 8), (float("nan"), 8)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                Policy(*args)
        for sample in (Confirmation(float("nan"), endpoint_ready=True),
                       Confirmation(12, timed_out=True, endpoint_ready=True),
                       Confirmation(12, endpoint_ready=1)):
            self.assertEqual(sample.verdict(Policy(4, 8)), "unknown")


class OwnershipTests(unittest.TestCase):
    def test_outer_manual_pins_are_never_released(self):
        for pin in ("Reality", "Hysteria2", "DIRECT", AUTO):
            owner = Ownership(NODES[:2]); p = snapshot(); p[OUTER]["now"] = pin
            self.assertFalse(owner.permitted(p))
            self.assertFalse(owner.suspended)

    def test_inner_legacy_manual_pin_is_preserved(self):
        owner = Ownership(NODES[:2]); p = snapshot(); p[AUTO]["fixed"] = "Hysteria2"
        self.assertFalse(owner.permitted(p))
        self.assertEqual(p[AUTO]["fixed"], "Hysteria2")

    def test_external_owned_group_change_suspends(self):
        owner = Ownership(NODES[:2]); p = snapshot(); p[GROUP]["fixed"] = "Hysteria2"
        self.assertFalse(owner.permitted(p))
        p[GROUP]["fixed"] = ""
        self.assertFalse(owner.permitted(p))

    def test_unknown_core_fixed_shape_never_controlled(self):
        owner = Ownership(NODES[:2]); p = snapshot(); del p[AUTO]["fixed"]
        self.assertFalse(owner.permitted(p))
        self.assertTrue(owner.suspended)

    def test_control_rechecks_and_only_own_group(self):
        controller = Controller("http://127.0.0.1:19091", "a" * 32)
        owner = Ownership(NODES[:2])
        with patch.object(controller, "proxies", return_value=snapshot()), patch.object(controller, "request") as call:
            self.assertTrue(controller.select("Hysteria2", owner))
            self.assertEqual(call.call_args.args, ("PUT", "/proxies/%E8%B4%A8%E9%87%8F%E8%87%AA%E5%8A%A8%E9%80%89%E6%8B%A9", {"name": "Hysteria2"}))
        self.assertEqual(owner.expected, "Hysteria2")

    def test_manual_change_between_snapshot_and_write_prevents_write(self):
        controller = Controller("http://127.0.0.1:19091", "a" * 32)
        p = snapshot(); p[OUTER]["now"] = "Reality"
        with patch.object(controller, "proxies", return_value=p), patch.object(controller, "request") as call:
            self.assertFalse(controller.select("Hysteria2", Ownership(NODES[:2])))
            call.assert_not_called()

    def test_restore_does_not_change_manual_outer(self):
        controller = Controller("http://127.0.0.1:19091", "a" * 32)
        owner = Ownership(NODES[:2]); owner.committed("Hysteria2")
        p = snapshot(); p[GROUP]["fixed"] = "Hysteria2"; p[OUTER]["now"] = "DIRECT"
        with patch.object(controller, "proxies", return_value=p), patch.object(controller, "request") as call:
            controller.restore(owner)
            self.assertEqual(call.call_args.args[0], "DELETE")
        self.assertEqual(p[OUTER]["now"], "DIRECT")

    def test_nonloopback_controller_rejected(self):
        for url in ("http://203.0.113.1:9090", "http://localhost:9090", "https://127.0.0.1:9090",
                    "http://user:pass@127.0.0.1:9090", "http://127.0.0.1:9090/x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Controller(url, "a" * 32)


class TelemetryTests(unittest.TestCase):
    def test_recent_liveness_and_missing_stale_future(self):
        p = snapshot()["Reality"]
        self.assertTrue(alive(p, time.time(), 90))
        self.assertIsNone(alive(p, time.time() + 100, 90))
        self.assertIsNone(alive(p, time.time() - 100, 90))
        self.assertIsNone(alive({"alive": True}, time.time(), 90))

    def test_churn_only_suspicion_not_verdict(self):
        passive = Passive(NODES[:2], 2)
        def value(ids):
            return {"connections": [{"id": i, "chains": ["Reality"], "upload": 0} for i in ids]}
        self.assertEqual(passive.suspicion(value(["a", "b"])), set())
        self.assertEqual(passive.suspicion(value(["c", "d"])), {"Reality"})

    def test_finished_connections_not_churn(self):
        passive = Passive(NODES[:2], 2)
        passive.suspicion({"connections": [{"id": "a", "chains": ["Reality"]},
                                         {"id": "b", "chains": ["Reality"]}]})
        self.assertEqual(passive.suspicion({"connections": []}), set())

    def test_active_rate_collapse_requests_confirmation(self):
        passive = Passive(NODES[:2], 2, {"Reality": 4})
        amount = 0; suspect = set()
        for at, delta in enumerate([0, 2000000, 2000000, 2000000, 0, 0]):
            amount += delta
            suspect = passive.suspicion({"connections": [
                {"id": "ongoing", "chains": ["Reality"], "upload": amount}]}, at)
        self.assertEqual(suspect, {"Reality"})

    def test_zero_demand_never_suspect(self):
        passive = Passive(NODES[:2], 2, {"Reality": 4})
        for at in range(10):
            self.assertEqual(passive.suspicion({"connections": [
                {"id": "idle", "chains": ["Reality"], "upload": 0}]}, at), set())

    def test_malformed_oversized_connections_drop_baseline(self):
        passive = Passive(NODES[:2], 2)
        self.assertEqual(passive.suspicion({"connections": [None]}), set())
        self.assertEqual(passive.suspicion({"connections": [{}] * 4097}), set())
        self.assertIsNone(passive.previous)

    def test_budget_is_aggregate_and_per_path(self):
        budget = Budget(100, 30)
        self.assertTrue(budget.reserve("Reality", 60, 0))
        self.assertFalse(budget.reserve("Hysteria2", 60, 0))
        self.assertFalse(budget.reserve("Reality", 20, 10))
        self.assertTrue(budget.reserve("Hysteria2", 40, 30))
        self.assertTrue(budget.reserve("Reality", 60, 60))
        self.assertLessEqual(len(budget.records), 2)


class ProfileConfigTests(unittest.TestCase):
    def test_single_and_dual_profiles_preserve_canonical_and_hopping(self):
        for dual in (False, True):
            with self.subTest(dual=dual), tempfile.TemporaryDirectory() as directory:
                base = Path(directory); (base/"A").mkdir(); (base/"B").mkdir()
                primary, backup = base/"A/event-mihomo.yaml", base/"B/event-mihomo.yaml"
                export(primary, hopping=True); export(backup, backup=True, hopping=True)
                out = base/"quality.yaml"
                CLI.prepare("event", str(primary), str(backup) if dual else None, str(out), configuration(dual))
                text = out.read_text(encoding="utf-8")
                self.assertIn("    default-selected: 自动选择", text)
                self.assertIn("      - 质量自动选择\n      - DIRECT", text)
                self.assertIn("    proxy: Reality", text)
                self.assertIn("    proxy: Hysteria2", text)
                self.assertEqual(text.count("    hop-interval: 30"), 2 if dual else 1)
                self.assertIn('    expected-status: "204"', text)
                self.assertIn("    interval: 60", text)
                self.assertEqual(text.count("    listen: 127.0.0.1"), 4 if dual else 2)
                self.assertEqual(text.split("listeners:")[0].encode(), "\n".join(MERGE.CANONICAL_PREFIX_LINES).encode()+"\n".encode())
                if os.name != "nt":
                    self.assertEqual(out.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(Exception):
                    CLI.prepare("event", str(primary), None, str(out), configuration())

    def test_source_name_or_credentials_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); (base/"A").mkdir(); (base/"B").mkdir()
            a, b = base/"A/event-mihomo.yaml", base/"B/event-mihomo.yaml"
            export(a); export(b)
            with self.assertRaises(Exception):
                CLI.prepare("event", str(a), str(b), str(base/"out.yaml"), configuration(True))
            self.assertFalse((base/"out.yaml").exists())

    def test_duplicate_json_keys_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/"config.json"; file.write_text('{"v":1,"v":1}'); file.chmod(0o600)
            with self.assertRaises(ValueError):
                read_json(file)

    def test_probe_must_be_attainable_budget_and_ports_distinct(self):
        for change in ("slow", "port", "budget", "freshness", "boolean", "extra"):
            cfg=configuration()
            if change=="slow": cfg["paths"][0]["rate_mbps"]=4
            if change=="port": cfg["paths"][0]["listener_port"]=cfg["paths"][1]["listener_port"]
            if change=="budget": cfg["probe_bytes_per_minute"]=32768
            if change=="freshness": cfg["probe_interval_seconds"]=120
            if change=="boolean": cfg["control_enabled"]=1
            if change=="extra": cfg["password"]="must-not-be-reflected"
            with self.subTest(change=change), self.assertRaises(ValueError):
                client(cfg)

    def test_no_arbitrary_probe_destination(self):
        for url in ("http://127.0.0.1:444", "https://example.com", "https://127.0.0.1/x",
                    "https://127.0.0.1?token=bad", "https://user:pass@127.0.0.1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)

    def test_observe_is_default_example_and_no_real_controls(self):
        cfg=configuration()
        runner=Runner(cfg)
        with patch.object(runner.controller,"proxies",return_value=snapshot()), patch.object(
                runner.controller,"request",return_value={"connections":[]}), patch.object(
                runner.controller,"select") as selected, patch.object(runner.controller,"restore") as restored:
            self.assertEqual(runner.cycle()["mode"],"observe")
            runner.close(); selected.assert_not_called(); restored.assert_not_called()


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.server=Server(("127.0.0.1",0),"a"*32,minute_bytes=65536)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True); self.worker.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join()

    def request(self, method, path, payload=b"", token=None, nonce=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=2)
        conn.request(method,path,payload,{"Authorization":"Bearer "+(token or "a"*32),
            "X-Probe-Nonce":nonce or "b"*32})
        response=conn.getresponse(); code, body=response.status,response.read(); conn.close()
        return code,body

    def test_authenticated_body_receipt_is_bounded_and_correlated(self):
        payload=b"x"*32768
        code,body=self.request("POST","/quality-v1/upload",payload)
        self.assertEqual(code,200)
        receipt=json.loads(body)
        self.assertEqual({key:receipt[key] for key in ("v","nonce","bytes","sha256")},
                         {"v":1,"nonce":"b"*32,"bytes":len(payload),
                          "sha256":hashlib.sha256(payload).hexdigest()})
        self.assertTrue(len(payload)-8192 <= receipt["measured_bytes"] < len(payload))
        self.assertTrue(0 < receipt["upload_seconds"] <= 15)
        self.assertNotIn(payload[:100],body)

    def test_ready_has_no_body_and_unknown_paths_refused(self):
        self.assertEqual(self.request("GET","/quality-v1/ready")[0],200)
        self.assertEqual(self.request("GET","/arbitrary")[0],403)

    def test_bad_auth_and_nonce_refused(self):
        self.assertEqual(self.request("POST","/quality-v1/upload",b"x",token="c"*32)[0],403)
        self.assertEqual(self.request("POST","/quality-v1/upload",b"x",nonce="invalid")[0],400)

    def test_over_budget_does_not_receive_body(self):
        self.assertEqual(self.request("POST","/quality-v1/upload",b"x"*32768)[0],200)
        self.assertEqual(self.request("POST","/quality-v1/upload",b"x"*32768)[0],200)
        self.assertEqual(self.request("POST","/quality-v1/upload",b"x")[0],429)

    def test_duplicate_and_chunked_headers_refused(self):
        for extra in ("Authorization: Bearer "+"a"*32+"\r\n", "Transfer-Encoding: chunked\r\n",
                      "Content-Length: 1\r\n"):
            with self.subTest(extra=extra):
                sock=socket.create_connection(self.server.server_address,timeout=2)
                sock.sendall(("POST /quality-v1/upload HTTP/1.1\r\nHost: localhost\r\n"
                    "Authorization: Bearer "+"a"*32+"\r\nX-Probe-Nonce: "+"b"*32+
                    "\r\nContent-Length: 1\r\n"+extra+"\r\n").encode())
                response=sock.recv(100); sock.close()
                self.assertIn(b"403",response)

    def test_upload_timeout_after_ready_and_unknown_setup_failure(self):
        probe=Probe("https://127.0.0.1:19443","a"*32,None,32768,20,6)
        with patch.object(probe,"request",side_effect=[.01,UploadTimeout()]):
            self.assertTrue(probe.measure(19200).timed_out)
        with patch.object(probe,"request",side_effect=[.01,TimeoutError()]):
            self.assertFalse(probe.measure(19200).timed_out)
        with patch.object(probe,"request",side_effect=ValueError("bad auth")):
            self.assertFalse(probe.measure(19200).endpoint_ready)



class BoundaryTests(unittest.TestCase):
    def test_wire_json_duplicate_and_nonfinite_refused(self):
        for raw in ('{"v":1,"v":1}', '{"upload_seconds":NaN}', '{"upload_seconds":Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                decode_json(raw)

    def test_malformed_owned_group_suspends_closed(self):
        owner=Ownership(NODES[:2]); value=snapshot(); value[GROUP]="wrong"
        self.assertFalse(owner.permitted(value))
        self.assertTrue(owner.suspended)

    def test_nonfinite_delay_is_unknown(self):
        for delay in (float("inf"),float("nan"),True,-1):
            value=snapshot()["Reality"]; value["history"][-1]["delay"]=delay
            self.assertIsNone(alive(value,time.time(),90))

    def test_native_hard_failure_clear_is_accepted_not_overwritten(self):
        owner=Ownership(NODES[:2]); owner.committed("Hysteria2")
        value=snapshot(); value["Hysteria2"]["alive"]=False
        self.assertTrue(owner.permitted(value))
        self.assertEqual(owner.expected,AUTO)

    def test_same_clear_on_still_alive_member_is_foreign(self):
        owner=Ownership(NODES[:2]); owner.committed("Hysteria2")
        self.assertFalse(owner.permitted(snapshot()))
        self.assertTrue(owner.suspended)

    def test_route_attribution_requires_unique_exact_connection(self):
        c=Controller("http://127.0.0.1:19091","a"*32)
        row={"metadata":{"sourceIP":"127.0.0.1","sourcePort":"20000",
            "inboundName":"quality-probe-0","destinationIP":"203.0.113.1",
            "destinationPort":"8448","specialProxy":"Reality"},"chains":["Reality"]}
        with patch.object(c,"request",return_value={"connections":[row]}):
            self.assertTrue(c.confirm_route("Reality","quality-probe-0",20000,"203.0.113.1",8448))
        for key,value in (("specialProxy","Hysteria2"),("inboundName","mixed"),
                          ("sourcePort","20001"),("destinationIP","198.51.100.1")):
            other=copy.deepcopy(row); other["metadata"][key]=value
            with patch.object(c,"request",return_value={"connections":[other]}):
                self.assertFalse(c.confirm_route("Reality","quality-probe-0",20000,"203.0.113.1",8448))
        with patch.object(c,"request",return_value={"connections":[row,row]}):
            self.assertFalse(c.confirm_route("Reality","quality-probe-0",20000,"203.0.113.1",8448))

    def test_probe_connections_do_not_manufacture_passive_churn(self):
        passive=Passive(NODES[:2],2)
        def payload(ids):
            return {"connections":[{"id":name,"chains":["Reality"],
                "metadata":{"inboundName":"quality-probe-0"}} for name in ids]}
        passive.suspicion(payload(["a","b"]))
        self.assertEqual(passive.suspicion(payload(["c","d"])),set())

    def test_bad_quality_counts_are_bounded(self):
        path=Engine({name:Policy(4,8) for name in NODES[:2]})
        for at in range(1000):
            path.update(at,{"Reality":(True,BAD),"Hysteria2":(True,GOOD)})
        self.assertEqual(path.paths["Reality"].bad,2)
        self.assertEqual(path.paths["Hysteria2"].good,3)

    def test_receiver_configuration_never_starts_without_tls_or_with_extra_keys(self):
        for cfg in ({},{"v":1,"listen":"127.0.0.1","port":8448,"token":"a"*32,
                     "certificate":"","private_key":"","minute_bytes":65536,"insecure":True}):
            with self.assertRaises(ValueError):
                CLI.serve(cfg)

    def test_receipt_wrong_nonce_bytes_shape_time_or_route_is_refused(self):
        probe=Probe("https://127.0.0.1:19443","a"*32,None,32768,20,6)
        payload=b"\0"*32768
        base={"v":1,"nonce":"b"*32,"bytes":32768,"sha256":hashlib.sha256(payload).hexdigest(),
              "measured_bytes":24576,"upload_seconds":.02}
        class Response:
            status=200
            def __init__(self, value): self.data=json.dumps(value).encode()
            def begin(self): pass
            def read1(self,n):
                result,self.data=self.data[:n],self.data[n:];return result
        sock=unittest.mock.Mock();sock.getsockname.return_value=("127.0.0.1",20000)
        def run(value, verifier=lambda port:True):
            with patch("quality_failover.transport.socks_connect",return_value=sock),patch.object(
                    ssl.SSLContext,"wrap_socket",return_value=sock),patch(
                    "quality_failover.transport.secrets.token_hex",return_value="b"*32),patch(
                    "quality_failover.transport.http.client.HTTPResponse",return_value=Response(value)):
                return probe.request(19200,"upload",payload,verifier)
        self.assertGreaterEqual(run(base),8)
        for key,value in (("nonce","c"*32),("bytes",1),("v",True),("measured_bytes",-1),
                          ("upload_seconds",float("nan")),("upload_seconds",True)):
            invalid=copy.deepcopy(base);invalid[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                run(invalid)
        with self.assertRaises(ValueError): run(base,lambda port:False)
        burst=copy.deepcopy(base);burst["upload_seconds"]=.000001
        self.assertEqual(run(burst),probe.rate)

    @unittest.skipIf(os.name=="nt","POSIX modes are enforced in Linux CI")
    def test_world_readable_config_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/"config.json";file.write_text('{"v":1}');file.chmod(0o644)
            with self.assertRaises(ValueError):read_json(file)

    @unittest.skipIf(os.name=="nt","Symlink creation is a privilege on Windows")
    def test_config_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/"config.json";target.write_text('{"v":1}');target.chmod(0o600)
            link=Path(directory)/"alias.json";link.symlink_to(target)
            with self.assertRaises((ValueError,OSError)):read_json(link)

if __name__=="__main__":
    unittest.main()
