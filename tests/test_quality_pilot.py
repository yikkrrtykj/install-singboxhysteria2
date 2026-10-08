"""Isolated pilot contracts: byte forwarding, no live-core writes, failure cleanup."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover import pilot
from quality_failover.relay import TCPWire, UDPWire


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = load(ROOT / "tests/test_quality_failover.py", "pilot_fixture")


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            while True:
                body = self.request.recv(8192)
                if not body:
                    return
                self.request.sendall(body)
        except OSError:
            return


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        body, sock = self.request
        sock.sendto(body, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class RelayTests(unittest.TestCase):
    def test_tcp_bytes_shaping_drop_restore_and_independent_client(self):
        with TCPServer(("127.0.0.1", 0), EchoTCP) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            wire = TCPWire(server.server_address)
            try:
                wire.fault(rate=1)
                with socket.create_connection(("127.0.0.1", wire.port), timeout=2) as client:
                    body = os.urandom(65536)
                    started = time.monotonic()
                    client.sendall(body)
                    answer = bytearray()
                    while len(answer) < len(body):
                        answer.extend(client.recv(len(body) - len(answer)))
                    self.assertEqual(answer, body)
                    self.assertGreater(time.monotonic() - started, .45)
                wire.fault(up=False)
                with socket.create_connection(("127.0.0.1", wire.port), timeout=2) as client:
                    self.assertEqual(client.recv(1), b"")
                with socket.create_connection(server.server_address, timeout=2) as direct:
                    direct.sendall(b"not-the-pilot")
                    self.assertEqual(direct.recv(32), b"not-the-pilot")
                wire.fault()
                with socket.create_connection(("127.0.0.1", wire.port), timeout=2) as client:
                    client.sendall(b"restored")
                    self.assertEqual(client.recv(32), b"restored")
            finally:
                wire.close()
                server.shutdown()
            self.assertFalse(any(item.is_alive() for item in wire.threads))
            self.assertFalse(wire.sockets)

    def test_udp_preserves_peers_and_fault_is_local(self):
        with socketserver.UDPServer(("127.0.0.1", 0), EchoUDP) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            wire = UDPWire(server.server_address)
            try:
                for index in range(3):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(1)
                        body = bytes([index]) * 2000
                        client.sendto(body, ("127.0.0.1", wire.port))
                        answer, source = client.recvfrom(3000)
                        self.assertEqual(answer, body)
                        self.assertEqual(source, ("127.0.0.1", wire.port))
                wire.fault(up=False)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(.2)
                    client.sendto(b"drop", ("127.0.0.1", wire.port))
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(32)
                    client.sendto(b"direct", server.server_address)
                    self.assertEqual(client.recvfrom(32)[0], b"direct")
                    wire.fault()
                    client.settimeout(1)
                    client.sendto(b"restore", ("127.0.0.1", wire.port))
                    self.assertEqual(client.recvfrom(32)[0], b"restore")
            finally:
                wire.close()
                server.shutdown()
            self.assertFalse(wire.sockets)

    def test_hopping_map_uses_equally_sized_loopback_range(self):
        wire = UDPWire(("127.0.0.1", 443), "40000-40100")
        try:
            self.assertEqual(len(wire.listeners), 102)
            self.assertEqual(wire.port_range[1] - wire.port_range[0], 100)
            for sock, remote in wire.listeners.items():
                self.assertEqual(sock.getsockname()[0], "127.0.0.1")
                if 40000 <= remote <= 40100:
                    self.assertEqual(sock.getsockname()[1] - wire.port_range[0], remote - 40000)
            self.assertEqual(len(wire.threads), 1)
        finally:
            wire.close()

    def test_wide_hopping_and_invalid_faults_refused(self):
        for value in ("0-1", "60000-59999", "1-1000", "1-2-3"):
            with self.assertRaises(ValueError):
                UDPWire(("127.0.0.1", 443), value)
        wire = UDPWire(("127.0.0.1", 443))
        try:
            with self.assertRaises(ValueError):
                wire.fault(rate=1)
            with self.assertRaises(ValueError):
                wire.fault(up="false")
        finally:
            wire.close()


class PreparationTests(unittest.TestCase):
    def test_receiver_init_private_no_overwrite_no_secret_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "receiver"
            def openssl(argv, **kwargs):
                Path(argv[argv.index("-out") + 1]).write_bytes(b"fake-public-ca")
                Path(argv[argv.index("-keyout") + 1]).write_bytes(b"fake-private-key")
            with patch.object(pilot.subprocess, "run", side_effect=openssl) as command:
                result = pilot.receiver_init(root, "203.0.113.1", 8448)
            server = json.loads((root / "receiver.json").read_bytes())
            info = json.loads((root / "receiver-info.json").read_bytes())
            self.assertEqual(server["token"], info["token"])
            self.assertEqual(info["certificate_sha256"], hashlib.sha256(b"fake-public-ca").hexdigest())
            self.assertNotIn(server["token"], json.dumps(result))
            self.assertNotIn("private_key", info)
            self.assertIn("subjectAltName=IP:203.0.113.1", command.call_args.args[0])
            self.assertFalse(result["started"])
            if os.name != "nt":
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
                self.assertEqual((root / "receiver-key.pem").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                pilot.receiver_init(root, "203.0.113.1", 8448)

    def test_init_bad_input_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "receiver"
            for address, port in (("example.com", 8448), ("203.0.113.1", 22), ("203.0.113.1", True)):
                with self.assertRaises(ValueError):
                    pilot.receiver_init(root, address, port)
            self.assertFalse(root.exists())

    def test_certificate_binding_and_closed_connection_info(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info, ca = root / "info.json", root / "ca.pem"
            ca.write_bytes(b"certificate")
            value = {"v": 1, "token": "a" * 32, "endpoint": "https://203.0.113.1:8448",
                     "certificate_sha256": hashlib.sha256(ca.read_bytes()).hexdigest()}
            pilot.private_file(info, json.dumps(value).encode())
            with patch.object(pilot.ssl, "create_default_context"):
                self.assertEqual(pilot.receiver_info(info, ca), value)
            ca.write_bytes(b"different")
            with self.assertRaises(ValueError):
                pilot.receiver_info(info, ca)
            value["private_key"] = "not-allowed"
            info.write_bytes(json.dumps(value).encode())
            with self.assertRaises(ValueError):
                pilot.receiver_info(info, ca)

    def test_binary_digest_required_and_streamed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core"
            path.write_bytes(os.urandom(180000))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(pilot.pinned_binary(path, digest), path.resolve())
            with self.assertRaises(ValueError):
                pilot.pinned_binary(path, "0" * 64)

    def test_profile_remaps_only_pilot_transport_and_has_no_system_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "event-mihomo.yaml"
            fixtures.export(source, hopping=True)
            before = source.read_bytes()
            cfg = fixtures.configuration()
            prepared = root / "prepared.yaml"
            fixtures.CLI.prepare("event", str(source), None, str(prepared), cfg)
            profile = fixtures.MERGE.parse_export(source, lambda: ValueError("test"))
            wires = [SimpleNamespace(port=22001), SimpleNamespace(port=22002, port_range=(23000, 23100))]
            text = pilot.isolated_profile(profile, prepared.read_text(encoding="utf-8"), wires, 24001, 24002, "a" * 32)
            self.assertIn("tun:\n  enable: false", text)
            self.assertIn("dns:\n  enable: false", text)
            self.assertNotIn("auto-route", text)
            self.assertNotIn('listen: "0.0.0.0:53"', text)
            self.assertNotIn("GEOIP", text)
            self.assertIn("    servername: www.example.com", text)
            self.assertIn("    sni: www.example.com", text)
            self.assertIn("    ports: 23000-23100", text)
            self.assertIn("    hop-interval: 30", text)
            self.assertEqual(source.read_bytes(), before)

    def test_exclusive_result_file_does_not_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt"
            pilot.private_file(path, b"original")
            with self.assertRaises(FileExistsError):
                pilot.private_file(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")


class CleanupTests(unittest.TestCase):
    def run_case(self, root, failure):
        source, binary, result = root / "event-mihomo.yaml", root / "fake-core", root / "result.json"
        fixtures.export(source)
        before = source.read_bytes()
        binary.write_bytes(b"fake-binary-never-executed")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        info = {"endpoint": "https://127.0.0.1:8448", "token": "a" * 32}
        process = Mock()
        process.poll.return_value = None
        owned_root = []
        def spawn(argv, **kwargs):
            owned_root.append(Path(argv[argv.index("-d") + 1]))
            return process
        def terminate():
            self.assertTrue(owned_root[0].is_dir(), "core files must exist until owned core stops")
        process.terminate.side_effect = terminate
        runner = Mock()
        runner.controller.proxies.return_value = {}
        error = pilot.Cancelled() if failure == "cancel" else ValueError("test-failure")
        if failure == "close":
            error = None
            runner.close.side_effect = ValueError("restore_ownership")
        with patch.object(pilot, "receiver_info", return_value=info), \
             patch.object(pilot.ssl, "create_default_context"), \
             patch.object(pilot.subprocess, "run"), \
             patch.object(pilot.subprocess, "Popen", side_effect=spawn), \
             patch.object(pilot, "Runner", return_value=runner), \
             patch.object(pilot.Suite, "execute", side_effect=error, return_value=[]):
            answer = pilot.run_pilot(str(source), "event", "unused-info", "unused-ca", str(binary), digest, str(result))
        process.terminate.assert_called_once()
        self.assertFalse(owned_root[0].exists())
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse(answer["passed"])
        self.assertTrue(answer["cleanup_complete"])
        self.assertEqual(answer["cancelled"], failure == "cancel")
        raw = result.read_text(encoding="utf-8")
        self.assertNotIn(info["token"], raw)
        self.assertNotIn("11111111-1111-4111-8111-111111111111", raw)
        self.assertNotIn(info["endpoint"], raw)

    def test_cancel_stops_exact_owned_core_before_removing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_case(Path(directory), "cancel")

    def test_failure_stops_exact_owned_core_and_never_reports_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_case(Path(directory), "failure")

    def test_exit_failure_after_successful_stages_cannot_report_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_case(Path(directory), "close")

    def test_rounds_require_real_confirmation_spacing_and_fail_closed(self):
        runner = Mock()
        runner.cycle.return_value = {"action": "observe", "paths": {}}
        suite = pilot.Suite(runner, [], 0)
        suite.pause = Mock()
        with self.assertRaises(ValueError):
            suite.rounds("recovery", 3, lambda result: False)
        self.assertEqual(runner.cycle.call_count, 3)
        self.assertEqual(suite.pause.call_args_list, [unittest.mock.call(30), unittest.mock.call(30)])
        self.assertFalse(suite.records[-1]["passed"])

    def test_cancel_interrupts_wait(self):
        event = threading.Event()
        event.set()
        suite = pilot.Suite(Mock(), [], 0, cancel=event)
        with self.assertRaises(pilot.Cancelled):
            suite.pause(30)

    def test_route_requires_unique_node_and_exact_destination(self):
        controller = Mock()
        row = {"metadata": {"sourceIP": "127.0.0.1", "sourcePort": "12345",
                            "destinationIP": "203.0.113.1", "destinationPort": "8448"},
               "chains": ["Reality", "质量自动选择"]}
        controller.request.return_value = {"connections": [row]}
        self.assertTrue(pilot.ordinary_route(controller, 12345, "203.0.113.1", 8448, "Reality"))
        self.assertFalse(pilot.ordinary_route(controller, 12345, "203.0.113.1", 8448, "Hysteria2"))
        controller.request.return_value = {"connections": [row, row]}
        self.assertFalse(pilot.ordinary_route(controller, 12345, "203.0.113.1", 8448, "Reality"))

    def test_initial_alive_without_probe_history_is_not_a_baseline(self):
        runner = Mock()
        runner.engine.policies = {"Reality": SimpleNamespace(freshness_seconds=90)}
        runner.controller.proxies.return_value = {"Reality": {"alive": True, "history": []}}
        suite = pilot.Suite(runner, [], 0)
        with patch.object(pilot.time, "monotonic", side_effect=(0, 0, 21)), \
             patch.object(suite, "pause"):
            with self.assertRaises(ValueError):
                suite.await_native("Reality", True)

    def test_diagnostics_never_reflect_unknown_exception_text(self):
        self.assertEqual(pilot.error_code(ValueError("binary_digest")), "binary_digest")
        self.assertEqual(pilot.error_code(ValueError("Bearer secret-in-error")), "preparation_or_acceptance_incomplete")
        self.assertEqual(pilot.error_code(OSError("private/path/or/token")), "preparation_or_acceptance_incomplete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
