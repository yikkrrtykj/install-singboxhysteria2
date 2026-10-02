"""Actual TLS/Windows storage and bounded-runtime checks; no verdict constants."""
from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "monitor-v2"))
from remote_probe.agent import ConfigError
from remote_probe.delivery import UploadConfigError, sign_record
from remote_probe.payload import encode_sample
from remote_probe.pinned_transport import PinnedHttpsIngest
from remote_probe.profiles import ProfileVault, PosixSecurity
from remote_probe.production_runtime import ProductionRuntime, make_agent
from remote_probe.windows_security import WindowsSecurity, StorageSecurityError
from remote_probe.spool import Spool, SpoolError


def fixture_policy():
    if os.name == "nt":
        # Explicitly scoped fixture SID; production has no such CLI option.
        result = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
        sid = re.search(r"S-1-[0-9-]+", result).group()
        return WindowsSecurity(fixture_sid=sid)
    return PosixSecurity()


class Certificates:
    def __init__(self, root):
        openssl = shutil.which("openssl")
        if not openssl and os.name == "nt":
            openssl = r"C:\Program Files\Git\usr\bin\openssl.exe"
        if not openssl or not pathlib.Path(openssl).exists():
            raise RuntimeError("openssl fixture generator unavailable")
        self.openssl = openssl
        self.root = pathlib.Path(root)
        self.new("server")
        self.new("impostor")
        self.new("wrong-ip", san="IP:127.0.0.2")
        self.new("expired", days="-1")

    def call(self, *args):
        result = subprocess.run([self.openssl, *args], capture_output=True,
                                  creationflags=0x08000000 if os.name == "nt" else 0)
        if result.returncode:
            raise RuntimeError("certificate fixture generation failed")

    def new(self, name, san="IP:127.0.0.1", days="1"):
        key = str(self.root / (name + ".key"))
        csr = str(self.root / (name + ".csr"))
        cert = str(self.root / (name + ".pem"))
        ext = self.root / (name + ".ext")
        ext.write_text("subjectAltName=" + san + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        self.call("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=P6-fixture",
                  "-keyout", key, "-out", csr)
        self.call("x509", "-req", "-in", csr, "-signkey", key, "-days", "1",
                  "-extfile", str(ext), "-out", cert)
        if days == "-1":
            index = self.root / "index"
            serial = self.root / "serial"
            index.write_text("")
            serial.write_text("01\n")
            config = self.root / "ca.conf"
            def quoted(path):
                return '"' + pathlib.Path(path).as_posix() + '"'
            config.write_text("[ca]\ndefault_ca=local\n[local]\n" +
                "database=" + quoted(index) + "\nserial=" + quoted(serial) + "\n" +
                "new_certs_dir=" + quoted(self.root) + "\ncertificate=" + quoted(cert) + "\n" +
                "private_key=" + quoted(key) + "\ndefault_md=sha256\npolicy=policy\n" +
                "[policy]\ncommonName=supplied\n[ext]\nsubjectAltName=" + san + "\n")
            output = self.root / "past.pem"
            self.call("ca", "-batch", "-selfsign", "-notext", "-config", str(config),
                      "-extensions", "ext", "-in", csr, "-out", str(output),
                      "-startdate", "20000101000000Z", "-enddate", "20000102000000Z")
            output.replace(cert)

    def pem(self, name="server"):
        return (self.root / (name + ".pem")).read_text()

    def pin(self, name="server"):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.pem(name))).hexdigest()


class Capture(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.seen.append((self.request_version, self.path, dict(self.headers), body))
        payload = b'{"v":1,"result":"accepted"}'
        self.send_response(self.server.response_status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class FixtureBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_temp = tempfile.TemporaryDirectory(prefix="p6b2-certs-")
        cls.certs = Certificates(cls.cert_temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.cert_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="p6b2-tests-")
        self.addCleanup(self.temp.cleanup)

    def server(self, certificate="server", handler=Capture, port=0):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        server.seen = []
        server.response_status = 200
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.certs.root / (certificate + ".pem")),
                            str(self.certs.root / (certificate + ".key")))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(cleanup)
        return server

    def transport(self, server, certificate="server", timeout=2):
        return PinnedHttpsIngest(f"https://127.0.0.1:{server.server_port}/api/v1/remote-probes/ingest",
                                  self.certs.pem(certificate), self.certs.pin(certificate), timeout)

    def manifest(self, probe="device-one", server="a" * 32, port=38443):
        return {"v": 1, "server_id": server, "probe_id": probe,
                "ingest_url": f"https://127.0.0.1:{port}/api/v1/remote-probes/ingest",
                "certificate_sha256": self.certs.pin(),
                "agent": {"mihomo_url": "http://127.0.0.1:9090",
                          "reality_node": "Reality", "hy2_node": "Hysteria2",
                          "dns_host": "www.cloudflare.com", "https_host": "www.cloudflare.com",
                          "egress_host": "www.cloudflare.com", "vps_host": "127.0.0.1"}}

    def vault(self):
        return ProfileVault(os.path.join(self.temp.name, "vault"), fixture_policy()).open()


class TransportTests(FixtureBase):
    def test_valid_wire_bytes_and_signature_headers(self):
        server = self.server()
        body = b'{"x":7}'
        headers = sign_record(b"k" * 32, "device-one", "a" * 32, 3, body, time.time())
        status, _ = self.transport(server).post(body, headers)
        self.assertEqual(status, 200)
        self.assertEqual(len(server.seen), 1)
        version, path, received, captured = server.seen[0]
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(path, "/api/v1/remote-probes/ingest")
        self.assertEqual(body, captured)
        self.assertEqual(received["Content-Length"], str(len(body)))
        self.assertNotIn("Transfer-Encoding", received)
        for key, value in headers.items():
            self.assertEqual(received[key], value)

    def test_impostor_gets_no_http_headers_or_body(self):
        server = self.server("impostor")
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.transport(server).post(b"{}", {"X-Remote-Probe-Signature": "private"})
        self.assertEqual(server.seen, [])

    def test_leaf_pin_checked_even_if_other_cert_chain_trusted(self):
        server = self.server("impostor")
        transport = self.transport(server)
        transport.context.load_verify_locations(cadata=self.certs.pem("impostor"))
        with self.assertRaises(ssl.SSLCertVerificationError):
            transport.post(b"{}", {"X-Remote-Probe-Signature": "private"})
        self.assertEqual(server.seen, [])

    def test_expired_cert_gets_no_http(self):
        server = self.server("expired")
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.transport(server, "expired").post(b"{}", {})
        self.assertEqual(server.seen, [])

    def test_ip_san_mismatch_gets_no_http(self):
        server = self.server("wrong-ip")
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.transport(server, "wrong-ip").post(b"{}", {})
        self.assertEqual(server.seen, [])

    def test_wrong_manifest_pin_refused_before_connect(self):
        with self.assertRaises(UploadConfigError):
            PinnedHttpsIngest("https://127.0.0.1/api/v1/remote-probes/ingest",
                              self.certs.pem(), "0" * 64)

    def test_redirect_is_not_followed(self):
        server = self.server()
        server.response_status = 302
        status, _ = self.transport(server).post(b"{}", {})
        self.assertEqual(status, 302)
        self.assertEqual(len(server.seen), 1)

    def test_framing_cannot_be_overridden(self):
        server = self.server()
        for headers in ({"Transfer-Encoding": "chunked"}, {"content-length": "9"}, {"Host": "other"}):
            with self.subTest(headers=headers), self.assertRaises(UploadConfigError):
                self.transport(server).post(b"{}", headers)
        self.assertEqual(server.seen, [])

    def test_no_system_trust_or_keylog_env(self):
        server = self.server()
        old = os.environ.get("SSLKEYLOGFILE")
        keylog = os.path.join(self.temp.name, "must-not-exist.log")
        os.environ["SSLKEYLOGFILE"] = keylog
        try:
            transport = self.transport(server)
            self.assertIsNone(transport.context.keylog_filename)
            transport.post(b"{}", {})
            self.assertFalse(os.path.exists(keylog))
        finally:
            if old is None:
                os.environ.pop("SSLKEYLOGFILE", None)
            else:
                os.environ["SSLKEYLOGFILE"] = old

    def test_slow_header_total_deadline(self):
        class Drip(Capture):
            def do_POST(self):
                try:
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n":
                        self.connection.sendall(bytes([byte]))
                        time.sleep(.05)
                except OSError:
                    pass
        server = self.server(handler=Drip)
        start = time.monotonic()
        with self.assertRaises((OSError, http.client.HTTPException)):
            self.transport(server, timeout=.2).post(b"{}", {})
        self.assertLess(time.monotonic() - start, 1.5)

    def test_slow_close_delimited_body_total_deadline(self):
        class Drip(Capture):
            def do_POST(self):
                try:
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                    for _ in range(60):
                        self.connection.sendall(b"x")
                        time.sleep(.05)
                except OSError:
                    pass
        server = self.server(handler=Drip)
        start = time.monotonic()
        try:
            self.transport(server, timeout=.2).post(b"{}", {})
        except (OSError, http.client.HTTPException):
            pass
        self.assertLess(time.monotonic() - start, 1.5)


class ProfileTests(FixtureBase):
    def test_idempotent_import_retains_key_and_spool(self):
        vault = self.vault()
        manifest = self.manifest()
        key, created = vault.import_profile(manifest, b"k" * 32, self.certs.pem())
        self.assertTrue(created)
        spool = os.path.join(vault._path(key), "spool", "sentinel")
        vault._write(os.path.dirname(spool), "sentinel", b"durable")
        again, created = vault.import_profile(manifest, b"k" * 32, self.certs.pem())
        self.assertEqual(key, again)
        self.assertFalse(created)
        self.assertEqual(vault.security.read(spool, 8), b"durable")
        self.assertEqual(vault.read_secret(key), b"k" * 32)

    def test_changed_secret_and_endpoint_refused(self):
        vault = self.vault()
        manifest = self.manifest()
        key, _ = vault.import_profile(manifest, b"k" * 32, self.certs.pem())
        with self.assertRaises(ConfigError):
            vault.import_profile(manifest, b"x" * 32, self.certs.pem())
        changed = copy.deepcopy(manifest)
        changed["ingest_url"] = changed["ingest_url"].replace("38443", "38444")
        with self.assertRaises(ConfigError):
            vault.import_profile(changed, b"k" * 32, self.certs.pem())
        self.assertEqual(vault.load(key), manifest)

    def test_same_probe_two_servers_isolated_and_purge_only_one(self):
        vault = self.vault()
        first, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        second, _ = vault.import_profile(self.manifest(server="b" * 32), b"x" * 32, self.certs.pem())
        self.assertNotEqual(first, second)
        self.assertNotEqual(vault.agent_config(first, vault.load(first)).spool_dir,
                            vault.agent_config(second, vault.load(second)).spool_dir)
        vault.set_enabled(first, False)
        vault.purge(first)
        self.assertEqual(vault.keys(), [second])
        self.assertEqual(vault.read_secret(second), b"x" * 32)

    def test_secret_not_in_manifest(self):
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        self.assertNotIn((b"k" * 32).hex(), json.dumps(vault.load(key)))

    def test_paused_purge_required_and_active_lock_refused(self):
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        with self.assertRaises(ConfigError):
            vault.purge(key)
        spool = Spool(os.path.join(vault._path(key), "spool")).open()
        vault.set_enabled(key, False)
        try:
            with self.assertRaises(SpoolError):
                vault.purge(key)
        finally:
            spool.close()
        vault.purge(key)
        self.assertEqual(vault.keys(), [])

    def test_max_eight_profiles(self):
        vault = self.vault()
        for index in range(8):
            vault.import_profile(self.manifest(probe=f"device-{index}"), bytes([index]) * 32, self.certs.pem())
        with self.assertRaises(ConfigError):
            vault.import_profile(self.manifest(probe="overflow"), b"k" * 32, self.certs.pem())
        self.assertEqual(len(vault.keys()), 8)

    def test_unknown_secret_paths_and_nan_settings_refused(self):
        vault = self.vault()
        for change in ({"ingest_secret_file": "elsewhere"}, {"cadence": float("nan")}, {"mihomo_url": "http://8.8.8.8:9090"}):
            manifest = self.manifest()
            manifest["agent"].update(change)
            with self.subTest(change=change), self.assertRaises((ConfigError, ValueError)):
                vault.import_profile(manifest, b"k" * 32, self.certs.pem())
        self.assertEqual(vault.keys(), [])

    def test_wrong_role_and_other_vps_refused(self):
        vault = self.vault()
        for change in ({"hy2_node": "Reality"}, {"vps_host": "127.0.0.2"}):
            manifest = self.manifest()
            manifest["agent"].update(change)
            with self.subTest(change=change), self.assertRaises(ConfigError):
                vault.import_profile(manifest, b"k" * 32, self.certs.pem())

    def test_real_agent_wires_transport_without_environment_secret(self):
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        old = os.environ.get("MIHOMO_API_SECRET")
        os.environ["MIHOMO_API_SECRET"] = "must-not-inherit"
        try:
            agent = make_agent(vault, key, vault.load(key))
            self.addCleanup(agent.close)
            self.assertIsInstance(agent._poster, PinnedHttpsIngest)
            self.assertEqual(agent.mihomo.secret, "")
            self.assertEqual(agent._ingest_secret, b"k" * 32)
        finally:
            if old is None:
                os.environ.pop("MIHOMO_API_SECRET", None)
            else:
                os.environ["MIHOMO_API_SECRET"] = old


class RuntimeTests(FixtureBase):
    def test_bounded_parallel_cycles_pause_and_exclusive_runtime(self):
        vault = self.vault()
        for index in range(3):
            vault.import_profile(self.manifest(probe=f"device-{index}"), bytes([index]) * 32, self.certs.pem())
        gate = threading.Event()
        running = []
        closed = []
        def factory(_vault, key, _manifest):
            def cycle():
                running.append(key)
                gate.wait(3)
            return types.SimpleNamespace(config=types.SimpleNamespace(cadence=60),
                                         run_cycle=cycle, close=lambda: closed.append(key))
        runtime = ProductionRuntime(vault, factory).open()
        self.addCleanup(runtime.close)
        with self.assertRaises(SpoolError):
            other = ProductionRuntime(vault, factory)
            try:
                other.open()
            finally:
                other.close()
        runtime.tick()
        deadline = time.monotonic() + 2
        while len(running) < 2 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(len(running), 2)
        runtime.tick()
        self.assertEqual(runtime.status()["active_cycles"], 2)
        runtime.pause.set()
        gate.set()
        for future in runtime._futures.values():
            future.result(timeout=3)
        runtime.tick()
        self.assertEqual(runtime.status()["active_cycles"], 0)
        self.assertEqual(len(closed), 2)
        runtime.pause.clear()
        runtime.tick()
        for future in runtime._futures.values():
            future.result(timeout=3)
        self.assertEqual(len(set(running)), 3)

    def test_profile_failure_is_contained(self):
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        def broken(*args):
            raise RuntimeError("secret-that-must-not-appear")
        runtime = ProductionRuntime(vault, broken).open()
        self.addCleanup(runtime.close)
        runtime.tick()
        self.assertEqual(runtime.status()["profiles"][key], "profile_unavailable")
        self.assertNotIn("secret-that", json.dumps(runtime.status()))


class IntegrationTests(FixtureBase):
    def plane(self):
        from web.remote_ingest import RemoteIngest
        from web.remote_registry import REGISTRY_READY
        entry = types.SimpleNamespace(key=b"k" * 32, enabled=True)
        registry = types.SimpleNamespace(health=lambda: (REGISTRY_READY, None),
                     lookup=lambda probe: entry if probe == "device-one" else None)
        plane = RemoteIngest(os.path.join(self.temp.name, "server-state"), registry=registry)
        self.addCleanup(plane.close)
        return plane

    def bridge(self, plane, port=0):
        class Ingest(Capture):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                status, payload, _ = self.server.plane.handle(body, dict(self.headers))
                self.server.seen.append(body)
                encoded = json.dumps(payload).encode("ascii")
                self.send_response(status)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
        server = self.server(handler=Ingest, port=port)
        server.plane = plane
        return server

    def sample(self, seq=1):
        # Same frozen sample constructor as the existing P6B suite, no schema fork.
        sys.path.insert(0, str(ROOT / "tests" / "remote-server"))
        from server_groups import _sample
        return _sample(seq, probe="device-one", epoch=time.time())

    def test_real_tls_hmac_receipts_and_server_restart(self):
        plane = self.plane()
        server = self.bridge(plane)
        sample = self.sample()
        body = encode_sample(sample)
        headers = sign_record(b"k" * 32, sample["probe_id"], sample["run"], 1, body, time.time())
        transport = self.transport(server)
        status, response = transport.post(body, headers)
        self.assertEqual((status, json.loads(response)["result"]), (200, "accepted"))
        status, response = transport.post(body, headers)
        self.assertEqual((status, json.loads(response)["result"]), (200, "duplicate"))
        altered = copy.deepcopy(sample)
        altered["dns"]["latency_ms"] += 1
        changed = encode_sample(altered)
        changed_headers = sign_record(b"k" * 32, sample["probe_id"], sample["run"], 1, changed, time.time())
        status, response = transport.post(changed, changed_headers)
        self.assertEqual((status, json.loads(response)["error"]), (409, "equivocation"))
        plane.store.close()
        plane.store.open()
        status, response = transport.post(body, headers)
        self.assertEqual((status, json.loads(response)["result"]), (200, "duplicate"))

    def test_real_offline_spool_reopen_then_https_replay(self):
        plane = self.plane()
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(port=port), b"k" * 32, self.certs.pem())
        agent = make_agent(vault, key, vault.load(key))
        sample = self.sample()
        body = encode_sample(sample)
        agent.spool.append(sample["probe_id"], sample["run"], 1, body, queued_epoch=sample["sample_epoch"])
        summary = agent.deliver()
        self.assertEqual(summary["retries"], 1)
        self.assertEqual(agent.spool.status()["pending"], 1)
        agent.close()
        server = self.bridge(plane, port)
        agent = make_agent(vault, key, vault.load(key))
        self.addCleanup(agent.close)
        agent.clock = lambda: time.time() + 120
        summary = agent.deliver()
        self.assertEqual(summary["acked"], 1)
        self.assertEqual(agent.spool.status()["pending"], 0)
        self.assertEqual(server.seen, [body])


class WindowsTests(FixtureBase):
    def test_real_dacl_inheritance_and_unsafe_acl_refusal(self):
        vault = self.vault()
        key, _ = vault.import_profile(self.manifest(), b"k" * 32, self.certs.pem())
        path = os.path.join(vault._path(key), "ingest.key")
        self.assertEqual(vault.security.read(path, 128).strip(), (b"k" * 32).hex().encode())
        result = subprocess.run(["icacls", path, "/grant", "*S-1-1-0:(R)"], capture_output=True)
        self.assertEqual(result.returncode, 0)
        with self.assertRaises(StorageSecurityError):
            vault.read_secret(key)

    def test_real_junction_refused(self):
        vault = self.vault()
        target = os.path.join(self.temp.name, "target")
        os.mkdir(target)
        link = os.path.join(vault.root, "junction")
        result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", link, target], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.addCleanup(lambda: os.rmdir(link) if os.path.lexists(link) else None)
        with self.assertRaises(StorageSecurityError):
            vault.security.validate(link, True)

    def test_actual_native_scm_console_refusal(self):
        from remote_probe.service_host import run_service
        with self.assertRaises(OSError) as caught:
            run_service("P6FixtureConsole", lambda: None)
        self.assertEqual(caught.exception.errno, 1063)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (TransportTests, ProfileTests, RuntimeTests, IntegrationTests):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    if os.name == "nt":
        suite.addTests(loader.loadTestsFromTestCase(WindowsTests))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
