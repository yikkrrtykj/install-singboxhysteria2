"""Default TLS reuse preserves profile isolation, trust refresh, and slot deadlines."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import ssl
import sys
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "monitor-v2"), str(ROOT / "tests/remote-production")]

from remote_probe import direct_probe as dp
from remote_probe.production_runtime import ProductionAgent, _DirectTLSContext
from test_foundations import FixtureBase
from test_iplark_egress import ProviderTests


class EmptyResponse:
    status = 204

    def read(self, *_):
        return b""


class FakeConnection:
    def __init__(self, *args, **kwargs):
        pass

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return EmptyResponse()

    def close(self):
        pass


class TLSReuseTests(unittest.TestCase):
    def test_two_production_slots_use_one_default_context(self):
        config = types.SimpleNamespace(
            spool_dir="unused", https_host="www.gstatic.com", egress_host="iplark.com"
        )
        agent = ProductionAgent(config, spool=object(), mihomo=object())
        contexts = []

        class RecordingConnection(FakeConnection):
            def __init__(self, host, port, timeout, context):
                self.host = host
                contexts.append(context)
                if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                    raise AssertionError("TLS validation weakened")

            def getresponse(self):
                if self.host == "iplark.com":
                    return types.SimpleNamespace(status=200, read=lambda *_: b"8.8.8.8")
                return EmptyResponse()

        with (
            patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as factory,
            patch.object(dp.http.client, "HTTPSConnection", RecordingConnection),
        ):
            for _ in range(3):
                self.assertEqual(agent._probe_https()["status"], "ok")
                self.assertEqual(agent._probe_egress()["status"], "ok")
            self.assertEqual(factory.call_count, 1)

        self.assertEqual(len(contexts), 6)
        self.assertEqual(len({id(context) for context in contexts}), 1)
        other = ProductionAgent(config, spool=object(), mihomo=object())
        self.assertIsNot(other._direct_tls, agent._direct_tls)


class CachePolicyTests(unittest.TestCase):
    def test_expiry_reloads_trust_without_mutating_used_context(self):
        clock = [10.0]
        cache = _DirectTLSContext(lambda: clock[0])
        first = ssl.create_default_context()
        second = ssl.create_default_context()
        with patch.object(ssl, "create_default_context", side_effect=[first, second]) as create:
            self.assertIs(cache(), first)
            clock[0] = 69.99
            self.assertIs(cache(), first)
            clock[0] = 70.0
            self.assertIs(cache(), second)
            self.assertEqual(create.call_count, 2)

        for context in (first, second):
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    def test_failed_refresh_refuses_stale_trust_and_can_retry(self):
        clock = [0.0]
        cache = _DirectTLSContext(lambda: clock[0])
        first = ssl.create_default_context()
        second = ssl.create_default_context()
        with patch.object(
            ssl, "create_default_context", side_effect=[first, OSError("fixture"), second]
        ):
            self.assertIs(cache(), first)
            clock[0] = 60.0
            with self.assertRaises(OSError):
                cache()
            self.assertIs(cache(), second)

    def test_concurrent_requests_initialize_once(self):
        cache = _DirectTLSContext()
        started = threading.Event()
        release = threading.Event()
        actual = ssl.create_default_context()

        def create():
            started.set()
            if not release.wait(2):
                raise TimeoutError("fixture timeout")
            return actual

        with (
            patch.object(ssl, "create_default_context", side_effect=create) as factory,
            ThreadPoolExecutor(max_workers=8) as pool,
        ):
            futures = [pool.submit(cache) for _ in range(8)]
            try:
                self.assertTrue(started.wait(2))
            finally:
                release.set()
            values = [future.result(timeout=3) for future in futures]
            self.assertEqual(factory.call_count, 1)
            self.assertTrue(all(context is actual for context in values))

    def test_context_creation_remains_inside_absolute_slot_budget(self):
        cache = _DirectTLSContext()
        done = threading.Event()
        release = threading.Event()
        actual = ssl.create_default_context()

        def slow():
            if not release.wait(2):
                raise TimeoutError("fixture timeout")
            done.set()
            return actual

        with (
            patch.object(ssl, "create_default_context", side_effect=slow),
            patch.object(dp.http.client, "HTTPSConnection", FakeConnection),
        ):
            try:
                result = dp.probe_https("fixture", budget=0.03, expected_status=204, context=cache)
                self.assertEqual(result["error_code"], "timeout")
                self.assertFalse(done.is_set())
            finally:
                release.set()
                self.assertTrue(done.wait(1))


class ActualTLSCacheTests(FixtureBase):
    target = ProviderTests.target

    def test_cached_context_keeps_untrusted_and_hostname_refusal(self):
        server, trusted, seen = self.target()
        cache = _DirectTLSContext()
        with patch.object(ssl, "create_default_context", return_value=trusted):
            for _ in range(2):
                result = dp.probe_egress(
                    "127.0.0.1", port=server.server_port, context=cache, strict_ip=True
                )
                self.assertEqual(result["status"], "ok")
        self.assertEqual(len(seen), 2)

        # A different profile's default trust never receives the fixture root.
        other = _DirectTLSContext()
        result = dp.probe_egress(
            "127.0.0.1", port=server.server_port, context=other, strict_ip=True
        )
        self.assertEqual(result["error_code"], "tls_failed")
        self.assertEqual(len(seen), 2)

        # The cached trusted context still checks each connection's hostname.
        result = dp.probe_egress(
            "localhost", port=server.server_port, context=cache, strict_ip=True
        )
        self.assertEqual(result["error_code"], "tls_failed")
        self.assertEqual(len(seen), 2)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for test_class in (TLSReuseTests, CachePolicyTests, ActualTLSCacheTests):
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
