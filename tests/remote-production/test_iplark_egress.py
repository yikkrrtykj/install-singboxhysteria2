"""Real TLS IPLark adapter, strict IP parsing and scoped local display checks."""
import base64
import http.server
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'monitor-v2'), str(ROOT/'windows'), str(ROOT/'tests/remote-production'), str(ROOT/'tests/remote-server')]
from remote_probe import direct_probe as dp
from remote_probe.agent import RemoteProbeAgent
from remote_probe.production_runtime import ProductionAgent
from remote_probe.profiles import canonical
from p6installer.status import latest_sample, snapshot
from test_foundations import FixtureBase
from test_windows_gui import SnapshotTests
from server_groups import _sample


class ProviderTests(FixtureBase):
    def target(self, body=b'8.8.8.8\n', status=200, wait=0):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Accept')))
                time.sleep(wait)
                try:
                    self.send_response(status)
                    if status == 302:
                        self.send_header('Location', 'https://must-not-follow.invalid/')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, ssl.SSLError):
                    pass
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.certs.root/'server.pem'), str(self.certs.root/'server.key'))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        trusted = ssl.create_default_context(cadata=self.certs.pem())
        return server, trusted, seen

    def agent(self, cls=ProductionAgent, host='api.ipify.org'):
        agent = object.__new__(cls)
        agent.config = types.SimpleNamespace(egress_host=host, spool_dir=self.temp.name)
        agent._baseline = None
        agent._pending_baseline = None
        agent.baseline_write_failures = 0
        return agent

    def request(self, agent, body=b'8.8.8.8\n', status=200, trusted=True, wait=0, budget=5):
        server, context, seen = self.target(body, status, wait)
        original = dp.probe_egress
        calls = []
        def local(host, **kwargs):
            calls.append((host, kwargs.copy()))
            kwargs.pop('context', None)  # This fixture explicitly supplies local TLS trust.
            return original('127.0.0.1', port=server.server_port, budget=budget,
                            context=context if trusted else ssl.create_default_context(), **kwargs)
        with patch('remote_probe.production_runtime.dp.probe_egress', side_effect=local):
            result = agent._probe_egress()
        return result, seen, calls

    def test_legacy_profile_uses_iplark_plain_ip_real_tls(self):
        value, seen, calls = self.request(self.agent())
        self.assertEqual(value['status'], 'ok')
        self.assertEqual(value['ip'], '8.8.8.8')
        self.assertEqual(value['change'], 'unknown')
        self.assertEqual(seen, [('/ipapi/public/ip', 'text/plain')])
        self.assertEqual(calls[0][0], 'iplark.com')
        self.assertTrue(calls[0][1]['strict_ip'])

    def test_new_profile_uses_same_target_and_canonical_ipv6(self):
        value, seen, _ = self.request(self.agent(host='iplark.com'), b'2001:4860:4860:0000:0000:0000:0000:8888\n')
        self.assertEqual(value['ip'], '2001:4860:4860::8888')
        self.assertEqual(seen[0][0], '/ipapi/public/ip')

    def test_html_json_and_multiple_tokens_are_not_scraped(self):
        for raw in (b'<p>8.8.8.8</p>', b'{"ip":"8.8.8.8"}', b'8.8.8.8 1.1.1.1', b'ip=8.8.8.8', b'8.8.8.8,1.1.1.1', b'\xff'):
            with self.subTest(raw=raw):
                value, _, _ = self.request(self.agent(), raw)
                self.assertEqual(value['error_code'], 'parse_failed')
                self.assertIsNone(value['ip'])

    def test_private_reserved_multicast_and_fake_ip_refused(self):
        for raw in (b'127.0.0.1', b'192.168.0.1', b'198.18.0.1', b'224.0.0.1', b'2001:db8::1'):
            with self.subTest(raw=raw):
                value, _, _ = self.request(self.agent(), raw)
                self.assertEqual(value['error_code'], 'parse_failed')

    def test_oversized_body_with_valid_ip_prefix_refused(self):
        value, _, _ = self.request(self.agent(), b'8.8.8.8'+b' '*4096)
        self.assertEqual(value['error_code'], 'bad_response')
        self.assertIsNone(value['ip'])

    def test_redirect_and_non200_fail_without_following(self):
        for status in (204, 302, 403, 429, 500):
            with self.subTest(status=status):
                value, seen, _ = self.request(self.agent(), status=status)
                self.assertEqual(value['error_code'], 'bad_response')
                self.assertEqual(len(seen), 1)

    def test_normal_certificate_validation_required(self):
        value, seen, _ = self.request(self.agent(), trusted=False)
        self.assertEqual(value['error_code'], 'tls_failed')
        self.assertEqual(seen, [])

    def test_real_slow_response_is_bounded(self):
        start = time.monotonic()
        value, _, _ = self.request(self.agent(), wait=0.25, budget=0.06)
        self.assertEqual(value['error_code'], 'timeout')
        self.assertLess(time.monotonic()-start, 1.0)

    def test_base_and_other_reviewed_profiles_keep_prior_parser_path(self):
        for agent in (self.agent(RemoteProbeAgent), self.agent(host='other-reviewed.example')):
            with self.subTest(cls=type(agent).__name__):
                value, seen, calls = self.request(agent, b'8.8.8.8 legacy-text')
                self.assertEqual(value['ip'], '8.8.8.8')
                self.assertEqual(seen, [('/', 'text/plain')])
                self.assertNotIn('strict_ip', calls[0][1])
                self.assertEqual(calls[0][0], agent.config.egress_host)

    def test_provider_baseline_is_separate_and_survives_restart(self):
        old = Path(self.temp.name)/'egress.baseline.json'
        old.write_bytes(b'{"v":1,"ip":"1.1.1.1"}')
        old.chmod(0o600)
        agent = self.agent()
        agent._read_baseline()
        self.assertIsNone(agent._baseline)
        value, _, _ = self.request(agent)
        self.assertEqual(value['change'], 'unknown')
        agent._pending_baseline = value['ip']
        agent._commit_baseline()
        self.assertEqual(agent._baseline, '8.8.8.8')
        self.assertEqual(old.read_bytes(), b'{"v":1,"ip":"1.1.1.1"}')
        resumed = self.agent(host='iplark.com')
        resumed._read_baseline()
        self.assertEqual(resumed._baseline, '8.8.8.8')
        value, _, _ = self.request(resumed)
        self.assertEqual(value['change'], 'unchanged')
        value, _, _ = self.request(resumed, b'1.1.1.1')
        self.assertEqual(value['change'], 'changed')

    def test_failed_commit_does_not_advance_baseline(self):
        agent = self.agent()
        agent._pending_baseline = '8.8.8.8'
        with patch.object(agent, '_write_baseline', side_effect=OSError('fixture disk failure')):
            agent._commit_baseline()
        self.assertIsNone(agent._baseline)
        self.assertEqual(agent.baseline_write_failures, 1)
        self.assertFalse(Path(agent._baseline_path()).exists())

    def test_other_host_keeps_existing_baseline_filename(self):
        old = Path(self.temp.name)/'egress.baseline.json'
        old.write_bytes(b'{"v":1,"ip":"1.1.1.1"}')
        old.chmod(0o600)
        agent = self.agent(host='other-reviewed.example')
        self.assertEqual(agent._baseline_path(), str(old))
        agent._read_baseline()
        self.assertEqual(agent._baseline, '1.1.1.1')


class CurrentIPSnapshotTests(SnapshotTests):
    def encode_record(self, seq=1, failed=False):
        sample = _sample(seq, probe='device-one', epoch=1000+seq)
        if failed:
            sample['egress'] = {'status':'failed', 'latency_ms':None, 'error_code':'connect_failed', 'ip':None, 'change':'unknown'}
        return {'probe_id':sample['probe_id'], 'run':sample['run'], 'seq':seq,
                'body_b64':base64.b64encode(canonical(sample)).decode()}

    def test_success_ip_is_visible_without_body_or_secret(self):
        self.vault._write(str(self.path), 'spool.jsonl', canonical(self.encode_record())+b'\n')
        before = self.tree()
        result = snapshot(self.manager, self.reader)
        value = result['profiles'][0]['sample']
        self.assertEqual(value['egress_ip'], '8.8.8.8')
        self.assertEqual(self.tree(), before)
        self.assertNotIn('body_b64', value)
        self.assertNotIn('LOCAL-CANARY', json.dumps(result))
        self.assertNotIn('mihomo.key', self.read_names)

    def test_failure_clears_previous_success_ip(self):
        raw = canonical(self.encode_record())+b'\n'+canonical(self.encode_record(2,True))+b'\n'
        value = latest_sample(raw, 'device-one')
        self.assertEqual(value['seq'], 2)
        self.assertEqual(value['egress_error_code'], 'connect_failed')
        self.assertIsNone(value['egress_ip'])


def load_tests(loader, _tests, _pattern):
    # Reuse fixture helpers without duplicating every inherited GUI test/count.
    suite = loader.loadTestsFromTestCase(ProviderTests)
    for name in ('test_success_ip_is_visible_without_body_or_secret', 'test_failure_clears_previous_success_ip'):
        suite.addTest(CurrentIPSnapshotTests(name))
    return suite


if __name__ == '__main__':
    unittest.main(verbosity=2)
