"""Real TLS and Windows file-sharing field-repair checks; no live-service control."""
import errno
import http.server
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'windows'))
from remote_probe import direct_probe as dp
from remote_probe.agent import RemoteProbeAgent
from remote_probe.production_runtime import ProductionAgent
from remote_probe.production_storage import ProductionSpool, closed_diagnostics, failure_class
from remote_probe.spool import Spool, SpoolError
from p6installer.status import summarize_spool, read_live
from test_foundations import FixtureBase, fixture_policy
from test_windows_gui import _sample
from remote_probe.payload import encode_sample


class TargetTests(FixtureBase):
    def target(self, status):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(status)
                self.send_header('Content-Length', '0')
                if status == 302:
                    self.send_header('Location', 'https://must-not-follow.invalid/')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.certs.root / 'server.pem'), str(self.certs.root / 'server.key'))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        trusted = ssl.create_default_context(cadata=self.certs.pem())
        return server, trusted, seen

    def production_request(self, status, trusted=True):
        server, context, seen = self.target(status)
        original = dp.probe_https
        def request(host, **kwargs):
            self.assertEqual(host, 'www.gstatic.com')
            return original('127.0.0.1', port=server.server_port,
                            context=context if trusted else ssl.create_default_context(), **kwargs)
        agent = object.__new__(ProductionAgent)
        agent.config = type('Config', (), {'https_host': 'www.gstatic.com'})()
        with patch('remote_probe.production_runtime.dp.probe_https', side_effect=request):
            result = agent._probe_https()
        return result, seen

    def test_production_generate204_real_tls(self):
        result, seen = self.production_request(204)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(seen, ['/generate_204'])

    def test_exact_status_no_redirect_or_arbitrary_success(self):
        for status in (200, 201, 302, 404, 500):
            with self.subTest(status=status):
                result, seen = self.production_request(status)
                self.assertEqual(result['error_code'], 'bad_response')
                self.assertEqual(seen, ['/generate_204'])

    def test_production_target_normal_tls_still_required(self):
        result, seen = self.production_request(204, trusted=False)
        self.assertEqual(result['error_code'], 'tls_failed')
        self.assertEqual(seen, [])

    def test_base_defaults_and_other_production_hosts_unchanged(self):
        for agent_type in (RemoteProbeAgent, ProductionAgent):
            agent = object.__new__(agent_type)
            agent.config = type('Config', (), {'https_host': 'reviewed-other.example'})()
            with patch('remote_probe.agent.dp.probe_https', return_value={'status': 'ok'}) as call:
                self.assertEqual(agent._probe_https(), {'status': 'ok'})
                call.assert_called_once_with('reviewed-other.example')
        server, context, seen = self.target(204)
        self.assertEqual(dp.probe_https('127.0.0.1', port=server.server_port, context=context)['error_code'], 'bad_response')
        self.assertEqual(seen, ['/'])

    def test_invalid_expected_status_does_not_connect(self):
        for value in (True, 201, 302, '204', None):
            self.assertEqual(dp.probe_https('must-not-resolve.invalid', expected_status=value)['error_code'], 'unavailable')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = fixture_policy()
        self.root = Path(self.temp.name) / 'protected'
        self.policy.mkdir(str(self.root))
        self.path = self.root / 'spool'
        self.policy.mkdir(str(self.path))
        self.spool = ProductionSpool(str(self.path), security=self.policy).open()
        self.addCleanup(self.spool.close)
        import time
        sample = _sample(1, probe='device-one', epoch=time.time())
        self.spool.append(sample['probe_id'], sample['run'], 1, encode_sample(sample), queued_epoch=sample['sample_epoch'])

    def durable(self):
        return json.loads((self.path / 'spool.state.json').read_bytes())

    def test_legacy_state_counter_preserved_and_diagnostics_reopen(self):
        self.spool._state['state_save_failures'] = 1
        self.spool._save_state()
        self.spool.close()
        raw = self.durable()
        del raw['production_storage']
        (self.path / 'spool.state.json').write_text(json.dumps(raw))
        self.spool.open()
        self.assertEqual(self.spool.status()['state_save_failures'], 1)
        self.assertEqual(self.spool.storage_diagnostics['last_failure'], 'unknown')
        self.spool.note_attempt(1)
        self.spool.close()
        self.spool.open()
        self.assertEqual(self.spool.attempts(1), 1)
        self.assertEqual(self.spool.status()['state_save_failures'], 1)

    def test_hard_disk_failure_refuses_and_rolls_back_attempt(self):
        with patch.object(ProductionSpool, '_save_state_once', side_effect=OSError(errno.ENOSPC, 'PRIVATE-CANARY')) as save:
            with self.assertRaises(SpoolError):
                self.spool.note_attempt(1)
            self.assertEqual(save.call_count, 1)
        self.assertEqual(self.spool.attempts(1), 0)
        self.assertEqual(self.spool.status()['state_save_failures'], 1)
        self.spool.note_attempt(1)
        self.assertEqual(self.durable()['production_storage']['last_failure'], 'disk_full')
        self.assertNotIn('PRIVATE-CANARY', json.dumps(self.durable()))
        self.spool.close()
        self.spool.open()
        self.assertEqual(self.spool.attempts(1), 1)

    def test_permission_and_fsync_errors_not_retried(self):
        for number, expected in ((errno.EACCES, 'permission_denied'), (errno.EIO, 'io_error')):
            with self.subTest(number=number):
                with patch.object(ProductionSpool, '_save_state_once', side_effect=OSError(number, 'PRIVATE-CANARY')) as save:
                    self.spool._save_state_soft()
                    self.assertEqual(save.call_count, 1)
                self.assertEqual(self.spool.storage_diagnostics['last_failure'], expected)
        self.spool._save_state()
        self.assertEqual(self.durable()['state_save_failures'], 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows adapter fsync boundary')
    def test_native_fsync_failure_leaves_old_durable_attempts(self):
        self.spool._save_state()
        original = (self.path / 'spool.state.json').read_bytes()
        with patch('remote_probe.production_storage._fsync', side_effect=OSError(errno.EIO, 'PRIVATE-CANARY')) as sync:
            with self.assertRaises(SpoolError):
                self.spool.note_attempt(1)
            self.assertEqual(sync.call_count, 1)
        self.assertEqual((self.path / 'spool.state.json').read_bytes(), original)
        self.assertEqual(self.spool.attempts(1), 0)
        self.assertEqual(self.spool.status()['state_save_failures'], 1)

    def test_diagnostics_closed_bounded_and_optional_snapshot(self):
        self.spool._save_state()
        raw = self.durable()
        self.assertEqual(summarize_spool(json.dumps(raw).encode())['storage_diagnostics'],
                         {'last_failure': 'unknown', 'sharing_retries': 0})
        for value in ({'last_failure': 'PRIVATE-CANARY', 'sharing_retries': 0},
                      {'last_failure': [], 'sharing_retries': 0},
                      {'last_failure': 'unknown', 'sharing_retries': True},
                      {'last_failure': 'unknown', 'sharing_retries': 2**63}):
            self.assertIsNone(closed_diagnostics(value))
        del raw['production_storage']
        self.assertIsNone(summarize_spool(json.dumps(raw).encode())['storage_diagnostics'])
        for native in (32, 33):
            error = OSError(errno.EACCES, 'PRIVATE-CANARY')
            error.winerror = native
            self.assertEqual(failure_class(error), 'sharing_violation')

    @unittest.skipUnless(os.name == 'nt', 'native Windows held-file test')
    def test_real_held_state_refusal_then_recovery_without_attempt_loss(self):
        self.spool._save_state()
        handle = self.policy.open_handle(str(self.path / 'spool.state.json'))
        try:
            with self.assertRaises(SpoolError):
                self.spool.note_attempt(1)
            self.assertEqual(self.spool.attempts(1), 0)
            self.assertEqual(self.spool.status()['state_save_failures'], 1)
            self.assertEqual(self.spool.storage_diagnostics['last_failure'], 'sharing_violation')
            self.assertEqual(self.spool.storage_diagnostics['sharing_retries'], 2)
        finally:
            self.policy.k.CloseHandle(handle)
        self.spool.note_attempt(1)
        self.assertEqual(self.durable()['retry_attempts'], {'1': 1})
        self.assertEqual(self.durable()['state_save_failures'], 1)
        self.assertEqual(self.durable()['production_storage']['sharing_retries'], 2)

    @unittest.skipUnless(os.name == 'nt', 'native Windows transient sharing test')
    def test_real_transient_lock_short_retry_recovers(self):
        self.spool._save_state()
        handle = self.policy.open_handle(str(self.path / 'spool.state.json'))
        original = self.policy.k.CloseHandle
        import time
        sleep = time.sleep
        # The first failed replace triggers release before the bounded retry.
        from remote_probe import production_storage
        def release_and_wait(seconds):
            original(handle)
            sleep(seconds)
        with patch.object(production_storage.time, 'sleep', side_effect=release_and_wait):
            self.spool.note_attempt(1)
        self.assertEqual(self.spool.attempts(1), 1)
        self.assertEqual(self.durable()['state_save_failures'], 0)
        self.assertEqual(self.durable()['production_storage']['sharing_retries'], 1)

    @unittest.skipUnless(os.name == 'nt', 'native Windows live reader sharing test')
    def test_actual_snapshot_reader_allows_parallel_atomic_replace(self):
        self.spool._save_state()
        original = self.policy._check_handle
        started = [False]
        def held_reader(handle, directory):
            original(handle, directory)
            if not started[0]:
                started[0] = True
                self.spool.note_attempt(1)
        with patch.object(self.policy, '_check_handle', side_effect=held_reader):
            raw = read_live(self.policy, self.path / 'spool.state.json', 524288)
        # Held reader may observe old bytes; the writer must remain durable.
        self.assertEqual(json.loads(raw)['retry_attempts'], {})
        self.assertEqual(self.durable()['retry_attempts'], {'1': 1})
        self.assertEqual(self.spool.status()['state_save_failures'], 0)
        self.policy.validate(str(self.path / 'spool.state.json'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
