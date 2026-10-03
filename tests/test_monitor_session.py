"""Real HTTP and deterministic idle-expiry regressions for one-login sessions."""
import concurrent.futures
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
from web.auth import AuthStore, SessionStore
from web.access import AccessPolicy
from web.server import MonitorWebApp, build_server

class Clock:
    def __init__(self): self.now = 1000.0
    def __call__(self): return self.now

class Broker:
    def snapshot_json(self): return 1, '{"snapshot_version":1}'
    def subscribe(self, after_version):
        for n in range(100):
            time.sleep(.01)
            yield n + 2, '{}'

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.auth = AuthStore(self.tmp.name, clock=self.clock)
        self.password = 'session-policy-test-password'
        self.auth.set_password(self.password)
        self.app = MonitorWebApp(Broker(), AccessPolicy(self.tmp.name),
            static_dir=str(ROOT / 'monitor-v2/web/static'), auth=self.auth)
        self.server = build_server(self.app, '127.0.0.1', 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, headers, body = self.request('POST', '/api/v1/login', {'password': self.password}, auth=False)
        self.assertEqual(status, 200, body)
        self.cookie = headers['set-cookie'].split(';')[0]
        self.token = self.cookie.split('=', 1)[1]
        self.csrf = self.request('GET', '/api/v1/session')[2]['csrf_token']

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, body=None, *, auth=True, csrf=True, extra=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=3)
        headers = {'Content-Type': 'application/json'}
        if auth: headers['Cookie'] = self.cookie
        if csrf and hasattr(self, 'csrf'): headers['X-CSRF-Token'] = self.csrf
        headers.update(extra or {})
        conn.request(method, path, None if body is None else json.dumps(body).encode(), headers)
        response = conn.getresponse(); raw = response.read(); status = response.status
        h = {k.lower(): v for k, v in response.getheaders()}; conn.close()
        return status, h, json.loads(raw)

    def test_password_login_authorizes_all_protected_families_without_step_up(self):
        self.assertTrue(self.auth.sessions.step_up_active(self.token))
        self.assertRegex(self.auth.sessions.step_up_credentials(self.token)['fp'], '^[0-9a-f]{16}$')
        expected = {'/api/v1/clients/windows': 503, '/api/v1/clients/bundle': 400,
                    '/api/v1/clients/export': 503, '/api/v1/clients/probes/enroll': 400,
                    '/api/v1/clients/probes/revoke': 400, '/api/v1/clients/delete': 503,
                    '/api/v1/management/activate': 503, '/api/v1/incidents/rearm': 503}
        for path, expected_status in expected.items():
            status, _, body = self.request('POST', path, {})
            self.assertEqual(status, expected_status, (path, body))
        self.clock.now += 600
        self.assertTrue(self.auth.sessions.step_up_active(self.token))
        self.assertNotEqual(self.request('POST', '/api/v1/clients/windows', {})[0], 401)

    def test_background_session_snapshot_status_and_sse_never_renew(self):
        for offset in (300, 600, 899):
            self.clock.now = 1000 + offset
            self.assertEqual(self.request('GET', '/api/v1/snapshot')[0], 200)
            self.request('GET', '/api/v1/management/status')
            data = self.request('GET', '/api/v1/session')[2]
            self.assertEqual(data['idle_remaining_seconds'], 900 - offset)
        self.clock.now = 1900
        self.assertEqual(self.request('GET', '/api/v1/snapshot')[0], 401)
        self.assertFalse(self.request('GET', '/api/v1/session')[2]['authenticated'])
        self.assertEqual(self.request('POST', '/api/v1/clients/windows', {})[0], 401)

    def test_activity_renews_only_with_closed_body_session_csrf_and_origin(self):
        self.clock.now += 899
        for body in ({'epoch': 9999999}, {'ttl': 999999}, [], None):
            self.assertEqual(self.request('POST', '/api/v1/session/activity', body)[0], 400)
        self.assertEqual(self.request('POST', '/api/v1/session/activity', {}, csrf=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/v1/session/activity', {},
            extra={'Origin': 'https://foreign.invalid'})[0], 403)
        self.assertEqual(self.request('POST', '/api/v1/session/activity', {}, auth=False)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/session/activity")[0], 405)
        self.assertEqual(self.auth.sessions.remaining(self.token), 1)
        status, headers, data = self.request('POST', '/api/v1/session/activity', {})
        self.assertEqual(status, 200); self.assertEqual(data['idle_remaining_seconds'], 900)
        self.assertIn('no-store', headers['cache-control'])
        self.clock.now += 600
        self.assertEqual(self.request('GET', '/api/v1/snapshot')[0], 200)
        self.clock.now += 300
        self.assertEqual(self.request('GET', '/api/v1/snapshot')[0], 401)

    def test_expired_session_never_revives_by_activity_or_legacy_step_up(self):
        self.clock.now += 900
        self.assertEqual(self.request('POST', '/api/v1/session/activity', {})[0], 401)
        self.assertEqual(self.request('POST', '/api/v1/step-up', {'password': self.password})[0], 401)
        self.assertIsNone(self.auth.sessions.activity(self.token))
        self.assertIsNone(self.auth.sessions.grant_step_up(self.token, 999999))

    def test_continuous_activity_still_hits_eight_hour_absolute_ceiling(self):
        for n in range(1, 48):
            self.clock.now = 1000 + n * 600
            self.assertEqual(self.request('POST', '/api/v1/session/activity', {})[0], 200)
        self.clock.now = 1000 + 8 * 3600
        self.assertEqual(self.request('POST', '/api/v1/session/activity', {})[0], 401)
        self.assertEqual(self.request('POST', '/api/v1/clients/windows', {})[0], 401)

    def test_logout_password_recovery_and_restart_revoke_without_regrant(self):
        self.assertEqual(self.request('POST', '/api/v1/logout', {})[0], 200)
        self.assertIsNone(self.auth.sessions.resolve(self.token))
        for mutation in ('password', 'recovery'):
            token = self.auth.login(self.password)
            self.assertIsNotNone(token)
            if mutation == 'password': self.auth.set_password(self.password, keep_session=token)
            else: self.auth.set_recovery_key('new-recovery-test-key')
            self.assertIsNone(self.auth.sessions.resolve(token))
            self.assertFalse(self.auth.sessions.step_up_active(token))
        token = self.auth.login(self.password)
        restored = AuthStore(self.tmp.name, clock=self.clock)
        self.assertIsNone(restored.sessions.resolve(token))
        raw = Path(self.auth.path).read_text()
        for secret in (token, self.password, 'idle_expires', 'stepup_fp'):
            self.assertNotIn(secret, raw)

    def test_bad_login_does_not_create_authorized_session(self):
        before = len(self.auth.sessions._sessions)
        self.assertEqual(self.request('POST', '/api/v1/login', {'password': 'wrong'}, auth=False)[0], 401)
        self.assertEqual(len(self.auth.sessions._sessions), before)

    def test_activity_expiry_mutex_uses_current_time_and_never_resurrects(self):
        # Queue activity while the clock crosses the exact cutoff inside the lock.
        self.auth.sessions._mutex.acquire()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.auth.sessions.activity, self.token)
            time.sleep(.02)
            self.clock.now = 1900
            self.auth.sessions._mutex.release()
            self.assertIsNone(pending.result(timeout=2))
        self.assertIsNone(self.auth.sessions.resolve(self.token))

    def test_open_sse_stops_on_idle_expiry(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=3)
        conn.request('GET', '/api/v1/stream', headers={'Cookie': self.cookie})
        response = conn.getresponse(); self.assertEqual(response.status, 200)
        self.assertEqual(response.readline(), b'retry: 3000\n'); response.readline()
        self.clock.now = 1900
        self.assertEqual(response.read(), b''); conn.close()
        self.assertFalse(self.auth.sessions.step_up_active(self.token))

    def test_authentication_root_change_cannot_race_login_to_create_old_authority(self):
        ready, proceed = threading.Event(), threading.Event()
        import web.auth as module
        original = module.verify_secret
        from unittest.mock import patch
        def verify(value, record):
            if value == self.password:
                ready.set(); self.assertTrue(proceed.wait(2))
            return original(value, record)
        with patch.object(module, 'verify_secret', verify), concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            login = pool.submit(self.auth.login, self.password)
            self.assertTrue(ready.wait(2))
            change = pool.submit(self.auth.set_password, 'replacement-password')
            proceed.set()
            token = login.result(2); change.result(2)
        self.assertIsNone(self.auth.sessions.resolve(token))

if __name__ == '__main__': unittest.main(verbosity=2)
