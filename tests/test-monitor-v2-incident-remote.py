"""P6C: real remote SQLite and shipped HTTP handler, offline and cross-platform."""
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
from remote_probe.payload import canonical_bytes
from web.incident_remote import incident_remote, ROW_LIMIT
from web.remote_ingest import RemoteIngest
from web.remote_store import RemoteStore, RemoteStoreError, MAX_AGE_SECONDS
from web.remote_registry import RegistryError
from web import incident_history as ih
from web.server import MonitorWebApp, build_server
from web.access import AccessPolicy
from web.auth import AuthStore

NOW = time.time()
RUN = 'a' * 32
SENTINEL = b'secret-must-never-appear'

class Registry:
    def __init__(self):
        self.entries = {name: SimpleNamespace(enabled=True, site_label='office',
            path_label=name + '-path', key=SENTINEL, key_file='sensitive.key')
            for name in ('device-a', 'device-b')}
    def health(self):
        return ('ready', None) if self.entries else ('not_configured', None)
    def lookup(self, name):
        return self.entries.get(name)
    def identity_problems(self):
        return {}

def sample(seq, probe='device-a', epoch=None, failed=False):
    slot = {'status': 'ok', 'latency_ms': 7, 'error_code': 'NONE'}
    return dict(v=1, probe_id=probe, run=RUN, seq=seq,
        sample_epoch=NOW-60+seq if epoch is None else epoch,
        dns=dict(slot), https=dict(slot), vps_tcp=dict(slot),
        egress=dict(slot, ip='203.0.113.7', change='changed'),
        mihomo_api={'status': 'ok'}, flags={'truncated': False, 'source_unavailable': []},
        active=[dict(role='reality', source='active_delay',
                     outcome='timeout' if failed else 'ok', delay_ms=None if failed else 72,
                     test_id='must-not-leak-test-id', independent=True),
                dict(role='reality', source='passive_cache', outcome='ok', delay_ms=71,
                     test_id='must-not-leak-test-id', independent=False)])

class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = NOW
        self.store = RemoteStore(self.temp.name, clock=lambda: self.clock).open()
        self.registry = Registry()
        self.plane = RemoteIngest(self.temp.name, clock=lambda: self.clock,
            registry=self.registry, store=self.store)
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def accept(self, row):
        return self.store.accept(row['probe_id'], row['run'], row['seq'],
            row['sample_epoch'], canonical_bytes(row), now=self.clock)
    def read(self, start=None, end=None):
        return incident_remote(self.plane, 1, NOW-300 if start is None else start,
            NOW if end is None else end, now=self.clock)
    def test_closed_schema_and_no_credentials_or_run_metadata(self):
        self.accept(sample(1))
        result = self.read()
        self.assertEqual(set(result), {'v','incident_id','window','retention','current_status','rows','truncated','limit'})
        self.assertEqual(set(result['current_status']), {'observed_epoch','status','subcode','probes'})
        self.assertEqual(set(result['retention']), {'max_age_seconds','retention_cutoff_epoch','retained_since_epoch','budget_pruned'})
        self.assertEqual(set(result['rows'][0]), {'sample_epoch','probe_id','dns','https','vps_tcp','egress','mihomo_api','flags','active','mapping_retired','site_label','path_label'})
        encoded = json.dumps(result)
        for secret in ('secret-must-never-appear', 'sensitive.key', 'must-not-leak-test-id', RUN, 'body_hash', 'accepted_epoch'):
            self.assertNotIn(secret, encoded)
    def test_same_bucket_split_is_raw_fact_only(self):
        self.accept(sample(1, failed=True))
        self.accept(sample(1, 'device-b'))
        rows = self.read()['rows']
        self.assertEqual([r['active'][0]['outcome'] for r in rows], ['timeout', 'ok'])
        self.assertEqual([r['path_label'] for r in rows], ['device-a-path', 'device-b-path'])
        self.assertNotIn('root_cause', json.dumps(self.read()))
    def test_egress_change_is_preserved_without_provider_inference(self):
        self.accept(sample(1))
        self.assertEqual(self.read()['rows'][0]['egress']['change'], 'changed')
        self.assertNotIn('isp', json.dumps(self.read()))
    def test_passive_echo_never_becomes_independent(self):
        self.accept(sample(1))
        self.assertFalse(self.read()['rows'][0]['active'][1]['independent'])
    def test_silence_is_unavailable_not_failed_path(self):
        self.accept(sample(1, epoch=NOW-1000))
        result = self.read(NOW-1500)
        self.assertEqual(result['current_status']['status'], 'source_unavailable')
        self.assertEqual(result['current_status']['subcode'], 'probe_not_reporting')
        self.assertEqual(result['rows'][0]['active'][0]['outcome'], 'ok')
    def test_absent_plane_is_not_configured(self):
        self.assertEqual(incident_remote(None, 1, NOW-1, NOW, now=NOW)['current_status']['status'], 'not_configured')
    def test_retired_mapping_does_not_reconstruct_labels(self):
        self.accept(sample(1))
        self.registry.entries.clear()
        row = self.read()['rows'][0]
        self.assertTrue(row['mapping_retired'])
        self.assertIsNone(row['site_label'])
        self.assertIsNone(row['path_label'])
    def test_window_boundaries_and_outside_rows(self):
        for seq, delta in enumerate((-301, -300, 0, 1), 1):
            self.accept(sample(seq, epoch=NOW+delta))
        result = self.read()
        self.assertEqual([r['sample_epoch'] for r in result['rows']], [NOW-300, NOW])
    def test_idle_retention_preserves_receipts_but_not_evidence(self):
        self.accept(sample(1, epoch=NOW-MAX_AGE_SECONDS+1))
        self.clock = NOW+2
        result = self.read(NOW-MAX_AGE_SECONDS-100)
        self.assertEqual(result['rows'], [])
        self.assertIsNotNone(self.store.receipt_hash('device-a', RUN, 1))
        self.assertIsNone(result['retention']['retained_since_epoch'])
    def test_very_long_incident_is_intersected_with_retention(self):
        self.accept(sample(1))
        result = self.read(NOW-2*MAX_AGE_SECONDS)
        self.assertEqual(len(result['rows']), 1)
        self.assertEqual(result['window']['start_epoch'], NOW-2*MAX_AGE_SECONDS)
    def test_limit_has_actual_extra_row_witness(self):
        for seq in range(1, ROW_LIMIT+2):
            self.accept(sample(seq, epoch=NOW-500+seq))
        result = self.read(NOW-600)
        self.assertEqual(len(result['rows']), ROW_LIMIT)
        self.assertTrue(result['truncated'])
    def test_exact_limit_does_not_claim_truncation(self):
        with patch.object(self.plane, 'read_samples', return_value=[]):
            self.assertFalse(self.read()['truncated'])
        self.accept(sample(1))
        row = self.read()['rows'][0]
        wrapped = {'sample': sample(1), 'mapping_retired':False, 'site_label':'office','path_label':'a'}
        with patch.object(self.plane, 'read_samples', return_value=[wrapped]*ROW_LIMIT):
            self.assertFalse(self.read()['truncated'])
    def test_unreadable_store_is_closed_remote_degradation(self):
        with patch.object(self.plane, 'read_samples', side_effect=RemoteStoreError('private disk path')):
            result = self.read()
        self.assertEqual(result['current_status']['subcode'], 'remote_store_unavailable')
        self.assertNotIn('private disk path', json.dumps(result))
        self.assertEqual(result['rows'], [])
    def test_budget_status_is_explicit(self):
        self.store._budget_pruned = True
        self.assertTrue(self.read()['retention']['budget_pruned'])
    def test_current_status_is_separate_from_incident_window(self):
        self.accept(sample(1, epoch=NOW-1000, failed=True))
        self.accept(sample(2, epoch=NOW-1))
        self.registry.entries.pop('device-b')
        result = self.read(NOW-1100, NOW-900)
        self.assertEqual(result['current_status']['status'], 'fresh')
        self.assertEqual(result['rows'][0]['active'][0]['outcome'], 'timeout')
    def test_registry_fence_failure_is_configuration_unavailable(self):
        @contextmanager
        def refused():
            raise RegistryError('private credential path')
            yield
        self.registry.config_path = 'fixture-not-opened'
        self.registry.live = refused
        result = self.read()
        self.assertEqual(result['current_status']['subcode'], 'remote_config_invalid')
        self.assertEqual(result['rows'], [])
        self.assertNotIn('private credential path', json.dumps(result))
    def test_closed_store_does_not_fabricate_healthy_records(self):
        self.store.close()
        result = self.read()
        self.assertEqual(result['current_status']['status'], 'degraded')
        self.assertEqual(result['current_status']['subcode'], 'remote_store_unavailable')
        self.assertEqual(result['rows'], [])

class History:
    def __init__(self):
        self.calls = []
        self.outcome = ih.OUTCOME_OK
    def incident_detail(self, ident):
        self.calls.append(ident)
        if ident != 1: return ih.OUTCOME_MISSING, None
        return self.outcome, {'analysis_start_epoch': NOW-300, 'last_classified_end_epoch': NOW}

class HTTPTests(unittest.TestCase):
    accept = RemoteTests.accept
    def setUp(self):
        RemoteTests.setUp(self)
        self.accept(sample(1))
        self.history = History()
        auth = AuthStore(self.temp.name, session_ttl=3600)
        auth.set_password('fixture-password-only')
        app = MonitorWebApp(None, AccessPolicy(self.temp.name), None, auth=auth,
            incident_history=self.history, remote_plane=self.plane)
        self.server = build_server(app, '127.0.0.1', 0, None)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, data, headers = self.request('POST','/api/v1/login', {'password':'fixture-password-only'})
        self.assertEqual(status, 200, data)
        self.cookie = headers['Set-Cookie'].split(';')[0]
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(5)
        RemoteTests.tearDown(self)
    def request(self, method='GET', path='/api/v1/incidents/1/remote-probes', body=None, cookie=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=5)
        headers = {'Content-Type':'application/json'}
        if cookie: headers['Cookie'] = cookie
        try:
            conn.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
            res = conn.getresponse()
            return res.status, json.loads(res.read()), dict(res.getheaders())
        finally: conn.close()
    def test_session_required_before_reading_history(self):
        self.history.calls.clear()
        status, _, _ = self.request()
        self.assertEqual(status, 401)
        self.assertEqual(self.history.calls, [])
    def test_authenticated_response_and_arbitrary_query_cannot_change_window(self):
        status, data, headers = self.request(path='/api/v1/incidents/1/remote-probes?start_epoch=0&end_epoch=9999999999&limit=999999&probe_id=other', cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data['window'], {'start_epoch':NOW-300,'end_epoch':NOW})
        self.assertEqual(len(data['rows']), 1)
        self.assertIn('no-store', headers['Cache-Control'])
    def test_missing_and_invalid_id_closed(self):
        for suffix in ('0','-1','01','+1','1/other','abc','9'*100,'999','%C2%B2'):
            with self.subTest(suffix=suffix):
                status, data, _ = self.request(path='/api/v1/incidents/'+suffix+'/remote-probes', cookie=self.cookie)
                self.assertEqual(status, 404)
                self.assertEqual(data, {'error':'incident_not_found'})
    def test_post_is_method_refusal(self):
        status, _, headers = self.request('POST', body={}, cookie=self.cookie)
        self.assertEqual(status, 405)
        self.assertEqual(headers['Allow'], 'GET')
    def test_history_failure_never_turns_into_empty_success(self):
        self.history.outcome = ih.OUTCOME_STORE_UNAVAILABLE
        status, data, _ = self.request(cookie=self.cookie)
        self.assertEqual(status, 503)
        self.assertEqual(data, {'error':'incident history unavailable'})

if __name__ == '__main__':
    unittest.main(verbosity=2)
