"""Native root fixture: real worker, peer-authenticated RPC and Monitor HTTP.

All state/socket/listeners are disposable /run or loopback fixtures. Production
peer policy stays sboxweb-only; only this daemon's explicit TEST sandbox admits
the root fixture client. No real VPS/service/firewall is touched.
"""
import concurrent.futures
import copy
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'tests/remote-production'))
import test_provisioning as fixtures
import test_bundle as portable
from p6_artifact import read_artifact, ArtifactError
from web.e3rpc import E3RpcClient, RpcTransportError, MAX_FRAME
from web.e3_broker import E3Broker
from web.server import P6_ROUTES


class BundleLinuxTests(unittest.TestCase):
    TEMP_DIR = '/run'
    setUpClass = fixtures.ProvisioningTests.__dict__['setUpClass']
    tearDownClass = fixtures.ProvisioningTests.__dict__['tearDownClass']
    write_binding = fixtures.ProvisioningTests.write_binding
    row = fixtures.ProvisioningTests.row
    state = fixtures.ProvisioningTests.state
    fail_code = fixtures.ProvisioningTests.fail_code

    def setUp(self):
        fixtures.ProvisioningTests.setUp(self)
        self.addCleanup(fixtures.ProvisioningTests.tearDown, self)
        self.root.chmod(0o755)
        self.helper = self.root / 'helper'
        self.helper.mkdir(mode=0o755)
        for name in ('sbox-cm-ops', 'p6_provision.py', 'p6_bundle.py'):
            shutil.copyfile(ROOT / 'sbox-cm' / name, self.helper / name)
            (self.helper / name).chmod(0o755 if name == 'sbox-cm-ops' else 0o644)
        shutil.copyfile(ROOT / 'monitor-v2/p6_artifact.py', self.helper / 'p6_artifact.py')
        (self.helper / 'p6_artifact.py').chmod(0o644)
        fixtures.ProvisioningTests.setup_client_worker(self)
        self.proxy_config.parent.chmod(0o700)
        config = json.loads(self.proxy_config.read_bytes())
        config['inbounds'][0].update(listen_port=443, tls={
            'server_name': 'www.example.com', 'reality': {'short_id': ['1234abcd']}})
        config['inbounds'][1]['listen_port'] = 8443
        self.proxy_config.write_text(json.dumps(config))
        Path(self.env['SB_STATE_FILE']).write_text("SERVER_IP='192.0.2.10'\nPUBLIC_KEY='fixture-public-key'\n"
                                                 "HY_SERVER_NAME='www.example.com'\nHY_HOPPING=FALSE\n")
        self.artifact_dir = self.root / 'artifact'
        self.artifact_dir.mkdir(mode=0o755)
        self.manifest, self.generic = portable.builder.build()
        for name, raw in (('artifact.json', json.dumps(self.manifest).encode()), ('p6-agent.pyz', self.generic)):
            path = self.artifact_dir / name
            path.write_bytes(raw)
            path.chmod(0o644)
        self.env['SB_P6_ARTIFACT_DIR'] = str(self.artifact_dir)
        result = self.call_worker('probe.enroll', name='event-pc', device='laptop-01',
                                  idempotency_key='bundle-enrollment-0001', site_label='office', path_label='path')
        self.assertTrue(result['ok'], result)
        self.generation = self.row()['client_generation']
        self.socket = self.root / 'helper.sock'
        self.daemon = subprocess.Popen([sys.executable, str(ROOT / 'sbox-cm/sbox-cm'), 'run'],
            env=self.env | {'SBOX_CM_SOCKET': str(self.socket), 'SBOX_CM_WORKER': str(self.helper / 'sbox-cm-ops'),
                            'SBOX_CM_ALLOWED_UID': '0'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.close_daemon)
        deadline = time.monotonic() + 10
        while not self.socket.exists():
            if self.daemon.poll() is not None:
                self.fail(self.daemon.stderr.read().decode())
            if time.monotonic() > deadline:
                self.fail('fixture daemon did not bind')
            time.sleep(.01)
        self.client = E3RpcClient(str(self.socket))
        self.calls = []
        real_call = self.client.call
        def observed(op, *args, **kwargs):
            self.calls.append(op)
            return real_call(op, *args, **kwargs)
        self.client.call = observed
        self.app = self.server.app
        self.app.e3_broker = E3Broker(self.client)
        self.app.bundle_artifact = lambda: read_artifact(str(self.artifact_dir))
        self.token = self.app.auth.sessions.create()
        self.csrf = self.app.auth.sessions.resolve(self.token)['csrf_token']
        self.app.auth.sessions.grant_step_up(self.token)

    def close_daemon(self):
        if self.daemon.poll() is None:
            self.daemon.terminate()
        _, error = self.daemon.communicate(timeout=10)
        self.assertNotIn(self.row()['secret'].encode(), error)

    def call_worker(self, op, **args):
        args['request_id'] = 'bundle-request-' + os.urandom(12).hex()
        result = subprocess.run(['bash', str(self.helper / 'sbox-cm-ops'), op], input=json.dumps(args).encode(),
                                env=self.env, capture_output=True, timeout=35)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def http(self, path='/api/v1/clients/bundle', body=None, method='POST', auth=True, csrf=True, headers=None):
        sending = {'Content-Type': 'application/json'}
        if auth:
            sending['Cookie'] = 'monitor_session=' + self.token
        if csrf:
            sending['X-CSRF-Token'] = self.csrf
        sending.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=35)
        raw = json.dumps(body if body is not None else {'name': 'event-pc', 'device': 'laptop-01'}).encode()
        try:
            connection.request(method, path, raw if method == 'POST' else None, sending)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def audit(self):
        path = Path(self.env['SB_CM_STATE_DIR']) / 'audit/cm.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_real_rpc_http_zip_has_canonical_yaml_and_one_device_key(self):
        exported = self.client.call('client.export', {'name': 'event-pc'})['data']['content'].encode()
        status, headers, raw = self.http()
        self.assertEqual(status, 200, raw)
        self.assertEqual(headers['Content-Type'], 'application/zip')
        self.assertIn('event-pc-laptop-01-client-bundle.zip', headers['Content-Disposition'])
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(int(headers['Content-Length']), len(raw))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(archive.read('event-pc-mihomo.yaml'), exported)
            self.assertEqual(archive.read('ingest.key'), (self.row()['secret'] + '\n').encode())
            profile = json.loads(archive.read('profile.json'))
            self.assertEqual(profile['probe_id'], self.row()['probe_id'])
            self.assertEqual(profile['agent']['reality_node'], 'Reality')
            self.assertEqual(profile['agent']['hy2_node'], 'Hysteria2')
            self.assertEqual(profile['agent']['vps_port'], 443)
            self.assertEqual(archive.read('agent/p6-agent.pyz'), self.generic)
        self.assertEqual(self.plane.store.status()['sample_count'], 0)
        self.assertEqual(self.plane.store.status()['receipt_count'], 0)
        records = [r for r in self.audit() if r['op'] == 'client.bundle']
        self.assertEqual(records[-1]['device'], 'laptop-01')
        self.assertEqual(records[-1]['actor']['session_fp'], self.app.session_fingerprint(self.token))
        self.assertRegex(records[-1]['actor']['stepup_fp'], r'^[0-9a-f]{16}$')
        self.assertNotIn(self.row()['secret'], json.dumps(records))

    def test_repeat_download_is_identical_and_does_not_change_state(self):
        before = Path(self.worker.state_path).read_bytes()
        first = self.http()
        second = self.http()
        self.assertEqual(first[0], 200)
        self.assertEqual(first[2], second[2])
        self.assertEqual(Path(self.worker.state_path).read_bytes(), before)
        self.assertEqual(len([r for r in self.audit() if r['op'] == 'client.bundle']), 2)

    def test_http_enroll_and_revoke_use_real_worker_and_closed_metadata(self):
        status, _, raw = self.http('/api/v1/clients/probes/enroll',
            {'name': 'event-pc', 'device': 'laptop-02', 'site_label': 'office', 'path_label': 'operator-path'},
            headers={'Idempotency-Key': 'http-enrollment-000002'})
        self.assertEqual(status, 200, raw)
        row = self.row('laptop-02')
        self.assertTrue(fixtures.p6.live_proof(self.worker.port, row, True))
        self.assertNotIn(row['secret'].encode(), raw)
        status, _, raw = self.http('/api/v1/clients/probes/revoke',
            {'name': 'event-pc', 'device': 'laptop-02', 'probe_id': row['probe_id']})
        self.assertEqual(status, 200, raw)
        self.assertTrue(json.loads(raw)['data']['revoked'])
        self.assertTrue(fixtures.p6.live_proof(self.worker.port, row, False))
        self.assertTrue(fixtures.p6.live_proof(self.worker.port, self.row(), True))

    def test_selected_old_identity_revoke_preserves_same_device_new_generation(self):
        old = self.row().copy()
        new = self.worker.enroll('event-pc', 'laptop-01', 'e' * 64,
            'new-generation-00001', 'office', 'path')
        current = next(r for r in self.state()['records'] if r['probe_id'] == new['probe_id'])
        self.fail_code('E_P6_NOT_ENROLLED', lambda: self.worker.revoke(
            'wrong-client', 'laptop-01', probe_id=old['probe_id']))
        self.assertEqual(self.http('/api/v1/clients/probes/revoke')[0], 400)
        status, _, raw = self.http('/api/v1/clients/probes/revoke',
            {'name': 'event-pc', 'device': 'laptop-01', 'probe_id': old['probe_id']})
        self.assertEqual(status, 200, raw)
        self.assertEqual(json.loads(raw)['data']['count'], 1)
        self.assertTrue(fixtures.p6.live_proof(self.worker.port, old, False))
        self.assertTrue(fixtures.p6.live_proof(self.worker.port, current, True))
        self.assertEqual(next(r for r in self.state()['records'] if r['probe_id'] == new['probe_id']), current)

    def test_changed_server_binding_refuses_delivery_without_rotation(self):
        original = self.row().copy()
        self.binding['server_id'] = 'd' * 32
        self.write_binding()
        status, _, raw = self.http()
        self.assertEqual(status, 409, raw)
        self.assertNotIn(original['secret'].encode(), raw)
        self.assertEqual(self.row(), original)

    def test_auth_csrf_stepup_and_origin_refuse_before_artifact_or_rpc(self):
        with patch.object(self.app, 'bundle_artifact', side_effect=AssertionError('unauthorized artifact read')):
            for expected, kwargs in ((401, {'auth': False}), (403, {'csrf': False}),
                    (403, {'headers': {'Origin': 'https://foreign.example'}})):
                with self.subTest(kwargs=kwargs):
                    self.assertEqual(self.http(**kwargs)[0], expected)
            self.app.auth.sessions.revoke_all_step_ups()
            self.assertEqual(self.http()[0], 401)
        self.assertEqual(self.calls, [])

    def test_all_new_routes_are_post_only_and_closed_for_other_methods(self):
        for route in P6_ROUTES:
            for method in ('GET', 'PUT', 'DELETE'):
                with self.subTest(route=route, method=method):
                    self.assertEqual(self.http(path=route, method=method)[0], 405)
        self.assertEqual(self.calls, [])

    def test_malformed_body_path_generation_and_idempotency_cannot_dispatch(self):
        for body in ({'name': 'event-pc'}, {'name': 'event-pc', 'device': '../escape'},
                {'name': 'event-pc', 'device': 'laptop-01', 'client_generation': self.generation},
                {'name': 'event-pc', 'device': 'laptop-01', 'secret': 'b' * 64}):
            with self.subTest(body=body):
                self.assertEqual(self.http(body=body)[0], 400)
        self.assertEqual(self.http(headers={'Idempotency-Key': 'forbidden-export-0001'})[0], 400)
        self.assertEqual(self.calls, [])

    def test_fresh_management_gate_refuses_zero_sensitive_rpc(self):
        # Use the broker's actual failure type so HTTP maps the refusal cleanly.
        from web.e3_broker import BrokerUnavailable
        self.app.e3_broker.require_export_ready = lambda: (_ for _ in ()).throw(BrokerUnavailable())
        self.assertEqual(self.http()[0], 503)
        self.assertEqual(self.calls, [])

    def test_revocation_blocks_a_repeated_request_id_in_actual_daemon(self):
        payload = {'name': 'event-pc', 'device': 'laptop-01'}
        first = self.client.call('client.bundle', payload, request_id='bundle-identical-request-001')
        self.assertTrue(first['ok'])
        self.assertLess(len(json.dumps(first).encode()), MAX_FRAME)
        self.worker.revoke('event-pc', 'laptop-01')
        second = self.client.call('client.bundle', payload, request_id='bundle-identical-request-001')
        self.assertFalse(second['ok'])
        self.assertEqual(second['error']['code'], 'E_P6_REVOKED')
        self.assertNotIn(self.row()['secret'], json.dumps(second))
        records = [r for r in self.audit() if r['op'] == 'client.bundle']
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]['audit_id'], records[1]['audit_id'])

    def test_two_devices_receive_distinct_keys_without_leaking_other_profile(self):
        result = self.call_worker('probe.enroll', name='event-pc', device='laptop-02',
            idempotency_key='bundle-enrollment-0002', site_label='office', path_label='path')
        self.assertTrue(result['ok'])
        other = next(row for row in self.state()['records'] if row['device'] == 'laptop-02')
        status, _, raw = self.http()
        self.assertEqual(status, 200)
        self.assertNotIn(other['secret'].encode(), raw)
        self.assertNotEqual(other['secret'], self.row()['secret'])

    def test_missing_changed_or_unsafe_artifact_refuses_before_sensitive_rpc(self):
        path = self.artifact_dir / 'p6-agent.pyz'
        original = path.read_bytes()
        for case in ('missing', 'changed', 'mode', 'symlink', 'hardlink'):
            with self.subTest(case=case):
                self.calls.clear()
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_bytes(original)
                path.chmod(0o644)
                if case == 'missing':
                    path.unlink()
                elif case == 'changed':
                    path.write_bytes(original + b'bad')
                elif case == 'mode':
                    path.chmod(0o666)
                elif case == 'symlink':
                    path.unlink(); path.symlink_to(self.artifact_dir / 'artifact.json')
                else:
                    path.unlink(); os.link(self.artifact_dir / 'artifact.json', path)
                response = self.http()
                self.assertEqual(response[0], 503)
                self.assertNotIn('client.bundle', self.calls)
                self.assertNotIn(self.row()['secret'].encode(), response[2])

    def test_audit_failure_returns_no_bundle_parts_or_credential(self):
        audit_dir = Path(self.env['SB_CM_STATE_DIR']) / 'audit'
        # Wrong type on the fixed audit file makes durable append fail. The
        # parent remains protected; this is no unowned-file takeover fixture.
        file = audit_dir / 'cm.jsonl'
        file.unlink()
        file.mkdir()
        status, _, raw = self.http()
        self.assertEqual(status, 503, raw)
        self.assertNotIn(self.row()['secret'].encode(), raw)
        self.assertNotIn(b'p6-client-bundle-parts', raw)

    def test_metadata_routes_never_forward_unknown_secret_fields(self):
        original = self.app.e3_broker.p6_request
        def poisoned(op, payload, actor=None):
            result = original(op, payload, actor=actor)
            if result.get('ok') and op == 'probe.list':
                result['data']['secret'] = self.row()['secret']
                result['data']['devices'][0]['secret'] = self.row()['secret']
            return result
        self.app.e3_broker.p6_request = poisoned
        status, _, raw = self.http('/api/v1/clients/probes/list', {'name': 'event-pc'})
        self.assertEqual(status, 200)
        self.assertNotIn(self.row()['secret'].encode(), raw)
        self.assertNotIn(b'"secret"', raw)

    def test_concurrent_export_and_revoke_linearize_on_existing_locks(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            exported = pool.submit(self.client.call, 'client.bundle', {'name': 'event-pc', 'device': 'laptop-01'})
            revoked = pool.submit(self.worker.revoke, 'event-pc', 'laptop-01')
            result = exported.result()
            self.assertTrue(revoked.result()['revoked'])
        self.assertTrue(result['ok'] or result['error']['code'] == 'E_P6_REVOKED')
        self.assertEqual(self.http()[0], 409)

    def test_pending_identity_recovers_after_lost_browser_key_without_rotation(self):
        state = self.state()
        state['records'][0].update(verified='pending', verified_epoch=None)
        self.worker._save(state)
        original = self.row().copy()
        self.assertEqual(self.http()[0], 409)
        status, _, raw = self.http('/api/v1/clients/probes/resume', {'name': 'event-pc', 'device': 'laptop-01'})
        self.assertEqual(status, 200, raw)
        for field in ('probe_id', 'secret', 'enrollment', 'client_generation', 'site_label', 'path_label'):
            self.assertEqual(self.row()[field], original[field])
        self.assertEqual(self.http()[0], 200)

    def test_resume_refuses_retired_and_recreated_client_generation(self):
        self.worker.revoke('event-pc', 'laptop-01')
        self.fail_code('E_P6_REVOKED', lambda: self.worker.resume('event-pc', 'laptop-01', self.generation))
        self.fail_code('E_P6_NOT_ENROLLED', lambda: self.worker.resume('event-pc', 'laptop-01', 'c' * 64))
        self.assertEqual(self.row()['desired'], 'revoked')

    def test_changed_registry_key_or_generation_cannot_export(self):
        self.fail_code('E_P6_NOT_ENROLLED', lambda: self.worker.export_material('event-pc', 'laptop-01', 'c' * 64))
        key = self.config_dir / 'remote-probes.d' / (self.row()['probe_id'] + '.key')
        self.worker._write(str(key), b'c' * 64 + b'\n', 0o640, self.gid)
        self.fail_code('E_P6_KEY_CHANGED', lambda: self.worker.export_material('event-pc', 'laptop-01', self.generation))
        self.assertEqual(self.http()[0], 409)

    def test_serialized_parts_budget_refuses_json_escape_inflation(self):
        spec = importlib.util.spec_from_file_location('bundle_factory', self.helper / 'p6_bundle.py')
        factory = importlib.util.module_from_spec(spec); spec.loader.exec_module(factory)
        args = {'name': 'event-pc', 'device': 'laptop-01', 'client_generation': self.generation,
                'server_ip': '192.0.2.10', 'vps_port': 443, 'yaml': '"' * 32768}
        with self.assertRaises(factory.p6.ProvisionError) as caught:
            factory.make_parts(self.worker, args, str(self.artifact_dir))
        self.assertEqual(caught.exception.code, 'E_P6_CAPACITY')

    def test_unprivileged_process_reads_generic_but_not_device_ledger(self):
        def drop():
            os.setgroups([]); os.setgid(65534); os.setuid(65534)
        code = '''import sys
sys.path.insert(0,sys.argv[1])
from p6_artifact import read_artifact
manifest,raw=read_artifact(sys.argv[2])
denied=False
try: open(sys.argv[3],'rb')
except PermissionError: denied=True
print(len(raw),denied)
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(self.helper),
                str(self.artifact_dir), str(self.worker.state_path)], preexec_fn=drop,
                cwd='/', capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.decode().strip(), str(len(self.generic)) + ' True')

    def test_download_concurrency_capacity_refuses_without_rpc(self):
        self.app.bundle_slots.acquire(); self.app.bundle_slots.acquire()
        try:
            self.assertEqual(self.http()[0], 429)
            self.assertEqual(self.calls, [])
        finally:
            self.app.bundle_slots.release(); self.app.bundle_slots.release()

    def test_installer_under_private_umask_publishes_outside_0700_helper(self):
        prefix = self.root / 'installed'
        helper = prefix / 'usr/local/lib/sbox-cm'
        helper.mkdir(parents=True)
        helper.chmod(0o700)
        state = prefix / 'state'
        def private_umask():
            os.umask(0o077)
        installed = subprocess.run(['bash', str(ROOT / 'sbox-cm/deploy/install-sbox-cm.sh'), 'install'],
            env=os.environ | {'SBXCM_PREFIX': str(prefix), 'SBXCM_SYSTEMCTL': '/usr/bin/true',
                              'SB_CM_STATE_DIR': str(state)}, preexec_fn=private_umask,
            capture_output=True, timeout=30)
        self.assertEqual(installed.returncode, 0, installed.stderr.decode())
        self.assertEqual(helper.stat().st_mode & 0o777, 0o700)
        public = prefix / 'usr/local/share/sbox-p6-artifact'
        self.assertEqual(read_artifact(str(public))[0], self.manifest)
        # Actual non-root file reads after the actual deployment script. This
        # reproduces the real private-parent failure missed by root HTTP tests.
        reader = self.root / 'public-reader'
        reader.mkdir(mode=0o755)
        shutil.copyfile(ROOT / 'monitor-v2/p6_artifact.py', reader / 'p6_artifact.py')
        (reader / 'p6_artifact.py').chmod(0o644)
        def unprivileged():
            os.setgroups([]); os.setgid(65534); os.setuid(65534)
        code = '''import sys
sys.path.insert(0,sys.argv[1])
from p6_artifact import read_artifact
m,b=read_artifact(sys.argv[2])
denied=False
try: open(sys.argv[3],'rb')
except PermissionError: denied=True
assert denied
print(m['sha256'])
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(reader), str(public),
                                 str(helper / 'sbox-cm')], preexec_fn=unprivileged,
                                cwd='/', capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.decode().strip(), self.manifest['sha256'])
        uninstalled = subprocess.run(['bash', str(ROOT / 'sbox-cm/deploy/install-sbox-cm.sh'), 'uninstall'],
            env=os.environ | {'SBXCM_PREFIX': str(prefix), 'SBXCM_SYSTEMCTL': '/usr/bin/true',
                              'SB_CM_STATE_DIR': str(state)}, capture_output=True, timeout=15)
        self.assertEqual(uninstalled.returncode, 0, uninstalled.stderr.decode())
        self.assertFalse(public.exists())
        self.assertTrue(state.is_dir())

    def test_root_validator_refuses_private_artifact_parent(self):
        # Root can read both files; the validator must still refuse a layout
        # that the actual unprivileged HTTP process cannot traverse.
        private = self.root / 'private'
        private.mkdir(mode=0o700)
        moved = private / 'artifact'
        shutil.move(str(self.artifact_dir), str(moved))
        with self.assertRaises(ArtifactError):
            read_artifact(str(moved))


if __name__ == '__main__':
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Linux root bundle fixtures required; no skipped acceptance')
    unittest.main(verbosity=2)
