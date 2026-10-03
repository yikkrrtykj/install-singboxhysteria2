"""Linux root lifecycle fixtures: real registry, HTTP handler, flock and Client worker.

No public listener/VPS. Missing Linux/root is a hard failure, never a skipped
PASS. Injected crash hooks are constructor-only; success proofs use shipped
Monitor's real machine-auth route unless a test explicitly exercises failure.
"""
import concurrent.futures
import grp
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'tests/remote-server'))
sys.path.insert(0, str(ROOT / 'tests/remote-production'))
import server_groups as harness
from test_foundations import Certificates
from web.remote_registry import RemoteRegistry
from web.remote_ingest import RemoteIngest
from remote_probe.payload import verify_signature

spec = importlib.util.spec_from_file_location('p6_provision', ROOT / 'sbox-cm/p6_provision.py')
p6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)


class ProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_root = tempfile.TemporaryDirectory()
        cls.certs = Certificates(cls.cert_root.name)
        cls.certs.new('vps', san='IP:192.0.2.10')

    @classmethod
    def tearDownClass(cls):
        cls.cert_root.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=getattr(self, 'TEMP_DIR', None))
        self.root = Path(self.tmp.name)
        self.gid = grp.getgrnam('sboxweb').gr_gid
        self.config_dir = self.root / 'config'
        self.state_dir = self.root / 'provision'
        self.worker = p6.Provisioner(str(self.state_dir), str(self.config_dir), fixture=True)
        self.binding = {'v': 1, 'server_id': 'a' * 32,
                        'ingest_url': 'https://192.0.2.10:38443' + p6.INGEST_PATH,
                        'certificate_sha256': self.certs.pin('vps')}
        self.write_binding()
        self.registry = RemoteRegistry(str(self.config_dir / 'remote-probes.json'),
                                       str(self.config_dir / 'remote-probes.d'))
        self.plane = RemoteIngest(str(self.root / 'evidence'), registry=self.registry)
        self.server, self.request, self.webroot = harness._serve(self.plane)
        self.worker.port = self.server.server_address[1]
        self.worker.proof = lambda row, active: p6.live_proof(self.worker.port, row, active)
        self.generation = 'b' * 64

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.plane.close()
        harness.clean(self.webroot)
        self.tmp.cleanup()

    def write_binding(self, cert='vps'):
        self.worker._write(str(self.config_dir / 'p6-server.json'), p6.encoded(self.binding), 0o600, 0)
        self.worker._write(str(self.config_dir / 'p6-server.pem'), self.certs.pem(cert).encode(), 0o640, self.gid)

    def enroll(self, device='laptop-01', key='enrollment-00000001', name='event-pc'):
        return self.worker.enroll(name, device, self.generation, key, 'office', 'operator-path')

    def state(self):
        return json.loads((self.state_dir / 'devices.json').read_bytes())

    def row(self, device='laptop-01'):
        return next(r for r in self.state()['records'] if r['device'] == device)

    def fail_code(self, code, call):
        with self.assertRaises(p6.ProvisionError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_dark_running_monitor_enrollment_authenticates_without_restart(self):
        self.assertFalse(self.plane.configured())
        result = self.enroll()
        self.assertTrue(self.plane.configured())
        self.assertEqual(result['verified'], 'active')
        self.assertTrue(p6.live_proof(self.worker.port, self.row(), True))
        self.assertEqual(self.plane.store.status()['receipt_count'], 0)
        self.assertEqual(self.plane.store.status()['sample_count'], 0)
        self.assertEqual(self.plane.store.status()['run_count'], 0)

    def test_same_client_two_devices_have_independent_random_keys(self):
        a = self.enroll()
        b = self.enroll('laptop-02', 'enrollment-00000002')
        self.assertNotEqual(a['probe_id'], b['probe_id'])
        self.assertNotEqual(self.row()['secret'], self.row('laptop-02')['secret'])
        self.assertEqual(len(bytes.fromhex(self.row()['secret'])), 32)
        for row in self.state()['records']:
            self.assertNotIn(row['secret'], json.dumps(self.worker.listing('event-pc')))
        self.assertEqual(a['server_id'], self.binding['server_id'])
        self.assertEqual(a['certificate_sha256'], self.binding['certificate_sha256'])

    def test_same_enrollment_retry_is_stable_after_worker_reopen(self):
        original = self.enroll()
        secret = self.row()['secret']
        again = p6.Provisioner(str(self.state_dir), str(self.config_dir), self.worker.port, fixture=True)
        result = again.enroll('event-pc', 'laptop-01', self.generation,
                              'enrollment-00000001', 'office', 'operator-path')
        self.assertEqual({k: v for k, v in result.items() if k != 'verified_epoch'},
                         {k: v for k, v in original.items() if k != 'verified_epoch'})
        self.assertGreaterEqual(result['verified_epoch'], original['verified_epoch'])
        self.assertEqual(self.row()['secret'], secret)

    def test_idempotency_semantic_conflict_and_duplicate_slot_refused(self):
        self.enroll()
        self.fail_code('E_P6_IDEMPOTENCY_CONFLICT', lambda: self.enroll('different'))
        self.fail_code('E_P6_DEVICE_EXISTS', lambda: self.enroll(key='enrollment-00000099'))
        self.assertEqual(len(self.state()['records']), 1)

    def test_revoke_live_old_secret_fails_and_other_device_stays_active(self):
        self.enroll()
        self.enroll('laptop-02', 'enrollment-00000002')
        old = self.row()
        self.assertEqual(self.worker.revoke('event-pc', 'laptop-01'), {'revoked': True, 'count': 1})
        self.assertTrue(p6.live_proof(self.worker.port, old, False))
        self.assertTrue(p6.live_proof(self.worker.port, self.row('laptop-02'), True))
        self.assertFalse((self.config_dir / 'remote-probes.d' / (old['probe_id'] + '.key')).exists())

    def test_revoked_enrollment_retry_never_reactivates_or_rotates(self):
        result = self.enroll()
        original = self.row()
        self.worker.revoke('event-pc', 'laptop-01')
        replay = self.enroll()
        self.assertEqual(replay['probe_id'], result['probe_id'])
        self.assertEqual(replay['verified'], 'revoked')
        self.assertEqual(self.row()['secret'], original['secret'])
        self.assertTrue(p6.live_proof(self.worker.port, original, False))
        self.assertEqual(self.worker.revoke('event-pc', 'laptop-01')['count'], 1)

    def test_live_failure_is_pending_and_same_retry_recovers_original_identity(self):
        proof = self.worker.proof
        self.worker.proof = lambda *args: False
        self.fail_code('E_P6_LIVE_UNCONFIRMED', self.enroll)
        row = self.row()
        self.assertEqual(row['verified'], 'pending')
        self.worker.proof = proof
        self.assertEqual(self.enroll()['probe_id'], row['probe_id'])
        self.assertEqual(self.row()['secret'], row['secret'])

    def test_revoke_failure_has_durable_pending_retirement_and_retry(self):
        self.enroll()
        original = self.row()
        proof = self.worker.proof
        self.worker.proof = lambda *args: False
        self.fail_code('E_P6_LIVE_UNCONFIRMED', lambda: self.worker.revoke('event-pc', 'laptop-01'))
        self.assertEqual((self.row()['desired'], self.row()['verified']), ('revoked', 'pending'))
        self.assertTrue(p6.live_proof(self.worker.port, original, False))
        self.worker.proof = proof
        self.worker.revoke('event-pc', 'laptop-01')
        self.assertEqual(self.row()['verified'], 'revoked')

    def test_crash_at_each_publication_boundary_reuses_identity(self):
        for index, phase in enumerate(('intent_durable', 'keys_durable', 'registry_durable', 'live_confirmed')):
            def child():
                worker = p6.Provisioner(str(self.state_dir), str(self.config_dir), self.worker.port,
                                       fixture=True, fault=lambda value: os._exit(91) if value == phase else None)
                worker.enroll('event-pc', 'device-' + str(index), self.generation,
                              'enrollment-crash-' + str(index), 'office', 'operator-path')
            process = multiprocessing.get_context('fork').Process(target=child)
            process.start(); process.join(8)
            if process.is_alive():
                process.kill(); process.join()
                self.fail('crash fixture exceeded bound')
            self.assertEqual(process.exitcode, 91)
            original = self.row('device-' + str(index))
            restored = self.enroll('device-' + str(index), 'enrollment-crash-' + str(index))
            self.assertEqual(restored['probe_id'], original['probe_id'])
            self.assertEqual(self.row('device-' + str(index))['secret'], original['secret'])

    def test_real_process_crash_revocation_recovers_tombstone(self):
        for index, phase in enumerate(('intent_durable', 'keys_durable', 'registry_durable', 'live_confirmed')):
            device = 'device-' + str(index)
            self.enroll(device, 'enrollment-crash-' + str(index))
            original = self.row(device)
            def child():
                worker = p6.Provisioner(str(self.state_dir), str(self.config_dir), self.worker.port,
                                       fixture=True, fault=lambda value: os._exit(91) if value == phase else None)
                worker.revoke('event-pc', device)
            process = multiprocessing.get_context('fork').Process(target=child)
            process.start(); process.join(8)
            if process.is_alive():
                process.kill(); process.join()
                self.fail('crash fixture exceeded bound')
            self.assertEqual(process.exitcode, 91)
            self.worker.revoke('event-pc', device)
            self.assertEqual(self.row(device)['verified'], 'revoked')
            self.assertTrue(p6.live_proof(self.worker.port, original, False))

    def test_interrupted_staging_cleanup_preserves_unrelated_files(self):
        self.enroll()
        staged = self.state_dir / '.p6-interrupted'
        self.worker._write(str(staged), b'private staging', 0o600, 0)
        unrelated = self.config_dir / 'monitor.conf'
        unrelated.write_text('existing config')
        self.enroll()
        self.assertFalse(staged.exists())
        self.assertEqual(unrelated.read_text(), 'existing config')

    def test_existing_monitor_config_directory_is_preserved(self):
        os.chown(self.config_dir, 0, 0); os.chmod(self.config_dir, 0o755)
        again = p6.Provisioner(str(self.state_dir), str(self.config_dir), self.worker.port, fixture=True)
        result = again.enroll('event-pc', 'laptop-01', self.generation,
                             'enrollment-00000001', 'office', 'operator-path')
        self.assertEqual(result['verified'], 'active')
        st = self.config_dir.stat()
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (0, 0, 0o755))

    def test_real_systemd_sandbox_can_publish_group_owned_keys_and_prove_live(self):
        self.assertTrue(Path('/run/systemd/system').is_dir(), 'real systemd fixture required')
        # Own only this random /run directory. The transient unit uses the
        # shipped sandbox properties, with write paths narrowed to the fixture.
        with tempfile.TemporaryDirectory(prefix='p6b2-sandbox-', dir='/run') as root:
            state = Path(root) / 'state'
            config = Path(root) / 'config'
            worker = p6.Provisioner(str(state), str(config), self.worker.port, fixture=True)
            worker._write(str(config / 'p6-server.json'), p6.encoded(self.binding), 0o600, 0)
            worker._write(str(config / 'p6-server.pem'), self.certs.pem('vps').encode(), 0o640, self.gid)
            self.registry.config_path = str(config / 'remote-probes.json')
            self.registry.key_dir = str(config / 'remote-probes.d')
            keys = {'ProtectSystem', 'ProtectHome', 'PrivateTmp', 'PrivateDevices',
                    'NoNewPrivileges', 'RestrictAddressFamilies', 'IPAddressDeny',
                    'IPAddressAllow', 'CapabilityBoundingSet', 'RestrictSUIDSGID',
                    'SystemCallArchitectures', 'LockPersonality'}
            template = (ROOT / 'sbox-cm/deploy/sbox-cm.service.in').read_text()
            properties = [line for line in template.splitlines() if '=' in line and
                          line.split('=', 1)[0] in keys]
            self.assertEqual(len(properties), len(keys))
            command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                       '--unit=P6B2Fixture' + os.urandom(8).hex()]
            for prop in properties + ['ReadWritePaths=' + root]:
                command.extend(['--property', prop])
            for name, value in {'SBOX_CM_TEST_SANDBOX': '1', 'SB_P6_STATE_DIR': str(state),
                               'SB_P6_CONFIG_DIR': str(config), 'SB_P6_MONITOR_PORT': str(self.worker.port)}.items():
                command.append('--setenv=' + name + '=' + value)
            command.extend([sys.executable, '-I', str(ROOT / 'sbox-cm/p6_provision.py'), 'enroll'])
            result = subprocess.run(command, input=p6.encoded({'name': 'event-pc',
                'device': 'laptop-01', 'client_generation': self.generation,
                'idempotency_key': 'enrollment-00000001', 'site_label': 'office',
                'path_label': 'operator-path'}), capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            response = json.loads(result.stdout)
            self.assertTrue(response['ok'], response)
            row = worker._load()['records'][0]
            self.assertTrue(p6.live_proof(self.worker.port, row, True))
            key = config / 'remote-probes.d' / (row['probe_id'] + '.key')
            st = key.stat()
            self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (0, self.gid, 0o640))

    def test_concurrent_same_enrollment_has_one_identity(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.enroll(), range(4)))
        self.assertEqual(len({r['probe_id'] for r in results}), 1)
        self.assertEqual(len(self.state()['records']), 1)

    def test_concurrent_enroll_revoke_final_secret_disabled(self):
        self.enroll()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.enroll), pool.submit(self.worker.revoke, 'event-pc', 'laptop-01')]
            for future in futures:
                future.result()
        self.assertEqual(self.row()['verified'], 'revoked')
        self.assertTrue(p6.live_proof(self.worker.port, self.row(), False))

    def test_revoke_drains_inflight_authenticated_commit(self):
        result = self.enroll()
        original = self.row()
        sample = harness._sample(1, probe=result['probe_id'], epoch=int(time.time()))
        raw, headers = harness.body_for(sample, key=bytes.fromhex(original['secret']),
                                       probe=result['probe_id'], epoch=int(time.time()))
        # The older P6B fixture signs its fixed NOW; this live fixture needs
        # refreshed transport freshness while preserving exact sample bytes.
        sent = int(time.time())
        headers['X-Remote-Probe-Sent-Epoch'] = str(sent)
        headers['X-Remote-Probe-Signature'] = harness.pl.sign(bytes.fromhex(original['secret']),
                result['probe_id'], sent, sample['run'], sample['seq'], raw)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        real = self.plane.store.accept
        def delayed(*args):
            entered.set()
            if not release.wait(3):
                raise AssertionError('fixture commit not released')
            return real(*args)
        with patch.object(self.plane.store, 'accept', delayed):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                ingest = pool.submit(harness.post, self.request, raw, headers)
                self.assertTrue(entered.wait(2))
                def revoke():
                    response = self.worker.revoke('event-pc', 'laptop-01')
                    finished.set()
                    return response
                retiring = pool.submit(revoke)
                self.assertFalse(finished.wait(0.1))
                release.set()
                self.assertEqual(ingest.result()[0], 200)
                self.assertTrue(retiring.result()['revoked'])
        self.assertEqual(harness.post(self.request, raw, headers)[0], 401)
        self.assertEqual(self.plane.store.status()['receipt_count'], 1)
        self.assertEqual(self.plane.store.status()['sample_count'], 1)
        self.assertTrue(self.plane.read_samples(sample['sample_epoch'], sample['sample_epoch'] + 1)[0]['mapping_retired'])

    def test_changed_binding_refused_without_key_rotation(self):
        self.enroll()
        original = self.row()
        self.binding['server_id'] = 'c' * 32
        self.write_binding()
        self.fail_code('E_P6_BINDING_CHANGED', self.enroll)
        self.assertEqual(self.row(), original)

    def test_operator_changed_managed_row_is_not_silently_reactivated(self):
        self.enroll()
        rows = self.worker._registry()
        rows[0]['enabled'] = False
        self.worker._write(self.worker.config, p6.encoded({'v': 1, 'probes': rows}), 0o640, self.gid)
        self.fail_code('E_P6_REGISTRY_CHANGED', self.enroll)
        self.assertFalse(self.worker._registry()[0]['enabled'])

    def test_bad_pin_ip_san_expired_and_missing_binding_refused(self):
        original_url = self.binding['ingest_url']
        for url in ('https://192.0.2.10:' + '0' * 280 + '38443' + p6.INGEST_PATH,
                    'https://192.0.2.10:\n38443' + p6.INGEST_PATH):
            self.binding['ingest_url'] = url
            self.write_binding()
            self.fail_code('E_P6_BINDING', self.enroll)
            self.assertFalse((self.state_dir / 'devices.json').exists())
        self.binding['ingest_url'] = original_url
        for certificate in ('server', 'expired'):
            self.binding['certificate_sha256'] = self.certs.pin(certificate)
            self.write_binding(certificate)
            self.fail_code('E_P6_BINDING', self.enroll)
        self.binding['certificate_sha256'] = '0' * 64
        self.write_binding()
        self.fail_code('E_P6_BINDING', self.enroll)
        (self.config_dir / 'p6-server.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.enroll()
        self.assertFalse((self.state_dir / 'devices.json').exists())

    def test_malformed_binding_url_has_precise_closed_binding_error(self):
        for url in ('https://192.0.2.10:bad' + p6.INGEST_PATH, 'https://[bad]:38443' + p6.INGEST_PATH,
                    'https://:38443' + p6.INGEST_PATH, 'https://localhost:38443' + p6.INGEST_PATH):
            self.binding['ingest_url'] = url
            self.write_binding()
            self.fail_code('E_P6_BINDING', self.enroll)
            self.assertFalse((self.state_dir / 'devices.json').exists())

    def test_unknown_paths_and_browser_authority_fields_rejected_by_rpc(self):
        from importlib.machinery import SourceFileLoader
        rpc = SourceFileLoader('p6_rpc', str(ROOT / 'sbox-cm/sbox-cm')).load_module()
        request = {'v': rpc.RPC_VERSION, 'request_id': 'request-provision-0001', 'op': 'probe.enroll',
                   'name': 'event-pc', 'device': 'laptop-01', 'idempotency_key': 'enrollment-00000001',
                   'site_label': 'office', 'path_label': 'operator-path'}
        op, args = rpc.validate_request(request)
        self.assertEqual(op, 'probe.enroll')
        self.assertNotIn('client_generation', args)
        for field in ('secret', 'client_generation', 'ingest_url', 'certificate_sha256', 'key_file'):
            with self.assertRaises(rpc.RpcError):
                rpc.validate_request(request | {field: 'chosen-by-browser'})

    def test_real_rpc_lifecycle_responses_bypass_replay_cache(self):
        from importlib.machinery import SourceFileLoader
        import struct
        rpc = SourceFileLoader('p6_rpc_cache', str(ROOT / 'sbox-cm/sbox-cm')).load_module()
        calls = []
        def worker(op, args):
            calls.append(op)
            return {'ok': True, 'data': {'attempt': len(calls)}, 'warnings': [], 'transaction': {}}
        rpc.allowed_uid = lambda: os.getuid()
        rpc.run_worker = worker
        for op in ('probe.enroll', 'probe.revoke', 'probe.list'):
            request = {'v': rpc.RPC_VERSION, 'request_id': 'same-request-00000001', 'op': op, 'name': 'event-pc'}
            if op != 'probe.list':
                request['device'] = 'laptop-01'
            if op == 'probe.enroll':
                request.update(idempotency_key='enrollment-00000001', site_label='office', path_label='path')
            responses = []
            for _ in range(2):
                client, server = socket.socketpair()
                thread = threading.Thread(target=rpc.handle_connection, args=(server, os.getuid()))
                thread.start()
                raw = p6.encoded(request)
                client.sendall(struct.pack('>I', len(raw)) + raw)
                size = struct.unpack('>I', client.recv(4))[0]
                response = b''
                while len(response) < size:
                    response += client.recv(size - len(response))
                responses.append(json.loads(response))
                client.close(); thread.join(2)
            self.assertTrue(all(r['ok'] for r in responses))
            self.assertNotEqual(responses[0]['data'], responses[1]['data'])
        self.assertEqual(len(calls), 6)

    def test_registry_capacity_includes_manual_identities_and_no_eviction(self):
        self.worker._directory(str(self.config_dir / 'remote-probes.d'), 0o750, self.gid)
        manual = [{'probe_id': 'manual-' + str(i), 'enabled': False,
                   'site_label': 'site', 'path_label': 'path', 'key_file': 'manual-' + str(i) + '.key'}
                  for i in range(64)]
        self.worker._write(str(self.config_dir / 'remote-probes.json'), p6.encoded({'v': 1, 'probes': manual}), 0o640, self.gid)
        original = (self.config_dir / 'remote-probes.json').read_bytes()
        self.fail_code('E_P6_CAPACITY', self.enroll)
        self.assertEqual((self.config_dir / 'remote-probes.json').read_bytes(), original)
        self.assertFalse((self.state_dir / 'devices.json').exists())

    def test_root_state_tombstone_capacity_fails_closed(self):
        self.enroll()
        with patch.object(p6, 'MAX_RECORDS', 1):
            self.fail_code('E_P6_CAPACITY', lambda: self.enroll('laptop-02', 'enrollment-00000002'))
        self.assertEqual(len(self.state()['records']), 1)

    def test_tombstone_listing_pagination_keeps_rpc_frame_bounded(self):
        self.enroll()
        state = self.state()
        original = state['records'][0]
        state['records'] = [original | {'probe_id': 'p6-%032x' % i,
            'device': 'device-' + str(i), 'enrollment': '%064x' % i,
            'desired': 'revoked', 'verified': 'revoked'} for i in range(150)]
        self.worker._save(state)
        seen, cursor = [], None
        while True:
            page = self.worker.listing('event-pc', cursor)
            self.assertLess(len(p6.encoded(page)), 60000)
            self.assertLessEqual(len(page['devices']), 64)
            seen.extend(row['probe_id'] for row in page['devices'])
            cursor = page['next_cursor']
            if cursor is None:
                break
        self.assertEqual(len(seen), 150)
        self.assertEqual(len(set(seen)), 150)

    def test_many_pending_retirements_checkpoint_bounded_batches(self):
        self.enroll()
        state = self.state()
        original = state['records'][0]
        state['records'] = [original | {'probe_id': 'p6-%032x' % i,
            'device': 'device-' + str(i), 'enrollment': '%064x' % i,
            'desired': 'revoked', 'verified': 'pending', 'verified_epoch': None}
                           for i in range(66)]
        self.worker._save(state)
        calls = []
        proof = self.worker.proof
        def counted(row, active):
            calls.append(row['probe_id'])
            return proof(row, active)
        self.worker.proof = counted
        self.fail_code('E_P6_CONFIRM_PENDING', lambda: self.worker.revoke('event-pc'))
        self.assertEqual(len(calls), 64)
        self.assertEqual(sum(row['verified'] == 'revoked' for row in self.state()['records']), 64)
        result = self.worker.revoke('event-pc')
        self.assertTrue(result['revoked'])
        self.assertEqual(len(calls), 66)
        self.assertEqual(sum(row['verified'] == 'revoked' for row in self.state()['records']), 66)

    def test_manual_registry_rows_and_keys_preserved(self):
        self.enroll()
        registry = self.worker._registry()
        registry.append({'probe_id': 'manual', 'enabled': True, 'site_label': 'other',
                         'path_label': 'other', 'key_file': 'manual.key'})
        key_path = self.config_dir / 'remote-probes.d/manual.key'
        self.worker._write(str(key_path), b'c' * 64 + b'\n', 0o640, self.gid)
        self.worker._write(self.worker.config, p6.encoded({'v': 1, 'probes': registry}), 0o640, self.gid)
        self.worker.revoke('event-pc')
        self.assertEqual(self.worker._registry(), [registry[-1]])
        self.assertEqual(key_path.read_bytes(), b'c' * 64 + b'\n')

    def test_real_modes_ownership_and_non_root_state_refused(self):
        self.enroll()
        for path, mode, gid in ((self.state_dir, 0o700, 0),
                (self.state_dir / 'devices.json', 0o600, 0),
                (self.config_dir / 'remote-probes.d', 0o750, self.gid),
                (self.config_dir / 'remote-probes.json', 0o640, self.gid),
                (Path(self.worker.gate), 0o640, self.gid)):
            info = path.lstat()
            self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (0, gid, mode))
        path = self.state_dir / 'devices.json'
        os.chmod(path, 0o640)
        self.fail_code('E_P6_AUTHORITY', self.enroll)

    def test_symlink_gate_key_state_and_directory_fail_closed(self):
        self.enroll()
        for path in (Path(self.worker.gate), self.state_dir / 'devices.json',
                     self.config_dir / 'remote-probes.d' / (self.row()['probe_id'] + '.key')):
            original = path.with_name(path.name + '.saved')
            path.rename(original)
            path.symlink_to(original)
            self.fail_code('E_P6_AUTHORITY', self.enroll)
            path.unlink(); original.rename(path)
        original = self.config_dir / 'remote-probes.d'
        backup = self.config_dir / 'keys.saved'
        original.rename(backup); original.symlink_to(backup, target_is_directory=True)
        self.fail_code('E_P6_AUTHORITY', self.enroll)
        original.unlink(); backup.rename(original)

    def test_hardlinked_key_and_changed_secret_are_not_overwritten(self):
        self.enroll()
        path = self.config_dir / 'remote-probes.d' / (self.row()['probe_id'] + '.key')
        link = self.root / 'key-link'
        os.link(path, link)
        self.fail_code('E_P6_AUTHORITY', self.enroll)
        link.unlink()
        path.write_bytes(b'0' * 64 + b'\n')
        self.fail_code('E_P6_KEY_CHANGED', self.enroll)
        self.assertEqual(path.read_bytes(), b'0' * 64 + b'\n')

    def test_corrupt_state_and_registry_are_not_replaced(self):
        self.enroll()
        state = (self.state_dir / 'devices.json').read_bytes()
        (self.state_dir / 'devices.json').write_bytes(b'{}')
        self.fail_code('E_P6_STATE', self.enroll)
        self.assertEqual((self.state_dir / 'devices.json').read_bytes(), b'{}')
        (self.state_dir / 'devices.json').write_bytes(state)
        Path(self.worker.config).write_bytes(b'{"v":1,"probes":[{}]}')
        self.fail_code('E_P6_REGISTRY', self.enroll)
        self.assertEqual(Path(self.worker.config).read_bytes(), b'{"v":1,"probes":[{}]}')

    def test_proof_hmac_is_shared_protocol_and_never_evidence(self):
        self.enroll()
        row = self.row()
        headers = p6.proof_headers(row['probe_id'], row['secret'])
        self.assertTrue(verify_signature(bytes.fromhex(row['secret']), row['probe_id'],
                        int(headers['X-Remote-Probe-Sent-Epoch']), headers['X-Remote-Probe-Run'],
                        1, b'{}', headers['X-Remote-Probe-Signature']))
        wrong = row | {'secret': '0' * 64}
        self.assertFalse(p6.live_proof(self.worker.port, wrong, True))
        self.assertEqual(self.plane.store.status()['receipt_count'], 0)

    def setup_client_worker(self):
        proxy = self.root / 'proxy'
        proxy.mkdir()
        self.proxy_config = proxy / 'server.json'
        self.proxy_config.write_text(json.dumps({'inbounds': [
            {'type': 'vless', 'tag': 'vless-in', 'users': [{'name': 'legacy', 'uuid': 'legacy-uuid', 'flow': 'xtls-rprx-vision'}]},
            {'type': 'hysteria2', 'tag': 'hy2-in', 'users': [{'name': 'legacy', 'password': 'legacy-pass'}]}]}))
        shim = self.root / 'shim'
        shim.mkdir()
        mock = proxy / 'sing-box'
        mock.write_text('#!/bin/bash\ncase "$1" in\ncheck) exit 0;;\ngenerate) cat /proc/sys/kernel/random/uuid;;\nesac\n')
        mock.chmod(0o755)
        for name, body in (('systemctl', 'exit 0'), ('pgrep', 'exit 1')):
            file = shim / name
            file.write_text('#!/bin/bash\n' + body + '\n'); file.chmod(0o755)
        self.env = os.environ | {'SBOX_CM_TEST_SANDBOX': '1', 'SB_SERVER_CONFIG': str(self.proxy_config),
            'SB_STATE_FILE': str(proxy / 'config'), 'SB_CLIENTS_DIR': str(proxy / 'clients'),
            'SB_SING_BOX_BIN': str(mock), 'SB_LOCK_FILE': str(proxy / 'config.lock'),
            'SB_CM_STATE_DIR': str(proxy / 'state'), 'SB_CM_LIB_DIR': str(ROOT / 'lib'),
            'SB_P6_STATE_DIR': str(self.state_dir), 'SB_P6_CONFIG_DIR': str(self.config_dir),
            'SB_P6_MONITOR_PORT': str(self.worker.port), 'PATH': str(shim) + ':' + os.environ['PATH']}
        self.call_worker('management.activate')
        self.assertTrue(self.call_worker('client.add', name='event-pc', idempotency_key='client-add-000001')['ok'])

    def call_worker(self, op, **args):
        args['request_id'] = 'request-' + os.urandom(12).hex()
        result = subprocess.run(['bash', str(ROOT / 'sbox-cm/sbox-cm-ops'), op],
                                input=p6.encoded(args), env=self.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_real_client_worker_enrollment_and_retirement_gate(self):
        self.setup_client_worker()
        result = self.call_worker('probe.enroll', name='event-pc', device='laptop-01',
                idempotency_key='enrollment-00000001', site_label='office', path_label='path')
        self.assertTrue(result['ok'], result)
        row = self.row()
        self.assertTrue(p6.live_proof(self.worker.port, row, True))
        listing = self.call_worker('probe.list', name='event-pc')
        self.assertNotIn(row['secret'], json.dumps(listing))
        result = self.call_worker('client.delete', name='event-pc', idempotency_key='client-delete-0001')
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['data']['deleted'])
        self.assertEqual(self.row()['verified'], 'revoked')
        self.assertTrue(p6.live_proof(self.worker.port, row, False))
        self.assertNotIn('event-pc', self.proxy_config.read_text())

    def test_delete_client_proof_failure_preserves_account_and_retry_recovers(self):
        self.setup_client_worker()
        response = self.call_worker('probe.enroll', name='event-pc', device='laptop-01',
                idempotency_key='enrollment-00000001', site_label='office', path_label='path')
        self.assertTrue(response['ok'], response)
        unused = socket.socket(); unused.bind(('127.0.0.1', 0))
        self.env['SB_P6_MONITOR_PORT'] = str(unused.getsockname()[1])
        original = self.proxy_config.read_bytes()
        result = self.call_worker('client.delete', name='event-pc', idempotency_key='client-delete-0001')
        unused.close()
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'E_P6_REVOKE_PENDING')
        self.assertEqual(self.proxy_config.read_bytes(), original)
        self.assertEqual(self.row()['verified'], 'pending')
        self.env['SB_P6_MONITOR_PORT'] = str(self.worker.port)
        retry = self.call_worker('client.delete', name='event-pc', idempotency_key='client-delete-0001')
        self.assertTrue(retry['ok'], retry)
        self.assertEqual(self.row()['verified'], 'revoked')

    def test_retirement_targets_client_generation_not_recreated_account(self):
        self.enroll()
        original = self.row()
        self.worker.revoke('event-pc', generation=self.generation)
        self.generation = 'd' * 64
        self.enroll(key='enrollment-00000002')
        records = self.state()['records']
        fresh = records[-1]
        self.worker.revoke('event-pc', generation=original['client_generation'])
        self.assertTrue(p6.live_proof(self.worker.port, fresh, True))
        self.assertTrue(p6.live_proof(self.worker.port, original, False))

    def call_cli_delete(self):
        installer = (ROOT / 'install.sh').read_text()
        section = installer.split('# >>> phase-c client-management >>>')[1].split('# <<< phase-c client-management <<<')[0]
        phase = self.root / 'phase-c.sh'
        phase.write_text(section)
        env = self.env | {'SB_CLIENT_MANAGEMENT_LIB': str(ROOT / 'lib/client-management.sh'),
                         'SB_P6_PROVISION_SCRIPT': str(ROOT / 'sbox-cm/p6_provision.py')}
        command = 'warning() { echo "$*" >&2; }; info() { echo "$*"; }; error() { echo "$*" >&2; exit 1; }; . "$1"; with_client_lock _delete_client_locked event-pc'
        return subprocess.run(['bash', '-c', command, 'fixture', str(phase)], env=env, capture_output=True, timeout=30)

    def test_main_cli_delete_retires_via_same_live_worker_before_proxy_commit(self):
        self.setup_client_worker()
        self.assertTrue(self.call_worker('probe.enroll', name='event-pc', device='laptop-01',
                idempotency_key='enrollment-00000001', site_label='office', path_label='path')['ok'])
        row = self.row()
        result = self.call_cli_delete()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn('event-pc', self.proxy_config.read_text())
        self.assertTrue(p6.live_proof(self.worker.port, row, False))
        self.assertEqual(self.row()['verified'], 'revoked')
        self.assertNotIn(row['secret'], (result.stdout + result.stderr).decode())

    def test_main_cli_delete_unconfirmed_revocation_preserves_client_retry_recovers(self):
        self.setup_client_worker()
        self.assertTrue(self.call_worker('probe.enroll', name='event-pc', device='laptop-01',
                idempotency_key='enrollment-00000001', site_label='office', path_label='path')['ok'])
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0))
            self.env['SB_P6_MONITOR_PORT'] = str(unused.getsockname()[1])
            original = self.proxy_config.read_bytes()
            result = self.call_cli_delete()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.proxy_config.read_bytes(), original)
            self.assertEqual(self.row()['verified'], 'pending')
        self.env['SB_P6_MONITOR_PORT'] = str(self.worker.port)
        self.assertEqual(self.call_cli_delete().returncode, 0)
        self.assertEqual(self.row()['verified'], 'revoked')

    def test_main_cli_delete_without_p6_preserves_original_non_p6_behavior(self):
        self.setup_client_worker()
        self.assertEqual(self.call_cli_delete().returncode, 0)
        self.assertNotIn('event-pc', self.proxy_config.read_text())


if __name__ == '__main__':
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Linux root fixture required; no skipped acceptance')
    result = unittest.main(verbosity=2, exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    # The native root CI entry exercises the sensitive download chain too;
    # report its independent count, without rediscovering the original suite.
    for suite in ('test_bundle_linux.py', 'test_distribution_linux.py'):
        code = subprocess.call([sys.executable, str(ROOT / 'tests/remote-production' / suite)])
        if code:
            raise SystemExit(code)
    raise SystemExit(0)
