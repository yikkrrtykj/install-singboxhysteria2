"""Portable real generic zipapp and bounded ZIP/Agent-import tests."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'tests/remote-production'))
from test_foundations import Certificates
from web.p6_bundle import assemble, BundleError

spec = importlib.util.spec_from_file_location('build_p6_artifact', ROOT / 'tools/build-p6-artifact.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_tmp = tempfile.TemporaryDirectory()
        cls.certs = Certificates(cls.cert_tmp.name)
        cls.certs.new('bundle', san='IP:192.0.2.10')
        cls.manifest, cls.generic = builder.build()

    @classmethod
    def tearDownClass(cls):
        cls.cert_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.profile = {'v': 1, 'server_id': 'a' * 32, 'probe_id': 'p6-device-one',
                'ingest_url': 'https://192.0.2.10:38443/api/v1/remote-probes/ingest',
                'certificate_sha256': self.certs.pin('bundle'), 'agent': {
                    'mihomo_url': 'http://127.0.0.1:9090', 'reality_node': 'Reality',
                    'hy2_node': 'Hysteria2', 'watched_group': '自动选择', 'dns_host': 'dns.google',
                    'https_host': 'www.gstatic.com', 'egress_host': 'iplark.com',
                    'vps_host': '192.0.2.10', 'vps_port': 443,
                    'cadence': 60, 'cycle_deadline': 20, 'diagnostic_timeout': 5}}
        self.parts = {'format': 'p6-client-bundle-parts/1', 'yaml': 'canonical YAML\n\n',
                      'profile': self.profile, 'secret': 'b' * 64,
                      'certificate': self.certs.pem('bundle'), 'artifact': self.manifest}

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self, parts=None):
        return assemble('event-pc', 'laptop-01', parts or self.parts, self.generic)

    def test_generic_artifact_is_deterministic_and_digest_versioned(self):
        manifest, raw = builder.build()
        self.assertEqual((manifest, raw), (self.manifest, self.generic))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['sha256'])
        self.assertEqual(manifest['version'], 'p6-agent-source-1-' + manifest['sha256'][:16])

    def test_standalone_zipapp_runs_without_repo_or_pythonpath(self):
        path = self.root / 'p6-agent.pyz'
        path.write_bytes(self.generic)
        result = subprocess.run([sys.executable, '-I', str(path), '--help'],
                                cwd=self.root, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'--vault', result.stdout)
        self.assertIn(b'service', result.stdout)

    def test_generic_contains_reviewed_source_only_and_no_credentials(self):
        with zipfile.ZipFile(io.BytesIO(self.generic)) as archive:
            names = set(archive.namelist())
            self.assertEqual(len(names), 19)
            self.assertEqual(archive.read('remote_probe/production_storage.py'),
                             (ROOT / 'monitor-v2/remote_probe/production_storage.py').read_bytes().replace(b'\r\n', b'\n'))
            self.assertEqual(archive.read('remote_probe/production.py'),
                             (ROOT / 'monitor-v2/remote_probe/production.py').read_bytes().replace(b'\r\n', b'\n'))
            self.assertEqual(archive.read('mihomo/client.py'),
                             (ROOT / 'monitor-v2/mihomo/client.py').read_bytes().replace(b'\r\n', b'\n'))
            self.assertFalse(any(name.endswith(('.key', '.pem', '.json')) for name in names))
        self.assertNotIn(self.parts['secret'].encode(), self.generic)
        source = self.root / 'source'
        agent = source / 'monitor-v2/remote_probe'
        agent.mkdir(parents=True)
        for name in builder.AGENT_MODULES:
            shutil.copyfile(ROOT / 'monitor-v2/remote_probe' / name, agent / name)
        (source / 'monitor-v2/mihomo').mkdir()
        for name in ('client.py', 'model.py'):
            shutil.copyfile(ROOT / 'monitor-v2/mihomo' / name, source / 'monitor-v2/mihomo' / name)
        (agent / 'unreviewed.py').write_text('unreviewed-secret-marker')
        with patch.object(builder, 'ROOT', source):
            self.assertEqual(builder.build()[1], self.generic)
            (agent / 'payload.py').unlink()
            with self.assertRaises(FileNotFoundError):
                builder.build()

    def test_bundle_contains_exact_yaml_separate_secret_cert_and_generic(self):
        with patch('socket.socket', side_effect=AssertionError('passive bundle opened socket')), \
                patch('socket.create_connection', side_effect=AssertionError('passive bundle connected')):
            raw = self.bundle()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()), {'event-pc-mihomo.yaml', 'profile.json', 'ingest.key',
                'server.pem', 'agent/p6-agent.pyz', 'agent/artifact.json', 'bundle.json', 'README.txt'})
            self.assertEqual(archive.read('event-pc-mihomo.yaml'), self.parts['yaml'].encode())
            self.assertEqual(archive.read('ingest.key'), (self.parts['secret'] + '\n').encode())
            self.assertEqual(json.loads(archive.read('profile.json')), self.profile)
            self.assertNotIn(self.parts['secret'], archive.read('profile.json').decode())
            self.assertEqual(archive.read('agent/p6-agent.pyz'), self.generic)
            self.assertNotIn(b'PRIVATE KEY', archive.read('server.pem'))
            self.assertIn(b'separate administrator-published signed download', archive.read('README.txt'))
            self.assertIn(b'P6Setup.exe', archive.read('README.txt'))

    def test_repeat_bundle_does_not_rotate_or_add_download_timestamp(self):
        self.assertEqual(self.bundle(), self.bundle())
        self.assertEqual(self.parts['secret'], 'b' * 64)

    def test_wrong_generic_or_changed_manifest_refused(self):
        with self.assertRaises(BundleError):
            assemble('event-pc', 'laptop-01', self.parts, self.generic + b'tampered')
        changed = copy.deepcopy(self.parts)
        changed['artifact']['size'] += 1
        with self.assertRaises(BundleError):
            self.bundle(changed)

    def test_wrong_certificate_or_pin_refused_without_secret_error(self):
        changed = copy.deepcopy(self.parts)
        changed['profile']['certificate_sha256'] = '0' * 64
        with self.assertRaises(BundleError) as caught:
            self.bundle(changed)
        self.assertEqual(str(caught.exception), 'E_P6_BUNDLE')
        self.assertNotIn(self.parts['secret'], str(caught.exception))

    def test_controller_target_node_and_timing_injection_refused(self):
        for field, value in (('mihomo_url', 'http://192.0.2.11:9090'), ('vps_host', '192.0.2.11'),
                ('reality_node', 'HK-Reality'), ('hy2_node', 'Reality'), ('cadence', 1), ('cycle_deadline', 60)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.parts)
                changed['profile']['agent'][field] = value
                with self.assertRaises(BundleError):
                    self.bundle(changed)

    def test_shape_secret_yaml_and_filename_bounds(self):
        for field, value in (('yaml', 'x' * 32769), ('secret', 'b' * 63), ('secret', 'B' * 64),
                             ('certificate', 'PRIVATE KEY'), ('format', 'unknown'), ('display', None)):

            changed = copy.deepcopy(self.parts)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(BundleError):
                self.bundle(changed)
        changed = copy.deepcopy(self.parts)
        changed['extra'] = 'unexpected'
        with self.assertRaises(BundleError):
            self.bundle(changed)
        for name in ('../escape', 'name\r\nInjected: true', 'a' * 33):
            with self.subTest(name=name), self.assertRaises(BundleError):
                assemble(name, 'laptop-01', self.parts, self.generic)

    def test_real_artifact_import_uses_native_vault_and_keeps_identity(self):
        path = self.root / 'p6-agent.pyz'
        path.write_bytes(self.generic)
        # Actual zipimport in a fresh isolated interpreter: no repository
        # runtime fallback. Windows uses real native SID/DACL fixture policy.
        code = '''import json, os, re, subprocess, sys
sys.path.insert(0, sys.argv[1])
from remote_probe.profiles import ProfileVault, PosixSecurity
from remote_probe.windows_security import WindowsSecurity
from remote_probe.agent import ConfigError
data=json.load(sys.stdin)
security=PosixSecurity()
if os.name == 'nt':
    sid=re.search(r'S-1-[0-9-]+', subprocess.check_output(['whoami','/user','/fo','csv','/nh'],text=True)).group()
    security=WindowsSecurity(fixture_sid=sid)
vault=ProfileVault(sys.argv[2],security=security).open()
key,created=vault.import_profile(data['profile'],bytes.fromhex(data['secret']),data['certificate'])
_,again=vault.import_profile(data['profile'],bytes.fromhex(data['secret']),data['certificate'])
refused=False
try: vault.import_profile(data['profile'],b'z'*32,data['certificate'])
except ConfigError: refused=True
print(json.dumps({'created':created,'again':again,'refused':refused,'key':key}))
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(path), str(self.root / 'vault')],
                                input=json.dumps(self.parts).encode(), cwd=self.root,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        receipt = json.loads(result.stdout)
        self.assertEqual({key: receipt[key] for key in ('created', 'again', 'refused')},
                         {'created': True, 'again': False, 'refused': True})
        self.assertEqual(receipt['key'], hashlib.sha256(('a' * 32 + '\np6-device-one').encode()).hexdigest())
        self.assertNotIn(self.parts['secret'].encode(), result.stdout + result.stderr)

    def test_server_import_does_not_require_client_only_mihomo_or_profile_runtime(self):
        stage = self.root / 'server-only'
        stage.mkdir()
        for package in ('web', 'diagnostics'):
            shutil.copytree(ROOT / 'monitor-v2' / package, stage / package,
                            ignore=shutil.ignore_patterns('__pycache__'))
        probe = stage / 'remote_probe'
        probe.mkdir()
        for name in ('__init__.py', '__main__.py', 'agent.py', 'delivery.py', 'direct_probe.py',
                     'evidence.py', 'mihomo_probe.py', 'payload.py', 'spool.py'):
            shutil.copyfile(ROOT / 'monitor-v2/remote_probe' / name, probe / name)
        for name in ('p6_artifact.py', 'p6_distribution.py'):
            shutil.copyfile(ROOT / 'monitor-v2' / name, stage / name)
        code = 'import sys; sys.path.insert(0,sys.argv[1]); from web.server import MonitorWebApp; print("server_import_ok")'
        result = subprocess.run([sys.executable, '-I', '-c', code, str(stage)],
                                cwd=self.root, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), b'server_import_ok')


if __name__ == '__main__':
    unittest.main(verbosity=2)
