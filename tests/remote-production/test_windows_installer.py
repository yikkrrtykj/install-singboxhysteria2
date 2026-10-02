"""Portable installer import/controller/state tests. Native SCM is separate."""
import copy
import http.server
import io
import json
import os
from pathlib import Path
import sys
import threading
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'windows'))
sys.path.insert(0, str(ROOT / 'tests/remote-production'))
from test_bundle import BundleTests
from test_foundations import fixture_policy
from p6installer.bundle import read_bundle, verify_controller
from remote_probe.agent import ConfigError
from remote_probe.profiles import ProfileVault


class Controller(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.seen.append((self.command, self.path, self.headers.get('Authorization')))
        value = {'version': 'fixture'} if self.path == '/version' else self.server.nodes
        code = 200
        if self.headers.get('Authorization') != self.server.authorization:
            code = 401
        if self.server.redirect:
            code = 302
        raw = json.dumps(value).encode()
        if self.server.oversized:
            raw = b' ' * (512 * 1024 + 1)
        self.send_response(code)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (OSError, ConnectionError):
            pass


def controller(profile, secret=''):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Controller)
    server.seen = []
    server.redirect = server.oversized = False
    server.authorization = ('Bearer ' + secret) if secret else None
    server.nodes = {'proxies': {name: {} for name in ('Reality', 'Hysteria2', '自动选择')}}
    profile['agent']['mihomo_url'] = 'http://127.0.0.1:' + str(server.server_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BundleTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        BundleTests.tearDownClass()

    def setUp(self):
        self.bundle_fixture = BundleTests('test_repeat_bundle_does_not_rotate_or_add_download_timestamp')
        self.bundle_fixture.setUp()
        self.addCleanup(self.bundle_fixture.tearDown)
        self.path = self.bundle_fixture.root / 'bundle.zip'
        self.path.write_bytes(self.bundle_fixture.bundle())
        self.artifact = self.bundle_fixture.manifest
        self.profile = copy.deepcopy(self.bundle_fixture.profile)

    def edit(self, transform):
        with zipfile.ZipFile(self.path) as archive:
            values = [(item, archive.read(item)) for item in archive.infolist()]
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            for item, data in transform(values):
                archive.writestr(item, data)
        self.path.write_bytes(raw.getvalue())

    def server(self, secret=''):
        server = controller(self.profile, secret)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_exact_bundle_import_parts_are_passive_and_do_not_extract(self):
        before = set(self.path.parent.iterdir())
        profile, key, certificate = read_bundle(self.path, self.artifact)
        self.assertEqual(profile, self.profile)
        self.assertEqual(key, bytes.fromhex('b' * 64))
        self.assertEqual(certificate, self.bundle_fixture.parts['certificate'])
        self.assertEqual(set(self.path.parent.iterdir()), before)

    def test_duplicate_zip_member_refused(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.edit(lambda values: values + [values[0]])
        with self.assertRaises(ConfigError):
            read_bundle(self.path, self.artifact)

    def test_traversal_and_symlink_zip_members_refused(self):
        for name in ('../escape', 'C:/escape', 'profile.json:stream'):
            self.path.write_bytes(self.bundle_fixture.bundle())
            self.edit(lambda values: [(name, values[0][1])] + values[1:])
            with self.assertRaises(ConfigError):
                read_bundle(self.path, self.artifact)
        self.path.write_bytes(self.bundle_fixture.bundle())
        def symlink(values):
            values[0][0].external_attr = 0o120777 << 16
            return values
        self.edit(symlink)
        with self.assertRaises(ConfigError):
            read_bundle(self.path, self.artifact)

    def test_compressed_bomb_is_refused_before_read(self):
        def compressed(values):
            for item, _ in values:
                item.compress_type = zipfile.ZIP_DEFLATED
            return values
        self.edit(compressed)
        with self.assertRaises(ConfigError):
            read_bundle(self.path, self.artifact)

    def test_installed_artifact_is_authority_not_bundle_code(self):
        changed = copy.deepcopy(self.artifact)
        changed['sha256'] = '0' * 64
        with self.assertRaises(ConfigError):
            read_bundle(self.path, changed)

    def test_duplicate_json_keys_fail_closed(self):
        self.edit(lambda values: [(item, b'{"v":1,"v":1}' if item.filename == 'profile.json' else data)
                                  for item, data in values])
        with self.assertRaises(ConfigError):
            read_bundle(self.path, self.artifact)

    def test_wrong_pin_refused_without_key_disclosure(self):
        def change(values):
            result = []
            for item, data in values:
                if item.filename == 'profile.json':
                    value = json.loads(data)
                    value['certificate_sha256'] = '0' * 64
                    data = json.dumps(value).encode()
                result.append((item, data))
            return result
        self.edit(change)
        with self.assertRaises(ConfigError) as caught:
            read_bundle(self.path, self.artifact)
        self.assertNotIn('b' * 64, str(caught.exception))

    def test_controller_uses_only_two_read_only_gets_and_auth_header(self):
        server = self.server('local-secret')
        self.assertEqual(verify_controller(self.profile, 'local-secret'), {'controller': 'verified', 'nodes': 'verified'})
        self.assertEqual(server.seen, [('GET', '/version', 'Bearer local-secret'),
                                      ('GET', '/proxies', 'Bearer local-secret')])

    def test_wrong_auth_redirect_and_oversize_refused(self):
        server = self.server('local-secret')
        with self.assertRaises(ConfigError):
            verify_controller(self.profile, 'wrong-secret')
        server.redirect = True
        with self.assertRaises(ConfigError):
            verify_controller(self.profile, 'local-secret')
        server.redirect, server.oversized = False, True
        with self.assertRaises(ConfigError):
            verify_controller(self.profile, 'local-secret')

    def test_missing_explicit_nodes_never_report_path_failure(self):
        server = self.server()
        for name in ('Reality', 'Hysteria2', '自动选择'):
            server.nodes = {'proxies': {n: {} for n in ('Reality', 'Hysteria2', '自动选择') if n != name}}
            with self.assertRaises(ConfigError) as caught:
                verify_controller(self.profile, '')
            self.assertNotIn('timeout', str(caught.exception))

    def test_nonloopback_and_header_injected_controller_secret_never_send(self):
        server = self.server()
        with self.assertRaises(ConfigError):
            verify_controller(self.profile, 'secret\r\nX: bad')
        self.profile['agent']['mihomo_url'] = 'http://192.0.2.1:9090'
        with self.assertRaises(ConfigError):
            verify_controller(self.profile, 'local-secret')
        self.assertEqual(server.seen, [])

    def test_atomic_local_credential_import_repeat_preserves_pause_and_spool(self):
        vault = ProfileVault(str(self.bundle_fixture.root / 'vault'), fixture_policy()).open()
        key, created = vault.import_profile(self.profile, b'k' * 32, self.bundle_fixture.parts['certificate'],
                                            controller_secret='local-secret')
        self.assertTrue(created)
        vault.set_enabled(key, False)
        spool = Path(vault._path(key)) / 'spool'
        vault._write(str(spool), 'pending-fixture', b'pending bytes')
        key2, created = vault.import_profile(self.profile, b'k' * 32, self.bundle_fixture.parts['certificate'],
                                             controller_secret='local-secret')
        self.assertEqual(key, key2)
        self.assertFalse(created)
        self.assertFalse(vault.enabled(key))
        self.assertEqual(vault.security.read(str(spool / 'pending-fixture'), 128), b'pending bytes')
        with self.assertRaises(ConfigError):
            vault.import_profile(self.profile, b'k' * 32, self.bundle_fixture.parts['certificate'],
                                 controller_secret='changed-secret')
        self.assertEqual(vault.security.read(str(Path(vault._path(key)) / 'mihomo.key'), 4096), b'local-secret')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstallerTests)
    assert suite.countTestCases() == 12
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
