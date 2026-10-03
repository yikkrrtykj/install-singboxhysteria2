"""Scoped controller parser and mutation-free local observation contracts."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'monitor-v2'), str(ROOT / 'windows'), str(ROOT / 'tests/remote-production'), str(ROOT / 'tests/remote-server')]
from p6installer.controller import DiscoveryError, extract_credential, discover_credential, LocalSourceSecurity, SOURCE_LIMIT
from p6installer.status import summarize_spool, latest_sample, snapshot, read_live
from remote_probe.agent import ConfigError
from remote_probe.profiles import canonical
from remote_probe.windows_security import StorageSecurityError
from test_foundations import FixtureBase, fixture_policy
from server_groups import _sample


class DiscoveryTests(unittest.TestCase):
    url = 'http://127.0.0.1:9090'

    def test_exact_controller_and_secret_scalars(self):
        raw = b'external-controller: 127.0.0.1:9090\nsecret: local-only-canary\nproxies:\n  - name: irrelevant\n'
        self.assertEqual(extract_credential(raw, self.url), 'local-only-canary')

    def test_explicit_empty_secret_and_quoted_scalars(self):
        for value in (b"''", b'""'):
            self.assertEqual(extract_credential(b'external-controller: "localhost:9090"\nsecret: ' + value, self.url), '')
        self.assertEqual(extract_credential(b"external-controller: '127.0.0.1:9090'\nsecret: 'a''b'", self.url), "a'b")

    def test_duplicate_alias_and_quoted_keys_fail_closed(self):
        for suffix in (b'secret: second', b'"secret": second', b"'secret': second", b'<<: *shared'):
            with self.subTest(suffix=suffix), self.assertRaises(DiscoveryError):
                extract_credential(b'external-controller: 127.0.0.1:9090\nsecret: first\n' + suffix, self.url)

    def test_unsupported_scalar_shapes_and_document_markers(self):
        for value in (b'', b'null', b'true', b'yes', b'123', b'~', b'&anchor abc', b'*anchor', b'[]', b'{}', b'|', b'>', b'"a" # comment'):
            with self.subTest(value=value), self.assertRaises(DiscoveryError):
                extract_credential(b'external-controller: 127.0.0.1:9090\nsecret: ' + value, self.url)
        with self.assertRaises(DiscoveryError):
            extract_credential(b'---\nexternal-controller: 127.0.0.1:9090\nsecret: abc', self.url)

    def test_missing_or_nested_keys_never_select_another_instance(self):
        for raw in (b'secret: abc', b'external-controller: 127.0.0.1:9090', b'x:\n  external-controller: 127.0.0.1:9090\n  secret: abc'):
            with self.assertRaises(DiscoveryError):
                extract_credential(raw, self.url)

    def test_port_remote_address_and_scheme_mismatch(self):
        for endpoint in ('127.0.0.1:9097', '0.0.0.0:9090', '192.0.2.1:9090', 'example.com:9090', '127.0.0.1:9090/path'):
            with self.subTest(endpoint=endpoint), self.assertRaises(DiscoveryError):
                extract_credential(('external-controller: ' + endpoint + '\nsecret: abc').encode(), self.url)
        with self.assertRaises(DiscoveryError):
            extract_credential(b'external-controller: 127.0.0.1:9090\nsecret: abc', 'https://127.0.0.1:9090')

    def test_bounds_encoding_header_injection_and_redacted_errors(self):
        canary = 'PRIVATE-CANARY'
        for raw in (b'x' * (SOURCE_LIMIT + 1), b'\xff', b'\x00',
                    b'external-controller: 127.0.0.1:9090\nsecret: "PRIVATE-CANARY\\r\\nattack"',
                    ('external-controller: 127.0.0.1:9090\nsecret: ' + canary * 400).encode()):
            with self.assertRaises(DiscoveryError) as caught:
                extract_credential(raw, self.url)
            self.assertNotIn(canary, str(caught.exception))

    def test_unsupported_platform_discovery_is_closed_error(self):
        with patch('p6installer.controller.os.name', 'posix'), self.assertRaises(DiscoveryError):
            discover_credential(self.url)


class SnapshotTests(FixtureBase):
    def setUp(self):
        super().setUp()
        self.policy = fixture_policy()
        self.root = Path(self.temp.name) / 'installation'
        self.policy.mkdir(str(self.root))
        for name in ('retired', 'releases'):
            self.policy.mkdir(str(self.root / name))
        from remote_probe.profiles import ProfileVault
        self.vault = ProfileVault(str(self.root / 'profiles'), self.policy).open()
        self.manifest_value = self.manifest()
        self.key, _ = self.vault.import_profile(self.manifest_value, b'k' * 32, self.certs.pem(), controller_secret='LOCAL-CANARY')
        self.state = {'next_record_id': 5, 'resolved_through': 2, 'acknowledged_total': 2,
                      'quarantined_total': 0, 'expired_total': 0, 'budget_dropped_total': 0,
                      'corrupt_total': 0, 'state_save_failures': 0, 'retry_attempts': {'3': 1}}
        self.path = Path(self.vault._path(self.key)) / 'spool'
        self.vault._write(str(self.path), 'spool.state.json', canonical(self.state))
        self.read_names = []
        self.manager = types.SimpleNamespace(root=self.root, security=self.policy, vault=self.vault,
            _active=lambda: 'a' * 64, _check_release=lambda _: None, _command=lambda _: 'fixture-only',
            service=types.SimpleNamespace(state=lambda _: 4))

    def reader(self, path, limit, tail=False):
        self.read_names.append(Path(path).name)
        return self.policy.read(str(path), limit)

    def tree(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob('*') if p.is_file()}

    def record(self, seq=1):
        sample = _sample(seq, probe='device-one', epoch=1000)
        return {'probe_id': sample['probe_id'], 'run': sample['run'], 'seq': seq,
                'body_b64': base64.b64encode(canonical(sample)).decode()}

    def test_status_never_recovers_mutates_or_reads_credentials(self):
        before = self.tree()
        value = snapshot(self.manager, self.reader)
        self.assertEqual(self.tree(), before)
        self.assertEqual(value['profiles'][0]['spool']['acknowledged_total'], 2)
        self.assertEqual(value['profiles'][0]['spool']['unresolved_record_span'], 2)
        self.assertEqual(value['profiles'][0]['spool']['tracked_retry_records'], 1)
        self.assertNotIn('ingest.key', self.read_names)
        self.assertNotIn('mihomo.key', self.read_names)
        self.assertNotIn('LOCAL-CANARY', json.dumps(value))
        self.assertEqual(value['service_state'], 4)

    def test_pending_intent_is_observed_and_preserved(self):
        for name in ('upgrade.json', 'uninstall.json'):
            self.vault._write(str(self.root), name, b'{"v":1,"intent":"do-not-recover"}')
            before = self.tree()
            result = snapshot(self.manager, self.reader)
            self.assertTrue(result['pending_recovery'])
            self.assertEqual(self.tree(), before)
            self.assertEqual(self.read_names, [])
            (self.root / name).unlink()

    def test_absent_installation_status_does_not_create_it(self):
        absent = self.root / 'absent'
        self.manager.root = absent
        self.assertFalse(snapshot(self.manager, self.reader)['installed'])
        self.assertFalse(absent.exists())

    def test_invalid_counters_and_duplicate_state_are_refused(self):
        for field in self.state:
            if field == 'retry_attempts':
                continue
            changed = copy.deepcopy(self.state)
            changed[field] = True
            with self.assertRaises(ConfigError):
                summarize_spool(canonical(changed))
        for values in ({'resolved_through': 5}, {'acknowledged_total': 5}, {'retry_attempts': []}):
            with self.assertRaises(ConfigError):
                summarize_spool(canonical(dict(self.state, **values)))
        with self.assertRaises(ConfigError):
            summarize_spool(b'{"next_record_id":1,"next_record_id":2}')

    def test_latest_complete_sample_skips_partial_append_and_wrong_probe(self):
        first, second = self.record(1), self.record(2)
        raw = canonical(first) + b'\n' + canonical(second) + b'\n{"incomplete"'
        self.assertEqual(latest_sample(raw, 'device-one')['seq'], 2)
        self.assertIsNone(latest_sample(raw, 'another-device'))
        self.assertEqual(latest_sample(canonical(first) + b'\n', 'device-one')['seq'], 1)

    def test_sample_hash_tuple_and_closed_schema_are_not_inferred(self):
        record = self.record()
        record['seq'] = 999
        self.assertIsNone(latest_sample(canonical(record) + b'\n', 'device-one'))
        record = self.record()
        sample = json.loads(base64.b64decode(record['body_b64']))
        sample['unexpected'] = 'do-not-display'
        record['body_b64'] = base64.b64encode(canonical(sample)).decode()
        self.assertIsNone(latest_sample(canonical(record) + b'\n', 'device-one'))

    def test_snapshot_exposes_selected_metrics_without_full_body(self):
        self.vault._write(str(self.path), 'spool.jsonl', canonical(self.record()) + b'\n')
        result = snapshot(self.manager, self.reader)
        sample = result['profiles'][0]['sample']
        self.assertEqual(sample['seq'], 1)
        self.assertNotIn('body_b64', sample)
        self.assertNotIn('run', sample)
        self.assertNotIn('probe_id', sample)
        self.assertNotIn('flags', sample)

    def test_changed_release_during_snapshot_is_refused(self):
        active = iter(('a' * 64, 'b' * 64))
        self.manager._active = lambda: next(active)
        with self.assertRaises(ConfigError):
            snapshot(self.manager, self.reader)


@unittest.skipUnless(os.name == 'nt', 'native Windows only')
class NativeSourceTests(unittest.TestCase):
    def test_actual_current_user_source_policy_and_writer_sharing(self):
        with tempfile.TemporaryDirectory(prefix='p6-gui-native-') as temp:
            policy = fixture_policy()
            directory = Path(temp) / 'source'
            policy.mkdir(str(directory))
            path = directory / 'config.yaml'
            from remote_probe.profiles import ProfileVault
            ProfileVault(str(directory), policy)._write(str(directory), 'config.yaml', b'external-controller: 127.0.0.1:9090\nsecret: local-native\n')
            source = LocalSourceSecurity()
            self.assertEqual(extract_credential(source.read(str(path), SOURCE_LIMIT), 'http://127.0.0.1:9090'), 'local-native')
            with path.open('ab') as writer:
                self.assertTrue(read_live(policy, path, SOURCE_LIMIT).startswith(b'external-controller:'))
                writer.write(b'# append still allowed\n')
            self.assertTrue(path.read_bytes().endswith(b'# append still allowed\n'))
            bad = subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'], capture_output=True)
            self.assertEqual(bad.returncode, 0)
            with self.assertRaises(StorageSecurityError):
                source.read(str(path), SOURCE_LIMIT)

    def test_actual_hardlink_and_junction_source_refusal(self):
        with tempfile.TemporaryDirectory(prefix='p6-gui-links-') as temp:
            policy = fixture_policy()
            root = Path(temp) / 'source'
            policy.mkdir(str(root))
            from remote_probe.profiles import ProfileVault
            ProfileVault(str(root), policy)._write(str(root), 'config.yaml', b'not-a-credential')
            os.link(root / 'config.yaml', root / 'alias.yaml')
            source = LocalSourceSecurity()
            with self.assertRaises(StorageSecurityError):
                source.read(str(root / 'config.yaml'), SOURCE_LIMIT)
            (root / 'alias.yaml').unlink()
            link = Path(temp) / 'junction'
            result = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(link), str(root)], capture_output=True)
            self.assertEqual(result.returncode, 0)
            try:
                with self.assertRaises(StorageSecurityError):
                    source.read(str(link / 'config.yaml'), SOURCE_LIMIT)
            finally:
                os.rmdir(link)


if __name__ == '__main__':
    result = unittest.main(verbosity=2, exit=False).result
    raise SystemExit(0 if result.wasSuccessful() else 1)
