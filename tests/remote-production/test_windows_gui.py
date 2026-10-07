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
from remote_probe.spool import SpoolError
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
            service=types.SimpleNamespace(state=lambda _: 4, start_mode=lambda _: 2))

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

    def test_startup_observation_is_actual_and_mutation_free(self):
        before = self.tree()
        for mode, expected in ((2, True), (3, False), (None, None)):
            self.manager.service.start_mode = lambda _, mode=mode: mode
            self.assertIs(snapshot(self.manager, self.reader)['autostart'], expected)
            self.assertEqual(self.tree(), before)
        self.manager.service.start_mode = lambda _: 4
        with self.assertRaises(ConfigError):
            snapshot(self.manager, self.reader)

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

    def test_closed_egress_detail_and_configured_cadence_failed_ip_is_none(self):
        record = self.record(3)
        sample = json.loads(base64.b64decode(record['body_b64']))
        sample['egress'] = {'status': 'failed', 'latency_ms': None,
                            'error_code': 'connect_failed', 'ip': None, 'change': 'unknown'}
        record['body_b64'] = base64.b64encode(canonical(sample)).decode()
        value = latest_sample(canonical(record) + b'\n', 'device-one')
        self.assertEqual(value['egress_error_code'], 'connect_failed')
        self.assertIsNone(value['egress_latency_ms'])
        self.assertIsNone(value['egress_ip'])
        self.assertNotIn('ip', value)
        self.assertNotIn('egress', value)
        self.assertEqual(snapshot(self.manager, self.reader)['profiles'][0]['cadence_seconds'], 60)

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


    def test_protected_display_labels_are_read_only_and_identity_bound(self):
        value={'v':1,'client':'event-pc','device':'laptop-01','location':'office','network_path':'wifi',
               'probe_id':self.manifest_value['probe_id'],'server_id':self.manifest_value['server_id']}
        path=Path(self.vault._path(self.key))
        self.vault._write(str(path),'display.json',canonical(value))
        before=self.tree();result=snapshot(self.manager,self.reader)
        self.assertEqual(result['profiles'][0]['display'],value)
        self.assertEqual(self.tree(),before)
        self.assertNotIn('ingest.key',self.read_names);self.assertNotIn('mihomo.key',self.read_names)
        changed=dict(value,probe_id='unrelated')
        (path/'display.json').unlink();self.vault._write(str(path),'display.json',canonical(changed))
        with self.assertRaises(ConfigError):snapshot(self.manager,self.reader)

    def test_legacy_profile_display_fallback_does_not_change_profile_or_spool(self):
        before=self.tree();result=snapshot(self.manager,self.reader)
        self.assertEqual(result['profiles'][0]['display']['client'],'')
        self.assertEqual(result['profiles'][0]['display']['network_path'],'')
        self.assertEqual(self.tree(),before)



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




class AdjacentBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_bundle as fixtures
        fixtures.BundleTests.setUpClass()
        cls.fixture_class=fixtures.BundleTests

    @classmethod
    def tearDownClass(cls):
        cls.fixture_class.tearDownClass()

    def setUp(self):
        self.fixture=self.fixture_class('test_repeat_bundle_does_not_rotate_or_add_download_timestamp')
        self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        self.root=self.fixture.root
        self.artifact=self.fixture.manifest
        from p6installer.bundle import discover_adjacent,read_bundle
        self.discover=discover_adjacent;self.read=read_bundle

    def write(self,name='device-bundle.zip',v2=True):
        parts=copy.deepcopy(self.fixture.parts)
        if v2:parts['display']={'client':'event-pc','device':'laptop-01','location':'office','network_path':'wifi'}
        path=self.root/name;path.write_bytes(self.fixture.bundle(parts));return path

    def test_single_adjacent_v2_returns_validated_display_without_installing(self):
        path=self.write();before={p.name:p.read_bytes() for p in self.root.iterdir()}
        result=self.discover(self.root,self.artifact)
        self.assertEqual(result['state'],'selected');self.assertEqual(result['path'],str(path))
        self.assertEqual(result['display']['location'],'office');self.assertEqual(result['display']['device'],'laptop-01')
        self.assertEqual({p.name:p.read_bytes() for p in self.root.iterdir()},before)
        self.assertNotIn(self.fixture.parts['secret'],json.dumps(result))

    def test_zero_multiple_and_parent_config_never_auto_select(self):
        self.assertEqual(self.discover(self.root,self.artifact),{'state':'missing'})
        nested=self.root/'setup';nested.mkdir();self.write()
        self.assertEqual(self.discover(nested,self.artifact),{'state':'missing'})
        self.write('event-pc-laptop-02-client-bundle.zip')
        self.assertEqual(self.discover(self.root,self.artifact),{'state':'ambiguous'})

    def test_legacy_v1_bundle_is_readable_with_truthful_unset_location(self):
        path=self.write(v2=False)
        result=self.discover(self.root,self.artifact)
        self.assertEqual(result['display']['client'],'event-pc')
        self.assertEqual(result['display']['location'],'')
        self.assertEqual(len(self.read(path,self.artifact)),3)

    def test_wrong_artifact_corrupt_and_oversize_are_not_selected(self):
        path=self.write();changed=copy.deepcopy(self.artifact);changed['sha256']='a'*64
        with self.assertRaises(ConfigError):self.discover(self.root,changed)
        for raw in (b'not a ZIP',b'x'*(5*1024*1024+1)):
            path.write_bytes(raw)
            with self.assertRaises(ConfigError):self.discover(self.root,self.artifact)

    def test_directory_link_and_native_reparse_candidate_are_refused(self):
        target=self.root/'target';target.mkdir();self.write('target/device-bundle.zip')
        link=self.root/'device-bundle.zip'
        if os.name=='nt':
            subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True)
            self.addCleanup(lambda:os.rmdir(link))
        else:
            link.symlink_to(target/'device-bundle.zip')
        with self.assertRaises((ConfigError,StorageSecurityError,SpoolError)):self.discover(self.root,self.artifact)

    def test_directory_capacity_and_unrelated_archives_do_not_expand_search(self):
        (self.root/'unrelated.zip').write_bytes(b'not read')
        self.assertEqual(self.discover(self.root,self.artifact),{'state':'missing'})
        for n in range(129):(self.root/('unrelated-%d'%n)).write_bytes(b'x')
        with self.assertRaises(ConfigError):self.discover(self.root,self.artifact)

    def test_display_closed_binding_label_limits_and_zip_directory_bomb(self):
        from p6installer.bundle import validate_display
        path=self.write();_,_,_,display=self.read(path,self.artifact,include_display=True)
        for key,value in [('client','bad/name'),('location','x'*65),('network_path','line\nbreak'),('probe_id','other'),('v',True),('extra',1)]:
            with self.subTest(key=key),self.assertRaises(ConfigError):
                validate_display(dict(display,**{key:value}),self.fixture.profile)
        raw=bytearray(path.read_bytes());raw[-12:-10]=(65535).to_bytes(2,'little');path.write_bytes(raw)
        with self.assertRaises(ConfigError):self.read(path,self.artifact)


if __name__ == '__main__':
    result = unittest.main(verbosity=2, exit=False).result
    raise SystemExit(0 if result.wasSuccessful() else 1)
