"""Root admission/HTTP authority fixtures, not Linux Authenticode claims."""
import concurrent.futures
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'monitor-v2'), str(ROOT / 'tests/remote-production')]
import p6_distribution as d
from p6_artifact import ArtifactError
from test_distribution import fixture, record
from test_bundle_linux import BundleLinuxTests


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/run', prefix='p6-distribution-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o755)
        self.root = self.base / 'published'
        self.m, self.raw = fixture()
        self.package = self.base / 'installer.zip'; self.manifest = self.base / 'manifest.json'
        self.sources(self.m, self.raw)

    def sources(self, m, raw):
        self.package.write_bytes(raw); self.package.chmod(0o644)
        self.manifest.write_bytes(d.canonical(m)); self.manifest.chmod(0o644)

    def publish(self, m=None, **overrides):
        m = m or self.m
        args = dict(package=str(self.package), manifest_path=str(self.manifest),
                    expected_digest=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
                    publisher=m['publisher'], scope=m['scope'], artifact=m['artifact'], root=str(self.root))
        args.update(overrides)
        return d.publish(**args)

    def test_publish_retry_public_read_and_exact_preserved_bytes(self):
        result = self.publish(); self.assertEqual(result, self.publish())
        with d.open_release(self.m['artifact'], str(self.root)) as (m, f):
            self.assertEqual(m, self.m); self.assertEqual(f.read(), self.raw)
        self.assertEqual({x.name for x in self.root.iterdir()}, {self.m['archive']['sha256'], 'current.json', '.publish.lock'})

    def test_explicit_digest_publisher_scope_artifact_and_root_required(self):
        for override in ({'expected_digest': 'b' * 64}, {'publisher': 'B' * 40}, {'scope': 'production'},
                         {'artifact': fixture(b'other')[0]['artifact']}):
            with self.subTest(override=override), self.assertRaises(d.DistributionError): self.publish(**override)
        with patch.object(os, 'geteuid', return_value=65534), self.assertRaises(d.DistributionError): self.publish()
        self.assertFalse(self.root.exists())

    def test_source_symlink_hardlink_and_writable_file_refused(self):
        self.package.chmod(0o666)
        with self.assertRaises(d.DistributionError): self.publish()
        self.package.chmod(0o644)
        os.link(self.package, self.base / 'hardlink')
        with self.assertRaises(d.DistributionError): self.publish()
        (self.base / 'hardlink').unlink()
        self.package.unlink(); self.package.symlink_to(self.manifest)
        with self.assertRaises((OSError, d.DistributionError)): self.publish()
        self.assertFalse((self.root / 'current.json').exists())

    def test_current_reader_refuses_permission_links_tamper_and_mixed_agent(self):
        self.publish()
        path = self.root / self.m['archive']['sha256'] / 'windows-installer.zip'
        path.chmod(0o666)
        with self.assertRaises(d.DistributionError), d.open_release(self.m['artifact'], str(self.root)): pass
        path.chmod(0o644); path.write_bytes(self.raw + b'bad')
        with self.assertRaises(d.DistributionError), d.open_release(self.m['artifact'], str(self.root)): pass
        path.write_bytes(self.raw)
        os.link(path, self.base / 'hardlink')
        with self.assertRaises(d.DistributionError), d.open_release(self.m['artifact'], str(self.root)): pass
        (self.base / 'hardlink').unlink()
        with self.assertRaises(d.DistributionError), d.open_release(fixture(b'other')[0]['artifact'], str(self.root)): pass
        pointer = self.root / 'current.json'; pointer.unlink(); pointer.symlink_to(self.manifest)
        with self.assertRaises(d.DistributionError), d.open_release(self.m['artifact'], str(self.root)): pass

    def test_two_versions_no_auto_eviction_and_explicit_inactive_retire(self):
        self.publish(); first = self.m['archive']['sha256']
        second, raw = fixture(setup=b'format fixture two'); self.sources(second, raw); self.publish(second)
        third, raw = fixture(setup=b'format fixture three'); self.sources(third, raw)
        with self.assertRaises(d.DistributionError): self.publish(third)
        self.assertTrue((self.root / first).is_dir())
        with self.assertRaises(d.DistributionError): d.retire(second['archive']['sha256'], str(self.root))
        d.retire(first, str(self.root)); self.assertFalse((self.root / first).exists())
        self.publish(third)

    def test_publisher_scope_replacement_refused_preserving_current(self):
        self.publish(); original = (self.root / 'current.json').read_bytes()
        other, raw = fixture(publisher='B' * 40); self.sources(other, raw)
        with self.assertRaises(d.DistributionError): self.publish(other)
        self.sources(self.m, self.raw)
        m = json.loads(d.canonical(self.m)); m['scope'] = 'production'; m['timestamped'] = True
        self.sources(m, self.raw)
        with self.assertRaises(d.DistributionError): self.publish(m)
        self.assertEqual((self.root / 'current.json').read_bytes(), original)

    def test_interrupted_pointer_publish_recovers_without_exposing_stage(self):
        self.publish(); original = (self.root / 'current.json').read_bytes()
        other, raw = fixture(setup=b'stage fixture two'); self.sources(other, raw)
        with patch.object(d.os, 'replace', side_effect=OSError('fixture interruption')), self.assertRaises(OSError): self.publish(other)
        self.assertEqual((self.root / 'current.json').read_bytes(), original)
        with d.open_release(self.m['artifact'], str(self.root)) as (_, f): self.assertEqual(f.read(), self.raw)
        stage = next(x.name for x in self.root.iterdir() if x.name.startswith('.stage-'))
        with self.assertRaises(d.DistributionError): self.publish(other)
        d.retire(stage[7:], str(self.root), stage=True)
        self.publish(other)
        with d.open_release(other['artifact'], str(self.root)) as (_, f): self.assertEqual(f.read(), raw)

    def test_partial_stage_cleanup_is_explicit_and_foreign_files_refuse(self):
        self.publish(); selector = uuid.uuid4().hex; path = self.root / ('.stage-' + selector); path.mkdir(mode=0o700)
        part = path / 'windows-installer.zip'; part.write_bytes(b'partial'); part.chmod(0o644)
        (path / 'foreign').write_bytes(b'preserve')
        with self.assertRaises(d.DistributionError): d.retire(selector, str(self.root), stage=True)
        self.assertTrue((path / 'foreign').exists()); (path / 'foreign').unlink()
        d.retire(selector, str(self.root), stage=True); self.assertFalse(path.exists())

    def test_concurrent_retry_and_switch_preserve_held_reader(self):
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            values = list(pool.map(lambda _: self.publish(), range(2)))
        self.assertEqual(values[0], values[1])
        with d.open_release(self.m['artifact'], str(self.root)) as (_, old):
            other, raw = fixture(setup=b'new fixture'); self.sources(other, raw); self.publish(other)
            d.retire(self.m['archive']['sha256'], str(self.root))
            self.assertEqual(old.read(), self.raw)
            with d.open_release(other['artifact'], str(self.root)) as (_, new): self.assertEqual(new.read(), raw)

    def test_real_unprivileged_read_cannot_publish(self):
        self.publish(); helper = self.base / 'reader'; helper.mkdir(mode=0o755)
        for name in ('p6_artifact.py', 'p6_distribution.py'):
            shutil.copyfile(ROOT / 'monitor-v2' / name, helper / name); (helper / name).chmod(0o644)
        def drop(): os.setgroups([]); os.setgid(65534); os.setuid(65534)
        code = '''import sys,json,hashlib
sys.path.insert(0,sys.argv[1]);import p6_distribution as d
with d.open_release(json.loads(sys.argv[3]),sys.argv[2]) as (m,f): print(hashlib.sha256(f.read()).hexdigest())
try:d.retire(m['archive']['sha256'],sys.argv[2])
except d.DistributionError:print('authority_denied')
else:raise AssertionError('non-root retirement')
'''
        r = subprocess.run([sys.executable, '-I', '-c', code, str(helper), str(self.root), json.dumps(self.m['artifact'])],
                           preexec_fn=drop, cwd='/', capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual(r.stdout.decode().splitlines(), [self.m['archive']['sha256'], 'authority_denied'])


class DownloadTests(BundleLinuxTests):
    def setUp(self):
        super().setUp()
        self.distribution = self.root / 'windows'
        self.dist_manifest, self.dist_raw = fixture(self.generic)
        package = self.root / 'windows.zip'; manifest = self.root / 'windows.json'
        package.write_bytes(self.dist_raw); package.chmod(0o644)
        raw = d.canonical(self.dist_manifest); manifest.write_bytes(raw); manifest.chmod(0o644)
        d.publish(str(package), str(manifest), hashlib.sha256(raw).hexdigest(), self.dist_manifest['publisher'],
                  'lab', self.manifest, str(self.distribution))
        self.app.windows_distribution = lambda artifact: d.open_release(artifact, str(self.distribution))

    def download(self, **kwargs): return self.http(path='/api/v1/clients/windows', body={}, **kwargs)

    def test_software_real_authenticated_stream_preserves_bytes_without_credential_rpc(self):
        status, headers, raw = self.download()
        self.assertEqual(status, 200, raw)
        self.assertEqual(raw, self.dist_raw); self.assertEqual(int(headers['Content-Length']), len(raw))
        self.assertEqual(headers['X-P6-Distribution-Scope'], 'lab')
        self.assertIn('p6-windows-lab.zip', headers['Content-Disposition'])
        self.assertIn('no-store', headers['Cache-Control']); self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertNotIn('client.bundle', self.calls)
        self.assertNotIn(self.row()['secret'].encode(), raw)
        self.assertEqual(self.plane.store.status()['sample_count'], 0)

    def test_software_auth_and_fresh_gate_refuse_before_distribution_io(self):
        with patch.object(self.app, 'windows_distribution', side_effect=AssertionError('unauthorized software I/O')):
            for expected, kw in ((401, {'auth': False}), (403, {'csrf': False}),
                                 (403, {'headers': {'Origin': 'https://foreign.example'}})):
                self.assertEqual(self.download(**kw)[0], expected)
            from web.e3_broker import BrokerUnavailable
            with patch.object(self.app.e3_broker, 'require_export_ready', side_effect=BrokerUnavailable()):
                self.assertEqual(self.download()[0], 503)
            self.app.auth.sessions.revoke_all_step_ups(); self.assertEqual(self.download()[0], 401)
        self.assertEqual(self.calls, [])

    def test_software_closed_input_methods_and_shared_concurrency_slots(self):
        for body in ({'path': '/root/secret'}, {'url': 'https://foreign'}, [], {'name': 'event-pc'}):
            self.assertEqual(self.http(path='/api/v1/clients/windows', body=body)[0], 400)
        self.assertEqual(self.download(headers={'Idempotency-Key': 'forbidden-download-0001'})[0], 400)
        for method in ('GET', 'PUT', 'DELETE'): self.assertEqual(self.download(method=method)[0], 405)
        self.app.bundle_slots.acquire(); self.app.bundle_slots.acquire()
        try: self.assertEqual(self.download()[0], 429)
        finally: self.app.bundle_slots.release(); self.app.bundle_slots.release()
        self.assertEqual(self.calls, [])

    def test_software_missing_corrupt_and_mixed_release_closed_failure_releases_slots(self):
        self.app.windows_distribution = lambda artifact: d.open_release(artifact, str(self.root / 'missing'))
        status, _, raw = self.download(); self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)['code'], 'E_P6_WINDOWS_UNAVAILABLE')
        self.app.windows_distribution = lambda artifact: d.open_release(artifact, str(self.distribution))
        path = self.distribution / self.dist_manifest['archive']['sha256'] / 'windows-installer.zip'
        path.write_bytes(b'corrupt')
        self.assertEqual(self.download()[0], 503)
        path.write_bytes(self.dist_raw)
        self.assertEqual(self.download()[0], 200)
        self.assertNotIn('client.bundle', self.calls)

    def test_software_helper_reinstall_preserves_current_distribution(self):
        prefix = self.root / 'installed'; published = prefix / 'usr/local/share/sbox-p6-windows'
        published.mkdir(parents=True); published.chmod(0o755)
        marker = published / 'fixture-preserved'; marker.write_bytes(b'public existing fixture')
        for _ in range(2):
            r = subprocess.run(['bash', str(ROOT / 'sbox-cm/deploy/install-sbox-cm.sh'), 'install'],
                env=os.environ | {'SBXCM_PREFIX': str(prefix), 'SBXCM_SYSTEMCTL': '/usr/bin/true',
                                  'SB_CM_STATE_DIR': str(prefix / 'state')}, capture_output=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr.decode())
            self.assertEqual(marker.read_bytes(), b'public existing fixture')
            self.assertTrue((prefix / 'usr/local/lib/sbox-cm/publish-p6-windows.py').is_file())



    def test_combined_client_real_http_contains_exact_software_and_current_device(self):
        status,headers,raw=self.http(path='/api/v1/clients/windows-bundle')
        self.assertEqual(status,200,raw)
        self.assertEqual(int(headers['Content-Length']),len(raw))
        self.assertIn('no-store',headers['Cache-Control'])
        self.assertEqual(headers['X-P6-Distribution-Scope'],'lab')
        self.assertIn('event-pc-laptop-01-windows-client.zip',headers['Content-Disposition'])
        with zipfile.ZipFile(io.BytesIO(raw)) as outer,zipfile.ZipFile(io.BytesIO(self.dist_raw)) as software:
            for name in software.namelist():self.assertEqual(outer.read(name),software.read(name))
            with zipfile.ZipFile(io.BytesIO(outer.read('device-bundle.zip'))) as config:
                self.assertEqual(config.read('ingest.key'),(self.row()['secret']+'\n').encode())
                self.assertEqual(config.read('event-pc-mihomo.yaml'),outer.read('event-pc-mihomo.yaml'))
                meta=json.loads(config.read('bundle.json'))
                self.assertEqual(meta['v'],2);self.assertEqual(meta['location'],self.row()['site_label'])
                self.assertEqual(meta['network_path'],self.row()['path_label'])
                self.assertEqual(json.loads(config.read('profile.json'))['probe_id'],self.row()['probe_id'])
        self.assertIn('client.bundle',self.calls)
        self.assertTrue(any(row['op']=='client.bundle' for row in self.audit()))

    def test_combined_unavailable_software_fails_before_sensitive_rpc(self):
        self.app.windows_distribution=lambda artifact:d.open_release(artifact,str(self.root/'missing'))
        status,_,raw=self.http(path='/api/v1/clients/windows-bundle')
        self.assertEqual(status,503);self.assertEqual(json.loads(raw)['code'],'E_P6_WINDOWS_UNAVAILABLE')
        self.assertEqual(self.calls,['management.status'])  # read-only fresh gate; zero credential RPC
        self.assertTrue(self.app.bundle_slots.acquire(blocking=False));self.app.bundle_slots.release()

    def test_combined_old_signed_release_fails_before_credential_export(self):
        old, raw = fixture(self.generic, entry='gui-v1')
        archive=self.root/'old.zip'; metadata=self.root/'old.json'
        archive.write_bytes(raw);archive.chmod(0o644)
        record=d.canonical(old);metadata.write_bytes(record);metadata.chmod(0o644)
        d.publish(str(archive),str(metadata),hashlib.sha256(record).hexdigest(),old['publisher'],
                  'lab',self.manifest,str(self.distribution))
        status,_,body=self.http(path='/api/v1/clients/windows-bundle')
        self.assertEqual(status,503);self.assertEqual(json.loads(body)['code'],'E_P6_WINDOWS_UNAVAILABLE')
        self.assertEqual(self.calls,['management.status'])  # read-only fresh gate; zero credential RPC
        self.assertEqual(self.download()[0],200)

    def test_combined_closed_schema_auth_origin_and_shared_capacity(self):
        route='/api/v1/clients/windows-bundle'
        self.assertEqual(self.http(path=route,auth=False)[0],401)
        self.assertEqual(self.http(path=route,csrf=False)[0],403)
        self.assertEqual(self.http(path=route,headers={'Origin':'https://foreign'})[0],403)
        for body in ({},{'name':'event-pc'},{'name':'event-pc','device':'laptop-01','path':'/root/secret'}):
            self.assertEqual(self.http(path=route,body=body)[0],400)
        for method in ('GET','PUT','DELETE'):self.assertEqual(self.http(path=route,method=method)[0],405)
        self.app.bundle_slots.acquire();self.app.bundle_slots.acquire()
        try:self.assertEqual(self.http(path=route)[0],429)
        finally:self.app.bundle_slots.release();self.app.bundle_slots.release()
        self.assertEqual(self.calls,[])

    def test_combined_retired_device_cannot_download_and_other_identity_is_not_created(self):
        self.worker.revoke('event-pc','laptop-01',self.generation,self.row()['probe_id'])
        self.assertNotEqual(self.http(path='/api/v1/clients/windows-bundle')[0],200)
        self.assertNotIn(self.row()['secret'].encode(),self.http(path='/api/v1/clients/windows-bundle')[2])


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(PublicationTests)
    # Reuse full real RPC/Monitor fixtures, without repeating the inherited
    # Bundle assertions and misreporting their count as new software tests.
    for name in sorted(DownloadTests.__dict__):
        if name.startswith('test_'): suite.addTest(DownloadTests(name))
    return suite


if __name__ == '__main__':
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('mandatory Linux root distribution fixtures')
    unittest.main(verbosity=2)
