"""Mandatory elevated Windows CI: actual bundled runtime/signatures/SCM.

Only random P6InstallerFixture services/state and a scoped CI signing fixture
certificate are touched. This is not a production signer or client rollout.
"""
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'windows'))
sys.path.insert(0, str(ROOT / 'tests/remote-production'))
from test_windows_installer import InstallerTests, controller
from test_bundle import BundleTests
from p6installer.bundle import read_bundle
from p6installer.manager import Manager, validate_release, verify_signatures
from p6installer.scm import Service, Failure, Action, Config
from remote_probe.agent import ConfigError
from remote_probe.profiles import canonical, profile_id
from remote_probe.windows_security import StorageSecurityError, WindowsSecurity
from remote_probe.spool import SpoolError

spec = importlib.util.spec_from_file_location('windows_builder', ROOT / 'tools/build-p6-windows.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


spec = importlib.util.spec_from_file_location('windows_exporter', ROOT / 'tools/export-p6-windows.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class NativeInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('mandatory elevated native Windows installer CI')
        cls.tmp = tempfile.TemporaryDirectory(prefix='p6-native-installer-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        # This elevated fixture launches the production LocalSystem service,
        # which must see the same SYSTEM/Administrators-only storage policy.
        # The unprivileged portable fixture's extra user SID is intentionally
        # rejected by that service and must not be added to its vault.
        cls.policy = WindowsSecurity()
        cls.protected = cls.root / 'protected'
        cls.policy.mkdir(str(cls.protected))
        cls.powershell = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        cls.sign_script = cls.root / 'sign.ps1'
        cls.sign_script.write_text('''param([string]$Package,[string]$Thumbprint)
$ErrorActionPreference='Stop'
foreach($m in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','PKI')) {
  Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop
}
$PSModuleAutoloadingPreference='None'
Write-Output 'fixture: native modules loaded'
if($Package) {
  $cert=Get-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+$Thumbprint)
  New-FileCatalog -Path (Join-Path $Package 'payload') -CatalogFilePath (Join-Path $Package 'payload.cat') -CatalogVersion 2.0 | Out-Null
  foreach($name in @('P6Setup.exe','Setup.ps1','payload.cat')) {
    $signature=Set-AuthenticodeSignature -LiteralPath (Join-Path $Package $name) -Certificate $cert -HashAlgorithm SHA256
    if($signature.Status -ne 'Valid'){throw 'fixture signature failed'}
  }
} else {
  $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=P6InstallerFixture-'+[Guid]::NewGuid()) -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 2048
  Write-Output 'fixture: private signing certificate generated'
  # CurrentUser Root can display a native trust-confirmation dialog even in
  # NonInteractive PowerShell. Elevated CI uses the isolated runner's machine
  # store without that UI; teardown removes exactly this random public cert.
  $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
  $store.Open('ReadWrite')
  $public=[Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$cert.RawData)
  $store.Add($public);$store.Close()
  Write-Output $cert.Thumbprint
}
''', encoding='utf-8')
        try:
            result = subprocess.run([cls.powershell, '-NoProfile', '-NonInteractive', '-File', str(cls.sign_script)],
                                    capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError('fixture certificate setup timed out at: ' + (error.stdout or b'').decode(errors='replace')) from None
        if result.returncode:
            raise RuntimeError('native fixture signing failed: ' + result.stderr)
        cls.publisher = result.stdout.strip().splitlines()[-1]
        if len(cls.publisher) != 40:
            raise RuntimeError('fixture publisher unavailable')
        cls.addClassCleanup(cls.cleanup_certificate)
        archive = cls.root / 'runtime.zip'
        with urllib.request.urlopen(builder.RUNTIME_URL, timeout=60) as source:
            raw = source.read(16 * 1024 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != builder.RUNTIME_SHA256:
            raise RuntimeError('runtime checksum mismatch')
        archive.write_bytes(raw)
        cls.runtime_archive = archive
        cls.package = cls.protected / 'package'
        cls.meta = builder.build(archive, cls.publisher, cls.package)
        cls.sign(cls.package)
        verify_signatures(cls.package, cls.publisher)
        validate_release(cls.package, cls.policy)
        BundleTests.setUpClass()

    @classmethod
    def sign(cls, package):
        result = subprocess.run([cls.powershell, '-NoProfile', '-NonInteractive', '-File',
                                str(cls.sign_script), '-Package', str(package), '-Thumbprint', cls.publisher],
                                capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('fixture package signing failed: ' + result.stderr.decode(errors='replace'))

    @classmethod
    def cleanup_certificate(cls):
        # Only the recorded random fixture certificate, never other trust.
        cleanup = cls.root / 'certificate-cleanup.ps1'
        cleanup.write_text('''param([string]$Thumbprint)
$ErrorActionPreference='Stop'
foreach($m in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management')) {
  Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop
}
foreach($store in @('Root','My')) {
  $scope=if($store -eq 'Root'){'LocalMachine'}else{'CurrentUser'}
  $path='Cert:\\'+$scope+'\\'+$store+'\\'+$Thumbprint
  if(Test-Path -LiteralPath $path){
    if($store -eq 'My'){Remove-Item -LiteralPath $path -Force -DeleteKey}
    else{Remove-Item -LiteralPath $path -Force}
  }
}
''')
        subprocess.run([cls.powershell, '-NoProfile', '-NonInteractive', '-File', str(cleanup),
                        '-Thumbprint', cls.publisher], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        BundleTests.tearDownClass()

    def setUp(self):
        self.name = 'P6InstallerFixture' + uuid.uuid4().hex
        self.service = Service(self.name)
        self.directory = self.protected / uuid.uuid4().hex
        self.manager = Manager(self.directory, self.service, self.policy,
                               publisher=self.publisher).open()
        self.addCleanup(self.cleanup_service)

    def cleanup_service(self):
        # Exact fixture service only; accept the two recorded journal commands.
        ids = []
        active = self.manager._active()
        if active:
            ids.append(active)
        intent = self.manager._read('upgrade.json')
        if intent:
            ids.extend(x for x in (intent['new'], intent['old']) if x)
        for release in ids:
            try:
                command = self.manager._command(release)
                if self.service.state(command):
                    self.service.stop(command)
                    self.service.delete(command)
                return
            except ConfigError:
                pass

    def install(self):
        result = self.manager.install(self.package)
        self.assertEqual(result['service'], 'running')
        return result

    def next_release(self):
        import zipfile
        target = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, target)
        os.unlink(target / 'payload.cat')
        installer = target / 'payload/p6-installer.pyz'
        with zipfile.ZipFile(installer, 'a') as archive:
            archive.comment = b'isolated-fixture-release-two'
        meta = copy.deepcopy(self.meta)
        raw = installer.read_bytes()
        meta['files']['p6-installer.pyz'] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        meta['release'] = hashlib.sha256(canonical({k: meta[k] for k in meta if k != 'release'})).hexdigest()
        (target / 'payload/release.json').write_bytes(canonical(meta))
        self.sign(target)
        return target, meta

    def profile(self, probe='p6-device-one'):
        fixture = BundleTests('test_repeat_bundle_does_not_rotate_or_add_download_timestamp')
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.profile['probe_id'] = probe
        # Use actual local controller. Its mapping is read-only, no proxy
        # selector/config endpoint exists in this fixture.
        server = controller(fixture.profile, 'local-secret')
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        fixture.parts['profile'] = fixture.profile
        fixture.parts['artifact'] = self.meta['artifact']
        fixture.generic = (self.package / 'payload/p6-agent.pyz').read_bytes()
        path = fixture.root / 'bundle.zip'
        # Server validates canonical controller 9090, so fixture ZIP is formed
        # by the reviewed assembler first, then only local controller port is
        # overridden for the isolated native installation test.
        original = fixture.profile['agent']['mihomo_url']
        fixture.profile['agent']['mihomo_url'] = 'http://127.0.0.1:9090'
        raw = fixture.bundle()
        fixture.profile['agent']['mihomo_url'] = original
        import io, zipfile
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, 'w') as target:
            for item in source.infolist():
                target.writestr(item, canonical(fixture.profile) if item.filename == 'profile.json' else source.read(item))
        path.write_bytes(output.getvalue())
        return fixture, path, server

    def test_native_signed_lab_export_roundtrip_retains_native_catalog_and_publisher(self):
        import zipfile
        from p6_distribution import object_json, verify_archive
        output = self.protected / uuid.uuid4().hex
        result = exporter.export(self.package, self.publisher, output, lab=True)
        raw = (output / 'release.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['manifest_sha256'])
        manifest = object_json(raw)
        self.assertEqual(manifest['publisher'], self.publisher)
        self.assertEqual(manifest['scope'], 'lab')
        self.assertFalse(manifest['timestamped'])
        with (output / 'windows-installer.zip').open('rb') as stream:
            verify_archive(stream, manifest)
        extracted = self.protected / uuid.uuid4().hex
        self.policy.mkdir(str(extracted))
        with zipfile.ZipFile(output / 'windows-installer.zip') as archive:
            archive.extractall(extracted)
        verify_signatures(extracted, self.publisher)
        self.assertEqual(validate_release(extracted, self.policy), self.meta)
        self.assertFalse((extracted / 'profile.json').exists())

    def test_native_export_refuses_missing_production_timestamps_and_wrong_publisher(self):
        for publisher, lab in ((self.publisher, False), ('0' * 40, True)):
            output = self.protected / uuid.uuid4().hex
            with self.assertRaises(Exception):
                exporter.export(self.package, publisher, output, lab=lab)
            self.assertFalse((output / 'release.json').exists())
        self.assertEqual(validate_release(self.package, self.policy), self.meta)

    def test_native_export_refuses_tampered_signed_entry_before_publication(self):
        bad = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, bad)
        with (bad / 'P6Setup.exe').open('ab') as stream:
            stream.write(b'fixture signature tamper')
        output = self.protected / uuid.uuid4().hex
        with self.assertRaises(Exception):
            exporter.export(bad, self.publisher, output, lab=True)
        self.assertFalse((output / 'windows-installer.zip').exists())

    def test_actual_bundled_interpreter_isolated_from_pythonpath_and_repo(self):
        environment = dict(os.environ, PYTHONPATH=str(self.root / 'untrusted'), PYTHONHOME=str(self.root / 'untrusted'))
        result = subprocess.run([str(self.package / 'payload/runtime/python.exe'), '-I', '-B',
                                 str(self.package / 'payload/p6-agent.pyz'), '--help'], cwd=self.root,
                                 env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'--vault', result.stdout)
        result = subprocess.run([str(self.package / 'payload/runtime/python.exe'), '-I', '-c',
            'import sys,site;assert sys.flags.isolated;assert not site.ENABLE_USER_SITE;print(sys.version_info[:3])'],
             env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'(3, 13, 16)', result.stdout)

    def test_native_auto_start_failure_recovery_and_scm_ownership(self):
        self.install()
        manager, handle = self.service._open()
        try:
            self.service._config(handle, self.manager._command(self.meta['release']))
            data = self.service._buffer(self.service.a.QueryServiceConfig2W, handle, 2)
            failure = ctypes.cast(data, ctypes.POINTER(Failure)).contents
            self.assertEqual(failure.reset, 86400)
            self.assertEqual([(failure.actions[i].kind, failure.actions[i].delay) for i in range(failure.count)],
                             [(1, 60000), (1, 120000), (1, 300000), (0, 0)])
            self.assertFalse(failure.command)
        finally:
            self.service._close(manager, handle)
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 4)

    def test_native_manual_start_survives_reinstall_upgrade_and_rollback(self):
        self.install()

        def start_mode(value=None):
            manager, handle = self.service._open()
            try:
                if value is not None:
                    # Only this random fixture service's start mode changes.
                    self.service._check(self.service.a.ChangeServiceConfigW(
                        handle, 0xffffffff, value, 0xffffffff, None, None,
                        None, None, None, None, None))
                buffer = self.service._buffer(self.service.a.QueryServiceConfigW, handle)
                return ctypes.cast(buffer, ctypes.POINTER(Config)).contents.start
            finally:
                self.service._close(manager, handle)

        self.assertEqual(start_mode(), 2)
        try:
            self.assertEqual(start_mode(3), 3)
            command = self.manager._command(self.meta['release'])
            self.assertEqual(self.service.state(command), 4)
            self.service.stop(command)
            self.assertEqual(self.service.state(command), 1)
            self.service.start(command)
            self.assertEqual(self.service.state(command), 4)
            self.install()
            self.assertEqual(start_mode(), 3)
            package, next_meta = self.next_release()
            self.assertEqual(self.manager.install(package)['release'], next_meta['release'])
            self.assertEqual(start_mode(), 3)
            self.assertEqual(self.manager.rollback()['release'], self.meta['release'])
            self.assertEqual(start_mode(), 3)
            self.service.stop(command)
            self.assertEqual(start_mode(4), 4)
            for operation in (lambda: self.service.state(command),
                              lambda: self.service.start(command),
                              lambda: self.service.configure(command)):
                with self.assertRaises(ConfigError):
                    operation()
            self.assertEqual(start_mode(), 4)
        finally:
            # Restore the scoped fixture even if old code fails at Manual.
            start_mode(2)

    def test_native_import_pause_resume_reinstall_preserve_secret_spool(self):
        self.install()
        fixture, path, server = self.profile()
        imported = self.manager.operate('import', bundle=path, controller_secret='local-secret')
        key = imported['profile']
        self.assertTrue(imported['created'])
        self.manager.operate('pause', profile=key)
        self.assertFalse(self.manager.vault.enabled(key))
        self.manager.vault._write(str(Path(self.manager.vault._path(key)) / 'spool'), 'pending-fixture', b'pending bytes')
        self.install()
        self.assertFalse(self.manager.vault.enabled(key))
        self.assertEqual(self.manager.vault.read_secret(key), bytes.fromhex('b' * 64))
        self.assertEqual(self.policy.read(str(Path(self.manager.vault._path(key)) / 'spool/pending-fixture'), 128), b'pending bytes')
        self.manager.operate('resume', profile=key)
        self.assertTrue(self.manager.vault.enabled(key))

    def test_native_remove_one_profile_keeps_other_then_uninstall_and_purge(self):
        self.install()
        _, path, _ = self.profile()
        one = self.manager.operate('import', bundle=path, controller_secret='local-secret')['profile']
        _, path, _ = self.profile('p6-device-two')
        two = self.manager.operate('import', bundle=path, controller_secret='local-secret')['profile']
        with self.assertRaises(ConfigError):
            self.manager.operate('uninstall')
        result = self.manager.operate('remove', profile=one)
        self.assertEqual(result['data'], 'retained')
        self.assertEqual(self.manager.vault.keys(), [two])
        self.assertEqual(self.manager.vault.read_secret(two), bytes.fromhex('b' * 64))
        self.assertEqual(self.manager.operate('remove', profile=one), result)
        self.manager.operate('remove', profile=two)
        self.assertEqual(self.manager.operate('uninstall')['retained_profiles'], 2)
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 0)
        self.assertTrue((self.directory / 'retired' / two / 'ingest.key').exists())
        self.manager.operate('purge', profile=one)
        self.assertFalse((self.directory / 'retired' / one).exists())
        self.assertTrue((self.directory / 'retired' / two).exists())

    def test_changed_bundle_key_never_overwrites_existing_identity(self):
        self.install()
        _, path, _ = self.profile()
        key = self.manager.operate('import', bundle=path, controller_secret='local-secret')['profile']
        self.manager.operate('pause', profile=key)
        import io, zipfile
        raw = io.BytesIO()
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(raw, 'w') as target:
            for item in source.infolist():
                target.writestr(item, b'c' * 64 if item.filename == 'ingest.key' else source.read(item))
        path.write_bytes(raw.getvalue())
        with self.assertRaises(ConfigError):
            self.manager.operate('import', bundle=path, controller_secret='local-secret')
        self.assertEqual(self.manager.vault.read_secret(key), bytes.fromhex('b' * 64))
        self.assertFalse(self.manager.vault.enabled(key))

    def test_signature_tamper_and_wrong_publisher_fail_before_service(self):
        with self.assertRaises(ConfigError):
            verify_signatures(self.package, '0' * 40)
        bad = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, bad)
        (bad / 'payload/p6-agent.pyz').write_bytes(b'tampered')
        with self.assertRaises(ConfigError):
            self.manager.install(bad)
        self.assertIsNone(self.manager._active())
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 0)

    def test_native_hardlink_and_junction_refused(self):
        path = self.directory / 'linked'
        source = self.directory / 'original'
        self.manager.vault._write(str(self.directory), 'original', b'fixture')
        os.link(source, path)
        with self.assertRaises(StorageSecurityError):
            self.policy.read(str(source), 128)
        os.unlink(path)
        target = self.directory / 'target'
        self.policy.mkdir(str(target))
        junction = self.directory / 'junction'
        result = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        try:
            with self.assertRaises(StorageSecurityError):
                self.policy.validate(str(junction), True)
        finally:
            os.rmdir(junction)

    def test_pending_upgrade_recovers_actual_scm_after_durable_intent(self):
        self.install()
        release = self.meta['release']
        self.manager._write(self.directory / 'upgrade.json', {'v': 1, 'old': release, 'new': release})
        recovered = Manager(self.directory, self.service, self.policy, publisher=self.publisher)
        self.assertEqual(recovered.install(self.package)['release'], release)
        self.assertFalse((self.directory / 'upgrade.json').exists())
        self.assertEqual(self.service.state(self.manager._command(release)), 4)

    def test_actual_upgrade_and_rollback_preserve_paused_profile_and_pending_bytes(self):
        self.install()
        fixture, _, _ = self.profile()
        self.service.stop(self.manager._command(self.meta['release']))
        key, _ = self.manager.vault.import_profile(fixture.profile, b'k' * 32, fixture.parts['certificate'], controller_secret='local-secret')
        self.manager.vault.set_enabled(key, False)
        self.manager.vault._write(str(Path(self.manager.vault._path(key)) / 'spool'), 'pending-fixture', b'pending bytes')
        self.service.start(self.manager._command(self.meta['release']))
        package, next_meta = self.next_release()
        self.assertEqual(self.manager.install(package)['release'], next_meta['release'])
        self.assertEqual(self.manager.rollback()['release'], self.meta['release'])
        self.assertFalse(self.manager.vault.enabled(key))
        self.assertEqual(self.manager.vault.read_secret(key), b'k' * 32)
        self.assertEqual(self.policy.read(str(Path(self.manager.vault._path(key)) / 'spool/pending-fixture'), 128), b'pending bytes')
        self.assertEqual(len(os.listdir(self.directory / 'releases')), 2)

    def test_failed_native_startup_keeps_intent_and_explicit_rollback_recovers(self):
        self.install()
        package, meta = self.next_release()
        start = self.service.start
        def failure(command):
            if command == self.manager._command(meta['release']):
                raise ConfigError('injected startup boundary failure')
            return start(command)
        with patch.object(self.service, 'start', side_effect=failure):
            with self.assertRaises(ConfigError):
                self.manager.install(package)
        self.assertTrue((self.directory / 'upgrade.json').exists())
        self.assertEqual(self.manager.rollback()['release'], self.meta['release'])
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 4)
        self.assertFalse((self.directory / 'upgrade.json').exists())

    def test_concurrent_installer_lock_refuses_before_service_or_state_change(self):
        self.install()
        before = self.manager._read('active.json')
        lock = self.manager._lock()
        try:
            with self.assertRaises(SpoolError):
                self.manager.install(self.package)
        finally:
            lock.release()
        self.assertEqual(self.manager._read('active.json'), before)
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 4)

    def test_retired_profiles_count_toward_capacity_and_junction_purge_refuses(self):
        self.install()
        fixture, _, _ = self.profile()
        self.service.stop(self.manager._command(self.meta['release']))
        keys = []
        for index in range(8):
            profile = copy.deepcopy(fixture.profile)
            profile['probe_id'] = 'capacity-' + str(index)
            key, _ = self.manager.vault.import_profile(profile, b'k' * 32, fixture.parts['certificate'])
            self.manager.vault.set_enabled(key, False)
            keys.append(key)
        self.service.start(self.manager._command(self.meta['release']))
        self.manager.operate('remove', profile=keys[0])
        _, path, server = self.profile('capacity-nine')
        with self.assertRaises(ConfigError):
            self.manager.operate('import', bundle=path, controller_secret='local-secret')
        self.assertEqual(server.seen, [])
        self.assertEqual(self.manager._slots(), 8)
        target = self.directory / 'sentinel'
        self.policy.mkdir(str(target))
        self.manager.vault._write(str(target), 'marker', b'keep')
        junction = self.directory / 'retired' / keys[0] / 'spool' / 'unsafe'
        result = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        try:
            with self.assertRaises(StorageSecurityError):
                self.manager.operate('purge', profile=keys[0])
            self.assertEqual(self.policy.read(str(target / 'marker'), 128), b'keep')
            self.assertEqual(len(self.manager.vault.keys()), 7)
        finally:
            os.rmdir(junction)

    def test_real_signed_setup_uses_embedded_installer_and_no_production_root(self):
        # Production setup intentionally targets fixed ProgramData. Only the
        # negative signature gate is exercised through that public entry; all
        # successful SCM tests above use explicit random constructor fixtures.
        bad = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, bad)
        (bad / 'payload.cat').write_bytes(b'bad signature')
        result = subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-File',
                                  str(bad / 'Setup.ps1'), '-Operation', 'install'],
                                  capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'[FAIL]', result.stdout)

    def test_actual_signed_bootstrap_install_and_uninstall_random_fixture(self):
        name = 'P6InstallerFixture' + uuid.uuid4().hex
        package = self.protected / uuid.uuid4().hex
        meta = builder.build(self.runtime_archive, self.publisher, package, fixture_name=name)
        self.sign(package)
        buffer = ctypes.create_unicode_buffer(32768)
        self.assertEqual(ctypes.windll.shell32.SHGetFolderPathW(None, 35, None, 0, buffer), 0)
        target = Path(buffer.value) / name
        service = Service(name)
        manager = Manager(target, service, publisher=self.publisher)
        def setup(operation):
            return subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-File',
                str(package / 'Setup.ps1'), '-Operation', operation], capture_output=True, timeout=120)
        try:
            result = setup('install')
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
            self.assertEqual(service.state(manager._command(meta['release'])), 4)
            result = setup('uninstall')
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
            self.assertEqual(service.state(manager._command(meta['release'])), 0)
        finally:
            if target.exists():
                active = manager._active()
                if active:
                    service.stop(manager._command(active))
                    service.delete(manager._command(active))
                manager._tree(target / 'profiles')
                # target is the exact verified native fixture path, never a
                # computed production path. Validate all objects before purge.
                for current, dirs, files in os.walk(target, followlinks=False):
                    manager.security.validate(current, True)
                    for directory in dirs:
                        manager.security.validate(str(Path(current) / directory), True)
                    for file in files:
                        manager.security.validate(str(Path(current) / file))
                shutil.rmtree(target)


    def test_graphical_entry_signature_tamper_and_missing_entry_refused(self):
        bad = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, bad)
        exe = bad / 'P6Setup.exe'
        raw = bytearray(exe.read_bytes())
        raw[0x80] ^= 1
        exe.write_bytes(raw)
        with self.assertRaises(ConfigError):
            self.manager.install(bad)
        self.assertIsNone(self.manager._active())
        exe.write_bytes(b'x' * (4 * 1024 * 1024 + 1))
        with self.assertRaises(StorageSecurityError):
            validate_release(bad, self.policy)
        exe.unlink()
        with self.assertRaises(ConfigError):
            validate_release(bad, self.policy)
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), 0)

    def test_actual_native_graphical_form_and_backend_dispatch(self):
        # Construct our own native controls without an interactive runner session.
        # A fixed recording backend exercises the real GUI handlers, not a grep.
        source = self.root / ('gui-' + uuid.uuid4().hex + '.ps1')
        gui = (ROOT / 'windows/Manager.ps1').read_text(encoding='utf-8-sig')
        source.write_text(gui + r'''

$ErrorActionPreference='Stop'
$form=New-P6ManagerForm
$script:seen=@()
function Invoke-P6Backend($Action,$SelectedProfile,$SelectedBundle,$Auto,$Credential) {
    $script:seen+=@{action=$Action;profile=$SelectedProfile;bundle=$SelectedBundle;auto=$Auto;hasCredential=($null -ne $Credential)}
    if($Action -eq 'ui-status') {
        return @{ok=$true;value=@{v=1;installed=$true;pending_recovery=$false;service_state=4;
          profiles=@(@{id=('a'*64);probe_id='fixture-probe';server_id=('b'*32);enabled=$true;spool=$null;sample=$null;display=@{client='event-pc';device='laptop-01';location='office';network_path='wifi'}});retired=@()}}
    }
    return @{ok=$true;value=@{}}
}
try {
  Refresh-P6Status
  if($script:p6Profiles.Items.Count -ne 1 -or $script:p6Grid.Columns.Count -ne 3 -or $form.Controls.Count -ne 19){throw 'form shape'}
  if($form.Text -ne '客户端管理' -or @($form.Controls | Where-Object {$_.Text -eq '技术详情'}).Count -ne 1){throw 'primary title or technical details'}
  if($script:p6Details.Text -notmatch '客户端：event-pc / 设备：laptop-01' -or $script:p6Details.Text -match 'fixture-probe'){throw 'primary device labels'}
  $script:p6Bundle.Text='C:\fixture-only\client.zip'
  Run-P6Action 'import'
  Run-P6Action 'pause'
  Run-P6Action 'resume'
  $imports=@($script:seen | Where-Object {$_.action -eq 'import'})
  if($imports.Count -ne 1 -or -not $imports[0].auto -or $imports[0].hasCredential){throw 'discovery dispatch'}
  foreach($action in @('pause','resume')) {
    $calls=@($script:seen | Where-Object {$_.action -eq $action})
    if($calls.Count -ne 1 -or $calls[0].profile -ne ('a'*64) -or $calls[0].hasCredential){throw 'profile dispatch'}
  }
  if(-not $script:p6Buttons['pause'].Enabled -or $script:p6Buttons['purge'].Enabled){throw 'action containment'}
  Write-Output 'GUI_NATIVE_FORM_AND_DISPATCH_PASS'
} finally {$form.Dispose()}
''', encoding='utf-8-sig')
        result = subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-STA', '-File', str(source)],
                                capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'GUI_NATIVE_FORM_AND_DISPATCH_PASS', result.stdout)

    def test_actual_snapshot_preserves_live_service_queues_and_pending_intent(self):
        from p6installer.status import snapshot
        self.install()
        _, path, _ = self.profile()
        key = self.manager.operate('import', bundle=path, controller_secret='local-secret')['profile']
        self.manager.operate('pause', profile=key)
        spool = Path(self.manager.vault._path(key)) / 'spool'
        self.manager.vault._write(str(spool), 'pending-fixture', b'pending bytes')
        self.manager._write(spool / 'spool.state.json', {'next_record_id': 2, 'resolved_through': 0, 'acknowledged_total': 0,
            'quarantined_total': 0, 'expired_total': 0, 'budget_dropped_total': 0, 'corrupt_total': 0,
            'state_save_failures': 0, 'retry_attempts': {'1': 1}})
        before = self.policy.read(str(spool / 'pending-fixture'), 128)
        state = self.service.state(self.manager._command(self.meta['release']))
        result = snapshot(self.manager)
        self.assertEqual(result['service_state'], state)
        self.assertEqual(result['profiles'][0]['id'], key)
        self.assertEqual(result['profiles'][0]['spool']['acknowledged_total'], 0)
        self.assertEqual(self.policy.read(str(spool / 'pending-fixture'), 128), before)
        self.assertFalse(self.manager.vault.enabled(key))
        intent = {'v': 1, 'old': self.meta['release'], 'new': self.meta['release']}
        self.manager._write(self.directory / 'upgrade.json', intent)
        self.assertTrue(snapshot(self.manager)['pending_recovery'])
        self.assertEqual(self.manager._read('upgrade.json'), intent)
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])), state)

    def test_legacy_signed_three_member_release_still_allows_upgrade_and_rollback(self):
        legacy = self.protected / uuid.uuid4().hex
        shutil.copytree(self.package, legacy)
        (legacy / 'P6Setup.exe').unlink()
        (legacy / 'payload.cat').unlink()
        meta = copy.deepcopy(self.meta)
        del meta['entry']
        meta['release'] = hashlib.sha256(canonical({k: meta[k] for k in meta if k != 'release'})).hexdigest()
        (legacy / 'payload/release.json').write_bytes(canonical(meta))
        # The legacy entry is the actual previous trusted template, not the GUI
        # template pretending it can launch with a missing required executable.
        old_raw = (ROOT / 'tests/remote-production/fixtures/Setup-pre-gui.ps1').read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(hashlib.sha256(old_raw).hexdigest(), 'c636f551801d1ba5719a9005b66c1ff5aeb6a1e73f79821f592648ef71922c80')
        old_setup = old_raw.decode('utf-8-sig')
        (legacy / 'Setup.ps1').write_bytes(old_setup.replace('@P6_PUBLISHER@', self.publisher).encode('utf-8-sig'))
        legacy_sign = self.root / ('legacy-sign-' + uuid.uuid4().hex + '.ps1')
        text = self.sign_script.read_text().replace("@('P6Setup.exe','Setup.ps1','payload.cat')", "@('Setup.ps1','payload.cat')")
        legacy_sign.write_text(text)
        signed = subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-File', str(legacy_sign),
            '-Package', str(legacy), '-Thumbprint', self.publisher], capture_output=True, timeout=60)
        self.assertEqual(signed.returncode, 0)
        self.manager.install(legacy)
        self.assertEqual(self.manager._active(), meta['release'])
        self.manager.install(self.package)
        self.assertEqual(self.manager._active(), self.meta['release'])
        self.assertEqual(self.manager.rollback()['release'], meta['release'])
        self.assertEqual(self.service.state(self.manager._command(meta['release'])), 4)



    def test_actual_signed_windowed_entry_opens_and_closes_without_install(self):
        from ctypes import wintypes as W
        name = 'P6InstallerFixture' + uuid.uuid4().hex
        package = self.protected / uuid.uuid4().hex
        builder.build(self.runtime_archive, self.publisher, package, fixture_name=name)
        self.sign(package)
        buffer = ctypes.create_unicode_buffer(32768)
        self.assertEqual(ctypes.windll.shell32.SHGetFolderPathW(None, 35, None, 0, buffer), 0)
        target = Path(buffer.value) / name
        self.assertFalse(target.exists())
        user = ctypes.WinDLL('user32', use_last_error=True)
        user.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
        user.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, ctypes.c_int]
        user.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, ctypes.c_int]
        user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
        callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        user.EnumWindows.argtypes = [callback_type, W.LPARAM]
        process = subprocess.Popen([str(package / 'P6Setup.exe')], creationflags=0x08000000)
        observed = []
        faults = []
        def owned_window(hwnd, _):
            pid = W.DWORD()
            user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value != process.pid:
                return True
            kind, title = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
            user.GetClassNameW(hwnd, kind, 256)
            user.GetWindowTextW(hwnd, title, 256)
            if title.value.startswith('客户端管理 · E_'):
                faults.append(title.value)
                user.PostMessageW(hwnd, 0x0010, 0, 0)
            if title.value == '客户端管理' and kind.value.startswith('WindowsForms10.'):
                observed.append(hwnd)
                # This exact CI-owned application only, never another desktop app.
                user.PostMessageW(hwnd, 0x0010, 0, 0)
            return True
        callback = callback_type(owned_window)
        deadline = time.monotonic() + 60
        try:
            while process.poll() is None and time.monotonic() < deadline:
                user.EnumWindows(callback, 0)
                time.sleep(.25)
            self.assertTrue(observed, 'signed native manager window did not open: ' + repr(faults))
            self.assertEqual(process.wait(timeout=5), 0, repr(faults))
            self.assertFalse(target.exists(), 'opening/closing GUI must not install or create fixture state')
        finally:
            if process.poll() is None:
                # No install/profile action was sent. Kill only this CI-owned
                # window process on test failure, never SCM/runtime or host apps.
                process.terminate()
                process.wait(timeout=10)



    def test_native_combined_download_keeps_signatures_and_passive_adjacent_selection(self):
        import io,zipfile
        from p6_distribution import object_json
        from web.p6_windows_bundle import WindowsClientPackage
        from p6installer.bundle import discover_adjacent
        output=self.protected/uuid.uuid4().hex
        exporter.export(self.package,self.publisher,output,lab=True)
        manifest=object_json((output/'release.json').read_bytes())
        fx,config,_=self.profile()
        with (output/'windows-installer.zip').open('rb') as source:
            package=WindowsClientPackage(source,manifest,config.read_bytes(),'event-pc-mihomo.yaml',fx.parts['yaml'].encode())
            try:raw=b''.join(package.chunks())
            finally:package.close()
        extracted=self.protected/uuid.uuid4().hex;self.policy.mkdir(str(extracted))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:archive.extractall(extracted)
        # Setup copies only signed software into protected staging. Adjacent
        # private configuration stays in the original download directory and
        # must never widen validate_release's closed package inventory.
        verified=self.protected/uuid.uuid4().hex;self.policy.mkdir(str(verified))
        for name in ('P6Setup.exe','Setup.ps1','payload.cat'):
            (verified/name).write_bytes((extracted/name).read_bytes())
        shutil.copytree(extracted/'payload',verified/'payload')
        verify_signatures(verified,self.publisher)
        self.assertEqual(validate_release(verified,self.policy),self.meta)
        before={p.relative_to(extracted).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in extracted.rglob('*') if p.is_file()}
        result=discover_adjacent(extracted,self.meta['artifact'])
        self.assertEqual(result['state'],'selected');self.assertEqual(result['display']['device'],'laptop-01')
        self.assertEqual(before,{p.relative_to(extracted).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in extracted.rglob('*') if p.is_file()})
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])),0)

    def test_native_display_import_conflict_and_retirement_preserve_identity_and_bytes(self):
        import io,zipfile
        from p6installer.status import snapshot
        self.install();_,path,_=self.profile()
        original=path.read_bytes()
        imported=self.manager.operate('import',bundle=path,controller_secret='local-secret')
        key=imported['profile'];profile_root=Path(self.manager.vault._path(key))
        display_bytes=(profile_root/'display.json').read_bytes()
        display=snapshot(self.manager)['profiles'][0]['display']
        self.assertEqual(display['client'],'event-pc');self.assertEqual(display['device'],'laptop-01')
        changed=io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(original)) as source,zipfile.ZipFile(changed,'w') as target:
            for item in source.infolist():
                value=source.read(item)
                if item.filename=='bundle.json':
                    meta=json.loads(value);meta['device']='different-device';value=canonical(meta)
                target.writestr(item,value)
        path.write_bytes(changed.getvalue())
        with self.assertRaises(ConfigError):self.manager.operate('import',bundle=path,controller_secret='local-secret')
        self.assertEqual((profile_root/'display.json').read_bytes(),display_bytes)
        self.assertEqual(self.manager.vault.read_secret(key),bytes.fromhex('b'*64))
        self.assertEqual(self.service.state(self.manager._command(self.meta['release'])),4)
        self.manager.operate('remove',profile=key)
        self.assertEqual((self.manager.root/'retired'/key/'display.json').read_bytes(),display_bytes)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeInstallerTests)
    assert suite.countTestCases() == 25
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
