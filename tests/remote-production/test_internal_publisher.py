"""Native publisher lifecycle. Only random fixture keys/certs; no client/VPS changes."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
PS = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def native(code):
    # Owned test scripts and literal data. No execution-policy changes or -Bypass.
    code = "$ErrorActionPreference='Stop';foreach($m in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','PKI')){Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1')))};" + code
    return subprocess.run([str(PS), '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True,
        text=True, timeout=60, creationflags=0x08000000)

def run_tool(name, **args):
    raw = (ROOT / 'windows' / name).read_text(encoding='utf-8-sig')
    call = '&([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(' + quote(base64.b64encode(raw.encode()).decode()) + '))))'
    for k, v in args.items():
        call += ' -' + k + ' ' + quote(v)
    return native(call)

class NativePublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != 'nt':
            raise RuntimeError('native Windows publisher tests required')
        cls.tmp = tempfile.TemporaryDirectory(prefix='p6-internal-publisher-')
        cls.root = Path(cls.tmp.name)
        cls.output = cls.root / 'identity'
        cls.subject = 'CN=P6InternalFixture-' + uuid.uuid4().hex
        cls.thumbprints = []
        cls.addClassCleanup(cls.cleanup)
        r = run_tool('New-InternalPublisher.ps1', Output=cls.output, Subject=cls.subject)
        if r.returncode:
            raise RuntimeError('fixture creation failed: ' + r.stdout + r.stderr)
        cls.record = json.loads((cls.output / 'publisher.json').read_text())
        cls.thumbprints.append(cls.record['publisher'])
        cls.cert = cls.output / 'publisher.cer'

    @classmethod
    def cleanup(cls):
        # Exact random test authorities only, even if a trust test raises.
        for thumb in cls.thumbprints:
            code = "foreach($n in @('Root','TrustedPublisher')){$s=[Security.Cryptography.X509Certificates.X509Store]::new($n,'LocalMachine');try{$s.Open('ReadWrite');foreach($c in @($s.Certificates)){if($c.Thumbprint -eq " + quote(thumb) + "){$s.Remove($c)}}}catch{}finally{$s.Close()}};$private=Get-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+" + quote(thumb) + ");$rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($private);try{$rsa.Key.Delete()}finally{$rsa.Dispose()};Remove-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+" + quote(thumb) + ") -ErrorAction Stop"
            r = native(code)
            if r.returncode:
                raise RuntimeError('exact fixture key cleanup failed: ' + r.stderr)
        cls.tmp.cleanup()

    def trust(self, **kwargs):
        return run_tool('Trust-InternalPublisher.ps1', **(dict(Operation='Check', Certificate=self.cert,
            ExpectedSha256=self.record['certificate_sha256'], ExpectedPublisher=self.record['publisher']) | kwargs))

    def assert_ok(self, r):
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def assert_refused(self, r):
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)

    def test_public_only_identity_and_nonexportable_private_key(self):
        self.assertFalse(self.record['private_key_exported'])
        self.assertFalse(self.record['trust_installed'])
        self.assertEqual(hashlib.sha256(self.cert.read_bytes()).hexdigest(), self.record['certificate_sha256'])
        self.assertEqual({p.name for p in self.output.iterdir()}, {'publisher.cer', 'publisher.json'})
        r = native("$c=Get-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+" + quote(self.record['publisher']) + ");$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){exit 2}}finally{$k.Dispose()}")
        self.assert_ok(r)

    def test_repeated_create_refuses_and_never_rotates(self):
        before = (self.output / 'publisher.json').read_bytes()
        self.assert_refused(run_tool('New-InternalPublisher.ps1', Output=self.output, Subject=self.subject))
        self.assertEqual((self.output / 'publisher.json').read_bytes(), before)

    def test_explicit_existing_identity_reuse(self):
        output = self.root / ('reuse-' + uuid.uuid4().hex)
        self.assert_ok(run_tool('New-InternalPublisher.ps1', Output=output, Subject=self.subject,
            ExistingThumbprint=self.record['publisher']))
        self.assertEqual((output / 'publisher.cer').read_bytes(), self.cert.read_bytes())

    def test_check_is_readonly_and_reports_store_presence(self):
        r = self.trust()
        self.assert_ok(r)
        self.assertIn('private_key_imported', r.stdout)

    def test_wrong_digest_and_publisher_refuse_before_trust(self):
        self.assert_refused(self.trust(ExpectedSha256='0' * 64))
        self.assert_refused(self.trust(ExpectedPublisher='0' * 40))

    def test_trailing_der_bytes_refused_even_with_matching_digest(self):
        path = self.root / 'trailing.cer'
        path.write_bytes(self.cert.read_bytes() + b'trailing')
        self.assert_refused(self.trust(Certificate=path, ExpectedSha256=hashlib.sha256(path.read_bytes()).hexdigest()))

    def test_tls_certificate_refused_even_with_exact_pin(self):
        path = self.root / 'tls.cer'
        code = "$c=New-SelfSignedCertificate -DnsName fixture.invalid -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy NonExportable -KeyAlgorithm RSA -KeyLength 3072;[IO.File]::WriteAllBytes(" + quote(path) + ",$c.RawData);Write-Output $c.Thumbprint"
        r = native(code)
        self.assert_ok(r)
        thumb = r.stdout.strip().splitlines()[-1]
        self.thumbprints.append(thumb)
        self.assert_refused(self.trust(Certificate=path, ExpectedPublisher=thumb,
            ExpectedSha256=hashlib.sha256(path.read_bytes()).hexdigest()))

    def test_native_expired_code_certificate_refused(self):
        path = self.root / 'expired.cer'
        code = "$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=ExpiredInternalFixture' -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy NonExportable -KeyAlgorithm RSA -KeyLength 3072 -NotBefore ([DateTime]::Now.AddDays(-2)) -NotAfter ([DateTime]::Now.AddDays(-1));[IO.File]::WriteAllBytes(" + quote(path) + ",$c.RawData);Write-Output $c.Thumbprint"
        r = native(code)
        self.assert_ok(r)
        thumb = r.stdout.strip().splitlines()[-1]
        self.thumbprints.append(thumb)
        self.assert_refused(self.trust(Certificate=path, ExpectedPublisher=thumb,
            ExpectedSha256=hashlib.sha256(path.read_bytes()).hexdigest()))

    @unittest.skipUnless(os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin(), 'machine trust requires administrator; exercised by Windows CI')
    def test_native_idempotent_trust_two_same_identity_signatures_and_exact_removal(self):
        try:
            self.assert_ok(self.trust(Operation='Install'))
            self.assert_ok(self.trust(Operation='Install'))
            for n in range(2):
                path = self.root / ('version' + str(n) + '.ps1')
                path.write_text('Write-Output ' + str(n), encoding='utf-8-sig')
                r = native("$c=Get-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+" + quote(self.record['publisher']) + ");$s=Set-AuthenticodeSignature -LiteralPath " + quote(path) + " -Certificate $c -HashAlgorithm SHA256;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $c.Thumbprint){exit 2}")
                self.assert_ok(r)  # Native identity test, no timestamp/production export claim.
        finally:
            self.assert_ok(self.trust(Operation='Remove'))
        r = self.trust()
        self.assert_ok(r)
        self.assertIn('"Root":false', r.stdout)
        self.assertIn('"TrustedPublisher":false', r.stdout)

if __name__ == '__main__':
    if '--require-admin' in sys.argv:
        sys.argv.remove('--require-admin')
        if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('mandatory administrator Windows publisher CI')
    unittest.main(verbosity=2)
