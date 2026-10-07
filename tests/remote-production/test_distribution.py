"""Portable format checks; fixture bytes do not claim Authenticode signing."""
import copy
import hashlib
import io
from pathlib import Path
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
from p6_distribution import DistributionError, canonical, object_json, validate_manifest_record, verify_archive, MAX_ARCHIVE


def record(raw):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}


def fixture(agent=b'FORMAT FIXTURE, NOT SIGNED', setup=b'FORMAT FIXTURE, NOT PE', publisher='A' * 40, entry='gui-v2'):
    artifact = dict(v=1, version='p6-agent-source-1-' + record(agent)['sha256'][:16], **record(agent))
    payload = {'p6-agent.pyz': agent, 'p6-installer.pyz': b'fixture installer', 'runtime/python.exe': b'fixture python',
               'runtime/pythonw.exe': b'fixture pythonw', 'runtime/python313.dll': b'fixture dll',
               'runtime/python313.zip': b'fixture stdlib',
               'runtime/python313._pth': b'python313.zip\n.\n../p6-agent.pyz\n../p6-installer.pyz\n'}
    meta = {'v': 1, 'entry': entry, 'runtime': 'cpython-3.13.16-amd64', 'artifact': artifact,
            'files': {k: record(v) for k, v in payload.items()}}
    meta['release'] = hashlib.sha256(canonical(meta)).hexdigest()
    files = {'P6Setup.exe': setup, 'Setup.ps1': b'fixture script', 'payload.cat': b'fixture catalog',
             'payload/release.json': canonical(meta)} | {'payload/' + k: v for k, v in payload.items()}
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED) as z:
        for name, raw in sorted(files.items()):
            item = zipfile.ZipInfo(name); item.create_system = 3; item.external_attr = 0o100644 << 16
            z.writestr(item, raw)
    raw = out.getvalue()
    manifest = {'v': 1, 'kind': 'p6-windows-distribution/1', 'scope': 'lab', 'publisher': publisher,
                'installation': 'P6RemoteProbe', 'timestamped': False, 'release': meta['release'],
                'artifact': artifact, 'archive': record(raw), 'files': {k: record(v) for k, v in files.items()}}
    return manifest, raw


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.m, self.raw = fixture()

    def test_closed_lab_roundtrip_does_not_claim_signatures(self):
        self.assertEqual(validate_manifest_record(self.m), self.m)
        stream = io.BytesIO(self.raw); verify_archive(stream, self.m)
        self.assertEqual(stream.tell(), 0)
        self.assertEqual(self.m['scope'], 'lab')
        self.assertFalse(self.m['timestamped'])
        self.assertFalse(any('key' in x or 'profile' in x or 'yaml' in x for x in self.m['files']))

    def test_production_requires_timestamp_and_normal_installation(self):
        self.m['scope'] = 'production'
        with self.assertRaises(DistributionError): validate_manifest_record(self.m)
        self.m['timestamped'] = True
        self.m['installation'] = 'P6InstallerFixture' + 'a' * 32
        with self.assertRaises(DistributionError): validate_manifest_record(self.m)

    def test_closed_manifest_exact_types_publisher_and_extra_keys(self):
        for key, value in [('v', True), ('files', []), ('publisher', 'a' * 40), ('scope', 'other'), ('timestamped', 1), ('extra', 1)]:
            with self.subTest(key=key):
                m = copy.deepcopy(self.m); m[key] = value
                with self.assertRaises(DistributionError): validate_manifest_record(m)

    def test_duplicate_json_fields_refused(self):
        with self.assertRaises(DistributionError): object_json(b'{"v":1,"v":1}')

    def test_archive_hash_and_size_tamper_refused(self):
        with self.assertRaises(DistributionError): verify_archive(io.BytesIO(self.raw[:-1]), self.m)
        m = copy.deepcopy(self.m); m['archive']['sha256'] = 'b' * 64
        with self.assertRaises(DistributionError): verify_archive(io.BytesIO(self.raw), m)

    def test_file_hash_tamper_refused_even_with_original_archive_hash(self):
        self.m['files']['P6Setup.exe']['sha256'] = 'b' * 64
        with self.assertRaises(DistributionError): verify_archive(io.BytesIO(self.raw), self.m)

    def test_missing_runtime_and_unexpected_credential_inventory_refused(self):
        for name in ('payload/runtime/pythonw.exe', 'payload/runtime/python313.dll', 'payload/runtime/python313._pth'):
            m = copy.deepcopy(self.m); del m['files'][name]
            with self.assertRaises(DistributionError): validate_manifest_record(m)
        self.m['files']['ingest.key'] = record(b'never admitted')
        with self.assertRaises(DistributionError): validate_manifest_record(self.m)

    def test_capacity_and_boolean_sizes_refused(self):
        for size in (MAX_ARCHIVE + 1, True, 0):
            m = copy.deepcopy(self.m); m['archive']['size'] = size
            with self.assertRaises(DistributionError): validate_manifest_record(m)

    def test_zip_comment_and_compressed_payload_refused(self):
        for compression, comment in ((zipfile.ZIP_STORED, b'comment'), (zipfile.ZIP_DEFLATED, b'')):
            stream = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(self.raw)) as original, zipfile.ZipFile(stream, 'w', compression=compression) as z:
                for i in original.infolist():
                    value = original.read(i.filename); i.compress_type = compression; z.writestr(i, value)
                z.comment = comment
            value = stream.getvalue(); m = copy.deepcopy(self.m); m['archive'] = record(value)
            with self.assertRaises(DistributionError): verify_archive(io.BytesIO(value), m)

    def test_archive_artifact_and_payload_manifest_must_agree(self):
        self.m['artifact'], _ = fixture(agent=b'different Agent')
        # Use the artifact record from another fixture, not its whole manifest.
        self.m['artifact'] = self.m['artifact']['artifact']
        with self.assertRaises(DistributionError): verify_archive(io.BytesIO(self.raw), self.m)



class ClientPackageTests(unittest.TestCase):
    def prepare(self, agent=b'fixture signed-file bytes'):
        from web.p6_windows_bundle import WindowsClientPackage
        self.manifest,self.raw=fixture(agent)
        self.source=io.BytesIO(self.raw)
        verify_archive(self.source,self.manifest)
        package=WindowsClientPackage(self.source,self.manifest,b'fixture-private-config',
            'client-mihomo.yaml',b'canonical YAML\n')
        self.addCleanup(package.close)
        return package

    def test_client_zip_interop_preserves_every_software_file_byte(self):
        package=self.prepare()
        raw=b''.join(package.chunks())
        self.assertEqual(len(raw),package.size)
        with zipfile.ZipFile(io.BytesIO(self.raw)) as original,zipfile.ZipFile(io.BytesIO(raw)) as combined:
            self.assertEqual(combined.testzip(),None)
            self.assertEqual(set(combined.namelist()),set(original.namelist())|{'device-bundle.zip','client-mihomo.yaml','README-client.txt'})
            for name in original.namelist():
                self.assertEqual(combined.read(name),original.read(name))
            self.assertEqual(combined.read('device-bundle.zip'),b'fixture-private-config')
            self.assertEqual(combined.read('client-mihomo.yaml'),b'canonical YAML\n')
            self.assertIn('受控测试版',combined.read('README-client.txt').decode())

    def test_large_software_uses_bounded_chunks_not_one_archive_buffer(self):
        package=self.prepare(b'x'*(2*1024*1024))
        sizes=[len(chunk) for chunk in package.chunks()]
        self.assertEqual(sum(sizes),package.size)
        self.assertLessEqual(max(sizes),65536)
        self.assertGreater(len(sizes),32)

    def test_input_and_total_capacity_are_closed(self):
        from web.p6_windows_bundle import WindowsClientPackage
        from unittest.mock import patch
        m,raw=fixture()
        for name,yaml,bundle in [('../bad',b'y',b'b'),('x-mihomo.yaml',b'',b'b'),('x-mihomo.yaml',b'y',b'x'*(5*1024*1024+1))]:
            with self.subTest(name=name),self.assertRaises(DistributionError):
                WindowsClientPackage(io.BytesIO(raw),m,bundle,name,yaml)
        with patch('web.p6_windows_bundle.MAX_CLIENT_PACKAGE',100),self.assertRaises(DistributionError):
            WindowsClientPackage(io.BytesIO(raw),m,b'b','x-mihomo.yaml',b'y')

    def test_wrong_inventory_is_refused_before_chunks(self):
        from web.p6_windows_bundle import WindowsClientPackage
        m,raw=fixture(); changed=copy.deepcopy(m);changed['files']['payload/runtime/unexpected.dll']=record(b'x')
        with self.assertRaises(DistributionError):
            WindowsClientPackage(io.BytesIO(raw),changed,b'b','x-mihomo.yaml',b'y')

    def test_single_use_and_software_mutation_abort(self):
        package=self.prepare()
        list(package.chunks())
        with self.assertRaises(DistributionError):list(package.chunks())
        package=self.prepare()
        row=package.archive.getinfo('P6Setup.exe')
        self.source.seek(row.header_offset+30+len(row.filename));self.source.write(b'X')
        with self.assertRaises(DistributionError):list(package.chunks())

    def test_old_software_is_still_valid_but_combined_export_requires_new_capability(self):
        from web.p6_windows_bundle import require_client_package
        old, raw = fixture(entry='gui-v1')
        source = io.BytesIO(raw)
        verify_archive(source, old)
        with self.assertRaises(DistributionError): require_client_package(source, old)
        self.assertEqual(source.tell(), 0)
        new, raw = fixture()
        require_client_package(io.BytesIO(raw), new)

    def test_aborted_generator_keeps_file_owned_by_caller(self):
        package=self.prepare();iterator=package.chunks();next(iterator);iterator.close();package.close()
        self.assertFalse(self.source.closed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
