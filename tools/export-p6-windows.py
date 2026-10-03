#!/usr/bin/env python3
"""Native build-host export of an ALREADY SIGNED protected Windows package.

No signing key generation/import/policy changes; separate explicit lab scope.
"""
import argparse
import ast
import base64
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'monitor-v2'), str(ROOT / 'windows')]
from p6_distribution import canonical, validate_manifest_record, verify_archive, MAX_ARCHIVE
from p6installer.manager import validate_release, verify_signatures
from remote_probe.windows_security import WindowsSecurity


def export(package, publisher, output, lab=False):
    if os.name != 'nt' or not re.fullmatch(r'[0-9A-F]{40}', publisher):
        raise ValueError('native release host required')
    policy = WindowsSecurity(); package = Path(package); output = Path(output)
    meta = validate_release(package, policy)
    if meta.get('entry') != 'gui-v1':
        raise ValueError('graphical package required')
    verify_signatures(package, publisher)
    # Verify timestamps through the exact native system verifier, never PATH.
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise ValueError('native verifier unavailable')
    native = str(Path(buf.value) / 'WindowsPowerShell/v1.0/powershell.exe')
    code = "$ErrorActionPreference='Stop';Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Security','Microsoft.PowerShell.Security.psd1'));$PSModuleAutoloadingPreference='None';try{$all=$true;foreach($f in @('P6Setup.exe','Setup.ps1','payload.cat')){$s=Get-AuthenticodeSignature -LiteralPath ([IO.Path]::Combine('" + str(package).replace("'", "''") + "',$f));if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne '" + publisher + "'){exit 2};if(-not $s.TimeStamperCertificate){$all=$false}};if($all){exit 0}else{exit 3}}catch{exit 2}"
    result = subprocess.run([native, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=60, creationflags=0x08000000)
    if result.returncode not in (0, 3) or (not lab and result.returncode != 0):
        raise ValueError('production timestamps required')
    timestamped = result.returncode == 0
    installer = policy.read(str(package / 'payload/p6-installer.pyz'), 4 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(installer)) as z:
        tree = ast.parse(z.read('p6installer/publisher.py'))
    if len(tree.body) != 2:
        raise ValueError('publisher binding')
    constants = {}
    for row in tree.body:
        if not isinstance(row, ast.Assign) or len(row.targets) != 1 or not isinstance(row.targets[0], ast.Name) \
                or not isinstance(row.value, ast.Constant) or type(row.value.value) is not str:
            raise ValueError('publisher binding')
        if row.targets[0].id in constants:
            raise ValueError('publisher binding')
        constants[row.targets[0].id] = row.value.value
    if set(constants) != {'PUBLISHER', 'INSTALLATION_NAME'} or constants['PUBLISHER'] != publisher \
            or (not lab and constants['INSTALLATION_NAME'] != 'P6RemoteProbe'):
        raise ValueError('publisher binding')
    names = ['P6Setup.exe', 'Setup.ps1', 'payload.cat', 'payload/release.json'] + ['payload/' + name for name in meta['files']]
    policy.mkdir(str(output)); archive = output / 'windows-installer.zip'
    if archive.exists() or (output / 'release.json').exists():
        raise ValueError('export collision')
    files = {}; total = 0
    try:
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as z:
            for name in sorted(names):
                value = policy.read(str(package / name), 4 * 1024 * 1024 if name in ('P6Setup.exe', 'Setup.ps1', 'payload.cat') else MAX_ARCHIVE)
                total += len(value)
                if total > MAX_ARCHIVE:
                    raise ValueError('distribution capacity')
                files[name] = {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); item.create_system = 3; item.external_attr = 0o100644 << 16
                z.writestr(item, value)
        digest = hashlib.sha256()
        with archive.open('rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                digest.update(chunk)
        manifest = {'v': 1, 'kind': 'p6-windows-distribution/1', 'scope': 'lab' if lab else 'production', 'publisher': publisher,
                    'installation': constants['INSTALLATION_NAME'], 'timestamped': timestamped, 'release': meta['release'],
                    'artifact': meta['artifact'], 'archive': {'sha256': digest.hexdigest(), 'size': archive.stat().st_size}, 'files': files}
        validate_manifest_record(manifest)
        with archive.open('rb') as f:
            verify_archive(f, manifest)
        # Original protected package is rechecked; no unsigned fallback.
        verify_signatures(package, publisher)
        raw = canonical(manifest); (output / 'release.json').write_bytes(raw)
        return {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'archive_sha256': digest.hexdigest(), 'scope': manifest['scope'], 'publisher': publisher}
    except BaseException:
        if archive.exists():
            archive.unlink()
        raise


def main():
    p = argparse.ArgumentParser(); p.add_argument('--package', required=True); p.add_argument('--publisher', required=True)
    p.add_argument('--output', required=True); p.add_argument('--lab', action='store_true')
    a = p.parse_args()
    try:
        result = export(a.package, a.publisher.upper(), a.output, a.lab)
        print('[PASS] native signed distribution export ' + json.dumps(result, sort_keys=True))
        print('[SKIP] no trust import, server publication or production rollout performed')
        return 0
    except Exception:
        print('[FAIL] signed_distribution_export_unavailable'); return 2


if __name__ == '__main__':
    raise SystemExit(main())
