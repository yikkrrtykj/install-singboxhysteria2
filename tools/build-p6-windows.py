#!/usr/bin/env python3
"""Windows x64 payload builder. Signing is a separate mandatory release gate.

No runtime download during client installation. CPython archive is supplied
by the build operator/CI and must match the fixed upstream SHA-256. This tool
produces an UNSIGNED staging payload, never a publishable release by itself.
"""
import argparse
import ctypes
import base64
import os
import subprocess
import tempfile
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_URL = 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip'
RUNTIME_SHA256 = '97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297'
spec = importlib.util.spec_from_file_location('generic_builder', ROOT / 'tools/build-p6-artifact.py')
generic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generic)


def build(runtime_archive, publisher, destination, fixture_name=None):
    if not re.fullmatch(r'[0-9A-F]{40}', publisher):
        raise ValueError('publisher certificate thumbprint required')
    if fixture_name is not None and not re.fullmatch(r'P6InstallerFixture[0-9a-f]{32}', fixture_name):
        raise ValueError('invalid isolated fixture name')
    runtime = Path(runtime_archive).read_bytes()
    if len(runtime) > 16 * 1024 * 1024 or hashlib.sha256(runtime).hexdigest() != RUNTIME_SHA256:
        raise ValueError('fixed CPython runtime checksum mismatch')
    target = Path(destination)
    target.mkdir(exist_ok=False)
    payload = target / 'payload'
    payload.mkdir()
    (payload / 'runtime').mkdir()
    files = {}
    with zipfile.ZipFile(io.BytesIO(runtime)) as archive:
        for item in archive.infolist():
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', item.filename) or item.file_size > 32 * 1024 * 1024:
                raise ValueError('unexpected CPython runtime member')
            files['runtime/' + item.filename] = archive.read(item)
    files['runtime/python313._pth'] = b'python313.zip\n.\n../p6-agent.pyz\n../p6-installer.pyz\n'
    artifact, agent = generic.build()
    files['p6-agent.pyz'] = agent
    with zipfile.ZipFile(io.BytesIO(agent)) as archive:
        installer_files = {name: archive.read(name) for name in archive.namelist()}
    installer_files['__main__.py'] = b'from p6installer.manager import main\nraise SystemExit(main())\n'
    for name in ('__init__.py', 'bundle.py', 'scm.py', 'manager.py', 'controller.py', 'status.py'):
        installer_files['p6installer/' + name] = (ROOT / 'windows/p6installer' / name).read_bytes().replace(b'\r\n', b'\n')
    installer_files['p6_artifact.py'] = (ROOT / 'monitor-v2/p6_artifact.py').read_bytes().replace(b'\r\n', b'\n')
    # No operational flag permits changing root/service. Native CI compiles a
    # separately signed random fixture package through this constructor only.
    installer_files['p6installer/publisher.py'] = ('PUBLISHER = ' + repr(publisher)
        + '\nINSTALLATION_NAME = ' + repr(fixture_name or 'P6RemoteProbe') + '\n').encode('ascii')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(installer_files.items()):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.create_system, item.external_attr = 3, 0o100644 << 16
            archive.writestr(item, raw)
    files['p6-installer.pyz'] = output.getvalue()
    meta = {'v': 1, 'entry': 'gui-v2', 'runtime': 'cpython-3.13.16-amd64', 'artifact': artifact,
            'files': {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
                      for name, raw in sorted(files.items())}}
    from remote_probe.profiles import canonical
    meta['release'] = hashlib.sha256(canonical(meta)).hexdigest()
    for name, raw in files.items():
        (payload / name).write_bytes(raw)
    (payload / 'release.json').write_bytes(canonical(meta))
    setup = (ROOT / 'windows/Setup.ps1').read_text(encoding='utf-8-sig')
    gui = (ROOT / 'windows/Manager.ps1').read_text(encoding='utf-8-sig')
    (target / 'Setup.ps1').write_bytes(setup.replace('@P6_PUBLISHER@', publisher).replace('# P6_GUI_CODE', gui).encode('utf-8-sig'))
    compile_launcher(target, publisher)
    return meta


def compile_launcher(target, publisher):
    if os.name != 'nt':
        raise ValueError('native Windows release builder required')
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    if not kernel.GetSystemWindowsDirectoryW(buffer, len(buffer)):
        raise ValueError('native compiler directory unavailable')
    framework = Path(buffer.value) / 'Microsoft.NET/Framework64/v4.0.30319'
    with tempfile.TemporaryDirectory(prefix='p6-launcher-build-') as temporary:
        script = Path(temporary) / 'P6Launcher.cs'
        embedded = (Path(target) / 'Setup.ps1').read_text(encoding='utf-8-sig').replace('$PSScriptRoot', '$script:P6CompiledPackageRoot')
        code = base64.b64encode(embedded.encode('utf-8')).decode('ascii')
        script.write_text((ROOT / 'windows/P6Launcher.cs').read_text(encoding='utf-8').replace('@P6_PUBLISHER@', publisher).replace('@P6_COMPILED_SETUP@', code), encoding='utf-8')
        result = subprocess.run([str(framework / 'csc.exe'), '/nologo', '/noconfig', '/nostdlib+',
            '/target:winexe', '/platform:x64', '/optimize+',
            '/reference:' + str(framework / 'mscorlib.dll'), '/reference:' + str(framework / 'System.dll'),
            '/reference:' + str(framework / 'System.Windows.Forms.dll'),
            '/reference:' + str(framework / 'System.Core.dll'),
            '/reference:' + str(Path(buffer.value) / 'Microsoft.NET/assembly/GAC_MSIL/System.Management.Automation/v4.0_3.0.0.0__31bf3856ad364e35/System.Management.Automation.dll'),
            '/win32manifest:' + str(ROOT / 'windows/P6Launcher.manifest'),
            '/out:' + str(Path(target) / 'P6Setup.exe'), str(script)],
            capture_output=True, timeout=60, creationflags=0x08000000)
    if result.returncode:
        raise ValueError('native graphical launcher build unavailable')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-archive', required=True)
    parser.add_argument('--publisher-thumbprint', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        meta = build(args.runtime_archive, args.publisher_thumbprint, args.output)
        print('[PASS] unsigned payload built: ' + meta['release'])
        print('[SKIP] signing is not supplied by this builder; not a release artifact')
        return 0
    except (OSError, ValueError, zipfile.BadZipFile):
        print('[FAIL] windows_payload_build_unavailable', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
