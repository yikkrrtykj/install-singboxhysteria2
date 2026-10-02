#!/usr/bin/env python3
"""Build a deterministic generic source zipapp; not a Windows installer/EXE.

No downloaded code, interpreter or credentials. Normalized source bytes come
from this checkout's reviewed modules. Deployment supplies protected modes.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
from p6_artifact import MAX_ARTIFACT_BYTES

AGENT_MODULES = ('__init__.py', '__main__.py', 'agent.py', 'delivery.py',
    'direct_probe.py', 'evidence.py', 'mihomo_probe.py', 'payload.py',
    'pinned_transport.py', 'production.py', 'production_runtime.py',
    'profiles.py', 'service_host.py', 'spool.py', 'windows_security.py')


def build():
    files = {'__main__.py': b'from remote_probe.production import main\nraise SystemExit(main())\n'}
    for name in AGENT_MODULES:
        path = ROOT / 'monitor-v2/remote_probe' / name
        files['remote_probe/' + path.name] = path.read_bytes().replace(b'\r\n', b'\n')
    for name in ('client.py', 'model.py'):
        files['mihomo/' + name] = (ROOT / 'monitor-v2/mihomo' / name).read_bytes().replace(b'\r\n', b'\n')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    raw = output.getvalue()
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError('artifact oversized')
    digest = hashlib.sha256(raw).hexdigest()
    return {'v': 1, 'version': 'p6-agent-source-1-' + digest[:16],
            'sha256': digest, 'size': len(raw)}, raw


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError('one output directory required')
        target = Path(sys.argv[1])
        manifest, raw = build()
        # Caller creates a new private staging directory; never overwrite an
        # existing artifact or follow links in this non-privileged builder.
        for name, value in (('p6-agent.pyz', raw), ('artifact.json',
                json.dumps(manifest, sort_keys=True).encode('ascii') + b'\n')):
            with (target / name).open('xb') as stream:
                stream.write(value)
        print('[PASS] generic Agent source artifact built')
        return 0
    except (OSError, ValueError):
        print('[FAIL] generic Agent artifact build failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
