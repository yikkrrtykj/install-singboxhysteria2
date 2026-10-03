"""Root-admitted Windows distribution. Native signing is verified on Windows.

Linux trusts the operator's explicit expected manifest digest/publisher/scope,
then proves inventory, bytes and DAC. This is NOT Linux Authenticode validation.
No credential, extraction, HTTP selector or public-ingest surface exists here.
"""
import contextlib
import hashlib
import json
import os
import re
import stat
import struct
import uuid
import zipfile

from p6_artifact import ArtifactError, _read, validate_manifest
if os.name == 'posix':
    import fcntl

DISTRIBUTION_DIR = '/usr/local/share/sbox-p6-windows'
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_MANIFEST = 32768
MAX_FILES = 68
HEX = re.compile(r'[0-9a-f]{64}')
KEYS = {'v', 'kind', 'scope', 'publisher', 'installation', 'timestamped', 'release', 'artifact', 'archive', 'files'}


class DistributionError(Exception):
    def __init__(self):
        super().__init__('E_P6_WINDOWS_UNAVAILABLE')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def object_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise DistributionError()
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def validate_manifest_record(m):
    try:
        if type(m) is not dict or set(m) != KEYS or type(m['v']) is not int or m['v'] != 1 \
                or m['kind'] != 'p6-windows-distribution/1' or m['scope'] not in ('production', 'lab') \
                or type(m['publisher']) is not str or not re.fullmatch(r'[0-9A-F]{40}', m['publisher']) \
                or type(m['timestamped']) is not bool or (m['scope'] == 'production' and not m['timestamped']) \
                or type(m['release']) is not str or not HEX.fullmatch(m['release']) \
                or type(m['installation']) is not str or not re.fullmatch(r'P6RemoteProbe|P6InstallerFixture[0-9a-f]{32}', m['installation']) \
                or (m['scope'] == 'production' and m['installation'] != 'P6RemoteProbe'):
            raise DistributionError()
        validate_manifest(m['artifact'])
        for record in (m['archive'], *m['files'].values()):
            if type(record) is not dict or set(record) != {'sha256', 'size'} \
                    or type(record['sha256']) is not str or not HEX.fullmatch(record['sha256']) \
                    or type(record['size']) is not int or not 0 < record['size'] <= MAX_ARCHIVE:
                raise DistributionError()
        if type(m['files']) is not dict or not 8 <= len(m['files']) <= MAX_FILES \
                or not {'P6Setup.exe', 'Setup.ps1', 'payload.cat', 'payload/release.json', 'payload/p6-agent.pyz',
                        'payload/p6-installer.pyz', 'payload/runtime/python.exe', 'payload/runtime/pythonw.exe',
                        'payload/runtime/python313.dll', 'payload/runtime/python313._pth', 'payload/runtime/python313.zip'} <= set(m['files']):
            raise DistributionError()
        for name, record in m['files'].items():
            if type(name) is not str or not re.fullmatch(r'P6Setup\.exe|Setup\.ps1|payload\.cat|payload/release\.json|payload/p6-(?:agent|installer)\.pyz|payload/runtime/[A-Za-z0-9_.-]+', name) \
                    or (name in ('P6Setup.exe', 'Setup.ps1', 'payload.cat', 'payload/p6-installer.pyz', 'payload/p6-agent.pyz') and record['size'] > 4 * 1024 * 1024) \
                    or (name == 'payload/release.json' and record['size'] > MAX_MANIFEST):
                raise DistributionError()
        if sum(v['size'] for v in m['files'].values()) > MAX_ARCHIVE:
            raise DistributionError()
        return m
    except (ArtifactError, KeyError, TypeError, ValueError, AttributeError):
        raise DistributionError() from None


def verify_archive(stream, m):
    """Reject oversized central directories before ZipFile constructs entries."""
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    if size != m['archive']['size'] or not 22 <= size <= MAX_ARCHIVE:
        raise DistributionError()
    stream.seek(size - 22)
    e = struct.unpack('<4s4H2LH', stream.read(22))
    if e[0] != b'PK\x05\x06' or e[1:3] != (0, 0) or e[3] != e[4] \
            or not 8 <= e[4] <= MAX_FILES or e[5] > 65536 or e[6] + e[5] != size - 22 or e[7] != 0:
        raise DistributionError()
    stream.seek(0); digest = hashlib.sha256()
    while True:
        raw = stream.read(65536)
        if not raw:
            break
        digest.update(raw)
    if digest.hexdigest() != m['archive']['sha256']:
        raise DistributionError()
    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        rows = archive.infolist()
        if len(rows) != len(m['files']) or len({i.filename for i in rows}) != len(rows) \
                or {i.filename for i in rows} != set(m['files']):
            raise DistributionError()
        for item in rows:
            record = m['files'][item.filename]
            if item.compress_type != zipfile.ZIP_STORED or item.flag_bits & 1 or item.extra or item.comment \
                    or item.file_size != record['size'] or item.compress_size != item.file_size \
                    or stat.S_IFMT(item.external_attr >> 16) != stat.S_IFREG:
                raise DistributionError()
            digest = hashlib.sha256()
            with archive.open(item) as entry:
                for raw in iter(lambda: entry.read(65536), b''):
                    digest.update(raw)
            if digest.hexdigest() != record['sha256']:
                raise DistributionError()
        meta = object_json(archive.read('payload/release.json'))
        if type(meta) is not dict or set(meta) != {'v', 'entry', 'release', 'runtime', 'artifact', 'files'} or type(meta['v']) is not int or meta['v'] != 1 \
                or meta['entry'] not in ('gui-v1', 'gui-v2') or meta['runtime'] != 'cpython-3.13.16-amd64' \
                or type(meta['files']) is not dict or meta['release'] != m['release'] or meta['artifact'] != m['artifact'] \
                or hashlib.sha256(canonical({k: v for k, v in meta.items() if k != 'release'})).hexdigest() != m['release'] \
                or {'payload/' + name for name in meta['files']} != set(m['files']) - {'P6Setup.exe', 'Setup.ps1', 'payload.cat', 'payload/release.json'}:
            raise DistributionError()
        for name, record in meta['files'].items():
            if record != m['files']['payload/' + name]:
                raise DistributionError()
        if archive.read('payload/runtime/python313._pth') != b'python313.zip\n.\n../p6-agent.pyz\n../p6-installer.pyz\n':
            raise DistributionError()
        if m['files']['payload/p6-agent.pyz'] != {k: m['artifact'][k] for k in ('sha256', 'size')}:
            raise DistributionError()
    stream.seek(0)


def directory(path, exact=True):
    path = os.path.abspath(path); original = path
    while True:
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or not s.st_mode & 1 \
                or (path == original and exact and (s.st_gid, stat.S_IMODE(s.st_mode)) != (0, 0o755)):
            raise DistributionError()
        parent = os.path.dirname(path)
        if path == parent:
            return
        path = parent


@contextlib.contextmanager
def opened(path):
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd); after = os.lstat(path)
        if not stat.S_ISREG(s.st_mode) or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) != (0, 0, 0o644, 1) \
                or not 0 < s.st_size <= MAX_ARCHIVE \
                or (s.st_dev, s.st_ino) != (before.st_dev, before.st_ino) \
                or (s.st_dev, s.st_ino) != (after.st_dev, after.st_ino):
            raise DistributionError()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            yield stream, s
    finally:
        os.close(fd)


@contextlib.contextmanager
def open_release(expected_artifact, root=DISTRIBUTION_DIR):
    try:
        directory(root)
        pointer = object_json(_read(os.path.join(root, 'current.json'), 256))
        if type(pointer) is not dict or set(pointer) != {'v', 'archive_sha256'} or type(pointer['v']) is not int \
                or pointer['v'] != 1 or type(pointer['archive_sha256']) is not str or not HEX.fullmatch(pointer['archive_sha256']):
            raise DistributionError()
        version = os.path.join(root, pointer['archive_sha256']); directory(version)
        if set(os.listdir(version)) != {'release.json', 'windows-installer.zip'}:
            raise DistributionError()
        m = validate_manifest_record(object_json(_read(os.path.join(version, 'release.json'), MAX_MANIFEST)))
        if (expected_artifact is not None and m['artifact'] != expected_artifact) or m['archive']['sha256'] != pointer['archive_sha256']:
            raise DistributionError()
        with opened(os.path.join(version, 'windows-installer.zip')) as (stream, s):
            verify_archive(stream, m)
            now = os.fstat(stream.fileno())
            if (s.st_size, s.st_mtime_ns, s.st_ctime_ns) != (now.st_size, now.st_mtime_ns, now.st_ctime_ns):
                raise DistributionError()
            yield m, stream
    except (ArtifactError, OSError, ValueError, TypeError, KeyError, AttributeError, struct.error, zipfile.BadZipFile, RuntimeError):
        raise DistributionError() from None


def write_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb', closefd=False) as target:
            target.write(raw); target.flush(); os.fsync(fd)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(package, manifest_path, expected_digest, publisher, scope, artifact, root=DISTRIBUTION_DIR):
    """Root CLI only. No automatic eviction/replacement of another publisher."""
    if os.geteuid() != 0 or not HEX.fullmatch(expected_digest) or not re.fullmatch(r'[0-9A-F]{40}', publisher):
        raise DistributionError()
    raw = _read(manifest_path, MAX_MANIFEST)
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise DistributionError()
    m = validate_manifest_record(object_json(raw))
    if m['publisher'] != publisher or m['scope'] != scope or m['artifact'] != artifact:
        raise DistributionError()
    if not os.path.exists(root):
        directory(os.path.dirname(root), exact=False)
        try:
            os.mkdir(root, 0o755)
        except FileExistsError:
            # Another root publisher may win first creation before our flock
            # exists. Never chmod/adopt its object: the full exact directory
            # authority/no-link check below still decides admission.
            pass
        else:
            os.chmod(root, 0o755)
    directory(root)
    lock = os.path.join(root, '.publish.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    stage = None
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size != 0 or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) != (0, 0, 0o600, 1):
            raise DistributionError()
        fcntl.flock(fd, fcntl.LOCK_EX)
        children = set(os.listdir(root)); versions = {x for x in children if HEX.fullmatch(x)}
        if len(versions) > 2 or children - versions - {'current.json', '.publish.lock'}:
            raise DistributionError()
        # Admission proves all retained managed versions remain within the
        # footprint bound, including an interrupted unpublished version.
        for name in versions:
            retained = os.path.join(root, name); directory(retained)
            if set(os.listdir(retained)) != {'release.json', 'windows-installer.zip'}:
                raise DistributionError()
            old = validate_manifest_record(object_json(_read(os.path.join(retained, 'release.json'), MAX_MANIFEST)))
            if old['archive']['sha256'] != name:
                raise DistributionError()
            with opened(os.path.join(retained, 'windows-installer.zip')) as (stream, _):
                verify_archive(stream, old)
        if 'current.json' in children:
            with open_release(None, root) as (current, _):
                if current['publisher'] != publisher or current['scope'] != scope:
                    raise DistributionError()
        identity = m['archive']['sha256']; destination = os.path.join(root, identity)
        if identity not in versions and len(versions) >= 2:
            raise DistributionError()
        with opened(package) as (source, snapshot):
            verify_archive(source, m)
            if identity not in versions:
                stage = os.path.join(root, '.stage-' + uuid.uuid4().hex); os.mkdir(stage, 0o700)
                target = os.path.join(stage, 'windows-installer.zip')
                out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                try:
                    os.fchmod(out, 0o644)
                    with os.fdopen(out, 'wb', closefd=False) as output:
                        copied = 0; digest = hashlib.sha256()
                        for chunk in iter(lambda: source.read(65536), b''):
                            copied += len(chunk)
                            if copied > MAX_ARCHIVE:
                                raise DistributionError()
                            output.write(chunk); digest.update(chunk)
                        output.flush(); os.fsync(out)
                    if copied != m['archive']['size'] or digest.hexdigest() != identity:
                        raise DistributionError()
                finally:
                    os.close(out)
                write_file(os.path.join(stage, 'release.json'), raw); sync_dir(stage)
                os.chmod(stage, 0o755); os.rename(stage, destination); stage = None; sync_dir(root)
            else:
                directory(destination)
                if _read(os.path.join(destination, 'release.json'), MAX_MANIFEST) != raw:
                    raise DistributionError()
                with opened(os.path.join(destination, 'windows-installer.zip')) as (installed, _):
                    verify_archive(installed, m)
        pointer = os.path.join(root, '.stage-' + uuid.uuid4().hex)
        write_file(pointer, canonical({'v': 1, 'archive_sha256': identity}))
        os.replace(pointer, os.path.join(root, 'current.json')); sync_dir(root)
        return {'scope': scope, 'release': m['release'], 'archive_sha256': identity, 'publisher': publisher}
    finally:
        if stage is not None:
            for name in ('release.json', 'windows-installer.zip'):
                path = os.path.join(stage, name)
                if os.path.exists(path):
                    os.unlink(path)
            os.rmdir(stage)
        os.close(fd)


def retire(selector, root=DISTRIBUTION_DIR, stage=False):
    """Explicit root retirement; never current, recursive or foreign cleanup."""
    if os.geteuid() != 0 or not re.fullmatch(r'[0-9a-f]{32}' if stage else r'[0-9a-f]{64}', selector):
        raise DistributionError()
    directory(root)
    fd = os.open(os.path.join(root, '.publish.lock'), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size != 0 or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) != (0, 0, 0o600, 1):
            raise DistributionError()
        fcntl.flock(fd, fcntl.LOCK_EX)
        path = os.path.join(root, '.stage-' + selector if stage else selector)
        if not stage:
            with open_release(None, root) as (current, _):
                if current['archive']['sha256'] == selector:
                    raise DistributionError()
            directory(path)
            m = validate_manifest_record(object_json(_read(os.path.join(path, 'release.json'), MAX_MANIFEST)))
            if m['archive']['sha256'] != selector:
                raise DistributionError()
            with opened(os.path.join(path, 'windows-installer.zip')) as (stream, _):
                verify_archive(stream, m)
        else:
            s = os.lstat(path)
            if stat.S_ISREG(s.st_mode):
                _read(path, 256); os.unlink(path); sync_dir(root); return
            if not stat.S_ISDIR(s.st_mode) or (s.st_uid, s.st_gid) != (0, 0) or stat.S_IMODE(s.st_mode) not in (0o700, 0o755):
                raise DistributionError()
        names = set(os.listdir(path))
        if names - {'release.json', 'windows-installer.zip'}:
            raise DistributionError()
        for name in names:
            s = os.lstat(os.path.join(path, name))
            if not stat.S_ISREG(s.st_mode) or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) != (0, 0, 0o644, 1) \
                    or s.st_size > (MAX_MANIFEST if name == 'release.json' else MAX_ARCHIVE):
                raise DistributionError()
        for name in names:
            os.unlink(os.path.join(path, name))
        os.rmdir(path); sync_dir(root)
    finally:
        os.close(fd)
