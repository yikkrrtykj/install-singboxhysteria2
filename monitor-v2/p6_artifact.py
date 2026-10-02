"""Permission-protected, digest-verified generic Agent; never contains profiles.

The privileged response carries only its bounded manifest. Both export planes
read the same installed public artifact, not a URL or browser-selected path.
"""
import hashlib
import json
import os
import re
import stat

# Generic code is public/read-only. The root-only helper tree is intentionally
# not traversable by sboxweb and must never become an artifact parent.
ARTIFACT_DIR = '/usr/local/share/sbox-p6-artifact'
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MANIFEST_KEYS = {'v', 'version', 'sha256', 'size'}


class ArtifactError(Exception):
    def __init__(self):
        super().__init__('E_P6_ARTIFACT')


def validate_manifest(value):
    if type(value) is not dict or set(value) != MANIFEST_KEYS or type(value['v']) is not int \
            or value['v'] != 1 or type(value['version']) is not str \
            or not re.fullmatch(r'p6-agent-source-1-[0-9a-f]{16}', value['version']) \
            or type(value['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['sha256']) \
            or type(value['size']) is not int or not 0 < value['size'] <= MAX_ARTIFACT_BYTES \
            or value['version'] != 'p6-agent-source-1-' + value['sha256'][:16]:
        raise ArtifactError()
    return value


def _read(path, limit):
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        after = os.lstat(path)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 \
                or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (0, 0, 0o644) \
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) \
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise ArtifactError()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit or os.fstat(fd).st_size != len(raw):
            raise ArtifactError()
        return raw
    finally:
        os.close(fd)


def read_artifact(directory=ARTIFACT_DIR):
    """Directory override is constructor/test wiring, never HTTP/RPC input."""
    try:
        if os.name != 'posix':
            raise ArtifactError()
        path = os.path.abspath(directory)
        while True:
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 \
                    or not st.st_mode & 0o001:
                raise ArtifactError()
            if path == os.path.abspath(directory) and (st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0o755):
                raise ArtifactError()
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        manifest = validate_manifest(json.loads(_read(os.path.join(directory, 'artifact.json'), 2048)))
        raw = _read(os.path.join(directory, 'p6-agent.pyz'), MAX_ARTIFACT_BYTES)
        if len(raw) != manifest['size'] or hashlib.sha256(raw).hexdigest() != manifest['sha256']:
            raise ArtifactError()
        return manifest, raw
    except (OSError, ValueError, TypeError, KeyError):
        raise ArtifactError() from None
