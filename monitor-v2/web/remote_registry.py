"""Server-side probe registry (issue #67 §10, PR-6B).

The operator is the ONLY authority for probe identity metadata. The config
file maps ``probe_id -> enabled -> site_label/path_label`` and names the key
file; the payload can never authoritatively define site, path, ISP or
provider, and no IP/ASN inference exists anywhere in this module.

Frozen filesystem contract (production):

- config ``/etc/singbox-monitor/remote-probes.json``  regular, 0640;
- key dir  ``/etc/singbox-monitor/remote-probes.d/``  real dir, 0750;
- keys     ``.../remote-probes.d/<name>.key``         regular, no-follow, 0640.

Loading uses exactly the E4-Diag class of primitives: open with
``O_NOFOLLOW``, fstat the open descriptor (regular file, same object), and
-- on POSIX -- verify the frozen permission bits. A malformed config or key
disables ONLY the affected remote identity (or the whole remote plane for a
malformed config): it never raises into Monitor, History, the scanner, the
broker, the journal-reader, sing-box or Mihomo.

Every per-probe key is exactly 64 lowercase hex characters -> the exact
32-byte / 256-bit HMAC key PR-6A signs with. Weak/malformed keys refuse that
identity. ``DUMMY_KEY`` is the fixed material used for the unknown-identity
dummy HMAC work: unknown and disabled identities execute the same HMAC
computation as known ones and then expose the SAME closed authentication
failure, so no identity enumeration oracle exists.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat as stat_module

from remote_probe import PROBE_ID_PATTERN, RUN_PATTERN

REMOTE_CONFIG_PATH = "/etc/singbox-monitor/remote-probes.json"
REMOTE_KEY_DIR = "/etc/singbox-monitor/remote-probes.d"
MAX_PROBES = 64                       # §3: maximum configured identities
MAX_LABEL_CHARS = 64                  # bounded operational text, not notes
MAX_KEYFILE_CHARS = 128

_CONFIG_VERSION = 1
_CONFIG_KEYS = frozenset({"v", "probes"})
_PROBE_ENTRY_KEYS = frozenset({"probe_id", "enabled", "site_label",
                               "path_label", "key_file"})

_PROBE_ID_RE = re.compile(r"\A%s\Z" % PROBE_ID_PATTERN)
_RUN_RE = re.compile(r"\A%s\Z" % RUN_PATTERN)
_KEY_FILE_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,127}\Z")
_LABEL_RE = re.compile(r"\A[ -~]{1,%d}\Z" % MAX_LABEL_CHARS)

_SECRET_HEX_CHARS = 64                # 64 lowercase hex == exactly 256 bits

# Fixed non-secret dummy material: the HMAC work an UNKNOWN identity still
# performs so its timing is the same as a known one's. It verifies nothing.
DUMMY_KEY = hashlib.sha256(b"p6-v1 remote-probe dummy identity key"
                           ).digest()

# Closed registry health (the plane aggregates it into remote status).
REGISTRY_NOT_CONFIGURED = "not_configured"
REGISTRY_READY = "ready"
REGISTRY_DEGRADED = "degraded"
SUBCODE_REMOTE_CONFIG_INVALID = "remote_config_invalid"


class RegistryError(Exception):
    """The registry is unusable for the whole plane (sanitized text only)."""


def _open_regular(path, mode_bits):
    """Open a regular, no-follow file and verify it on the OPEN descriptor.

    Returns ``(fd, st)`` or raises ``RegistryError``. On POSIX the frozen
    permission bits are enforced; on other hosts the shape checks still run.
    """
    flags = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, os.O_RDONLY | flags)
    except FileNotFoundError:
        raise RegistryError("registry file absent") from None
    except OSError as exc:
        # O_NOFOLLOW turns a symlink into ELOOP; everything else is sanitized.
        raise RegistryError("registry file refused: %s"
                            % type(exc).__name__) from None
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise RegistryError("registry file must be a regular file")
        if os.name == "posix":
            if stat_module.S_IMODE(st.st_mode) != mode_bits:
                raise RegistryError("registry file mode must be %04o"
                                    % mode_bits)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _read_bounded(fd, limit):
    chunks = []
    remaining = int(limit)
    while remaining > 0:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_secret_key(raw):
    """Key-file bytes -> the exact 32-byte key, or None when unusable.

    Exactly 64 LOWERCASE hex characters (PR-6A's key representation) with
    optional surrounding ASCII whitespace; anything else -- uppercase,
    short, long, non-hex, binary -- is a weak/malformed key and is refused.
    """
    if type(raw) is not bytes:
        return None
    text = raw.decode("ascii", errors="strict").strip(" \t\r\n") \
        if len(raw) <= 4096 else None
    if type(text) is not str or len(text) != _SECRET_HEX_CHARS:
        return None
    if any(ch not in "0123456789abcdef" for ch in text):
        return None
    try:
        key = bytes.fromhex(text)
    except ValueError:
        return None
    return key if len(key) == 32 else None


class ProbeEntry:
    """One closed registry row. Labels are operator assertions, never facts."""

    __slots__ = ("probe_id", "enabled", "site_label", "path_label",
                 "key_file", "key")

    def __init__(self, probe_id, enabled, site_label, path_label, key_file,
                 key):
        self.probe_id = probe_id
        self.enabled = enabled
        self.site_label = site_label
        self.path_label = path_label
        self.key_file = key_file
        self.key = key


class RemoteRegistry:
    """The closed probe registry: config + per-identity key material."""

    def __init__(self, config_path=REMOTE_CONFIG_PATH,
                 key_dir=REMOTE_KEY_DIR):
        self.config_path = config_path
        self.key_dir = key_dir
        self.entries = {}
        self.state = REGISTRY_NOT_CONFIGURED
        self.subcode = None
        self.load()

    # -- loading -------------------------------------------------------------

    def load(self):
        """Load config + keys, fail-closed per identity.

        An absent config file is the normal DARK state (not_configured). An
        UNREADABLE or malformed config degrades the whole remote plane; a
        malformed KEY degrades only that identity. Nothing here raises into
        the caller: the worst outcome is a degraded registry that
        authenticates nobody.
        """
        self.entries = {}
        self.state = REGISTRY_NOT_CONFIGURED
        self.subcode = None
        if not os.path.lexists(self.config_path):
            return                      # DARK: no remote plane configured
        try:
            entries, per_identity = self._load_config()
        except RegistryError as exc:
            self.state = REGISTRY_DEGRADED
            self.subcode = SUBCODE_REMOTE_CONFIG_INVALID
            self._reason = str(exc)
            return
        self.entries = entries
        self._identity_problems = per_identity
        self.state = REGISTRY_READY if entries else REGISTRY_DEGRADED
        if not entries:
            self.subcode = SUBCODE_REMOTE_CONFIG_INVALID

    def _load_config(self):
        fd, _st = _open_regular(self.config_path, 0o640)
        try:
            raw = _read_bounded(fd, 256 * 1024)
        finally:
            os.close(fd)
        import json
        try:
            config = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RegistryError("config is not JSON") from None
        if not isinstance(config, dict) or set(config) != _CONFIG_KEYS:
            raise RegistryError("config key-set")
        if config["v"] != _CONFIG_VERSION or isinstance(config["v"], bool):
            raise RegistryError("config version")
        probes = config["probes"]
        if not isinstance(probes, list) or len(probes) > MAX_PROBES:
            raise RegistryError("config probes list")
        entries = {}
        per_identity = {}
        for item in probes:
            if not isinstance(item, dict) or set(item) != _PROBE_ENTRY_KEYS:
                raise RegistryError("probe entry key-set")
            probe_id = item["probe_id"]
            if type(probe_id) is not str or not _PROBE_ID_RE.match(probe_id):
                raise RegistryError("probe_id grammar")
            if probe_id in entries:
                raise RegistryError("duplicate probe_id")
            enabled = item["enabled"]
            if type(enabled) is not bool:
                raise RegistryError("enabled must be bool")
            labels = []
            for label in (item["site_label"], item["path_label"]):
                if type(label) is not str or not _LABEL_RE.match(label or ""):
                    raise RegistryError("label grammar")
                labels.append(label)
            key_file = item["key_file"]
            if type(key_file) is not str \
                    or not _KEY_FILE_RE.match(key_file or "") \
                    or key_file in (".", ".."):
                raise RegistryError("key_file grammar")
            key, problem = self._load_key(key_file)
            if key is None:
                # ONE identity is broken; the plane and every other identity
                # stay usable. The broken identity authenticates nobody.
                per_identity[probe_id] = problem
                continue
            entries[probe_id] = ProbeEntry(probe_id, enabled, labels[0],
                                           labels[1], key_file, key)
        return entries, per_identity

    def _load_key(self, key_file):
        path = os.path.join(self.key_dir, key_file)
        if os.path.abspath(path) \
                != os.path.abspath(os.path.join(self.key_dir, key_file)):
            return None, "key path escapes the key directory"
        try:
            fd, _st = _open_regular(path, 0o640)
        except RegistryError as exc:
            return None, str(exc)
        try:
            raw = _read_bounded(fd, 4096)
        finally:
            os.close(fd)
        key = parse_secret_key(raw)
        if key is None:
            return None, "key material is not 64 lowercase hex"
        return key, None

    # -- lookups -------------------------------------------------------------

    def lookup(self, probe_id):
        """The entry for ``probe_id``, or None when unknown."""
        return self.entries.get(probe_id)

    def health(self):
        """(state, subcode) -- a closed pair for the remote status plane."""
        if self.state == REGISTRY_READY:
            return REGISTRY_READY, None
        if self.state == REGISTRY_DEGRADED:
            return REGISTRY_DEGRADED, (self.subcode
                                       or SUBCODE_REMOTE_CONFIG_INVALID)
        return REGISTRY_NOT_CONFIGURED, None

    def identity_problems(self):
        """Closed mapping of probe_id -> sanitized reason for broken keys."""
        return dict(getattr(self, "_identity_problems", {}))
