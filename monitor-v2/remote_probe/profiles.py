"""Bounded profile vault; immutable enrollment, separate mutable control.

Inputs are delivered by the future trusted bundle installer. This is not an
arbitrary ZIP extractor or server provisioning endpoint. Secrets are separate
files, never included in profile/status objects. Publication is one directory
rename; interrupted staging is inert and counts towards the eight-slot cap.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import uuid

from .agent import AgentConfig, ConfigError
from .pinned_transport import PinnedHttpsIngest
from .spool import _InstanceLock, _fsync_dir, _write_all, check_no_symlink_component
from .windows_security import StorageSecurityError, WindowsSecurity

MAX_PROFILES = 8
MANIFEST_LIMIT = 16384
CERT_LIMIT = 16384
SECRET_LIMIT = 128
ALLOWED_AGENT = {"mihomo_url", "reality_node", "hy2_node", "dns_host",
                 "https_host", "egress_host", "vps_host", "vps_port",
                 "watched_group", "cadence", "cycle_deadline", "diagnostic_timeout"}
MANIFEST_KEYS = {"v", "server_id", "probe_id", "ingest_url", "certificate_sha256", "agent"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def profile_id(manifest):
    server = manifest.get("server_id")
    probe = manifest.get("probe_id")
    if type(server) is not str or not re.fullmatch(r"[0-9a-f]{32}", server):
        raise ConfigError("invalid server identity")
    if type(probe) is not str or not re.fullmatch(r"[a-z0-9-]{1,64}", probe):
        raise ConfigError("invalid probe identity")
    return hashlib.sha256((server + "\n" + probe).encode("ascii")).hexdigest()


def durable_replace(source, target):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes as W
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.MoveFileExW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
        kernel.MoveFileExW.restype = W.BOOL
        if not kernel.MoveFileExW(source, target, 1 | 8):
            raise StorageSecurityError("durable publication failed")
    else:
        os.replace(source, target)
        _fsync_dir(os.path.dirname(target))


class PosixSecurity:
    """Linux test/management policy; Windows never selects this fallback."""
    def check_components(self, path):
        check_no_symlink_component(path)

    def validate(self, path, directory=False):
        check_no_symlink_component(path)
        st = os.lstat(path)
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(st.st_mode) or st.st_uid != os.getuid():
            raise StorageSecurityError("unsafe storage object")
        if stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
            raise StorageSecurityError("unsafe storage permissions")

    def mkdir(self, path):
        check_no_symlink_component(path)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        self.validate(path, True)

    def validate_fd(self, fd):
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise StorageSecurityError("unsafe open file")

    def read(self, path, limit):
        self.validate(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.lstat(path)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise StorageSecurityError("storage object changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise StorageSecurityError("protected file oversized")
            return data
        finally:
            os.close(fd)


class ProfileVault:
    def __init__(self, root, security=None):
        self.root = os.path.abspath(root)
        self.security = security or (WindowsSecurity() if os.name == "nt" else PosixSecurity())

    def open(self):
        self.security.mkdir(self.root)
        return self

    def _path(self, key):
        if type(key) is not str or not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ConfigError("invalid profile identifier")
        return os.path.join(self.root, key)

    def _lock(self):
        self.security.validate(self.root, True)
        lock = _InstanceLock(os.path.join(self.root, "vault.lock"))
        self.security.check_components(lock.path)
        lock.acquire()
        try:
            self.security.validate_fd(lock.fd)
        except BaseException:
            lock.release()
            raise
        return lock

    def _write(self, directory, name, data):
        self.security.validate(directory, True)
        path = os.path.join(directory, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        try:
            self.security.validate_fd(fd)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(directory)

    def _validate(self, manifest, certificate):
        if type(manifest) is not dict or set(manifest) != MANIFEST_KEYS or type(manifest["v"]) is not int or manifest["v"] != 1:
            raise ConfigError("invalid provisioning manifest")
        key = profile_id(manifest)
        if len(canonical(manifest)) > MANIFEST_LIMIT:
            raise ConfigError("manifest oversized")
        agent = manifest["agent"]
        if type(agent) is not dict or set(agent) - ALLOWED_AGENT:
            raise ConfigError("invalid agent settings")
        transport = PinnedHttpsIngest(manifest["ingest_url"], certificate,
                                      manifest["certificate_sha256"])
        if agent.get("vps_host") != transport.host:
            raise ConfigError("probe target differs from originating server")
        for field in ("cadence", "cycle_deadline", "diagnostic_timeout"):
            if field in agent and (type(agent[field]) not in (int, float) or not math.isfinite(agent[field])):
                raise ConfigError("invalid timing setting")
        self.agent_config(key, manifest)
        from .mihomo_probe import parse_controller_url, ConfigurationError
        try:
            parse_controller_url(agent["mihomo_url"])
        except ConfigurationError:
            raise ConfigError("controller must be loopback") from None
        return key

    def agent_config(self, key, manifest):
        directory = self._path(key)
        return AgentConfig(probe_id=manifest["probe_id"], ingest_url=manifest["ingest_url"],
                           spool_dir=os.path.join(directory, "spool"),
                           ingest_secret_file=os.path.join(directory, "ingest.key"),
                           **manifest["agent"])

    def import_profile(self, manifest, secret, certificate, controller_secret=None):
        if type(secret) is not bytes or len(secret) != 32:
            raise ConfigError("independent 256-bit secret required")
        if controller_secret is not None and (type(controller_secret) is not str
                or len(controller_secret.encode('utf-8')) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in controller_secret)):
            raise ConfigError("invalid local controller credential")
        key = self._validate(manifest, certificate)
        lock = self._lock()
        stage = None
        try:
            target = self._path(key)
            if os.path.lexists(target):
                existing = self.load(key)
                import hmac
                if existing != manifest or not hmac.compare_digest(self.read_secret(key), secret) or self.read_certificate(key) != certificate:
                    raise ConfigError("identity change requires explicit replacement")
                if controller_secret is not None:
                    path = os.path.join(target, 'mihomo.key')
                    original = self.security.read(path, 4096).decode('utf-8') if os.path.lexists(path) else ''
                    if not hmac.compare_digest(original.encode('utf-8'), controller_secret.encode('utf-8')):
                        raise ConfigError("local controller credential change requires explicit replacement")
                return key, False
            # Staging left by a crash is never activated and cannot evade capacity.
            slots = sum(1 for name in os.listdir(self.root) if re.fullmatch(r"[0-9a-f]{64}", name) or name.startswith(".enroll-"))
            if slots >= MAX_PROFILES:
                raise ConfigError("profile capacity reached")
            stage = os.path.join(self.root, ".enroll-" + uuid.uuid4().hex)
            self.security.mkdir(stage)
            self._write(stage, "profile.json", canonical(manifest))
            self._write(stage, "ingest.key", secret.hex().encode("ascii") + b"\n")
            self._write(stage, "server.pem", certificate.encode("ascii"))
            self._write(stage, "control.json", canonical({"enabled": True}))
            if controller_secret:
                self._write(stage, "mihomo.key", controller_secret.encode('utf-8'))
            self.security.mkdir(os.path.join(stage, "spool"))
            durable_replace(stage, target)
            stage = None
            return key, True
        finally:
            if stage is not None:
                shutil.rmtree(stage)
            lock.release()

    def _read(self, key, name, limit):
        directory = self._path(key)
        self.security.validate(self.root, True)
        self.security.validate(directory, True)
        return self.security.read(os.path.join(directory, name), limit)

    def load(self, key):
        try:
            manifest = json.loads(self._read(key, "profile.json", MANIFEST_LIMIT))
            if self._validate(manifest, self.read_certificate(key)) != key:
                raise ConfigError("profile identity mismatch")
            return manifest
        except (ValueError, UnicodeError, TypeError, KeyError):
            raise ConfigError("invalid stored profile") from None

    def read_certificate(self, key):
        return self._read(key, "server.pem", CERT_LIMIT).decode("ascii")

    def read_secret(self, key):
        value = self._read(key, "ingest.key", SECRET_LIMIT).strip()
        if not re.fullmatch(b"[0-9a-f]{64}", value):
            raise ConfigError("invalid stored secret")
        return bytes.fromhex(value.decode("ascii"))

    def enabled(self, key):
        try:
            control = json.loads(self._read(key, "control.json", 128))
            if set(control) != {"enabled"} or type(control["enabled"]) is not bool:
                raise ValueError()
            return control["enabled"]
        except (ValueError, TypeError):
            raise ConfigError("invalid profile control") from None

    def set_enabled(self, key, enabled):
        if type(enabled) is not bool:
            raise ConfigError("invalid control state")
        lock = self._lock()
        temp = ".control-" + uuid.uuid4().hex
        try:
            self.load(key)
            directory = self._path(key)
            self._write(directory, temp, canonical({"enabled": enabled}))
            durable_replace(os.path.join(directory, temp), os.path.join(directory, "control.json"))
        finally:
            lock.release()

    def keys(self):
        self.security.validate(self.root, True)
        keys = sorted(name for name in os.listdir(self.root) if re.fullmatch(r"[0-9a-f]{64}", name))
        if len(keys) > MAX_PROFILES:
            raise ConfigError("profile capacity reached")
        return keys

    def purge(self, key):
        """Explicit destructive action; pause first, wait for runtime to close.

        Holding spool's existing single-writer lock prevents deleting a running
        profile. Walk validates every object before removing the bounded tree.
        """
        lock = self._lock()
        spool_lock = None
        try:
            self.load(key)
            if self.enabled(key):
                raise ConfigError("pause profile before purge")
            directory = self._path(key)
            spool_path = os.path.join(directory, "spool")
            self.security.validate(spool_path, True)
            spool_lock = _InstanceLock(os.path.join(spool_path, "spool.lock"))
            self.security.check_components(spool_lock.path)
            spool_lock.acquire()
            for current, directories, files in os.walk(directory, followlinks=False):
                self.security.validate(current, True)
                for name in directories:
                    self.security.validate(os.path.join(current, name), True)
                for name in files:
                    path = os.path.join(current, name)
                    if path == spool_lock.path:
                        self.security.validate_fd(spool_lock.fd)
                    else:
                        self.security.validate(path)
            # Windows cannot unlink an open locking file; retain the vault lock
            # while releasing spool.lock. Disabled profiles are never reopened.
            spool_lock.release()
            spool_lock = None
            shutil.rmtree(directory)
            _fsync_dir(self.root)
        finally:
            if spool_lock is not None:
                spool_lock.release()
            lock.release()
