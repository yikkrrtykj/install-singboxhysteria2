"""Production-only bounded state-write recovery and closed local diagnostics.

The audited P6A spool owns durability/queue semantics. This adapter does not
delete, reset, acknowledge, or alter its hard/soft failure behavior.
"""
import errno
import json
import os
import time

from .spool import (Spool, SpoolError, STATE_MAX_BYTES, read_restricted,
                    open_restricted, _write_all, _fsync, _fsync_dir,
                    canonical_bytes, check_no_symlink_component, assert_safe_regular)

DIAGNOSTIC_KEY = "production_storage"
FAILURES = ("unknown", "sharing_violation", "permission_denied", "disk_full",
            "io_error", "state_invalid")
MAX_COUNTER = 2**63 - 1
SHARING_DELAYS = (0.02, 0.05)


def closed_diagnostics(value):
    if type(value) is not dict or set(value) != {"last_failure", "sharing_retries"}:
        return None
    if value["last_failure"] not in FAILURES or type(value["sharing_retries"]) is not int \
            or not 0 <= value["sharing_retries"] <= MAX_COUNTER:
        return None
    return dict(value)


def failure_class(error):
    native = getattr(error, "winerror", None)
    number = getattr(error, "errno", None)
    if native in (32, 33):
        return "sharing_violation"
    if native == 5 or number in (errno.EACCES, errno.EPERM):
        return "permission_denied"
    if native in (39, 112) or number in (errno.ENOSPC, getattr(errno, "EDQUOT", -1)):
        return "disk_full"
    if isinstance(error, SpoolError):
        return "state_invalid"
    return "io_error"


class ProductionSpool(Spool):
    def __init__(self, *args, security=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.security = security
        if os.name == "nt" and self.security is None:
            from .windows_security import WindowsSecurity
            self.security = WindowsSecurity()
        self.storage_diagnostics = {"last_failure": "unknown", "sharing_retries": 0}

    def _load_state(self):
        super()._load_state()
        if os.path.lexists(self._state_path()):
            raw = json.loads(read_restricted(self._state_path(), STATE_MAX_BYTES).decode("utf-8"))
            value = closed_diagnostics(raw.get(DIAGNOSTIC_KEY))
            if value is not None:
                self.storage_diagnostics = value

    def _save_state(self):
        for attempt in range(len(SHARING_DELAYS) + 1):
            self._state[DIAGNOSTIC_KEY] = dict(self.storage_diagnostics)
            try:
                self._save_state_once()
                return
            except (SpoolError, OSError) as error:
                self.storage_diagnostics["last_failure"] = failure_class(error)
                if os.name != "nt" or getattr(error, "winerror", None) not in (32, 33) \
                        or attempt == len(SHARING_DELAYS):
                    raise
                self.storage_diagnostics["sharing_retries"] = min(
                    MAX_COUNTER, self.storage_diagnostics["sharing_retries"] + 1)
                time.sleep(SHARING_DELAYS[attempt])

    def _save_state_once(self):
        if os.name != 'nt':
            return super()._save_state()
        payload = canonical_bytes(self._state)
        if len(payload) > STATE_MAX_BYTES:
            raise SpoolError('spool state oversized')
        target = self._state_path()
        temporary = target + '.tmp'
        check_no_symlink_component(temporary)
        check_no_symlink_component(target)
        if os.path.lexists(target):
            assert_safe_regular(target, 'state target')
        if os.path.lexists(temporary):
            assert_safe_regular(temporary, 'state staging')
        from .windows_security import StorageSecurityError
        try:
            self.security.check_components(temporary)
            self.security.check_components(target)
            if os.path.lexists(target):
                self.security.validate(target)
            if os.path.lexists(temporary):
                self.security.validate(temporary)
        except StorageSecurityError:
            raise SpoolError('state authority unavailable') from None
        fd = open_restricted(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            try:
                self.security.validate_fd(fd)
            except StorageSecurityError:
                raise SpoolError('state authority unavailable') from None
            _write_all(fd, payload)
            _fsync(fd)
        finally:
            os.close(fd)
        if os.path.lexists(target):
            import ctypes
            from ctypes import wintypes as W
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.ReplaceFileW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR,
                                           W.DWORD, W.LPVOID, W.LPVOID]
            kernel.ReplaceFileW.restype = W.BOOL
            if not kernel.ReplaceFileW(target, temporary, None, 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(temporary, target)
        _fsync_dir(self.directory)
