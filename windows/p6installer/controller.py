"""One explicitly supported local source; never edits Clash or exposes secrets."""
import ctypes
import json
import os
from pathlib import Path
import re

from remote_probe.agent import ConfigError
from remote_probe.mihomo_probe import ConfigurationError, parse_controller_url
from remote_probe.windows_security import WindowsSecurity

SOURCE_LIMIT = 256 * 1024
APP = 'io.github.clash-verge-rev.clash-verge-rev'


class DiscoveryError(ConfigError):
    pass


def _scalar(value):
    value = value.strip()
    if value.startswith('"'):
        result = json.loads(value)
        if type(result) is not str:
            raise ValueError()
        return result
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ValueError()
        inner = value[1:-1]
        if "'" in inner.replace("''", ''):
            raise ValueError()
        return inner.replace("''", "'")
    # Only an unambiguous string subset; do not implement a YAML loader.
    if not value or not re.fullmatch(r'[A-Za-z0-9_.:/+~=-]*', value) \
            or value.lower() in ('null', 'true', 'false', 'yes', 'no', 'on', 'off', '~') \
            or re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]+)?', value):
        raise ValueError()
    return value


def extract_credential(raw, expected_url):
    """Pure parser. Caller must enforce source authority on the opened object."""
    try:
        if len(raw) > SOURCE_LIMIT or b'\x00' in raw:
            raise ValueError()
        text = raw.decode('utf-8-sig')
        values = {}
        for line in text.splitlines():
            if not line or line[0].isspace() or line.startswith('#'):
                continue
            if line.startswith(('<<:', '&', '*', '---', '...', '%')):
                raise ValueError()
            match = re.match(r'^(external-controller|secret)\s*:\s*(.*)$', line)
            if not match:
                # Quoted/aliased versions of these keys are unsupported, not ignored.
                if re.match(r'''^["']?(external-controller|secret)["']?\s*:''', line):
                    raise ValueError()
                continue
            key = match[1]
            if key in values:
                raise ValueError()
            values[key] = _scalar(match[2])
        if set(values) != {'external-controller', 'secret'}:
            raise ValueError()
        host, port, scheme = parse_controller_url(expected_url)
        found_host, found_port, found_scheme = parse_controller_url('http://' + values['external-controller'])
        normalize = lambda h: '127.0.0.1' if h == 'localhost' else h
        if (normalize(host), port, scheme) != (normalize(found_host), found_port, found_scheme):
            raise ValueError()
        secret = values['secret']
        if len(secret.encode('utf-8')) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise ValueError()
        return secret
    except (ValueError, UnicodeError, TypeError, KeyError, ConfigError, ConfigurationError):
        raise DiscoveryError('local_controller_discovery_unavailable') from None


def _current_user_sid():
    from ctypes import wintypes as W
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    adv.GetTokenInformation.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [W.LPVOID, ctypes.POINTER(W.LPWSTR)]
    kernel.LocalFree.argtypes = [W.LPVOID]
    token, size = W.HANDLE(), W.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ConfigError('local_controller_discovery_unavailable')
    try:
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 8 <= size.value <= 4096:
            raise ConfigError('local_controller_discovery_unavailable')
        data = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise ConfigError('local_controller_discovery_unavailable')
        sid = ctypes.cast(data, ctypes.POINTER(W.LPVOID)).contents.value
        result = W.LPWSTR()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(result)):
            raise ConfigError('local_controller_discovery_unavailable')
        try:
            return result.value
        finally:
            kernel.LocalFree(ctypes.cast(result, W.LPVOID))
    finally:
        kernel.CloseHandle(token)


class LocalSourceSecurity(WindowsSecurity):
    """Separate source policy. Never use it for the installed profile vault."""
    def __init__(self):
        super().__init__()
        self.allowed.add(_current_user_sid())


def discover_credential(expected_url):
    try:
        if os.name != 'nt':
            raise ConfigError('local_controller_discovery_unavailable')
        buffer = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 26, None, 0, buffer):
            raise ConfigError('local_controller_discovery_unavailable')
        path = Path(buffer.value) / APP / 'clash-verge.yaml'
        raw = LocalSourceSecurity().read(str(path), SOURCE_LIMIT)
        return extract_credential(raw, expected_url)
    except Exception:
        # Source paths, parser bodies and credential strings never enter diagnostics.
        raise DiscoveryError('local_controller_discovery_unavailable') from None
