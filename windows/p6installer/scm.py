"""Native SCM ownership/configuration checks; never shell-output parsing."""
import ctypes
import os
import time
from ctypes import wintypes as W

from remote_probe.agent import ConfigError

ALL = 0xF01FF


class Config(ctypes.Structure):
    _fields_ = [('kind', W.DWORD), ('start', W.DWORD), ('error', W.DWORD),
                ('binary', W.LPWSTR), ('group', W.LPWSTR), ('tag', W.DWORD),
                ('dependencies', W.LPWSTR), ('account', W.LPWSTR), ('display', W.LPWSTR)]


class Status(ctypes.Structure):
    _fields_ = [(name, W.DWORD) for name in ('kind', 'state', 'accepted', 'exit',
                    'specific', 'checkpoint', 'hint')]


class Action(ctypes.Structure):
    _fields_ = [('kind', W.DWORD), ('delay', W.DWORD)]


class Failure(ctypes.Structure):
    _fields_ = [('reset', W.DWORD), ('reboot', W.LPWSTR), ('command', W.LPWSTR),
                ('count', W.DWORD), ('actions', ctypes.POINTER(Action))]


class Service:
    def __init__(self, name='P6RemoteProbe'):
        if os.name != 'nt':
            raise ConfigError('Windows SCM required')
        self.name = name
        self.a = ctypes.WinDLL('advapi32', use_last_error=True)
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        definitions = {
            'OpenSCManagerW': ([W.LPCWSTR, W.LPCWSTR, W.DWORD], W.HANDLE),
            'OpenServiceW': ([W.HANDLE, W.LPCWSTR, W.DWORD], W.HANDLE),
            'CloseServiceHandle': ([W.HANDLE], W.BOOL),
            'CreateServiceW': ([W.HANDLE, W.LPCWSTR, W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD,
                W.DWORD, W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(W.DWORD), W.LPCWSTR, W.LPCWSTR, W.LPCWSTR], W.HANDLE),
            'QueryServiceConfigW': ([W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL),
            'ChangeServiceConfigW': ([W.HANDLE, W.DWORD, W.DWORD, W.DWORD, W.LPCWSTR,
                W.LPCWSTR, ctypes.POINTER(W.DWORD), W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR], W.BOOL),
            'QueryServiceStatus': ([W.HANDLE, ctypes.POINTER(Status)], W.BOOL),
            'ControlService': ([W.HANDLE, W.DWORD, ctypes.POINTER(Status)], W.BOOL),
            'StartServiceW': ([W.HANDLE, W.DWORD, W.LPVOID], W.BOOL),
            'DeleteService': ([W.HANDLE], W.BOOL),
            'ChangeServiceConfig2W': ([W.HANDLE, W.DWORD, W.LPVOID], W.BOOL),
            'QueryServiceConfig2W': ([W.HANDLE, W.DWORD, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL),
            'QueryServiceObjectSecurity': ([W.HANDLE, W.DWORD, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL),
            'SetServiceObjectSecurity': ([W.HANDLE, W.DWORD, W.LPVOID], W.BOOL),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW': ([W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), W.LPVOID], W.BOOL),
            'ConvertSecurityDescriptorToStringSecurityDescriptorW': ([W.LPVOID, W.DWORD, W.DWORD, ctypes.POINTER(W.LPWSTR), W.LPVOID], W.BOOL),
        }
        for name, (args, result) in definitions.items():
            method = getattr(self.a, name)
            method.argtypes, method.restype = args, result
        self.k.LocalFree.argtypes, self.k.LocalFree.restype = [W.LPVOID], W.LPVOID

    def _check(self, success):
        if not success:
            raise ConfigError('managed service unavailable')

    def _open(self):
        manager = self.a.OpenSCManagerW(None, None, 3)
        self._check(manager)
        service = self.a.OpenServiceW(manager, self.name, ALL)
        code = ctypes.get_last_error()
        if not service and code != 1060:
            self.a.CloseServiceHandle(manager)
            raise ConfigError('managed service unavailable')
        return manager, service

    def _close(self, manager, service):
        if service:
            self.a.CloseServiceHandle(service)
        self.a.CloseServiceHandle(manager)

    def _buffer(self, method, service, *args):
        size = W.DWORD()
        method(service, *args, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise ConfigError('managed service configuration unavailable')
        buffer = ctypes.create_string_buffer(size.value)
        self._check(method(service, *args, buffer, len(buffer), ctypes.byref(size)))
        return buffer

    def _acl(self, service):
        from remote_probe.windows_security import WindowsSecurity
        _owner, entries = WindowsSecurity()._descriptor(service, object_type=5)
        if len(entries) != 2 or {item[2] for item in entries} != {'S-1-5-18', 'S-1-5-32-544'} \
                or any(flags != 0 or mask not in (ALL, 0x10000000) for flags, mask, _ in entries):
            raise ConfigError('unowned service ACL')

    def _config(self, service, expected):
        buffer = self._buffer(self.a.QueryServiceConfigW, service)
        config = ctypes.cast(buffer, ctypes.POINTER(Config)).contents
        self._acl(service)
        if config.kind != 0x10 or config.start != 2 or config.binary != expected \
                or config.account != 'LocalSystem' or config.dependencies or config.group:
            raise ConfigError('unowned service configuration')

    def _state(self, handle):
        state = Status()
        self._check(self.a.QueryServiceStatus(handle, ctypes.byref(state)))
        return state.state

    def _wait(self, handle, state):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            current = self._state(handle)
            if current == state:
                return
            if state == 4 and current == 1:
                raise ConfigError('service startup failed')
            time.sleep(.1)
        raise ConfigError('service did not drain')

    def state(self, expected):
        manager, service = self._open()
        try:
            if not service:
                return 0
            self._config(service, expected)
            return self._state(service)
        finally:
            self._close(manager, service)

    def stop(self, expected):
        manager, service = self._open()
        try:
            if not service:
                return
            self._config(service, expected)
            current = self._state(service)
            if current != 1:
                if current != 3:
                    state = Status()
                    self._check(self.a.ControlService(service, 1, ctypes.byref(state)))
                self._wait(service, 1)
        finally:
            self._close(manager, service)

    def configure(self, command, previous=None):
        manager, service = self._open()
        try:
            if service:
                self._config(service, previous or command)
                if self._state(service) != 1:
                    raise ConfigError('stop managed service before configure')
                self._check(self.a.ChangeServiceConfigW(service, 0x10, 2, 1, command, '', None, '', 'LocalSystem', None, None))
            else:
                service = self.a.CreateServiceW(manager, self.name, self.name, ALL,
                            0x10, 2, 1, command, None, None, None, 'LocalSystem', None)
                self._check(service)
                descriptor = W.LPVOID()
                self._check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    'D:P(A;;GA;;;SY)(A;;GA;;;BA)', 1, ctypes.byref(descriptor), None))
                try:
                    self._check(self.a.SetServiceObjectSecurity(service, 4, descriptor))
                finally:
                    self.k.LocalFree(descriptor)
            actions = (Action * 4)(Action(1, 60000), Action(1, 120000), Action(1, 300000), Action(0, 0))
            failure = Failure(86400, None, None, 4, actions)
            self._check(self.a.ChangeServiceConfig2W(service, 2, ctypes.byref(failure)))
            flag = W.BOOL(True)
            self._check(self.a.ChangeServiceConfig2W(service, 4, ctypes.byref(flag)))
            self._config(service, command)
        finally:
            self._close(manager, service)

    def start(self, expected):
        manager, service = self._open()
        try:
            self._check(service)
            self._config(service, expected)
            if self._state(service) == 1:
                self._check(self.a.StartServiceW(service, 0, None))
            self._wait(service, 4)
        finally:
            self._close(manager, service)

    def delete(self, expected):
        manager, service = self._open()
        try:
            if not service:
                return
            self._config(service, expected)
            if self._state(service) != 1:
                raise ConfigError('stop service before uninstall')
            self._check(self.a.DeleteService(service))
        finally:
            self._close(manager, service)
