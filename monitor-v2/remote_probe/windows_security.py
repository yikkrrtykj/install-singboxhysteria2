"""Native Windows protected storage, without chmod-as-ACL assumptions.

Default allowlist is SYSTEM / Administrators only. A test-only principal may
be injected by callers constructing isolated fixtures; no CLI exposes this.
Windows junctions and all reparse points are refused. ACLs are checked on
opened handles, which also deny sharing for writers during reads.
"""
from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes as W


class StorageSecurityError(Exception):
    pass


class SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


class WindowsSecurity:
    def __init__(self, fixture_sid=None):
        if os.name != "nt":
            raise StorageSecurityError("Windows storage required")
        if fixture_sid is not None and not re.fullmatch(r"S-1-[0-9-]+", fixture_sid):
            raise StorageSecurityError("invalid fixture SID")
        self.allowed = {"SY", "BA", "S-1-5-18", "S-1-5-32-544"}
        if fixture_sid:
            self.allowed.add(fixture_sid)
        self.sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if fixture_sid:
            self.sddl += "(A;OICI;FA;;;" + fixture_sid + ")"
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)
        self.k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
        self.k.CreateFileW.restype = W.HANDLE
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.LocalFree.argtypes = [W.LPVOID]
        self.k.LocalFree.restype = W.LPVOID
        self.k.CreateDirectoryW.argtypes = [W.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
        self.k.CreateDirectoryW.restype = W.BOOL
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), W.LPVOID]
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = W.BOOL
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [W.LPVOID, W.DWORD, W.DWORD, ctypes.POINTER(W.LPWSTR), W.LPVOID]
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = W.BOOL
        self.a.GetSecurityInfo.argtypes = [W.HANDLE, W.DWORD, W.DWORD, W.LPVOID, W.LPVOID, W.LPVOID, W.LPVOID, ctypes.POINTER(W.LPVOID)]
        self.a.GetSecurityInfo.restype = W.DWORD
        self.k.GetFileInformationByHandleEx.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD]
        self.k.GetFileInformationByHandleEx.restype = W.BOOL

    def check_components(self, path):
        path = os.path.abspath(path)
        if path.startswith("\\\\") or ":" in path[2:]:
            raise StorageSecurityError("network/alternate-stream path refused")
        current = path
        while True:
            try:
                st = os.lstat(current)
                if getattr(st, "st_file_attributes", 0) & 0x400:
                    raise StorageSecurityError("reparse point refused")
            except FileNotFoundError:
                pass
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

    def _descriptor(self, handle):
        descriptor = W.LPVOID()
        code = self.a.GetSecurityInfo(handle, 1, 1 | 4, None, None, None, None,
                                      ctypes.byref(descriptor))
        if code:
            raise StorageSecurityError("security descriptor unavailable")
        text = W.LPWSTR()
        try:
            if not self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 1 | 4, ctypes.byref(text), None):
                raise StorageSecurityError("security descriptor unavailable")
            return text.value
        finally:
            if text:
                self.k.LocalFree(ctypes.cast(text, W.LPVOID))
            self.k.LocalFree(descriptor)

    def _check_handle(self, handle, directory):
        # FILE_ATTRIBUTE_TAG_INFO, queried on the exact opened object.
        attrs = (W.DWORD * 2)()
        if not self.k.GetFileInformationByHandleEx(handle, 9, attrs, ctypes.sizeof(attrs)):
            raise StorageSecurityError("file attributes unavailable")
        if attrs[0] & 0x400 or bool(attrs[0] & 0x10) != bool(directory):
            raise StorageSecurityError("unsafe storage object")
        sddl = self._descriptor(handle)
        owner = re.search(r"O:(.*?)(?=[GDS]:|$)", sddl)
        if not owner or owner.group(1) not in self.allowed:
            raise StorageSecurityError("unsafe storage owner")
        dacl = sddl.split("D:", 1)[1] if "D:" in sddl else ""
        entries = re.findall(r"\(([^()]*)\)", dacl)
        if not entries or "NO_ACCESS_CONTROL" in dacl:
            raise StorageSecurityError("missing restricted DACL")
        principals = set()
        for entry in entries:
            parts = entry.split(";")
            if len(parts) != 6 or parts[0] != "A" or parts[5] not in self.allowed:
                raise StorageSecurityError("unsafe storage DACL")
            if parts[2] not in ("FA", "0x1f01ff") or "IO" in parts[1]:
                raise StorageSecurityError("incomplete storage authority")
            principals.add(parts[5])
        if not principals.intersection({"SY", "S-1-5-18"}):
            raise StorageSecurityError("SYSTEM access required")

    def open_handle(self, path, directory=False):
        self.check_components(path)
        # READ_CONTROL + GENERIC_READ; share read only; never follow final link.
        handle = self.k.CreateFileW(os.path.abspath(path), 0x80020000, 1, None,
                                     3, 0x00200000 | 0x02000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise StorageSecurityError("protected object unavailable")
        try:
            self._check_handle(handle, directory)
        except BaseException:
            self.k.CloseHandle(handle)
            raise
        return handle

    def validate(self, path, directory=False):
        handle = self.open_handle(path, directory)
        self.k.CloseHandle(handle)

    def validate_fd(self, fd):
        import msvcrt
        self._check_handle(msvcrt.get_osfhandle(fd), False)

    def mkdir(self, path):
        self.check_components(path)
        descriptor = W.LPVOID()
        if not self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                self.sddl, 1, ctypes.byref(descriptor), None):
            raise StorageSecurityError("cannot create restricted DACL")
        try:
            attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            if not self.k.CreateDirectoryW(os.path.abspath(path), ctypes.byref(attrs)):
                if ctypes.get_last_error() != 183:
                    raise StorageSecurityError("protected directory unavailable")
        finally:
            self.k.LocalFree(descriptor)
        self.validate(path, directory=True)

    def read(self, path, limit):
        import msvcrt
        handle = self.open_handle(path)
        # open_osfhandle transfers ownership to fd; no double CloseHandle.
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            self.k.CloseHandle(handle)
            raise
        try:
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    return bytes(data)
                data.extend(chunk)
            raise StorageSecurityError("protected file oversized")
        finally:
            os.close(fd)
