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
        self.allowed = {"S-1-5-18", "S-1-5-32-544"}
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
        self.a.ConvertSidToStringSidW.argtypes = [W.LPVOID, ctypes.POINTER(W.LPWSTR)]
        self.a.ConvertSidToStringSidW.restype = W.BOOL
        self.a.GetAce.argtypes = [W.LPVOID, W.DWORD, ctypes.POINTER(W.LPVOID)]
        self.a.GetAce.restype = W.BOOL
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
        """Compare canonical native SIDs, not OS-dependent SDDL aliases.

        Windows Server renders a fixture's local Administrator SID as LA;
        client Windows often renders its full SID. They are the same SID.
        """
        descriptor = W.LPVOID()
        owner = W.LPVOID()
        dacl = W.LPVOID()
        code = self.a.GetSecurityInfo(handle, 1, 1 | 4, ctypes.byref(owner), None,
                                      ctypes.byref(dacl), None,
                                      ctypes.byref(descriptor))
        if code:
            raise StorageSecurityError("security descriptor unavailable")
        def sid_string(sid):
            text = W.LPWSTR()
            if not self.a.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise StorageSecurityError("invalid security principal")
            try:
                return text.value
            finally:
                self.k.LocalFree(ctypes.cast(text, W.LPVOID))
        try:
            if not owner or not dacl:
                raise StorageSecurityError("missing restricted DACL/owner")
            class ACL(ctypes.Structure):
                _fields_ = [("revision", W.BYTE), ("reserved", W.BYTE),
                            ("size", W.WORD), ("count", W.WORD), ("reserved2", W.WORD)]
            class ACE(ctypes.Structure):
                _fields_ = [("kind", W.BYTE), ("flags", W.BYTE),
                            ("size", W.WORD), ("mask", W.DWORD)]
            acl = ctypes.cast(dacl, ctypes.POINTER(ACL)).contents
            if not 0 < acl.count <= 8:
                raise StorageSecurityError("unsafe storage DACL")
            entries = []
            for index in range(acl.count):
                pointer = W.LPVOID()
                if not self.a.GetAce(dacl, index, ctypes.byref(pointer)):
                    raise StorageSecurityError("invalid storage DACL")
                ace = ctypes.cast(pointer, ctypes.POINTER(ACE)).contents
                if ace.kind != 0 or ace.size < 16:
                    raise StorageSecurityError("unsafe storage DACL")
                entries.append((ace.flags, ace.mask, sid_string(pointer.value + 8)))
            return sid_string(owner), entries
        finally:
            self.k.LocalFree(descriptor)

    def _check_handle(self, handle, directory):
        # FILE_ATTRIBUTE_TAG_INFO, queried on the exact opened object.
        attrs = (W.DWORD * 2)()
        if not self.k.GetFileInformationByHandleEx(handle, 9, attrs, ctypes.sizeof(attrs)):
            raise StorageSecurityError("file attributes unavailable")
        if attrs[0] & 0x400 or bool(attrs[0] & 0x10) != bool(directory):
            raise StorageSecurityError("unsafe storage object")
        owner, entries = self._descriptor(handle)
        if owner not in self.allowed:
            raise StorageSecurityError("unsafe storage owner")
        principals = set()
        for flags, mask, principal in entries:
            if principal not in self.allowed:
                raise StorageSecurityError("unsafe storage DACL")
            if mask != 0x1f01ff or flags & 0x08:
                raise StorageSecurityError("incomplete storage authority")
            principals.add(principal)
        if "S-1-5-18" not in principals:
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
