#!/usr/bin/env python3
"""Issue #48 HA-02 -- offline competition-HA batch profile delivery.

One operator-local command turns a local terminal inventory plus two
independent canonical `client.export` trees (A/ and B/) into one dual-active
Mihomo profile per terminal:

    inventory.csv + exports/A/<name>-mihomo.yaml + exports/B/<name>-mihomo.yaml
        -> delivery/<name>-ha.yaml                     (four nodes, per terminal)
        -> delivery/ha-delivery-<config-version>.json  (hashes + rollback)

The canonical parser is NOT reimplemented here: this tool loads
`tools/mihomo-multi-vps-merge.py` and calls its parser, provenance, source and
credential gates, its byte-preserving profile builder and its atomic
no-clobber writer. This file only adds the batch decisions the merge tool
deliberately does not own: the inventory, A-first/B-first role assignment,
batch-wide source/credential consistency, case-insensitive path collisions,
private-directory enforcement (POSIX mode AND real Windows ACL),
all-or-nothing prevalidation, the SHA-256 delivery manifest and rollback of the
files this batch created.

Hermetic: no network, no subprocess, no third-party YAML library. Python 3.10
standard library only. Credentials never appear in argv, stdout, stderr, error
text or the manifest.
"""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import time

MAX_INVENTORY_BYTES = 128 * 1024
MAX_TERMINALS = 256
INVENTORY_HEADER = "terminal,group"
GROUPS = ("A-first", "B-first")
PRIMARY_VPS = {"A-first": "A", "B-first": "B"}
BACKUP_VPS = {"A-first": "B", "B-first": "A"}
OUTPUT_SUFFIX = "-ha.yaml"
MANIFEST_PREFIX = "ha-delivery-"
MANIFEST_SUFFIX = ".json"
MANIFEST_SCHEMA = "mihomo-competition-ha-batch/1"
TOOL_VERSION = "1"
MERGE_TOOL_NAME = "mihomo-multi-vps-merge.py"
EXPORT_SUFFIX = "-mihomo.yaml"

CONFIG_VERSION_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
ROW_RE = re.compile(r"\A([A-Za-z0-9][A-Za-z0-9._-]{0,31}),(A-first|B-first)\Z")

E_USAGE = "E_USAGE"
E_INVENTORY = "E_INVENTORY"
E_INVENTORY_DUPLICATE = "E_INVENTORY_DUPLICATE"
E_SOURCE_MISSING = "E_SOURCE_MISSING"
E_SOURCE_NOT_CANONICAL = "E_SOURCE_NOT_CANONICAL"
E_NAME_MISMATCH = "E_NAME_MISMATCH"
E_SOURCE_COLLISION = "E_SOURCE_COLLISION"
E_CREDENTIAL_REUSE = "E_CREDENTIAL_REUSE"
E_SOURCE_MIXED = "E_SOURCE_MIXED"
E_PATH_CONFLICT = "E_PATH_CONFLICT"
E_OUTPUT_EXISTS = "E_OUTPUT_EXISTS"
E_INSECURE_PERMISSIONS = "E_INSECURE_PERMISSIONS"
E_GENERATED_INVALID = "E_GENERATED_INVALID"
E_TOOL_MISSING = "E_TOOL_MISSING"
E_IO = "E_IO"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

# A Windows delivery directory is only accepted with a conservative
# allowlist: the current operator, SYSTEM, Administrators, plus the two
# owner/inheritance pseudo-principals when (and only when) they are limited to
# inherited child objects. Every other allowed principal -- an unknown local or
# domain group, an object/callback ACE, a missing or NULL DACL -- is refused.
# This is deliberately not a general ACL engine and not a denylist.
ALLOWED_PRINCIPAL_SIDS = frozenset({"S-1-5-18",      # NT AUTHORITY\SYSTEM
                                    "S-1-5-32-544"})  # BUILTIN\Administrators
INHERIT_ONLY_SIDS = frozenset({"S-1-3-0",           # CREATOR OWNER
                               "S-1-3-4"})          # OWNER RIGHTS
# Canonical SID spelling for the SDDL aliases a DACL can contain. Mapping is
# for reporting (and to keep the allowlist comparison exact); aliases outside
# the allowlist remain refused.
SDD_ALIAS = {
    "SY": "S-1-5-18", "BA": "S-1-5-32-544", "CO": "S-1-3-0", "OW": "S-1-3-4",
    "WD": "S-1-1-0", "NU": "S-1-5-2", "IU": "S-1-5-4", "SU": "S-1-5-6",
    "AN": "S-1-5-7", "AU": "S-1-5-11", "RC": "S-1-5-12", "LS": "S-1-5-19",
    "NS": "S-1-5-20", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546",
    "RD": "S-1-5-32-555", "AC": "S-1-15-2-1", "PS": "S-1-5-10",
}
ALLOW_ACE_TYPES = frozenset({"A", "OA"})
DENY_ACE_TYPES = frozenset({"D", "OD"})
IGNORED_ACE_TYPES = frozenset({"AU", "AL", "OU", "OL", "ML", "ID", "RA", "SP"})
KNOWN_ACE_TYPES = ALLOW_ACE_TYPES | DENY_ACE_TYPES | IGNORED_ACE_TYPES
LOCAL_ADMIN_SID_RE = re.compile(r"\AS-1-5-21-\d+-\d+-\d+-500\Z")

_CURRENT_USER_SID = []


class BatchError(Exception):
    """A failure reported only as a fixed code plus non-secret context."""

    def __init__(self, code, exit_status=EXIT_FAILED, terminal=None, vps=None,
                 role=None, detail=None):
        super().__init__(code)
        self.code = code
        self.exit_status = exit_status
        self.terminal = terminal
        self.vps = vps
        self.role = role
        self.detail = detail
        self.rollback = None


class Terminal(object):
    __slots__ = ("name", "group", "a_path", "b_path", "a_profile", "b_profile")

    def __init__(self, name, group):
        self.name = name
        self.group = group
        self.a_path = None
        self.b_path = None
        self.a_profile = None
        self.b_profile = None


def fail(code, **kwargs):
    def raiser():
        return BatchError(code, **kwargs)
    return raiser


def load_merge_tool():
    """Load the canonical parser from the sibling merge tool, never a copy."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        MERGE_TOOL_NAME)
    try:
        spec = importlib.util.spec_from_file_location(
            "mihomo_multi_vps_merge", path)
        if spec is None or spec.loader is None:
            raise OSError(path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        raise BatchError(E_TOOL_MISSING) from None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def path_key(path):
    """Case-folded, normalised paths for collision decisions.

    Windows is case-insensitive by default, so every collision gate here is
    case-insensitive on every host: a batch that is safe on Linux must not
    become an overwrite when the same delivery is copied to Windows.
    """
    return os.path.normcase(os.path.normpath(os.path.abspath(path))).casefold()


def uuid_key(value):
    """Credential identity of a canonical UUID: case-insensitive.

    The canonical parser accepts upper and lower hex, and a UUID has no case
    distinction, so two spellings of the same UUID are the same credential.
    This key is used only for comparisons; build_output still copies the source
    bytes, so the delivered UUID spelling is unchanged.
    """
    return value.lower()


def normalize_server(value):
    """Equivalent-address key for source-identity comparisons only.

    IP literals compare by parsed value; hostnames compare case-insensitively
    and without the DNS root dot. Two different keys therefore still prove two
    different *addresses*, never two independent providers or fault domains.
    """
    try:
        return "ip:" + str(ipaddress.ip_address(value))
    except ValueError:
        pass
    name = value.casefold()
    while name.endswith("."):
        name = name[:-1]
    return "dns:" + name


def read_inventory(path):
    """Strict operator-file reader: no symlink, size cap, UTF-8, no NUL/tab.

    CR is accepted only as part of CRLF line endings, because the inventory is
    hand-edited on Windows; a lone CR inside a row still fails.
    """
    if os.path.islink(path):
        raise BatchError(E_INVENTORY)
    try:
        if is_reparse(os.lstat(path)):
            raise BatchError(E_INVENTORY)
    except OSError:
        raise BatchError(E_INVENTORY) from None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise BatchError(E_INVENTORY) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INVENTORY_BYTES:
            raise BatchError(E_INVENTORY)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(MAX_INVENTORY_BYTES + 1)
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > MAX_INVENTORY_BYTES or b"\x00" in raw or b"\t" in raw:
        raise BatchError(E_INVENTORY)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BatchError(E_INVENTORY) from None
    if text.startswith("\ufeff"):
        raise BatchError(E_INVENTORY)
    lines = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if "\r" in line:
            raise BatchError(E_INVENTORY)
        lines.append(line)
    return raw, lines


def parse_inventory(lines):
    """Return the ordered terminal list, or fail closed.

    Accepted document: blank lines, `#` comment lines, at most one exact
    `terminal,group` header as the first content line, and rows that are
    exactly `<client-name>,<first|second>`-style group tokens with no padding.
    """
    terminals = []
    seen = {}
    header_done = False
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("#"):
            continue
        if not header_done and line == INVENTORY_HEADER:
            header_done = True
            continue
        header_done = True
        match = ROW_RE.match(line)
        if match is None:
            raise BatchError(E_INVENTORY)
        name, group = match.group(1), match.group(2)
        key = name.casefold()
        if key in seen:
            raise BatchError(E_INVENTORY_DUPLICATE, terminal=name)
        seen[key] = name
        terminals.append(Terminal(name, group))
        if len(terminals) > MAX_TERMINALS:
            raise BatchError(E_INVENTORY)
    if not terminals:
        raise BatchError(E_INVENTORY)
    return terminals


def is_reparse(info):
    """True for a Windows symlink, junction or any other reparse point.

    `os.path.islink` is not sufficient: a directory junction is still
    `S_ISDIR` and reports no link, but it redirects the path (and therefore the
    credential check) elsewhere.
    """
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def check_directory(path, role):
    """An existing real directory that is not a link or reparse point."""
    try:
        info = os.lstat(path)
    except OSError:
        raise BatchError(E_PATH_CONFLICT, role=role) from None
    if (not stat.S_ISDIR(info.st_mode) or os.path.islink(path)
            or is_reparse(info)):
        raise BatchError(E_PATH_CONFLICT, role=role)


def check_inventory_file(path):
    try:
        info = os.lstat(path)
    except OSError:
        raise BatchError(E_INVENTORY) from None
    if (not stat.S_ISREG(info.st_mode) or os.path.islink(path)
            or is_reparse(info)):
        raise BatchError(E_INVENTORY)


def _sddl_dacl(sddl):
    start = sddl.find("D:")
    if start < 0:
        return None
    section = sddl[start + 2:]
    end = section.find("S:")
    if end >= 0:
        section = section[:end]
    return section


def _sddl_owner(sddl):
    """Owner token from an SDDL string (`O:<owner><G|D|S>:...`).

    The section marker letter sits immediately before its colon, so the owner
    region ends at the first colon and may carry that trailing marker letter.
    """
    region = sddl[2:] if sddl.startswith("O:") else sddl
    colon = region.find(":")
    if colon < 0:
        return region.strip()
    token = region[:colon].strip()
    if token and token[-1] in "GDS":
        token = token[:-1]
    return token


def _canonical_sdd_sid(token):
    token = (token or "").strip()
    if token.startswith("S-"):
        return token
    return SDD_ALIAS.get(token, token)


def _principal_sid(token, current_user_sid):
    """Canonical SID for an ACE/owner token, resolving the local-admin alias.

    SDDL renders the built-in local Administrator account (RID 500) as `LA`,
    which is a machine-relative alias rather than a fixed SID. It is equivalent
    to the current operator only when the current token itself is that account;
    otherwise it remains an unknown principal and is refused.
    """
    sid = _canonical_sdd_sid(token)
    if sid == "LA" and LOCAL_ADMIN_SID_RE.match(current_user_sid or ""):
        return current_user_sid
    return sid


def sddl_aces(sddl):
    """All DACL ACEs as (type, flags, sid-token) tuples, or None if unparsable.

    The DACL section must be *completely* explained before any ACE is trusted:
    an optional DACL flag prefix followed by a contiguous run of well-formed
    ACEs. Trailing text, a broken ACE, an empty SID or an unexpected character
    returns None, which the caller reports as `unparsable-ace` (fail closed).
    """
    section = _sddl_dacl(sddl)
    if section is None:
        return None
    text = section.strip()
    if not text or "NO_ACCESS_CONTROL" in text:
        return []
    flags = re.match(r"[AIPR]*", text).group(0)
    rest = text[len(flags):]
    if rest and not re.fullmatch(r"(?:\([^()]*\))+", rest):
        return None
    aces = []
    for match in re.finditer(r"\(([^()]*)\)", rest):
        fields = match.group(1).split(";")
        if len(fields) != 6 or not fields[5].strip():
            return None
        ace_type, ace_flags, _rights, _object, _inherit, sid = fields
        aces.append((ace_type.strip(), ace_flags.strip(), sid.strip()))
    return aces


def sddl_allow_aces(sddl):
    """Every allow-ACE in an SDDL DACL as (sid-token, rights-token) pairs."""
    aces = sddl_aces(sddl) or []
    return [(sid, "") for ace_type, _flags, sid in aces
            if ace_type in ALLOW_ACE_TYPES]


def acl_problems(sddl, owner_token, current_user_sid):
    """Classify one SDDL descriptor against the conservative allowlist.

    [] means: a DACL is present, every allow-ACE names the current operator,
    SYSTEM, Administrators, or an inherit-only owner pseudo-principal, every
    ACE type is understood, and the owner cannot rewrite the DACL. Anything
    else is refused; unknown principals are not assumed to be benign.
    """
    problems = []
    aces = sddl_aces(sddl)
    if aces is None:
        problems.append("missing-dacl" if _sddl_dacl(sddl) is None
                        else "unparsable-ace")
        aces = []
    if "NO_ACCESS_CONTROL" in sddl:
        problems.append("null-dacl")
    for ace_type, flags, token in aces:
        if ace_type in IGNORED_ACE_TYPES or ace_type in DENY_ACE_TYPES:
            continue
        if ace_type not in ALLOW_ACE_TYPES:
            problems.append("ace-type=" + ace_type)
            continue
        sid = _principal_sid(token, current_user_sid)
        if sid == current_user_sid or sid in ALLOWED_PRINCIPAL_SIDS:
            continue
        if sid in INHERIT_ONLY_SIDS and "IO" in flags:
            continue
        problems.append("principal=" + sid)
    owner = _principal_sid(owner_token, current_user_sid)
    if not owner:
        problems.append("missing-owner")
    elif owner != current_user_sid and owner not in ALLOWED_PRINCIPAL_SIDS:
        problems.append("owner=" + owner)
    return problems


# Kept as the platform-independent entry point the contract suite exercises.
sddl_problems = acl_problems


def _windows_token_sid():
    """Current process user SID, via the process token (Windows only)."""
    if _CURRENT_USER_SID:
        return _CURRENT_USER_SID[0]
    import ctypes
    import ctypes.wintypes as wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    token_query = 0x0008
    token_user = 1

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                             ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query,
                                     ctypes.byref(token)):
        raise OSError("OpenProcessToken")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, token_user, None, 0,
                                     ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, token_user, buffer, needed,
                                            ctypes.byref(needed)):
            raise OSError("GetTokenInformation")
        sid_pointer = ctypes.c_void_p.from_address(
            ctypes.addressof(buffer)).value
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            raise OSError("ConvertSidToStringSidW")
        try:
            sid = text.value
        finally:
            kernel32.LocalFree(text)
        _CURRENT_USER_SID.append(sid)
        return sid
    finally:
        kernel32.CloseHandle(token)


def _windows_sddl(path):
    """Owner + DACL of a path as an SDDL string (Windows only)."""
    import ctypes
    import ctypes.wintypes as wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    se_file_object = 1
    owner_information = 0x00000001
    dacl_information = 0x00000004
    sddl_revision_1 = 1

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = \
        wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    owner = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        path, se_file_object, owner_information | dacl_information,
        ctypes.byref(owner), None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor))
    if result != 0:
        raise OSError("GetNamedSecurityInfoW")
    try:
        text = wintypes.LPWSTR()
        needed = wintypes.DWORD()
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, sddl_revision_1,
                owner_information | dacl_information, ctypes.byref(text),
                ctypes.byref(needed)):
            raise OSError(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW")
        try:
            return text.value or ""
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


def posix_problems(mode, uid, euid):
    """POSIX problems for one credential-bearing path; [] means private."""
    problems = []
    if mode & 0o077:
        problems.append("mode=%03o" % mode)
    if uid != euid:
        problems.append("owner=%d" % uid)
    return problems


def posix_component_problem(is_symlink, is_directory, mode, uid, euid):
    """Classify one ancestor component of a POSIX private root."""
    if is_symlink:
        return "ancestor-symlink"
    if not is_directory:
        return "ancestor-not-directory"
    if uid not in (euid, 0):
        return "ancestor-owner=%d" % uid
    if mode & 0o022 and not mode & stat.S_ISVTX:
        return "ancestor-writable"
    return None


def posix_boundary_problem(path, euid=None):
    """Problem with an ancestor of `path`, or None.

    A group/other-writable directory above the private root lets someone swap
    the directory entry; a symlinked or reparse ancestor redirects the path the
    tool just validated; an ancestor owned by another unprivileged user can be
    renamed or chmod-ed. Sticky directories (e.g. /tmp, 1777) are accepted
    because a sticky directory does not let another user replace the entry.
    Root-owned ancestors are trusted.
    """
    euid = os.geteuid() if euid is None else euid
    current = os.path.dirname(os.path.abspath(path))
    while True:
        try:
            info = os.lstat(current)
        except OSError:
            return "ancestor-unreadable"
        problem = posix_component_problem(
            stat.S_ISLNK(info.st_mode) or is_reparse(info),
            stat.S_ISDIR(info.st_mode), stat.S_IMODE(info.st_mode),
            info.st_uid, euid)
        if problem is not None:
            return problem
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def windows_local_problem(path):
    """Reject UNC, non-fixed drives and reparse ancestors for a private path."""
    if path.startswith("\\\\") or path.startswith("//"):
        return "unc"
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    if not drive:
        return "no-drive"
    import ctypes
    drive_type_fixed = 3
    try:
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
    except Exception:
        return "drive-type-unreadable"
    if drive_type != drive_type_fixed:
        return "drive-type=%d" % drive_type
    current = os.path.dirname(os.path.abspath(path))
    while True:
        try:
            info = os.lstat(current)
        except OSError:
            return "ancestor-unreadable"
        if is_reparse(info) or os.path.islink(current):
            return "ancestor-reparse"
        if not stat.S_ISDIR(info.st_mode):
            return "ancestor-not-directory"
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def check_local_boundary(path, role):
    """Keep credential-bearing paths on private local storage.

    Windows ancestors are checked for reparse points and non-directories only:
    the operator must still provide a private, operator-owned root (the
    per-path ACL gate above is the authority for the declared paths).
    """
    if os.name == "nt":
        problem = windows_local_problem(path)
    else:
        problem = posix_boundary_problem(path)
    if problem is not None:
        raise BatchError(E_INSECURE_PERMISSIONS, role=role,
                         detail="boundary-" + problem)


def verify_temp_inheritance(directory):
    """Prove the delivery directory's permissions are inherited by new files.

    The canonical writer creates its private temp file in this same directory;
    checking a probe file of the same shape before any sensitive write proves
    the inherited ACL/mode rather than assuming it.
    """
    try:
        fd, probe = tempfile.mkstemp(prefix=".ha-acl-probe-", dir=directory)
    except OSError:
        raise BatchError(E_INSECURE_PERMISSIONS, role="temp-probe",
                         detail="create-failed") from None
    try:
        os.close(fd)
        if os.name != "nt":
            os.chmod(probe, 0o600)
        check_private_path(probe, "temp-probe")
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass


def check_private_path(path, role):
    """Refuse a credential-bearing path other local principals can reach.

    POSIX hosts are judged on the real mode bits and the file owner. Windows
    hosts are judged on the owner + DACL read from the kernel (`chmod` has no
    access semantics on NTFS) against a conservative allowlist: the current
    operator, SYSTEM, Administrators, and inherit-only owner pseudo-principals.
    Unknown allow principals, unparsable/unknown allow ACEs and missing or NULL
    DACLs are refused. This is used for directories, source files, inventory
    files and the delivered files themselves.
    """
    if os.name != "nt":
        try:
            info = os.stat(path)
        except OSError:
            raise BatchError(E_INSECURE_PERMISSIONS, role=role,
                             detail="unreadable") from None
        problems = posix_problems(stat.S_IMODE(info.st_mode), info.st_uid,
                                  os.geteuid())
        if problems:
            raise BatchError(E_INSECURE_PERMISSIONS, role=role,
                             detail=problems[0])
        return
    try:
        current_user = _windows_token_sid()
        sddl = _windows_sddl(path)
    except Exception:
        raise BatchError(E_INSECURE_PERMISSIONS, role=role,
                         detail="acl-unreadable") from None
    match = _sddl_owner(sddl)
    problems = acl_problems(sddl, match, current_user)
    if problems:
        raise BatchError(E_INSECURE_PERMISSIONS, role=role,
                         detail=problems[0])


def read_sources(terminals, exports_root, merge):
    """Parse and gate both sources of every terminal before any write."""
    for terminal in terminals:
        paths = {}
        for vps in ("A", "B"):
            path = os.path.join(exports_root, vps,
                                terminal.name + EXPORT_SUFFIX)
            paths[vps] = path
            if not os.path.exists(path):
                raise BatchError(E_SOURCE_MISSING, terminal=terminal.name,
                                 vps=vps)
            try:
                if is_reparse(os.lstat(path)):
                    raise BatchError(E_SOURCE_NOT_CANONICAL,
                                     terminal=terminal.name, vps=vps)
            except OSError:
                raise BatchError(E_SOURCE_MISSING, terminal=terminal.name,
                                 vps=vps) from None
            check_private_path(path, "source-" + vps)
        for vps, attr in (("A", "a"), ("B", "b")):
            path = paths[vps]
            try:
                profile = merge.parse_export(
                    path, fail(E_SOURCE_NOT_CANONICAL, terminal=terminal.name,
                               vps=vps))
                merge.check_provenance(
                    path, terminal.name,
                    fail(E_NAME_MISMATCH, terminal=terminal.name, vps=vps))
            except merge.MergeError as exc:
                raise BatchError(exc.code, terminal=terminal.name,
                                 vps=vps) from None
            setattr(terminal, attr + "_path", path)
            setattr(terminal, attr + "_profile", profile)


def check_batch_identity(terminals, merge):
    """Batch-wide A/B source and credential independence.

    The canonical parser validates each document; this layer validates the
    batch. Identity comparisons use normalised keys -- UUIDs are case-
    insensitive, passwords stay case-sensitive, IP literals compare by value and
    hostnames case-insensitively without the DNS root dot -- because two
    spellings of one identity are one identity. Nothing here rewrites a source
    byte, and two distinct address keys still do not prove two providers.
    """
    fingerprints = {"A": {}, "B": {}}
    uuids = {}
    passwords = {}
    for terminal in terminals:
        for vps in ("A", "B"):
            profile = getattr(terminal, vps.lower() + "_profile")
            fingerprint = sha256_hex(
                normalize_server(profile.reality["server"]).encode("utf-8"))[:16]
            fingerprints[vps].setdefault(fingerprint, 0)
            fingerprints[vps][fingerprint] += 1
        try:
            merge.check_sources(terminal.a_profile, terminal.b_profile)
            merge.check_credentials(terminal.a_profile, terminal.b_profile)
        except merge.MergeError as exc:
            raise BatchError(exc.code, terminal=terminal.name) from None
        # The merge tool compares the rendered strings; these comparisons also
        # catch equivalent spellings (IPv6 forms, DNS case/trailing dot).
        for profile in (terminal.a_profile, terminal.b_profile):
            if (normalize_server(profile.reality["server"])
                    != normalize_server(profile.hysteria["server"])):
                raise BatchError(E_SOURCE_COLLISION, terminal=terminal.name)
        if (normalize_server(terminal.a_profile.reality["server"])
                == normalize_server(terminal.b_profile.reality["server"])):
            raise BatchError(E_SOURCE_COLLISION, terminal=terminal.name)
        for vps in ("A", "B"):
            profile = getattr(terminal, vps.lower() + "_profile")
            uuid = uuid_key(profile.reality["uuid"])
            password = profile.hysteria["password"]
            if uuid in uuids:
                raise BatchError(E_CREDENTIAL_REUSE, terminal=terminal.name,
                                 vps=vps, detail="uuid")
            if password in passwords:
                raise BatchError(E_CREDENTIAL_REUSE, terminal=terminal.name,
                                 vps=vps, detail="password")
            uuids[uuid] = (terminal.name, vps)
            passwords[password] = (terminal.name, vps)
    for vps in ("A", "B"):
        if len(fingerprints[vps]) != 1:
            raise BatchError(E_SOURCE_MIXED, vps=vps,
                             detail="distinct=%d" % len(fingerprints[vps]))
    if set(fingerprints["A"]) == set(fingerprints["B"]):
        raise BatchError(E_SOURCE_COLLISION)
    return {vps: next(iter(fingerprints[vps])) for vps in ("A", "B")}


PROXY_NAMES = ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")


def verify_payload(payload, terminal):
    """Structural self-check of the generated profile, before it is written."""
    try:
        lines = payload.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        raise BatchError(E_GENERATED_INVALID, terminal=terminal.name) from None
    try:
        proxies_at = lines.index("proxies:")
        groups_at = lines.index("proxy-groups:")
    except ValueError:
        raise BatchError(E_GENERATED_INVALID, terminal=terminal.name) from None
    names = tuple(line[len("  - name: "):]
                  for line in lines[proxies_at:groups_at]
                  if line.startswith("  - name: "))
    if names != PROXY_NAMES or auto_members(lines[groups_at:]) != PROXY_NAMES:
        raise BatchError(E_GENERATED_INVALID, terminal=terminal.name)
    for legacy in ('    up: "300 Mbps"', '    down: "300 Mbps"'):
        if legacy in lines:
            raise BatchError(E_GENERATED_INVALID, terminal=terminal.name)


def auto_members(group_lines):
    members = []
    inside = False
    for line in group_lines:
        if line == "  - name: 自动选择":
            inside = True
            continue
        if inside and line.startswith("    url: "):
            break
        if inside and line.startswith("      - "):
            members.append(line[len("      - "):])
    return tuple(members)


def manifest_document(config_version, inventory_sha, terminals, fingerprints,
                      deliveries, manifest_name):
    entries = []
    for terminal, _output_path, payload_hash, payload_size in deliveries:
        primary = PRIMARY_VPS[terminal.group]
        backup = BACKUP_VPS[terminal.group]
        entries.append({
            "name": terminal.name,
            "group": terminal.group,
            "primary_vps": primary,
            "backup_vps": backup,
            "output": terminal.name + OUTPUT_SUFFIX,
            "output_sha256": payload_hash,
            "output_bytes": payload_size,
            "hy2_hopping": {
                "primary": "ports" in getattr(
                    terminal, primary.lower() + "_profile").hysteria,
                "backup": "ports" in getattr(
                    terminal, backup.lower() + "_profile").hysteria,
            },
        })
    return {
        "schema": MANIFEST_SCHEMA,
        "generator": {
            "tool": "tools/" + os.path.basename(__file__),
            "version": TOOL_VERSION,
            "config_version": config_version,
        },
        "canonical_validator": "tools/" + MERGE_TOOL_NAME,
        "permission_gate": ("windows-acl-allowlist" if os.name == "nt"
                            else "posix-mode-owner"),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inventory_sha256": inventory_sha,
        "terminal_count": len(terminals),
        "groups": {group: sum(1 for t in terminals if t.group == group)
                   for group in GROUPS},
        "vps_sources": {vps: {"fingerprint_sha256_16": fingerprints[vps]}
                        for vps in ("A", "B")},
        "terminals": entries,
        "rollback": {
            "kind": "delete-files-created-by-this-batch",
            "files": [entry["output"] for entry in entries] + [manifest_name],
        },
    }


def file_identity(path):
    """(device, inode/file-id) of a regular, non-reparse file, or None."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if (stat.S_ISLNK(info.st_mode) or is_reparse(info)
            or not stat.S_ISREG(info.st_mode)):
        return None
    return (info.st_dev, info.st_ino)


def rollback(created):
    """Delete only files that are still this batch's own regular file.

    `created` holds (path, sha256, size, device, file-id). Deletion requires
    the exact same file identity *and* the same bytes; a substituted file is
    left in place even when its content happens to be identical, and a reparse
    point or non-regular object is never followed or removed.
    """
    removed = 0
    skipped = 0
    complete = True
    for path, expected_hash, expected_size, expected_dev, expected_ino \
            in reversed(created):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        if (stat.S_ISLNK(info.st_mode) or is_reparse(info)
                or not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino) != (expected_dev, expected_ino)):
            skipped += 1
            complete = False
            continue
        try:
            with open(path, "rb") as handle:
                data = handle.read(expected_size + 1)
            if len(data) != expected_size or sha256_hex(data) != expected_hash:
                skipped += 1
                complete = False
                continue
            os.unlink(path)
            removed += 1
        except FileNotFoundError:
            pass
        except OSError:
            complete = False
    return {"removed": removed, "skipped": skipped, "complete": complete}


def read_back(path, expected):
    """Read a just-written file and assert it is exactly the expected bytes."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(len(expected) + 1)
    except OSError:
        raise BatchError(E_IO) from None
    if data != expected:
        raise BatchError(E_IO)
    return data


def generate(inventory_path, exports_root, output_dir, config_version,
             merge=None):
    """Prevalidate the whole batch, then write it; roll back on any failure."""
    if merge is None:
        merge = load_merge_tool()
    if not CONFIG_VERSION_RE.match(config_version or ""):
        raise BatchError(E_USAGE, exit_status=EXIT_USAGE)
    check_inventory_file(inventory_path)
    inventory_raw, lines = read_inventory(inventory_path)
    terminals = parse_inventory(lines)

    exports_root = os.path.abspath(exports_root)
    output_dir = os.path.abspath(output_dir)
    a_dir = os.path.join(exports_root, "A")
    b_dir = os.path.join(exports_root, "B")
    # The roots are judged before their children so a shared directory is
    # reported as the permission failure it is, not as a missing subdirectory.
    for path, role in ((exports_root, "exports-root"),
                       (output_dir, "output-dir")):
        check_directory(path, role)
        check_private_path(path, role)
        check_local_boundary(path, role)
    check_private_path(inventory_path, "inventory")
    check_local_boundary(inventory_path, "inventory")
    for path, role in ((a_dir, "exports-A"), (b_dir, "exports-B")):
        check_directory(path, role)
        check_private_path(path, role)
    if path_key(a_dir) == path_key(b_dir):
        raise BatchError(E_PATH_CONFLICT, role="exports-A")
    output_key = path_key(output_dir)
    for source_dir in (a_dir, b_dir):
        source_key = path_key(source_dir)
        if output_key == source_key or output_key.startswith(
                source_key + os.sep):
            raise BatchError(E_PATH_CONFLICT, role="output-dir")
    # Prove the temp-file inheritance of the delivery directory before any
    # sensitive write, then verify the real ACL/mode of every delivered file.
    verify_temp_inheritance(output_dir)

    read_sources(terminals, exports_root, merge)
    fingerprints = check_batch_identity(terminals, merge)

    manifest_name = MANIFEST_PREFIX + config_version + MANIFEST_SUFFIX
    input_keys = {path_key(inventory_path)}
    for terminal in terminals:
        input_keys.update({path_key(terminal.a_path),
                           path_key(terminal.b_path)})
    try:
        existing = {name.casefold() for name in os.listdir(output_dir)}
    except OSError:
        raise BatchError(E_IO) from None
    output_keys = set()
    deliveries = []
    for terminal in terminals:
        output_name = terminal.name + OUTPUT_SUFFIX
        output_path = os.path.join(output_dir, output_name)
        key = path_key(output_path)
        if key in input_keys or key in output_keys:
            raise BatchError(E_PATH_CONFLICT, terminal=terminal.name)
        output_keys.add(key)
        # The case-folded directory listing catches a Windows collision even
        # when this host's filesystem is case-sensitive, so a delivery cannot
        # pass Linux validation and overwrite on the Windows target.
        if os.path.lexists(output_path) or output_name.casefold() in existing:
            raise BatchError(E_OUTPUT_EXISTS, terminal=terminal.name,
                             role="output")
        deliveries.append((terminal, output_path))
    manifest_path = os.path.join(output_dir, manifest_name)
    if path_key(manifest_path) in input_keys or path_key(manifest_path) in \
            output_keys:
        raise BatchError(E_PATH_CONFLICT, role="manifest")
    if os.path.lexists(manifest_path) or manifest_name.casefold() in existing:
        raise BatchError(E_OUTPUT_EXISTS, role="manifest")

    payloads = []
    for terminal, _output_path in deliveries:
        primary = PRIMARY_VPS[terminal.group]
        backup = BACKUP_VPS[terminal.group]
        payload = merge.build_output(
            getattr(terminal, primary.lower() + "_profile"),
            getattr(terminal, backup.lower() + "_profile"))
        verify_payload(payload, terminal)
        payloads.append(payload)

    created = []
    try:
        written = []
        for (terminal, output_path), payload in zip(deliveries, payloads):
            try:
                merge.write_output(payload, output_path)
            except merge.MergeError as exc:
                raise BatchError(exc.code, terminal=terminal.name,
                                 role="output") from None
            identity = file_identity(output_path)
            if identity is None:
                raise BatchError(E_IO, terminal=terminal.name, role="output")
            created.append((output_path, sha256_hex(payload), len(payload),
                            identity[0], identity[1]))
            data = read_back(output_path, payload)
            check_private_path(output_path, "output-file")
            written.append((terminal, output_path, sha256_hex(data), len(data)))
        document = manifest_document(config_version,
                                     sha256_hex(inventory_raw), terminals,
                                     fingerprints, written, manifest_name)
        manifest_payload = json.dumps(
            document, sort_keys=True, indent=2,
            ensure_ascii=True).encode("utf-8") + b"\n"
        try:
            merge.write_output(manifest_payload, manifest_path)
        except merge.MergeError as exc:
            raise BatchError(exc.code, role="manifest") from None
        identity = file_identity(manifest_path)
        if identity is None:
            raise BatchError(E_IO, role="manifest")
        created.append((manifest_path, sha256_hex(manifest_payload),
                        len(manifest_payload), identity[0], identity[1]))
        read_back(manifest_path, manifest_payload)
        check_private_path(manifest_path, "manifest-file")
    except BaseException as exc:
        result = rollback(created)
        if isinstance(exc, BatchError):
            exc.rollback = result
            raise
        error = BatchError(E_IO)
        error.rollback = result
        raise error from None

    return {
        "terminals": len(terminals),
        "groups": {group: sum(1 for t in terminals if t.group == group)
                   for group in GROUPS},
        "version": config_version,
        "manifest": manifest_name,
        "manifest_path": manifest_path,
        "output_paths": [path for _terminal, path in deliveries],
        "hashes": {terminal.name: (digest, size)
                   for terminal, _path, digest, size in written},
    }


def build_arg_parser(merge):
    parser = merge._SilentParser(
        prog="mihomo-competition-ha-batch", add_help=False,
        allow_abbrev=False,
        description="Offline competition-HA batch profile delivery "
                    "(operator-local; no network)")
    parser.add_argument("--inventory", required=True,
                        help="terminal inventory CSV (terminal,group)")
    parser.add_argument("--exports", required=True,
                        help="directory containing A/ and B/ canonical exports")
    parser.add_argument("--output-dir", required=True,
                        help="existing private directory for the delivery")
    parser.add_argument("--config-version", required=True,
                        help="local configuration version label")
    return parser


def report_failure(error):
    line = "ha-batch: FAIL %s" % error.code
    if error.terminal is not None:
        line += " terminal=%s" % error.terminal
    if error.vps is not None:
        line += " vps=%s" % error.vps
    if error.role is not None:
        line += " role=%s" % error.role
    if error.detail is not None:
        line += " detail=%s" % error.detail
    print(line, file=sys.stderr)
    if error.rollback is not None:
        print("ha-batch: ROLLBACK removed=%d skipped=%d complete=%s"
              % (error.rollback["removed"], error.rollback["skipped"],
                 "yes" if error.rollback["complete"] else "no"),
              file=sys.stderr)


def main(argv=None):
    try:
        merge = load_merge_tool()
    except BatchError as exc:
        report_failure(exc)
        return exc.exit_status
    try:
        args = build_arg_parser(merge).parse_args(argv)
    except merge.MergeError as exc:
        report_failure(BatchError(exc.code, exit_status=exc.exit_status))
        return exc.exit_status
    except Exception:
        report_failure(BatchError(E_IO))
        return EXIT_FAILED
    try:
        result = generate(args.inventory, args.exports, args.output_dir,
                          args.config_version, merge=merge)
    except BatchError as exc:
        report_failure(exc)
        return exc.exit_status
    except Exception:
        report_failure(BatchError(E_IO))
        return EXIT_FAILED
    print("ha-batch: OK")
    print("terminals: %d" % result["terminals"])
    print("groups: A-first=%d B-first=%d"
          % (result["groups"]["A-first"], result["groups"]["B-first"]))
    print("version: %s" % result["version"])
    print("manifest: %s" % result["manifest"])
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
