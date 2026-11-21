"""Private local storage for credential-bearing files on Windows.

Every credential-bearing artifact (staged canonical exports, HA deliveries,
manifests, final A-first/B-first YAML, local run records) lives below one
workspace root that is protected with a *real* NTFS DACL and then verified with
the repository's existing ACL gate (``tools/mihomo-competition-ha-batch.py``).

Rules:

* creation goes through :func:`ensure_private_dir` / write helpers here; the
  private ACL is applied with ``icacls`` on the exact path, then verified by the
  reviewed Python gate (read from the kernel, not by re-reading icacls output);
* a ``reparse point`` (symlink/junction), a non-fixed drive, a UNC path, or a
  path escaping the workspace is refused before any write;
* writes are same-directory temp file + fsync + hard-link (no-clobber) or
  ``os.replace`` (atomic update); a failed verification removes the new file so
  a missing credential copy is always safer than a half-written one;
* no file here is ever world-readable, and no plaintext password is written at
  all: passwords only go to the Windows Credential Manager.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from . import errors
from . import ha_tools
from .config_store import default_workspace_root
from .errors import HaUiError

_RUN_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MAX_LOCAL_FILE = 2 * 1024 * 1024


def is_windows() -> bool:
    return os.name == "nt"


def _is_reparse(info: os.stat_result) -> bool:
    attr = getattr(info, "st_file_attributes", 0)
    return bool(attr & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _current_user_sid() -> str:
    if not is_windows():
        raise HaUiError(errors.E_ACL, detail="windows-only")
    batch = ha_tools.batch_tool()
    try:
        return batch._windows_token_sid()  # noqa: SLF001 - reviewed helper
    except Exception:
        raise HaUiError(errors.E_ACL, detail="sid") from None


def _icacls(args: list[str]) -> int:
    try:
        proc = subprocess.run(["icacls"] + args, capture_output=True,
                              timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        raise HaUiError(errors.E_ACL, detail="icacls-run") from None
    return int(proc.returncode)


def _apply_private_acl(path: Path, *, directory: bool) -> None:
    if not is_windows():
        os.chmod(path, 0o700 if directory else 0o600)
        return
    sid = _current_user_sid()
    inheritable = ":(OI)(CI)F" if directory else ":F"
    rc = _icacls([str(path), "/inheritance:r", "/grant:r",
                  "*%s%s" % (sid, inheritable),
                  "*S-1-5-18%s" % inheritable,
                  "*S-1-5-32-544%s" % inheritable])
    if rc != 0:
        raise HaUiError(errors.E_ACL, detail="icacls-grant")
    # Some tokens make icacls add an OWNER RIGHTS allow-ACE without the
    # inherit-only flag; the reviewed gate correctly refuses that. Removing the
    # pseudo-principal does not reduce any real principal's access.
    _icacls([str(path), "/remove:g", "*S-1-3-4"])
    _verify(path, role="private-dir" if directory else "private-file",
            directory=directory)


def _verify(path: Path, *, role: str, directory: bool) -> None:
    if not is_windows():
        info = path.stat()
        wanted = 0o700 if directory else 0o600
        if stat.S_IMODE(info.st_mode) & 0o077 or stat.S_IMODE(info.st_mode) != wanted:
            raise HaUiError(errors.E_ACL, detail=role)
        return
    if directory:
        ha_tools.verify_private_dir(path, role)
    else:
        ha_tools.verify_private_file(path, role)


def _check_regular_not_reparse(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise HaUiError(errors.E_PATH, detail="missing") from None
    if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
        raise HaUiError(errors.E_PATH, detail="reparse")
    return info


def safe_child(root: Path, name: str) -> Path:
    """Join one validated filename below *root* (no separators, no dots)."""
    if not isinstance(name, str) or not name or name in (".", ".."):
        raise HaUiError(errors.E_PATH, detail="name")
    if any(sep in name for sep in ("/", "\\", "\x00")) or ":" in name:
        raise HaUiError(errors.E_PATH, detail="name")
    if Path(name).name != name:
        raise HaUiError(errors.E_PATH, detail="name")
    return root / name


def is_within(root: Path, path: Path) -> bool:
    try:
        root_real = os.path.realpath(root)
        path_real = os.path.realpath(path)
        return os.path.commonpath([root_real, path_real]) == root_real
    except (OSError, ValueError):
        return False


def _ensure_ancestors_not_reparse(workspace: Path, target: Path) -> None:
    """Refuse a target whose path below the workspace traverses a reparse point."""
    if not is_within(workspace, target):
        raise HaUiError(errors.E_PATH, detail="outside-workspace")
    current = workspace
    relative = os.path.relpath(os.path.abspath(target), os.path.abspath(workspace))
    if relative.startswith(".."):
        raise HaUiError(errors.E_PATH, detail="outside-workspace")
    for part in Path(relative).parts:
        if part in ("", "."):
            continue
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
            raise HaUiError(errors.E_PATH, detail="reparse")
        if not stat.S_ISDIR(info.st_mode) and current != target:
            raise HaUiError(errors.E_PATH, detail="not-directory")


def ensure_private_dir(path: str | os.PathLike,
                       workspace: str | os.PathLike | None = None) -> Path:
    """Create (if needed) a directory with a verified private ACL."""
    target = Path(path)
    root = Path(workspace) if workspace is not None else default_workspace_root()
    if not is_windows():
        target.mkdir(parents=True, exist_ok=True)
        _apply_private_acl(target, directory=True)
        return target
    target = target.absolute()
    root = root.absolute()
    if not is_within(root, target) and target != root:
        raise HaUiError(errors.E_PATH, detail="outside-workspace")
    # Create missing components one by one so every newly created directory gets
    # the private ACL immediately (no inherited-wide-open window).
    missing: list[Path] = []
    current = target
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            raise HaUiError(errors.E_PATH, detail="root")
        current = parent
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            pass
        except OSError:
            raise HaUiError(errors.E_STORE_IO, detail="mkdir") from None
        _apply_private_acl(directory, directory=True)
    _check_regular_not_reparse(target)
    if not target.is_dir():
        raise HaUiError(errors.E_PATH, detail="not-directory")
    # Re-apply and re-verify the target even when it already existed.
    _apply_private_acl(target, directory=True)
    if root.exists():
        _ensure_ancestors_not_reparse(root, target)
    return target


def verify_private_dir(path: str | os.PathLike) -> None:
    target = Path(path)
    _check_regular_not_reparse(target)
    if not target.is_dir():
        raise HaUiError(errors.E_PATH, detail="not-directory")
    _verify(target, role="private-dir", directory=True)


def verify_private_file(path: str | os.PathLike) -> None:
    target = Path(path)
    info = _check_regular_not_reparse(target)
    if not stat.S_ISREG(info.st_mode):
        raise HaUiError(errors.E_PATH, detail="not-file")
    _verify(target, role="private-file", directory=False)


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        os.close(fd)


def _write_temp(directory: Path, payload: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=".ha-ui-", dir=str(directory))
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temp
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp.unlink()
        except OSError:
            pass
        raise HaUiError(errors.E_STORE_IO, detail="temp-write") from None


def secure_write_new(path: str | os.PathLike, payload: bytes,
                     *, workspace: str | os.PathLike | None = None) -> str:
    """No-clobber atomic write of credential-bearing bytes; returns SHA-256."""
    target = Path(path)
    parent = target.parent
    ensure_private_dir(parent, workspace)
    if not is_within(parent if workspace is None else Path(workspace), target):
        raise HaUiError(errors.E_PATH, detail="outside-workspace")
    if target.exists() or os.path.lexists(target):
        raise HaUiError(errors.E_OUTPUT_EXISTS, detail="target")
    temp = _write_temp(parent, payload)
    try:
        _apply_private_acl(temp, directory=False)
        try:
            os.link(temp, target)
        except FileExistsError:
            raise HaUiError(errors.E_OUTPUT_EXISTS, detail="target") from None
        except OSError:
            raise HaUiError(errors.E_STORE_IO, detail="publish") from None
        _fsync_dir(parent)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
    try:
        verify_private_file(target)
        data = target.read_bytes()
        if data != payload:
            raise HaUiError(errors.E_STORE_IO, detail="readback")
    except HaUiError:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def secure_write_replace(path: str | os.PathLike, payload: bytes,
                         *, workspace: str | os.PathLike | None = None) -> None:
    """Atomic update for non-secret configuration files."""
    target = Path(path)
    parent = target.parent
    ensure_private_dir(parent, workspace)
    temp = _write_temp(parent, payload)
    try:
        _apply_private_acl(temp, directory=False)
        os.replace(temp, target)
        _fsync_dir(parent)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
    verify_private_file(target)


def read_private_file(path: str | os.PathLike,
                      max_bytes: int = _MAX_LOCAL_FILE) -> bytes:
    target = Path(path)
    info = _check_regular_not_reparse(target)
    if not stat.S_ISREG(info.st_mode):
        raise HaUiError(errors.E_PATH, detail="not-file")
    if info.st_size > max_bytes:
        raise HaUiError(errors.E_PATH, detail="too-large")
    verify_private_file(target)
    try:
        with open(target, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        raise HaUiError(errors.E_STORE_IO, detail="read") from None
    if len(data) > max_bytes:
        raise HaUiError(errors.E_PATH, detail="too-large")
    return data


def run_dir(workspace: Path, run_id: str) -> Path:
    if not _RUN_ID_RE.fullmatch(run_id or ""):
        raise HaUiError(errors.E_PATH, detail="run-id")
    base = Path(workspace) / "runs"
    ensure_private_dir(base, workspace=workspace)
    path = safe_child(base, run_id)
    ensure_private_dir(path, workspace=workspace)
    return path


def output_dir(workspace: Path) -> Path:
    path = Path(workspace) / "output"
    ensure_private_dir(path, workspace=workspace)
    return path


def delete_tree_under(root: str | os.PathLike,
                      path: str | os.PathLike) -> None:
    root_p = Path(root)
    target = Path(path)
    if not is_within(root_p, target) or target.absolute() == root_p.absolute():
        raise HaUiError(errors.E_PATH, detail="outside-workspace")
    _check_regular_not_reparse(target)
    if not target.is_dir():
        raise HaUiError(errors.E_PATH, detail="not-directory")
    try:
        shutil.rmtree(target)
    except OSError:
        raise HaUiError(errors.E_STORE_IO, detail="cleanup") from None


def file_sha256(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_folder(path: str | os.PathLike) -> None:
    target = str(path)
    if not is_windows():
        raise HaUiError(errors.E_USAGE, detail="windows-only")
    try:
        os.startfile(target)  # type: ignore[attr-defined]
    except OSError:
        raise HaUiError(errors.E_STORE_IO, detail="open-folder") from None
