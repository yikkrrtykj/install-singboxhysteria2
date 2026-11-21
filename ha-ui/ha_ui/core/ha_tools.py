"""Loader/wrapper for the reviewed, pre-existing HA tools in ``tools/``.

The HA-UI app deliberately contains **no** re-implementation of the HA
algorithms, renderers, manifests or ACL gates. It imports the reviewed modules
from the repository (bundled into the EXE as data files) and:

* uses ``mihomo-competition-ha-batch.py`` for the canonical export parser,
  atomic no-clobber writer and the real POSIX/NTFS private-ACL checks;
* runs the HA-02, HA-03, HA-04 and friendly-export CLIs in-process through their
  public ``main(argv)`` entry points, capturing stdout/stderr. The tools keep
  their own exit codes, fail-closed codes and no-clobber behaviour.

The captured stdout/stderr is metadata-only by tool contract; the app still
only persists fixed error codes and paths, never YAML or credentials.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
from pathlib import Path
from types import ModuleType

from . import errors
from .errors import HaUiError
from .models import ToolResult

_TOOL_FILES = {
    "batch": "mihomo-competition-ha-batch.py",
    "merge": "mihomo-multi-vps-merge.py",
    "profile": "mihomo-competition-ha-profile.py",
    "fastprobe": "mihomo-competition-ha4-fastprobe.py",
    "friendly": "mihomo-competition-ha-friendly-export.py",
}

_CACHE: dict[str, ModuleType] = {}


def _bundle_tools_dir() -> Path | None:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / "tools"
        if candidate.is_dir():
            return candidate
    return None


def _dev_tools_dir() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "tools"
        if (candidate / _TOOL_FILES["batch"]).is_file():
            return candidate
    return None


def tools_dir() -> Path:
    override = os.environ.get("HA_UI_TOOLS_DIR")
    if override:
        candidate = Path(override)
        if (candidate / _TOOL_FILES["batch"]).is_file():
            return candidate
        raise HaUiError(errors.E_TOOL_MISSING, detail="HA_UI_TOOLS_DIR")
    candidate = _bundle_tools_dir() or _dev_tools_dir()
    if candidate is None:
        raise HaUiError(errors.E_TOOL_MISSING, detail="tools-dir")
    return candidate


def tool_path(name: str) -> Path:
    filename = _TOOL_FILES.get(name)
    if filename is None:
        raise HaUiError(errors.E_TOOL_MISSING, detail=name)
    path = tools_dir() / filename
    if not path.is_file():
        raise HaUiError(errors.E_TOOL_MISSING, detail=name)
    return path


def tool_sha256(name: str) -> str:
    import hashlib
    return hashlib.sha256(tool_path(name).read_bytes()).hexdigest()


def load_tool(name: str) -> ModuleType:
    cached = _CACHE.get(name)
    if cached is not None:
        return cached
    path = tool_path(name)
    module_name = "ha_ui_tool_" + name
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise OSError(str(path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except HaUiError:
        raise
    except Exception:
        # Do not render the exception: import errors can contain paths.
        _CACHE.pop(name, None)
        sys.modules.pop(module_name, None)
        raise HaUiError(errors.E_TOOL_MISSING, detail=name) from None
    _CACHE[name] = module
    return module


def batch_tool() -> ModuleType:
    return load_tool("batch")


def merge_tool() -> ModuleType:
    return load_tool("merge")


def profile_tool() -> ModuleType:
    return load_tool("profile")


def fastprobe_tool() -> ModuleType:
    return load_tool("fastprobe")


def friendly_tool() -> ModuleType:
    return load_tool("friendly")


def clear_cache() -> None:
    _CACHE.clear()
    for name in list(sys.modules):
        if name.startswith("ha_ui_tool_"):
            del sys.modules[name]


# --------------------------------------------------------------------------- #
# Real permission / boundary gates from the reviewed batch tool.
# --------------------------------------------------------------------------- #
def _map_acl_error(exc: BaseException) -> HaUiError:
    code = getattr(exc, "code", "")
    role = getattr(exc, "role", None)
    detail = getattr(exc, "detail", None)
    safe = code or "E_INSECURE_PERMISSIONS"
    if role:
        safe += "/" + str(role)
    if detail and isinstance(detail, str) and len(detail) <= 64:
        safe += ":" + detail
    return HaUiError(errors.E_ACL, detail=safe)


def verify_private_path(path: str | os.PathLike, role: str) -> None:
    batch = batch_tool()
    try:
        batch.check_private_path(str(path), role)
    except batch.BatchError as exc:  # type: ignore[attr-defined]
        raise _map_acl_error(exc) from None


def verify_private_dir(path: str | os.PathLike, role: str) -> None:
    batch = batch_tool()
    try:
        batch.check_directory(str(path), role)
        batch.check_private_path(str(path), role)
        batch.check_local_boundary(str(path), role)
    except batch.BatchError as exc:  # type: ignore[attr-defined]
        raise _map_acl_error(exc) from None


def verify_private_file(path: str | os.PathLike, role: str) -> None:
    batch = batch_tool()
    try:
        batch.check_private_path(str(path), role)
    except batch.BatchError as exc:  # type: ignore[attr-defined]
        raise _map_acl_error(exc) from None


def atomic_no_clobber_write(payload: bytes, output_path: str | os.PathLike,
                            role: str) -> None:
    """Use the canonical private-temp + hard-link writer (no clobber)."""
    merge = merge_tool()
    try:
        merge.write_output(payload, str(output_path))
    except merge.MergeError as exc:  # type: ignore[attr-defined]
        code = getattr(exc, "code", "E_IO")
        if code == "E_OUTPUT_EXISTS":
            raise HaUiError(errors.E_OUTPUT_EXISTS, detail=role) from None
        raise HaUiError(errors.E_STORE_IO, detail=code) from None
    verify_private_path(output_path, role)


# --------------------------------------------------------------------------- #
# In-process CLI execution with captured output.
# --------------------------------------------------------------------------- #
def run_tool(name: str, argv: list[str]) -> ToolResult:
    """Run a reviewed tool's public ``main(argv)`` and capture its output.

    The tools print metadata only (counts, versions, file names, hashes). This
    wrapper never logs the captured text; callers keep only fixed codes.
    """
    module = load_tool(name)
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = 1
    try:
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            result = module.main(list(argv))
        exit_code = int(result) if result is not None else 0
    except SystemExit as exc:  # argparse-free tools return ints, be safe
        code = exc.code
        exit_code = int(code) if isinstance(code, int) else 1
    except HaUiError:
        raise
    except Exception:
        raise HaUiError(errors.E_TOOL_FAILED, detail=name) from None
    return ToolResult(exit_code=exit_code, stdout=stdout.getvalue(),
                      stderr=stderr.getvalue())


def first_failure_code(result: ToolResult) -> str:
    """Extract the fixed ``E_...`` code a tool printed, or a safe default."""
    text = (result.stderr or "") + "\n" + (result.stdout or "")
    for line in text.splitlines():
        for token in line.replace(":", " ").split():
            if token.startswith("E_") and token[2:].isupper() and len(token) <= 48:
                return token
    return "E_TOOL_FAILED"


def toolset_fingerprint() -> dict[str, str]:
    """SHA-256 of each bundled tool, for the local build/run receipt."""
    out: dict[str, str] = {}
    for name in _TOOL_FILES:
        try:
            out[name] = tool_sha256(name)
        except HaUiError:
            out[name] = "missing"
    return out
