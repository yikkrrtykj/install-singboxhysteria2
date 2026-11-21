"""Shared fixtures for the HA-UI core security/regression tests.

Every fixture builds its mutable state below ``<worktree>/.scratch/tests/<uuid>``
instead of the system temp directory, and ``HA_UI_HOME`` is pointed at that
directory, so the default private workspace used by
:mod:`ha_ui.core.config_store` / :mod:`ha_ui.core.private_fs` can never escape
this git worktree.

``HA_UI_TOOLS_DIR`` is pre-set to ``<worktree>/tools`` (unless the caller already
set it) because the tests exercise the reviewed, pre-existing HA tool modules.
"""

from __future__ import annotations

import os
import shutil
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

# ha-ui/tests/conftest.py -> parents[2] is the repository worktree root.
REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
SCRATCH_BASE = REPO_ROOT / ".scratch" / "tests"

os.environ.setdefault("HA_UI_TOOLS_DIR", str(TOOLS_DIR))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Repository worktree root (contains ``tools/`` and ``.scratch/``)."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def bundled_tools_dir(repo_root: Path) -> Path:
    """The reviewed ``tools/`` directory bundled by the dev loader."""
    tools = repo_root / "tools"
    assert tools.is_dir(), "missing repository tools directory: %s" % tools
    return tools


@pytest.fixture(autouse=True)
def _fresh_tool_module_cache() -> Iterator[None]:
    """The HA tool modules are cached process-wide; isolate every test.

    Without this, a test that monkeypatches ``HA_UI_TOOLS_DIR`` or checks the
    loader cache could see a module loaded by an earlier test.
    """
    from ha_ui.core import ha_tools

    ha_tools.clear_cache()
    yield
    ha_tools.clear_cache()


def _force_rmtree(path: Path) -> None:
    """Remove *path* even if a test left read-only or ACL-protected files."""
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass

    def _retry(func, target, _exc_info) -> None:
        try:
            os.chmod(target, 0o700)
        except OSError:
            pass
        try:
            func(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=_retry)
    if path.exists():
        warnings.warn("could not fully remove test workspace: %s" % path)


@pytest.fixture()
def workspace_tmp(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A unique, empty directory under ``.scratch/tests``; cleaned afterwards.

    ``HA_UI_HOME`` is redirected to it for the duration of the test so the
    default workspace root never points at the real LOCALAPPDATA.
    """
    SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
    workspace = SCRATCH_BASE / uuid.uuid4().hex
    workspace.mkdir()
    monkeypatch.setenv("HA_UI_HOME", str(workspace))
    try:
        yield workspace
    finally:
        _force_rmtree(workspace)


@pytest.fixture()
def private_workspace(workspace_tmp: Path) -> Path:
    """``workspace_tmp`` hardened with the real private ACL and verified."""
    from ha_ui.core import private_fs

    private_fs.ensure_private_dir(workspace_tmp, workspace=workspace_tmp)
    private_fs.verify_private_dir(workspace_tmp)
    return workspace_tmp
