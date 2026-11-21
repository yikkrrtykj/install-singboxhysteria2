"""Packaging/CI contract tests for the HA-UI Windows EXE slice.

These are cheap, hermetic checks; the actual PyInstaller build runs in the
`windows-exe` CI job, which also performs the cold-start self-test.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent
BUILD_SCRIPT = APP_ROOT / "scripts" / "build_windows.py"
# GitHub refuses workflow-file updates from OAuth tokens without the `workflow`
# scope. The reviewed workflow therefore lives as a tracked template under
# ha-ui/ci/; activating it is a one-copy operation by a maintainer with the
# right scope (documented in docs/windows-ha-ui-build.md).
WORKFLOW_TEMPLATE = APP_ROOT / "ci" / "ha-ui-workflow.yml"
WORKFLOW_LIVE = REPO_ROOT / ".github" / "workflows" / "ha-ui.yml"


def load_build_module():
    spec = importlib.util.spec_from_file_location("ha_ui_build_windows",
                                                  BUILD_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_requirements_and_build_pins_match():
    build = load_build_module()
    requirements = {}
    for line in (APP_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, version = line.partition("==")
        assert sep, line
        requirements[name] = version
    assert build.PINNED_DEPENDENCIES == requirements
    assert build.PYINSTALLER_VERSION == "6.22.3"
    assert build.BUILD_PYTHON == (3, 13)


def test_source_set_covers_app_and_reviewed_tools():
    build = load_build_module()
    files = build._source_files()
    relative = {path.relative_to(REPO_ROOT).as_posix() for path in files}
    assert "ha-ui/scripts/entry.py" in relative
    assert "ha-ui/ha_ui/app.py" in relative
    for tool in build.TOOL_FILES:
        assert "tools/" + tool in relative
    digest = build.source_tree_digest(files)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_pyinstaller_command_bundles_tools_and_has_no_console():
    build = load_build_module()
    command = build.pyinstaller_command(Path("C:/build"), Path("entry.py"))
    assert "--onefile" in command
    assert "--windowed" in command
    assert "--noupx" in command
    add_data = command[command.index("--add-data") + 1]
    assert "tools" in add_data
    assert "--hidden-import" in command
    assert "keyring.backends.Windows" in command
    assert not any("password" in part.casefold() or "servers.json" in part
                   for part in command)


def test_ci_workflow_template_runs_pinned_windows_build_and_selftest():
    text = WORKFLOW_TEMPLATE.read_text(encoding="utf-8")
    assert "windows-2022" in text
    assert 'python-version: "3.13"' in text
    assert "QT_QPA_PLATFORM: offscreen" in text
    assert "python -m pytest tests -q" in text
    assert "python ha-ui/scripts/build_windows.py" in text
    assert "ha-ui.exe" in text
    assert "receipt.json" in text
    # No deployment / merge / Clash automation in the CI file.
    lowered = text.casefold()
    for forbidden in ("gh pr merge", "clash verge", "systemctl", "sing-box",
                      "id_rsa", "servers.json"):
        assert forbidden not in lowered
    # If the workflow was already activated, the two files must be identical.
    if WORKFLOW_LIVE.is_file():
        assert WORKFLOW_LIVE.read_bytes() == WORKFLOW_TEMPLATE.read_bytes(), (
            "activated workflow must match the reviewed tracked template")


@pytest.mark.parametrize("name", ["entry.py", "build_windows.py"])
def test_scripts_exist_and_compile(name):
    import py_compile
    path = APP_ROOT / "scripts" / name
    assert path.is_file()
    py_compile.compile(str(path), doraise=True)
