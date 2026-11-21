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
    # Hardening added by the pre-acceptance review.
    assert "concurrency:" in text
    assert "persist-credentials: false" in text
    assert "python -m pip check" in text
    assert "ha-ui/ci/check_pins.py" in text
    assert "ha-ui/ci/verify_receipt.py" in text
    assert "if-no-files-found: error" in text
    assert "GITHUB_STEP_SUMMARY" in text
    assert "source_tree_sha256" in text
    assert "receipt.pyinstaller" in text
    assert "receipt.python" in text
    # No deployment / merge / Clash automation in the CI file.
    lowered = text.casefold()
    for forbidden in ("gh pr merge", "clash verge", "systemctl", "sing-box",
                      "id_rsa", "servers.json"):
        assert forbidden not in lowered
    # If the workflow was already activated, the two files must be identical.
    if WORKFLOW_LIVE.is_file():
        assert WORKFLOW_LIVE.read_bytes() == WORKFLOW_TEMPLATE.read_bytes(), (
            "activated workflow must match the reviewed tracked template")


def test_ci_support_scripts_exist_and_are_safe_text():
    check = APP_ROOT / "ci" / "check_pins.py"
    runner = APP_ROOT / "ci" / "run-windows-ci.ps1"
    activate = APP_ROOT / "ci" / "activate-workflow.ps1"
    verifier = APP_ROOT / "ci" / "verify_receipt.py"
    for path in (check, runner, activate, verifier):
        assert path.is_file(), path
    runner_text = runner.read_text(encoding="utf-8")
    assert "pip check" in runner_text
    assert "check_pins.py" in runner_text
    assert "verify_receipt.py" in runner_text
    assert "Get-FileHash" in runner_text
    assert "selftest" in runner_text
    activate_text = activate.read_text(encoding="utf-8")
    assert "does not push, activate, or claim CI is active" in activate_text
    assert "workflow scope" in activate_text
    assert "gh auth refresh" in activate_text


def test_ci_workflow_has_no_vps_or_client_import_automation():
    import re
    lowered = WORKFLOW_TEMPLATE.read_text(encoding="utf-8").casefold()
    forbidden_patterns = (
        r"\bssh\s+-", r"\bscp\s", r"gh pr merge", r"apt-get",
        r"\bsystemctl\b", r"sing-box", r"servers\.json",
        r"management\.active",
    )
    for pattern in forbidden_patterns:
        assert not re.search(pattern, lowered), (
            "forbidden CI operation/pattern in HA-UI workflow: " + pattern)
    # The workflow may only mention import/TUN terms inside the read-only
    # static guard that forbids such code in the app.
    assert "forbidden public listener / auto-import construct" in lowered


def test_static_pin_gate_passes_without_runtime_dependencies():
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, str(APP_ROOT / "ci" / "check_pins.py"),
         "--static-only"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "pins OK" in proc.stdout


@pytest.mark.parametrize("name", ["entry.py", "build_windows.py"])
def test_scripts_exist_and_compile(name):
    import py_compile
    path = APP_ROOT / "scripts" / name
    assert path.is_file()
    py_compile.compile(str(path), doraise=True)
