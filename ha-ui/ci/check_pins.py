#!/usr/bin/env python3
"""CI gate: every pinned dependency must be exactly the reviewed version.

Two modes:

* ``--static-only`` (used by the Ubuntu static job, no dependencies installed):
  parse requirements/build constants and the pinned tool set only;
* default (used on Windows after ``pip install``): also verify the installed
  distributions match the pins, so a transient resolver upgrade fails loudly.

Runs on Windows and Linux; exits 1 with a fixed, non-secret message.
"""

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent


def load_build_module():
    import importlib.util
    path = APP_ROOT / "scripts" / "build_windows.py"
    spec = importlib.util.spec_from_file_location("ha_ui_build_windows", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_requirements(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
            continue
        name, sep, version = line.partition("==")
        if not sep:
            raise SystemExit("unpinned requirement in %s: %r" % (path.name, raw))
        pins[name.strip()] = version.strip()
    return pins


def static_checks() -> list[str]:
    problems: list[str] = []
    build = load_build_module()
    runtime = parse_requirements(APP_ROOT / "requirements.txt")
    dev = parse_requirements(APP_ROOT / "requirements-dev.txt")
    if build.PINNED_DEPENDENCIES != runtime:
        problems.append("requirements.txt != build_windows.PINNED_DEPENDENCIES")
    if dev.get("pyinstaller") != build.PYINSTALLER_VERSION:
        problems.append("requirements-dev pyinstaller pin != build pin")
    if build.BUILD_PYTHON != (3, 13):
        problems.append("unexpected BUILD_PYTHON")
    for name, version in dev.items():
        if name == "pyinstaller":
            continue
        if len(version) < 3:
            problems.append("suspicious dev pin: %s" % name)
    for name in build.TOOL_FILES:
        if not (REPO_ROOT / "tools" / name).is_file():
            problems.append("missing reviewed tool: " + name)
    for script in ("entry.py", "build_windows.py"):
        if not (APP_ROOT / "scripts" / script).is_file():
            problems.append("missing build script: " + script)
    workflow = APP_ROOT / "ci" / "ha-ui-workflow.yml"
    if not workflow.is_file():
        problems.append("missing CI workflow template")
    if not (APP_ROOT / "ci" / "run-windows-ci.ps1").is_file():
        problems.append("missing local CI runner")
    if not (APP_ROOT / "ci" / "verify_receipt.py").is_file():
        problems.append("missing receipt verifier")
    if not (APP_ROOT / "ci" / "verify_artifact_sums.py").is_file():
        problems.append("missing artifact sums verifier")
    if not (APP_ROOT / "ci" / "activate-workflow.ps1").is_file():
        problems.append("missing workflow activation helper")
    return problems


def installed_checks() -> list[str]:
    problems = static_checks()
    build = load_build_module()
    expected = dict(build.PINNED_DEPENDENCIES)
    for path in (APP_ROOT / "requirements-dev.txt",):
        for name, version in parse_requirements(path).items():
            if name not in expected:
                expected[name] = version
    if f"{sys.version_info.major}.{sys.version_info.minor}" != "3.13":
        problems.append("CI expects Python 3.13, found %s"
                        % sys.version.split()[0])
    for name, wanted in sorted(expected.items()):
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append("missing dependency: " + name)
            continue
        if actual != wanted:
            problems.append("%s==%s installed, expected %s"
                            % (name, actual, wanted))
    return problems


def main(argv: list[str]) -> int:
    static_only = "--static-only" in argv
    problems = static_checks() if static_only else installed_checks()
    if problems:
        for problem in problems:
            print("::error::" + problem, file=sys.stderr)
        return 1
    print("pins OK (%s)" % ("static" if static_only else "installed+static"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
