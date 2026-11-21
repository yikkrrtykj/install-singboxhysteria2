#!/usr/bin/env python3
"""Verify a built HA-UI EXE artifact against its receipt (CI + operators).

Checks, fail-closed with fixed messages:

* receipt schema/format, `signed=false`, `configuration_embedded=false`,
  selftest `ok=true`, expected Python/PyInstaller versions and pinned deps;
* EXE size and SHA-256 match the receipt;
* every bundled reviewed tool's SHA-256 matches the receipt;
* the source-tree digest recomputes from the same app/tool sources;
* no credential/config file is referenced as embedded.

Usage: ``python ha-ui/ci/verify_receipt.py --dist dist``
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def load_build_module():
    path = APP_ROOT / "scripts" / "build_windows.py"
    spec = importlib.util.spec_from_file_location("ha_ui_build_windows", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(dist: Path) -> list[str]:
    problems: list[str] = []
    receipt_path = dist / "receipt.json"
    exe_path = dist / "ha-ui.exe"
    if not receipt_path.is_file():
        return ["missing receipt.json"]
    if not exe_path.is_file():
        return ["missing ha-ui.exe"]
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except ValueError:
        return ["receipt is not valid JSON"]
    if not isinstance(receipt, dict):
        return ["receipt is not an object"]
    if receipt.get("schema") != "ha-ui/windows-exe-receipt/1":
        problems.append("wrong receipt schema")
    if receipt.get("signed") is not False:
        problems.append("receipt must state signed=false")
    if receipt.get("configuration_embedded") is not False:
        problems.append("receipt must state configuration_embedded=false")
    selftest = receipt.get("selftest")
    if not isinstance(selftest, dict) or selftest.get("ok") is not True:
        problems.append("EXE cold-start self-test not ok")
    build = load_build_module()
    if receipt.get("python") != "%d.%d." % build.BUILD_PYTHON:
        # Exact patch version is recorded but only the minor is pinned.
        recorded = str(receipt.get("python", ""))
        if not recorded.startswith("%d.%d." % build.BUILD_PYTHON):
            problems.append("unexpected Python version in receipt")
    if receipt.get("pyinstaller") != build.PYINSTALLER_VERSION:
        problems.append("unexpected PyInstaller version in receipt")
    deps = receipt.get("dependencies")
    if not isinstance(deps, dict):
        problems.append("missing dependency versions")
    else:
        for name, wanted in build.PINNED_DEPENDENCIES.items():
            if deps.get(name) != wanted:
                problems.append("dependency mismatch: " + name)
    if receipt.get("exe_bytes") != exe_path.stat().st_size:
        problems.append("EXE size does not match receipt")
    if receipt.get("exe_sha256") != sha256_file(exe_path):
        problems.append("EXE SHA-256 does not match receipt")
    source_digest = receipt.get("source_tree_sha256")
    if not isinstance(source_digest, str) or not HEX64.fullmatch(source_digest):
        problems.append("missing source-tree digest")
    else:
        expected = build.source_tree_digest(build._source_files())
        if expected != source_digest:
            problems.append("source-tree digest does not match current sources")
    tools = receipt.get("tools")
    if not isinstance(tools, dict) or set(tools) != set(build.TOOL_FILES):
        problems.append("tool hash set is incomplete")
    else:
        for name, digest in tools.items():
            path = REPO_ROOT / "tools" / name
            if not HEX64.fullmatch(str(digest or "")):
                problems.append("bad tool hash: " + name)
            elif not path.is_file() or sha256_file(path) != digest:
                problems.append("tool hash mismatch: " + name)
    if not receipt.get("git_head"):
        problems.append("missing git HEAD in receipt")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", default=str(REPO_ROOT / "dist"))
    args = parser.parse_args(argv)
    problems = verify(Path(args.dist).resolve())
    if problems:
        for problem in problems:
            print("::error::" + problem, file=sys.stderr)
        return 1
    print("receipt/EXE/tools/source-tree verification OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
