#!/usr/bin/env python3
"""Build and smoke-test the unsigned Windows EXE for HA-UI.

The build is reproducible enough to audit: every input is pinned and the
receipt records the Python/PyInstaller/dependency versions, each reviewed HA
tool SHA-256, the application source-tree digest, the EXE SHA-256 and the
cold-start self-test result. No credential or `servers.json` is bundled; the
app creates its private per-user workspace at first run.

Usage (from the repository root, with the pinned venv active):

    python ha-ui/scripts/build_windows.py
    python ha-ui/scripts/build_windows.py --skip-selftest

The script refuses to run on a non-Windows host or with a different Python
minor than the pinned build interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

BUILD_PYTHON = (3, 13)
PYINSTALLER_VERSION = "6.22.3"
PINNED_DEPENDENCIES = {
    "PySide6": "6.12.0",
    "paramiko": "5.1.0",
    "keyring": "25.7.0",
}
TOOL_FILES = (
    "mihomo-competition-ha-batch.py",
    "mihomo-competition-ha-profile.py",
    "mihomo-competition-ha4-fastprobe.py",
    "mihomo-competition-ha-friendly-export.py",
    "mihomo-multi-vps-merge.py",
)
EXE_NAME = "ha-ui.exe"
SUM_FILE_NAME = "SHA256SUMS.txt"
SELFTEST_MARKER = "HA-UI self-test: OK"


class BuildError(Exception):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def app_root() -> Path:
    return repo_root() / "ha-ui"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_files() -> list[Path]:
    app = app_root()
    files = sorted((app / "ha_ui").rglob("*.py"))
    files.append(app / "scripts" / "entry.py")
    files.extend(repo_root() / "tools" / name for name in TOOL_FILES)
    return [path for path in files if path.is_file()]


def source_tree_digest(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(repo_root()).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def installed_versions() -> dict[str, str]:
    out = {}
    for name in PINNED_DEPENDENCIES:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = "missing"
    return out


def check_environment() -> None:
    if os.name != "nt":
        raise BuildError("the HA-UI EXE build is Windows-only")
    if sys.version_info[:2] != BUILD_PYTHON:
        raise BuildError("build requires Python %d.%d (found %d.%d)"
                         % (BUILD_PYTHON + sys.version_info[:2]))
    versions = installed_versions()
    problems = [name for name, wanted in PINNED_DEPENDENCIES.items()
                if versions.get(name) != wanted]
    try:
        pyinstaller = importlib.metadata.version("PyInstaller")
    except importlib.metadata.PackageNotFoundError:
        pyinstaller = "missing"
    if pyinstaller != PYINSTALLER_VERSION:
        problems.append("PyInstaller")
    if problems:
        raise BuildError("unpinned dependencies: " + ", ".join(problems))


def clean_build(build_root: Path) -> None:
    if build_root.exists():
        shutil.rmtree(build_root)
    for name in ("work", "spec", "dist"):
        (build_root / name).mkdir(parents=True)


def pyinstaller_command(build_root: Path, entry: Path) -> list[str]:
    add_data = "%s%s%s" % (repo_root() / "tools", os.pathsep, "tools")
    return [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed", "--noupx",
        "--name", "ha-ui",
        "--distpath", str(build_root / "dist"),
        "--workpath", str(build_root / "work"),
        "--specpath", str(build_root / "spec"),
        "--paths", str(app_root()),
        "--add-data", add_data,
        "--hidden-import", "keyring.backends.Windows",
        "--hidden-import", "keyring.backends.fail",
        "--exclude-module", "pytest",
        "--exclude-module", "PySide6.QtWebEngineCore",
        "--exclude-module", "PySide6.QtWebEngineWidgets",
        "--exclude-module", "PySide6.QtWebEngineQuick",
        "--exclude-module", "PySide6.QtQuick",
        "--exclude-module", "PySide6.QtQml",
        str(entry),
    ]


def run_selftest(exe: Path, build_root: Path) -> dict[str, object]:
    home = build_root / "selftest-home"
    result_file = build_root / "selftest-result.json"
    # Keep the onefile extraction entirely inside the build directory: hermetic,
    # and it also works on locked-down Windows agents where the system %TEMP%
    # is not writable for the launched process.
    temp_dir = build_root / "selftest-temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["HA_UI_HOME"] = str(home)
    env["HA_UI_SELFTEST_RESULT"] = str(result_file)
    env["TEMP"] = str(temp_dir)
    env["TMP"] = str(temp_dir)
    env.pop("HA_UI_TOOLS_DIR", None)
    started = time.monotonic()
    try:
        proc = subprocess.run([str(exe), "--self-test"], env=env,
                              capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "timeout"}
    elapsed = round(time.monotonic() - started, 2)
    marker = SELFTEST_MARKER in (proc.stdout or "")
    result_ok = False
    if result_file.is_file():
        try:
            result_ok = json.loads(
                result_file.read_text(encoding="utf-8")).get("ok") is True
        except ValueError:
            result_ok = False
    ok = proc.returncode == 0 and marker and result_ok
    return {
        "ok": ok,
        "exit_code": int(proc.returncode),
        "stdout_marker": marker,
        "result_file_ok": result_ok,
        "seconds": elapsed,
        "stderr_tail": (proc.stderr or "")[-400:],
    }


def write_sha256sums(output_root: Path,
                     names: tuple[str, ...]) -> Path:
    """Write hashes of the files that are actually on disk (LF only).

    Reading the files back is deliberate: it proves the receipt's bytes are
    hashed as written on Windows (``write_text`` would translate LF to CRLF,
    making an in-memory hash disagree with the delivered file).
    """
    lines = []
    for name in names:
        target = output_root / name
        if not target.is_file():
            raise BuildError("missing build artifact: " + name)
        lines.append("%s  %s\n" % (sha256_file(target), name))
    sums = output_root / SUM_FILE_NAME
    sums.write_bytes("".join(lines).encode("utf-8"))
    return sums


def write_receipt(path: Path, receipt: dict[str, object]) -> None:
    payload = (json.dumps(receipt, ensure_ascii=False, indent=2,
                          sort_keys=True) + "\n").encode("utf-8")
    # Byte writes keep LF on every host; no newline translation.
    path.write_bytes(payload)
    write_sha256sums(path.parent, (EXE_NAME, path.name))


def build(output_root: Path, *, run_self_test: bool = True) -> dict[str, object]:
    check_environment()
    entry = app_root() / "scripts" / "entry.py"
    if not entry.is_file():
        raise BuildError("missing entry script")
    files = _source_files()
    digest = source_tree_digest(files)
    build_root = Path(tempfile.mkdtemp(prefix="ha-ui-build-",
                                       dir=str(output_root.parent)))
    try:
        clean_build(build_root)
        command = pyinstaller_command(build_root, entry)
        print("running PyInstaller (%d source files)" % len(files))
        proc = subprocess.run(command, cwd=str(repo_root()),
                              capture_output=True, text=True)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "")[-1200:]
            raise BuildError("PyInstaller failed: " + tail)
        exe = build_root / "dist" / EXE_NAME
        if not exe.is_file():
            raise BuildError("PyInstaller produced no EXE")
        output_root.mkdir(parents=True, exist_ok=True)
        target = output_root / EXE_NAME
        shutil.copy2(exe, target)
        selftest = (run_selftest(target, build_root) if run_self_test
                    else {"ok": None, "reason": "skipped"})
        if run_self_test and not selftest.get("ok"):
            raise BuildError("EXE cold-start self-test failed: %s"
                             % json.dumps(selftest, ensure_ascii=False))
        receipt = {
            "schema": "ha-ui/windows-exe-receipt/1",
            "app_version": "0.1.0",
            "built_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "build_host": "windows",
            "python": "%d.%d.%d" % sys.version_info[:3],
            "pyinstaller": PYINSTALLER_VERSION,
            "dependencies": installed_versions(),
            "onefile": True,
            "console": False,
            "signed": False,
            "configuration_embedded": False,
            "exe_name": EXE_NAME,
            "exe_bytes": target.stat().st_size,
            "exe_sha256": sha256_file(target),
            "source_tree_sha256": digest,
            "source_file_count": len(files),
            "tools": {name: sha256_file(repo_root() / "tools" / name)
                      for name in TOOL_FILES},
            "selftest": selftest,
            "git_head": _git_head(),
        }
        write_receipt(output_root / "receipt.json", receipt)
        print("EXE: %s" % target)
        print("SHA-256: %s" % receipt["exe_sha256"])
        print("receipt: %s" % (output_root / "receipt.json"))
        print("self-test: %s" % ("OK" if selftest.get("ok") else "SKIPPED"))
        return receipt
    finally:
        shutil.rmtree(build_root, ignore_errors=True)


def _git_head() -> str:
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"],
                              cwd=str(repo_root()), capture_output=True,
                              text=True, timeout=20)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(repo_root() / "dist"))
    parser.add_argument("--skip-selftest", action="store_true")
    args = parser.parse_args(argv)
    try:
        build(Path(args.output_dir).resolve(),
              run_self_test=not args.skip_selftest)
    except BuildError as error:
        print("build: FAIL %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
