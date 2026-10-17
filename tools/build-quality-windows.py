#!/usr/bin/env python3
"""Build an unsigned, configuration-free Windows EXE with its own Python/Tk."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYINSTALLER_VERSION = "6.22.3"
DATA_FILES = ("mihomo-multi-vps-merge.py", "mihomo-quality-failover.py")


def source_record():
    """Release receipts must name committed sources, including dynamic modules."""
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=ROOT, text=True)
    if dirty or len(commit) != 40:
        raise ValueError("commit tracked source changes before building")
    return {"v": 1, "source_commit": commit, "bundled_data_sha256": {
        name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest() for name in DATA_FILES}}


def build(output):
    if os.name != "nt":
        raise ValueError("Windows build required")
    import PyInstaller
    if PyInstaller.__version__ != PYINSTALLER_VERSION:
        raise ValueError("fixed PyInstaller version required")
    source = source_record()
    target = Path(output).resolve()
    target.mkdir(exist_ok=False)
    provenance = target / "quality-build-source.json"
    provenance.write_text(json.dumps(source, sort_keys=True), encoding="utf-8")
    data_arguments = []
    for path in [*(ROOT / "tools" / name for name in DATA_FILES), provenance]:
        data_arguments.extend(["--add-data", str(path) + os.pathsep + "."])
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
                    "--noupx", "--name", "质量切换", "--distpath", str(target / "software"),
                    "--workpath", str(target / "work"), "--specpath", str(target / "spec"),
                    "--paths", str(ROOT / "tools"), "--hidden-import", "__future__",
                    "--hidden-import", "quality_failover.receiver",
                    *data_arguments,
                    str(ROOT / "tools/mihomo-quality-desktop.py")], check=True, timeout=300)
    if source_record() != source:
        raise ValueError("sources changed during build; discard this EXE")
    exe = target / "software/质量切换.exe"
    receipt = {**source, "pyinstaller": PYINSTALLER_VERSION, "python": sys.version.split()[0],
               "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "configuration_embedded": False,
               "signed": False, "publishable": False}
    (target / "build.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output)))
