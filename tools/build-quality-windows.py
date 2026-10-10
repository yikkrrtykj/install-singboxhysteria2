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


def build(output):
    if os.name != "nt":
        raise ValueError("Windows build required")
    import PyInstaller
    if PyInstaller.__version__ != PYINSTALLER_VERSION:
        raise ValueError("fixed PyInstaller version required")
    target = Path(output).resolve()
    target.mkdir(exist_ok=False)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
                    "--noupx", "--name", "质量切换", "--distpath", str(target / "software"),
                    "--workpath", str(target / "work"), "--specpath", str(target / "spec"),
                    "--paths", str(ROOT / "tools"), "--hidden-import", "__future__",
                    "--hidden-import", "quality_failover.receiver",
                    "--add-data", str(ROOT / "tools/mihomo-multi-vps-merge.py") + os.pathsep + ".",
                    "--add-data", str(ROOT / "tools/mihomo-quality-failover.py") + os.pathsep + ".",
                    str(ROOT / "tools/mihomo-quality-desktop.py")], check=True, timeout=300)
    exe = target / "software/质量切换.exe"
    receipt = {"v": 1, "pyinstaller": PYINSTALLER_VERSION, "python": sys.version.split()[0],
               "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "configuration_embedded": False,
               "signed": False, "publishable": False}
    (target / "build.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output)))
