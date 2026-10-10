"""Run the actual frozen EXE with relocated synthetic inputs and no Python path."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover.pilot import receiver_init
spec = importlib.util.spec_from_file_location("exe_export_fixture", ROOT / "tests/test_quality_failover.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def accept(exe):
    with tempfile.TemporaryDirectory(prefix="quality-exe-acceptance-") as temporary:
        root = Path(temporary)
        receiver_init(root / "sink", "127.0.0.1", 19443, os.environ.get("P48_TEST_OPENSSL", "openssl"))
        recipient = root / "同事电脑 完整解压包"; recipient.mkdir()
        app = recipient / "质量切换.exe"; shutil.copyfile(exe, app)
        yaml = recipient / "synthetic-mihomo.yaml"; fixture.export(yaml)
        for name in ("receiver-info.json", "receiver-ca.pem"):
            shutil.copyfile(root / "sink" / name, recipient / name)
        files = [yaml, recipient / "receiver-info.json", recipient / "receiver-ca.pem"]
        manifest = {"v": 1, "client": "synthetic", "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
        (recipient / "quality-package.json").write_text(json.dumps(manifest), encoding="utf-8")
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PATH")}
        environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        report = root / "valid.json"
        result = subprocess.run([str(app), "--self-check", str(report)], env=environment,
                                cwd=root, timeout=45, creationflags=0x08000000)
        observed = json.loads(report.read_text())
        assert result.returncode == 0, observed
        assert observed == {"v": 1, "portable_package_valid": True, "tk_available": True,
                            "frozen": True, "controller_contacted": False}
        yaml.write_bytes(b"edited configuration")
        refused = root / "refused.json"
        result = subprocess.run([str(app), "--self-check", str(refused)], env=environment,
                                cwd=root, timeout=45, creationflags=0x08000000)
        assert result.returncode == 2
        refusal = json.loads(refused.read_text())
        assert refusal == {"v": 1, "portable_package_valid": False, "controller_contacted": False,
                           "phase": "adjacent_inputs", "failure_class": "ValueError"}
        assert not (recipient / "receiver-key.pem").exists()
        print('[PASS] actual frozen EXE: moved Unicode folder, Windows-only PATH, paired files and Tk; edited config refused; no controller contact')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    accept(parser.parse_args().exe)
