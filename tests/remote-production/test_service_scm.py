"""Mandatory Windows CI: real temporary SCM service lifecycle, never a skip.

Creates ONLY a random P6B2Fixture* demand-start service; no installed product
service is touched. Administrative Windows runner required. No secret args.
"""
import ctypes
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "monitor-v2"))
from remote_probe.profiles import ProfileVault


class ActualServiceTests(unittest.TestCase):
    def test_native_scm_start_pause_continue_stop(self):
        self.assertEqual(os.name, "nt", "Windows CI is mandatory")
        self.assertTrue(ctypes.windll.shell32.IsUserAnAdmin(), "elevated Windows fixture required")
        name = "P6B2Fixture" + uuid.uuid4().hex
        self.assertRegex(name, r"^P6B2Fixture[0-9a-f]{32}$")
        temp = tempfile.TemporaryDirectory(prefix="p6b2-scm-")
        path = os.path.join(temp.name, "vault")
        ProfileVault(path).open()
        command = subprocess.list2cmdline([sys.executable, str(ROOT / "tools" / "p6-agent.py"),
                                           "--vault", path, "service", "--name", name])
        def sc(*args):
            return subprocess.run(["sc.exe", *args], capture_output=True, text=True,
                                   creationflags=0x08000000)
        def wait_state(wanted):
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                result = sc("query", name)
                match = re.search(r"STATE\s*:\s*(\d+)", result.stdout)
                if result.returncode == 0 and match and int(match.group(1)) == wanted:
                    return
                time.sleep(.2)
            self.fail("SCM did not reach state " + str(wanted))
        created = False
        try:
            result = sc("create", name, "binPath=", command, "start=", "demand", "obj=", "LocalSystem")
            self.assertEqual(result.returncode, 0, "temporary service creation failed")
            created = True
            self.assertEqual(sc("start", name).returncode, 0)
            wait_state(4)
            self.assertEqual(sc("pause", name).returncode, 0)
            wait_state(7)
            self.assertEqual(sc("continue", name).returncode, 0)
            wait_state(4)
            self.assertEqual(sc("stop", name).returncode, 0)
            wait_state(1)
            self.assertTrue(os.path.isfile(os.path.join(path, "service.lock")))
        finally:
            if created:
                result = sc("query", name)
                if re.search(r"STATE\s*:\s*[2-7]", result.stdout):
                    sc("stop", name)
                    wait_state(1)
                self.assertEqual(sc("delete", name).returncode, 0)
            temp.cleanup()


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    raise SystemExit(subprocess.call([sys.executable, str(ROOT / 'tests/remote-production/test_windows_service_installer.py')]))
