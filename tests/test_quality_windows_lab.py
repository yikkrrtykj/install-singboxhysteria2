"""Frozen-acceptance provenance, independent upload observations and native
Windows process-identity contracts for the EXE acceptance harness.
"""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
import quality_windows_lab as winlab
from quality_windows_lab import (
    GuiProcessExited, GuiStartTimeout, GuiWindowNotFound, ProcessEnumerationError,
    ProcessIdentity, ProcessIdentityMismatch, TrackedReceiver, descendants, normalize_image_path,
    process_table, stale_parent_attribution, validate_identity, validate_known_identity, wait_for_gui)

spec = importlib.util.spec_from_file_location("frozen_acceptance_contract", ROOT / "tests/quality-windows-exe-lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
HEAD = "1" * 40


class SourceGuardTests(unittest.TestCase):
    def test_old_receipt_refused_before_network_or_exe_even_with_matching_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "build.json"
            receipt.write_text(json.dumps({"source_commit": "0" * 40, "configuration_embedded": False,
                "bundled_data_sha256": {name: lab.digest(ROOT / "tools" / name) for name in (
                    "mihomo-multi-vps-merge.py", "mihomo-quality-failover.py")}}), encoding="utf-8")
            with patch.object(lab.subprocess, "check_output", return_value=HEAD + "\n"), patch.object(lab, "receiver_init") as receiver:
                with self.assertRaisesRegex(ValueError, "source_commit"):
                    lab.accept(Path(directory) / "must-not-run.exe", receipt)
                receiver.assert_not_called()

    def test_dirty_checkout_refused(self):
        with patch.object(lab.subprocess, "check_output", side_effect=[HEAD, " M tools/quality_failover/desktop.py\n"]):
            with self.assertRaisesRegex(ValueError, "clean tracked"):
                lab.verify_checkout(HEAD)

    def test_clean_matching_checkout_accepted(self):
        with patch.object(lab.subprocess, "check_output", side_effect=[HEAD, ""]):
            lab.verify_checkout(HEAD)


class UploadObservationTests(unittest.TestCase):
    def setUp(self):
        self.sink = TrackedReceiver()
        self.addCleanup(self.sink.server_close)

    def test_readiness_without_upload_does_not_confirm_quality(self):
        self.assertFalse(self.sink.confirmed("Reality", 0))

    def test_other_protocol_and_stale_receipts_do_not_confirm_recovery(self):
        self.sink.completed_uploads = [
            {"node": "Reality", "at": 1, "mbps": 20},
            {"node": "Hysteria2", "at": 3, "mbps": 20}]
        self.assertFalse(self.sink.confirmed("Reality", 2))
        self.assertTrue(self.sink.confirmed("Hysteria2", 2))

    def test_recovery_requires_consecutive_recent_good_uploads(self):
        self.sink.completed_uploads = [
            {"node": "Reality", "at": 1, "mbps": 20},
            {"node": "Reality", "at": 2, "mbps": 2},
            {"node": "Reality", "at": 3, "mbps": 20},
            {"node": "Reality", "at": 4, "mbps": 20}]
        self.assertFalse(self.sink.confirmed("Reality", 0, count=3))
        self.sink.completed_uploads.append({"node": "Reality", "at": 5, "mbps": 20})
        self.assertTrue(self.sink.confirmed("Reality", 0, count=3))


class LifecycleTests(unittest.TestCase):
    def test_restore_before_stop_is_not_mislabelled_as_protocol_failback(self):
        events = [{"kind": "alternate_selected"}, {"kind": "controller_write", "method": "DELETE", "name": ""}]
        self.assertEqual(lab.lifecycle_failure(events, None), "worker_restored_before_stop")
        events[1] = {"kind": "controller_write", "method": "PUT", "name": "Reality"}
        self.assertEqual(lab.lifecycle_failure(events, None), "protocol_failback_before_stop")

    def test_requested_restore_and_intentional_fault_are_not_unexplained_failures(self):
        for cause in ("stop_requested", "state_write_fault_injected"):
            events = [{"kind": "alternate_selected"}, {"kind": cause},
                      {"kind": "controller_write", "method": "DELETE", "name": ""}, {"kind": "close_requested"}]
            self.assertIsNone(lab.lifecycle_failure(events, 0))

    def test_cleanup_kill_is_not_used_as_original_process_exit(self):
        events = [{"kind": "test_cleanup_forced_kill"}]
        self.assertIsNone(lab.lifecycle_failure(events, None))
        self.assertEqual(lab.lifecycle_failure(events, 1), "gui_exited_before_close")

    def test_repetition_count_is_bounded_before_any_network(self):
        for invalid in (0, 4, True):
            with patch.object(lab, "receiver_init") as receiver, self.assertRaises(ValueError):
                lab.accept("not-run.exe", "not-read.json", invalid)
            receiver.assert_not_called()


class _FakeSnapshotApi:
    """Hands out scripted snapshot outcomes and counts kernel calls."""

    def __init__(self, outcomes=None, table=None):
        self.outcomes = list(outcomes or [])
        self.table = {1: 0} if table is None else table
        self.calls = 0

    def snapshot_table(self):
        self.calls += 1
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return self.table


class _AlwaysFailingSnapshotApi:
    def __init__(self, error):
        self.error = error
        self.calls = 0

    def snapshot_table(self):
        self.calls += 1
        raise self.error


class _AliveProcess:
    returncode = None

    def poll(self):
        return None


class _ExitedProcess:
    def __init__(self, returncode):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class _ScriptedWindow:
    def __init__(self, count=0, error=None):
        self.count = count
        self.error = error
        self.calls = 0

    def children(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return [None] * self.count


class ProcessTreeTests(unittest.TestCase):
    def test_descendants_include_only_verified_ancestry(self):
        table = {200: 100, 300: 200, 500: 100, 600: 999}
        self.assertEqual(descendants(table, 100), {200: 1, 500: 1, 300: 2})

    def test_descendants_are_depth_bounded_and_cycle_safe(self):
        table = {pid: pid - 1 for pid in range(2, 11)}
        self.assertEqual(descendants(table, 1, max_depth=2), {2: 1, 3: 2})
        self.assertEqual(descendants({5: 5}, 5), {})

    def test_direct_child_must_run_the_started_exe_image(self):
        image = normalize_image_path(r"c:\lab\app.exe")
        root = ProcessIdentity(10, 100, image)
        self.assertEqual(validate_identity(ProcessIdentity(11, 200, normalize_image_path(r"C:\Lab\APP.exe")),
                                           1, root, image).pid, 11)
        with self.assertRaises(ProcessIdentityMismatch):
            validate_identity(ProcessIdentity(12, 200, r"c:\windows\system32\whoami.exe"), 1, root, image)

    def test_verified_helper_descendant_may_use_another_image(self):
        image = normalize_image_path(r"c:\lab\app.exe")
        parent = ProcessIdentity(11, 200, image)
        helper = ProcessIdentity(12, 300, r"c:\windows\system32\whoami.exe")
        self.assertEqual(validate_identity(helper, 2, parent, image), helper)

    def test_process_created_before_its_parent_is_rejected(self):
        image = normalize_image_path(r"c:\lab\app.exe")
        parent = ProcessIdentity(11, 500, image)
        with self.assertRaises(ProcessIdentityMismatch):
            validate_identity(ProcessIdentity(12, 400, image), 2, parent, image)

    def test_recycled_or_expired_pid_is_rejected(self):
        cached = ProcessIdentity(11, 200, normalize_image_path(r"c:\lab\app.exe"))
        self.assertEqual(validate_known_identity(cached, cached), cached)
        with self.assertRaises(ProcessIdentityMismatch):
            validate_known_identity(cached, ProcessIdentity(11, 201, cached.image_path))

    def test_recycled_parent_pid_is_excluded_not_trusted(self):
        image = normalize_image_path(r"c:\lab\app.exe")
        parent = ProcessIdentity(11, 500, image)
        stale = ProcessIdentity(12, 400, normalize_image_path(r"c:\windows\system32\conhost.exe"))
        real_child = ProcessIdentity(13, 600, image)
        self.assertTrue(stale_parent_attribution(stale, parent))
        self.assertFalse(stale_parent_attribution(real_child, parent))

    def test_image_path_comparison_strips_nt_prefixes(self):
        self.assertEqual(normalize_image_path(r"\\?\C:\Lab\APP.EXE"), normalize_image_path(r"c:/lab/app.exe"))
        self.assertEqual(normalize_image_path(r"\\?\UNC\server\share\app.exe"),
                         normalize_image_path(r"\\server\share\app.exe"))


class EnumerationFailureTests(unittest.TestCase):
    def test_transient_kernel_error_is_retried_then_accepted(self):
        api = _FakeSnapshotApi([OSError(winlab.ERROR_BAD_LENGTH, "transient")])
        self.assertEqual(process_table(api=api), api.table)
        self.assertEqual(api.calls, 2)

    def test_persistent_kernel_error_is_bounded_and_fails_closed(self):
        api = _AlwaysFailingSnapshotApi(OSError(winlab.ERROR_NOT_ENOUGH_MEMORY, "busy"))
        with self.assertRaises(ProcessEnumerationError) as caught:
            process_table(api=api)
        self.assertEqual(caught.exception.classification, "PROCESS_ENUMERATION_FAILED")
        self.assertEqual(api.calls, winlab.MAX_ENUMERATION_ATTEMPTS)
        self.assertIn("winerror=%d" % winlab.ERROR_NOT_ENOUGH_MEMORY, str(caught.exception))

    def test_non_transient_kernel_error_is_not_retried(self):
        api = _AlwaysFailingSnapshotApi(OSError(5, "access denied"))
        with self.assertRaises(ProcessEnumerationError):
            process_table(api=api)
        self.assertEqual(api.calls, 1)


class GuiWaitClassificationTests(unittest.TestCase):
    def test_gui_process_exit_is_distinguished_from_window_problems(self):
        with self.assertRaises(GuiProcessExited) as caught:
            wait_for_gui(_ScriptedWindow(error=AssertionError("must not enumerate")), _ExitedProcess(3), seconds=1)
        self.assertEqual(caught.exception.classification, "GUI_PROCESS_EXITED")
        self.assertIn("3", str(caught.exception))

    def test_no_visible_window_is_gui_window_not_found(self):
        with self.assertRaises(GuiWindowNotFound) as caught:
            wait_for_gui(_ScriptedWindow(count=0), _AliveProcess(), seconds=.25, minimum=10)
        self.assertEqual(caught.exception.classification, "GUI_WINDOW_NOT_FOUND")

    def test_incomplete_widget_tree_is_gui_start_timeout(self):
        with self.assertRaises(GuiStartTimeout) as caught:
            wait_for_gui(_ScriptedWindow(count=3), _AliveProcess(), seconds=.25, minimum=10)
        self.assertEqual(caught.exception.classification, "GUI_START_TIMEOUT")

    def test_successful_window_tree_is_returned(self):
        self.assertEqual(wait_for_gui(_ScriptedWindow(count=11), _AliveProcess(), seconds=1), 11)

    def test_enumeration_failure_is_never_a_gui_result(self):
        error = ProcessEnumerationError("kernel snapshot failed")
        with self.assertRaises(ProcessEnumerationError) as caught:
            wait_for_gui(_ScriptedWindow(error=error), _AliveProcess(), seconds=1)
        self.assertEqual(caught.exception.classification, "PROCESS_ENUMERATION_FAILED")
        self.assertNotIsInstance(caught.exception, GuiWindowNotFound)

    def test_identity_mismatch_is_not_reported_as_a_timeout(self):
        with self.assertRaises(ProcessIdentityMismatch):
            wait_for_gui(_ScriptedWindow(error=ProcessIdentityMismatch("recycled")), _AliveProcess(), seconds=1)


class _ScriptedRootProcess:
    """Popen-like object that never owns a real process."""

    def __init__(self, kill_error=None, wait_error=None):
        self.pid = 4294967295
        self.alive = True
        self.returncode = None
        self.kill_error = kill_error
        self.wait_error = wait_error

    def poll(self):
        return None if self.alive else self.returncode

    def kill(self):
        if self.kill_error is not None:
            raise self.kill_error
        self.alive = False
        self.returncode = 1

    def wait(self, timeout=None):
        if self.wait_error is not None:
            raise self.wait_error
        self.alive = False
        return self.returncode or 0


class _ScriptedCleanupWindow:
    def __init__(self, problems=()):
        self.problems = list(problems)
        self.cleaned = False

    def cleanup(self):
        self.cleaned = True

    def cleanup_problems(self):
        return list(self.problems)


class CleanupContractTests(unittest.TestCase):
    def test_root_stop_uses_only_the_popen_handle(self):
        process, window = _ScriptedRootProcess(), _ScriptedCleanupWindow()
        self.assertEqual(lab.stop_started_process(process, window), [])
        self.assertTrue(window.cleaned)
        self.assertFalse(process.alive)

    def test_unresponsive_root_is_reported_not_tree_killed(self):
        process = _ScriptedRootProcess(kill_error=OSError(5, "access denied"))
        window = _ScriptedCleanupWindow(["could not terminate verified PID 7"])
        problems = lab.stop_started_process(process, window)
        self.assertTrue(any("started process" in problem for problem in problems), problems)
        self.assertTrue(any("still running" in problem for problem in problems), problems)
        self.assertTrue(any("PID 7" in problem for problem in problems), problems)

    def test_verified_cleanup_problems_are_reported(self):
        window = _ScriptedCleanupWindow(["could not terminate verified PID 9"])
        problems = lab.stop_started_process(_ScriptedRootProcess(), window)
        self.assertTrue(any("PID 9" in problem for problem in problems), problems)

    def test_missing_cleanup_contract_is_reported(self):
        class WindowWithoutProblems:
            def cleanup(self):
                pass

        problems = lab.stop_started_process(_ScriptedRootProcess(), WindowWithoutProblems())
        self.assertTrue(any("missing cleanup_problems" in problem for problem in problems), problems)

    def test_incomplete_cleanup_has_a_stable_classification(self):
        self.assertEqual(winlab.CleanupIncomplete.classification, "CLEANUP_INCOMPLETE")


class HarnessSourceGuardTests(unittest.TestCase):
    def test_acceptance_harness_has_no_external_process_management_query(self):
        source = (ROOT / "tests/quality_windows_lab.py").read_text(encoding="utf-8")
        for forbidden in ("Get-CimInstance", "Win32_Process", "powershell"):
            self.assertNotIn(forbidden, source)

    def test_acceptance_lab_has_no_identity_free_tree_kill(self):
        source = (ROOT / "tests/quality-windows-exe-lab.py").read_text(encoding="utf-8")
        self.assertNotIn("taskkill", source.lower())


_NATIVE_SLEEP_CODE = "import time; time.sleep(60)"


def _stop(process):
    if process is not None and process.poll() is None:
        process.kill()
    if process is not None:
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass


@unittest.skipUnless(sys.platform == "win32", "requires native Windows process and window APIs")
class NativeProcessIdentityTests(unittest.TestCase):
    def setUp(self):
        # The frozen EXE is a windowed (GUI-subsystem) binary. Use the same
        # subsystem for helper processes so the OS console host never becomes a
        # child of the process under test and direct-child checks stay strict.
        # The base interpreter is used directly: a venv launcher would insert a
        # different-image child between the started process and its script.
        base = Path(getattr(sys, "_base_executable", sys.executable))
        self.python = str(base.with_name("pythonw.exe"))
        if not Path(self.python).is_file():
            self.skipTest("pythonw.exe is required for console-free native helper processes")
        self.directory = tempfile.mkdtemp(prefix="quality-native-process-")
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.started = []

    def tearDown(self):
        for process in reversed(self.started):
            _stop(process)

    def _start(self, *arguments):
        process = subprocess.Popen([self.python, *arguments])
        self.started.append(process)
        return process

    def _wait(self, predicate, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(.05)
        return False

    def _is_gone(self, pid):
        try:
            winlab.process_api().process_identity(pid)
        except OSError:
            return True
        return False

    def _wait_gone(self, pid, seconds=10):
        return self._wait(lambda: self._is_gone(pid), seconds)

    def _start_foreign_child_tree(self):
        """Start a real process whose direct child intentionally runs another image.

        The foreign child is a GUI-subsystem script host (no console), so no OS
        console host is created that could outlive the test and be attributed to
        a recycled root PID by a later test.
        """
        pidfile = Path(self.directory) / "foreign.pid"
        script = Path(self.directory) / "sleep.vbs"
        script.write_text("WScript.Sleep 60000\n", encoding="ascii")
        wscript = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wscript.exe")
        if not Path(wscript).is_file():
            self.skipTest("wscript.exe is required for the foreign direct-child fixture")
        root = self._start("-c", (
            "import os,subprocess,sys,time; "
            "p=subprocess.Popen([sys.argv[1],sys.argv[2]]); "
            "open(sys.argv[3],'w').write(str(p.pid)); time.sleep(60)"),
            wscript, str(script), str(pidfile))
        self.assertTrue(self._wait(
            lambda: pidfile.is_file() and pidfile.read_text(encoding="utf-8").strip(), seconds=15),
            "the foreign child process was not started")
        return root, int(pidfile.read_text(encoding="utf-8"))

    def _kill_verified(self, pid):
        api = winlab.process_api()
        try:
            identity = api.process_identity(pid)
        except OSError:
            return
        api.terminate(pid, identity)
        self._wait_gone(pid)

    def test_native_tree_finds_the_real_parent_child_processes(self):
        root = self._start("-c", "import subprocess,sys,time; "
                           "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                           "time.sleep(60)")
        window = winlab.ChildWindow(root)
        try:
            self.assertTrue(self._wait(lambda: len(window.children()) >= 0 and len(window.pids) >= 2),
                            "real child process was not discovered: %r" % (window.pids,))
            table = process_table()
            self.assertIn(root.pid, table)
            self.assertGreaterEqual(len(descendants(table, root.pid)), 1)
            for identity in window._identities.values():
                self.assertEqual(identity.image_path, normalize_image_path(self.python))
        finally:
            window.cleanup()

    def test_native_parent_exit_keeps_child_identity_and_cleanup_kills_it(self):
        pidfile = Path(self.directory) / "child.pid"
        root = self._start("-c", "import subprocess,sys,time; "
                           "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                           "open(sys.argv[1],'w').write(str(p.pid)); time.sleep(1.5)", str(pidfile))
        window = winlab.ChildWindow(root)
        self.assertEqual(root.wait(timeout=20), 0)
        child_pid = int(pidfile.read_text(encoding="utf-8"))
        try:
            self.assertEqual(window.children(), [])
            self.assertIn(child_pid, window.pids)
        finally:
            window.cleanup()
        self.assertTrue(self._wait_gone(child_pid), "orphaned GUI child was not cleaned up")

    def test_native_cleanup_is_idempotent_and_releases_the_pinned_handle(self):
        root = self._start("-c", _NATIVE_SLEEP_CODE)
        window = winlab.ChildWindow(root)
        self.assertIsNotNone(window._root_handle)
        window.cleanup()
        self.assertIsNone(window._root_handle)
        window.cleanup()
        self.assertIsNone(window._root_handle)

    def test_native_unrelated_process_is_never_part_of_the_tree(self):
        unrelated = self._start("-c", _NATIVE_SLEEP_CODE)
        root = self._start("-c", _NATIVE_SLEEP_CODE)
        window = winlab.ChildWindow(root)
        try:
            window.children()
            self.assertIn(root.pid, window.pids)
            self.assertNotIn(unrelated.pid, window.pids)
        finally:
            window.cleanup()

    def test_native_wrong_image_for_started_pid_is_rejected(self):
        root = self._start("-c", _NATIVE_SLEEP_CODE)

        class ForeignProcess:
            pid = root.pid
            args = [r"C:\Windows\System32\definitely-not-the-test.exe"]
            returncode = None

            def poll(self):
                return None

        with self.assertRaises(ProcessIdentityMismatch) as caught:
            winlab.ChildWindow(ForeignProcess())
        self.assertEqual(caught.exception.classification, "PROCESS_IDENTITY_MISMATCH")

    def test_native_gui_never_appears_is_classified(self):
        root = self._start("-c", _NATIVE_SLEEP_CODE)
        window = winlab.ChildWindow(root)
        try:
            with self.assertRaises(GuiWindowNotFound) as caught:
                wait_for_gui(window, root, seconds=.4, minimum=10)
            self.assertEqual(caught.exception.classification, "GUI_WINDOW_NOT_FOUND")
        finally:
            window.cleanup()

    def test_native_gui_process_exit_is_classified(self):
        root = self._start("-c", "import time; time.sleep(.2)")
        window = None
        try:
            with self.assertRaises(GuiProcessExited) as caught:
                window = winlab.ChildWindow(root)
                wait_for_gui(window, root, seconds=10)
            self.assertEqual(caught.exception.classification, "GUI_PROCESS_EXITED")
        finally:
            if window is not None:
                window.cleanup()

    def test_native_unverified_child_is_not_killed_by_verified_cleanup(self):
        root, foreign_pid = self._start_foreign_child_tree()
        window = winlab.ChildWindow(root)
        try:
            with self.assertRaises(ProcessIdentityMismatch):
                window.children()
        finally:
            window.cleanup()
        try:
            self.assertFalse(self._is_gone(foreign_pid),
                             "verified cleanup killed a descendant whose identity was never verified")
        finally:
            self._kill_verified(foreign_pid)

    def test_native_started_process_stop_never_tree_kills_unverified_child(self):
        root, foreign_pid = self._start_foreign_child_tree()
        window = winlab.ChildWindow(root)
        problems = lab.stop_started_process(root, window)
        try:
            self.assertIsNotNone(root.poll())
            self.assertFalse(self._is_gone(foreign_pid),
                             "stop_started_process killed an unverified descendant")
            self.assertTrue(any("unverified descendant" in problem for problem in problems), problems)
            self.assertTrue(any("PID %d" % foreign_pid in problem for problem in problems), problems)
        finally:
            self._kill_verified(foreign_pid)

    def test_native_snapshot_does_not_leak_process_handles(self):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel32.GetProcessHandleCount.restype = ctypes.c_int

        def handles():
            count = ctypes.c_ulong()
            self.assertTrue(kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(count)))
            return count.value

        baseline = handles()
        for _ in range(100):
            process_table()
        self.assertLessEqual(handles() - baseline, 5)


if __name__ == "__main__":
    unittest.main()
