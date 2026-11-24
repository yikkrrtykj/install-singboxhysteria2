#!/usr/bin/env python3
"""Acceptance harness: the packaged HA-UI EXE must not open CMD windows.

The windowed EXE has no console.  Its private-storage layer runs ``icacls.exe``
(a console-subsystem program) for every private directory/file; without
``CREATE_NO_WINDOW`` Windows allocates a fresh console window each time.  This
harness runs the EXE's ``--self-test`` (which now exercises the private-storage
path) in a fresh ``HA_UI_HOME`` + private ``TEMP``/``TMP`` and fails if any new
visible ``ConsoleWindowClass`` window appears (the actual CMD popup).

Detector: ``EnumWindows`` + ``GetClassNameW`` and a ``Toolhelp32`` process
snapshot (ctypes, no subprocess/WMI), so no admin rights and no third-party
modules.  New console windows / console hosts are attributed to the EXE's
process tree, so unrelated console windows from other programs are ignored.

A positive control (``cmd /c ping`` with ``CREATE_NEW_CONSOLE``) must be
detected first; if it is not, the detector is reported ``unavailable`` and the
exit code is 2 (never a false "ok").

Note on ``conhost.exe``: ``CREATE_NO_WINDOW`` still starts a *headless* console
host for ``icacls.exe`` (verified on Windows 10/11: conhost with no console
window at all).  Counting every new conhost would therefore fail the correct
fix.  This harness samples conhost for diagnostics but treats a new *visible*
``ConsoleWindowClass`` window as the popup event; the positive control proves
that such a window is detectable.

Usage (built EXE, the real acceptance gate)::

    python ha-ui/ci/check_no_console_popup.py --exe dist/ha-ui.exe

Development pre-build check (runs the app through pythonw.exe, no console)::

    python ha-ui/ci/check_no_console_popup.py --source

Exit codes: 0 = no console window/conhost observed; 1 = regression or the
self-test failed; 2 = detector unavailable / unusable environment.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path

WINDOWS = os.name == "nt"
REPO_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = REPO_ROOT / "ha-ui"
TOOLS_DIR = REPO_ROOT / "tools"
SCRATCH_ROOT = REPO_ROOT / ".scratch" / "console-popup"

CREATE_NEW_CONSOLE = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
PING_COMMAND = ["cmd", "/c", "ping", "-n", "3", "127.0.0.1"]
CONSOLE_HOSTS = {"conhost.exe", "openconsole.exe"}

_SOURCE_SNIPPET = (
    "import sys\n"
    "from ha_ui.app import main\n"
    "sys.exit(main(['--self-test']))\n"
)


class DetectorError(RuntimeError):
    """The Win32 detector cannot work in this environment."""


if WINDOWS:
    _EnumWindowsProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]


class ConsoleDetector:
    """Minimal Win32 console-window / console-host observer (no admin)."""

    def __init__(self) -> None:
        if not WINDOWS:
            raise DetectorError("windows-only")
        try:
            self._user32 = ctypes.WinDLL("user32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except OSError as exc:  # pragma: no cover - Windows core DLLs exist
            raise DetectorError("win32-dll") from exc
        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self._kernel32.CreateToolhelp32Snapshot.argtypes = [
            wintypes.DWORD, wintypes.DWORD]
        self._kernel32.Process32FirstW.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
        self._kernel32.Process32NextW.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    # ------------------------------------------------------------- windows --
    def console_windows(self) -> dict[int, int]:
        """Map each *visible* top-level ``ConsoleWindowClass`` HWND to its PID.

        Hidden/headless consoles are excluded on purpose: ``CREATE_NO_WINDOW``
        creates one for every ``icacls`` call without any popup.
        """
        found: dict[int, int] = {}

        def _callback(hwnd, _lparam):
            buffer = ctypes.create_unicode_buffer(256)
            if self._user32.GetClassNameW(hwnd, buffer, 256):
                if (buffer.value == "ConsoleWindowClass"
                        and self._user32.IsWindowVisible(hwnd)):
                    pid = wintypes.DWORD()
                    self._user32.GetWindowThreadProcessId(
                        hwnd, ctypes.byref(pid))
                    found[int(hwnd)] = int(pid.value)
            return True

        if not self._user32.EnumWindows(_EnumWindowsProc(_callback), 0):
            error = ctypes.get_last_error()
            if error:
                raise DetectorError("EnumWindows:%d" % error)
        return found

    # ------------------------------------------------------------ processes --
    def process_table(self) -> dict[int, tuple[int, str]]:
        """``pid -> (parent_pid, exe_name)`` from a Toolhelp32 snapshot."""
        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0)
        if not snapshot or int(snapshot) == ctypes.c_void_p(-1).value:
            raise DetectorError("Toolhelp32-snapshot")
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        table: dict[int, tuple[int, str]] = {}
        try:
            if not self._kernel32.Process32FirstW(
                    snapshot, ctypes.byref(entry)):
                raise DetectorError("Toolhelp32-first")
            while True:
                table[int(entry.th32ProcessID)] = (
                    int(entry.th32ParentProcessID), str(entry.szExeFile))
                if not self._kernel32.Process32NextW(
                        snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._kernel32.CloseHandle(snapshot)
        return table

    def console_host_pids(self) -> dict[int, int]:
        """``pid -> parent_pid`` for conhost.exe / OpenConsole.exe."""
        table = self.process_table()
        return {pid: parent for pid, (parent, name) in table.items()
                if name.casefold() in CONSOLE_HOSTS}

    def snapshot(self) -> dict[str, dict[int, int]]:
        return {"windows": self.console_windows(),
                "hosts": self.console_host_pids()}


def _descendants(table: dict[int, tuple[int, str]],
                 root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, (parent, _name) in table.items():
        children.setdefault(parent, []).append(pid)
    found: set[int] = set()
    stack = [root_pid]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _scan(detector: ConsoleDetector, baseline: dict[str, dict[int, int]],
          root_pid: int, known: set[int], events: set[tuple[str, int]]) -> None:
    """Record new console windows/hosts that belong to *root_pid*'s tree."""
    windows = detector.console_windows()
    hosts = detector.console_host_pids()
    fresh_windows = {hwnd: pid for hwnd, pid in windows.items()
                     if hwnd not in baseline["windows"]}
    fresh_hosts = {pid: parent for pid, parent in hosts.items()
                   if pid not in baseline["hosts"]}
    if not fresh_windows and not fresh_hosts:
        return
    table = detector.process_table()
    known |= _descendants(table, root_pid)
    for hwnd, owner in fresh_windows.items():
        if owner in known:
            events.add(("window", hwnd))
    for pid, parent in fresh_hosts.items():
        if parent in known:
            events.add(("conhost", pid))


def _watch(detector: ConsoleDetector, process: subprocess.Popen,
           baseline: dict[str, dict[int, int]],
           timeout: float) -> tuple[set[tuple[str, int]], bool]:
    """Sample while *process* runs; return events and a timeout flag."""
    events: set[tuple[str, int]] = set()
    known: set[int] = {int(process.pid)}
    started = time.perf_counter()
    timed_out = False
    while process.poll() is None:
        _scan(detector, baseline, int(process.pid), known, events)
        if time.perf_counter() - started >= timeout:
            timed_out = True
            process.kill()
            break
        time.sleep(0.002)
    process.wait()
    _scan(detector, baseline, int(process.pid), known, events)
    return events, timed_out


def _run_observed(detector: ConsoleDetector, command: list[str],
                  creationflags: int,
                  timeout: float) -> tuple[int, set[tuple[str, int]], bool]:
    baseline = detector.snapshot()
    process = subprocess.Popen(command, creationflags=creationflags,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    events, timed_out = _watch(detector, process, baseline, timeout)
    return int(process.returncode), events, timed_out


def _build_env(mode: str, run_root: Path) -> tuple[dict[str, str],
                                                   Path | None]:
    home = run_root / "home"
    temp = run_root / "temp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["HA_UI_HOME"] = str(home)
    env["TEMP"] = str(temp)
    env["TMP"] = str(temp)
    result_file: Path | None = None
    if mode == "exe":
        env.pop("HA_UI_TOOLS_DIR", None)  # bundled tools only, like the build
        result_file = run_root / "selftest-result.json"
        env["HA_UI_SELFTEST_RESULT"] = str(result_file)
        return env, result_file
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.is_file():
        raise DetectorError("pythonw-missing")
    env["HA_UI_TOOLS_DIR"] = str(TOOLS_DIR)
    env["PYTHONPATH"] = str(APP_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env, result_file


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=False))


def _fail(message: str) -> None:
    print("[check_no_console_popup] %s" % message, file=sys.stderr)


def _force_rmtree(path: Path) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass

    def _retry(func, target, _exc_info) -> None:
        try:
            os.chmod(target, 0o700)
        except OSError:
            pass
        try:
            func(target)
        except OSError:
            pass

    try:
        shutil.rmtree(path, onerror=_retry)
    except OSError:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check that the HA-UI EXE self-test opens no CMD window.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--exe", type=Path,
                      help="built windowed ha-ui.exe (acceptance gate)")
    mode.add_argument("--source", action="store_true",
                      help="pre-build check through pythonw.exe (development)")
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="seconds allowed for the self-test (default 180)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the .scratch run directory for debugging")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not WINDOWS:
        _fail("console-window detector is Windows-only")
        _emit({"checked": False, "positive_control": False,
               "console_events": 0, "detector": "unavailable", "ok": False})
        return 2

    try:
        detector = ConsoleDetector()
        detector.snapshot()  # fail early if ctypes/Win32 detection is broken
    except (OSError, DetectorError) as exc:
        _fail("detector unavailable: %r" % (exc,))
        _emit({"checked": False, "positive_control": False,
               "console_events": 0, "detector": "unavailable", "ok": False})
        return 2

    mode = "exe" if args.exe is not None else "source"
    run_root = SCRATCH_ROOT / ("run-%s" % uuid.uuid4().hex)
    try:
        try:
            env, result_file = _build_env(mode, run_root)
        except (OSError, DetectorError) as exc:
            _fail("cannot prepare the %s check: %r" % (mode, exc))
            _emit({"checked": False, "positive_control": False,
                   "console_events": 0, "detector": "unavailable",
                   "ok": False})
            return 2
        if mode == "exe":
            exe = Path(args.exe).expanduser()
            if not exe.is_file():
                _fail("EXE not found: %s" % exe)
                return 1
            command = [str(exe), "--self-test"]
            cwd = str(exe.parent)
        else:
            pythonw = Path(sys.executable).with_name("pythonw.exe")
            command = [str(pythonw), "-c", _SOURCE_SNIPPET]
            cwd = str(APP_ROOT)

        # Positive control: a console child with CREATE_NEW_CONSOLE must be
        # detected through the same window/process attribution used below.
        # The ping exit code is ignored (ICMP may be blocked; the window is
        # what matters).
        try:
            _rc, control_events, _timed_out = _run_observed(
                detector, PING_COMMAND, CREATE_NEW_CONSOLE, timeout=30.0)
        except OSError as exc:
            _fail("positive control could not run: %r" % (exc,))
            _emit({"checked": False, "positive_control": False,
                   "console_events": 0, "detector": "unavailable",
                   "ok": False})
            return 2
        if not control_events:
            _fail("positive control produced no detectable console window; "
                  "detector cannot be trusted in this environment")
            _emit({"checked": False, "positive_control": False,
                   "console_events": 0, "detector": "unavailable",
                   "ok": False})
            return 2
        control_windows = {event for event in control_events
                           if event[0] == "window"}
        if not control_windows:
            # A headless console host alone does not prove the *window*
            # detector works, so refuse to report a green result.
            _fail("positive control produced no visible ConsoleWindowClass "
                  "window; window detector cannot be trusted")
            _emit({"checked": False, "positive_control": False,
                   "console_events": 0, "detector": "unavailable",
                   "ok": False})
            return 2
        time.sleep(0.2)  # let the control's console host settle

        # The real check: run --self-test and sample before/during/after.
        baseline = detector.snapshot()
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        except OSError as exc:
            _fail("could not start self-test: %r" % (exc,))
            return 1
        events, timed_out = _watch(detector, process, baseline,
                                   args.timeout)
        exit_code = int(process.returncode)

        selftest_ok = True
        if result_file is not None and result_file.is_file():
            try:
                selftest_ok = json.loads(
                    result_file.read_text(encoding="utf-8")).get("ok") is True
            except (OSError, ValueError):
                selftest_ok = False

        window_events = {event for event in events if event[0] == "window"}
        conhost_events = {event for event in events if event[0] == "conhost"}
        ok = (not timed_out and exit_code == 0 and selftest_ok
              and not window_events)
        if timed_out:
            _fail("self-test timed out after %.0fs" % args.timeout)
        if exit_code != 0:
            _fail("self-test exited with code %d" % exit_code)
        if window_events:
            _fail("visible console window events during self-test: %r"
                  % sorted(window_events))
        if conhost_events and window_events:
            _fail("console host events sampled during self-test: %d"
                  % len(conhost_events))
        elif conhost_events:
            # Informational only: CREATE_NO_WINDOW still starts headless
            # console hosts; the popup signal is a visible console window.
            _fail("note: %d headless console host(s) sampled during self-test "
                  "(expected with CREATE_NO_WINDOW)" % len(conhost_events))
        if not selftest_ok:
            _fail("self-test result file is missing or reports failure")
        _emit({"checked": True, "positive_control": True,
               "console_events": len(window_events), "ok": ok})
        return 0 if ok else 1
    finally:
        if args.keep:
            _fail("run directory kept: %s" % run_root)
        else:
            _force_rmtree(run_root)


if __name__ == "__main__":
    raise SystemExit(main())
