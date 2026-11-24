"""Console-window isolation regression tests for the windowed HA-UI app.

Two independent checks:

* a hard, platform-guarded assertion that the real ``icacls`` invocation built
  by :mod:`ha_ui.core.private_fs` carries Windows ``CREATE_NO_WINDOW`` (and no
  ``creationflags`` on POSIX);
* a real Windows observation test that uses ``EnumWindows``/``GetClassNameW``
  to detect ``ConsoleWindowClass`` windows.  The positive control
  (``cmd /c ping`` with ``CREATE_NEW_CONSOLE``) proves the detector works in
  this desktop session; the negative control (same command with
  ``CREATE_NO_WINDOW``) proves the detector is not simply counting existing
  windows; finally the private-storage app path is run from a ``pythonw.exe``
  helper (no attached console, like the packaged ``--windowed`` EXE) and must
  not create a console window.

The observation test is best-effort *only* when the positive control cannot see
a console window in the current environment (for example a locked-down session
without a visible console); in that case it prints a diagnostic and skips the
observation assertion.  The flags assertion above is never skipped and never
weakened.  Everything is hermetic: no network, no credential manager.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import pytest

from ha_ui.core import errors, private_fs
from ha_ui.core.errors import HaUiError

WINDOWS = os.name == "nt"
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
TH32CS_SNAPPROCESS = 0x00000002

requires_windows = pytest.mark.skipif(
    not WINDOWS, reason="requires a real Windows desktop session")

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

    _USER32 = ctypes.WinDLL("user32", use_last_error=True)
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _KERNEL32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD,
                                                   wintypes.DWORD]
    _KERNEL32.Process32FirstW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    _KERNEL32.Process32NextW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]


# --------------------------------------------------------------------------- #
# Required hard assertion: the flag logic itself
# --------------------------------------------------------------------------- #
def test_icacls_call_uses_create_no_window_flag(monkeypatch) -> None:
    """The real ``_icacls`` command must suppress a console window on Windows."""
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = list(command)
        captured["kwargs"] = dict(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(private_fs.subprocess, "run", fake_run)
    assert private_fs._icacls([r"C:\some\private\dir"]) == 0

    kwargs = captured["kwargs"]
    assert captured["command"][0] == "icacls"
    # Existing invocation contract must not change.
    assert kwargs["capture_output"] is True
    assert kwargs["timeout"] == 30
    assert kwargs["check"] is False
    if WINDOWS:
        # Hard assertion, never skipped on a Windows host.
        assert "creationflags" in kwargs
        assert kwargs["creationflags"] & CREATE_NO_WINDOW
    else:
        assert "creationflags" not in kwargs


def test_console_isolation_kwargs_are_platform_specific() -> None:
    kwargs = private_fs.console_isolation_kwargs()
    if WINDOWS:
        assert private_fs.CREATE_NO_WINDOW == CREATE_NO_WINDOW
        assert kwargs == {"creationflags": CREATE_NO_WINDOW}
        assert kwargs["creationflags"] & CREATE_NO_WINDOW
    else:
        assert kwargs == {}


def test_icacls_keeps_return_code_and_error_mapping(monkeypatch) -> None:
    """CREATE_NO_WINDOW must not alter the existing return/error handling."""
    monkeypatch.setattr(
        private_fs.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 7))
    assert private_fs._icacls(["x"]) == 7

    def raises(command, **kwargs):
        raise OSError(2, "missing icacls")

    monkeypatch.setattr(private_fs.subprocess, "run", raises)
    with pytest.raises(HaUiError) as excinfo:
        private_fs._icacls(["x"])
    assert excinfo.value.code == errors.E_ACL
    assert excinfo.value.detail == "icacls-run"


# --------------------------------------------------------------------------- #
# Win32 detector helpers (only imported/called on Windows)
# --------------------------------------------------------------------------- #
def _console_windows() -> dict[int, int]:
    """Map every *visible* top-level ``ConsoleWindowClass`` HWND to its PID.

    ``CREATE_NO_WINDOW`` still creates a headless console host, so only a
    visible window counts as a popup.
    """
    found: dict[int, int] = {}

    def _callback(hwnd, _lparam):
        buffer = ctypes.create_unicode_buffer(256)
        if _USER32.GetClassNameW(hwnd, buffer, 256):
            if (buffer.value == "ConsoleWindowClass"
                    and _USER32.IsWindowVisible(hwnd)):
                pid = wintypes.DWORD()
                _USER32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                found[int(hwnd)] = int(pid.value)
        return True

    if not _USER32.EnumWindows(_EnumWindowsProc(_callback), 0):
        error = ctypes.get_last_error()
        if error:
            raise OSError(error, "EnumWindows failed")
    return found


def _process_table() -> dict[int, int]:
    """``pid -> parent pid`` via a Toolhelp32 snapshot (no subprocess/WMI)."""
    snapshot = _KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or int(snapshot) == ctypes.c_void_p(-1).value:
        raise OSError("CreateToolhelp32Snapshot failed")
    entry = _ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    table: dict[int, int] = {}
    try:
        if not _KERNEL32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return table
        while True:
            table[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not _KERNEL32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _KERNEL32.CloseHandle(snapshot)
    return table


def _descendants(table: dict[int, int], root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, parent in table.items():
        children.setdefault(parent, []).append(pid)
    found: set[int] = set()
    stack = [root_pid]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _collect_new_console_windows(baseline: dict[int, int], root_pid: int,
                                 seen: dict[int, int]) -> None:
    """Record only *new* console windows owned by *root_pid*'s process tree."""
    current = _console_windows()
    fresh = {hwnd: pid for hwnd, pid in current.items()
             if hwnd not in baseline}
    if not fresh:
        return
    try:
        allowed = _descendants(_process_table(), root_pid) | {root_pid}
    except OSError:
        allowed = {root_pid}
    for hwnd, pid in fresh.items():
        if pid in allowed:
            seen[hwnd] = pid


def _watch_console_windows(proc: subprocess.Popen,
                           baseline: dict[int, int],
                           timeout: float) -> dict[int, int]:
    seen: dict[int, int] = {}
    started = time.perf_counter()
    while proc.poll() is None and time.perf_counter() - started < timeout:
        _collect_new_console_windows(baseline, proc.pid, seen)
        time.sleep(0.002)
    if proc.poll() is None:  # timeout: never hang the test run
        proc.kill()
    proc.wait()
    _collect_new_console_windows(baseline, proc.pid, seen)
    return seen


def _run_observed(command: list[str], creationflags: int,
                  timeout: float = 30.0) -> tuple[int, dict[int, int]]:
    baseline = _console_windows()
    proc = subprocess.Popen(command, creationflags=creationflags,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    seen = _watch_console_windows(proc, baseline, timeout)
    return int(proc.returncode), seen


_APP_PATH_HELPER = """
import sys
from pathlib import Path
from ha_ui.core import private_fs

workspace = Path(sys.argv[1])
target = private_fs.ensure_private_dir(workspace / "console-check",
                                       workspace=workspace)
leaf = target / "probe.bin"
private_fs.secure_write_replace(leaf, b"console-isolation\\n",
                                workspace=workspace)
private_fs.verify_private_file(leaf)
if private_fs.read_private_file(leaf, workspace=workspace) != b"console-isolation\\n":
    raise SystemExit(3)
"""


@requires_windows
@pytest.mark.windows_only
def test_private_storage_does_not_open_console_window(
        repo_root: Path, workspace_tmp: Path) -> None:
    # 1. Positive control: a console-subsystem child with CREATE_NEW_CONSOLE
    #    really does create a detectable ConsoleWindowClass window.  The ping
    #    exit code is deliberately ignored: on hosts where ICMP is blocked it
    #    returns 1 while the console window still appears (the window is the
    #    signal under test, not connectivity).
    _positive_rc, positive_windows = _run_observed(
        ["cmd", "/c", "ping", "-n", "3", "127.0.0.1"], CREATE_NEW_CONSOLE)

    # 2. Negative control: CREATE_NO_WINDOW suppresses it.  This also proves
    #    the detector is not merely counting pre-existing console windows.
    _negative_rc, negative_windows = _run_observed(
        ["cmd", "/c", "ping", "-n", "3", "127.0.0.1"], CREATE_NO_WINDOW)

    # 3. The real app path from a GUI (console-less) process: either the
    #    packaged EXE or, here, a pythonw.exe helper running the same private_fs
    #    calls on a temp dir below .scratch/tests/.
    app_path = repo_root / "ha-ui"
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(app_path) + os.pathsep + env.get("PYTHONPATH", "")
    env["HA_UI_HOME"] = str(workspace_tmp)
    baseline = _console_windows()
    if not pythonw.is_file():
        # No console-less interpreter available: run the same calls in-process.
        # This cannot reproduce GUI console allocation, so the observation
        # assertion is skipped with a diagnostic (the packaged EXE harness in
        # ci/check_no_console_popup.py covers that case).
        print("DIAGNOSTIC: pythonw.exe not found; app-path observation skipped")
        target = private_fs.ensure_private_dir(
            workspace_tmp / "console-check", workspace=workspace_tmp)
        private_fs.secure_write_replace(target / "probe.bin",
                                        b"console-isolation\n",
                                        workspace=workspace_tmp)
        private_fs.verify_private_file(target / "probe.bin")
        return

    proc = subprocess.Popen(
        [str(pythonw), "-c", _APP_PATH_HELPER, str(workspace_tmp)],
        cwd=str(app_path), env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    observed = _watch_console_windows(proc, baseline, timeout=180.0)
    assert proc.returncode == 0, (
        "private-storage helper failed with exit code %r" % proc.returncode)

    if positive_windows:
        assert not negative_windows, (
            "negative control unexpectedly opened console window(s): %r"
            % sorted(negative_windows))
        assert observed == {}, (
            "private_fs created %d visible console window(s) during "
            "ensure_private_dir/secure_write_replace: %r"
            % (len(observed), sorted(observed)))
    else:
        # Documented fallback: if the positive control could not observe a
        # console window in this session (no desktop / different console host),
        # the observation itself proves nothing; report it and keep the rest of
        # the suite green.  The flags assertion at the top of this module is
        # still a hard assertion and is never skipped.
        print(
            "DIAGNOSTIC: console-window detector unavailable in this session "
            "(positive=%r negative=%r); skipping the app-path observation "
            "assertion only" % (positive_windows, negative_windows))
