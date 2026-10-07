"""Native stdlib-only Windows SCM host; no interactive service UI.

Installation/autostart/failure recovery belong to the subsequent signed
installer slice. This host never creates, reconfigures or removes services.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes as W


def run_service(name, runtime_factory):
    if os.name != "nt":
        raise OSError("Windows SCM required")
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    Main = ctypes.WINFUNCTYPE(None, W.DWORD, ctypes.POINTER(W.LPWSTR))
    Handler = ctypes.WINFUNCTYPE(W.DWORD, W.DWORD, W.DWORD, W.LPVOID, W.LPVOID)

    class Status(ctypes.Structure):
        _fields_ = [(field, W.DWORD) for field in (
            "kind", "state", "accepted", "exit_code", "specific",
            "checkpoint", "wait_hint")]

    class Entry(ctypes.Structure):
        _fields_ = [("name", W.LPWSTR), ("main", Main)]

    api.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]
    api.StartServiceCtrlDispatcherW.restype = W.BOOL
    api.RegisterServiceCtrlHandlerExW.argtypes = [W.LPCWSTR, Handler, W.LPVOID]
    api.RegisterServiceCtrlHandlerExW.restype = W.HANDLE
    api.SetServiceStatus.argtypes = [W.HANDLE, ctypes.POINTER(Status)]
    api.SetServiceStatus.restype = W.BOOL
    state = {"handle": None, "runtime": None, "checkpoint": 0}

    def report(value, error=0):
        pending = value in (2, 3, 5, 6)
        state["checkpoint"] = state["checkpoint"] + 1 if pending else 0
        status = Status(0x10, value, 0 if value in (1, 2, 3) else 1 | 2 | 4,
                         1066 if error else 0, error, state["checkpoint"],
                         30000 if pending else 0)
        if state["handle"]:
            api.SetServiceStatus(state["handle"], ctypes.byref(status))

    @Handler
    def handler(control, _event, _data, _context):
        runtime = state["runtime"]
        if runtime is None:
            return 0
        if control in (1, 5):
            report(3)
            runtime.stop.set()
        elif control == 2:
            report(6)
            runtime.pause.set()
        elif control == 3:
            runtime.pause.clear()
            report(4)
        elif control == 4:
            report(7 if runtime.pause.is_set() and not runtime._futures else 4)
        return 0

    @Main
    def main(_count, _args):
        handle = api.RegisterServiceCtrlHandlerExW(name, handler, None)
        if not handle:
            return
        state["handle"] = handle
        runtime = None
        error = 0
        try:
            report(2)
            runtime = runtime_factory()
            state["runtime"] = runtime
            runtime.open()
            report(4)
            while not runtime.stop.is_set():
                runtime.tick()
                if runtime.pause.is_set() and not runtime._futures:
                    report(7)
                runtime.stop.wait(0.5)
            report(3)
        except Exception:
            error = 1  # closed service-specific failure, never secret exception
        finally:
            if runtime is not None:
                try:
                    runtime.close()
                except Exception:
                    error = 1
            state["runtime"] = None
            report(1, error)

    table = (Entry * 2)(Entry(name, main), Entry(None, Main()))
    if not api.StartServiceCtrlDispatcherW(table):
        # Console execution (1063) must fail, never silently become a process
        # outside the service lifecycle / account boundary.
        raise OSError(ctypes.get_last_error(), "SCM connection unavailable")
