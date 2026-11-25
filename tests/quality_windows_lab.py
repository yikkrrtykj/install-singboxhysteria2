"""External Windows acceptance fixtures. Never imported or shipped by the EXE.

Only the child process's Tk window receives posted navigation keys. No global
cursor/keyboard events, real Clash settings, external hosts or production tokens.
"""
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ntpath
import os
import select
import socket
import socketserver
import struct
import threading
import time
from typing import NamedTuple
from urllib.parse import quote

from quality_failover.policy import GROUP, NODES
from quality_failover.receiver import Handler, Server
from quality_failover.transport import recv_exact


def until(predicate, seconds=30, label="condition"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError("timed out: " + label)


class TrackedReceiver(Server):
    """Observe real authenticated replies without reading the app's state file."""
    def __init__(self):
        self.node_by_peer_port = {}
        self.completed_uploads = []
        self.receipt_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), "a" * 64, minute_bytes=16 * 1024 * 1024)
        self.RequestHandlerClass = TrackedHandler

    def uploads(self, node, after):
        with self.receipt_lock:
            return [row for row in self.completed_uploads if row["node"] == node and row["at"] >= after]

    def confirmed(self, node, after, minimum=8, count=1):
        rows = self.uploads(node, after)
        return len(rows) >= count and all(row["mbps"] >= minimum for row in rows[-count:])


class TrackedHandler(Handler):
    def reply(self, nonce, size, digest, measured_bytes=0, seconds=0):
        node = self.server.node_by_peer_port.get(self.client_address[1])
        super().reply(nonce, size, digest, measured_bytes, seconds)
        if node in NODES[:2] and size == 524288 and seconds > 0:
            with self.server.receipt_lock:
                self.server.completed_uploads.append({"node": node, "at": time.monotonic(),
                    "mbps": min(20, measured_bytes * 8 / seconds / 1e6)})


class LoopbackController(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, sink):
        self.sink = sink
        self.started = time.monotonic()
        self.observations = 0
        self.timeline, self.timeline_lock = [], threading.Lock()
        self.secret = "synthetic-exe-controller-only"
        self.marker = None
        self.fixed = ""
        self.reachable = dict.fromkeys(NODES[:2], True)
        self.routes, self.writes, self.unexpected = {}, [], []
        super().__init__(("127.0.0.1", 0), ControllerHandler)

    def event(self, kind, **facts):
        with self.timeline_lock:
            self.timeline.append(dict(at=round(time.monotonic() - self.started, 3), kind=kind, **facts))

    def snapshot(self):
        rows = {name: {"type": "Vless" if index == 0 else "Hysteria2",
                       "alive": self.reachable[name], "history": [{
                           "time": datetime.now(timezone.utc).isoformat(),
                           "delay": 25 if self.reachable[name] else 0}]}
                for index, name in enumerate(NODES[:2])}
        rows[GROUP] = {"type": "Fallback", "all": list(NODES[:2]), "fixed": self.fixed,
                       "now": self.fixed or NODES[0], "hidden": True}
        rows["GLOBAL"] = {"type": "Selector", "all": [*NODES[:2], GROUP, "DIRECT"], "now": GROUP}
        return {"proxies": rows}


class ControllerHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        server = self.server
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size)) if size else None
        permitted = "/proxies/" + quote(GROUP, safe="")
        valid = self.headers.get("Authorization") == "Bearer " + server.secret
        if valid and self.command == "GET" and self.path == "/configs":
            result = {"mode": "global", "global-ua": "ClashQualitySwitch/2 " + server.marker}
        elif valid and self.command == "GET" and self.path == "/proxies":
            result = server.snapshot()
        elif valid and self.command == "GET" and self.path == "/connections":
            server.observations += 1
            result = {"connections": list(server.routes.values())}
        elif valid and self.path == permitted and self.command == "PUT" and body in (
                {"name": NODES[0]}, {"name": NODES[1]}):
            if not server.writes and not all(server.sink.confirmed(node, server.started) for node in NODES[:2]):
                server.unexpected.append(("selection_before_both_confirmed", self.path))
                self.send_error(403)
                return
            server.fixed = body["name"]
            server.writes.append(("PUT", server.fixed))
            server.event("controller_write", method="PUT", name=server.fixed)
            result = {}
        elif valid and self.path == permitted and self.command == "DELETE" and body is None:
            server.fixed = ""
            server.writes.append(("DELETE", ""))
            server.event("controller_write", method="DELETE", name="")
            result = {}
        else:
            server.unexpected.append((self.command, self.path))
            self.send_error(403)
            return
        raw = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_PUT = do_DELETE = handle_request


class SocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port, node, controller, sink):
        self.node, self.controller, self.sink = node, controller, sink
        self.receiver_port = sink.server_port
        self.upload_connections = 0
        super().__init__(("127.0.0.1", port), SocksHandler)


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        incoming, server = self.request, self.server
        source = self.client_address[1]
        outgoing = None
        sink_peer = None
        try:
            deadline = time.monotonic() + 15
            if recv_exact(incoming, 3, deadline) != b"\x05\x01\x00":
                return
            incoming.sendall(b"\x05\x00")
            # Hard allowlist: this relay can ONLY connect to this lab's sink.
            expected = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", server.receiver_port)
            if recv_exact(incoming, 10, deadline) != expected:
                return
            outgoing = socket.create_connection(("127.0.0.1", server.receiver_port), timeout=5)
            sink_peer = outgoing.getsockname()[1]
            server.sink.node_by_peer_port[sink_peer] = server.node
            index = list(NODES[:2]).index(server.node)
            server.controller.routes[source] = {"id": str(source), "upload": 0,
                "chains": [server.node], "metadata": {
                    "sourceIP": "127.0.0.1", "sourcePort": str(source),
                    "inboundName": "quality-probe-%d" % index, "specialProxy": server.node,
                    "destinationIP": "127.0.0.1", "destinationPort": str(server.receiver_port)}}
            incoming.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            server.upload_connections += 1
            while time.monotonic() < deadline:
                readable, _, _ = select.select([incoming, outgoing], [], [], .2)
                for sock in readable:
                    raw = sock.recv(65536)
                    if not raw:
                        return
                    (outgoing if sock is incoming else incoming).sendall(raw)
        except OSError:
            pass
        finally:
            server.controller.routes.pop(source, None)
            if sink_peer is not None:
                server.sink.node_by_peer_port.pop(sink_peer, None)
            if outgoing is not None:
                outgoing.close()


def serve(server):
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server


class LabFailure(AssertionError):
    """Native acceptance failure with a stable, reportable classification."""
    classification = "LAB_FAILURE"


class ProcessEnumerationError(LabFailure):
    """The test could not ask the OS which processes/windows exist."""
    classification = "PROCESS_ENUMERATION_FAILED"


class ProcessIdentityMismatch(LabFailure):
    """A PID is not, or is no longer, the process this test started."""
    classification = "PROCESS_IDENTITY_MISMATCH"


class GuiProcessExited(LabFailure):
    """The started EXE/GUI process terminated before the test finished."""
    classification = "GUI_PROCESS_EXITED"


class GuiWindowNotFound(LabFailure):
    """The process is alive but never created a visible window."""
    classification = "GUI_WINDOW_NOT_FOUND"


class GuiStartTimeout(GuiWindowNotFound):
    """A window exists but its widget tree never reached the expected layout."""
    classification = "GUI_START_TIMEOUT"


# Acceptance must learn "which processes did I start and which windows belong to
# them" from the kernel, not from an out-of-process management query. Toolhelp32
# and the per-process image queries below are bounded kernel calls; a slow or
# failing query is classified and fails closed instead of being read as "no GUI".
TH32CS_SNAPPROCESS = 0x00000002
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_NO_MORE_FILES = 18
ERROR_BAD_LENGTH = 24
ERROR_INVALID_PARAMETER = 87
PROCESS_QUERY_LIMITED_INFORMATION = 0x001000
PROCESS_TERMINATE = 0x0001
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PROCESS_TREE_DEPTH = 4
MAX_PROCESS_TREE_SIZE = 64
MAX_ENUMERATION_ATTEMPTS = 3
ENUMERATION_RETRY_DELAY = 0.05
TRANSIENT_ENUMERATION_ERRORS = frozenset((ERROR_NOT_ENOUGH_MEMORY, ERROR_BAD_LENGTH))


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class ProcessIdentity(NamedTuple):
    pid: int
    creation_time: int
    image_path: str


def _winerror(error):
    return getattr(error, "winerror", None) or getattr(error, "errno", None)


def normalize_image_path(path):
    """Canonical comparison form for a Windows image path (never a title)."""
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


class _Win32ProcessApi:
    """Minimal kernel32 wrapper; every handle opened here is closed here."""

    def __init__(self):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.GetProcessTimes.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        self.kernel32 = kernel32

    def snapshot_table(self):
        snapshot = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == INVALID_HANDLE_VALUE:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not self.kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error == ERROR_NO_MORE_FILES:
                    return {}
                raise OSError(error, "Process32FirstW failed")
            table = {}
            while True:
                table[entry.th32ProcessID] = entry.th32ParentProcessID
                if not self.kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    error = ctypes.get_last_error()
                    if error == ERROR_NO_MORE_FILES:
                        return table
                    raise OSError(error, "Process32NextW failed")
        finally:
            self.kernel32.CloseHandle(snapshot)

    def open_process(self, pid, access):
        handle = self.kernel32.OpenProcess(access, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), "OpenProcess failed for PID %d" % pid)
        return handle

    def close_handle(self, handle):
        if handle:
            self.kernel32.CloseHandle(handle)

    def identity_from_handle(self, handle, pid):
        creation, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not self.kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exited),
                                             ctypes.byref(kernel), ctypes.byref(user)):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed for PID %d" % pid)
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "QueryFullProcessImageNameW failed for PID %d" % pid)
        ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return ProcessIdentity(pid, ticks, normalize_image_path(buffer.value))

    def process_identity(self, pid):
        handle = self.open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
        try:
            return self.identity_from_handle(handle, pid)
        finally:
            self.close_handle(handle)

    def terminate(self, pid, expected):
        """Terminate only the still-identical process; a recycled PID is refused."""
        try:
            handle = self.open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE)
        except OSError:
            return False
        try:
            if self.identity_from_handle(handle, pid) != expected:
                return False
            return bool(self.kernel32.TerminateProcess(handle, 1))
        except OSError:
            return False
        finally:
            self.close_handle(handle)


_PROCESS_API = None


def process_api():
    global _PROCESS_API
    if _PROCESS_API is None:
        if os.name != "nt":
            raise RuntimeError("native Windows process enumeration is Windows-only")
        _PROCESS_API = _Win32ProcessApi()
    return _PROCESS_API


def process_table(api=None):
    """Return {pid: parent_pid} with bounded retries; never loops forever."""
    api = api if api is not None else process_api()
    last_error = None
    for attempt in range(1, MAX_ENUMERATION_ATTEMPTS + 1):
        try:
            return api.snapshot_table()
        except OSError as error:
            last_error = error
            winerror = _winerror(error)
            if winerror not in TRANSIENT_ENUMERATION_ERRORS:
                raise ProcessEnumerationError(
                    "process enumeration failed: winerror=%s" % (winerror,)) from error
            if attempt < MAX_ENUMERATION_ATTEMPTS:
                time.sleep(ENUMERATION_RETRY_DELAY * attempt)
    raise ProcessEnumerationError(
        "process enumeration failed after %d attempts: winerror=%s"
        % (MAX_ENUMERATION_ATTEMPTS, _winerror(last_error))) from last_error


def descendants(table, root_pid, max_depth=MAX_PROCESS_TREE_DEPTH):
    """Return {pid: depth} for the real descendants of root_pid, cycle safe."""
    children = {}
    for pid, parent in table.items():
        children.setdefault(parent, []).append(pid)
    found = {}
    frontier = [root_pid]
    for depth in range(1, max_depth + 1):
        following = []
        for parent in frontier:
            for pid in sorted(children.get(parent, ())):
                if pid == root_pid or pid in found:
                    continue
                found[pid] = depth
                following.append(pid)
                if len(found) > MAX_PROCESS_TREE_SIZE:
                    raise ProcessEnumerationError(
                        "process tree exceeds the %d-process acceptance bound" % MAX_PROCESS_TREE_SIZE)
        frontier = following
        if not frontier:
            break
    return found


def validate_identity(identity, depth, parent, expected_image):
    """Accept a descendant only with verified ancestry, image and creation time."""
    if depth == 1 and identity.image_path != expected_image:
        raise ProcessIdentityMismatch(
            "direct child %d runs %r, not the started test EXE %r"
            % (identity.pid, identity.image_path, expected_image))
    if identity.creation_time < parent.creation_time:
        raise ProcessIdentityMismatch(
            "process %d was created before its verified parent %d"
            % (identity.pid, parent.pid))
    return identity


def validate_known_identity(cached, identity):
    """Reject PID reuse: a previously verified PID must keep its creation time."""
    if cached != identity:
        raise ProcessIdentityMismatch(
            "PID %d was recycled or replaced after it was verified" % identity.pid)
    return identity


def wait_for_gui(window, process, seconds=30, minimum=10):
    """Wait for a real, verified Tk window tree; classify every failure cause.

    A process-management failure is re-raised as PROCESS_ENUMERATION_FAILED and
    never counted as a GUI success or as a GUI timeout.
    """
    deadline = time.monotonic() + seconds
    observed = 0
    while True:
        if process.poll() is not None:
            raise GuiProcessExited(
                "GUI process exited with code %r before its window was usable"
                % (process.returncode,))
        observed = len(window.children())
        if observed > minimum:
            return observed
        if time.monotonic() >= deadline:
            break
        time.sleep(.1)
    if observed == 0:
        raise GuiWindowNotFound(
            "GUI process created no visible window within %s seconds" % seconds)
    raise GuiStartTimeout(
        "GUI window had %d visible widgets (need >%d) after %s seconds; layout never completed"
        % (observed, minimum, seconds))


class ChildWindow:
    """Address only visible Tk children owned by this exact test process.

    Identity comes from the kernel: the Popen process is pinned with an open
    handle (its PID cannot be recycled while that handle lives) and the
    PyInstaller onefile GUI child must be a direct child with the same image and
    a later creation time. Tk does not expose ttk button text through Win32, so
    identify the known four-button layout and post Tab/Space to this process's
    own Tk HWND; fail closed if the layout changes and never send input to the
    foreground window or match windows by title.
    """
    def __init__(self, process, api=None):
        self.process = process
        self.api = api if api is not None else process_api()
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        self.user.IsWindowVisible.argtypes = [wintypes.HWND]
        self.user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        self.user.EnumWindows.argtypes = [self.callback, wintypes.LPARAM]
        self.user.EnumChildWindows.argtypes = [wintypes.HWND, self.callback, wintypes.LPARAM]
        arguments = process.args
        executable = arguments[0] if isinstance(arguments, (list, tuple)) else arguments
        self.expected_image = normalize_image_path(os.path.abspath(os.fspath(executable)))
        self.focus = -1  # Initial toplevel, then Treeview/start/stop/folder/close.
        self.pids = {process.pid}
        self._root_handle = None
        self._root = None
        self._identities = {}
        self._gui_children = {}
        self._depths = {}
        self._visible_windows = 0
        self._child_widgets = 0
        self._cleanup_errors = []
        self._closed = False
        self._pin_root()

    def _pin_root(self):
        if self.process.poll() is not None:
            raise GuiProcessExited("GUI process exited before its identity could be verified")
        try:
            handle = self.api.open_process(self.process.pid, PROCESS_QUERY_LIMITED_INFORMATION)
        except OSError as error:
            if self.process.poll() is not None:
                raise GuiProcessExited("GUI process exited before its identity could be verified") from error
            raise ProcessEnumerationError(
                "cannot open the started EXE process: winerror=%s" % _winerror(error)) from error
        try:
            identity = self.api.identity_from_handle(handle, self.process.pid)
        except OSError as error:
            self.api.close_handle(handle)
            raise ProcessEnumerationError(
                "cannot read the started EXE identity: winerror=%s" % _winerror(error)) from error
        if identity.image_path != self.expected_image:
            self.api.close_handle(handle)
            raise ProcessIdentityMismatch(
                "started process image %r is not the test EXE %r"
                % (identity.image_path, self.expected_image))
        self._root_handle = handle
        self._root = identity
        self._identities[identity.pid] = identity

    def _verified_table(self, table):
        if self.process.pid not in table and self.process.poll() is None:
            raise ProcessEnumerationError(
                "started EXE process %d is missing from the kernel process table"
                % self.process.pid)
        depths = descendants(table, self.process.pid)
        verified = {self.process.pid: self._root}
        by_depth = {}
        for pid, depth in depths.items():
            by_depth.setdefault(depth, []).append(pid)
        for depth in sorted(by_depth):
            for pid in sorted(by_depth[depth]):
                parent = verified.get(table.get(pid))
                if parent is None:
                    continue  # ancestor chain unverified: never trust its windows
                try:
                    identity = self.api.process_identity(pid)
                except OSError as error:
                    winerror = _winerror(error)
                    if winerror == ERROR_INVALID_PARAMETER:
                        if depth == 1:
                            if self.process.poll() is not None:
                                raise GuiProcessExited(
                                    "started EXE process exited before its GUI child was verified") from error
                            raise GuiProcessExited(
                                "PyInstaller GUI child exited before its window was verified") from error
                        continue  # transient helper process already exited
                    raise ProcessEnumerationError(
                        "cannot read process %d identity: winerror=%s" % (pid, winerror)) from error
                cached = self._identities.get(pid)
                if cached is not None:
                    validate_known_identity(cached, identity)
                else:
                    validate_identity(identity, depth, parent, self.expected_image)
                    self._identities[pid] = identity
                verified[pid] = identity
        direct = {pid for pid, depth in depths.items() if depth == 1 and pid in verified}
        if self._gui_children and not (direct & set(self._gui_children)):
            raise GuiProcessExited(
                "the PyInstaller GUI child exited while the test still needed its window")
        for pid in direct:
            self._gui_children[pid] = verified[pid]
        self._depths = {pid: 0 if pid == self.process.pid else depths[pid] for pid in verified}
        return verified

    def children(self):
        table = process_table(self.api)
        verified = self._verified_table(table)
        self.pids = set(verified)
        windows = []

        def top(hwnd, _):
            pid = wintypes.DWORD()
            self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value in self.pids and self.user.IsWindowVisible(hwnd):
                windows.append(hwnd)
            return True

        self.user.EnumWindows(self.callback(top), 0)
        items = []

        def child(hwnd, _):
            pid = wintypes.DWORD()
            self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value in self.pids and self.user.IsWindowVisible(hwnd):
                rect = wintypes.RECT()
                self.user.GetWindowRect(hwnd, ctypes.byref(rect))
                items.append((hwnd, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top))
            return True

        for window in windows:
            self.user.EnumChildWindows(window, self.callback(child), 0)
        self._visible_windows = len(windows)
        self._child_widgets = len(items)
        return items

    def click(self, name):
        if self.process.poll() is not None:
            raise GuiProcessExited("GUI process exited before button click %r" % name)
        items = self.children()
        # Actual ttk buttons are the only short rectangular leaves in the
        # bottom action area; labels there are narrower in height.
        buttons = [item for item in items if 24 <= item[4] <= 42 and 65 <= item[3] <= 300]
        if buttons:
            bottom = max(item[2] for item in buttons)
            buttons = [item for item in buttons if item[2] >= bottom - 100]
        if len(buttons) != 4:
            raise AssertionError("unexpected child button layout: " + repr(buttons))
        hwnd = max(items, key=lambda item: item[3] * item[4])[0]
        target = {"start": 1, "stop": 2, "close": 4}[name]

        def key(value):
            assert self.user.PostMessageW(hwnd, 0x0100, value, 1)
            time.sleep(.08)
            assert self.user.PostMessageW(hwnd, 0x0101, value, 1)
            time.sleep(.08)

        for _ in range((target - self.focus) % 5):
            key(9)
        key(32)
        self.focus = target

    def diagnostics(self):
        return {
            "root_pid": self.process.pid,
            "root_image": self._root.image_path if self._root else None,
            "root_creation_time": self._root.creation_time if self._root else None,
            "tracked_processes": [
                {"pid": pid, "depth": self._depths.get(pid),
                 "image": identity.image_path, "creation_time": identity.creation_time}
                for pid, identity in sorted(self._identities.items())],
            "gui_children": sorted(self._gui_children),
            "visible_windows": self._visible_windows,
            "visible_child_widgets": self._child_widgets,
            "pinned_handle_open": self._root_handle is not None,
            "closed": self._closed,
            "cleanup_errors": list(self._cleanup_errors),
        }

    def close(self):
        """Release the pinned root handle; safe to call more than once."""
        handle, self._root_handle = self._root_handle, None
        if handle is not None:
            self.api.close_handle(handle)

    def cleanup(self):
        """Stop this test's verified GUI descendants and release handles.

        Only processes whose identity was verified, or a direct child proven to
        run the same image, are terminated; a recycled PID is never killed.
        """
        if self._closed:
            return
        self._closed = True
        try:
            try:
                table = process_table(self.api)
            except ProcessEnumerationError as error:
                table = {}
                self._cleanup_errors.append("enumeration during cleanup: %s" % error)
            candidates = {pid for pid in self._identities if pid != self.process.pid}
            try:
                candidates.update(descendants(table, self.process.pid))
            except ProcessEnumerationError as error:
                self._cleanup_errors.append("tree during cleanup: %s" % error)
            candidates.discard(self.process.pid)
            for pid in sorted(candidates):
                try:
                    identity = self.api.process_identity(pid)
                except OSError:
                    continue  # already gone
                cached = self._identities.get(pid)
                if cached is not None:
                    if identity != cached:
                        self._cleanup_errors.append(
                            "refused to signal recycled PID %d" % pid)
                        continue
                elif table.get(pid) == self.process.pid:
                    if identity.image_path != self.expected_image:
                        continue
                    if self._root is None or identity.creation_time < self._root.creation_time:
                        continue
                else:
                    continue
                if not self.api.terminate(pid, identity):
                    try:
                        self.api.process_identity(pid)
                    except OSError:
                        continue  # exited on its own between the checks
                    self._cleanup_errors.append("could not terminate verified PID %d" % pid)
        finally:
            self.close()
