"""External Windows acceptance fixtures. Never imported or shipped by the EXE.

Only the child process's Tk buttons receive posted mouse messages. No global
cursor/keyboard events, real Clash settings, external hosts or production tokens.
"""
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import threading
import time
from urllib.parse import quote

from quality_failover.policy import GROUP, NODES
from quality_failover.transport import recv_exact


def until(predicate, seconds=30, label="condition"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError("timed out: " + label)


def read_state(bundle):
    try:
        return json.loads((Path(bundle).parent / "state.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


class LoopbackController(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.secret = "synthetic-exe-controller-only"
        self.marker = None
        self.fixed = ""
        self.reachable = dict.fromkeys(NODES[:2], True)
        self.routes, self.writes, self.unexpected = {}, [], []
        super().__init__(("127.0.0.1", 0), ControllerHandler)

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
            result = {"connections": list(server.routes.values())}
        elif valid and self.path == permitted and self.command == "PUT" and body in (
                {"name": NODES[0]}, {"name": NODES[1]}):
            server.fixed = body["name"]
            server.writes.append(("PUT", server.fixed))
            result = {}
        elif valid and self.path == permitted and self.command == "DELETE" and body is None:
            server.fixed = ""
            server.writes.append(("DELETE", ""))
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

    def __init__(self, port, node, controller, receiver_port):
        self.node, self.controller, self.receiver_port = node, controller, receiver_port
        self.upload_connections = 0
        super().__init__(("127.0.0.1", port), SocksHandler)


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        incoming, server = self.request, self.server
        source = self.client_address[1]
        outgoing = None
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
            if outgoing is not None:
                outgoing.close()


def serve(server):
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server


class ChildWindow:
    """Address only visible Tk children owned by this exact test process.

    Tk does not expose ttk button text through Win32. Identify the known four
    button layout, then post client-coordinate mouse events to its HWND. Fail
    closed if that layout changes; never send input to the foreground window.
    """
    def __init__(self, process):
        self.process = process
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        self.user.IsWindowVisible.argtypes = [wintypes.HWND]
        self.user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        self.user.EnumWindows.argtypes = [self.callback, wintypes.LPARAM]
        self.user.EnumChildWindows.argtypes = [wintypes.HWND, self.callback, wintypes.LPARAM]
        # PyInstaller onefile's parent waits for its GUI child. Both are scoped
        # to the copied executable, checked by process ancestry below.
        self.pids = {process.pid}

    def children(self):
        # Query only descendants of the Popen PID; do not match window titles.
        import subprocess
        query = ("$p=Get-CimInstance Win32_Process; $ids=@(" + str(self.process.pid) + "); "
                 "1..3 | ForEach-Object {$ids+=@($p | Where-Object {$_.ParentProcessId -in $ids} | "
                 "ForEach-Object ProcessId)}; $ids | Sort-Object -Unique")
        output = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
                                         creationflags=0x08000000, timeout=15, text=True,
                                         env={k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"})
        self.pids = {int(line) for line in output.splitlines() if line.strip().isdigit()}
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
            if self.user.IsWindowVisible(hwnd):
                rect = wintypes.RECT()
                self.user.GetWindowRect(hwnd, ctypes.byref(rect))
                items.append((hwnd, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top))
            return True
        for window in windows:
            self.user.EnumChildWindows(window, self.callback(child), 0)
        return items

    def click(self, name):
        items = self.children()
        # Actual ttk buttons are the only short rectangular leaves in the
        # bottom action area; labels there are narrower in height.
        buttons = [item for item in items if 24 <= item[4] <= 42 and 65 <= item[3] <= 300]
        if buttons:
            bottom = max(item[2] for item in buttons)
            buttons = [item for item in buttons if item[2] >= bottom - 100]
        if len(buttons) != 4:
            raise AssertionError("unexpected child button layout: " + repr(buttons))
        close = max(buttons, key=lambda item: item[2])
        row = sorted((item for item in buttons if item != close), key=lambda item: item[1])
        target = {"start": row[0], "stop": row[1], "close": close}[name]
        hwnd = target[0]
        point = 10 | (10 << 16)
        assert self.user.PostMessageW(hwnd, 0x0201, 1, point)
        assert self.user.PostMessageW(hwnd, 0x0202, 0, point)
