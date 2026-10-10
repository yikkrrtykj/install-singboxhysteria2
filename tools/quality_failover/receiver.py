"""Controlled-VPS HTTPS upload sink. Never part of Monitor, no payload persistence."""
import hashlib
import hmac
import json
import re
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .transport import MAX_BODY

NONCE = re.compile(r"\A[0-9a-f]{32}\Z")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, token, context=None, minute_bytes=2 * MAX_BODY):
        if type(token) is not str or not token.isascii() or not token.isalnum() or not 32 <= len(token) <= 128:
            raise ValueError("token")
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self.token, self.context = token, context
        self.gate = threading.BoundedSemaphore(2)
        self.budget_lock = threading.Lock()
        self.minute_start, self.minute_used = time.monotonic(), 0
        self.minute_bytes = minute_bytes
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.gate.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.gate.release()
            raise

    def process_request_thread(self, request, address):
        try:
            if self.context is not None:
                request.settimeout(2)
                request = self.context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.gate.release()

    def handle_error(self, request, address):
        pass

    def reserve(self, size):
        with self.budget_lock:
            now = time.monotonic()
            if now - self.minute_start >= 60:
                self.minute_start, self.minute_used = now, 0
            if self.minute_used + size > self.minute_bytes:
                return False
            self.minute_used += size
            return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        self.request.settimeout(2)
        super().setup()
        def abort():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.deadline_timer = threading.Timer(20, abort)
        self.deadline_timer.daemon = True
        self.deadline_timer.start()

    def finish(self):
        try:
            super().finish()
        finally:
            self.deadline_timer.cancel()

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        # No request path, auth material, body or peer address in responses/logs.
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def checked(self, upload):
        if (self.path != "/quality-v1/" + ("upload" if upload else "ready")
                or len(self.headers.get_all("Authorization", [])) != 1
                or not self.headers.get("Authorization", "").isascii()
                or not hmac.compare_digest(self.headers.get("Authorization", ""),
                                            "Bearer " + self.server.token)
                or self.headers.get("Transfer-Encoding") is not None
                or len(self.headers.get_all("Content-Length", [])) != 1
                or len(self.headers.get_all("X-Probe-Nonce", [])) != 1):
            self.send_error(403)
            return None
        nonce = self.headers["X-Probe-Nonce"]
        try:
            raw_size = self.headers["Content-Length"]
            if not re.fullmatch(r"0|[1-9][0-9]{0,6}", raw_size):
                raise ValueError()
            size = int(raw_size)
            if not NONCE.fullmatch(nonce) or not ((0 < size <= MAX_BODY) if upload else size == 0):
                raise ValueError()
        except ValueError:
            self.send_error(400)
            return None
        if not self.server.reserve(size):
            self.send_error(429)
            return None
        return nonce, size

    def do_GET(self):
        request = self.checked(False)
        if request is not None:
            self.reply(request[0], 0, hashlib.sha256(b"").hexdigest())

    def do_POST(self):
        request = self.checked(True)
        if request is None:
            return
        nonce, size = request
        digest = hashlib.sha256()
        body_start, first_chunk = None, 0
        deadline, remaining = time.monotonic() + 15, size
        try:
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise TimeoutError()
                self.connection.settimeout(min(2, budget))
                # read1 returns currently available bytes, so each read has a
                # fresh absolute-deadline check even against a dribbling peer.
                chunk = self.rfile.read1(min(8192, remaining))
                if not chunk:
                    raise OSError()
                if body_start is None:
                    body_start, first_chunk = time.monotonic(), len(chunk)
                remaining -= len(chunk)
                digest.update(chunk)
            seconds = max(.000001, time.monotonic() - body_start)
            self.reply(nonce, size, digest.hexdigest(), size - first_chunk, seconds)
        except (OSError, socket.timeout):
            self.close_connection = True

    def reply(self, nonce, size, digest, measured_bytes=0, seconds=0):
        body = json.dumps({"v": 1, "nonce": nonce, "bytes": size, "sha256": digest, "measured_bytes": measured_bytes,
                           "upload_seconds": seconds},
                          separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
