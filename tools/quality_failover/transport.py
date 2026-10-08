"""Deadline/byte/rate-bounded upload through a dedicated loopback SOCKS listener."""
import hashlib
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import time
import threading
from urllib.parse import urlsplit
from .policy import Confirmation, number

MAX_BODY = 1024 * 1024
MAX_REPLY = 1024


class UploadTimeout(TimeoutError):
    pass


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    def constant(token):
        raise ValueError("nonfinite_json")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError:
        raise ValueError("json_depth") from None


def endpoint(value):
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path not in ("", "/")):
        raise ValueError("endpoint")
    # DNS timeouts cannot be enforced by socket.settimeout. V1 therefore uses
    # a numeric controlled endpoint with an IP SAN TLS certificate.
    address = ipaddress.ip_address(parts.hostname)
    return str(address), parts.port or 443


def recv_exact(sock, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        sock.settimeout(remaining)
        block = sock.recv(count - len(result))
        if not block:
            raise OSError()
        result.extend(block)
    return bytes(result)


def socks_connect(port, host, remote_port, deadline):
    sock = socket.create_connection(("127.0.0.1", port),
                                    timeout=max(.01, deadline - time.monotonic()))
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2, deadline) != b"\x05\x00":
            raise OSError()
        address = ipaddress.ip_address(host)
        atyp = b"\x01" if address.version == 4 else b"\x04"
        sock.sendall(b"\x05\x01\x00" + atyp + address.packed + struct.pack(">H", remote_port))
        reply = recv_exact(sock, 4, deadline)
        if reply[:2] != b"\x05\x00":
            raise OSError()
        length = {1: 4, 4: 16}.get(reply[3])
        if length is None:
            raise OSError()
        recv_exact(sock, length + 2, deadline)
        return sock
    except BaseException:
        sock.close()
        raise


class Probe:
    def __init__(self, url, token, ca_file, payload_bytes, rate_mbps, timeout_seconds):
        self.host, self.port = endpoint(url)
        if (type(token) is not str or not 32 <= len(token) <= 128
                or not token.isascii() or not token.isalnum()
                or type(payload_bytes) is not int or not 32768 <= payload_bytes <= MAX_BODY
                or not number(rate_mbps, .1, 100)
                or not number(timeout_seconds, 1, 15)
                or payload_bytes * 8 / (rate_mbps * 1e6) >= timeout_seconds / 2):
            raise ValueError("probe")
        self.token, self.size, self.rate, self.timeout = token, payload_bytes, rate_mbps, timeout_seconds
        self.context = ssl.create_default_context(cafile=ca_file)

    def request(self, listener_port, path, payload=b"", verifier=None):
        deadline = time.monotonic() + self.timeout
        sock = socks_connect(listener_port, self.host, self.port, deadline)
        tls, timer, upload_started = None, None, False
        expired = threading.Event()
        try:
            sock.settimeout(max(.01, deadline - time.monotonic()))
            tls = self.context.wrap_socket(sock, server_hostname=self.host)
            def abort():
                expired.set()
                try:
                    tls.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(.001, deadline - time.monotonic()), abort)
            timer.daemon = True
            timer.start()
            if verifier is not None and verifier(tls.getsockname()[1]) is not True:
                raise ValueError("route_unconfirmed")
            nonce = secrets.token_hex(16)
            method = "POST" if payload else "GET"
            authority = "[%s]" % self.host if ":" in self.host else self.host
            headers = (f"{method} /quality-v1/{path} HTTP/1.1\r\n"
                       f"Host: {authority}:{self.port}\r\n"
                       f"Authorization: Bearer {self.token}\r\n"
                       f"X-Probe-Nonce: {nonce}\r\n"
                       f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n")
            tls.sendall(headers.encode("ascii"))
            start = time.monotonic()
            upload_started = bool(payload)
            sent = 0
            for offset in range(0, len(payload), 8192):
                delay = sent * 8 / (self.rate * 1e6) - (time.monotonic() - start)
                if delay > 0:
                    if time.monotonic() + delay >= deadline:
                        raise TimeoutError()
                    time.sleep(delay)
                tls.settimeout(max(.001, deadline - time.monotonic()))
                block = payload[offset:offset + 8192]
                tls.sendall(block)
                sent += len(block)
            tls.settimeout(max(.001, deadline - time.monotonic()))
            response = http.client.HTTPResponse(tls)
            response.begin()
            # Incremental reads prevent a slow response from stretching the
            # absolute budget one socket timeout per received chunk.
            chunks = bytearray()
            while len(chunks) <= MAX_REPLY:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                tls.settimeout(remaining)
                block = response.read1(min(256, MAX_REPLY + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if time.monotonic() > deadline or response.status != 200 or len(chunks) > MAX_REPLY:
                raise ValueError("response")
            value = decode_json(chunks)
            expected = {"v": 1, "nonce": nonce, "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest()}
            if type(value) is not dict or set(value) != set(expected) | {"measured_bytes", "upload_seconds"}:
                raise ValueError("receipt")
            if any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items()):
                raise ValueError("receipt")
            measured, seconds = value["measured_bytes"], value["upload_seconds"]
            if not payload:
                if type(measured) is not int or measured != 0 or not number(seconds, 0, 0):
                    raise ValueError("receipt")
                return 0
            if (type(measured) is not int or not len(payload) - 8192 <= measured < len(payload)
                    or not number(seconds, .000001, 15)):
                raise ValueError("receipt")
            # VPS body arrival time excludes connection/TLS setup and ACK RTT.
            # Clamp buffer bursts to the configured send cap.
            return min(self.rate, measured * 8 / seconds / 1e6)
        except (OSError, http.client.HTTPException) as exc:
            if upload_started and (expired.is_set() or isinstance(exc, TimeoutError)):
                raise UploadTimeout() from None
            raise
        finally:
            if timer is not None:
                timer.cancel()
            if tls is not None:
                tls.close()
            else:
                sock.close()

    def measure(self, listener_port, verifier=None):
        try:
            self.request(listener_port, "ready", verifier=verifier)
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            return Confirmation()  # endpoint failure is NOT a quality verdict
        try:
            mbps = self.request(listener_port, "upload", b"\0" * self.size, verifier=verifier)
            if mbps <= 0:
                return Confirmation()
            return Confirmation(mbps, endpoint_ready=True)
        except UploadTimeout:
            return Confirmation(timed_out=True, endpoint_ready=True)
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            return Confirmation()
