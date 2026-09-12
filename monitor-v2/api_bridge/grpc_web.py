"""Minimal gRPC-Web client for the sing-box service.api (stdlib only).

sing-box 1.14 ``service.api`` is a gRPC server that ALSO accepts gRPC-Web on
the same TCP listener (see ``service/api/web_bridge.go`` at tag v1.14.0):

    POST /daemon.StartedService/SubscribeConnections
    Content-Type: application/grpc-web+proto

BOTH directions use the standard gRPC length-prefixed frames
(1 byte flags + 4 bytes big-endian length + payload): the request body MUST
carry the  0x00 + BE length + protobuf  envelope (the official bridge only
rewrites the content type and forwards the body to the gRPC server), and the
response is a stream of 0x00 data frames followed by one 0x80 trailer frame.

The streaming body is read through a raw socket with select-based pacing:
a healthy but idle stream legitimately stays silent for a long time (the
official server skips empty ticker batches), so read silence produces an empty
"heartbeat" batch instead of an error, and a timed-out read can never corrupt
client-side connection state (http.client was too fragile for this).

SECURITY: the service must only ever be reached on the loopback interface.
``parse_api_url`` refuses anything else (fail-closed) so a secret can never be
sent to a non-loopback host by accident.
"""

from __future__ import annotations

import select
import socket
import ssl
import urllib.parse

from .proto_wire import decode_connection_events

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_API_PORT = 9091
GRPC_WEB_CONTENT_TYPE = "application/grpc-web+proto"
FLAG_DATA = 0x00
FLAG_TRAILER = 0x80
MAX_HEADER_BYTES = 65536
RECV_CHUNK = 65536


class ConfigurationError(Exception):
    """Fatal collector configuration problem (e.g. non-loopback URL)."""


class StreamError(Exception):
    """The event stream failed (transport, gRPC status or decode error)."""


class _Idle(Exception):
    """No data arrived within the idle allowance (healthy silence)."""


def parse_api_url(url):
    """Parse and VALIDATE the service.api URL. Loopback only, fail-closed.

    Returns (host, port). Accepts 127.0.0.1, localhost and ::1; rejects
    0.0.0.0, private ranges, hostnames and everything else.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ConfigurationError(
            "service.api URL scheme must be http(s), got %r" % parts.scheme)
    host = (parts.hostname or "").lower()
    if host not in LOOPBACK_HOSTS:
        raise ConfigurationError(
            "service.api URL must target the loopback interface "
            "(127.0.0.1 / localhost / ::1), got host %r. Refusing to send "
            "API credentials or queries anywhere else." % url)
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else DEFAULT_API_PORT
    if not 0 < port < 65536:
        raise ConfigurationError("invalid service.api port: %r" % (parts.port,))
    return host, port


class GrpcWebStream:
    """One long-lived gRPC-Web streaming call over a raw socket."""

    def __init__(self, host, port, path, request_bytes, timeout=5.0, secret=None,
                 scheme="http", idle_timeout=30.0):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path
        self.request_bytes = request_bytes
        # timeout only bounds the connect / response-header phase; body reads
        # use the separate idle_timeout (healthy silence -> heartbeat batch).
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.secret = secret
        self._sock = None
        self._raw = b""       # undecoded bytes straight from the socket
        self._buffer = b""    # decoded body bytes awaiting frame parsing
        self._chunked = False
        self._chunk_left = None
        self._chunk_tail = False  # chunk data done, trailing CRLF pending
        self._eof = False
        self.status = None
        self.headers = {}

    # -- connect / headers -----------------------------------------------------

    def _open_socket(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.scheme == "https":
            context = ssl.create_default_context()
            raw = context.wrap_socket(raw, server_hostname=self.host)
        return raw

    def connect(self):
        self._sock = self._open_socket()
        framed = b"\x00" + len(self.request_bytes).to_bytes(4, "big") + self.request_bytes
        lines = [
            "POST %s HTTP/1.1" % self.path,
            "Host: %s:%d" % (self.host, self.port),
            "Content-Type: %s" % GRPC_WEB_CONTENT_TYPE,
            "X-Grpc-Web: 1",
            "TE: trailers",
            "Connection: keep-alive",
            "Content-Length: %d" % len(framed),
        ]
        if self.secret:
            # Bearer metadata, matching the official client interceptors; the
            # value must never be logged or serialized.
            lines.append("Authorization: Bearer %s" % self.secret)
        self._sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + framed)

        while b"\r\n\r\n" not in self._raw:
            try:
                data = self._sock.recv(RECV_CHUNK)
            except socket.timeout:
                raise StreamError("service.api header read timed out")
            if not data:
                raise StreamError("service.api closed the connection during headers")
            self._raw += data
            if len(self._raw) > MAX_HEADER_BYTES:
                raise StreamError("service.api response header too large")

        head, _, rest = self._raw.partition(b"\r\n\r\n")
        self._raw = rest
        head_lines = head.split(b"\r\n")
        try:
            self.status = int(head_lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            raise StreamError("malformed HTTP status line")
        for line in head_lines[1:]:
            key, sep, value = line.partition(b":")
            if sep:
                self.headers[key.strip().lower().decode("ascii", "replace")] = \
                    value.strip().decode("ascii", "replace")
        if self.status != 200:
            raise StreamError("service.api returned HTTP %s (grpc-status=%s)"
                              % (self.status, self.headers.get("grpc-status")))
        self._chunked = "chunked" in self.headers.get("transfer-encoding", "").lower()
        self._sock.settimeout(self.idle_timeout)
        return self

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # -- body pumping ----------------------------------------------------------

    def _fill_raw(self, timeout):
        """Read once from the socket into self._raw.

        Raises _Idle when nothing arrives within ``timeout`` (healthy
        silence). Returns False when the peer closed the stream.
        """
        if timeout is not None:
            ready = select.select([self._sock], [], [], timeout)[0]
            if not ready:
                raise _Idle()
        try:
            data = self._sock.recv(RECV_CHUNK)
        except socket.timeout:
            raise _Idle()
        except OSError as exc:
            raise StreamError("socket error: %s" % exc)
        if not data:
            self._eof = True
            return False
        self._raw += data
        return True

    def _pump(self, timeout):
        """Move one step of decoded body bytes into self._buffer.

        Returns False on end-of-body (chunked terminator or EOF).
        """
        if not self._chunked:
            if not self._raw:
                if not self._fill_raw(timeout):
                    return False
            self._buffer += self._raw
            self._raw = b""
            return True
        while True:
            if self._chunk_left is None:
                if b"\r\n" not in self._raw:
                    if not self._fill_raw(timeout):
                        raise StreamError("connection closed inside a chunk header")
                    continue
                line, _, rest = self._raw.partition(b"\r\n")
                self._raw = rest
                try:
                    self._chunk_left = int(line.split(b";", 1)[0], 16)
                except ValueError:
                    raise StreamError("bad chunk header %r" % line[:32])
                self._chunk_tail = False
                continue
            if self._chunk_left == 0 and not self._chunk_tail:
                self._raw = b""  # HTTP trailers (if any) are not part of gRPC-Web
                return False
            if self._chunk_left == 0 and self._chunk_tail:
                # chunk data fully delivered; consume its terminating CRLF
                while len(self._raw) < 2:
                    if not self._fill_raw(timeout):
                        raise StreamError("connection closed after chunk data")
                if not self._raw.startswith(b"\r\n"):
                    raise StreamError("malformed chunk terminator")
                self._raw = self._raw[2:]
                self._chunk_left = None
                self._chunk_tail = False
                continue
            if not self._raw:
                if not self._fill_raw(timeout):
                    raise StreamError("connection closed mid-chunk")
                continue
            take = min(len(self._raw), self._chunk_left)
            self._buffer += self._raw[:take]
            self._raw = self._raw[take:]
            self._chunk_left -= take
            if self._chunk_left == 0:
                self._chunk_tail = True
            return True

    def _read_exact(self, count, timeout):
        while len(self._buffer) < count:
            if not self._pump(timeout):
                if self._buffer:
                    raise StreamError("stream ended mid-frame (%d/%d bytes)"
                                      % (len(self._buffer), count))
                raise EOFError("stream ended")
        out = self._buffer[:count]
        self._buffer = self._buffer[count:]
        return out

    def _read_frame(self, timeout):
        header = self._read_exact(5, timeout)
        flags = header[0]
        length = int.from_bytes(header[1:5], "big")
        payload = self._read_exact(length, timeout) if length else b""
        return flags, payload

    @staticmethod
    def _read_trailers(payload):
        status = None
        for line in payload.decode("utf-8", errors="replace").splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() == "grpc-status":
                status = value.strip()
        return status

    def batches(self):
        """Yield decoded ConnectionEvents batches until the stream ends.

        A read timeout yields an EMPTY heartbeat batch instead of failing:
        the official server sends nothing at all while there is no traffic,
        so silence is health, not staleness. Real failures (EOF, transport
        errors, non-zero grpc-status, decode errors) still raise / end the
        stream.
        """
        while True:
            try:
                flags, payload = self._read_frame(self.idle_timeout)
            except _Idle:
                yield {"reset": False, "events": [], "heartbeat": True}
                continue
            except EOFError:
                return
            if flags & FLAG_TRAILER:
                status = self._read_trailers(payload)
                if status not in (None, "0"):
                    raise StreamError("grpc-status=%s" % status)
                return
            if flags != FLAG_DATA:
                raise StreamError("unknown gRPC-Web frame flags 0x%02x" % flags)
            yield decode_connection_events(payload)
