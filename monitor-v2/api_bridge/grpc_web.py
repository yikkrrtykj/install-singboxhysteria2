"""Minimal gRPC-Web client for the sing-box service.api (stdlib only).

sing-box 1.14 ``service.api`` is a gRPC server that ALSO accepts gRPC-Web on
the same TCP listener (see ``service/api/web_bridge.go`` at tag v1.14.0):

    POST /daemon.StartedService/SubscribeConnections
    Content-Type: application/grpc-web+proto

    body: standard gRPC length-prefixed frames
          (1 byte flags + 4 bytes big-endian length + payload)
          data frames carry flags 0x00, the final trailer frame 0x80.

The bridge streams server responses with immediate flushes, so a plain
HTTP/1.1 client (stdlib ``http.client``) can consume the event stream without
any third-party dependency.

SECURITY: the service must only ever be reached on the loopback interface.
``parse_api_url`` refuses anything else (fail-closed) so a secret can never be
sent to a non-loopback host by accident.
"""

from __future__ import annotations

import http.client
import urllib.parse

from .proto_wire import decode_connection_events

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_API_PORT = 9091
GRPC_WEB_CONTENT_TYPE = "application/grpc-web+proto"
FLAG_DATA = 0x00
FLAG_TRAILER = 0x80


class ConfigurationError(Exception):
    """Fatal collector configuration problem (e.g. non-loopback URL)."""


class StreamError(Exception):
    """The event stream failed (transport, gRPC status or decode error)."""


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
    """One long-lived gRPC-Web streaming call; iterates decoded batches."""

    def __init__(self, host, port, path, request_bytes, timeout=5.0, secret=None,
                 scheme="http"):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path
        self.request_bytes = request_bytes
        self.timeout = timeout
        self.secret = secret
        self._conn = None
        self._response = None
        self._buffer = b""
        self._eof = False

    def connect(self):
        if self.scheme == "https":
            self._conn = http.client.HTTPSConnection(self.host, self.port,
                                                     timeout=self.timeout)
        else:
            self._conn = http.client.HTTPConnection(self.host, self.port,
                                                    timeout=self.timeout)
        headers = {
            "Content-Type": GRPC_WEB_CONTENT_TYPE,
            "X-Grpc-Web": "1",
            "TE": "trailers",
        }
        if self.secret:
            # authorization is set via metadata, matching the official client
            # interceptors; the value must never be logged or serialized.
            headers["Authorization"] = "Bearer %s" % self.secret
        self._conn.request("POST", self.path, body=self.request_bytes,
                           headers=headers)
        self._response = self._conn.getresponse()
        if self._response.status != 200:
            grpc_status = self._response.getheader("grpc-status")
            raise StreamError("service.api returned HTTP %s (grpc-status=%s)"
                              % (self._response.status, grpc_status))
        return self

    def _read_exact(self, count):
        while len(self._buffer) < count:
            if self._eof:
                raise EOFError("stream ended mid-frame")
            chunk = self._response.read(min(65536, count - len(self._buffer)))
            if not chunk:
                self._eof = True
                if self._buffer:
                    raise StreamError("stream ended mid-frame (%d/%d bytes)"
                                      % (len(self._buffer), count))
                raise EOFError("stream ended")
            self._buffer += chunk
        out = self._buffer[:count]
        self._buffer = self._buffer[count:]
        return out

    def _read_frame(self):
        header = self._read_exact(5)
        flags = header[0]
        length = int.from_bytes(header[1:5], "big")
        payload = self._read_exact(length)
        return flags, payload

    def _read_trailers(self, payload):
        status = None
        for line in payload.decode("utf-8", errors="replace").splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() == "grpc-status":
                status = value.strip()
        return status

    def batches(self):
        """Yield decoded ConnectionEvents batches until the stream ends.

        Raises StreamError on gRPC failure / decode problems; StopIteration
        semantics are expressed via return.
        """
        while True:
            try:
                flags, payload = self._read_frame()
            except EOFError:
                return
            if flags & FLAG_TRAILER:
                status = self._read_trailers(payload)
                if status not in (None, "0"):
                    raise StreamError("grpc-status=%s" % status)
                return
            yield decode_connection_events(payload)

    def close(self):
        try:
            if self._response is not None:
                self._response.close()
        finally:
            if self._conn is not None:
                self._conn.close()
            self._conn = None
            self._response = None
