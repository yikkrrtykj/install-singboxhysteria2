"""sing-box 1.14 ``service.api`` event stream adapter.

Uses the OFFICIAL gRPC surface (``daemon.StartedService/SubscribeConnections``,
see ``daemon/started_service.proto`` at tag v1.14.0) over gRPC-Web, which the
service.api natively accepts on the same loopback listener. There is no Clash
REST ``/connections`` endpoint involved anywhere -- that belongs to the old
Clash API, not to the Phase D service.api.

Official stream contract (verified against the v1.14.0 source,
``daemon/started_service.go``):

* the FIRST message of every subscription carries ``reset=true`` and contains
  NEW events for ALL active connections plus NEW events (with ``closedAt``
  set) for recently closed ones -- the client rebuilds its state from it;
* UPDATE events carry only ``id`` + ``uplinkDelta`` + ``downlinkDelta`` (no
  Connection object); a UPDATE(0,0) signals "traffic stopped";
* CLOSED events carry ``id`` + ``closedAt`` (Connection object optional);
* ``interval`` in SubscribeConnectionsRequest is NANOSECONDS and only paces
  the UPDATE ticker; NEW/CLOSED are pushed in real time.
"""

from __future__ import annotations

from .grpc_web import (ConfigurationError, GrpcWebStream, StreamError,
                       parse_api_url)
from .proto_wire import encode_subscribe_connections_request

SERVICE_PATH = "/daemon.StartedService/SubscribeConnections"
__all__ = ["ConfigurationError", "StreamError", "SingboxEventStream",
           "parse_api_url", "SERVICE_PATH"]


class SingboxEventStream:
    """Connects to the service.api event stream and yields decoded batches.

    Each batch is ``{"reset": bool, "events": [event, ...]}`` with JSON-friendly
    snake_case fields that mirror the official proto names (id / user / inbound
    / inbound_type / network / source / destination / created_at / closed_at /
    uplink_total / downlink_total / uplink_delta / downlink_delta).
    """

    def __init__(self, url, interval_seconds=2.0, secret=None,
                 connect_timeout=5.0, idle_timeout=30.0):
        # parse_api_url is fail-closed: anything non-loopback is refused here.
        self.host, self.port = parse_api_url(url)
        self.url = url
        self.interval_seconds = interval_seconds
        self.secret = secret
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.interval_ns = int(round(interval_seconds * 1_000_000_000)) or 1
        self._stream = None

    def __iter__(self):
        request = encode_subscribe_connections_request(self.interval_ns)
        self._stream = GrpcWebStream(
            self.host, self.port, SERVICE_PATH, request,
            timeout=self.connect_timeout, secret=self.secret,
            idle_timeout=self.idle_timeout,
            scheme="https" if self.url.startswith("https") else "http")
        self._stream.connect()
        return self._stream.batches()

    def close(self):
        if self._stream is not None:
            self._stream.close()
            self._stream = None
