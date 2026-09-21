"""AF_UNIX RPC client for the sbox-cm privileged execution plane (M2-B).

Transport contract (mirrors the daemon, ``sbox-cm/sbox-cm``):

* AF_UNIX SOCK_STREAM to ``/run/sbox-cm/sbox-cm.sock`` (root:sboxweb 0660;
  this process runs as ``sboxweb``, so the socket DAC and the daemon's
  SO_PEERCRED check are the entire authentication -- nothing else is sent);
* one request per connection: connect -> one framed request -> one framed
  response -> close. No pipelining, no session state;
* frame = 4-byte big-endian unsigned payload length + UTF-8 JSON payload;
  the daemon closes the connection on a bad frame and never answers it;
* the ONLY helper-side deadline is the 5 s frame read (M1 B6: there is no
  per-op kill deadline anywhere). The per-op budgets below are the M2
  CALLER's wait budget: they bound how long THIS process waits, never what
  the helper may do. A budget exhaustion after the frame was sent is
  reported as an uncertain outcome -- the transaction keeps running inside
  the helper and drives itself to a terminal state.

Stage semantics of :class:`RpcTransportError` -- callers depend on them:

``connect``   the connection was never established, so the request was
              definitively NOT dispatched (no transaction can have started);
``send``      the frame may have been partially delivered -- the request MAY
              have been dispatched (uncertain);
``read``      the frame was fully sent and no complete response arrived in
              the caller's budget -- the request WAS dispatched and the
              outcome is UNCERTAIN by design (M1 keeps the transaction
              running; see the Idempotency-Key ledger);
``frame``     a response arrived but violates the framing/JSON contract --
              treated as uncertain like ``read`` (something answered; we
              cannot prove what).

There is deliberately NO retry anywhere in this module: retrying a
mutation could double-execute it, and retrying a read is the broker's
decision (single-flight), not the transport's.
"""

from __future__ import annotations

import json
import socket
import struct
import uuid

DEFAULT_SOCKET_PATH = "/run/sbox-cm/sbox-cm.sock"
RPC_VERSION = "e3-rpc/1"
MAX_FRAME = 65536

# Caller wait budgets (M2 frozen ruling; NOT helper deadlines). client.list
# gets 20s because the helper's config.lock wait alone can run 15s.
# M4: client.export shares that 20s read budget (same lock wait, plus the
# in-process render); it is a read -- no 120s mutation window applies.
DEFAULT_OP_BUDGETS = {
    "management.status": 5.0,
    "client.list": 20.0,
    "client.export": 20.0,
    "management.activate": 30.0,
    "management.deactivate": 30.0,
    "client.add": 120.0,
    "client.delete": 120.0,
}

REQUEST_ID_PREFIX = "web-"


class RpcTransportError(Exception):
    """A transport-layer failure. Never carries a helper verdict."""

    def __init__(self, stage, detail=""):
        Exception.__init__(self, "%s: %s" % (stage, detail or stage))
        self.stage = stage
        self.detail = detail

    @property
    def uncertain(self):
        """True when the request MAY have been dispatched (post-send)."""
        return self.stage in ("send", "read", "frame")


def new_request_id():
    """A fresh request_id per physical RPC attempt (helper REQID_RE shape)."""
    return "%s%s" % (REQUEST_ID_PREFIX, uuid.uuid4().hex)


def _recv_exact(sock, count, deadline, clock):
    buf = b""
    while len(buf) < count:
        remaining = deadline - clock()
        if remaining <= 0:
            raise RpcTransportError("read", "caller budget exhausted")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(count - len(buf))
        except socket.timeout:
            raise RpcTransportError("read", "caller budget exhausted")
        except OSError as exc:
            raise RpcTransportError("read", str(exc))
        if not chunk:
            raise RpcTransportError("read", "peer closed mid-frame")
        buf += chunk
    return buf


class E3RpcClient:
    """One-shot framed RPC client. Injectable socket path and budgets for
    tests; production uses the module constants. stdlib only."""

    def __init__(self, socket_path=DEFAULT_SOCKET_PATH,
                 budgets=None, clock=None):
        self.socket_path = socket_path
        self.budgets = dict(DEFAULT_OP_BUDGETS)
        if budgets:
            self.budgets.update(budgets)
        self._clock = clock or _monotonic

    def call(self, op, payload=None, actor=None, request_id=None):
        """One RPC attempt. Returns the parsed response dict (which may be
        ``ok:false`` -- a helper VERDICT, never an exception). Raises
        RpcTransportError when the transport itself fails; there is no
        retry. ``request_id`` is regenerated per attempt unless the caller
        supplies one (tests)."""
        import time as _time

        clock = self._clock
        budget = self.budgets.get(op, 30.0)
        deadline = clock() + budget

        body = {"v": RPC_VERSION, "request_id": request_id or new_request_id(),
                "op": op}
        if payload:
            body.update(payload)
        if actor:
            body["actor"] = actor
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_FRAME:
            raise RpcTransportError("send", "request exceeds the frame limit")

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except (AttributeError, OSError) as exc:
            raise RpcTransportError("connect", "AF_UNIX unavailable: %s" % exc)
        try:
            remaining = deadline - clock()
            if remaining <= 0:
                raise RpcTransportError("connect", "caller budget exhausted")
            sock.settimeout(remaining)
            try:
                sock.connect(self.socket_path)
            except socket.timeout:
                raise RpcTransportError("connect", "caller budget exhausted")
            except OSError as exc:
                raise RpcTransportError("connect", str(exc))
            try:
                sock.sendall(struct.pack(">I", len(raw)) + raw)
            except socket.timeout:
                raise RpcTransportError("send", "caller budget exhausted")
            except OSError as exc:
                raise RpcTransportError("send", str(exc))

            header = _recv_exact(sock, 4, deadline, clock)
            (length,) = struct.unpack(">I", header)
            if length == 0 or length > MAX_FRAME:
                raise RpcTransportError("frame", "invalid frame length")
            payload_bytes = _recv_exact(sock, length, deadline, clock)
            try:
                verdict = json.loads(payload_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise RpcTransportError("frame", str(exc))
            if not isinstance(verdict, dict):
                raise RpcTransportError("frame", "response is not an object")
            return verdict
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _monotonic():
    import time
    return time.monotonic()
