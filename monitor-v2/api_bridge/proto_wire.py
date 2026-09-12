"""Hand-rolled protobuf wire codec for the exact messages of the
sing-box 1.14 ``daemon.StartedService`` connection API.

Field numbers come from the OFFICIAL proto file
``daemon/started_service.proto`` at tag v1.14.0
(https://github.com/SagerNet/sing-box/blob/v1.14.0/daemon/started_service.proto)
and must never be guessed:

    message SubscribeConnectionsRequest { int64 interval = 1; }  // nanoseconds

    message ConnectionEvents {
      repeated ConnectionEvent events = 1;
      bool reset = 2;
    }
    message ConnectionEvent {
      ConnectionEventType type          = 1;  // 0=NEW 1=UPDATE 2=CLOSED
      string              id            = 2;
      Connection          connection    = 3;
      int64               uplinkDelta   = 4;
      int64               downlinkDelta = 5;
      int64               closedAt      = 6;
    }
    message Connection {
      string id            = 1;
      string inbound       = 2;
      string inboundType   = 3;
      int32  ipVersion     = 4;
      string network       = 5;
      string source        = 6;
      string destination   = 7;
      string domain        = 8;
      string protocol      = 9;
      string user          = 10;
      string fromOutbound  = 11;
      int64  createdAt     = 12;
      int64  closedAt      = 13;
      int64  uplink        = 14;
      int64  downlink      = 15;
      int64  uplinkTotal   = 16;
      int64  downlinkTotal = 17;
      ...  // rule/outbound/chainList/processInfo -- not needed by E1
    }

Unknown fields (including the messages E1 does not model) are skipped by wire
type, exactly as a protobuf implementation is required to do.
"""

from __future__ import annotations

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5


class ProtoDecodeError(ValueError):
    """Raised when a payload does not conform to the protobuf wire format."""


def encode_varint(value):
    if value < 0:
        raise ValueError("encode_varint expects a non-negative integer")
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _decode_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ProtoDecodeError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ProtoDecodeError("varint too long")


def _to_signed64(unsigned):
    """proto int64/sint? -- int64 uses two's-complement 64-bit varints."""
    return unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned


def decode_message(buf, spec):
    """Decode ``buf`` according to ``spec``: {field_number: (name, kind)}.

    kind is one of ``varint`` (int64), ``bool``, ``string`` or ``message``
    (the latter returns the raw sub-bytes; the caller decodes recursively).
    Repeated occurrences of the same field accumulate into a list.
    Unknown fields are skipped by wire type. Returns a plain dict.
    """
    values = {}
    pos = 0
    size = len(buf)
    while pos < size:
        tag, pos = _decode_varint(buf, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == WIRE_VARINT:
            raw, pos = _decode_varint(buf, pos)
            value = _to_signed64(raw)
        elif wire_type == WIRE_LEN:
            length, pos = _decode_varint(buf, pos)
            if pos + length > size:
                raise ProtoDecodeError("length-delimited field overruns buffer")
            value = buf[pos:pos + length]
            pos += length
        elif wire_type == WIRE_FIXED64:
            if pos + 8 > size:
                raise ProtoDecodeError("truncated fixed64")
            value = buf[pos:pos + 8]
            pos += 8
        elif wire_type == WIRE_FIXED32:
            if pos + 4 > size:
                raise ProtoDecodeError("truncated fixed32")
            value = buf[pos:pos + 4]
            pos += 4
        else:
            raise ProtoDecodeError("unsupported wire type %d" % wire_type)

        entry = spec.get(field_number)
        if entry is None:
            continue  # unknown field: skipped, as protobuf requires
        name, kind = entry
        if kind == "varint":
            decoded = value if isinstance(value, int) else None
        elif kind == "bool":
            decoded = bool(value)
        elif kind == "string":
            decoded = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else None
        elif kind == "message":
            decoded = value if isinstance(value, bytes) else None
        else:
            decoded = None
        if decoded is None:
            continue
        if name in values:
            if not isinstance(values[name], list):
                values[name] = [values[name]]
            values[name].append(decoded)
        else:
            values[name] = decoded
    return values


def encode_length_delimited(field_number, payload):
    payload = bytes(payload)
    return encode_varint((field_number << 3) | WIRE_LEN) + \
        encode_varint(len(payload)) + payload


def encode_varint_field(field_number, value):
    return encode_varint((field_number << 3) | WIRE_VARINT) + encode_varint(value)


# ---- concrete messages -------------------------------------------------------

EVENT_TYPE_NEW = "NEW"
EVENT_TYPE_UPDATE = "UPDATE"
EVENT_TYPE_CLOSED = "CLOSED"
_EVENT_TYPE_NAMES = {0: EVENT_TYPE_NEW, 1: EVENT_TYPE_UPDATE, 2: EVENT_TYPE_CLOSED}

CONNECTION_SPEC = {
    1: ("id", "string"),
    2: ("inbound", "string"),
    3: ("inbound_type", "string"),
    4: ("ip_version", "varint"),
    5: ("network", "string"),
    6: ("source", "string"),
    7: ("destination", "string"),
    10: ("user", "string"),
    12: ("created_at", "varint"),
    13: ("closed_at", "varint"),
    16: ("uplink_total", "varint"),
    17: ("downlink_total", "varint"),
}

CONNECTION_EVENT_SPEC = {
    1: ("type", "varint"),
    2: ("id", "string"),
    3: ("connection", "message"),
    4: ("uplink_delta", "varint"),
    5: ("downlink_delta", "varint"),
    6: ("closed_at", "varint"),
}

CONNECTION_EVENTS_SPEC = {
    1: ("events", "message"),
    2: ("reset", "bool"),
}


def encode_subscribe_connections_request(interval_ns):
    """SubscribeConnectionsRequest{ int64 interval = 1; } -- nanoseconds."""
    return encode_varint_field(1, int(interval_ns))


def decode_connection(raw):
    if not isinstance(raw, (bytes, bytearray)):
        return None
    return decode_message(bytes(raw), CONNECTION_SPEC)


def decode_connection_event(raw):
    if not isinstance(raw, (bytes, bytearray)):
        return None
    fields = decode_message(bytes(raw), CONNECTION_EVENT_SPEC)
    type_number = fields.get("type", 0)
    return {
        "type": _EVENT_TYPE_NAMES.get(type_number, "UNKNOWN_%d" % type_number),
        "id": fields.get("id", ""),
        "connection": decode_connection(fields["connection"])
        if isinstance(fields.get("connection"), bytes) else None,
        "uplink_delta": float(fields.get("uplink_delta", 0)),
        "downlink_delta": float(fields.get("downlink_delta", 0)),
        "closed_at": int(fields.get("closed_at", 0)),
    }


def decode_connection_events(raw):
    """Decode one ConnectionEvents message into a JSON-friendly batch."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ProtoDecodeError("ConnectionEvents payload must be bytes")
    fields = decode_message(bytes(raw), CONNECTION_EVENTS_SPEC)
    raw_events = fields.get("events", [])
    if not isinstance(raw_events, list):
        raw_events = [raw_events]
    events = []
    for raw_event in raw_events:
        event = decode_connection_event(raw_event)
        if event is not None:
            events.append(event)
    return {"reset": bool(fields.get("reset", False)), "events": events}


def decode_connection_field_numbers():  # pragma: no cover - documentation aid
    return dict(CONNECTION_SPEC)
