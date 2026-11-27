package linuxobs

import (
	"encoding/binary"
	"errors"
	"time"
)

// This file is the hand-rolled gRPC-Web + protobuf wire codec for the official
// sing-box 1.14 ``daemon.StartedService.SubscribeConnections`` event stream.
//
// It mirrors monitor-v2/api_bridge/proto_wire.py and grpc_web.py field for
// field (the proto file is ``daemon/started_service.proto`` at tag v1.14.0):
//
//	message SubscribeConnectionsRequest { int64 interval = 1; }  // nanoseconds
//
//	message ConnectionEvents {
//	  repeated ConnectionEvent events = 1;
//	  bool reset = 2;
//	}
//	message ConnectionEvent {
//	  ConnectionEventType type          = 1;  // 0=NEW 1=UPDATE 2=CLOSED
//	  string              id            = 2;
//	  Connection          connection    = 3;
//	  int64               uplinkDelta   = 4;
//	  int64               downlinkDelta = 5;
//	  int64               closedAt      = 6;
//	}
//	message Connection {
//	  string id            = 1;
//	  string inbound       = 2;
//	  string inboundType   = 3;   // present on the wire, not needed here
//	  int32  ipVersion     = 4;
//	  string network       = 5;
//	  string source        = 6;
//	  string destination   = 7;
//	  string domain        = 8;
//	  string protocol      = 9;
//	  string user          = 10;
//	  string fromOutbound  = 11;
//	  int64  createdAt     = 12;
//	  int64  closedAt      = 13;
//	  int64  uplink        = 14;
//	  int64  downlink      = 15;
//	  int64  uplinkTotal   = 16;
//	  int64  downlinkTotal = 17;
//	  // rule / outbound / chainList / processInfo are deliberately not modeled
//	  // because the accumulator never needs them; unknown fields are skipped by
//	  // wire type exactly as protobuf requires.
//	}
//
// No external protobuf dependency is used. Every decoder error message is a
// fixed package-level string: raw frame bytes are never echoed into an error
// (they can legitimately contain user/device metadata and, on a hostile local
// peer, anything at all).

// Protobuf wire types. The deprecated group wire types (3 and 4) are rejected
// rather than skipped, matching the reference Python decoder.
const (
	protoWireVarint  = 0
	protoWireFixed64 = 1
	protoWireBytes   = 2
	protoWireFixed32 = 5
)

// gRPC-Web frame flags. A response body is a sequence of data frames followed
// by exactly one trailer frame (unless the peer dies first).
const (
	serviceAPIGRPCWebDataFlag    = 0x00
	serviceAPIGRPCWebTrailerFlag = 0x80

	serviceAPISubscribeIntervalFieldNumber = 1
)

// ConnectionEvent.type enum values (see the proto). Any other value is an
// unknown event type and is skipped by the accumulator, never guessed.
const (
	serviceAPIEventNew    = 0
	serviceAPIEventUpdate = 1
	serviceAPIEventClosed = 2
)

// Fixed decoder/encoder errors. These never contain payload bytes.
var (
	errServiceAPIProtoTruncated     = errors.New("linuxobs: truncated protobuf payload")
	errServiceAPIProtoVarint        = errors.New("linuxobs: malformed protobuf varint")
	errServiceAPIProtoWireType      = errors.New("linuxobs: unsupported protobuf wire type")
	errServiceAPIProtoLength        = errors.New("linuxobs: protobuf field length overruns the payload")
	errServiceAPIProtoField         = errors.New("linuxobs: malformed protobuf field")
	errServiceAPIProtoTooManyEvents = errors.New("linuxobs: too many connection events in one frame")
)

// serviceAPIConnection is the modeled proto Connection message. has* flags
// preserve protobuf presence: proto3 omits zero-valued scalars, so
// UPDATE-with-Connection "authoritative totals" can only be distinguished from
// absent fields by presence. The accumulator itself consumes only
// id/inbound/closedAt/uplinkTotal/downlinkTotal; inboundType/user/createdAt are
// decoded to stay field-for-field pinned to the reference Python codec.
type serviceAPIConnection struct {
	id    string
	hasID bool

	inbound    string
	hasInbound bool

	inboundType    string
	hasInboundType bool

	user    string
	hasUser bool

	createdAt    int64
	hasCreatedAt bool

	uplinkTotal    int64
	hasUplinkTotal bool

	downlinkTotal    int64
	hasDownlinkTotal bool

	closedAt    int64
	hasClosedAt bool
}

// serviceAPIConnectionEvent is one decoded ConnectionEvent.
type serviceAPIConnectionEvent struct {
	kind    int
	hasKind bool

	id    string
	hasID bool

	connection *serviceAPIConnection

	uplinkDelta   int64
	downlinkDelta int64

	closedAt    int64
	hasClosedAt bool
}

// serviceAPIConnectionBatch is one decoded ConnectionEvents message.
type serviceAPIConnectionBatch struct {
	reset  bool
	events []serviceAPIConnectionEvent
}

// serviceAPIFrameParser incrementally parses standard gRPC-Web response
// frames. Arbitrary transport chunking is handled by buffering: feed() may be
// called with any fragment size and only consumes complete frames.
//
// Bounds: a declared frame length above maxFrameBytes is an immediate error, so
// the parser can never be made to buffer more than maxFrameBytes+5 payload
// header bytes for an incomplete frame.
type serviceAPIFrameParser struct {
	buffer        []byte
	maxFrameBytes int
}

// feed appends data and dispatches every complete frame. handle returns
// (stop, err); a stop true ends the stream cleanly after the frame.
func (parser *serviceAPIFrameParser) feed(data []byte, handle func(flags byte, payload []byte) (bool, error)) (bool, error) {
	parser.buffer = append(parser.buffer, data...)
	for {
		if len(parser.buffer) < 5 {
			return false, nil
		}
		flags := parser.buffer[0]
		length := binary.BigEndian.Uint32(parser.buffer[1:5])
		if int64(length) > int64(parser.maxFrameBytes) {
			return false, serviceAPIUnavailable("response frame exceeds the frame size cap")
		}
		total := int(length) + 5
		if len(parser.buffer) < total {
			return false, nil
		}
		payload := parser.buffer[5:total]
		stop, err := handle(flags, payload)
		parser.buffer = parser.buffer[total:]
		if len(parser.buffer) == 0 {
			parser.buffer = nil
		}
		if err != nil || stop {
			return stop, err
		}
	}
}

// serviceAPIGRPCWebTrailerStatus extracts the grpc-status value from one
// gRPC-Web trailer frame payload. The payload is a small HTTP/1 header block
// such as "grpc-status: 0\r\n"; missing status is tolerated (the Python bridge
// treats it as clean termination). The returned string is only ever compared
// against "0" and is never formatted into an error.
func serviceAPIGRPCWebTrailerStatus(payload []byte) string {
	status := ""
	for len(payload) > 0 {
		line := payload
		if index := indexByte(payload, '\n'); index >= 0 {
			line, payload = payload[:index], payload[index+1:]
		} else {
			payload = nil
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		colon := indexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := trimASCIIWhitespace(line[:colon])
		if !asciiEqualFold(name, "grpc-status") {
			continue
		}
		status = string(trimASCIIWhitespace(line[colon+1:]))
	}
	return status
}

// indexByte is a tiny local wrapper so the wire file needs no bytes import.
func indexByte(payload []byte, target byte) int {
	for index, value := range payload {
		if value == target {
			return index
		}
	}
	return -1
}

// trimASCIIWhitespace trims the HTTP header optional whitespace set.
func trimASCIIWhitespace(value []byte) []byte {
	start := 0
	for start < len(value) && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	end := len(value)
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

// asciiEqualFold compares a byte slice against a lowercase ASCII literal.
func asciiEqualFold(value []byte, lower string) bool {
	if len(value) != len(lower) {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if current != lower[index] {
			return false
		}
	}
	return true
}

// encodeServiceAPISubscribeConnectionsRequest builds the complete gRPC request
// body: 0x00 + 4-byte big-endian length + protobuf
// SubscribeConnectionsRequest{field 1: interval nanoseconds}.
func encodeServiceAPISubscribeConnectionsRequest(interval time.Duration) []byte {
	payload := appendProtoVarint(nil, serviceAPISubscribeIntervalFieldNumber<<3)
	payload = appendProtoVarint(payload, uint64(interval))
	frame := make([]byte, 5, 5+len(payload))
	frame[0] = 0x00
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	return append(frame, payload...)
}

// appendProtoVarint appends a base-128 protobuf varint.
func appendProtoVarint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

// readProtoVarint reads one protobuf varint. At most ten bytes are accepted
// (the protobuf limit for 64-bit scalars; negative int64 values are encoded as
// ten-byte two's-complement varints).
func readProtoVarint(payload []byte, position int) (uint64, int, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if position >= len(payload) {
			return 0, 0, errServiceAPIProtoTruncated
		}
		current := payload[position]
		position++
		if shift == 63 && current > 1 {
			return 0, 0, errServiceAPIProtoVarint
		}
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, position, nil
		}
	}
	return 0, 0, errServiceAPIProtoVarint
}

// decodeProtoMessage walks one protobuf message, dispatching known fields to
// handle and skipping unknown fields by wire type.
func decodeProtoMessage(payload []byte, handle func(fieldNumber int, wireType int, varintValue uint64, bytesValue []byte) error) error {
	position := 0
	for position < len(payload) {
		tag, next, err := readProtoVarint(payload, position)
		if err != nil {
			return err
		}
		position = next
		fieldNumber := int(tag >> 3)
		wireType := int(tag & 0x07)
		if fieldNumber <= 0 {
			return errServiceAPIProtoField
		}
		switch wireType {
		case protoWireVarint:
			value, nextPosition, err := readProtoVarint(payload, position)
			if err != nil {
				return err
			}
			position = nextPosition
			if err := handle(fieldNumber, wireType, value, nil); err != nil {
				return err
			}
		case protoWireFixed64:
			if len(payload)-position < 8 {
				return errServiceAPIProtoTruncated
			}
			if err := handle(fieldNumber, wireType, 0, payload[position:position+8]); err != nil {
				return err
			}
			position += 8
		case protoWireBytes:
			length, nextPosition, err := readProtoVarint(payload, position)
			if err != nil {
				return err
			}
			position = nextPosition
			if length > uint64(len(payload)-position) {
				return errServiceAPIProtoLength
			}
			end := position + int(length)
			if err := handle(fieldNumber, wireType, 0, payload[position:end]); err != nil {
				return err
			}
			position = end
		case protoWireFixed32:
			if len(payload)-position < 4 {
				return errServiceAPIProtoTruncated
			}
			if err := handle(fieldNumber, wireType, 0, payload[position:position+4]); err != nil {
				return err
			}
			position += 4
		default:
			return errServiceAPIProtoWireType
		}
	}
	return nil
}

// protoBytesField validates the wire type of a length-delimited field.
func protoBytesField(wireType int, value []byte) ([]byte, error) {
	if wireType != protoWireBytes {
		return nil, errServiceAPIProtoField
	}
	return value, nil
}

// protoInt64Field validates the wire type of an int64 varint field and applies
// two's-complement sign conversion.
func protoInt64Field(wireType int, value uint64) (int64, error) {
	if wireType != protoWireVarint {
		return 0, errServiceAPIProtoField
	}
	return int64(value), nil
}

// decodeServiceAPIConnection decodes the modeled Connection fields. The
// accumulator itself only consumes id/inbound/closedAt/uplinkTotal/
// downlinkTotal, but inboundType/user/createdAt are decoded too so the Go codec
// is field-for-field pinned to monitor-v2/api_bridge/proto_wire.py. Fields
// 4/5/6/7/8/9/11/14/15 are skipped as unknown; they are never needed for
// per-inbound evidence.
func decodeServiceAPIConnection(payload []byte) (*serviceAPIConnection, error) {
	connection := &serviceAPIConnection{}
	err := decodeProtoMessage(payload, func(fieldNumber int, wireType int, varintValue uint64, bytesValue []byte) error {
		switch fieldNumber {
		case 1:
			value, err := protoBytesField(wireType, bytesValue)
			if err != nil {
				return err
			}
			connection.id = string(value)
			connection.hasID = true
		case 2:
			value, err := protoBytesField(wireType, bytesValue)
			if err != nil {
				return err
			}
			connection.inbound = string(value)
			connection.hasInbound = true
		case 3:
			value, err := protoBytesField(wireType, bytesValue)
			if err != nil {
				return err
			}
			connection.inboundType = string(value)
			connection.hasInboundType = true
		case 10:
			value, err := protoBytesField(wireType, bytesValue)
			if err != nil {
				return err
			}
			connection.user = string(value)
			connection.hasUser = true
		case 12:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			connection.createdAt = value
			connection.hasCreatedAt = true
		case 13:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			connection.closedAt = value
			connection.hasClosedAt = true
		case 16:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			connection.uplinkTotal = value
			connection.hasUplinkTotal = true
		case 17:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			connection.downlinkTotal = value
			connection.hasDownlinkTotal = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connection, nil
}

// decodeServiceAPIConnectionEvent decodes one ConnectionEvent.
func decodeServiceAPIConnectionEvent(payload []byte) (serviceAPIConnectionEvent, error) {
	event := serviceAPIConnectionEvent{}
	err := decodeProtoMessage(payload, func(fieldNumber int, wireType int, varintValue uint64, bytesValue []byte) error {
		switch fieldNumber {
		case 1:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			event.kind = int(value)
			event.hasKind = true
		case 2:
			value, err := protoBytesField(wireType, bytesValue)
			if err != nil {
				return err
			}
			event.id = string(value)
			event.hasID = true
		case 3:
			if wireType != protoWireBytes {
				return errServiceAPIProtoField
			}
			connection, err := decodeServiceAPIConnection(bytesValue)
			if err != nil {
				return err
			}
			event.connection = connection
		case 4:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			event.uplinkDelta = value
		case 5:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			event.downlinkDelta = value
		case 6:
			value, err := protoInt64Field(wireType, varintValue)
			if err != nil {
				return err
			}
			event.closedAt = value
			event.hasClosedAt = true
		}
		return nil
	})
	if err != nil {
		return serviceAPIConnectionEvent{}, err
	}
	return event, nil
}

// decodeServiceAPIConnectionEvents decodes one complete ConnectionEvents
// message. The event count is capped so a tiny-frame flood cannot turn into an
// unbounded decoded slice.
func decodeServiceAPIConnectionEvents(payload []byte) (serviceAPIConnectionBatch, error) {
	batch := serviceAPIConnectionBatch{}
	err := decodeProtoMessage(payload, func(fieldNumber int, wireType int, varintValue uint64, bytesValue []byte) error {
		switch fieldNumber {
		case 1:
			if wireType != protoWireBytes {
				return errServiceAPIProtoField
			}
			if len(batch.events) >= serviceAPIMaxEventsPerBatch {
				return errServiceAPIProtoTooManyEvents
			}
			event, err := decodeServiceAPIConnectionEvent(bytesValue)
			if err != nil {
				return err
			}
			batch.events = append(batch.events, event)
		case 2:
			if wireType != protoWireVarint {
				return errServiceAPIProtoField
			}
			batch.reset = varintValue != 0
		}
		return nil
	})
	if err != nil {
		return serviceAPIConnectionBatch{}, err
	}
	return batch, nil
}
