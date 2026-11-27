package linuxobs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file tests ServiceAPIProbe exclusively against synthetic httptest
// fixtures that speak hand-built gRPC-Web frames. No real sing-box, service.api
// socket, protoc or external dependency is involved. The fixtures encode the
// wire format documented in monitor-v2/api_bridge/proto_wire.py so the Go
// client is pinned to the same field numbers as the reference Python bridge.

// ---- synthetic protobuf / gRPC-Web encoding --------------------------------

func appendTestVarint(destination []byte, value uint64) []byte {
	for value >= 0x80 {
		destination = append(destination, byte(value)|0x80)
		value >>= 7
	}
	return append(destination, byte(value))
}

func appendTestTag(destination []byte, fieldNumber int, wireType int) []byte {
	return appendTestVarint(destination, uint64(fieldNumber)<<3|uint64(wireType))
}

func appendTestVarintField(destination []byte, fieldNumber int, value int64) []byte {
	destination = appendTestTag(destination, fieldNumber, protoWireVarint)
	return appendTestVarint(destination, uint64(value))
}

func appendTestBytesField(destination []byte, fieldNumber int, value []byte) []byte {
	destination = appendTestTag(destination, fieldNumber, protoWireBytes)
	destination = appendTestVarint(destination, uint64(len(value)))
	return append(destination, value...)
}

// testConnection is a synthetic proto Connection message. Presence flags are
// explicit because proto3 omits zero-valued scalars on the wire.
type testConnection struct {
	ID            string
	Inbound       string
	UplinkTotal   int64
	HasUplink     bool
	DownlinkTotal int64
	HasDownlink   bool
	ClosedAt      int64
	HasClosedAt   bool
}

func (connection testConnection) encode() []byte {
	var payload []byte
	if connection.ID != "" {
		payload = appendTestBytesField(payload, 1, []byte(connection.ID))
	}
	if connection.Inbound != "" {
		payload = appendTestBytesField(payload, 2, []byte(connection.Inbound))
	}
	if connection.HasClosedAt {
		payload = appendTestVarintField(payload, 13, connection.ClosedAt)
	}
	if connection.HasUplink {
		payload = appendTestVarintField(payload, 16, connection.UplinkTotal)
	}
	if connection.HasDownlink {
		payload = appendTestVarintField(payload, 17, connection.DownlinkTotal)
	}
	return payload
}

// testEvent is a synthetic proto ConnectionEvent message.
type testEvent struct {
	Kind          int
	HasKind       bool
	ID            string
	HasID         bool
	Connection    *testConnection
	UplinkDelta   int64
	DownlinkDelta int64
	ClosedAt      int64
	HasClosedAt   bool
}

func (event testEvent) encode() []byte {
	var payload []byte
	if event.HasKind {
		payload = appendTestVarintField(payload, 1, int64(event.Kind))
	}
	if event.HasID {
		payload = appendTestBytesField(payload, 2, []byte(event.ID))
	}
	if event.Connection != nil {
		payload = appendTestBytesField(payload, 3, event.Connection.encode())
	}
	if event.UplinkDelta != 0 {
		payload = appendTestVarintField(payload, 4, event.UplinkDelta)
	}
	if event.DownlinkDelta != 0 {
		payload = appendTestVarintField(payload, 5, event.DownlinkDelta)
	}
	if event.HasClosedAt {
		payload = appendTestVarintField(payload, 6, event.ClosedAt)
	}
	return payload
}

func testActiveEvent(id string, inbound string, uplinkTotal int64, downlinkTotal int64) testEvent {
	return testEvent{
		Kind: serviceAPIEventNew, HasKind: true, ID: id, HasID: true,
		Connection: &testConnection{
			ID: id, Inbound: inbound,
			UplinkTotal: uplinkTotal, HasUplink: true,
			DownlinkTotal: downlinkTotal, HasDownlink: true,
		},
	}
}

func testReplayedClosedEvent(id string, inbound string, uplinkTotal int64, downlinkTotal int64, closedAt int64) testEvent {
	event := testActiveEvent(id, inbound, uplinkTotal, downlinkTotal)
	event.Connection.ClosedAt = closedAt
	event.Connection.HasClosedAt = true
	return event
}

func testUpdateDeltasEvent(id string, uplinkDelta int64, downlinkDelta int64) testEvent {
	return testEvent{
		Kind: serviceAPIEventUpdate, HasKind: true, ID: id, HasID: true,
		UplinkDelta: uplinkDelta, DownlinkDelta: downlinkDelta,
	}
}

func testUpdateTotalsEvent(id string, inbound string, uplinkTotal int64, downlinkTotal int64) testEvent {
	return testEvent{
		Kind: serviceAPIEventUpdate, HasKind: true, ID: id, HasID: true,
		Connection: &testConnection{
			ID: id, Inbound: inbound,
			UplinkTotal: uplinkTotal, HasUplink: true,
			DownlinkTotal: downlinkTotal, HasDownlink: true,
		},
	}
}

func testClosedEvent(id string, connection *testConnection) testEvent {
	return testEvent{Kind: serviceAPIEventClosed, HasKind: true, ID: id, HasID: true, Connection: connection}
}

func testConnectionEventsPayload(reset bool, events ...testEvent) []byte {
	var payload []byte
	for _, event := range events {
		payload = appendTestBytesField(payload, 1, event.encode())
	}
	if reset {
		payload = appendTestVarintField(payload, 2, 1)
	}
	return payload
}

func testGRPCWebFrame(flags byte, payload []byte) []byte {
	frame := make([]byte, 5, 5+len(payload))
	frame[0] = flags
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	return append(frame, payload...)
}

func testResetFrame(events ...testEvent) []byte {
	return testGRPCWebFrame(serviceAPIGRPCWebDataFlag, testConnectionEventsPayload(true, events...))
}

func testDataFrame(events ...testEvent) []byte {
	return testGRPCWebFrame(serviceAPIGRPCWebDataFlag, testConnectionEventsPayload(false, events...))
}

func testTrailerFrame(status string) []byte {
	return testGRPCWebFrame(serviceAPIGRPCWebTrailerFlag, []byte("grpc-status: "+status+"\r\n"))
}

// ---- synthetic streaming HTTP fixture --------------------------------------

type serviceAPITestRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// serviceAPITestStream is the test-side handle of one in-flight subscription.
// The handler owns all ResponseWriter access; the test only hands it frames.
type serviceAPITestStream struct {
	writes   chan []byte
	stop     chan struct{}
	stopOnce sync.Once
}

// send hands one raw byte chunk to the fixture server (the handler writes and
// flushes it). Any frame fragmentation is preserved.
func (stream *serviceAPITestStream) send(t *testing.T, chunk []byte) {
	t.Helper()
	select {
	case stream.writes <- chunk:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out handing bytes to the fixture service.api server")
	}
}

// finish closes the response body (an abrupt stream end with no trailer frame).
func (stream *serviceAPITestStream) finish() {
	stream.stopOnce.Do(func() { close(stream.stop) })
}

// serviceAPITestServer is a synthetic service.api listener that streams frames
// handed to it by the test. It records every request verbatim.
type serviceAPITestServer struct {
	t          *testing.T
	httpServer *httptest.Server

	mu       sync.Mutex
	requests []serviceAPITestRequest
	streams  chan *serviceAPITestStream
}

func newServiceAPITestServer(t *testing.T) *serviceAPITestServer {
	t.Helper()
	server := &serviceAPITestServer{t: t, streams: make(chan *serviceAPITestStream, 8)}
	server.httpServer = httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(server.httpServer.Close)
	return server
}

func (server *serviceAPITestServer) handle(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	record := serviceAPITestRequest{
		Method: request.Method,
		Path:   request.URL.Path,
		Header: request.Header.Clone(),
		Body:   body,
	}
	server.mu.Lock()
	server.requests = append(server.requests, record)
	server.mu.Unlock()

	writer.Header().Set("Content-Type", serviceAPIContentType)
	writer.WriteHeader(http.StatusOK)
	flusher, _ := writer.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	stream := &serviceAPITestStream{writes: make(chan []byte, 16), stop: make(chan struct{})}
	select {
	case server.streams <- stream:
	case <-request.Context().Done():
		return
	}
	for {
		select {
		case chunk := <-stream.writes:
			if _, err := writer.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		case <-stream.stop:
			return
		case <-request.Context().Done():
			return
		}
	}
}

// nextStream waits for the next subscription request to reach the fixture and
// returns its frame sink.
func (server *serviceAPITestServer) nextStream(t *testing.T) *serviceAPITestStream {
	t.Helper()
	select {
	case stream := <-server.streams:
		return stream
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a service.api subscription request")
		return nil
	}
}

func (server *serviceAPITestServer) capturedRequests() []serviceAPITestRequest {
	server.mu.Lock()
	defer server.mu.Unlock()
	requests := make([]serviceAPITestRequest, len(server.requests))
	copy(requests, server.requests)
	return requests
}

func (server *serviceAPITestServer) lastRequest(t *testing.T) serviceAPITestRequest {
	t.Helper()
	requests := server.capturedRequests()
	if len(requests) == 0 {
		t.Fatal("fixture service.api server captured no request")
	}
	return requests[len(requests)-1]
}

// newServiceAPITestProbe builds a probe pointed at the fixture server and
// registers its cleanup before the server cleanup (LIFO: probe closes first).
func newServiceAPITestProbe(t *testing.T, server *serviceAPITestServer, config ServiceAPIConfig) *ServiceAPIProbe {
	t.Helper()
	config.URL = server.httpServer.URL
	probe, err := NewServiceAPIProbe(config)
	if err != nil {
		t.Fatalf("NewServiceAPIProbe: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe
}

func newServiceAPITestProbeAtURL(t *testing.T, rawURL string, config ServiceAPIConfig) *ServiceAPIProbe {
	t.Helper()
	config.URL = rawURL
	probe, err := NewServiceAPIProbe(config)
	if err != nil {
		t.Fatalf("NewServiceAPIProbe: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe
}

func observeServiceAPI(t *testing.T, probe *ServiceAPIProbe) ServiceAPIObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	observation, err := probe.ObserveServiceAPI(ctx)
	if err != nil {
		t.Fatalf("ObserveServiceAPI: %v", err)
	}
	return observation
}

func observeServiceAPIError(t *testing.T, probe *ServiceAPIProbe) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := probe.ObserveServiceAPI(ctx)
	return err
}

// serviceAPIObserveResult is one asynchronous ObserveServiceAPI outcome.
type serviceAPIObserveResult struct {
	observation ServiceAPIObservation
	err         error
}

// observeServiceAPIAsync starts one observation in the background. The probe
// subscribes lazily, so tests must start the observation before waiting for the
// fixture server to see the subscription request.
func observeServiceAPIAsync(probe *ServiceAPIProbe) <-chan serviceAPIObserveResult {
	results := make(chan serviceAPIObserveResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		observation, err := probe.ObserveServiceAPI(ctx)
		results <- serviceAPIObserveResult{observation: observation, err: err}
	}()
	return results
}

func awaitServiceAPIObservation(t *testing.T, results <-chan serviceAPIObserveResult) ServiceAPIObservation {
	t.Helper()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("ObserveServiceAPI: %v", result.err)
		}
		return result.observation
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ObserveServiceAPI")
		return ServiceAPIObservation{}
	}
}

func awaitServiceAPIError(t *testing.T, results <-chan serviceAPIObserveResult) error {
	t.Helper()
	select {
	case result := <-results:
		return result.err
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ObserveServiceAPI error")
		return nil
	}
}

// startServiceAPISubscription starts the first observation of a lazily
// subscribing probe and waits for its subscription to reach the fixture server.
func startServiceAPISubscription(t *testing.T, server *serviceAPITestServer, probe *ServiceAPIProbe) (*serviceAPITestStream, <-chan serviceAPIObserveResult) {
	t.Helper()
	results := observeServiceAPIAsync(probe)
	stream := server.nextStream(t)
	return stream, results
}

// requireServiceAPIUnavailable asserts the typed, non-secret unavailability
// contract shared with the frozen collector (ErrProbeUnavailable) and this
// probe's own sentinel.
func requireServiceAPIUnavailable(t *testing.T, err error) *ServiceAPIUnavailableError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a service.api unavailable error, got nil")
	}
	if !errors.Is(err, ErrServiceAPIUnavailable) {
		t.Fatalf("error %v does not match ErrServiceAPIUnavailable", err)
	}
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("error %v does not match ErrProbeUnavailable", err)
	}
	var typed *ServiceAPIUnavailableError
	if !errors.As(err, &typed) {
		t.Fatalf("error %v is not a *ServiceAPIUnavailableError", err)
	}
	return typed
}

func requireServiceAPIInbound(t *testing.T, observation ServiceAPIObservation, tag string) ServiceAPIInboundEvidence {
	t.Helper()
	evidence, ok := observation.Inbounds[tag]
	if !ok {
		t.Fatalf("observation has no inbound %q: %+v", tag, observation.Inbounds)
	}
	return evidence
}

func requireServiceAPIEvidence(t *testing.T, observation ServiceAPIObservation, tag string,
	activeConnections int64, uplinkBytes int64, downlinkBytes int64,
	uplinkTotal int64, downlinkTotal int64) {
	t.Helper()
	evidence := requireServiceAPIInbound(t, observation, tag)
	if !evidence.TotalsAvailable {
		t.Fatalf("inbound %q TotalsAvailable = false", tag)
	}
	if evidence.TotalsExact {
		t.Fatalf("inbound %q claims exact lifetime totals, which the service.api cannot provide", tag)
	}
	if evidence.ActiveConnections != activeConnections ||
		evidence.UplinkBytes != uplinkBytes || evidence.DownlinkBytes != downlinkBytes ||
		evidence.UplinkTotalBytes != uplinkTotal || evidence.DownlinkTotalBytes != downlinkTotal {
		t.Fatalf("inbound %q evidence = %+v, want active=%d active_bytes=%d/%d totals=%d/%d",
			tag, evidence, activeConnections, uplinkBytes, downlinkBytes, uplinkTotal, downlinkTotal)
	}
}

// waitForServiceAPIStreamEnd waits until the probe has recorded a terminal
// stream state (used before testing reconnect behaviour deterministically).
func waitForServiceAPIStreamEnd(t *testing.T, probe *ServiceAPIProbe) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe.mu.Lock()
		current := probe.state
		done := current != nil && current.done
		probe.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("service.api stream did not end")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ---- configuration / URL validation tests ----------------------------------

func TestNewServiceAPIProbeRejectsNonLoopbackURLs(t *testing.T) {
	invalid := []string{
		"",
		"127.0.0.1:9091",
		"localhost:9091",
		"http://localhost:9091",
		"http://localhost",
		"https://127.0.0.1:9091",
		"http://192.0.2.1:9091",
		"http://10.0.0.1:9091",
		"http://0.0.0.0:9091",
		"http://[2001:db8::1]:9091",
		"http://127.0.0.1:0",
		"http://127.0.0.1:65536",
		"http://127.0.0.1:notaport",
		"http://127.0.0.1:",
		"http://127.0.0.1:9091/",
		"http://127.0.0.1:9091/daemon.StartedService/SubscribeConnections",
		"http://127.0.0.1:9091?debug=1",
		"http://127.0.0.1:9091#fragment",
		"http://user:pass@127.0.0.1:9091",
		"http://127.0.0.1.evil.example:9091",
		"http://[::1%25lo]:9091",
		"ftp://127.0.0.1:9091",
		"http://",
	}
	for _, rawURL := range invalid {
		if _, err := NewServiceAPIProbe(ServiceAPIConfig{URL: rawURL}); err == nil {
			t.Errorf("NewServiceAPIProbe accepted %q", rawURL)
		}
	}

	valid := []struct {
		url  string
		host string
	}{
		{"http://127.0.0.1:9091", "127.0.0.1:9091"},
		{"http://127.0.0.2:1", "127.0.0.2:1"},
		{"http://127.0.0.1:65535", "127.0.0.1:65535"},
		{"http://[::1]:9091", "[::1]:9091"},
		{"http://[::1]", "[::1]:9091"},
		{"http://127.0.0.1", "127.0.0.1:9091"},
	}
	for _, testCase := range valid {
		probe, err := NewServiceAPIProbe(ServiceAPIConfig{URL: testCase.url})
		if err != nil {
			t.Errorf("NewServiceAPIProbe rejected %q: %v", testCase.url, err)
			continue
		}
		if probe.base.Host != testCase.host {
			t.Errorf("NewServiceAPIProbe(%q).base.Host = %q, want %q", testCase.url, probe.base.Host, testCase.host)
		}
		if probe.base.Scheme != "http" {
			t.Errorf("NewServiceAPIProbe(%q).base.Scheme = %q, want http", testCase.url, probe.base.Scheme)
		}
		_ = probe.Close()
	}
}

func TestNewServiceAPIProbeRejectsControlBytesInSecret(t *testing.T) {
	for _, secret := range []string{"line\nbreak", "carriage\rreturn", "nul\x00byte", "del\x7fbyte", "tab\tbyte"} {
		if _, err := NewServiceAPIProbe(ServiceAPIConfig{
			URL:    "http://127.0.0.1:9091",
			Secret: secret,
		}); err == nil {
			t.Errorf("NewServiceAPIProbe accepted a secret containing control bytes")
		}
	}
	probe, err := NewServiceAPIProbe(ServiceAPIConfig{
		URL:    "http://127.0.0.1:9091",
		Secret: "fixture-secret-not-for-output",
	})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe: %v", err)
	}
	_ = probe.Close()
}

func TestNewServiceAPIProbeDefaultsAndBounds(t *testing.T) {
	probe, err := NewServiceAPIProbe(ServiceAPIConfig{URL: "http://127.0.0.1"})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe: %v", err)
	}
	if probe.base.Host != "127.0.0.1:"+serviceAPIDefaultPort {
		t.Errorf("default-ported base = %q", probe.base.Host)
	}
	installed, err := NewServiceAPIProbe(ServiceAPIConfig{URL: DefaultServiceAPIURL})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe(DefaultServiceAPIURL): %v", err)
	}
	if installed.base.Host != "127.0.0.1:9091" {
		t.Errorf("DefaultServiceAPIURL base = %q, want 127.0.0.1:9091", installed.base.Host)
	}
	_ = installed.Close()
	if probe.interval != defaultServiceAPIInterval {
		t.Errorf("interval = %v, want %v", probe.interval, defaultServiceAPIInterval)
	}
	if probe.timeout != defaultServiceAPITimeout {
		t.Errorf("timeout = %v, want %v", probe.timeout, defaultServiceAPITimeout)
	}
	if probe.maxFrameBytes != defaultServiceAPIMaxFrameBytes {
		t.Errorf("maxFrameBytes = %d, want %d", probe.maxFrameBytes, defaultServiceAPIMaxFrameBytes)
	}
	if probe.drainWindow != serviceAPIDrainWindow {
		t.Errorf("drainWindow = %v, want %v", probe.drainWindow, serviceAPIDrainWindow)
	}
	if probe.client.CheckRedirect == nil {
		t.Error("redirect policy is not pinned")
	}
	_ = probe.Close()

	clamped, err := NewServiceAPIProbe(ServiceAPIConfig{
		URL:           "http://127.0.0.1",
		Timeout:       24 * time.Hour,
		MaxFrameBytes: maxServiceAPIMaxFrameBytes + 1024,
	})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe with huge bounds: %v", err)
	}
	if clamped.timeout != maxServiceAPITimeout {
		t.Errorf("clamped timeout = %v, want %v", clamped.timeout, maxServiceAPITimeout)
	}
	if clamped.maxFrameBytes != maxServiceAPIMaxFrameBytes {
		t.Errorf("clamped maxFrameBytes = %d, want %d", clamped.maxFrameBytes, maxServiceAPIMaxFrameBytes)
	}
	_ = clamped.Close()

	fallback, err := NewServiceAPIProbe(ServiceAPIConfig{
		URL:           "http://127.0.0.1",
		Interval:      -5 * time.Second,
		MaxFrameBytes: -1,
	})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe with negative optional bounds: %v", err)
	}
	if fallback.interval != defaultServiceAPIInterval {
		t.Errorf("negative interval did not fall back to the default: %v", fallback.interval)
	}
	if fallback.maxFrameBytes != defaultServiceAPIMaxFrameBytes {
		t.Errorf("negative maxFrameBytes did not fall back to the default: %d", fallback.maxFrameBytes)
	}
	_ = fallback.Close()
}

// ---- request shape / authentication tests ----------------------------------

func TestServiceAPIProbeRequestShapeAndInterval(t *testing.T) {
	server := newServiceAPITestServer(t)
	const secret = "fixture-service-api-secret"
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{
		Secret:   secret,
		Interval: 250 * time.Millisecond,
	})
	stream, results := startServiceAPISubscription(t, server, probe)
	request := server.lastRequest(t)

	if request.Method != http.MethodPost {
		t.Errorf("request method = %q, want POST", request.Method)
	}
	if request.Path != serviceAPISubscribePath {
		t.Errorf("request path = %q, want %q", request.Path, serviceAPISubscribePath)
	}
	if got := request.Header.Get("Content-Type"); got != serviceAPIContentType {
		t.Errorf("Content-Type = %q, want %q", got, serviceAPIContentType)
	}
	if got := request.Header.Get("X-Grpc-Web"); got != "1" {
		t.Errorf("X-Grpc-Web = %q, want 1", got)
	}
	if got := request.Header.Get("TE"); got != "trailers" {
		t.Errorf("TE = %q, want trailers", got)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+secret {
		t.Errorf("Authorization = %q, want the Bearer secret", got)
	}
	if len(request.Body) < 7 {
		t.Fatalf("request body too short for a gRPC frame: %x", request.Body)
	}
	if request.Body[0] != 0x00 {
		t.Errorf("request frame flags = 0x%02x, want 0x00", request.Body[0])
	}
	declared := binary.BigEndian.Uint32(request.Body[1:5])
	if int(declared) != len(request.Body)-5 {
		t.Fatalf("request frame length = %d, payload = %d", declared, len(request.Body)-5)
	}
	payload := request.Body[5:]
	if len(payload) < 2 || payload[0] != 0x08 {
		t.Fatalf("SubscribeConnectionsRequest payload = %x, want field 1 varint", payload)
	}
	interval, _, err := readProtoVarint(payload, 1)
	if err != nil {
		t.Fatalf("decode request interval: %v", err)
	}
	if interval != uint64(250*time.Millisecond) {
		t.Errorf("request interval_ns = %d, want %d", interval, 250*time.Millisecond)
	}

	stream.send(t, testResetFrame())
	observation := awaitServiceAPIObservation(t, results)
	if !observation.Connected {
		t.Error("observation Connected = false on a healthy stream")
	}
	if len(observation.Inbounds) != 0 {
		t.Errorf("empty reset produced inbound evidence: %+v", observation.Inbounds)
	}
	if rendered := fmt.Sprintf("%+v", observation); strings.Contains(rendered, secret) {
		t.Error("observation contains the service.api secret")
	}
}

func TestServiceAPIProbeWithoutSecretSendsNoAuthorization(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	request := server.lastRequest(t)
	if values, ok := request.Header["Authorization"]; ok {
		t.Fatalf("client sent an Authorization header without a configured secret: %v", values)
	}
	stream.send(t, testResetFrame())
	awaitServiceAPIObservation(t, results)
}

func TestServiceAPIProbeAuthFailure(t *testing.T) {
	const secret = "fixture-auth-failure-secret"
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("denied token=" + secret))
	}))
	defer server.Close()

	probe := newServiceAPITestProbeAtURL(t, server.URL, ServiceAPIConfig{Secret: secret, Timeout: time.Second})
	err := observeServiceAPIError(t, probe)
	requireServiceAPIUnavailable(t, err)
	if authorization != "Bearer "+secret {
		t.Errorf("Authorization = %q, want the Bearer secret", authorization)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("auth failure error leaked the API secret")
	}
	if strings.Contains(err.Error(), "denied token") {
		t.Fatal("auth failure error echoed the response body")
	}
}

// ---- accumulator semantics -------------------------------------------------

func TestServiceAPIProbeAccumulatesResetUpdateAndClosed(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	const closedAt = int64(1_700_000_000_000)

	// First subscription message: reset=true with all active connections plus
	// recently closed replay rows.
	stream.send(t, testResetFrame(
		testActiveEvent("conn-a", "vless-in", 100, 200),
		testReplayedClosedEvent("conn-b", "vless-in", 1000, 2000, closedAt),
		testActiveEvent("conn-c", "hy2-in", 50, 60),
	))
	observation := awaitServiceAPIObservation(t, results)
	if observation.Resets != 1 || observation.Batches != 1 {
		t.Fatalf("diagnostics = resets:%d batches:%d, want 1/1", observation.Resets, observation.Batches)
	}
	if observation.SkippedEvents != 0 || observation.IdentityConflicts != 0 {
		t.Fatalf("unexpected diagnostics: %+v", observation)
	}
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 100, 200, 1100, 2200)
	requireServiceAPIEvidence(t, observation, "hy2-in", 1, 50, 60, 50, 60)

	// UPDATE deltas accumulate onto the active lifecycle.
	stream.send(t, testDataFrame(
		testUpdateDeltasEvent("conn-a", 10, 20),
		testUpdateDeltasEvent("conn-c", 5, 7),
	))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 110, 220, 1110, 2220)
	requireServiceAPIEvidence(t, observation, "hy2-in", 1, 55, 67, 55, 67)

	// UPDATE WITH a Connection replaces authoritative totals instead of adding.
	stream.send(t, testDataFrame(testUpdateTotalsEvent("conn-a", "vless-in", 130, 260)))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 130, 260, 1130, 2260)

	// UPDATE(0,0) means "traffic stopped": no state change.
	stream.send(t, testDataFrame(testUpdateDeltasEvent("conn-a", 0, 0)))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 130, 260, 1130, 2260)

	// CLOSED carries the final authoritative totals including the traffic after
	// the last UPDATE ticker; it banks the lifecycle exactly once.
	stream.send(t, testDataFrame(testClosedEvent("conn-a", &testConnection{
		ID: "conn-a", Inbound: "vless-in",
		UplinkTotal: 150, HasUplink: true,
		DownlinkTotal: 300, HasDownlink: true,
		ClosedAt: closedAt, HasClosedAt: true,
	})))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 0, 0, 0, 1150, 2300)

	// A duplicated CLOSED / replayed lifecycle is never banked twice.
	stream.send(t, testDataFrame(testClosedEvent("conn-a", &testConnection{
		ID: "conn-a", Inbound: "vless-in",
		UplinkTotal: 150, HasUplink: true,
		DownlinkTotal: 300, HasDownlink: true,
		ClosedAt: closedAt, HasClosedAt: true,
	})))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 0, 0, 0, 1150, 2300)
	if observation.DuplicateEvents != 1 {
		t.Errorf("DuplicateEvents = %d, want 1", observation.DuplicateEvents)
	}

	// The frozen SingBoxProbe interface can only carry active lower bounds; the
	// true observed cumulative totals stay reachable through ObserveServiceAPI.
	singBoxObservation, err := probe.ObserveSingBox(context.Background())
	if err != nil {
		// No new batch is pending: a healthy idle stream returns immediately.
		t.Fatalf("ObserveSingBox: %v", err)
	}
	vless := singBoxObservation.Inbounds["vless-in"]
	if vless.ActiveConnections != 0 || vless.UplinkBytes != 0 || vless.DownlinkBytes != 0 {
		t.Fatalf("legacy evidence mapping = %+v, want active lower bounds only", vless)
	}
	hy2 := singBoxObservation.Inbounds["hy2-in"]
	if hy2.ActiveConnections != 1 || hy2.UplinkBytes != 55 || hy2.DownlinkBytes != 67 {
		t.Fatalf("legacy evidence mapping = %+v, want active lower bounds", hy2)
	}
}

func TestServiceAPIProbeResetReplayIsNeverDoubleCounted(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	const closedAt = int64(1_700_000_000_000)

	stream.send(t, testResetFrame(
		testActiveEvent("conn-a", "vless-in", 100, 200),
		testReplayedClosedEvent("conn-b", "vless-in", 300, 400, closedAt),
		testActiveEvent("conn-ghost", "hy2-in", 5, 6),
	))
	observation := awaitServiceAPIObservation(t, results)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 100, 200, 400, 600)

	// A second (re)subscription reset batch on the same stream: replay conn-b
	// (already banked, must not double count), refresh conn-a with authoritative
	// totals, add conn-d, and drop conn-ghost (ABANDONED lower bound, never
	// invented as closed).
	stream.send(t, testResetFrame(
		testReplayedClosedEvent("conn-b", "vless-in", 300, 400, closedAt),
		testActiveEvent("conn-a", "vless-in", 150, 250),
		testReplayedClosedEvent("conn-d", "vless-in", 10, 20, closedAt),
	))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 150, 250, 460, 670)
	requireServiceAPIEvidence(t, observation, "hy2-in", 0, 0, 0, 5, 6)
	if observation.Resets != 2 {
		t.Errorf("Resets = %d, want 2", observation.Resets)
	}
	if observation.DuplicateEvents != 1 {
		t.Errorf("DuplicateEvents = %d, want 1 (replayed conn-b)", observation.DuplicateEvents)
	}
	if observation.AbandonedOnReset != 1 {
		t.Errorf("AbandonedOnReset = %d, want 1 (conn-ghost)", observation.AbandonedOnReset)
	}
	if observation.IdentityConflicts != 0 || observation.SkippedEvents != 0 {
		t.Errorf("unexpected diagnostics: %+v", observation)
	}

	// The abandoned lifecycle later receives its authoritative CLOSED values:
	// the lower bound is replaced, never added twice.
	stream.send(t, testDataFrame(testClosedEvent("conn-ghost", &testConnection{
		ID: "conn-ghost", Inbound: "hy2-in",
		UplinkTotal: 7, HasUplink: true,
		DownlinkTotal: 8, HasDownlink: true,
		ClosedAt: closedAt, HasClosedAt: true,
	})))
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "hy2-in", 0, 0, 0, 7, 8)
}

func TestServiceAPIProbeSkipsUnknownAndMalformedEvents(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)

	stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
	awaitServiceAPIObservation(t, results)

	stream.send(t, testDataFrame(
		// UPDATE for an id never observed: skipped, never invented.
		testUpdateDeltasEvent("conn-unknown", 100, 100),
		// CLOSED for an id never observed: skipped, no invented traffic.
		testClosedEvent("conn-ghost", &testConnection{
			ID: "conn-ghost", Inbound: "vless-in",
			UplinkTotal: 999, HasUplink: true,
			DownlinkTotal: 999, HasDownlink: true,
		}),
		// Negative proto counters are malformed and must never decrease totals.
		testEvent{Kind: serviceAPIEventNew, HasKind: true, ID: "conn-neg", HasID: true,
			Connection: &testConnection{ID: "conn-neg", Inbound: "vless-in", UplinkTotal: -5, HasUplink: true}},
		// Unknown event type is skipped.
		testEvent{Kind: 7, HasKind: true, ID: "conn-a", HasID: true},
		// NEW without a Connection object cannot be attributed: skipped.
		testEvent{Kind: serviceAPIEventNew, HasKind: true, ID: "conn-bare", HasID: true},
	))
	observation := observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 10, 20, 10, 20)
	if observation.SkippedEvents != 5 {
		t.Errorf("SkippedEvents = %d, want 5", observation.SkippedEvents)
	}
}

func TestServiceAPIProbeIdentityConflictIsNeverMigrated(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)

	stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
	awaitServiceAPIObservation(t, results)

	// The same connection id claims another inbound tag: the traffic stays on
	// the original tag and the conflict is counted.
	stream.send(t, testDataFrame(
		testUpdateDeltasEvent("conn-a", 5, 5),
		testUpdateTotalsEvent("conn-a", "hy2-in", 500, 600),
	))
	observation := observeServiceAPI(t, probe)
	if observation.IdentityConflicts < 1 {
		t.Fatalf("IdentityConflicts = %d, want >= 1", observation.IdentityConflicts)
	}
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 15, 25, 15, 25)
	if _, ok := observation.Inbounds["hy2-in"]; ok {
		t.Fatal("identity conflict migrated traffic to another inbound tag")
	}
}

// ---- stream lifecycle / reconnect ------------------------------------------

func TestServiceAPIProbeReconnectsAndPreservesTotals(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{Timeout: 2 * time.Second})
	const closedAt = int64(1_700_000_000_000)

	firstStream, firstResults := startServiceAPISubscription(t, server, probe)
	firstStream.send(t, testResetFrame(
		testActiveEvent("conn-a", "vless-in", 100, 200),
		testReplayedClosedEvent("conn-b", "vless-in", 300, 400, closedAt),
	))
	observation := awaitServiceAPIObservation(t, firstResults)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 100, 200, 400, 600)

	// The server ends the subscription cleanly; the totals already banked must
	// survive the transparent re-subscription.
	firstStream.send(t, testTrailerFrame("0"))
	waitForServiceAPIStreamEnd(t, probe)

	reconnected := observeServiceAPIAsync(probe)
	secondStream := server.nextStream(t)
	secondStream.send(t, testResetFrame(
		testReplayedClosedEvent("conn-b", "vless-in", 300, 400, closedAt),
		testActiveEvent("conn-a", "vless-in", 150, 250),
		testReplayedClosedEvent("conn-d", "vless-in", 10, 20, closedAt),
	))
	reconnectedObservation := awaitServiceAPIObservation(t, reconnected)
	requireServiceAPIEvidence(t, reconnectedObservation, "vless-in", 1, 150, 250, 460, 670)
	if reconnectedObservation.Resets != 2 {
		t.Errorf("Resets = %d, want 2 across reconnects", reconnectedObservation.Resets)
	}
	if reconnectedObservation.DuplicateEvents != 1 {
		t.Errorf("DuplicateEvents = %d, want 1 (replayed conn-b)", reconnectedObservation.DuplicateEvents)
	}
	if len(server.capturedRequests()) != 2 {
		t.Errorf("subscription requests = %d, want 2", len(server.capturedRequests()))
	}
}

func TestServiceAPIProbeTrailerAndStreamEnd(t *testing.T) {
	t.Run("clean trailer ends the subscription and forces a re-subscribe", func(t *testing.T) {
		server := newServiceAPITestServer(t)
		probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{Timeout: 150 * time.Millisecond})
		stream, results := startServiceAPISubscription(t, server, probe)
		stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
		awaitServiceAPIObservation(t, results)

		stream.send(t, testTrailerFrame("0"))
		waitForServiceAPIStreamEnd(t, probe)
		probe.mu.Lock()
		terminal := probe.state.err
		probe.mu.Unlock()
		typed := requireServiceAPIUnavailable(t, terminal)
		if !strings.Contains(typed.Detail, "ended") {
			t.Errorf("terminal detail = %q, want a clean end classification", typed.Detail)
		}

		// The next observation transparently re-subscribes; the fixture sends no
		// reset on the new subscription, so the wait times out honestly.
		err := observeServiceAPIError(t, probe)
		requireServiceAPIUnavailable(t, err)
		if requests := len(server.capturedRequests()); requests != 2 {
			t.Errorf("subscription requests = %d, want 2", requests)
		}
	})

	t.Run("non-zero grpc-status is unavailable and never echoed", func(t *testing.T) {
		server := newServiceAPITestServer(t)
		probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
		stream, results := startServiceAPISubscription(t, server, probe)
		stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
		awaitServiceAPIObservation(t, results)

		stream.send(t, testGRPCWebFrame(serviceAPIGRPCWebTrailerFlag,
			[]byte("grpc-status: 13\r\ngrpc-message: fixture-server-error-secret\r\n")))
		waitForServiceAPIStreamEnd(t, probe)
		probe.mu.Lock()
		terminal := probe.state.err
		probe.mu.Unlock()
		typed := requireServiceAPIUnavailable(t, terminal)
		if !strings.Contains(typed.Detail, "non-zero gRPC status") {
			t.Errorf("terminal detail = %q, want a non-zero gRPC status classification", typed.Detail)
		}
		if strings.Contains(typed.Error(), "fixture-server-error-secret") {
			t.Fatal("terminal error echoed the trailer payload")
		}
	})

	t.Run("abrupt EOF is unavailable", func(t *testing.T) {
		server := newServiceAPITestServer(t)
		probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
		stream, results := startServiceAPISubscription(t, server, probe)
		stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
		awaitServiceAPIObservation(t, results)

		stream.finish()
		waitForServiceAPIStreamEnd(t, probe)
		probe.mu.Lock()
		terminal := probe.state.err
		probe.mu.Unlock()
		requireServiceAPIUnavailable(t, terminal)
	})
}

// ---- malformed wire / HTTP failure tests -----------------------------------

func TestServiceAPIProbeRejectsMalformedFrames(t *testing.T) {
	cases := []struct {
		name   string
		config ServiceAPIConfig
		chunk  []byte
	}{
		{
			name:  "malformed protobuf payload",
			chunk: testGRPCWebFrame(serviceAPIGRPCWebDataFlag, []byte{0x0a, 0x05, 0x01}),
		},
		{
			name:  "unsupported protobuf wire type",
			chunk: testGRPCWebFrame(serviceAPIGRPCWebDataFlag, []byte{0x08, 0x01, 0x0b, 0x00}),
		},
		{
			name:  "unknown frame flags",
			chunk: testGRPCWebFrame(0x40, nil),
		},
		{
			name:  "subscription without reset baseline",
			chunk: testDataFrame(testUpdateDeltasEvent("conn-a", 1, 1)),
		},
		{
			name:   "frame exceeds the configured frame cap",
			config: ServiceAPIConfig{MaxFrameBytes: 8},
			chunk:  []byte{0x00, 0x00, 0x00, 0x00, 0x09},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newServiceAPITestServer(t)
			probe := newServiceAPITestProbe(t, server, testCase.config)
			stream, results := startServiceAPISubscription(t, server, probe)
			stream.send(t, testCase.chunk)
			err := awaitServiceAPIError(t, results)
			requireServiceAPIUnavailable(t, err)
			waitForServiceAPIStreamEnd(t, probe)
		})
	}
}

func TestServiceAPIProbeRejectsNon200(t *testing.T) {
	const secret = "fixture-non-200-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte("upstream said " + secret))
	}))
	defer server.Close()

	probe := newServiceAPITestProbeAtURL(t, server.URL, ServiceAPIConfig{Secret: secret, Timeout: time.Second})
	err := observeServiceAPIError(t, probe)
	typed := requireServiceAPIUnavailable(t, err)
	if !strings.Contains(typed.Detail, "unexpected response status 503") {
		t.Errorf("detail = %q, want HTTP 503 classification", typed.Detail)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("non-200 error leaked the API secret")
	}
}

func TestServiceAPIProbeNeverFollowsRedirects(t *testing.T) {
	var destinationHits int32
	var destinationMu sync.Mutex
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationMu.Lock()
		destinationHits++
		destinationMu.Unlock()
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+serviceAPISubscribePath, http.StatusFound)
	}))
	defer redirector.Close()

	probe := newServiceAPITestProbeAtURL(t, redirector.URL, ServiceAPIConfig{Timeout: time.Second})
	err := observeServiceAPIError(t, probe)
	requireServiceAPIUnavailable(t, err)
	destinationMu.Lock()
	hits := destinationHits
	destinationMu.Unlock()
	if hits != 0 {
		t.Fatalf("client followed a redirect (%d destination hits)", hits)
	}
}

func TestServiceAPIProbeRejectsSlowHeaderResponse(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-release
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(release)

	probe := newServiceAPITestProbeAtURL(t, server.URL, ServiceAPIConfig{Timeout: 100 * time.Millisecond})
	started := time.Now()
	err := observeServiceAPIError(t, probe)
	requireServiceAPIUnavailable(t, err)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("slow header response took %v despite a 100ms timeout", elapsed)
	}
}

// ---- idle behaviour / fragmentation / secret hygiene ----------------------

func TestServiceAPIProbeIdleSubscriptionTimesOut(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{Timeout: 150 * time.Millisecond})
	started := time.Now()
	// Headers arrive; the fixture intentionally sends no reset batch.
	_, results := startServiceAPISubscription(t, server, probe)

	err := awaitServiceAPIError(t, results)
	requireServiceAPIUnavailable(t, err)
	elapsed := time.Since(started)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("idle observation returned after %v, before its 150ms wait", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("idle observation hung for %v", elapsed)
	}
	if !strings.Contains(err.Error(), "no reset batch") {
		t.Errorf("idle timeout error = %v, want a reset-batch timeout classification", err)
	}
}

func TestServiceAPIProbeHealthyIdleStreamReturnsSnapshot(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 10, 20)))
	awaitServiceAPIObservation(t, results)

	// No new events: the healthy stream must not hang, and the last known
	// snapshot is returned.
	started := time.Now()
	observation := observeServiceAPI(t, probe)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("idle observation hung for %v", elapsed)
	}
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 10, 20, 10, 20)
}

func TestServiceAPIProbeHandlesChunkedFrames(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)

	reset := testResetFrame(testActiveEvent("conn-a", "vless-in", 100, 200))
	// Fragment the 5-byte frame header, the payload, and the following frame
	// across arbitrary transport chunks (chunked transfer encoding boundaries).
	stream.send(t, reset[:2])
	stream.send(t, reset[2:5])
	stream.send(t, reset[5:9])
	stream.send(t, reset[9:])
	observation := awaitServiceAPIObservation(t, results)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 100, 200, 100, 200)

	update := testDataFrame(testUpdateDeltasEvent("conn-a", 10, 20))
	stream.send(t, update[:3])
	stream.send(t, update[3:])
	observation = observeServiceAPI(t, probe)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 110, 220, 110, 220)
}

func TestServiceAPIProbeNeverLeaksSecretInErrorsOrObservations(t *testing.T) {
	const secret = "fixture-never-leak-secret"
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{Secret: secret})
	stream, results := startServiceAPISubscription(t, server, probe)

	// A malformed data frame whose payload bytes contain the configured secret:
	// the decoder error must be a fixed classification, never echo payload bytes.
	malformed := append([]byte(secret), 0x0a, 0x7f)
	stream.send(t, testGRPCWebFrame(serviceAPIGRPCWebDataFlag, malformed))
	err := awaitServiceAPIError(t, results)
	requireServiceAPIUnavailable(t, err)
	if strings.Contains(err.Error(), secret) {
		t.Fatal("malformed-frame error leaked the configured secret")
	}

	// The captured subscription request body carries no secret at all.
	request := server.lastRequest(t)
	if strings.Contains(string(request.Body), secret) {
		t.Fatal("subscription request body contains the configured secret")
	}
	if strings.Contains(request.Path, secret) {
		t.Fatal("subscription request path contains the configured secret")
	}
}

func TestServiceAPIProbeObserveSingBoxCannotCarryTotals(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	const closedAt = int64(1_700_000_000_000)
	stream.send(t, testResetFrame(
		testActiveEvent("conn-a", "vless-in", 100, 200),
		testReplayedClosedEvent("conn-b", "vless-in", 1000, 2000, closedAt),
	))

	// ObserveSingBox is the frozen interface: it must expose only the active
	// lower bounds and never claim active bytes are lifetime totals. The richer
	// totals are available through ObserveServiceAPI.
	observation := awaitServiceAPIObservation(t, results)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 100, 200, 1100, 2200)

	singBoxObservation, err := probe.ObserveSingBox(context.Background())
	if err != nil {
		t.Fatalf("ObserveSingBox: %v", err)
	}
	evidence := singBoxObservation.Inbounds["vless-in"]
	if evidence != (InboundEvidence{ActiveConnections: 1, UplinkBytes: 100, DownlinkBytes: 200}) {
		t.Fatalf("legacy InboundEvidence = %+v, want active lower bounds only", evidence)
	}
}

func TestServiceAPIProbeContextCancellation(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := probe.ObserveServiceAPI(ctx)
		errc <- err
	}()
	_ = server.nextStream(t) // the subscription opened; no frames arrive
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled observation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled observation did not return promptly")
	}
}

func TestServiceAPIProbeCloseUnblocksObserver(t *testing.T) {
	server := newServiceAPITestServer(t)
	probe, err := NewServiceAPIProbe(ServiceAPIConfig{URL: server.httpServer.URL})
	if err != nil {
		t.Fatalf("NewServiceAPIProbe: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	results := observeServiceAPIAsync(probe)
	_ = server.nextStream(t)
	time.Sleep(20 * time.Millisecond)
	_ = probe.Close()
	err = awaitServiceAPIError(t, results)
	requireServiceAPIUnavailable(t, err)
}

func TestServiceAPIProbeIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:3128")
	t.Setenv("ALL_PROXY", "http://192.0.2.1:3128")
	t.Setenv("NO_PROXY", "")
	server := newServiceAPITestServer(t)
	probe := newServiceAPITestProbe(t, server, ServiceAPIConfig{})
	stream, results := startServiceAPISubscription(t, server, probe)
	stream.send(t, testResetFrame(testActiveEvent("conn-a", "vless-in", 1, 2)))
	observation := awaitServiceAPIObservation(t, results)
	requireServiceAPIEvidence(t, observation, "vless-in", 1, 1, 2, 1, 2)
}

// ---- wire codec pinning tests ----------------------------------------------

// TestServiceAPIWireDecodeConnectionFields pins the exact proto field numbers of
// the modeled Connection message (including the fields the accumulator does not
// consume) and proves unknown fields of every wire type are skipped.
func TestServiceAPIWireDecodeConnectionFields(t *testing.T) {
	var payload []byte
	payload = appendTestBytesField(payload, 1, []byte("conn-1"))
	payload = appendTestBytesField(payload, 2, []byte("vless-in"))
	payload = appendTestBytesField(payload, 3, []byte("vless"))
	payload = appendTestBytesField(payload, 10, []byte("fixture-user"))
	payload = appendTestVarintField(payload, 12, 1_700_000_000_000)
	payload = appendTestVarintField(payload, 13, 1_700_000_001_000)
	payload = appendTestVarintField(payload, 16, 123456)
	payload = appendTestVarintField(payload, 17, 654321)
	// Unknown fields of every supported wire type must be skipped.
	payload = appendTestVarintField(payload, 20, 42)
	payload = appendTestBytesField(payload, 21, []byte("unknown"))
	payload = appendTestTag(payload, 22, protoWireFixed64)
	payload = append(payload, make([]byte, 8)...)
	payload = appendTestTag(payload, 23, protoWireFixed32)
	payload = append(payload, make([]byte, 4)...)

	connection, err := decodeServiceAPIConnection(payload)
	if err != nil {
		t.Fatalf("decodeServiceAPIConnection: %v", err)
	}
	if connection.id != "conn-1" || !connection.hasID {
		t.Errorf("id = %q present=%v", connection.id, connection.hasID)
	}
	if connection.inbound != "vless-in" || !connection.hasInbound {
		t.Errorf("inbound = %q present=%v", connection.inbound, connection.hasInbound)
	}
	if connection.inboundType != "vless" || !connection.hasInboundType {
		t.Errorf("inboundType = %q present=%v", connection.inboundType, connection.hasInboundType)
	}
	if connection.user != "fixture-user" || !connection.hasUser {
		t.Errorf("user = %q present=%v", connection.user, connection.hasUser)
	}
	if connection.createdAt != 1_700_000_000_000 || !connection.hasCreatedAt {
		t.Errorf("createdAt = %d present=%v", connection.createdAt, connection.hasCreatedAt)
	}
	if connection.closedAt != 1_700_000_001_000 || !connection.hasClosedAt {
		t.Errorf("closedAt = %d present=%v", connection.closedAt, connection.hasClosedAt)
	}
	if connection.uplinkTotal != 123456 || !connection.hasUplinkTotal {
		t.Errorf("uplinkTotal = %d present=%v", connection.uplinkTotal, connection.hasUplinkTotal)
	}
	if connection.downlinkTotal != 654321 || !connection.hasDownlinkTotal {
		t.Errorf("downlinkTotal = %d present=%v", connection.downlinkTotal, connection.hasDownlinkTotal)
	}
}

// TestServiceAPIWireDecodeEventAndBatch pins the ConnectionEvent and
// ConnectionEvents field numbers.
func TestServiceAPIWireDecodeEventAndBatch(t *testing.T) {
	connection := testConnection{
		ID: "conn-1", Inbound: "vless-in",
		UplinkTotal: 11, HasUplink: true,
		DownlinkTotal: 22, HasDownlink: true,
	}.encode()
	var eventPayload []byte
	eventPayload = appendTestVarintField(eventPayload, 1, serviceAPIEventClosed)
	eventPayload = appendTestBytesField(eventPayload, 2, []byte("conn-1"))
	eventPayload = appendTestBytesField(eventPayload, 3, connection)
	eventPayload = appendTestVarintField(eventPayload, 4, 3)
	eventPayload = appendTestVarintField(eventPayload, 5, 4)
	eventPayload = appendTestVarintField(eventPayload, 6, 1_700_000_000_000)
	eventPayload = appendTestBytesField(eventPayload, 30, []byte("unknown"))

	event, err := decodeServiceAPIConnectionEvent(eventPayload)
	if err != nil {
		t.Fatalf("decodeServiceAPIConnectionEvent: %v", err)
	}
	if !event.hasKind || event.kind != serviceAPIEventClosed {
		t.Errorf("kind = %d present=%v, want CLOSED", event.kind, event.hasKind)
	}
	if event.id != "conn-1" || !event.hasID {
		t.Errorf("id = %q present=%v", event.id, event.hasID)
	}
	if event.uplinkDelta != 3 || event.downlinkDelta != 4 {
		t.Errorf("deltas = %d/%d, want 3/4", event.uplinkDelta, event.downlinkDelta)
	}
	if event.closedAt != 1_700_000_000_000 || !event.hasClosedAt {
		t.Errorf("closedAt = %d present=%v", event.closedAt, event.hasClosedAt)
	}
	if event.connection == nil || event.connection.id != "conn-1" ||
		event.connection.uplinkTotal != 11 || event.connection.downlinkTotal != 22 {
		t.Fatalf("connection = %+v, want the modeled totals", event.connection)
	}

	var batchPayload []byte
	batchPayload = appendTestBytesField(batchPayload, 1, eventPayload)
	batchPayload = appendTestBytesField(batchPayload, 1, eventPayload)
	batchPayload = appendTestVarintField(batchPayload, 2, 1)
	batch, err := decodeServiceAPIConnectionEvents(batchPayload)
	if err != nil {
		t.Fatalf("decodeServiceAPIConnectionEvents: %v", err)
	}
	if !batch.reset {
		t.Error("batch reset = false, want true")
	}
	if len(batch.events) != 2 {
		t.Fatalf("batch events = %d, want 2", len(batch.events))
	}
}

// TestServiceAPIWireRejectsMalformedBytes covers the decoder's structural
// failures without ever echoing payload content.
func TestServiceAPIWireRejectsMalformedBytes(t *testing.T) {
	cases := map[string][]byte{
		"truncated tag":               {0x80},
		"truncated varint":            {0x08, 0x80},
		"varint too long":             {0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
		"length overruns payload":     {0x0a, 0x05, 0x01},
		"unsupported group wire type": {0x0b},
		"truncated fixed64":           {0x09, 0x01},
		"truncated fixed32":           {0x0d, 0x01},
		"zero field number":           {0x00},
	}
	for name, payload := range cases {
		_, err := decodeServiceAPIConnectionEvents(payload)
		if err == nil {
			t.Errorf("%s: malformed protobuf payload was accepted", name)
		}
	}
	// A known field encoded with the wrong wire type is rejected, not guessed.
	// Field 2 (reset bytes=1) is a varint; this encodes it length-delimited.
	if _, err := decodeServiceAPIConnectionEvents([]byte{0x12, 0x00}); err == nil {
		t.Error("wrong wire type for the reset field was accepted")
	}
}

// TestServiceAPIWireTrailerStatus pins the gRPC-Web trailer parsing behaviour.
func TestServiceAPIWireTrailerStatus(t *testing.T) {
	cases := []struct {
		payload string
		status  string
	}{
		{"grpc-status: 0\r\n", "0"},
		{"grpc-status:0\n", "0"},
		{"Grpc-Status: 13\r\n", "13"},
		{"grpc-message: hi\r\n", ""},
		{"", ""},
		{"junk-without-colon\r\ngrpc-status: 7\r\n", "7"},
	}
	for _, testCase := range cases {
		if got := serviceAPIGRPCWebTrailerStatus([]byte(testCase.payload)); got != testCase.status {
			t.Errorf("serviceAPIGRPCWebTrailerStatus(%q) = %q, want %q", testCase.payload, got, testCase.status)
		}
	}
}

// TestServiceAPIWireEncodeSubscribeRequest pins the gRPC request envelope.
func TestServiceAPIWireEncodeSubscribeRequest(t *testing.T) {
	frame := encodeServiceAPISubscribeConnectionsRequest(2 * time.Second)
	if len(frame) < 7 {
		t.Fatalf("encoded request too short: %x", frame)
	}
	if frame[0] != 0x00 {
		t.Errorf("frame flags = 0x%02x, want 0x00", frame[0])
	}
	if declared := binary.BigEndian.Uint32(frame[1:5]); int(declared) != len(frame)-5 {
		t.Errorf("declared payload length = %d, actual = %d", declared, len(frame)-5)
	}
	payload := frame[5:]
	if len(payload) < 2 || payload[0] != 0x08 {
		t.Fatalf("payload = %x, want field 1 varint", payload)
	}
	interval, end, err := readProtoVarint(payload, 1)
	if err != nil {
		t.Fatalf("read request interval: %v", err)
	}
	if end != len(payload) {
		t.Errorf("request payload has %d trailing bytes", len(payload)-end)
	}
	if interval != uint64(2*time.Second) {
		t.Errorf("interval_ns = %d, want %d", interval, 2*time.Second)
	}
}
