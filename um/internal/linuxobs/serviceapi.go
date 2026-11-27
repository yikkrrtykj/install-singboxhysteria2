package linuxobs

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// This file implements a bounded, read-only client/accumulator for the official
// sing-box 1.14 service.api connection event stream, as an alternative to the
// legacy Clash-compatible ClashClient in singbox.go.
//
// Wire contract (verified against the v1.14.0 souce, daemon/started_service.go,
// and mirroring monitor-v2/api_bridge + monitor-v2/collector.py; do NOT guess):
//
//   - the service is a gRPC server that also accepts gRPC-Web on the same
//     loopback listener; the call is POST
//     /daemon.StartedService/SubscribeConnections with
//     Content-Type: application/grpc-web+proto;
//   - both directions use standard gRPC length-prefixed frames
//     (1 byte flags + 4 bytes big-endian length + payload);
//   - the FIRST message of every subscription carries reset=true and contains
//     NEW events for ALL active connections plus NEW events (with closedAt set)
//     for recently closed ones;
//   - UPDATE events carry only id + uplinkDelta + downlinkDelta (no Connection):
//     UPDATE(0,0) means "traffic stopped"; UPDATE WITH a Connection REPLACES the
//     authoritative totals;
//   - CLOSED events carry id + closedAt, normally with the final Connection
//     whose uplinkTotal/downlinkTotal include the traffic after the last UPDATE
//     ticker; closure must only ever be banked once;
//   - an idle-but-healthy stream can stay silent for a long time: the official
//     server skips empty ticker batches, so silence is health, not staleness.
//
// What this probe can and cannot prove (documented rather than fabricated):
//
//   - per-connection uplinkTotal/downlinkTotal are authoritative lifecycle
//     accumulators reported by the daemon;
//   - the daemon exposes NO per-inbound daemon-lifetime counter, so the
//     per-inbound totals produced here are probe-observed cumulative lower
//     bounds since this probe started (active authoritative totals plus
//     finalized closed/abandoned lifecycle totals banked exactly once). They
//     never claim to be daemon-lifetime totals;
//   - across a stream reconnect the reset batch is replayed; the banked-id
//     guard (independent of any display cache) makes sure a replayed lifecycle
//     is never banked twice, and an active connection missing from a reset is
//     banked as ABANDONED (lower bound), never invented as closed;
//   - CLOSED/UPDATE events for ids this probe never observed are skipped and
//     counted (SkippedEvents), never guessed.
//
// The legacy linuxobs.SingBoxProbe interface can only carry active-connection
// lower bounds (InboundEvidence.UplinkBytes/DownlinkBytes are documented as the
// counters of currently active connections, not lifetime totals). The richer
// ServiceAPIObservation therefore exists alongside it: ObserveSingBox maps the
// active lower bounds for interface compatibility, and callers that need true
// observed cumulative totals must use ObserveServiceAPI.
//
// Safety posture: literal loopback HTTP origin only, no redirects, no proxy
// environment, bounded response headers/frames/events, per-call timeout and a
// short observation idle window. The secret is held in memory only and never
// appears in an error, observation or log line.

const (
	// serviceAPISubscribePath is the only request path this client can emit.
	serviceAPISubscribePath = "/daemon.StartedService/SubscribeConnections"
	// serviceAPIContentType is the gRPC-Web content type the official bridge
	// accepts on the plain HTTP service.api listener.
	serviceAPIContentType = "application/grpc-web+proto"
	// serviceAPIDefaultPort is the install.sh services[].listen_port default.
	serviceAPIDefaultPort = "9091"

	// Timeouts and bounds. The stream itself is long-lived; Timeout bounds one
	// connect/header phase and one observation's first-reset wait.
	defaultServiceAPIInterval      = 2 * time.Second
	defaultServiceAPITimeout       = 5 * time.Second
	maxServiceAPITimeout           = 60 * time.Second
	defaultServiceAPIMaxFrameBytes = 4 << 20
	maxServiceAPIMaxFrameBytes     = 64 << 20
	// serviceAPIMaxResponseHeaderBytes bounds the HTTP response header block.
	serviceAPIMaxResponseHeaderBytes = int64(64 << 10)
	// serviceAPIReadChunk is the streaming read size; frame assembly buffers
	// independently, so arbitrary transport chunking is tolerated.
	serviceAPIReadChunk = 32 << 10
	// serviceAPIDrainWindow is how long one observation waits for the next
	// batch once a baseline exists. An idle-but-healthy stream legitimately
	// stays silent; this window keeps Observe calls non-blocking-ish while
	// still deterministically collecting batches that are already in flight.
	serviceAPIDrainWindow = 100 * time.Millisecond
	// serviceAPIMaxEventsPerBatch and serviceAPIMaxBankedIDs bound decoded and
	// retained per-connection state.
	serviceAPIMaxEventsPerBatch = 1 << 16
	serviceAPIMaxBankedIDs      = 4096
	// serviceAPIMaxConnectionIDBytes bounds the connection-id strings retained
	// in memory. Official ids are UUIDs; anything longer is malformed.
	serviceAPIMaxConnectionIDBytes = 128
	// serviceAPIMaxInboundTagBytes mirrors the frozen inbound_tag length bound.
	serviceAPIMaxInboundTagBytes = 64
	// serviceAPICloseWait bounds how long Close waits for the reader goroutine.
	serviceAPICloseWait = 5 * time.Second
)

// ErrServiceAPIUnavailable is the typed unavailability sentinel of the
// service.api probe. Errors returned by ObserveServiceAPI/ObserveSingBox match
// both this sentinel and ErrProbeUnavailable, so existing collector code that
// checks errors.Is(err, ErrProbeUnavailable) keeps rendering the source
// unavailable with no special casing.
var ErrServiceAPIUnavailable = errors.New("linuxobs: sing-box service.api unavailable")

// DefaultServiceAPIURL is the loopback service.api origin installed by
// install.sh (services[] entry with tag "monitor-api", listen 127.0.0.1,
// listen_port 9091).
const DefaultServiceAPIURL = "http://127.0.0.1:9091"

// ServiceAPIUnavailableError is the typed error returned when the service.api
// event stream cannot produce an honest observation. Detail is always a fixed,
// non-secret classification string; raw HTTP/protobuf payloads, the configured
// secret and peer metadata are never included.
type ServiceAPIUnavailableError struct {
	Detail string
}

// Error implements error.
func (err *ServiceAPIUnavailableError) Error() string {
	if err.Detail == "" {
		return ErrServiceAPIUnavailable.Error()
	}
	return ErrServiceAPIUnavailable.Error() + ": " + err.Detail
}

// Unwrap makes the error match both exported unavailability sentinels.
func (err *ServiceAPIUnavailableError) Unwrap() []error {
	return []error{ErrServiceAPIUnavailable, ErrProbeUnavailable}
}

// serviceAPIUnavailable builds one typed unavailability error.
func serviceAPIUnavailable(detail string) error {
	return &ServiceAPIUnavailableError{Detail: detail}
}

// ServiceAPIConfig configures the bounded read-only service.api client.
type ServiceAPIConfig struct {
	// URL is the literal loopback HTTP origin of the local service.api, e.g.
	// "http://127.0.0.1:9091". Hostnames (including "localhost"), HTTPS,
	// non-loopback addresses, userinfo, paths, queries and fragments are
	// rejected. The port is optional and defaults to 9091 (the install.sh
	// services[].listen_port default).
	URL string
	// Secret is the optional service.api transport credential sent as
	// "Authorization: Bearer <secret>". It is remembered only in memory and is
	// never logged, never placed in an observation and never returned in an
	// error.
	Secret string
	// Interval paces the daemon UPDATE ticker (SubscribeConnectionsRequest
	// interval in nanoseconds). It defaults to 2s and is floored at 1ns.
	Interval time.Duration
	// Timeout bounds one connect/response-header phase and one observation's
	// wait for the subscription reset batch. It defaults to 5s and is clamped
	// to at most 60s.
	Timeout time.Duration
	// MaxFrameBytes caps one gRPC-Web response frame payload. It defaults to
	// 4 MiB and is clamped to at most 64 MiB.
	MaxFrameBytes int
}

// ServiceAPIInboundEvidence is the accumulated evidence for one inbound tag.
type ServiceAPIInboundEvidence struct {
	// ActiveConnections is the number of connections currently active for the
	// tag.
	ActiveConnections int64
	// UplinkBytes and DownlinkBytes are the cumulative byte counters of those
	// currently ACTIVE connections only. They are a lower bound, not a
	// per-inbound lifetime total (the legacy InboundEvidence has exactly this
	// meaning).
	UplinkBytes   int64
	DownlinkBytes int64
	// UplinkTotalBytes and DownlinkTotalBytes are the probe-observed cumulative
	// totals: active authoritative counters plus finalized closed/abandoned
	// lifecycle totals banked exactly once. They are a monotonic lower bound on
	// the unknown daemon-lifetime counters, never an invented exact value.
	UplinkTotalBytes   int64
	DownlinkTotalBytes int64
	// TotalsAvailable reports whether UplinkTotalBytes/DownlinkTotalBytes are
	// meaningful. It is true for every inbound in a successful observation (a
	// reset baseline is always applied before an observation is returned) and
	// false only on zero-value evidence.
	TotalsAvailable bool
	// TotalsExact is ALWAYS false: the service.api exposes no per-inbound
	// daemon-lifetime counter, so UplinkTotalBytes/DownlinkTotalBytes are
	// probe-observed cumulative lower bounds (from probe start), never a
	// provable lifetime total. The field exists so callers cannot mistake them
	// for exact lifetime numbers without reading prose.
	TotalsExact bool
}

// ServiceAPIObservation is one honest observation of the service.api event
// stream accumulator.
type ServiceAPIObservation struct {
	// Inbounds is keyed by the inbound tag observed in stream events. No
	// connection id, user, address, domain or rule is ever retained here.
	Inbounds map[string]ServiceAPIInboundEvidence
	// Connected reports that the stream backing this observation was healthy at
	// snapshot time.
	Connected bool
	// Resets, Batches, SkippedEvents, DuplicateEvents, IdentityConflicts and
	// AbandonedOnReset are cumulative accumulator diagnostics. SkippedEvents > 0
	// means some bytes could not be honestly attributed (the totals stay valid
	// lower bounds); DuplicateEvents is the replay guard working as intended.
	Resets            int64
	Batches           int64
	SkippedEvents     int64
	DuplicateEvents   int64
	IdentityConflicts int64
	AbandonedOnReset  int64
	// ObservedAt is the local time the observation was produced.
	ObservedAt time.Time
}

// ServiceAPIProbe is the bounded read-only client/accumulator for the official
// sing-box 1.14 service.api connection event stream.
//
// One probe owns one persistent subscription: the agent calls
// ObserveServiceAPI (or the SingBoxProbe-compatible ObserveSingBox) on every
// cadence and the probe keeps the stream and accumulator alive across calls.
// A stream failure is reported as a typed unavailability error for that call
// and is transparently re-subscribed on the next call (using a new reset batch
// as the new baseline while preserving the banked totals/replay guard).
//
// The probe must be closed when no longer used so its reader goroutine and TCP
// connection are released.
type ServiceAPIProbe struct {
	base          *url.URL
	secret        string
	interval      time.Duration
	timeout       time.Duration
	maxFrameBytes int
	drainWindow   time.Duration
	client        *http.Client

	requestCtx    context.Context
	cancelRequest context.CancelFunc
	closed        chan struct{}
	closeOnce     sync.Once

	mu    sync.Mutex
	state *serviceAPIStreamState
	acc   *serviceAPIAccumulator
}

// serviceAPIStreamState is the per-subscription state shared between the
// observation call and the background reader goroutine. Mutable fields are
// guarded by ServiceAPIProbe.mu.
type serviceAPIStreamState struct {
	body       io.ReadCloser
	updates    chan struct{}
	doneCh     chan struct{}
	readerDone chan struct{}

	generation uint64
	resetSeen  bool
	done       bool
	err        error
}

// NewServiceAPIProbe validates the configuration and builds a read-only
// service.api probe. It performs no I/O: the subscription is opened lazily by
// the first Observe call.
func NewServiceAPIProbe(config ServiceAPIConfig) (*ServiceAPIProbe, error) {
	base, err := parseServiceAPILoopbackURL(config.URL)
	if err != nil {
		return nil, err
	}
	if hasServiceAPIControlByte(config.Secret) {
		return nil, errors.New("linuxobs: invalid service.api credential format")
	}
	interval := config.Interval
	if interval <= 0 {
		interval = defaultServiceAPIInterval
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultServiceAPITimeout
	}
	if timeout > maxServiceAPITimeout {
		timeout = maxServiceAPITimeout
	}
	maxFrameBytes := config.MaxFrameBytes
	if maxFrameBytes <= 0 {
		maxFrameBytes = defaultServiceAPIMaxFrameBytes
	}
	if maxFrameBytes > maxServiceAPIMaxFrameBytes {
		maxFrameBytes = maxServiceAPIMaxFrameBytes
	}

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	transport := &http.Transport{
		// Proxy nil: never honour HTTP_PROXY/HTTPS_PROXY/etc. A loopback
		// control API must not be reachable through an environment proxy.
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:     true,
		MaxResponseHeaderBytes: serviceAPIMaxResponseHeaderBytes,
		ResponseHeaderTimeout:  timeout,
		ForceAttemptHTTP2:      false,
	}
	client := &http.Client{
		Transport: transport,
		// Never follow redirects: a 3xx response is an unavailability error.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &ServiceAPIProbe{
		base:          base,
		secret:        config.Secret,
		interval:      interval,
		timeout:       timeout,
		maxFrameBytes: maxFrameBytes,
		drainWindow:   serviceAPIDrainWindow,
		client:        client,
		requestCtx:    requestCtx,
		cancelRequest: cancelRequest,
		closed:        make(chan struct{}),
		acc:           newServiceAPIAccumulator(),
	}, nil
}

// hasServiceAPIControlByte rejects header-injection control characters in the
// configured secret (the same posture as the legacy Clash client, extended to
// all control bytes because the value is emitted verbatim in an HTTP header).
func hasServiceAPIControlByte(value string) bool {
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current < 0x20 || current == 0x7f {
			return true
		}
	}
	return false
}

// parseServiceAPILoopbackURL validates the service.api origin: literal
// loopback IP, http scheme, optional explicit port (default 9091), no userinfo,
// path, query or fragment.
func parseServiceAPILoopbackURL(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "http" || origin.User != nil ||
		origin.Opaque != "" || origin.Host == "" || origin.Path != "" ||
		origin.RawPath != "" || origin.ForceQuery || origin.RawQuery != "" ||
		indexByte([]byte(raw), '#') >= 0 {
		return nil, errors.New("linuxobs: service.api URL must be a literal loopback HTTP IP origin")
	}
	host := origin.Hostname()
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return nil, errors.New("linuxobs: service.api URL must target a literal loopback IP address")
	}
	port := origin.Port()
	if port == "" {
		// Reject an explicit but empty port ("http://127.0.0.1:"); url.Parse
		// accepts it and Port() then reports an empty string.
		if len(origin.Host) > 0 && origin.Host[len(origin.Host)-1] == ':' {
			return nil, errors.New("linuxobs: service.api URL must carry a valid port")
		}
		port = serviceAPIDefaultPort
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return nil, errors.New("linuxobs: service.api URL must carry a non-zero port")
	}
	return &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(address.String(), strconv.FormatUint(parsedPort, 10)),
	}, nil
}

// ServiceAPIObserver is the richer read-only service.api probe API: it returns
// the honest probe-observed cumulative totals (lower bounds, never claimed to
// be daemon-lifetime totals) that the frozen SingBoxProbe interface cannot
// carry. The collector can accept this interface directly.
type ServiceAPIObserver interface {
	ObserveServiceAPI(ctx context.Context) (ServiceAPIObservation, error)
}

var _ ServiceAPIObserver = (*ServiceAPIProbe)(nil)

// ObserveSingBox implements SingBoxProbe. It maps the active-connection lower
// bounds into the frozen legacy evidence type; callers that need the true
// probe-observed cumulative totals must call ObserveServiceAPI directly,
// because InboundEvidence cannot carry them.
func (probe *ServiceAPIProbe) ObserveSingBox(ctx context.Context) (SingBoxObservation, error) {
	observation, err := probe.ObserveServiceAPI(ctx)
	if err != nil {
		return SingBoxObservation{}, err
	}
	inbounds := make(map[string]InboundEvidence, len(observation.Inbounds))
	for tag, evidence := range observation.Inbounds {
		inbounds[tag] = InboundEvidence{
			ActiveConnections: evidence.ActiveConnections,
			UplinkBytes:       evidence.UplinkBytes,
			DownlinkBytes:     evidence.DownlinkBytes,
		}
	}
	return SingBoxObservation{Inbounds: inbounds}, nil
}

var _ SingBoxProbe = (*ServiceAPIProbe)(nil)

// ObserveServiceAPI returns one observation of the persistent service.api
// accumulator.
//
// The subscription is started lazily on the first call. A successful call
// always reflects an applied reset baseline, so the active-connection snapshot
// is complete and the observed cumulative totals are meaningful. An idle but
// healthy stream returns the current snapshot after the bounded drain window;
// a stream that fails or ends returns a typed unavailability error (matching
// both ErrServiceAPIUnavailable and ErrProbeUnavailable) and is re-subscribed on
// the next call. The caller's context bounds only this observation wait: the
// persistent subscription is owned by the probe and closed by Close.
func (probe *ServiceAPIProbe) ObserveServiceAPI(ctx context.Context) (ServiceAPIObservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ServiceAPIObservation{}, err
	}

	probe.mu.Lock()
	state, err := probe.ensureStreamLocked()
	if err != nil {
		probe.mu.Unlock()
		return ServiceAPIObservation{}, err
	}
	startGeneration := state.generation
	established := state.resetSeen
	probe.mu.Unlock()

	wait := probe.drainWindow
	if !established {
		wait = probe.timeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return ServiceAPIObservation{}, err
		}
		probe.mu.Lock()
		if probe.state != state {
			probe.mu.Unlock()
			return ServiceAPIObservation{}, serviceAPIUnavailable("event stream was replaced")
		}
		if state.done {
			err := state.err
			probe.mu.Unlock()
			return ServiceAPIObservation{}, serviceAPIFinalError(err)
		}
		if state.resetSeen && state.generation > startGeneration {
			observation, err := probe.acc.snapshot(time.Now(), true)
			probe.mu.Unlock()
			return observation, err
		}
		probe.mu.Unlock()

		select {
		case <-state.updates:
		case <-state.doneCh:
		case <-timer.C:
			return probe.finishObservationWait(state)
		case <-ctx.Done():
			return ServiceAPIObservation{}, ctx.Err()
		case <-probe.closed:
			return ServiceAPIObservation{}, serviceAPIUnavailable("probe closed")
		}
	}
}

// finishObservationWait resolves the bounded wait once the observation window
// elapses: a missing baseline is an honest timeout, an established baseline is
// returned as-is (healthy silence means no state change).
func (probe *ServiceAPIProbe) finishObservationWait(state *serviceAPIStreamState) (ServiceAPIObservation, error) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.state != state {
		return ServiceAPIObservation{}, serviceAPIUnavailable("event stream was replaced")
	}
	if state.done {
		return ServiceAPIObservation{}, serviceAPIFinalError(state.err)
	}
	if !state.resetSeen {
		return ServiceAPIObservation{}, serviceAPIUnavailable("no reset batch within the observation timeout")
	}
	return probe.acc.snapshot(time.Now(), true)
}

// ensureStreamLocked returns a healthy stream, lazily (re)subscribing when the
// previous one ended. Callers must hold probe.mu.
func (probe *ServiceAPIProbe) ensureStreamLocked() (*serviceAPIStreamState, error) {
	select {
	case <-probe.closed:
		return nil, serviceAPIUnavailable("probe closed")
	default:
	}
	if probe.state != nil {
		if !probe.state.done {
			return probe.state, nil
		}
		probe.state = nil
	}
	state, err := probe.startStreamLocked()
	if err != nil {
		return nil, err
	}
	probe.state = state
	go probe.readStream(state)
	return state, nil
}

// startStreamLocked opens one gRPC-Web subscription. Callers must hold
// probe.mu; the call is bounded by the transport dial/response-header timeouts.
func (probe *ServiceAPIProbe) startStreamLocked() (*serviceAPIStreamState, error) {
	endpoint := *probe.base
	endpoint.Path = serviceAPISubscribePath
	request, err := http.NewRequestWithContext(probe.requestCtx, http.MethodPost, endpoint.String(),
		bytes.NewReader(encodeServiceAPISubscribeConnectionsRequest(probe.interval)))
	if err != nil {
		return nil, serviceAPIUnavailable("request construction failed")
	}
	request.Header.Set("Content-Type", serviceAPIContentType)
	request.Header.Set("X-Grpc-Web", "1")
	request.Header.Set("TE", "trailers")
	if probe.secret != "" {
		request.Header.Set("Authorization", "Bearer "+probe.secret)
	}
	response, err := probe.client.Do(request)
	if err != nil {
		select {
		case <-probe.closed:
			return nil, serviceAPIUnavailable("probe closed")
		default:
		}
		return nil, serviceAPIUnavailable("subscription request failed")
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, serviceAPIUnavailable(fmt.Sprintf("unexpected response status %d", response.StatusCode))
	}
	select {
	case <-probe.closed:
		_ = response.Body.Close()
		return nil, serviceAPIUnavailable("probe closed")
	default:
	}
	return &serviceAPIStreamState{
		body:       response.Body,
		updates:    make(chan struct{}, 1),
		doneCh:     make(chan struct{}),
		readerDone: make(chan struct{}),
	}, nil
}

// readStream consumes the response body, assembles frames and applies batches
// to the accumulator until the stream ends or fails.
func (probe *ServiceAPIProbe) readStream(state *serviceAPIStreamState) {
	defer close(state.readerDone)
	parser := &serviceAPIFrameParser{maxFrameBytes: probe.maxFrameBytes}
	buffer := make([]byte, serviceAPIReadChunk)
	for {
		read, err := state.body.Read(buffer)
		if read > 0 {
			stop, frameErr := parser.feed(buffer[:read], func(flags byte, payload []byte) (bool, error) {
				return probe.processFrame(state, flags, payload)
			})
			if frameErr != nil {
				probe.finishStream(state, frameErr)
				return
			}
			if stop {
				probe.finishStream(state, errServiceAPIStreamEnded)
				return
			}
		}
		if err != nil {
			select {
			case <-probe.closed:
				probe.finishStream(state, serviceAPIUnavailable("probe closed"))
			default:
				if errors.Is(err, io.EOF) {
					probe.finishStream(state, errServiceAPIStreamEnded)
				} else {
					probe.finishStream(state, serviceAPIUnavailable("event stream read failed"))
				}
			}
			return
		}
	}
}

// processFrame handles one complete gRPC-Web frame. It returns stop=true after
// a valid trailer (the subscription is over) and a typed error for any protocol
// violation; all mutable stream state is updated under probe.mu.
func (probe *ServiceAPIProbe) processFrame(state *serviceAPIStreamState, flags byte, payload []byte) (bool, error) {
	if flags&serviceAPIGRPCWebTrailerFlag != 0 {
		status := serviceAPIGRPCWebTrailerStatus(payload)
		if status != "" && status != "0" {
			return true, serviceAPIUnavailable("subscription ended with a non-zero gRPC status")
		}
		return true, nil
	}
	if flags != serviceAPIGRPCWebDataFlag {
		return false, serviceAPIUnavailable("unknown gRPC-Web frame flags")
	}
	batch, err := decodeServiceAPIConnectionEvents(payload)
	if err != nil {
		return false, serviceAPIUnavailable("malformed event frame")
	}
	probe.mu.Lock()
	if state.done {
		probe.mu.Unlock()
		return true, nil
	}
	if !state.resetSeen && !batch.reset {
		probe.mu.Unlock()
		return false, serviceAPIUnavailable("event stream did not start with a reset batch")
	}
	if err := probe.acc.applyBatch(batch); err != nil {
		probe.mu.Unlock()
		return false, err
	}
	state.generation++
	if batch.reset {
		state.resetSeen = true
	}
	probe.mu.Unlock()
	select {
	case state.updates <- struct{}{}:
	default:
	}
	return false, nil
}

// finishStream records terminal stream state exactly once and releases the
// response body. Terminal errors are normalized so no transport/protobuf detail
// (and never the configured secret or payload metadata) escapes to callers.
func (probe *ServiceAPIProbe) finishStream(state *serviceAPIStreamState, err error) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if state.done {
		return
	}
	state.done = true
	state.err = serviceAPIFinalError(err)
	close(state.doneCh)
	if state.body != nil {
		_ = state.body.Close()
	}
}

// serviceAPIFinalError normalizes a terminal stream error. Typed unavailability
// errors are returned unchanged; every other cause collapses to a fixed
// classification so raw transport/server-rendered text is never surfaced.
func serviceAPIFinalError(err error) error {
	if err == nil {
		return serviceAPIUnavailable("event stream unavailable")
	}
	var unavailable *ServiceAPIUnavailableError
	if errors.As(err, &unavailable) {
		return err
	}
	if errors.Is(err, errServiceAPIStreamEnded) {
		return serviceAPIUnavailable("event stream ended")
	}
	return serviceAPIUnavailable("event stream failed")
}

// errServiceAPIStreamEnded is the sentinel for a clean end of the subscription
// (a valid trailer frame or an EOF at a frame boundary).
var errServiceAPIStreamEnded = errors.New("linuxobs: service.api stream ended")

// Close releases the persistent subscription and stops the reader goroutine.
// It is safe to call more than once and is required for a clean shutdown.
func (probe *ServiceAPIProbe) Close() error {
	probe.closeOnce.Do(func() {
		close(probe.closed)
		probe.cancelRequest()
	})
	probe.mu.Lock()
	state := probe.state
	probe.mu.Unlock()
	probe.client.CloseIdleConnections()
	if state == nil {
		return nil
	}
	select {
	case <-state.readerDone:
	case <-time.After(serviceAPICloseWait):
	}
	return nil
}

// serviceAPIBytes is a pair of byte counters.
type serviceAPIBytes struct {
	uplink   int64
	downlink int64
}

// serviceAPIActive is one active lifecycle tracked by the accumulator.
type serviceAPIActive struct {
	inbound       string
	uplinkTotal   int64
	downlinkTotal int64
}

// serviceAPIBankedState distinguishes a finalized lifecycle from an ABANDONED
// one (an active id that disappeared from a reset without a CLOSED event). An
// abandoned record is a lower-bound placeholder that is un-banked and replaced
// if the authoritative final totals ever arrive.
type serviceAPIBankedState uint8

const (
	serviceAPIBankedClosed serviceAPIBankedState = iota
	serviceAPIBankedAbandoned
)

// serviceAPIBanked is one replay/accounting guard record, independent of any
// display cache (there is none here).
type serviceAPIBanked struct {
	id       string
	inbound  string
	uplink   int64
	downlink int64
	state    serviceAPIBankedState
}

// serviceAPIAccumulator is the in-memory event-driven lifecycle accumulator.
// It is not goroutine-safe; ServiceAPIProbe.mu guards it.
type serviceAPIAccumulator struct {
	active    map[string]*serviceAPIActive
	finalized map[string]*serviceAPIBytes
	banked    map[string]*list.Element
	bankedLRU *list.List

	resets     int64
	batches    int64
	skipped    int64
	duplicates int64
	conflicts  int64
	abandoned  int64
}

// newServiceAPIAccumulator returns an empty accumulator.
func newServiceAPIAccumulator() *serviceAPIAccumulator {
	return &serviceAPIAccumulator{
		active:    make(map[string]*serviceAPIActive),
		finalized: make(map[string]*serviceAPIBytes),
		banked:    make(map[string]*list.Element),
		bankedLRU: list.New(),
	}
}

// applyBatch applies one decoded ConnectionEvents message.
func (accumulator *serviceAPIAccumulator) applyBatch(batch serviceAPIConnectionBatch) error {
	accumulator.batches++
	if batch.reset {
		accumulator.resets++
		return accumulator.applyReset(batch.events)
	}
	for index := range batch.events {
		if err := accumulator.applyEvent(batch.events[index]); err != nil {
			return err
		}
	}
	return nil
}

// applyReset rebuilds the snapshot from an official reset batch.
//
// The batch contains NEW events for all currently ACTIVE connections plus NEW
// events (with closedAt set) for recently CLOSED ones. Active lifecycles present
// in the batch are refreshed with authoritative totals (same lifecycle, never
// double counted). Active ids NOT present are treated as ABANDONED/INCOMPLETE:
// they are never invented as closed, but their last known totals are banked as
// a lower bound so cumulative totals never go backwards across a reset; the
// lower bound is un-banked if the same id reappears.
func (accumulator *serviceAPIAccumulator) applyReset(events []serviceAPIConnectionEvent) error {
	seen := make(map[string]struct{}, len(events))
	for index := range events {
		event := &events[index]
		connection := event.connection
		id := ""
		if event.hasID {
			id = event.id
		}
		if id == "" && connection != nil && connection.hasID {
			id = connection.id
		}
		if !serviceAPIValidConnectionID(id) || connection == nil ||
			!connection.hasInbound || !serviceAPIValidInboundTag(connection.inbound) ||
			!serviceAPIConnectionCountersValid(connection) {
			accumulator.skipped++
			continue
		}
		seen[id] = struct{}{}
		if connection.hasClosedAt && connection.closedAt != 0 {
			if err := accumulator.recordClosed(id, connection); err != nil {
				return err
			}
			continue
		}
		if err := accumulator.upsertActive(id, connection); err != nil {
			return err
		}
	}
	for id, active := range accumulator.active {
		if _, ok := seen[id]; ok {
			continue
		}
		accumulator.abandoned++
		if err := accumulator.bank(active.inbound, active.uplinkTotal, active.downlinkTotal); err != nil {
			return err
		}
		accumulator.recordBanked(&serviceAPIBanked{
			id:       id,
			inbound:  active.inbound,
			uplink:   active.uplinkTotal,
			downlink: active.downlinkTotal,
			state:    serviceAPIBankedAbandoned,
		})
		delete(accumulator.active, id)
	}
	return nil
}

// applyEvent applies one non-reset ConnectionEvent.
func (accumulator *serviceAPIAccumulator) applyEvent(event serviceAPIConnectionEvent) error {
	kind := 0
	if event.hasKind {
		kind = event.kind
	}
	// The reference collector keys non-reset events on the event id only; a
	// Connection.id fallback is used only by reset batches.
	id := event.id
	switch kind {
	case serviceAPIEventNew:
		if !serviceAPIValidConnectionID(id) {
			accumulator.skipped++
			return nil
		}
		connection := event.connection
		if connection == nil || !serviceAPIConnectionCountersValid(connection) {
			accumulator.skipped++
			return nil
		}
		if connection.hasClosedAt && connection.closedAt != 0 {
			// A closed lifecycle replayed as NEW: the server does this in reset
			// batches and during restart replay.
			if !connection.hasInbound || !serviceAPIValidInboundTag(connection.inbound) {
				accumulator.skipped++
				return nil
			}
			return accumulator.recordClosed(id, connection)
		}
		if !connection.hasInbound || !serviceAPIValidInboundTag(connection.inbound) {
			accumulator.skipped++
			return nil
		}
		return accumulator.upsertActive(id, connection)
	case serviceAPIEventUpdate:
		if id == "" {
			accumulator.skipped++
			return nil
		}
		active := accumulator.active[id]
		if active == nil {
			// UPDATE for an unknown id: fail safe, never invent a lifecycle.
			accumulator.skipped++
			return nil
		}
		connection := event.connection
		if connection != nil && connection.hasInbound && connection.inbound != active.inbound {
			// An id keeps its inbound identity forever; traffic must never
			// migrate between inbound tags.
			accumulator.conflicts++
			return nil
		}
		if connection != nil && (connection.hasUplinkTotal || connection.hasDownlinkTotal) {
			// Authoritative totals inside UPDATE: replace, never add.
			if connection.hasUplinkTotal {
				if connection.uplinkTotal < 0 {
					accumulator.skipped++
					return nil
				}
				if connection.uplinkTotal > active.uplinkTotal {
					active.uplinkTotal = connection.uplinkTotal
				}
			}
			if connection.hasDownlinkTotal {
				if connection.downlinkTotal < 0 {
					accumulator.skipped++
					return nil
				}
				if connection.downlinkTotal > active.downlinkTotal {
					active.downlinkTotal = connection.downlinkTotal
				}
			}
			return nil
		}
		if event.uplinkDelta < 0 || event.downlinkDelta < 0 {
			accumulator.skipped++
			return nil
		}
		uplink, ok := serviceAPICheckedAdd(active.uplinkTotal, event.uplinkDelta)
		if !ok {
			return serviceAPIUnavailable("connection counter overflow")
		}
		downlink, ok := serviceAPICheckedAdd(active.downlinkTotal, event.downlinkDelta)
		if !ok {
			return serviceAPIUnavailable("connection counter overflow")
		}
		active.uplinkTotal = uplink
		active.downlinkTotal = downlink
		return nil
	case serviceAPIEventClosed:
		return accumulator.applyClosedEvent(event)
	default:
		accumulator.skipped++
		return nil
	}
}

// applyClosedEvent finalizes exactly one lifecycle. The final Connection object
// (when present) carries authoritative totals including traffic after the last
// UPDATE ticker, so it is applied before banking.
func (accumulator *serviceAPIAccumulator) applyClosedEvent(event serviceAPIConnectionEvent) error {
	id := event.id
	if id == "" {
		accumulator.skipped++
		return nil
	}
	connection := event.connection
	if connection != nil && !serviceAPIConnectionCountersValid(connection) {
		accumulator.skipped++
		return nil
	}
	if active := accumulator.active[id]; active != nil {
		delete(accumulator.active, id)
		if connection != nil {
			if !connection.hasInbound || connection.inbound == active.inbound {
				if connection.hasUplinkTotal && connection.uplinkTotal > active.uplinkTotal {
					active.uplinkTotal = connection.uplinkTotal
				}
				if connection.hasDownlinkTotal && connection.downlinkTotal > active.downlinkTotal {
					active.downlinkTotal = connection.downlinkTotal
				}
			} else {
				// Identity drift: count it, but finalize under the known identity
				// instead of migrating traffic to another tag.
				accumulator.conflicts++
			}
		}
		return accumulator.finalizeLifecycle(id, active.inbound, active.uplinkTotal, active.downlinkTotal)
	}
	record := accumulator.lookupBanked(id)
	if record == nil {
		// CLOSED for an id this probe never observed: skipping is the only
		// honest choice; inventing traffic would fabricate totals.
		accumulator.skipped++
		return nil
	}
	if record.state == serviceAPIBankedClosed {
		// Finalize exactly once, including reset replay.
		accumulator.duplicates++
		return nil
	}
	// Closure of an ABANDONED lifecycle: replace the lower-bound bank with the
	// authoritative final totals when the event carries a Connection.
	if connection == nil {
		return nil
	}
	if !connection.hasInbound || !serviceAPIValidInboundTag(connection.inbound) {
		accumulator.skipped++
		return nil
	}
	if connection.inbound != record.inbound {
		accumulator.conflicts++
		return nil
	}
	accumulator.dropBanked(id)
	if err := accumulator.unbank(record.inbound, record.uplink, record.downlink); err != nil {
		return err
	}
	return accumulator.finalizeClosedLifecycle(id, connection)
}

// upsertActive refreshes or creates one active lifecycle.
func (accumulator *serviceAPIAccumulator) upsertActive(id string, connection *serviceAPIConnection) error {
	if existing := accumulator.active[id]; existing != nil {
		if connection.hasInbound && connection.inbound != existing.inbound {
			accumulator.conflicts++
			return nil
		}
		// Authoritative totals: the same lifecycle is replaced, never added.
		if connection.hasUplinkTotal && connection.uplinkTotal > existing.uplinkTotal {
			existing.uplinkTotal = connection.uplinkTotal
		}
		if connection.hasDownlinkTotal && connection.downlinkTotal > existing.downlinkTotal {
			existing.downlinkTotal = connection.downlinkTotal
		}
		return nil
	}
	record := accumulator.lookupBanked(id)
	if record != nil {
		if connection.hasInbound && connection.inbound != record.inbound {
			accumulator.conflicts++
			return nil
		}
		// The same lifecycle continues (was closed or abandoned before): un-bank
		// its recorded totals and carry them forward as a floor.
		accumulator.dropBanked(id)
		if err := accumulator.unbank(record.inbound, record.uplink, record.downlink); err != nil {
			return err
		}
	}
	inbound := ""
	if connection.hasInbound {
		inbound = connection.inbound
	}
	if record != nil && inbound == "" {
		inbound = record.inbound
	}
	if !serviceAPIValidInboundTag(inbound) {
		accumulator.skipped++
		return nil
	}
	active := &serviceAPIActive{inbound: inbound}
	if connection.hasUplinkTotal {
		active.uplinkTotal = connection.uplinkTotal
	}
	if connection.hasDownlinkTotal {
		active.downlinkTotal = connection.downlinkTotal
	}
	if record != nil {
		if record.uplink > active.uplinkTotal {
			active.uplinkTotal = record.uplink
		}
		if record.downlink > active.downlinkTotal {
			active.downlinkTotal = record.downlink
		}
	}
	accumulator.active[id] = active
	return nil
}

// recordClosed handles a closed lifecycle announced as NEW (reset replay).
// The INDEPENDENT banked-id guard (not any display cache) makes sure a replayed
// lifecycle is never banked twice; an ABANDONED lower bound is replaced by the
// authoritative final values exactly once.
func (accumulator *serviceAPIAccumulator) recordClosed(id string, connection *serviceAPIConnection) error {
	if record := accumulator.lookupBanked(id); record != nil {
		if connection.inbound != record.inbound {
			accumulator.conflicts++
			return nil
		}
		accumulator.duplicates++
		if record.state == serviceAPIBankedClosed {
			return nil
		}
		accumulator.dropBanked(id)
		if err := accumulator.unbank(record.inbound, record.uplink, record.downlink); err != nil {
			return err
		}
		return accumulator.finalizeClosedLifecycle(id, connection)
	}
	if active := accumulator.active[id]; active != nil {
		delete(accumulator.active, id)
		if connection.hasInbound && connection.inbound != active.inbound {
			accumulator.conflicts++
		} else {
			if connection.hasUplinkTotal && connection.uplinkTotal > active.uplinkTotal {
				active.uplinkTotal = connection.uplinkTotal
			}
			if connection.hasDownlinkTotal && connection.downlinkTotal > active.downlinkTotal {
				active.downlinkTotal = connection.downlinkTotal
			}
		}
		return accumulator.finalizeLifecycle(id, active.inbound, active.uplinkTotal, active.downlinkTotal)
	}
	return accumulator.finalizeClosedLifecycle(id, connection)
}

// finalizeClosedLifecycle banks the authoritative final totals of a lifecycle
// described only by its Connection object.
func (accumulator *serviceAPIAccumulator) finalizeClosedLifecycle(id string, connection *serviceAPIConnection) error {
	if !connection.hasInbound || !serviceAPIValidInboundTag(connection.inbound) {
		accumulator.skipped++
		return nil
	}
	var uplink, downlink int64
	if connection.hasUplinkTotal {
		uplink = connection.uplinkTotal
	}
	if connection.hasDownlinkTotal {
		downlink = connection.downlinkTotal
	}
	return accumulator.finalizeLifecycle(id, connection.inbound, uplink, downlink)
}

// finalizeLifecycle banks one finalized lifecycle exactly once and registers its
// id for replay protection.
func (accumulator *serviceAPIAccumulator) finalizeLifecycle(id, inbound string, uplink, downlink int64) error {
	if err := accumulator.bank(inbound, uplink, downlink); err != nil {
		return err
	}
	accumulator.recordBanked(&serviceAPIBanked{
		id:       id,
		inbound:  inbound,
		uplink:   uplink,
		downlink: downlink,
		state:    serviceAPIBankedClosed,
	})
	return nil
}

// bank adds finalized counters for one inbound tag.
func (accumulator *serviceAPIAccumulator) bank(inbound string, uplink, downlink int64) error {
	slot := accumulator.finalized[inbound]
	if slot == nil {
		slot = &serviceAPIBytes{}
		accumulator.finalized[inbound] = slot
	}
	nextUplink, ok := serviceAPICheckedAdd(slot.uplink, uplink)
	if !ok {
		return serviceAPIUnavailable("connection counter overflow")
	}
	nextDownlink, ok := serviceAPICheckedAdd(slot.downlink, downlink)
	if !ok {
		return serviceAPIUnavailable("connection counter overflow")
	}
	slot.uplink = nextUplink
	slot.downlink = nextDownlink
	return nil
}

// unbank removes exactly the counters previously added by bank. A missing/too
// small slot means the internal accounting invariant was violated; that is
// reported as unavailability instead of being silently clamped.
func (accumulator *serviceAPIAccumulator) unbank(inbound string, uplink, downlink int64) error {
	slot := accumulator.finalized[inbound]
	if slot == nil || uplink > slot.uplink || downlink > slot.downlink {
		return serviceAPIUnavailable("cumulative accounting inconsistency")
	}
	slot.uplink -= uplink
	slot.downlink -= downlink
	if slot.uplink == 0 && slot.downlink == 0 {
		delete(accumulator.finalized, inbound)
	}
	return nil
}

// lookupBanked returns the replay-guard record for id, if any.
func (accumulator *serviceAPIAccumulator) lookupBanked(id string) *serviceAPIBanked {
	element := accumulator.banked[id]
	if element == nil {
		return nil
	}
	return element.Value.(*serviceAPIBanked)
}

// recordBanked inserts or refreshes one replay-guard record, evicting the least
// recently used ids beyond the retention cap.
func (accumulator *serviceAPIAccumulator) recordBanked(record *serviceAPIBanked) {
	if element := accumulator.banked[record.id]; element != nil {
		element.Value = record
		accumulator.bankedLRU.MoveToBack(element)
		return
	}
	accumulator.banked[record.id] = accumulator.bankedLRU.PushBack(record)
	for accumulator.bankedLRU.Len() > serviceAPIMaxBankedIDs {
		oldest := accumulator.bankedLRU.Front()
		if oldest == nil {
			break
		}
		accumulator.bankedLRU.Remove(oldest)
		delete(accumulator.banked, oldest.Value.(*serviceAPIBanked).id)
	}
}

// dropBanked removes and returns one replay-guard record.
func (accumulator *serviceAPIAccumulator) dropBanked(id string) *serviceAPIBanked {
	element := accumulator.banked[id]
	if element == nil {
		return nil
	}
	delete(accumulator.banked, id)
	accumulator.bankedLRU.Remove(element)
	return element.Value.(*serviceAPIBanked)
}

// snapshot projects the accumulator into the public observation type.
func (accumulator *serviceAPIAccumulator) snapshot(now time.Time, connected bool) (ServiceAPIObservation, error) {
	observation := ServiceAPIObservation{
		Inbounds:          make(map[string]ServiceAPIInboundEvidence),
		Connected:         connected,
		Resets:            accumulator.resets,
		Batches:           accumulator.batches,
		SkippedEvents:     accumulator.skipped,
		DuplicateEvents:   accumulator.duplicates,
		IdentityConflicts: accumulator.conflicts,
		AbandonedOnReset:  accumulator.abandoned,
		ObservedAt:        now,
	}
	for inbound, finalized := range accumulator.finalized {
		observation.Inbounds[inbound] = ServiceAPIInboundEvidence{
			UplinkTotalBytes:   finalized.uplink,
			DownlinkTotalBytes: finalized.downlink,
		}
	}
	for _, active := range accumulator.active {
		evidence := observation.Inbounds[active.inbound]
		activeConnections, ok := serviceAPICheckedAdd(evidence.ActiveConnections, 1)
		if !ok {
			return ServiceAPIObservation{}, serviceAPIUnavailable("connection counter overflow")
		}
		uplinkBytes, ok := serviceAPICheckedAdd(evidence.UplinkBytes, active.uplinkTotal)
		if !ok {
			return ServiceAPIObservation{}, serviceAPIUnavailable("connection counter overflow")
		}
		downlinkBytes, ok := serviceAPICheckedAdd(evidence.DownlinkBytes, active.downlinkTotal)
		if !ok {
			return ServiceAPIObservation{}, serviceAPIUnavailable("connection counter overflow")
		}
		evidence.ActiveConnections = activeConnections
		evidence.UplinkBytes = uplinkBytes
		evidence.DownlinkBytes = downlinkBytes
		observation.Inbounds[active.inbound] = evidence
	}
	for inbound, evidence := range observation.Inbounds {
		uplinkTotal, ok := serviceAPICheckedAdd(evidence.UplinkTotalBytes, evidence.UplinkBytes)
		if !ok {
			return ServiceAPIObservation{}, serviceAPIUnavailable("connection counter overflow")
		}
		downlinkTotal, ok := serviceAPICheckedAdd(evidence.DownlinkTotalBytes, evidence.DownlinkBytes)
		if !ok {
			return ServiceAPIObservation{}, serviceAPIUnavailable("connection counter overflow")
		}
		evidence.UplinkTotalBytes = uplinkTotal
		evidence.DownlinkTotalBytes = downlinkTotal
		evidence.TotalsAvailable = true
		observation.Inbounds[inbound] = evidence
	}
	return observation, nil
}

// serviceAPICheckedAdd adds two non-negative counters with int64 overflow
// detection.
func serviceAPICheckedAdd(left, right int64) (int64, bool) {
	if right > 0 && left > maxInt64Value-right {
		return 0, false
	}
	return left + right, true
}

// serviceAPIValidConnectionID bounds retained connection ids.
func serviceAPIValidConnectionID(id string) bool {
	return len(id) > 0 && len(id) <= serviceAPIMaxConnectionIDBytes
}

// serviceAPIValidInboundTag applies the frozen inbound_tag grammar.
func serviceAPIValidInboundTag(tag string) bool {
	return len(tag) > 0 && len(tag) <= serviceAPIMaxInboundTagBytes && inboundTagPattern.MatchString(tag)
}

// serviceAPIConnectionCountersValid rejects negative proto int64 counters,
// which would otherwise let malformed events decrease the observed totals.
func serviceAPIConnectionCountersValid(connection *serviceAPIConnection) bool {
	if connection == nil {
		return true
	}
	if connection.hasUplinkTotal && connection.uplinkTotal < 0 {
		return false
	}
	if connection.hasDownlinkTotal && connection.downlinkTotal < 0 {
		return false
	}
	return true
}
