package linuxobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Fixed read-only Clash-compatible endpoints. There is no method/path surface
// beyond these two GETs.
const (
	singBoxProxiesPath     = "/proxies"
	singBoxConnectionsPath = "/connections"

	defaultSingBoxTimeout = 3 * time.Second
	defaultSingBoxMaxBody = int64(4 << 20)
	// maxSingBoxBodyLimit bounds a caller-supplied response cap so the
	// MaxBodyBytes+1 limit arithmetic cannot overflow and one report can never
	// allocate an unbounded buffer.
	maxSingBoxBodyLimit = int64(64 << 20)
)

// InboundEvidence is the observed evidence for one sing-box inbound tag.
type InboundEvidence struct {
	// ActiveConnections is the number of connections attributed to the tag in
	// the observed /connections snapshot.
	ActiveConnections int64
	// UplinkBytes and DownlinkBytes are the cumulative byte counters of those
	// currently active connections. They are NOT the inbound's lifetime totals:
	// the Clash-compatible API exposes no per-inbound lifetime counter.
	UplinkBytes   int64
	DownlinkBytes int64
}

// SingBoxObservation is one read-only snapshot of the local sing-box API.
// Inbounds is keyed by the inbound tag observed in connection metadata and
// never contains free-form proxy names, addresses, connection ids or rules.
type SingBoxObservation struct {
	Inbounds map[string]InboundEvidence
}

// SingBoxProbe observes the local sing-box Clash-compatible API with read-only
// GET requests. Implementations must never mutate sing-box state and must not
// require privileges.
type SingBoxProbe interface {
	ObserveSingBox(ctx context.Context) (SingBoxObservation, error)
}

// unavailableSingBoxProbe is the shipped default: it performs no I/O and
// reports unavailable, so the singbox_api source stays honestly unavailable
// until an authorized probe is injected.
type unavailableSingBoxProbe struct{}

// ObserveSingBox implements SingBoxProbe as an honest unavailable result.
func (unavailableSingBoxProbe) ObserveSingBox(context.Context) (SingBoxObservation, error) {
	return SingBoxObservation{}, ErrProbeUnavailable
}

// SingBoxClientConfig configures the bounded read-only HTTP client.
type SingBoxClientConfig struct {
	// Controller is a literal loopback HTTP origin such as
	// "http://127.0.0.1:9090". Hostnames, non-loopback addresses, HTTPS,
	// paths, queries, fragments and userinfo are rejected.
	Controller string
	// Secret is an optional Bearer credential. It is remembered only in
	// memory, never logged and never placed in an observation or error.
	Secret string
	// Timeout bounds one whole observation (default 3s).
	Timeout time.Duration
	// MaxBodyBytes caps each API response body (default 4 MiB).
	MaxBodyBytes int64
}

// SingBoxClient is the bounded read-only client for the local sing-box
// Clash-compatible API.
//
// It sends only GET /proxies and GET /connections, only to the literal
// loopback origin configured at construction. Redirects are never followed,
// proxy environment variables are ignored, each response body is capped and
// the whole observation is timeout-bounded. The client is validated only
// against synthetic httptest fixtures in this package's tests; it is not a
// verified live production source and enabling singbox_api still requires the
// UM-B3 authorization audit (UM-A 04 §11 P1-10).
type SingBoxClient struct {
	base    *url.URL
	secret  string
	maxBody int64
	client  *http.Client
}

// NewSingBoxClient validates the controller origin and builds a bounded
// read-only client.
func NewSingBoxClient(config SingBoxClientConfig) (*SingBoxClient, error) {
	base, err := parseLoopbackHTTPOrigin(config.Controller)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(config.Secret, "\r\n") {
		return nil, errors.New("linuxobs: invalid sing-box API credential format")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultSingBoxTimeout
	}
	maxBody := config.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultSingBoxMaxBody
	}
	if maxBody > maxSingBoxBodyLimit {
		maxBody = maxSingBoxBodyLimit
	}
	return &SingBoxClient{
		base:    base,
		secret:  config.Secret,
		maxBody: maxBody,
		client: &http.Client{
			// Proxy nil: never honour HTTP_PROXY/HTTPS_PROXY/etc. A local
			// control API must not be reachable through an environment proxy.
			Transport: &http.Transport{Proxy: nil, DisableCompression: true},
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// ObserveSingBox implements SingBoxProbe. Both fixed endpoints must answer
// with a well-formed JSON object; any failure is an honest unavailable result
// and the caller must render protocols/traffic unavailable.
func (c *SingBoxClient) ObserveSingBox(ctx context.Context) (SingBoxObservation, error) {
	if err := ctx.Err(); err != nil {
		return SingBoxObservation{}, err
	}
	proxies, err := c.get(ctx, singBoxProxiesPath)
	if err != nil {
		return SingBoxObservation{}, err
	}
	if err := validateProxiesDocument(proxies); err != nil {
		return SingBoxObservation{}, err
	}
	connections, err := c.get(ctx, singBoxConnectionsPath)
	if err != nil {
		return SingBoxObservation{}, err
	}
	return parseConnectionsDocument(connections)
}

// get performs one bounded GET against a fixed read-only path.
func (c *SingBoxClient) get(ctx context.Context, path string) ([]byte, error) {
	endpoint := *c.base
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, singBoxUnavailable("request construction failed")
	}
	request.Header.Set("Accept", "application/json")
	if c.secret != "" {
		request.Header.Set("Authorization", "Bearer "+c.secret)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, singBoxUnavailable("request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, singBoxUnavailable("unexpected response status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	if err != nil {
		return nil, singBoxUnavailable("response read failed")
	}
	if int64(len(body)) > c.maxBody {
		return nil, singBoxUnavailable("response exceeds the body cap")
	}
	return body, nil
}

// validateProxiesDocument checks the /proxies response shape. The document is
// fetched because the frozen client surface is exactly these two fixed GETs
// and the API is only considered available when both answer a well-formed
// object; sing-box exposes no inbound inventory there, so it is never used to
// invent per-inbound state.
func validateProxiesDocument(raw []byte) error {
	var document struct {
		Proxies map[string]json.RawMessage `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return singBoxUnavailable("malformed proxies document")
	}
	if document.Proxies == nil {
		return singBoxUnavailable("proxies document has no proxies object")
	}
	return nil
}

// singBoxConnection is the subset of one /connections element the collector
// is allowed to consume. No host, address, rule or connection-id field is
// decoded.
type singBoxConnection struct {
	Metadata struct {
		Type string `json:"type"`
	} `json:"metadata"`
	Upload   json.RawMessage `json:"upload"`
	Download json.RawMessage `json:"download"`
}

// parseConnectionsDocument maps the /connections snapshot into per-inbound
// evidence. Only the inbound tag and byte counters are retained.
func parseConnectionsDocument(raw []byte) (SingBoxObservation, error) {
	var document struct {
		Connections json.RawMessage `json:"connections"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return SingBoxObservation{}, singBoxUnavailable("malformed connections document")
	}
	if len(document.Connections) == 0 {
		return SingBoxObservation{}, singBoxUnavailable("connections document has no connections member")
	}
	rows := make([]singBoxConnection, 0)
	if trimmed := strings.TrimSpace(string(document.Connections)); trimmed != "null" {
		if err := json.Unmarshal(document.Connections, &rows); err != nil {
			return SingBoxObservation{}, singBoxUnavailable("malformed connections array")
		}
	}

	inbounds := make(map[string]InboundEvidence)
	for _, row := range rows {
		tag, ok := connectionInboundTag(row.Metadata.Type)
		if !ok {
			continue
		}
		upload, err := parseSingBoxCounter(row.Upload)
		if err != nil {
			return SingBoxObservation{}, err
		}
		download, err := parseSingBoxCounter(row.Download)
		if err != nil {
			return SingBoxObservation{}, err
		}
		evidence := inbounds[tag]
		if evidence.ActiveConnections == maxInt64Value {
			return SingBoxObservation{}, singBoxUnavailable("connection counter overflow")
		}
		evidence.ActiveConnections++
		if evidence.UplinkBytes > maxInt64Value-upload {
			return SingBoxObservation{}, singBoxUnavailable("uplink counter overflow")
		}
		evidence.UplinkBytes += upload
		if evidence.DownlinkBytes > maxInt64Value-download {
			return SingBoxObservation{}, singBoxUnavailable("downlink counter overflow")
		}
		evidence.DownlinkBytes += download
		inbounds[tag] = evidence
	}
	return SingBoxObservation{Inbounds: inbounds}, nil
}

// connectionInboundTag extracts the inbound tag from the Clash-compatible
// metadata.type field. sing-box encodes it as "<inboundType>/<inboundTag>" and
// falls back to the bare inbound type when the tag is empty; only values that
// pass the frozen inbound_tag grammar are retained.
func connectionInboundTag(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	tag := raw
	if index := strings.IndexByte(raw, '/'); index >= 0 {
		tag = raw[index+1:]
	}
	if len(tag) == 0 || len(tag) > 64 || !inboundTagPattern.MatchString(tag) {
		return "", false
	}
	return tag, true
}

// parseSingBoxCounter decodes one non-negative integer byte counter. Missing,
// null, fractional, negative or non-numeric values are malformed.
func parseSingBoxCounter(raw json.RawMessage) (int64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return 0, singBoxUnavailable("missing connection byte counter")
	}
	value, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || value < 0 {
		return 0, singBoxUnavailable("malformed connection byte counter")
	}
	return value, nil
}

// singBoxUnavailable builds a non-secret error wrapping ErrProbeUnavailable.
func singBoxUnavailable(detail string) error {
	return fmt.Errorf("%w: %s", ErrProbeUnavailable, detail)
}

// parseLoopbackHTTPOrigin validates a literal loopback HTTP origin with an
// explicit port. This mirrors the frozen fixed-path/no-redirect posture: a
// plain HTTP control API on a loopback address only.
func parseLoopbackHTTPOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "http" || origin.User != nil ||
		origin.Opaque != "" || origin.Path != "" || origin.RawPath != "" ||
		origin.ForceQuery || origin.RawQuery != "" || strings.Contains(raw, "#") {
		return nil, errors.New("linuxobs: sing-box controller must be a literal loopback HTTP IP and port")
	}
	address, err := netip.ParseAddr(origin.Hostname())
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return nil, errors.New("linuxobs: sing-box controller must be a literal loopback IP address")
	}
	port, err := strconv.ParseUint(origin.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("linuxobs: sing-box controller must carry an explicit non-zero port")
	}
	return origin, nil
}
