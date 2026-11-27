package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const maxResponseBytes int64 = 1 << 20

// EnrollRequest is the frozen enrollment body (no locators/credentials).
type EnrollRequest struct {
	V            int      `json:"v"`
	NodeClass    string   `json:"node_class"`
	AgentVersion string   `json:"agent_version"`
	Host         hostJSON `json:"host"`
	Capabilities []string `json:"capabilities"`
}

type hostJSON struct {
	OS     string `json:"os"`
	Kernel string `json:"kernel"`
	Arch   string `json:"arch"`
}

type EnrollResponse struct {
	V              int     `json:"v"`
	NodeID         string  `json:"node_id"`
	EventID        string  `json:"event_id"`
	NodeClass      string  `json:"node_class"`
	KeyID          string  `json:"key_id"`
	ConfigVersion  int     `json:"config_version"`
	DeviceSalt     string  `json:"device_salt"`
	CadenceSeconds int     `json:"cadence_seconds"`
	ServerTime     int64   `json:"server_time"`
	CenterSPKI     *string `json:"center_spki_sha256"`
}

type ackResponse struct {
	V             int             `json:"v"`
	ReportID      string          `json:"report_id"`
	Result        string          `json:"result"`
	ServerTime    int64           `json:"server_time"`
	NextSeq       json.RawMessage `json:"next_seq"`
	ConfigVersion int             `json:"config_version"`
	RetryAfterS   json.RawMessage `json:"retry_after_s"`
}

type configResponse struct {
	V                   int             `json:"v"`
	NodeID              string          `json:"node_id"`
	EventID             string          `json:"event_id"`
	NodeClass           string          `json:"node_class"`
	ConfigVersion       int             `json:"config_version"`
	CadenceSeconds      int             `json:"cadence_seconds"`
	Collect             map[string]bool `json:"collect"`
	DeviceSalt          string          `json:"device_salt"`
	ServerTime          int64           `json:"server_time"`
	ExpectedInboundTags []struct {
		InboundTag string `json:"inbound_tag"`
		Kind       string `json:"kind"`
	} `json:"expected_inbound_tags"`
}

type rotateResponse struct {
	V             int    `json:"v"`
	NodeID        string `json:"node_id"`
	PreviousKeyID string `json:"previous_key_id"`
	NewKeyID      string `json:"new_key_id"`
	ConfigVersion int    `json:"config_version"`
	ServerTime    int64  `json:"server_time"`
}

// Ack is the validated acknowledgment exposed to the runtime.
type Ack struct {
	ReportID      string
	Result        string
	NextSeq       *uint64
	ConfigVersion int
	ServerTime    int64
	RetryAfterS   *int
}

// Config is a validated config response plus raw bytes for diagnostics.
type Config struct {
	V             int
	NodeID        string
	EventID       string
	NodeClass     string
	ConfigVersion int
	Cadence       int
	Collect       map[string]bool
	DeviceSalt    string
	ServerTime    int64
	Tags          []InboundTag
	Raw           []byte
}

// Rotation is a validated rotate response.
type Rotation struct {
	NodeID        string
	PreviousKeyID string
	NewKeyID      string
	ConfigVersion int
	ServerTime    int64
}

// Client is the strict agent-side center transport.
type Client struct {
	base *url.URL
	http *http.Client
	now  func() time.Time
}

// NewClient validates the center URL and constructs a strict, redirect-free
// client. Plain HTTP is permitted only for loopback test/local endpoints.
func NewClient(rawURL string, httpClient *http.Client, now func() time.Time) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("agent: invalid center URL")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("agent: center URL must not contain a path")
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" {
			return nil, errors.New("agent: center URL must use https")
		}
		host, err := netip.ParseAddr(u.Hostname())
		if err != nil || !host.IsLoopback() || host.Zone() != "" {
			return nil, errors.New("agent: plain HTTP is allowed only for loopback")
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		// Callers may inject a test/transport client, but they must not be able
		// to weaken the frozen redirect-free transport invariant.
		copied := *httpClient
		copied.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &copied
	}
	if now == nil {
		now = time.Now
	}
	return &Client{base: u, http: httpClient, now: now}, nil
}

func (c *Client) endpoint(ep wire.Endpoint) string {
	u := *c.base
	u.Path = "/v1/agent/" + string(ep)
	return u.String()
}

func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeCenterError(status int, raw []byte, retryAfterHeader string) error {
	var body struct {
		V          int    `json:"v"`
		Error      string `json:"error"`
		Retryable  bool   `json:"retryable"`
		ServerTime int64  `json:"server_time"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.V != 1 || body.Error == "" {
		return &TransportError{Cause: fmt.Sprintf("invalid center error status=%d", status)}
	}
	return &CenterError{Status: status, Code: body.Error, Retryable: body.Retryable || status >= 500,
		ServerTime: body.ServerTime, RetryAfterS: parseRetryAfterHeader(retryAfterHeader)}
}

func parseRetryAfterHeader(value string) *int {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 3600 {
		return nil
	}
	return &n
}

func (c *Client) send(ctx context.Context, fields wire.Fields, body []byte, token string, priv ed25519.PrivateKey) ([]byte, error) {
	// Build headers and sign in one place so enrollment/report/config/rotate
	// cannot accidentally use different header sets.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(fields.Endpoint), bytes.NewReader(body))
	if err != nil {
		return nil, &TransportError{Cause: "request construction"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderContentType, "application/json")
	req.Header.Set(wire.HeaderProtocol, fields.Protocol)
	req.Header.Set(wire.HeaderContentEnc, fields.Encoding)
	req.Header.Set(wire.HeaderSentAt, fields.SentAt)
	req.Header.Set(wire.HeaderNonce, fields.Nonce)
	if fields.Endpoint == wire.Enroll {
		req.Header.Set(wire.HeaderPubkey, fields.PublicKey)
		if token == "" {
			return nil, errors.New("agent: enrollment token required")
		}
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+token)
	} else {
		req.Header.Set(wire.HeaderNodeID, fields.NodeID)
		req.Header.Set(wire.HeaderKeyID, fields.KeyID)
		req.Header.Set(wire.HeaderBootGen, fields.BootGen)
		req.Header.Set(wire.HeaderBootID, fields.BootID)
		req.Header.Set(wire.HeaderSeq, fields.Sequence)
	}
	sig, err := wire.Sign(priv, fields, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(wire.HeaderSignature, sig)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &TransportError{Cause: "network failure"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || int64(len(raw)) > maxResponseBytes {
		return nil, &TransportError{Cause: "response read/limit"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, decodeCenterError(resp.StatusCode, raw, resp.Header.Get("Retry-After"))
	}
	return raw, nil
}

func (c *Client) nowUnix() int64 { return c.now().Unix() }

func fieldsPrefix(ep wire.Endpoint) wire.Fields {
	return wire.Fields{Endpoint: ep, Protocol: wire.ProtocolVersion, Encoding: "identity"}
}

func decodeSignatureKey(privBase64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privBase64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("agent: invalid private key")
	}
	return ed25519.PrivateKey(raw), nil
}

func (c *Client) Enroll(ctx context.Context, token string, req EnrollRequest, priv ed25519.PrivateKey) (EnrollResponse, error) {
	pub := priv.Public().(ed25519.PublicKey)
	body, err := json.Marshal(req)
	if err != nil {
		return EnrollResponse{}, err
	}
	nonce, err := newNonce()
	if err != nil {
		return EnrollResponse{}, err
	}
	f := fieldsPrefix(wire.Enroll)
	f.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	f.SentAt = strconv.FormatInt(c.nowUnix(), 10)
	f.Nonce = nonce
	raw, err := c.send(ctx, f, body, token, priv)
	if err != nil {
		return EnrollResponse{}, err
	}
	var resp EnrollResponse
	if err := decodeStrict(raw, &resp); err != nil || resp.V != 1 ||
		!nodeIDRe.MatchString(resp.NodeID) || !nodeIDRe.MatchString(resp.EventID) ||
		!keyIDRe.MatchString(resp.KeyID) || resp.ConfigVersion < 1 ||
		resp.CadenceSeconds < 30 || resp.CadenceSeconds > 300 ||
		resp.NodeClass != req.NodeClass {
		return EnrollResponse{}, &TransportError{Cause: "invalid enrollment response"}
	}
	return resp, nil
}

// requiredNullableUint64 decodes a required JSON property that may be null. A
// missing property is invalid; only an explicit null means exhaustion.
func requiredNullableUint64(raw json.RawMessage, field string) (*uint64, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("agent: ACK missing required %s", field)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return nil, nil
	}
	value, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil || value < 1 || value > wire.MaxNumeric {
		return nil, fmt.Errorf("agent: ACK invalid %s", field)
	}
	v := value
	return &v, nil
}

// requiredNullableRetryAfter decodes the required nullable retry_after_s
// property. The frozen schema permits null or an integer in [1, 3600].
func requiredNullableRetryAfter(raw json.RawMessage) (*int, error) {
	if len(raw) == 0 {
		return nil, errors.New("agent: ACK missing required retry_after_s")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return nil, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil || value < 1 || value > 3600 {
		return nil, errors.New("agent: ACK invalid retry_after_s")
	}
	v := value
	return &v, nil
}

// Report sends one exact persisted attempt.
func (c *Client) Report(ctx context.Context, identity Identity, attempt Attempt, kind string, body []byte) (Ack, error) {
	priv, err := decodeSignatureKey(identity.PrivateKey)
	if err != nil {
		return Ack{}, err
	}
	f := fieldsPrefix(wire.Report)
	f.NodeID = identity.NodeID
	f.KeyID = identity.KeyID
	f.BootGen = strconv.FormatUint(attempt.Generation, 10)
	f.BootID = attempt.BootID
	f.Sequence = strconv.FormatUint(attempt.Seq, 10)
	f.SentAt = strconv.FormatInt(attempt.SentAt, 10)
	f.Nonce = attempt.Nonce
	raw, err := c.send(ctx, f, body, "", priv)
	if err != nil {
		return Ack{}, err
	}
	var resp ackResponse
	if err := decodeStrict(raw, &resp); err != nil {
		return Ack{}, &TransportError{Cause: "invalid ack response"}
	}
	if resp.V != 1 || !nodeIDRe.MatchString(resp.ReportID) ||
		resp.Result != "accepted" && resp.Result != "duplicate" && resp.Result != "stale_ignored" ||
		resp.ConfigVersion < 1 || resp.ServerTime < 0 {
		return Ack{}, &TransportError{Cause: "invalid ack response"}
	}
	nextSeq, err := requiredNullableUint64(resp.NextSeq, "next_seq")
	if err != nil {
		return Ack{}, &TransportError{Cause: "invalid ack response"}
	}
	retryAfter, err := requiredNullableRetryAfter(resp.RetryAfterS)
	if err != nil {
		return Ack{}, &TransportError{Cause: "invalid ack response"}
	}
	return Ack{ReportID: resp.ReportID, Result: resp.Result, NextSeq: nextSeq,
		ConfigVersion: resp.ConfigVersion, ServerTime: resp.ServerTime, RetryAfterS: retryAfter}, nil
}

// Config sends an authenticated config pull.
func (c *Client) Config(ctx context.Context, identity Identity, attempt Attempt) (Config, error) {
	priv, err := decodeSignatureKey(identity.PrivateKey)
	if err != nil {
		return Config{}, err
	}
	f := fieldsPrefix(wire.Config)
	f.NodeID = identity.NodeID
	f.KeyID = identity.KeyID
	f.BootGen = strconv.FormatUint(attempt.Generation, 10)
	f.BootID = attempt.BootID
	f.Sequence = strconv.FormatUint(attempt.Seq, 10)
	f.SentAt = strconv.FormatInt(attempt.SentAt, 10)
	f.Nonce = attempt.Nonce
	raw, err := c.send(ctx, f, []byte("{}"), "", priv)
	if err != nil {
		return Config{}, err
	}
	var resp configResponse
	if err := decodeStrict(raw, &resp); err != nil || resp.V != 1 ||
		resp.NodeID != identity.NodeID || resp.EventID != identity.EventID ||
		resp.NodeClass != identity.NodeClass || resp.ConfigVersion < 1 ||
		resp.CadenceSeconds < 30 || resp.CadenceSeconds > 300 ||
		resp.DeviceSalt == "" || len(resp.Collect) != 6 {
		return Config{}, &TransportError{Cause: "invalid config response"}
	}
	tags := make([]InboundTag, 0, len(resp.ExpectedInboundTags))
	for _, t := range resp.ExpectedInboundTags {
		tags = append(tags, InboundTag{InboundTag: t.InboundTag, Kind: t.Kind})
	}
	return Config{V: resp.V, NodeID: resp.NodeID, EventID: resp.EventID, NodeClass: resp.NodeClass,
		ConfigVersion: resp.ConfigVersion, Cadence: resp.CadenceSeconds, Collect: resp.Collect,
		DeviceSalt: resp.DeviceSalt, ServerTime: resp.ServerTime, Tags: tags, Raw: append([]byte(nil), raw...)}, nil
}

// Rotate sends one persisted rotation intent signed by the old key.
func (c *Client) Rotate(ctx context.Context, identity Identity, attempt Attempt, nonce string, newPub string) (Rotation, error) {
	priv, err := decodeSignatureKey(identity.PrivateKey)
	if err != nil {
		return Rotation{}, err
	}
	body, err := json.Marshal(map[string]any{"v": 1, "new_pubkey": newPub})
	if err != nil {
		return Rotation{}, err
	}
	f := fieldsPrefix(wire.Rotate)
	f.NodeID = identity.NodeID
	f.KeyID = identity.KeyID
	f.BootGen = strconv.FormatUint(attempt.Generation, 10)
	f.BootID = attempt.BootID
	f.Sequence = strconv.FormatUint(attempt.Seq, 10)
	f.SentAt = strconv.FormatInt(attempt.SentAt, 10)
	f.Nonce = nonce
	raw, err := c.send(ctx, f, body, "", priv)
	if err != nil {
		return Rotation{}, err
	}
	var resp rotateResponse
	if err := decodeStrict(raw, &resp); err != nil || resp.V != 1 ||
		resp.NodeID != identity.NodeID || resp.PreviousKeyID != identity.KeyID ||
		!keyIDRe.MatchString(resp.NewKeyID) || resp.ConfigVersion < 1 {
		return Rotation{}, &TransportError{Cause: "invalid rotate response"}
	}
	return Rotation{NodeID: resp.NodeID, PreviousKeyID: resp.PreviousKeyID,
		NewKeyID: resp.NewKeyID, ConfigVersion: resp.ConfigVersion, ServerTime: resp.ServerTime}, nil
}

// Fingerprint exposes the frozen attempt fingerprint helper for the runtime.
func Fingerprint(fields wire.Fields, body []byte) (string, error) {
	return wire.Fingerprint(fields, body)
}
