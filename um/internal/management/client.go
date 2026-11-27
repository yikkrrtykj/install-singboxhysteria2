package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxAdminResponse = 2 << 20

// Client is the CLI's only transport to the management service. It never opens
// SQLite and never bypasses the admin service/RBAC/audit layer.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient validates a loopback admin URL and reads the protected bearer token
// file. The token is held only in memory and sent in the Authorization header.
func NewClient(rawURL, tokenFile string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("management: admin URL must be a plain http:// loopback origin")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("management: admin URL must be loopback")
	}
	token, err := ReadBearerTokenFile(tokenFile)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: strings.TrimRight(rawURL, "/"), token: token,
		http: &http.Client{Timeout: 30 * time.Second}}, nil
}

// APIError is a bounded error from the admin service.
type APIError struct {
	Status    int
	Code      string
	Retryable bool
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("management API error status=%d code=%s", e.Status, e.Code)
}

// Call sends one management request. out may be nil. The response body is
// size-capped and only a closed error envelope is decoded on failure.
func (c *Client) Call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("management: admin API unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminResponse+1))
	if err != nil || len(raw) > maxAdminResponse {
		return errors.New("management: invalid admin response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e ErrorBody
		_ = json.Unmarshal(raw, &e)
		if e.Error.Code == "" {
			e.Error.Code = "http_error"
		}
		return &APIError{Status: resp.StatusCode, Code: e.Error.Code,
			Retryable: e.Error.Retryable, RequestID: e.RequestID}
	}
	if out == nil {
		return nil
	}
	var envelope struct {
		V    int             `json:"v"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.V != 1 {
		return errors.New("management: invalid admin response")
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return errors.New("management: invalid admin response")
	}
	return nil
}

func intQuery(key string, v int) url.Values {
	q := url.Values{}
	if v > 0 {
		q.Set(key, strconv.Itoa(v))
	}
	return q
}
