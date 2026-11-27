package management

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	maxAuthFileBytes = 64 << 10
	maxBearerBytes   = 4096
)

// AuthConfig is the local, operator-owned admin credential file. It is loaded
// only by the server; the CLI reads a separate raw bearer token file and sends
// it in the Authorization header. Neither file is ever logged or persisted in
// SQLite. The file format is:
//
//	{"principals":[
//	  {"id":"local-platform-admin","role":"platform_admin","event_ids":[]},
//	  {"id":"event-a-operator","role":"event_admin","event_ids":["<uuid>"]}
//	],"tokens":[
//	  {"sha256":"<64 lowercase hex>","principal_id":"local-platform-admin"}
//	]}
//
// Roles are configured locally; a client can never self-report a role.
type AuthConfig struct {
	Principals []AuthPrincipal `json:"principals"`
	Tokens     []AuthToken     `json:"tokens"`
}

type AuthPrincipal struct {
	ID       string   `json:"id"`
	Role     Role     `json:"role"`
	EventIDs []string `json:"event_ids"`
}

type AuthToken struct {
	SHA256      string `json:"sha256"`
	PrincipalID string `json:"principal_id"`
}

// FileAuthenticator performs constant-time bearer-token authentication from a
// protected local file. It fails closed on any read/parse/config error.
type FileAuthenticator struct {
	principals map[string]Principal
	tokens     map[string]string // token sha256 -> principal id
}

// LoadFileAuthenticator reads and validates a 0600/0400 regular non-symlink
// JSON auth file.
func LoadFileAuthenticator(path string) (*FileAuthenticator, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("management: admin auth file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("management: admin auth file unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("management: admin auth file must be a regular non-symlink file")
	}
	if !protectedFileMode(path, info) {
		return nil, errors.New("management: admin auth file is not access-protected")
	}
	if info.Size() > maxAuthFileBytes {
		return nil, errors.New("management: admin auth file too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("management: admin auth file unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxAuthFileBytes+1))
	if err != nil {
		return nil, errors.New("management: admin auth file unavailable")
	}
	if len(raw) > maxAuthFileBytes {
		return nil, errors.New("management: admin auth file too large")
	}
	var cfg AuthConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, errors.New("management: admin auth file is invalid")
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	return newFileAuthenticator(cfg)
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("management: admin auth file has trailing or invalid JSON")
	}
	return nil
}

func newFileAuthenticator(cfg AuthConfig) (*FileAuthenticator, error) {
	if len(cfg.Principals) == 0 || len(cfg.Tokens) == 0 {
		return nil, errors.New("management: admin auth file requires principals and tokens")
	}
	a := &FileAuthenticator{
		principals: make(map[string]Principal, len(cfg.Principals)),
		tokens:     make(map[string]string, len(cfg.Tokens)),
	}
	for _, p := range cfg.Principals {
		if strings.TrimSpace(p.ID) == "" || len(p.ID) > 128 || controlRe.MatchString(p.ID) {
			return nil, errors.New("management: invalid principal id")
		}
		if err := validateEventScope(p.Role, p.EventIDs); err != nil {
			return nil, errors.New("management: invalid principal scope")
		}
		if _, exists := a.principals[p.ID]; exists {
			return nil, errors.New("management: duplicate principal id")
		}
		scope := make(map[string]bool, len(p.EventIDs))
		for _, id := range p.EventIDs {
			scope[id] = true
		}
		a.principals[p.ID] = Principal{ID: p.ID, Role: p.Role, EventIDs: scope}
	}
	for _, t := range cfg.Tokens {
		if !hex64Re.MatchString(t.SHA256) {
			return nil, errors.New("management: invalid token hash")
		}
		if _, ok := a.principals[t.PrincipalID]; !ok {
			return nil, errors.New("management: token references unknown principal")
		}
		if _, exists := a.tokens[t.SHA256]; exists {
			return nil, errors.New("management: duplicate token hash")
		}
		a.tokens[t.SHA256] = t.PrincipalID
	}
	return a, nil
}

// Authenticate extracts a bearer token from Authorization and resolves it to a
// trusted local principal. It never reads role/event headers or query values.
func (a *FileAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	if a == nil {
		return Principal{}, ErrUnauthenticated
	}
	header := r.Header.Get("Authorization")
	if len(header) > maxBearerBytes || !strings.HasPrefix(header, "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" || len(token) > maxBearerBytes {
		return Principal{}, ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	principalID, ok := a.tokens[hash]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	// Re-compare the computed hash with the stored key in constant time. The
	// map lookup itself is only an index; this avoids accidental early-exit
	// differences for a matching vs non-matching hash.
	matched := 0
	for stored := range a.tokens {
		matched |= subtle.ConstantTimeCompare([]byte(stored), []byte(hash))
	}
	if matched != 1 {
		return Principal{}, ErrUnauthenticated
	}
	p, ok := a.principals[principalID]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	return p, nil
}

// ReadBearerTokenFile reads a raw local CLI bearer token from a protected
// 0600/0400 regular non-symlink file. The raw token is returned only to the CLI
// transport; it is never printed or persisted.
func ReadBearerTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("management: admin token file unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!protectedFileMode(path, info) || info.Size() > maxBearerBytes {
		return "", errors.New("management: admin token file must be a 0600 regular non-symlink file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("management: admin token file unavailable")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > maxBearerBytes || controlRe.MatchString(token) {
		return "", errors.New("management: admin token is invalid")
	}
	return token, nil
}

// Bool is a helper used by JSON request types that need to distinguish an
// omitted field from an explicit false; it avoids pointer-heavy public DTOs.
type OptionalBool struct {
	Set   bool
	Value bool
}

func (b *OptionalBool) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return errors.New("management: null is not a valid switch value")
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	b.Set, b.Value = true, v
	return nil
}
