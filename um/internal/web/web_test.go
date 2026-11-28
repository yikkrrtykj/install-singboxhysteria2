package web_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

const testAccessIssuer = "https://team.cloudflareaccess.test"
const testAccessAudience = "um-c-test-audience"
const testAccessSubject = "access-subject-alice"

type accessFixture struct {
	private *rsa.PrivateKey
	kid     string
	server  *httptest.Server
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &accessFixture{private: key, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": f.kid, "use": "sig", "alg": "RS256", "n": n, "e": e,
		}}})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *accessFixture) token(t *testing.T, subject string, now time.Time) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": f.kid, "typ": "JWT"}
	claims := map[string]any{
		"iss": testAccessIssuer,
		"aud": testAccessAudience,
		"sub": subject,
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-10 * time.Second).Unix(),
		"iat": now.Add(-10 * time.Second).Unix(),
	}
	hraw, _ := json.Marshal(header)
	craw, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(hraw) + "." + enc(craw)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.private, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

type testWeb struct {
	handler  *web.Handler
	server   *httptest.Server
	client   *http.Client
	jwt      string
	access   *accessFixture
	master   []byte
	store    *store.Store
	userID   string
	password string
}

func newTestWeb(t *testing.T) *testWeb {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "center.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keyPath := filepath.Join(dir, "master.key")
	if err := umcauth.GenerateMasterKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	master, err := umcauth.LoadMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	access := newAccessFixture(t)
	verifier, err := umcauth.NewVerifier(umcauth.Config{Issuer: testAccessIssuer, Audience: testAccessAudience,
		JWKSURL: access.server.URL + "/jwks", AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := management.NewService(st)
	if err != nil {
		t.Fatal(err)
	}
	h, err := web.NewHandler(web.Config{Store: st, ManagementService: msg, Access: verifier,
		MasterKey: master, AllowedOrigins: []string{"https://web.example"}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	return &testWeb{handler: h, server: ts, client: client, jwt: access.token(t, testAccessSubject, time.Now()),
		access: access, master: master, store: st, password: "correct horse battery staple"}
}

func (tw *testWeb) request(t *testing.T, method, path, csrf string, body any, accessToken string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, tw.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func decodeMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return m
}

func TestUMCWebFullLoginTOTPSessionAndRBAC(t *testing.T) {
	tw := newTestWeb(t)
	hash, err := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	if err != nil {
		t.Fatal(err)
	}
	user, err := tw.store.BootstrapAuthUser(context.Background(), "web-admin", hash, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	tw.userID = user.UserID
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := tw.store.CreateEvent(context.Background(), eventA, "A", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	// Access JWT is required before any local login flow.
	status, raw := tw.request(t, http.MethodGet, "/auth/context", "", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("context without access status=%d body=%s", status, raw)
	}
	// No local session with a valid Access token.
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("API without local session status=%d body=%s", status, raw)
	}
	// Access alone cannot bypass local password/TOTP.
	status, raw = tw.request(t, http.MethodGet, "/auth/context", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("context status=%d body=%s", status, raw)
	}
	ctx := decodeMap(t, raw)
	preCSRF, _ := ctx["csrf_token"].(string)
	if preCSRF == "" {
		t.Fatalf("missing preauth csrf: %s", raw)
	}
	// Login CSRF is enforced.
	status, _ = tw.request(t, http.MethodPost, "/auth/login", "", map[string]any{"username": "web-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusForbidden {
		t.Fatalf("login without csrf status=%d", status)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/login", preCSRF,
		map[string]any{"username": "web-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, raw)
	}
	login := decodeMap(t, raw)
	if login["totp_setup_required"] != true || login["secret"] == nil {
		t.Fatalf("expected TOTP setup: %s", raw)
	}
	setupCSRF, _ := login["csrf_token"].(string)
	secret, _ := login["secret"].(string)
	if setupCSRF == "" || secret == "" {
		t.Fatalf("setup response missing fields: %s", raw)
	}
	code, err := umcauth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", setupCSRF, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP setup confirm status=%d body=%s", status, raw)
	}
	active := decodeMap(t, raw)
	csrf, _ := active["csrf_token"].(string)
	if active["authenticated"] != true || csrf == "" || active["recovery_codes"] == nil {
		t.Fatalf("active setup response=%s", raw)
	}
	// B4 management read through the Web bridge.
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(eventA)) {
		t.Fatalf("management read status=%d body=%s", status, raw)
	}
	// A B4 purge preview GET creates a durable receipt, so the Web bridge treats
	// it as a protected mutation and requires CSRF.
	status, _ = tw.request(t, http.MethodGet, "/api/v1/events/"+eventA+"/purge/preview", "", nil, tw.jwt)
	if status != http.StatusForbidden {
		t.Fatalf("purge preview without CSRF status=%d", status)
	}
	// Mutation requires CSRF; then succeeds through the same B4 API.
	status, _ = tw.request(t, http.MethodPost, "/api/v1/events", csrf,
		map[string]any{"event_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "display_name": "B"}, tw.jwt)
	if status != http.StatusCreated {
		t.Fatalf("management mutation without expected path status=%d", status)
	}
	status, _ = tw.request(t, http.MethodPost, "/api/v1/events", "",
		map[string]any{"event_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "display_name": "C"}, tw.jwt)
	if status != http.StatusForbidden {
		t.Fatalf("mutation without CSRF status=%d", status)
	}
	// Subject change invalidates the session even if the JWT is cryptographically valid.
	otherJWT := tw.access.token(t, "different-access-subject", time.Now())
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, otherJWT)
	if status != http.StatusUnauthorized {
		t.Fatalf("Access subject mismatch accepted session: status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodGet, "/web/api/users", "", nil, tw.jwt)
	if status != http.StatusOK || !bytes.Contains(raw, []byte("web-admin")) {
		t.Fatalf("user list status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodPost, "/web/api/users", csrf,
		map[string]any{"username": "event-a-admin", "role": "event_admin", "event_ids": []string{eventA}}, tw.jwt)
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", status, raw)
	}
	if !bytes.Contains(raw, []byte("initial_password")) {
		t.Fatalf("created user missing one-time password: %s", raw)
	}
	// A browser must not be able to use the local B4 bearer path.
	req, _ := http.NewRequest(http.MethodGet, tw.server.URL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer local-admin-token")
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("local bearer bypassed web Access: %d", resp.StatusCode)
	}
	// Logout revokes the current session.
	status, _ = tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
	if status != http.StatusNoContent {
		t.Fatalf("logout status=%d", status)
	}
	status, _ = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked session still accepted status=%d", status)
	}
	// TOTP replay: a fresh login using the already-consumed setup code fails. The
	// active session was revoked; obtain a new preauth challenge.
	status, raw = tw.request(t, http.MethodGet, "/auth/context", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("new context status=%d body=%s", status, raw)
	}
	preCSRF = decodeMap(t, raw)["csrf_token"].(string)
	status, raw = tw.request(t, http.MethodPost, "/auth/login", preCSRF,
		map[string]any{"username": "web-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("relogin status=%d body=%s", status, raw)
	}
	login = decodeMap(t, raw)
	pendingCSRF, _ := login["csrf_token"].(string)
	status, _ = tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("TOTP setup code replay status=%d", status)
	}
	nextCode, err := umcauth.TOTPCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": nextCode}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("fresh TOTP login status=%d body=%s", status, raw)
	}
}

func TestUMCLocalBearerAndAccessHeadersDoNotAuthorize(t *testing.T) {
	tw := newTestWeb(t)
	// Static/API without Access always fails even if loopback.
	req, _ := http.NewRequest(http.MethodGet, tw.server.URL+"/api/health", nil)
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health should be minimal anonymous: %d", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/health", "/auth/context", "/web/api/status"} {
		status, _ := tw.request(t, http.MethodGet, path, "", nil, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("%s without Access status=%d", path, status)
		}
	}
}

func TestUMCAccessJWTWrongSubjectDoesNotBindSession(t *testing.T) {
	// This test uses the same synthetic Access fixture implementation with a
	// second self-contained web instance to check local session subject binding.
	tw := newTestWeb(t)
	hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	if _, err := tw.store.BootstrapAuthUser(context.Background(), "web-admin", hash, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	status, raw := tw.request(t, http.MethodGet, "/auth/context", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("context=%d %s", status, raw)
	}
	// A forged email/role header is never identity.
	req, _ := http.NewRequest(http.MethodGet, tw.server.URL+"/api/v1/events", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", tw.jwt)
	req.Header.Set("Cf-Access-Authenticated-User-Email", "admin@example.com")
	req.Header.Set("X-Role", "platform_admin")
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("edge/email/role headers authorized without session: %d", resp.StatusCode)
	}
}

func TestUMCNoPublicBootstrapOrRegistration(t *testing.T) {
	tw := newTestWeb(t)
	for _, path := range []string{"/auth/bootstrap", "/auth/register", "/web/api/bootstrap"} {
		status, _ := tw.request(t, http.MethodPost, path, "", map[string]any{"username": "x"}, tw.jwt)
		if status != http.StatusNotFound && status != http.StatusUnauthorized {
			t.Fatalf("%s unexpectedly exposed: %d", path, status)
		}
	}
}
