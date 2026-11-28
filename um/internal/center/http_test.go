package center

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// ---------------------------------------------------------------------------
// Test fixtures and helpers
// ---------------------------------------------------------------------------

const (
	testNodeID    = "11111111-1111-4111-8111-111111111111"
	testEventID   = "22222222-2222-4222-8222-222222222222"
	testKeyID     = "key-0123abcd"
	testKeyID2    = "key-89abcdef"
	testBootID    = "abcdef0123456789abcdef0123456789"
	testToken     = "bootstrap-token-abc123"
	testPubkey    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"                                            // base64url 32 B
	testNonce     = "AAAAAAAAAAAAAAAAAAAAAA"                                                                 // base64url 16 B
	testSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // base64url 64 B (86 chars)
	testSalt      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"                                            // 43 chars
)

var (
	testNow = time.Unix(1700000000, 0).UTC()

	testContractDir = func() string {
		abs, err := filepath.Abs("../../../docs/um/contracts/v1")
		if err != nil {
			panic(fmt.Sprintf("resolve contract dir: %v", err))
		}
		return abs
	}()
)

var (
	testSchemaOnce sync.Once
	testSchemas_   *schema.Set
	testSchemaErr  error
)

func testSchemas(t *testing.T) *schema.Set {
	t.Helper()
	testSchemaOnce.Do(func() {
		testSchemas_, testSchemaErr = schema.Load(testContractDir)
	})
	if testSchemaErr != nil {
		t.Fatalf("schema.Load(%q): %v", testContractDir, testSchemaErr)
	}
	return testSchemas_
}

func testSentAt() string { return strconv.FormatInt(testNow.Unix(), 10) }

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(testContractDir, "examples", name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example %q: %v", path, err)
	}
	return body
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buffer.Bytes()
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func requireStatus(t *testing.T, recorder *httptest.ResponseRecorder, want int) {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, want, recorder.Body.String())
	}
}

func requireJSONContentType(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func validateAgainstSchema(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := testSchemas(t).Validate(name, body); err != nil {
		t.Fatalf("body does not conform to %s: %v\nbody: %s", name, err, body)
	}
}

func decodeObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatalf("decode JSON object from %q: %v", body, err)
	}
	return object
}

func jsonInt(t *testing.T, value any) int64 {
	t.Helper()
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Int64()
		if err != nil {
			t.Fatalf("json number %q is not int64: %v", typed, err)
		}
		return number
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	default:
		t.Fatalf("value %v (%T) is not a JSON number", value, value)
		return 0
	}
}

// requireErrorResponse asserts status, content type, frozen error.schema.json
// conformance and the error/retryable/server_time values.
func requireErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantCode string, wantRetryable bool) {
	t.Helper()
	requireStatus(t, recorder, wantStatus)
	requireJSONContentType(t, recorder)
	body := recorder.Body.Bytes()
	validateAgainstSchema(t, schemaError, body)
	object := decodeObject(t, body)
	if got := object["error"]; got != wantCode {
		t.Fatalf("error = %v, want %q; body = %s", got, wantCode, body)
	}
	if got := object["retryable"]; got != wantRetryable {
		t.Fatalf("retryable = %v, want %v; body = %s", got, wantRetryable, body)
	}
	if got := jsonInt(t, object["server_time"]); got != testNow.Unix() {
		t.Fatalf("server_time = %d, want %d", got, testNow.Unix())
	}
	if got := jsonInt(t, object["v"]); got != 1 {
		t.Fatalf("v = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Fake Service
// ---------------------------------------------------------------------------

type fakeService struct {
	mu sync.Mutex

	enrollCalls int
	reportCalls int
	rotateCalls int
	configCalls int

	lastEnroll EnrollRequest
	lastReport ReportRequest
	lastRotate RotateRequest
	lastConfig ConfigRequest

	enrollFn func(context.Context, EnrollRequest) (EnrollResult, error)
	reportFn func(context.Context, ReportRequest) (ReportResult, error)
	rotateFn func(context.Context, RotateRequest) (RotateResult, error)
	configFn func(context.Context, ConfigRequest) (ConfigResult, error)
}

func (f *fakeService) Enroll(ctx context.Context, req EnrollRequest) (EnrollResult, error) {
	f.mu.Lock()
	f.enrollCalls++
	f.lastEnroll = req
	f.mu.Unlock()
	if f.enrollFn != nil {
		return f.enrollFn(ctx, req)
	}
	return defaultEnrollResult(), nil
}

func (f *fakeService) Report(ctx context.Context, req ReportRequest) (ReportResult, error) {
	f.mu.Lock()
	f.reportCalls++
	f.lastReport = req
	f.mu.Unlock()
	if f.reportFn != nil {
		return f.reportFn(ctx, req)
	}
	nextSeq := uint64(2)
	return ReportResult{
		ReportID:      req.ReportID,
		Result:        "accepted",
		NextSeq:       &nextSeq,
		ConfigVersion: 1,
		ServerTime:    testNow.Unix(),
	}, nil
}

func (f *fakeService) Rotate(ctx context.Context, req RotateRequest) (RotateResult, error) {
	f.mu.Lock()
	f.rotateCalls++
	f.lastRotate = req
	f.mu.Unlock()
	if f.rotateFn != nil {
		return f.rotateFn(ctx, req)
	}
	return RotateResult{
		PreviousKeyID: testKeyID,
		NewKeyID:      testKeyID2,
		ConfigVersion: 2,
		ServerTime:    testNow.Unix(),
	}, nil
}

func (f *fakeService) Config(ctx context.Context, req ConfigRequest) (ConfigResult, error) {
	f.mu.Lock()
	f.configCalls++
	f.lastConfig = req
	f.mu.Unlock()
	if f.configFn != nil {
		return f.configFn(ctx, req)
	}
	return defaultConfigResult(), nil
}

func (f *fakeService) counts() (enroll, report, rotate, config int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enrollCalls, f.reportCalls, f.rotateCalls, f.configCalls
}

func (f *fakeService) enrollSnapshot() EnrollRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastEnroll
}

func (f *fakeService) reportSnapshot() ReportRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReport
}

func (f *fakeService) rotateSnapshot() RotateRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRotate
}

func (f *fakeService) configSnapshot() ConfigRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastConfig
}

func defaultEnrollResult() EnrollResult {
	return EnrollResult{
		NodeID:         testNodeID,
		EventID:        testEventID,
		NodeClass:      "linux_vps",
		KeyID:          testKeyID,
		DeviceSalt:     testSalt,
		ConfigVersion:  1,
		CadenceSeconds: 60,
		ServerTime:     testNow.Unix(),
	}
}

func defaultConfigResult() ConfigResult {
	body := readExampleForFake()
	return ConfigResult{ConfigVersion: 1, Body: body, ServerTime: testNow.Unix()}
}

var (
	fakeConfigOnce sync.Once
	fakeConfigBody []byte
	fakeConfigErr  error
)

func readExampleForFake() []byte {
	fakeConfigOnce.Do(func() {
		fakeConfigBody, fakeConfigErr = os.ReadFile(filepath.Join(testContractDir, "examples", "agent-config.v1.json"))
	})
	if fakeConfigErr != nil {
		panic(fakeConfigErr)
	}
	return fakeConfigBody
}

// ---------------------------------------------------------------------------
// Server helpers and request builders
// ---------------------------------------------------------------------------

type serverOption func(*Config)

func withRateLimit(perSecond float64, burst int) serverOption {
	return func(cfg *Config) {
		cfg.RateLimitPerSecond = perSecond
		cfg.RateLimitBurst = burst
	}
}

func withCaps(compressed, decoded, enroll int64) serverOption {
	return func(cfg *Config) {
		cfg.MaxCompressedBody = compressed
		cfg.MaxDecodedBody = decoded
		cfg.MaxEnrollBody = enroll
	}
}

func withClock(now func() time.Time) serverOption {
	return func(cfg *Config) { cfg.Now = now }
}

func newTestServer(t *testing.T, service Service, options ...serverOption) *Server {
	t.Helper()
	cfg := Config{
		IngestAddr:         "127.0.0.1:0",
		AdminAddr:          "127.0.0.1:0",
		DBPath:             filepath.Join(t.TempDir(), "private", "center.db"),
		ContractDir:        testContractDir,
		Now:                func() time.Time { return testNow },
		RateLimitPerSecond: -1, // disabled unless a test opts in
	}
	for _, option := range options {
		option(&cfg)
	}
	server, err := NewServer(cfg, service)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func addEnrollHeaders(header http.Header) {
	header.Set(wire.HeaderProtocol, "1")
	header.Set(wire.HeaderPubkey, testPubkey)
	header.Set(wire.HeaderSentAt, testSentAt())
	header.Set(wire.HeaderNonce, testNonce)
	header.Set(wire.HeaderContentEnc, "identity")
	header.Set(wire.HeaderSignature, testSignature)
	header.Set(wire.HeaderContentType, "application/json")
	header.Set(wire.HeaderAuthorization, "Bearer "+testToken)
}

func addNodeHeaders(header http.Header) {
	header.Set(wire.HeaderProtocol, "1")
	header.Set(wire.HeaderNodeID, testNodeID)
	header.Set(wire.HeaderKeyID, testKeyID)
	header.Set(wire.HeaderBootGen, "1")
	header.Set(wire.HeaderBootID, testBootID)
	header.Set(wire.HeaderSeq, "1")
	header.Set(wire.HeaderSentAt, testSentAt())
	header.Set(wire.HeaderNonce, testNonce)
	header.Set(wire.HeaderContentEnc, "identity")
	header.Set(wire.HeaderSignature, testSignature)
	header.Set(wire.HeaderContentType, "application/json")
}

func newEnrollRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(body))
	addEnrollHeaders(request.Header)
	return request
}

func newNodeRequest(t *testing.T, path string, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	addNodeHeaders(request.Header)
	return request
}

func newReportRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	return newNodeRequest(t, "/v1/agent/report", body)
}

func newRotateRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	return newNodeRequest(t, "/v1/agent/rotate", body)
}

func newConfigRequest(t *testing.T) *http.Request {
	t.Helper()
	return newNodeRequest(t, "/v1/agent/config", []byte("{}"))
}

// encodedConfigRequest builds a config request whose on-the-wire body and
// signed/HTTP content encodings are explicit.
func encodedConfigRequest(t *testing.T, wireBody []byte, signedEncoding, httpEncoding string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/config", bytes.NewReader(wireBody))
	addNodeHeaders(request.Header)
	request.Header.Set(wire.HeaderContentEnc, signedEncoding)
	if httpEncoding == "" {
		request.Header.Del("Content-Encoding")
	} else {
		request.Header.Set("Content-Encoding", httpEncoding)
	}
	return request
}

func encodedEnrollRequest(t *testing.T, wireBody []byte, signedEncoding, httpEncoding string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(wireBody))
	addEnrollHeaders(request.Header)
	request.Header.Set(wire.HeaderContentEnc, signedEncoding)
	if httpEncoding == "" {
		request.Header.Del("Content-Encoding")
	} else {
		request.Header.Set("Content-Encoding", httpEncoding)
	}
	return request
}

func reportRequestFromExample(t *testing.T, exampleName string) (*http.Request, []byte) {
	t.Helper()
	body := readExample(t, exampleName)
	return newReportRequest(t, body), body
}

// ---------------------------------------------------------------------------
// Config / NewServer / contract loading
// ---------------------------------------------------------------------------

func TestConfigValidate(t *testing.T) {
	base := Config{
		IngestAddr:  "127.0.0.1:0",
		AdminAddr:   "127.0.0.1:0",
		DBPath:      "center.db",
		ContractDir: testContractDir,
	}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "missing ingest addr", mutate: func(c *Config) { c.IngestAddr = "" }, wantErr: true},
		{name: "blank ingest addr", mutate: func(c *Config) { c.IngestAddr = "   " }, wantErr: true},
		{name: "invalid ingest addr", mutate: func(c *Config) { c.IngestAddr = "no-port" }, wantErr: true},
		{name: "missing admin addr", mutate: func(c *Config) { c.AdminAddr = "" }, wantErr: true},
		{name: "invalid admin addr", mutate: func(c *Config) { c.AdminAddr = "127.0.0.1" }, wantErr: true},
		{name: "missing db path", mutate: func(c *Config) { c.DBPath = "" }, wantErr: true},
		{name: "missing contract dir", mutate: func(c *Config) { c.ContractDir = "" }, wantErr: true},
		{name: "blank contract dir", mutate: func(c *Config) { c.ContractDir = " \t " }, wantErr: true},
		{name: "negative compressed cap", mutate: func(c *Config) { c.MaxCompressedBody = -1 }, wantErr: true},
		{name: "negative decoded cap", mutate: func(c *Config) { c.MaxDecodedBody = -1 }, wantErr: true},
		{name: "negative enroll cap", mutate: func(c *Config) { c.MaxEnrollBody = -1 }, wantErr: true},
		{name: "enroll cap above decoded cap", mutate: func(c *Config) { c.MaxDecodedBody = 10; c.MaxEnrollBody = 11 }, wantErr: true},
		{name: "negative burst", mutate: func(c *Config) { c.RateLimitBurst = -1 }, wantErr: true},
		{name: "zero caps mean defaults", mutate: func(c *Config) { c.MaxCompressedBody = 0; c.MaxDecodedBody = 0; c.MaxEnrollBody = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.MaxCompressedBody != DefaultMaxCompressedBody || cfg.MaxDecodedBody != DefaultMaxDecodedBody ||
		cfg.MaxEnrollBody != DefaultMaxEnrollBody {
		t.Fatalf("caps = %d/%d/%d", cfg.MaxCompressedBody, cfg.MaxDecodedBody, cfg.MaxEnrollBody)
	}
	if cfg.Now == nil {
		t.Fatal("Now = nil, want time.Now fallback")
	}
	if cfg.RateLimitPerSecond != DefaultRateLimitPerSecond || cfg.RateLimitBurst != DefaultRateLimitBurst {
		t.Fatalf("rate limit defaults = %v/%d", cfg.RateLimitPerSecond, cfg.RateLimitBurst)
	}
}

func TestNewServerRejectsBadConfigAndNilService(t *testing.T) {
	cfg := Config{
		IngestAddr:  "127.0.0.1:0",
		AdminAddr:   "127.0.0.1:0",
		DBPath:      "center.db",
		ContractDir: testContractDir,
		Now:         func() time.Time { return testNow },
	}
	if _, err := NewServer(cfg, nil); err == nil {
		t.Fatal("NewServer(nil service) = nil error, want error")
	}
	bad := cfg
	bad.ContractDir = filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := NewServer(bad, &fakeService{}); err == nil {
		t.Fatal("NewServer(nonexistent ContractDir) = nil error, want error")
	}
	bad = cfg
	bad.IngestAddr = ""
	if _, err := NewServer(bad, &fakeService{}); err == nil {
		t.Fatal("NewServer(missing IngestAddr) = nil error, want error")
	}
}

func TestLoadContracts(t *testing.T) {
	cfg := Config{ContractDir: testContractDir}
	set, err := cfg.LoadContracts()
	if err != nil {
		t.Fatalf("LoadContracts: %v", err)
	}
	for _, name := range ContractSchemaNames {
		if !set.Has(name) {
			t.Fatalf("contract set is missing %q", name)
		}
	}
	expected := len(ContractSchemaNames)
	if info, statErr := os.Stat(filepath.Join(testContractDir, "rev7")); statErr == nil && info.IsDir() {
		expected += 2
		for _, name := range []string{"report-snapshot.rev7.schema.json", "agent-config.rev7.schema.json"} {
			if !set.Has(name) {
				t.Fatalf("contract set is missing rev-7 overlay %q", name)
			}
		}
	}
	if names := set.Names(); len(names) != expected {
		t.Fatalf("loaded %d schemas (%v), want %d", len(names), names, expected)
	}

	if _, err := (Config{}).LoadContracts(); err == nil {
		t.Fatal("LoadContracts(empty dir) = nil error, want error")
	}

	// A compile-able but partial contract directory must fail: the center
	// insists on all ten frozen schemas.
	partialDir := t.TempDir()
	ackFile, err := os.ReadFile(filepath.Join(testContractDir, "ack.schema.json"))
	if err != nil {
		t.Fatalf("read ack schema: %v", err)
	}
	if err := os.WriteFile(filepath.Join(partialDir, "ack.schema.json"), ackFile, 0o600); err != nil {
		t.Fatalf("write partial schema: %v", err)
	}
	if _, err := (Config{ContractDir: partialDir}).LoadContracts(); err == nil {
		t.Fatal("LoadContracts(partial dir) = nil error, want missing-schema error")
	}

	// A corrupt schema file must fail the prevalidation.
	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, "broken.schema.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write corrupt schema: %v", err)
	}
	if _, err := (Config{ContractDir: corruptDir}).LoadContracts(); err == nil {
		t.Fatal("LoadContracts(corrupt schema) = nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// Listener lifecycle and plane isolation
// ---------------------------------------------------------------------------

func TestServerStartShutdownRealListeners(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	if got := server.IngestAddr(); got != "127.0.0.1:0" {
		t.Fatalf("IngestAddr before Start = %q", got)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.Start(); err == nil {
		t.Fatal("second Start = nil error, want already-started error")
	}
	ingestAddr, adminAddr := server.IngestAddr(), server.AdminAddr()
	if ingestAddr == "127.0.0.1:0" || adminAddr == "127.0.0.1:0" {
		t.Fatalf("actual addresses not reported: ingest=%q admin=%q", ingestAddr, adminAddr)
	}
	if ingestAddr == adminAddr {
		t.Fatalf("ingest and admin share address %q", ingestAddr)
	}
	if _, _, err := net.SplitHostPort(ingestAddr); err != nil {
		t.Fatalf("ingest addr %q is not host:port: %v", ingestAddr, err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	health, err := http.Get("http://" + adminAddr + "/api/health") //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET admin health: %v", err)
	}
	healthBody, _ := io.ReadAll(health.Body)
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK || string(healthBody) != `{"ok":true,"service":"um-center"}` {
		t.Fatalf("admin health = %d %q", health.StatusCode, healthBody)
	}

	// Ingest plane has no admin routes.
	isolationResponse, err := http.Get("http://" + ingestAddr + "/api/health") //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET ingest /api/health: %v", err)
	}
	isolationBody, _ := io.ReadAll(isolationResponse.Body)
	_ = isolationResponse.Body.Close()
	if isolationResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("ingest /api/health = %d, want 404", isolationResponse.StatusCode)
	}
	validateAgainstSchema(t, schemaError, isolationBody)

	// A real enrollment over the real ingest listener reaches the Service.
	enrollBody := readExample(t, "enroll-request.v1.json")
	enrollRequest, err := http.NewRequest(http.MethodPost, "http://"+ingestAddr+"/v1/agent/enroll", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("new enroll request: %v", err)
	}
	addEnrollHeaders(enrollRequest.Header)
	enrollResponse, err := client.Do(enrollRequest)
	if err != nil {
		t.Fatalf("real enroll: %v", err)
	}
	realEnrollBody, _ := io.ReadAll(enrollResponse.Body)
	_ = enrollResponse.Body.Close()
	if enrollResponse.StatusCode != http.StatusOK {
		t.Fatalf("real enroll = %d: %s", enrollResponse.StatusCode, realEnrollBody)
	}
	validateAgainstSchema(t, schemaEnrollResponse, realEnrollBody)

	// Admin plane has no node routes.
	adminNodeRequest, err := http.NewRequest(http.MethodPost, "http://"+adminAddr+"/v1/agent/enroll", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("new admin node request: %v", err)
	}
	addEnrollHeaders(adminNodeRequest.Header)
	adminNodeResponse, err := client.Do(adminNodeRequest)
	if err != nil {
		t.Fatalf("POST admin node path: %v", err)
	}
	adminNodeBody, _ := io.ReadAll(adminNodeResponse.Body)
	_ = adminNodeResponse.Body.Close()
	if adminNodeResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("admin /v1/agent/enroll = %d, want 404", adminNodeResponse.StatusCode)
	}
	validateAgainstSchema(t, schemaError, adminNodeBody)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := http.Get("http://" + adminAddr + "/api/health"); err == nil { //nolint:noctx // test client
		t.Fatal("GET admin health after Shutdown succeeded, want connection error")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close after Shutdown: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPlaneIsolationHandlers(t *testing.T) {
	server := newTestServer(t, &fakeService{})

	// Ingest admin route: unknown.
	requireErrorResponse(t, serve(server.Handler(), httptest.NewRequest(http.MethodGet, "/api/health", nil)),
		http.StatusNotFound, "endpoint_not_found", false)
	// Admin node route: unknown.
	requireErrorResponse(t, serve(server.AdminHandler(), httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(nil))),
		http.StatusNotFound, "endpoint_not_found", false)
	requireErrorResponse(t, serve(server.AdminHandler(), httptest.NewRequest(http.MethodGet, "/v1/agent/config", nil)),
		http.StatusNotFound, "endpoint_not_found", false)

	// Admin health success.
	health := serve(server.AdminHandler(), httptest.NewRequest(http.MethodGet, "/api/health", nil))
	requireStatus(t, health, http.StatusOK)
	requireJSONContentType(t, health)
	if got := health.Body.String(); got != `{"ok":true,"service":"um-center"}` {
		t.Fatalf("health body = %q", got)
	}
	// Non-GET admin method.
	requireErrorResponse(t, serve(server.AdminHandler(), httptest.NewRequest(http.MethodPost, "/api/health", nil)),
		http.StatusMethodNotAllowed, "method_not_allowed", false)
}

func TestIngestRouting(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
	}{
		{name: "unknown path", method: http.MethodPost, path: "/v1/agent/revoke", wantStatus: 404, wantCode: "endpoint_not_found"},
		{name: "root", method: http.MethodPost, path: "/", wantStatus: 404, wantCode: "endpoint_not_found"},
		{name: "trailing slash", method: http.MethodPost, path: "/v1/agent/enroll/", wantStatus: 404, wantCode: "endpoint_not_found"},
		{name: "admin path on ingest", method: http.MethodGet, path: "/api/health", wantStatus: 404, wantCode: "endpoint_not_found"},
		{name: "GET enroll", method: http.MethodGet, path: "/v1/agent/enroll", wantStatus: 405, wantCode: "method_not_allowed"},
		{name: "PUT report", method: http.MethodPut, path: "/v1/agent/report", wantStatus: 405, wantCode: "method_not_allowed"},
		{name: "DELETE config", method: http.MethodDelete, path: "/v1/agent/config", wantStatus: 405, wantCode: "method_not_allowed"},
		{name: "HEAD rotate", method: http.MethodHead, path: "/v1/agent/rotate", wantStatus: 405, wantCode: "method_not_allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			requireErrorResponse(t, serve(server.Handler(), request), test.wantStatus, test.wantCode, false)
		})
	}
}

// ---------------------------------------------------------------------------
// Raw header cardinality
// ---------------------------------------------------------------------------

func TestHeaderCardinality(t *testing.T) {
	server := newTestServer(t, &fakeService{})

	t.Run("unknown X-UM header", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Set("X-UM-Extension", "1")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})

	t.Run("unknown X-UM header mixed case", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header["X-uM-bOgUs"] = []string{"1"}
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})

	t.Run("duplicate unknown X-UM header", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header["X-UM-Bogus"] = []string{"1", "2"}
		requireErrorResponse(t, serve(server.Handler(), request), 400, "duplicate_header", false)
	})

	duplicates := []string{
		wire.HeaderNonce, wire.HeaderSignature, wire.HeaderProtocol,
		wire.HeaderContentEnc, wire.HeaderNodeID, wire.HeaderAuthorization,
		"Content-Encoding",
	}
	for _, header := range duplicates {
		header := header
		t.Run("duplicate "+header, func(t *testing.T) {
			request := newConfigRequest(t)
			// Add twice: some of the watched headers are not otherwise present
			// on a config request.
			request.Header.Add(header, "again")
			request.Header.Add(header, "and-again")
			requireErrorResponse(t, serve(server.Handler(), request), 400, "duplicate_header", false)
		})
	}

	t.Run("case-variant duplicate nonce", func(t *testing.T) {
		request := newConfigRequest(t)
		// http.Header.Set canonicalizes its key; insert a differently-cased raw
		// map key to simulate a peer that sent both spellings.
		request.Header["X-UM-NONCE"] = []string{"AAAAAAAAAAAAAAAAAAAAAA"}
		requireErrorResponse(t, serve(server.Handler(), request), 400, "duplicate_header", false)
	})

	t.Run("unrelated headers accepted", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Set("User-Agent", "um-agent/1.0")
		request.Header.Set("Accept", "application/json")
		requireStatus(t, serve(server.Handler(), request), http.StatusOK)
	})
}

func TestMissingRequiredHeaders(t *testing.T) {
	server := newTestServer(t, &fakeService{})

	enrollHeaders := []string{
		wire.HeaderProtocol, wire.HeaderPubkey, wire.HeaderSentAt,
		wire.HeaderNonce, wire.HeaderContentEnc, wire.HeaderSignature,
	}
	for _, header := range enrollHeaders {
		header := header
		t.Run("enroll missing "+header, func(t *testing.T) {
			body := readExample(t, "enroll-request.v1.json")
			request := newEnrollRequest(t, body)
			request.Header.Del(header)
			requireErrorResponse(t, serve(server.Handler(), request), 400, "missing_header", false)
		})
	}

	nodeHeaders := []string{
		wire.HeaderProtocol, wire.HeaderNodeID, wire.HeaderKeyID,
		wire.HeaderBootGen, wire.HeaderBootID, wire.HeaderSeq,
		wire.HeaderSentAt, wire.HeaderNonce, wire.HeaderContentEnc,
		wire.HeaderSignature,
	}
	for _, header := range nodeHeaders {
		header := header
		t.Run("config missing "+header, func(t *testing.T) {
			request := newConfigRequest(t)
			request.Header.Del(header)
			requireErrorResponse(t, serve(server.Handler(), request), 400, "missing_header", false)
		})
	}

	t.Run("missing content type", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Del(wire.HeaderContentType)
		requireErrorResponse(t, serve(server.Handler(), request), 400, "missing_header", false)
	})

	t.Run("empty required header value is invalid not missing", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Set(wire.HeaderNonce, "")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
}

func TestHeaderGrammar(t *testing.T) {
	server := newTestServer(t, &fakeService{})

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "protocol 2", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderProtocol, "2") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "protocol non numeric", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderProtocol, "one") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "sent-at leading zero", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSentAt, "01") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "sent-at sign", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSentAt, "+1") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "sent-at text", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSentAt, "now") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "nonce wrong length", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderNonce, "AAAA") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "node id uppercase", mutate: func(r *http.Request) {
			r.Header.Set(wire.HeaderNodeID, strings.ToUpper("0f3d7c2a-8b41-4a6e-9c55-2d7e1b9a4c60"))
		}, wantStatus: 400, wantCode: "invalid_header"},
		{name: "node id not uuid", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderNodeID, "not-a-uuid") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "key id shape", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderKeyID, "key-XYZ") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "boot gen zero", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderBootGen, "0") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "boot gen leading zero", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderBootGen, "01") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "boot gen above max numeric", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderBootGen, "9223372036854775807") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "boot id short", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderBootID, "abcd") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "seq zero", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSeq, "0") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "seq above max numeric", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSeq, "9223372036854775807") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "signature malformed", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSignature, "AAAA") }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "signature non base64url", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderSignature, strings.Repeat("+", 86)) }, wantStatus: 400, wantCode: "invalid_header"},
		{name: "encoding deflate", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderContentEnc, "deflate") }, wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "encoding stacked", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderContentEnc, "gzip, identity") }, wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "encoding empty", mutate: func(r *http.Request) { r.Header.Set(wire.HeaderContentEnc, "") }, wantStatus: 400, wantCode: "unsupported_encoding"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := newConfigRequest(t)
			test.mutate(request)
			requireErrorResponse(t, serve(server.Handler(), request), test.wantStatus, test.wantCode, false)
		})
	}

	t.Run("enroll pubkey malformed", func(t *testing.T) {
		body := readExample(t, "enroll-request.v1.json")
		request := newEnrollRequest(t, body)
		request.Header.Set(wire.HeaderPubkey, "short")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
}

func TestCrossEndpointHeaders(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	enrollBody := readExample(t, "enroll-request.v1.json")

	t.Run("enroll carries node id", func(t *testing.T) {
		request := newEnrollRequest(t, enrollBody)
		request.Header.Set(wire.HeaderNodeID, testNodeID)
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
	t.Run("enroll carries seq", func(t *testing.T) {
		request := newEnrollRequest(t, enrollBody)
		request.Header.Set(wire.HeaderSeq, "1")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
	t.Run("node request carries pubkey", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Set(wire.HeaderPubkey, testPubkey)
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
	t.Run("node request carries authorization", func(t *testing.T) {
		request := newConfigRequest(t)
		request.Header.Set(wire.HeaderAuthorization, "Bearer "+testToken)
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_header", false)
	})
}

// ---------------------------------------------------------------------------
// Content-Type and content encoding
// ---------------------------------------------------------------------------

func TestContentType(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	enrollBody := readExample(t, "enroll-request.v1.json")

	tests := []struct {
		name       string
		value      string
		remove     bool
		wantStatus int
		wantCode   string
	}{
		{name: "exact", value: "application/json", wantStatus: 200},
		{name: "surrounding whitespace", value: " application/json ", wantStatus: 200},
		{name: "charset parameter", value: "application/json; charset=utf-8", wantStatus: 400, wantCode: "invalid_header"},
		{name: "wrong type", value: "text/plain", wantStatus: 400, wantCode: "invalid_header"},
		{name: "uppercase", value: "Application/JSON", wantStatus: 400, wantCode: "invalid_header"},
		{name: "empty", value: "", wantStatus: 400, wantCode: "invalid_header"},
		{name: "missing", remove: true, wantStatus: 400, wantCode: "missing_header"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := newEnrollRequest(t, enrollBody)
			if test.remove {
				request.Header.Del(wire.HeaderContentType)
			} else {
				request.Header.Set(wire.HeaderContentType, test.value)
			}
			recorder := serve(server.Handler(), request)
			if test.wantStatus == 200 {
				requireStatus(t, recorder, 200)
				return
			}
			requireErrorResponse(t, recorder, test.wantStatus, test.wantCode, false)
		})
	}
}

func TestEncodingConsistency(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	enrollBody := readExample(t, "enroll-request.v1.json")
	compressedEnroll := gzipBytes(t, enrollBody)

	tests := []struct {
		name       string
		wireBody   []byte
		signed     string
		httpHeader string // empty = omit HTTP Content-Encoding
		wantStatus int
		wantCode   string
	}{
		{name: "identity absent HTTP header", wireBody: enrollBody, signed: "identity", httpHeader: "", wantStatus: 200},
		{name: "identity matching HTTP header", wireBody: enrollBody, signed: "identity", httpHeader: "identity", wantStatus: 200},
		{name: "identity but HTTP gzip", wireBody: enrollBody, signed: "identity", httpHeader: "gzip", wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "identity with empty HTTP header", wireBody: enrollBody, signed: "identity", httpHeader: " ", wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "gzip without HTTP header", wireBody: compressedEnroll, signed: "gzip", httpHeader: "", wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "gzip mismatched HTTP identity", wireBody: compressedEnroll, signed: "gzip", httpHeader: "identity", wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "gzip matching", wireBody: compressedEnroll, signed: "gzip", httpHeader: "gzip", wantStatus: 200},
		{name: "gzip case mismatch", wireBody: compressedEnroll, signed: "gzip", httpHeader: "GZip", wantStatus: 400, wantCode: "unsupported_encoding"},
		{name: "signed uppercase token", wireBody: compressedEnroll, signed: "GZIP", httpHeader: "GZIP", wantStatus: 400, wantCode: "unsupported_encoding"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := encodedEnrollRequest(t, test.wireBody, test.signed, test.httpHeader)
			recorder := serve(server.Handler(), request)
			if test.wantStatus == 200 {
				requireStatus(t, recorder, 200)
				return
			}
			requireErrorResponse(t, recorder, test.wantStatus, test.wantCode, false)
		})
	}
}

func TestGzipDecoding(t *testing.T) {
	server := newTestServer(t, &fakeService{})

	t.Run("valid single member config", func(t *testing.T) {
		request := encodedConfigRequest(t, gzipBytes(t, []byte("{}")), "gzip", "gzip")
		recorder := serve(server.Handler(), request)
		requireStatus(t, recorder, 200)
		if got := recorder.Body.Bytes(); !bytes.Equal(got, readExampleForFake()) {
			t.Fatalf("config response = %q, want example bytes", got)
		}
	})
	t.Run("trailing garbage", func(t *testing.T) {
		body := append(gzipBytes(t, []byte("{}")), []byte("trailing-garbage")...)
		request := encodedConfigRequest(t, body, "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "unsupported_encoding", false)
	})
	t.Run("concatenated members", func(t *testing.T) {
		body := append(gzipBytes(t, []byte("{}")), gzipBytes(t, []byte("{}"))...)
		request := encodedConfigRequest(t, body, "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "unsupported_encoding", false)
	})
	t.Run("truncated member", func(t *testing.T) {
		full := gzipBytes(t, []byte("{}"))
		request := encodedConfigRequest(t, full[:len(full)-4], "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "unsupported_encoding", false)
	})
	t.Run("not gzip", func(t *testing.T) {
		request := encodedConfigRequest(t, []byte("{}"), "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "unsupported_encoding", false)
	})
	t.Run("decoded config body still must be exactly braces", func(t *testing.T) {
		request := encodedConfigRequest(t, gzipBytes(t, []byte(`{"v":1}`)), "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_request", false)
	})
}

func TestBodyCaps(t *testing.T) {
	t.Run("default enroll cap", func(t *testing.T) {
		server := newTestServer(t, &fakeService{})
		request := newEnrollRequest(t, bytes.Repeat([]byte("a"), int(DefaultMaxEnrollBody)+1))
		requireErrorResponse(t, serve(server.Handler(), request), 413, "payload_too_large", false)
	})
	t.Run("custom decoded identity cap", func(t *testing.T) {
		server := newTestServer(t, &fakeService{}, withCaps(4096, 100, 100))
		request := newNodeRequest(t, "/v1/agent/config", bytes.Repeat([]byte("a"), 101))
		requireErrorResponse(t, serve(server.Handler(), request), 413, "payload_too_large", false)
	})
	t.Run("custom compressed cap", func(t *testing.T) {
		server := newTestServer(t, &fakeService{}, withCaps(32, 4096, 4096))
		payload := make([]byte, 512)
		for index := range payload {
			payload[index] = byte(index*37 + 11)
		}
		compressed := gzipBytes(t, payload)
		if len(compressed) <= 32 {
			t.Fatalf("fixture compressed size %d unexpectedly fits cap", len(compressed))
		}
		request := encodedConfigRequest(t, compressed, "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 413, "payload_too_large", false)
	})
	t.Run("decoded gzip cap", func(t *testing.T) {
		server := newTestServer(t, &fakeService{}, withCaps(4096, 64, 64))
		request := encodedConfigRequest(t, gzipBytes(t, bytes.Repeat([]byte("a"), 200)), "gzip", "gzip")
		requireErrorResponse(t, serve(server.Handler(), request), 413, "payload_too_large", false)
	})
	t.Run("enroll cap independent of decoded cap", func(t *testing.T) {
		server := newTestServer(t, &fakeService{}, withCaps(4096, 512, 64))
		request := newEnrollRequest(t, bytes.Repeat([]byte("a"), 100))
		requireErrorResponse(t, serve(server.Handler(), request), 413, "payload_too_large", false)
	})
}

// ---------------------------------------------------------------------------
// Config request body shape and strict JSON
// ---------------------------------------------------------------------------

func TestConfigBodyShape(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	invalidBodies := []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "whitespace", body: []byte(" ")},
		{name: "newline braces", body: []byte("\n{}")},
		{name: "trailing space", body: []byte("{} ")},
		{name: "object member", body: []byte(`{"v":1}`)},
		{name: "array", body: []byte("[]")},
		{name: "null", body: []byte("null")},
	}
	for _, test := range invalidBodies {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := newNodeRequest(t, "/v1/agent/config", test.body)
			requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_request", false)
		})
	}
	t.Run("exactly braces", func(t *testing.T) {
		requireStatus(t, serve(server.Handler(), newConfigRequest(t)), 200)
	})
}

func TestStrictJSONGrammar(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	tests := []struct {
		name string
		body []byte
	}{
		{name: "duplicate top level key", body: []byte(`{"v":1,"v":1}`)},
		{name: "duplicate nested key", body: []byte(`{"v":1,"host":{"os":"linux","os":"windows"}}`)},
		{name: "trailing data", body: []byte(`{"v":1}{"v":1}`)},
		{name: "malformed", body: []byte(`{`)},
		{name: "empty body", body: nil},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// The enroll path has no config-shape pre-check, so strict JSON is
			// the first body check that can fail.
			request := newEnrollRequest(t, test.body)
			recorder := serve(server.Handler(), request)
			requireErrorResponse(t, recorder, 400, "invalid_request", false)
		})
	}

	// A duplicate-key body must be rejected before any schema validation or
	// Service call.
	service := &fakeService{}
	fresh := newTestServer(t, service)
	recorder := serve(fresh.Handler(), newEnrollRequest(t, []byte(`{"v":1,"v":1}`)))
	requireErrorResponse(t, recorder, 400, "invalid_request", false)
	if enrollCalls, _, _, _ := service.counts(); enrollCalls != 0 {
		t.Fatalf("Service.Enroll called %d times for duplicate-key body", enrollCalls)
	}
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestEnrollSuccess(t *testing.T) {
	body := readExample(t, "enroll-request.v1.json")
	service := &fakeService{}
	server := newTestServer(t, service)
	recorder := serve(server.Handler(), newEnrollRequest(t, body))
	requireStatus(t, recorder, http.StatusOK)
	requireJSONContentType(t, recorder)
	validateAgainstSchema(t, schemaEnrollResponse, recorder.Body.Bytes())

	object := decodeObject(t, recorder.Body.Bytes())
	if got := object["node_id"]; got != testNodeID {
		t.Fatalf("node_id = %v", got)
	}
	if got := object["event_id"]; got != testEventID {
		t.Fatalf("event_id = %v", got)
	}
	if got := object["node_class"]; got != "linux_vps" {
		t.Fatalf("node_class = %v", got)
	}
	if got := object["key_id"]; got != testKeyID {
		t.Fatalf("key_id = %v", got)
	}
	if got := object["device_salt"]; got != testSalt {
		t.Fatalf("device_salt = %v", got)
	}
	if got := jsonInt(t, object["config_version"]); got != 1 {
		t.Fatalf("config_version = %d", got)
	}
	if got := jsonInt(t, object["cadence_seconds"]); got != 60 {
		t.Fatalf("cadence_seconds = %d", got)
	}
	if got := jsonInt(t, object["server_time"]); got != testNow.Unix() {
		t.Fatalf("server_time = %d", got)
	}
	spki, present := object["center_spki_sha256"]
	if !present {
		t.Fatal("center_spki_sha256 member is not present (schema requires the member, nullable)")
	}
	if spki != nil {
		t.Fatalf("center_spki_sha256 = %v, want null", spki)
	}

	received := service.enrollSnapshot()
	if received.Fields.Endpoint != wire.Enroll {
		t.Fatalf("Fields.Endpoint = %q", received.Fields.Endpoint)
	}
	if received.Fields.Protocol != "1" || received.Fields.Encoding != "identity" {
		t.Fatalf("Fields protocol/encoding = %q/%q", received.Fields.Protocol, received.Fields.Encoding)
	}
	if received.Fields.SentAt != testSentAt() || received.Fields.Nonce != testNonce {
		t.Fatalf("Fields sent-at/nonce = %q/%q", received.Fields.SentAt, received.Fields.Nonce)
	}
	if received.Fields.PublicKey != testPubkey {
		t.Fatalf("Fields.PublicKey = %q", received.Fields.PublicKey)
	}
	if received.Token != testToken {
		t.Fatalf("Token = %q", received.Token)
	}
	if received.Signature != testSignature {
		t.Fatalf("Signature = %q", received.Signature)
	}
	if received.BodySHA256 != sha256Hex(body) {
		t.Fatalf("BodySHA256 = %q, want %q", received.BodySHA256, sha256Hex(body))
	}
	if !bytes.Equal(received.Body, body) {
		t.Fatal("Service body differs from request body")
	}
	if received.Now != testNow.Unix() {
		t.Fatalf("Now = %d, want %d", received.Now, testNow.Unix())
	}
}

func TestEnrollCenterSPKI(t *testing.T) {
	service := &fakeService{enrollFn: func(context.Context, EnrollRequest) (EnrollResult, error) {
		result := defaultEnrollResult()
		result.CenterSPKISHA256 = testSalt
		return result, nil
	}}
	server := newTestServer(t, service)
	body := readExample(t, "enroll-request.v1.json")
	recorder := serve(server.Handler(), newEnrollRequest(t, body))
	requireStatus(t, recorder, 200)
	validateAgainstSchema(t, schemaEnrollResponse, recorder.Body.Bytes())
	object := decodeObject(t, recorder.Body.Bytes())
	if got := object["center_spki_sha256"]; got != testSalt {
		t.Fatalf("center_spki_sha256 = %v, want %q", got, testSalt)
	}
}

func TestEnrollAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		auth       string
		remove     bool
		wantStatus int
		wantCode   string
		wantCalls  int
	}{
		{name: "missing", remove: true, wantStatus: 401, wantCode: "unauthorized", wantCalls: 0},
		{name: "wrong scheme", auth: "Basic abc", wantStatus: 401, wantCode: "unauthorized", wantCalls: 0},
		{name: "bearer without token", auth: "Bearer", wantStatus: 401, wantCode: "unauthorized", wantCalls: 0},
		{name: "bearer blank token", auth: "Bearer    ", wantStatus: 401, wantCode: "unauthorized", wantCalls: 0},
		{name: "token with space", auth: "Bearer abc def", wantStatus: 401, wantCode: "unauthorized", wantCalls: 0},
		{name: "valid lower scheme", auth: "bearer " + testToken, wantStatus: 200, wantCalls: 1},
		{name: "valid", auth: "Bearer " + testToken, wantStatus: 200, wantCalls: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{}
			server := newTestServer(t, service)
			body := readExample(t, "enroll-request.v1.json")
			request := newEnrollRequest(t, body)
			if test.remove {
				request.Header.Del(wire.HeaderAuthorization)
			} else {
				request.Header.Set(wire.HeaderAuthorization, test.auth)
			}
			recorder := serve(server.Handler(), request)
			if test.wantStatus == 200 {
				requireStatus(t, recorder, 200)
			} else {
				requireErrorResponse(t, recorder, test.wantStatus, test.wantCode, false)
			}
			if enrollCalls, _, _, _ := service.counts(); enrollCalls != test.wantCalls {
				t.Fatalf("Service.Enroll calls = %d, want %d", enrollCalls, test.wantCalls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

func reportFields(t *testing.T) wire.Fields {
	t.Helper()
	fields := wire.Fields{
		Endpoint: wire.Report,
		Protocol: "1",
		Encoding: "identity",
		NodeID:   testNodeID,
		KeyID:    testKeyID,
		BootGen:  "1",
		BootID:   testBootID,
		Sequence: "1",
		SentAt:   testSentAt(),
		Nonce:    testNonce,
	}
	if err := fields.Validate(); err != nil {
		t.Fatalf("fixture fields invalid: %v", err)
	}
	return fields
}

func TestReportSuccess(t *testing.T) {
	request, body := reportRequestFromExample(t, "report-snapshot.v1.json")
	var example struct {
		ReportID    string `json:"report_id"`
		CollectedAt int64  `json:"collected_at"`
		Type        string `json:"type"`
	}
	if err := json.Unmarshal(body, &example); err != nil {
		t.Fatalf("decode snapshot example: %v", err)
	}
	service := &fakeService{}
	server := newTestServer(t, service)
	recorder := serve(server.Handler(), request)
	requireStatus(t, recorder, http.StatusOK)
	requireJSONContentType(t, recorder)
	validateAgainstSchema(t, schemaAck, recorder.Body.Bytes())

	object := decodeObject(t, recorder.Body.Bytes())
	if got := object["report_id"]; got != example.ReportID {
		t.Fatalf("report_id = %v, want %q", got, example.ReportID)
	}
	if got := object["result"]; got != "accepted" {
		t.Fatalf("result = %v", got)
	}
	if got := jsonInt(t, object["next_seq"]); got != 2 {
		t.Fatalf("next_seq = %d", got)
	}
	if _, present := object["next_seq"]; !present {
		t.Fatal("next_seq member missing")
	}
	if got, present := object["retry_after_s"]; !present || got != nil {
		t.Fatalf("retry_after_s = %v (present=%v), want explicit null", got, present)
	}

	received := service.reportSnapshot()
	if received.ReportType != "snapshot" || received.ReportID != example.ReportID {
		t.Fatalf("Service ReportType/ReportID = %q/%q", received.ReportType, received.ReportID)
	}
	if received.CollectedAt != example.CollectedAt {
		t.Fatalf("CollectedAt = %d, want %d", received.CollectedAt, example.CollectedAt)
	}
	if received.BodySHA256 != sha256Hex(body) {
		t.Fatalf("BodySHA256 = %q", received.BodySHA256)
	}
	if received.Signature != testSignature {
		t.Fatalf("Signature = %q", received.Signature)
	}
	wantFingerprint, err := wire.Fingerprint(reportFields(t), body)
	if err != nil {
		t.Fatalf("fixture fingerprint: %v", err)
	}
	if received.Fingerprint != wantFingerprint {
		t.Fatalf("Fingerprint = %q, want %q", received.Fingerprint, wantFingerprint)
	}
	if received.Now != testNow.Unix() {
		t.Fatalf("Now = %d", received.Now)
	}
}

func TestReportAllTypesDispatch(t *testing.T) {
	tests := []struct {
		example string
		want    string
	}{
		{example: "report-snapshot.v1.json", want: "snapshot"},
		{example: "report-metrics.v1.json", want: "metrics"},
		{example: "report-events.v1.json", want: "events"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.want, func(t *testing.T) {
			service := &fakeService{}
			server := newTestServer(t, service)
			request, _ := reportRequestFromExample(t, test.example)
			recorder := serve(server.Handler(), request)
			requireStatus(t, recorder, 200)
			validateAgainstSchema(t, schemaAck, recorder.Body.Bytes())
			if received := service.reportSnapshot(); received.ReportType != test.want {
				t.Fatalf("ReportType = %q, want %q", received.ReportType, test.want)
			}
		})
	}
}

func TestReportEnvelopeValidation(t *testing.T) {
	validUUID := "5a0d9e3c-1b2f-4c8a-9d6e-7f3a1c5b2e90"
	tests := []struct {
		name string
		body string
	}{
		{name: "empty object", body: `{}`},
		{name: "missing type", body: `{"v":1,"report_id":"` + validUUID + `","collected_at":1}`},
		{name: "unknown type", body: `{"v":1,"type":"bogus","report_id":"` + validUUID + `","collected_at":1}`},
		{name: "wrong version", body: `{"v":2,"type":"snapshot","report_id":"` + validUUID + `","collected_at":1}`},
		{name: "missing report id", body: `{"v":1,"type":"snapshot","collected_at":1}`},
		{name: "uppercase report id", body: `{"v":1,"type":"snapshot","report_id":"5A0D9E3C-1B2F-4C8A-9D6E-7F3A1C5B2E90","collected_at":1}`},
		{name: "non v4 report id", body: `{"v":1,"type":"snapshot","report_id":"5a0d9e3c-1b2f-8c8a-9d6e-7f3a1c5b2e90","collected_at":1}`},
		{name: "missing collected at", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `"}`},
		{name: "fractional collected at", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":1.5}`},
		{name: "exponent collected at", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":1e3}`},
		{name: "negative collected at", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":-1}`},
		{name: "collected at above schema max", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":1000000000001}`},
		{name: "leading zero collected at", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":01}`},
		{name: "collected at string", body: `{"v":1,"type":"snapshot","report_id":"` + validUUID + `","collected_at":"1"}`},
		{name: "array body", body: `[]`},
		{name: "null body", body: `null`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{}
			server := newTestServer(t, service)
			request := newReportRequest(t, []byte(test.body))
			requireErrorResponse(t, serve(server.Handler(), request), 400, "invalid_request", false)
			if _, reportCalls, _, _ := service.counts(); reportCalls != 0 {
				t.Fatalf("Service.Report called %d times for invalid envelope", reportCalls)
			}
		})
	}
}

func TestReportSchemaMismatch(t *testing.T) {
	snapshot := readExample(t, "report-snapshot.v1.json")
	// Keep the discriminator-valid envelope but declare a different type: the
	// per-type schema must reject the mismatched body.
	mismatched := bytes.Replace(snapshot, []byte(`"type":"snapshot"`), []byte(`"type":"metrics"`), 1)
	if bytes.Equal(mismatched, snapshot) {
		t.Fatal("fixture rewrite failed")
	}
	service := &fakeService{}
	server := newTestServer(t, service)
	requireErrorResponse(t, serve(server.Handler(), newReportRequest(t, mismatched)), 400, "invalid_request", false)
	if _, reportCalls, _, _ := service.counts(); reportCalls != 0 {
		t.Fatalf("Service.Report called %d times for schema mismatch", reportCalls)
	}
}

func TestReportNextSeqNull(t *testing.T) {
	service := &fakeService{reportFn: func(context.Context, ReportRequest) (ReportResult, error) {
		return ReportResult{Result: "accepted", NextSeq: nil, ConfigVersion: 1, ServerTime: testNow.Unix()}, nil
	}}
	server := newTestServer(t, service)
	request, body := reportRequestFromExample(t, "report-snapshot.v1.json")
	recorder := serve(server.Handler(), request)
	requireStatus(t, recorder, 200)
	validateAgainstSchema(t, schemaAck, recorder.Body.Bytes())
	object := decodeObject(t, recorder.Body.Bytes())
	if got, present := object["next_seq"]; !present || got != nil {
		t.Fatalf("next_seq = %v (present=%v), want explicit null", got, present)
	}
	var example struct {
		ReportID string `json:"report_id"`
	}
	if err := json.Unmarshal(body, &example); err != nil {
		t.Fatalf("decode example: %v", err)
	}
	if got := object["report_id"]; got != example.ReportID {
		t.Fatalf("report_id fallback = %v, want %q", got, example.ReportID)
	}
}

func TestReportRetryAfter(t *testing.T) {
	retry := 30
	service := &fakeService{reportFn: func(context.Context, ReportRequest) (ReportResult, error) {
		return ReportResult{
			Result: "accepted", NextSeq: nil, ConfigVersion: 1,
			ServerTime: testNow.Unix(), RetryAfterS: &retry,
		}, nil
	}}
	server := newTestServer(t, service)
	request, _ := reportRequestFromExample(t, "report-snapshot.v1.json")
	recorder := serve(server.Handler(), request)
	requireStatus(t, recorder, 200)
	validateAgainstSchema(t, schemaAck, recorder.Body.Bytes())
	object := decodeObject(t, recorder.Body.Bytes())
	if got := jsonInt(t, object["retry_after_s"]); got != 30 {
		t.Fatalf("retry_after_s = %d, want 30", got)
	}
}

// ---------------------------------------------------------------------------
// Rotate
// ---------------------------------------------------------------------------

func rotateFields(t *testing.T) wire.Fields {
	t.Helper()
	fields := wire.Fields{
		Endpoint: wire.Rotate,
		Protocol: "1",
		Encoding: "identity",
		NodeID:   testNodeID,
		KeyID:    testKeyID,
		BootGen:  "1",
		BootID:   testBootID,
		Sequence: "1",
		SentAt:   testSentAt(),
		Nonce:    testNonce,
	}
	if err := fields.Validate(); err != nil {
		t.Fatalf("fixture fields invalid: %v", err)
	}
	return fields
}

func TestRotateSuccess(t *testing.T) {
	body := readExample(t, "rotate-request.v1.json")
	service := &fakeService{}
	server := newTestServer(t, service)
	recorder := serve(server.Handler(), newRotateRequest(t, body))
	requireStatus(t, recorder, 200)
	requireJSONContentType(t, recorder)
	validateAgainstSchema(t, schemaRotateResponse, recorder.Body.Bytes())

	object := decodeObject(t, recorder.Body.Bytes())
	if got := object["node_id"]; got != testNodeID {
		t.Fatalf("node_id = %v", got)
	}
	if got := object["previous_key_id"]; got != testKeyID {
		t.Fatalf("previous_key_id = %v", got)
	}
	if got := object["new_key_id"]; got != testKeyID2 {
		t.Fatalf("new_key_id = %v", got)
	}
	if got := jsonInt(t, object["config_version"]); got != 2 {
		t.Fatalf("config_version = %d", got)
	}

	received := service.rotateSnapshot()
	if received.Fields.Endpoint != wire.Rotate || received.Fields.KeyID != testKeyID {
		t.Fatalf("Fields = %+v", received.Fields)
	}
	if received.BodySHA256 != sha256Hex(body) || received.Signature != testSignature {
		t.Fatalf("BodySHA256/Signature = %q/%q", received.BodySHA256, received.Signature)
	}
	wantFingerprint, err := wire.Fingerprint(rotateFields(t), body)
	if err != nil {
		t.Fatalf("fixture fingerprint: %v", err)
	}
	if received.Fingerprint != wantFingerprint {
		t.Fatalf("Fingerprint = %q, want %q", received.Fingerprint, wantFingerprint)
	}
}

func TestRotateReplayVerbatim(t *testing.T) {
	persisted := readExample(t, "rotate-response.v1.json")
	service := &fakeService{rotateFn: func(context.Context, RotateRequest) (RotateResult, error) {
		return RotateResult{Response: persisted}, nil
	}}
	server := newTestServer(t, service)
	body := readExample(t, "rotate-request.v1.json")
	recorder := serve(server.Handler(), newRotateRequest(t, body))
	requireStatus(t, recorder, 200)
	requireJSONContentType(t, recorder)
	if got := recorder.Body.Bytes(); !bytes.Equal(got, persisted) {
		t.Fatalf("replayed rotate body = %q, want exact persisted bytes %q", got, persisted)
	}
	validateAgainstSchema(t, schemaRotateResponse, recorder.Body.Bytes())
}

func TestRotateInvalidBodyAndBadReplay(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	t.Run("schema invalid rotate body", func(t *testing.T) {
		requireErrorResponse(t, serve(server.Handler(), newRotateRequest(t, []byte(`{"v":2,"new_pubkey":"x"}`))),
			400, "invalid_request", false)
	})
	t.Run("persisted response not contract shaped", func(t *testing.T) {
		badServer := newTestServer(t, &fakeService{rotateFn: func(context.Context, RotateRequest) (RotateResult, error) {
			return RotateResult{Response: []byte(`not-json`)}, nil
		}})
		body := readExample(t, "rotate-request.v1.json")
		recorder := serve(badServer.Handler(), newRotateRequest(t, body))
		requireErrorResponse(t, recorder, 503, "storage_unavailable", true)
		if strings.Contains(recorder.Body.String(), "not-json") {
			t.Fatalf("response leaked internal bytes: %s", recorder.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Config success
// ---------------------------------------------------------------------------

func TestConfigSuccess(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	recorder := serve(server.Handler(), newConfigRequest(t))
	requireStatus(t, recorder, 200)
	requireJSONContentType(t, recorder)
	validateAgainstSchema(t, schemaAgentConfig, recorder.Body.Bytes())
	if got := recorder.Body.Bytes(); !bytes.Equal(got, readExampleForFake()) {
		t.Fatalf("config body = %q, want example bytes", got)
	}

	received := service.configSnapshot()
	if received.Fields.Endpoint != wire.Config || received.Fields.NodeID != testNodeID {
		t.Fatalf("Fields = %+v", received.Fields)
	}
	if !bytes.Equal(received.Body, []byte("{}")) {
		t.Fatalf("Body = %q, want {}", received.Body)
	}
	if received.BodySHA256 != sha256Hex([]byte("{}")) {
		t.Fatalf("BodySHA256 = %q", received.BodySHA256)
	}
	wantFingerprint, err := wire.Fingerprint(wire.Fields{
		Endpoint: wire.Config, Protocol: "1", Encoding: "identity",
		NodeID: testNodeID, KeyID: testKeyID, BootGen: "1", BootID: testBootID,
		Sequence: "1", SentAt: testSentAt(), Nonce: testNonce,
	}, []byte("{}"))
	if err != nil {
		t.Fatalf("fixture fingerprint: %v", err)
	}
	if received.Fingerprint != wantFingerprint {
		t.Fatalf("Fingerprint = %q, want %q", received.Fingerprint, wantFingerprint)
	}
}

func TestConfigInvalidServiceBody(t *testing.T) {
	tests := []struct {
		name string
		fn   func(context.Context, ConfigRequest) (ConfigResult, error)
	}{
		{name: "nil body", fn: func(context.Context, ConfigRequest) (ConfigResult, error) {
			return ConfigResult{ConfigVersion: 1}, nil
		}},
		{name: "non JSON", fn: func(context.Context, ConfigRequest) (ConfigResult, error) {
			return ConfigResult{Body: []byte("not-json")}, nil
		}},
		{name: "schema invalid", fn: func(context.Context, ConfigRequest) (ConfigResult, error) {
			return ConfigResult{Body: []byte(`{}`)}, nil
		}},
		{name: "over response cap", fn: func(context.Context, ConfigRequest) (ConfigResult, error) {
			return ConfigResult{Body: bytes.Repeat([]byte("a"), int(DefaultMaxConfigResponse)+1)}, nil
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, &fakeService{configFn: test.fn})
			recorder := serve(server.Handler(), newConfigRequest(t))
			requireErrorResponse(t, recorder, 503, "storage_unavailable", true)
		})
	}
}

// ---------------------------------------------------------------------------
// Service error mapping and leakage
// ---------------------------------------------------------------------------

func TestServiceErrorMapping(t *testing.T) {
	retryCtxErr := fmt.Errorf("wrapped: %w", context.Canceled)
	tests := []struct {
		name          string
		err           error
		wantStatus    int
		wantCode      string
		wantRetryable bool
		wantRetryHdr  bool
	}{
		{name: "closed APIError unauthorized", err: NewAPIError(401, "bad_signature", false), wantStatus: 401, wantCode: "bad_signature"},
		{name: "closed APIError conflict", err: NewAPIError(409, "report_conflict", false), wantStatus: 409, wantCode: "report_conflict"},
		{name: "wrapped APIError", err: fmt.Errorf("outer: %w", NewAPIError(401, "revoked_key", false)), wantStatus: 401, wantCode: "revoked_key"},
		{name: "rate limited", err: NewAPIError(429, "rate_limited", true), wantStatus: 429, wantCode: "rate_limited", wantRetryable: true, wantRetryHdr: true},
		{name: "context canceled", err: context.Canceled, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true},
		{name: "wrapped context deadline", err: retryCtxErr, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true},
		{name: "unknown error", err: errors.New("dial tcp 10.1.2.3:5432: SECRET-PATH"), wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true},
		{name: "invalid status sanitized", err: NewAPIError(200, "invalid_request", false), wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true},
		{name: "invalid code sanitized", err: NewAPIError(400, "exception_text", false), wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{configFn: func(context.Context, ConfigRequest) (ConfigResult, error) {
				return ConfigResult{}, test.err
			}}
			server := newTestServer(t, service)
			recorder := serve(server.Handler(), newConfigRequest(t))
			requireErrorResponse(t, recorder, test.wantStatus, test.wantCode, test.wantRetryable)
			if test.wantRetryHdr && recorder.Header().Get("Retry-After") == "" {
				t.Fatal("429 response has no Retry-After header")
			}
			if !test.wantRetryHdr && recorder.Header().Get("Retry-After") != "" {
				t.Fatalf("unexpected Retry-After header: %q", recorder.Header().Get("Retry-After"))
			}
			for _, secret := range []string{"SECRET-PATH", "dial tcp", "exception_text", "outer:", "wrapped:"} {
				if strings.Contains(recorder.Body.String(), secret) {
					t.Fatalf("error body leaked internal text %q: %s", secret, recorder.Body.String())
				}
			}
		})
	}
}

func TestInvalidServiceSuccessBodyBecomes503(t *testing.T) {
	tests := []struct {
		name   string
		server func(t *testing.T) *Server
		req    func(t *testing.T) *http.Request
	}{
		{
			name: "enroll invalid result",
			server: func(t *testing.T) *Server {
				return newTestServer(t, &fakeService{enrollFn: func(context.Context, EnrollRequest) (EnrollResult, error) {
					return EnrollResult{NodeID: "not-a-uuid", EventID: testEventID, NodeClass: "linux_vps", KeyID: testKeyID, DeviceSalt: testSalt, ConfigVersion: 1, CadenceSeconds: 60}, nil
				}})
			},
			req: func(t *testing.T) *http.Request {
				return newEnrollRequest(t, readExample(t, "enroll-request.v1.json"))
			},
		},
		{
			name: "report invalid ack result",
			server: func(t *testing.T) *Server {
				return newTestServer(t, &fakeService{reportFn: func(context.Context, ReportRequest) (ReportResult, error) {
					return ReportResult{Result: "bogus", ConfigVersion: 1, ServerTime: testNow.Unix()}, nil
				}})
			},
			req: func(t *testing.T) *http.Request {
				request, _ := reportRequestFromExample(t, "report-snapshot.v1.json")
				return request
			},
		},
		{
			name: "rotate invalid result",
			server: func(t *testing.T) *Server {
				return newTestServer(t, &fakeService{rotateFn: func(context.Context, RotateRequest) (RotateResult, error) {
					return RotateResult{PreviousKeyID: "bad", NewKeyID: "bad", ConfigVersion: 1, ServerTime: testNow.Unix()}, nil
				}})
			},
			req: func(t *testing.T) *http.Request {
				return newRotateRequest(t, readExample(t, "rotate-request.v1.json"))
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			recorder := serve(test.server(t).Handler(), test.req(t))
			requireErrorResponse(t, recorder, 503, "storage_unavailable", true)
		})
	}
}

func TestErrorResponseMapping(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		now           int64
		wantStatus    int
		wantCode      string
		wantRetryable bool
		wantServer    int64
	}{
		{name: "nil error", err: nil, now: 123, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true, wantServer: 123},
		{name: "api error", err: NewAPIError(401, "unauthorized", false), now: 7, wantStatus: 401, wantCode: "unauthorized", wantServer: 7},
		{name: "unknown", err: errors.New("boom secret"), now: 9, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true, wantServer: 9},
		{name: "negative now clamps", err: nil, now: -42, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true, wantServer: 0},
		{name: "deadline", err: context.DeadlineExceeded, now: 5, wantStatus: 503, wantCode: "storage_unavailable", wantRetryable: true, wantServer: 5},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			status, body := ErrorResponse(test.err, test.now)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d", status, test.wantStatus)
			}
			validateAgainstSchema(t, schemaError, body)
			object := decodeObject(t, body)
			if got := object["error"]; got != test.wantCode {
				t.Fatalf("error = %v, want %q", got, test.wantCode)
			}
			if got := object["retryable"]; got != test.wantRetryable {
				t.Fatalf("retryable = %v, want %v", got, test.wantRetryable)
			}
			if got := jsonInt(t, object["server_time"]); got != test.wantServer {
				t.Fatalf("server_time = %d, want %d", got, test.wantServer)
			}
			if strings.Contains(string(body), "boom") || strings.Contains(string(body), "secret") {
				t.Fatalf("error body leaked error text: %s", body)
			}
		})
	}
}

func TestClosedErrorVocabulary(t *testing.T) {
	closed := []string{
		"invalid_request", "method_not_allowed", "endpoint_not_found", "missing_header",
		"duplicate_header", "invalid_header", "unsupported_encoding", "unauthorized",
		"unknown_node", "revoked_key", "bad_signature", "stale_timestamp", "replay",
		"nonce_reuse", "sequence_conflict", "identity_mismatch", "report_conflict",
		"token_invalid", "token_expired", "token_used", "token_scope_mismatch",
		"rate_limited", "payload_too_large", "unsupported_version", "upgrade_required",
		"storage_unavailable", "rotation_in_progress", "rotation_expired",
		"stale_boot_generation", "boot_identity_conflict", "platform_mismatch",
	}
	for _, code := range closed {
		if !IsClosedErrorCode(code) {
			t.Fatalf("IsClosedErrorCode(%q) = false, want true", code)
		}
	}
	for _, code := range []string{"", "internal_error", "Invalid_Request", "exception"} {
		if IsClosedErrorCode(code) {
			t.Fatalf("IsClosedErrorCode(%q) = true, want false", code)
		}
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func TestRateLimitPerIP(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service, withRateLimit(2, 2))
	for index := 0; index < 2; index++ {
		recorder := serve(server.Handler(), newConfigRequest(t))
		requireStatus(t, recorder, 200)
	}
	third := serve(server.Handler(), newConfigRequest(t))
	requireErrorResponse(t, third, 429, "rate_limited", true)
	retryAfter := third.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("429 response has no Retry-After header")
	}
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil || seconds < 1 {
		t.Fatalf("Retry-After = %q, want positive integer", retryAfter)
	}
	// The limiter is keyed by peer IP, not globally: a different peer still has
	// its own bucket and is allowed.
	otherPeer := newConfigRequest(t)
	otherPeer.RemoteAddr = "198.51.100.7:9000"
	requireStatus(t, serve(server.Handler(), otherPeer), 200)
}

func TestRateLimiterUnit(t *testing.T) {
	clock := testNow
	limiter := newRateLimiter(1, 1, func() time.Time { return clock })
	if allowed, _ := limiter.allow("a"); !allowed {
		t.Fatal("first request denied")
	}
	if allowed, wait := limiter.allow("a"); allowed || wait < 1 {
		t.Fatalf("second request = (%v,%d), want denied with wait >= 1", allowed, wait)
	}
	clock = clock.Add(time.Second)
	if allowed, _ := limiter.allow("a"); !allowed {
		t.Fatal("refilled request denied")
	}

	disabled := newRateLimiter(-1, 1, func() time.Time { return clock })
	for index := 0; index < 100; index++ {
		if allowed, _ := disabled.allow("a"); !allowed {
			t.Fatal("disabled limiter denied a request")
		}
	}

	bounded := newRateLimiter(1, 1, func() time.Time { return clock })
	for index := 0; index < maxRateLimitBuckets+10; index++ {
		bounded.allow(fmt.Sprintf("peer-%d", index))
	}
	bounded.mu.Lock()
	size := len(bounded.buckets)
	bounded.mu.Unlock()
	if size > maxRateLimitBuckets {
		t.Fatalf("limiter bucket map size = %d, want <= %d", size, maxRateLimitBuckets)
	}
}
