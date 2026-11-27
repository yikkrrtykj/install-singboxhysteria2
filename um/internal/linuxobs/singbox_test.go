package linuxobs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Synthetic httptest fixtures: these documents are hand-written mocks, not
// captures from a live sing-box. They exist to pin the read-only client's
// parsing and privacy behaviour.
const fixtureProxiesJSON = `{"proxies":{
	"GLOBAL":{"type":"Selector","now":"fixture-out","all":["fixture-out"]},
	"fixture-out":{"type":"Vless"}
}}`

const fixtureConnectionsJSON = `{
	"downloadTotal":300,
	"uploadTotal":200,
	"connections":[
		{
			"id":"fixture-connection-1",
			"metadata":{
				"network":"tcp",
				"type":"vless/vless-in",
				"sourceIP":"203.0.113.9",
				"destinationIP":"198.51.100.7",
				"host":"private.example",
				"processPath":"/usr/bin/fixture-agent"
			},
			"upload":100,
			"download":200,
			"chains":["fixture-out"],
			"rule":"final"
		},
		{
			"id":"fixture-connection-2",
			"metadata":{"network":"udp","type":"hysteria2/hy2-in"},
			"upload":50,
			"download":60,
			"chains":["fixture-out"]
		},
		{
			"id":"fixture-connection-3",
			"metadata":{"network":"tcp","type":"tun"},
			"upload":1,
			"download":2
		},
		{
			"id":"fixture-connection-4",
			"metadata":{"type":"bad tag!"},
			"upload":7,
			"download":8
		},
		{
			"id":"fixture-connection-5",
			"metadata":{},
			"upload":7,
			"download":8
		}
	]
}`

func TestNewSingBoxClientRejectsNonLoopbackOrigins(t *testing.T) {
	invalid := []string{
		"",
		"localhost:9090",
		"http://localhost:9090",
		"https://127.0.0.1:9090",
		"http://192.0.2.1:9090",
		"http://[2001:db8::1]:9090",
		"http://127.0.0.1",
		"http://127.0.0.1:0",
		"http://127.0.0.1:70000",
		"http://127.0.0.1:9090/",
		"http://127.0.0.1:9090/proxies",
		"http://127.0.0.1:9090?debug=1",
		"http://127.0.0.1:9090#fragment",
		"http://user:pass@127.0.0.1:9090",
		"http://127.0.0.1.evil.example:9090",
		"http://[::1%25lo]:9090",
	}
	for _, controller := range invalid {
		if _, err := NewSingBoxClient(SingBoxClientConfig{Controller: controller}); err == nil {
			t.Errorf("NewSingBoxClient accepted %q", controller)
		}
	}

	valid := []string{
		"http://127.0.0.1:9090",
		"http://127.0.0.2:1",
		"http://[::1]:8080",
	}
	for _, controller := range valid {
		if _, err := NewSingBoxClient(SingBoxClientConfig{Controller: controller}); err != nil {
			t.Errorf("NewSingBoxClient rejected %q: %v", controller, err)
		}
	}
	if _, err := NewSingBoxClient(SingBoxClientConfig{
		Controller: "http://127.0.0.1:9090",
		Secret:     "line\nbreak",
	}); err == nil {
		t.Error("NewSingBoxClient accepted a newline in the secret")
	}
}

func TestSingBoxClientDefaults(t *testing.T) {
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: "http://127.0.0.1:9090"})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	if client.maxBody != defaultSingBoxMaxBody {
		t.Fatalf("maxBody = %d, want %d", client.maxBody, defaultSingBoxMaxBody)
	}
	if client.client.Timeout != defaultSingBoxTimeout {
		t.Fatalf("timeout = %v, want %v", client.client.Timeout, defaultSingBoxTimeout)
	}
	if client.client.CheckRedirect == nil {
		t.Fatal("redirect policy is not pinned")
	}
	clamped, err := NewSingBoxClient(SingBoxClientConfig{
		Controller:   "http://127.0.0.1:9090",
		MaxBodyBytes: maxInt64Value,
	})
	if err != nil {
		t.Fatalf("NewSingBoxClient with huge body cap: %v", err)
	}
	if clamped.maxBody != maxSingBoxBodyLimit {
		t.Fatalf("huge body cap clamped to %d, want %d", clamped.maxBody, maxSingBoxBodyLimit)
	}
}

// TestSingBoxClientMapsSyntheticFixture verifies the fixed GET surface, the
// Bearer secret and the per-inbound projection from a mock server.
func TestSingBoxClientMapsSyntheticFixture(t *testing.T) {
	const secret = "fixture-bearer-not-for-output"
	var methods, paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/proxies":
			_, _ = w.Write([]byte(fixtureProxiesJSON))
		case "/connections":
			_, _ = w.Write([]byte(fixtureConnectionsJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL, Secret: secret})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	observation, err := client.ObserveSingBox(context.Background())
	if err != nil {
		t.Fatalf("ObserveSingBox: %v", err)
	}
	want := map[string]InboundEvidence{
		"vless-in": {ActiveConnections: 1, UplinkBytes: 100, DownlinkBytes: 200},
		"hy2-in":   {ActiveConnections: 1, UplinkBytes: 50, DownlinkBytes: 60},
		"tun":      {ActiveConnections: 1, UplinkBytes: 1, DownlinkBytes: 2},
	}
	if !reflect.DeepEqual(observation.Inbounds, want) {
		t.Fatalf("inbounds = %+v, want %+v", observation.Inbounds, want)
	}
	if !reflect.DeepEqual(methods, []string{http.MethodGet, http.MethodGet}) {
		t.Fatalf("methods = %v, want two GETs", methods)
	}
	if !reflect.DeepEqual(paths, []string{"/proxies", "/connections"}) {
		t.Fatalf("paths = %v, want the fixed allowlist", paths)
	}
	if rendered := fmt.Sprintf("%+v", observation); strings.Contains(rendered, secret) {
		t.Fatal("observation contains the API secret")
	}
}

// TestSingBoxClientRejectsMalformedDocuments covers every parse failure mode:
// each must be an honest ErrProbeUnavailable, never fabricated data.
func TestSingBoxClientRejectsMalformedDocuments(t *testing.T) {
	responses := []struct {
		name        string
		proxies     string
		connections string
	}{
		{"proxies invalid JSON", "{", `{"connections":[]}`},
		{"proxies missing member", `{}`, `{"connections":[]}`},
		{"proxies null", `{"proxies":null}`, `{"connections":[]}`},
		{"proxies wrong type", `{"proxies":[]}`, `{"connections":[]}`},
		{"connections invalid JSON", fixtureProxiesJSON, `{`},
		{"connections missing member", fixtureProxiesJSON, `{}`},
		{"connections wrong type", fixtureProxiesJSON, `{"connections":{}}`},
		{"connection string counter", fixtureProxiesJSON,
			`{"connections":[{"metadata":{"type":"vless/vless-in"},"upload":"100","download":1}]}`},
		{"connection missing counter", fixtureProxiesJSON,
			`{"connections":[{"metadata":{"type":"vless/vless-in"},"download":1}]}`},
		{"connection negative counter", fixtureProxiesJSON,
			`{"connections":[{"metadata":{"type":"vless/vless-in"},"upload":-1,"download":1}]}`},
	}
	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/proxies" {
					_, _ = w.Write([]byte(tc.proxies))
					return
				}
				_, _ = w.Write([]byte(tc.connections))
			}))
			defer server.Close()
			client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL})
			if err != nil {
				t.Fatalf("NewSingBoxClient: %v", err)
			}
			if _, err := client.ObserveSingBox(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
				t.Fatalf("ObserveSingBox error = %v, want ErrProbeUnavailable", err)
			}
		})
	}
}

func TestSingBoxClientEmptyConnectionsIsObservedZero(t *testing.T) {
	for _, connections := range []string{`{"connections":[]}`, `{"connections":null}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/proxies" {
				_, _ = w.Write([]byte(`{"proxies":{}}`))
				return
			}
			_, _ = w.Write([]byte(connections))
		}))
		client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL})
		if err != nil {
			server.Close()
			t.Fatalf("NewSingBoxClient: %v", err)
		}
		observation, err := client.ObserveSingBox(context.Background())
		server.Close()
		if err != nil {
			t.Fatalf("ObserveSingBox(%s): %v", connections, err)
		}
		if len(observation.Inbounds) != 0 {
			t.Fatalf("empty connection snapshot produced %+v", observation.Inbounds)
		}
	}
}

func TestSingBoxClientNeverFollowsRedirects(t *testing.T) {
	var followed bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer destination.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/proxies", http.StatusFound)
	}))
	defer redirector.Close()

	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: redirector.URL})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	if _, err := client.ObserveSingBox(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("redirect observation error = %v, want ErrProbeUnavailable", err)
	}
	if followed {
		t.Fatal("client followed a redirect")
	}
}

func TestSingBoxClientBodyCap(t *testing.T) {
	var connectionsRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connections" {
			connectionsRequested = true
		}
		_, _ = w.Write([]byte(strings.Repeat(" ", 256) + fixtureProxiesJSON))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL, MaxBodyBytes: 64})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	if _, err := client.ObserveSingBox(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("oversize observation error = %v, want ErrProbeUnavailable", err)
	}
	if connectionsRequested {
		t.Fatal("client continued after the proxies body cap violation")
	}
}

func TestSingBoxClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(fixtureProxiesJSON))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{
		Controller: server.URL,
		Timeout:    20 * time.Millisecond,
		Secret:     "fixture-timeout-secret",
	})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	_, err = client.ObserveSingBox(context.Background())
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("timeout observation error = %v, want ErrProbeUnavailable", err)
	}
	if strings.Contains(err.Error(), "fixture-timeout-secret") {
		t.Fatal("timeout error leaked the API secret")
	}
}

func TestSingBoxClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:3128")
	t.Setenv("NO_PROXY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			_, _ = w.Write([]byte(`{"proxies":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"connections":[]}`))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	if _, err := client.ObserveSingBox(context.Background()); err != nil {
		t.Fatalf("ObserveSingBox with proxy environment set: %v", err)
	}
}

func TestSingBoxClientSecretNeverLeaks(t *testing.T) {
	const secret = "fixture-secret-not-for-output"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("token=" + secret))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL, Secret: secret})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	_, err = client.ObserveSingBox(context.Background())
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("auth failure error = %v, want ErrProbeUnavailable", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("auth failure error leaked the API secret")
	}
}

func TestSingBoxClientWithoutSecretSendsNoAuthorization(t *testing.T) {
	var authorization string
	var sawHeader bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			sawHeader = true
			authorization = r.Header.Get("Authorization")
		}
		if r.URL.Path == "/proxies" {
			_, _ = w.Write([]byte(`{"proxies":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"connections":[]}`))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	if _, err := client.ObserveSingBox(context.Background()); err != nil {
		t.Fatalf("ObserveSingBox: %v", err)
	}
	if sawHeader {
		t.Fatalf("client sent an Authorization header without a configured secret: %q", authorization)
	}
}

// TestCollectorSingBoxFixtureDoesNotLeakMetadata runs the mock API through the
// real collector and asserts that connection metadata (addresses, hostnames,
// ids, process paths, chains) never reaches the report body.
func TestCollectorSingBoxFixtureDoesNotLeakMetadata(t *testing.T) {
	requireSupportedArch(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			_, _ = w.Write([]byte(fixtureProxiesJSON))
			return
		}
		_, _ = w.Write([]byte(fixtureConnectionsJSON))
	}))
	defer server.Close()
	client, err := NewSingBoxClient(SingBoxClientConfig{Controller: server.URL})
	if err != nil {
		t.Fatalf("NewSingBoxClient: %v", err)
	}
	collector := &Collector{
		ProcRoot:                writeTree(t, fakeProcFiles()),
		AgentVersion:            "1.2.3",
		DiskProbe:               &fakeDiskProbe{total: 42949672960, used: 10737418240},
		SingBoxProbe:            client,
		SingBoxSourceAuthorized: true,
	}
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"singbox_api"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	text := string(raw)
	for _, sentinel := range []string{
		"203.0.113.9", "198.51.100.7", "private.example", "fixture-connection",
		"fixture-out", "/usr/bin/fixture-agent", "fixtureProxiesJSON",
	} {
		if strings.Contains(text, sentinel) {
			t.Fatalf("snapshot leaked mock connection metadata %q", sentinel)
		}
	}
	body := unmarshalSnapshot(t, raw)
	wantProtocols := []protocolEntry{
		{Kind: "reality", InboundTag: "vless-in", State: "up", Reason: "ok", ObservedAt: testCollectedAt},
		{Kind: "hysteria2", InboundTag: "hy2-in", State: "up", Reason: "ok", ObservedAt: testCollectedAt},
	}
	if !reflect.DeepEqual(body.Protocols, wantProtocols) {
		t.Fatalf("protocols = %+v, want %+v", body.Protocols, wantProtocols)
	}
	requireInt64Ptr(t, "traffic[0].uplink", body.Traffic[0].UplinkTotalBytes, 100)
	requireInt64Ptr(t, "traffic[0].downlink", body.Traffic[0].DownlinkTotalBytes, 200)
	requireInt64Ptr(t, "traffic[1].uplink", body.Traffic[1].UplinkTotalBytes, 50)
	requireInt64Ptr(t, "traffic[1].downlink", body.Traffic[1].DownlinkTotalBytes, 60)
}

// TestParseConnectionsDocumentCornerCases covers the document grammar directly.
func TestParseConnectionsDocumentCornerCases(t *testing.T) {
	observation, err := parseConnectionsDocument([]byte(`{"connections":[]}`))
	if err != nil || observation.Inbounds == nil || len(observation.Inbounds) != 0 {
		t.Fatalf("empty connections = %+v, %v", observation, err)
	}
	observation, err = parseConnectionsDocument([]byte(`{"connections":null}`))
	if err != nil || len(observation.Inbounds) != 0 {
		t.Fatalf("null connections = %+v, %v", observation, err)
	}
	if _, err := parseConnectionsDocument([]byte(`{}`)); err == nil {
		t.Fatal("missing connections member was accepted")
	}

	// json.Number is not required: integer literals parse strictly, so a
	// fractional byte counter is malformed.
	if _, err := parseConnectionsDocument([]byte(
		`{"connections":[{"metadata":{"type":"vless/vless-in"},"upload":1.5,"download":1}]}`)); err == nil {
		t.Fatal("fractional byte counter was accepted")
	}
	// Unknown inbound shapes are skipped, never guessed.
	observation, err = parseConnectionsDocument([]byte(
		`{"connections":[{"metadata":{"type":"bad tag!"},"upload":1,"download":1},{"metadata":{},"upload":1,"download":1}]}`))
	if err != nil || len(observation.Inbounds) != 0 {
		t.Fatalf("unattributable connections = %+v, %v", observation, err)
	}
	// The JSON document is never echoed in errors.
	secretDocument := `{"connections":[{"metadata":{"type":"vless/vless-in"},"upload":"token=SECRET","download":1}]}`
	_, err = parseConnectionsDocument([]byte(secretDocument))
	if err == nil {
		t.Fatal("string counter was accepted")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal("parse error echoed API document content")
	}
}
