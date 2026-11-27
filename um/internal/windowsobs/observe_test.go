package windowsobs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func newTestObserver(t *testing.T, endpoint string, group string, routes map[Role]string, secret string) *Observer {
	t.Helper()
	observer, err := New(Profile{Controller: endpoint, Group: group, Routes: routes}, secret)
	if err != nil {
		t.Fatal(err)
	}
	return observer
}

func TestCollectShowsSelectedAndActiveRolesSeparately(t *testing.T) {
	const secret = "test-token-not-for-output"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Errorf("unexpected controller request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/proxies":
			_, _ = w.Write([]byte(`{
				"proxies": {
					"EVENT": {"now":"inner", "all":["inner"]},
					"inner": {"now":"backup", "all":["primary","backup"]},
					"primary": {"type":"Vless"},
					"backup": {"type":"Hysteria2"}
				}
			}`))
		case "/connections":
			_, _ = w.Write([]byte(`{"connections":[
				{"chains":["primary","inner","EVENT"],"metadata":{"host":"private.example"},"id":"connection-id"},
				{"chains":["EVENT","inner","backup"]},
				{"chains":["primary","unrelated"]},
				{"chains":["EVENT","unmapped-node"]},
				{"chains":["EVENT","primary","backup"]}
			]}`))
		default:
			t.Errorf("unexpected controller path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	observer := newTestObserver(t, server.URL, "EVENT",
		map[Role]string{AReality: "primary", BHY2: "backup"}, secret)
	snapshot := observer.Collect(context.Background())
	if snapshot.Selection.State != StateObserved || snapshot.Selection.Role != BHY2 ||
		snapshot.Selection.Reason != "" || snapshot.Selection.SampledAt == 0 {
		t.Fatalf("selection = %+v", snapshot.Selection)
	}
	if snapshot.Active.State != StateObserved || snapshot.Active.Reason != "" ||
		snapshot.Active.SampledAt == 0 || snapshot.Active.Unknown == nil || *snapshot.Active.Unknown != 2 ||
		!reflect.DeepEqual(snapshot.Active.Counts, map[Role]int{AReality: 1, BHY2: 1}) {
		t.Fatalf("active = %+v", snapshot.Active)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"EVENT", "inner", "primary", "backup", "private.example", "connection-id",
		"unmapped-node", secret, "test-token-not-for-output",
	} {
		if strings.Contains(string(body), raw) {
			t.Fatalf("raw controller value leaked: %q", raw)
		}
	}
}

func TestSixFrozenRouteTokens(t *testing.T) {
	want := []Role{"a_reality", "a_hy2", "b_reality", "b_hy2", "direct", "unknown"}
	tokens := Tokens()
	if !reflect.DeepEqual(tokens, want) {
		t.Fatalf("tokens = %v, want %v", tokens, want)
	}
	seen := make(map[Role]bool, len(tokens))
	for _, token := range tokens {
		if seen[token] {
			t.Fatalf("duplicate token %q", token)
		}
		seen[token] = true
	}
}

// TestDirectRequiresExplicitOperatorBinding is the NEG-PLAT-08 guard: the
// built-in DIRECT name (and any unmapped leaf) is never classified as direct
// without an explicit operator-local binding.
func TestDirectRequiresExplicitOperatorBinding(t *testing.T) {
	const directLeaf = "operator-direct-leaf"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{
				"EVENT":{"now":"` + directLeaf + `","all":["` + directLeaf + `","primary"]},
				"` + directLeaf + `":{"type":"Direct"},
				"primary":{"type":"Vless"}
			}}`))
		case "/connections":
			_, _ = w.Write([]byte(`{"connections":[
				{"chains":["` + directLeaf + `","EVENT"]},
				{"chains":["primary","EVENT"]}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("unbound leaf is unknown, never direct", func(t *testing.T) {
		observer := newTestObserver(t, server.URL, "EVENT",
			map[Role]string{AReality: "primary"}, "")
		snapshot := observer.Collect(context.Background())
		if snapshot.Selection.State != StateUnknown || snapshot.Selection.Role != "" ||
			snapshot.Selection.Reason != ReasonRouteUnbound {
			t.Fatalf("unbound selection = %+v", snapshot.Selection)
		}
		if snapshot.Active.State != StateObserved || snapshot.Active.Unknown == nil ||
			*snapshot.Active.Unknown != 1 || snapshot.Active.Counts[Direct] != 0 ||
			snapshot.Active.Counts[AReality] != 1 {
			t.Fatalf("unbound active = %+v", snapshot.Active)
		}
	})

	t.Run("explicit direct binding is honoured", func(t *testing.T) {
		observer := newTestObserver(t, server.URL, "EVENT",
			map[Role]string{AReality: "primary", Direct: directLeaf}, "")
		snapshot := observer.Collect(context.Background())
		if snapshot.Selection.State != StateObserved || snapshot.Selection.Role != Direct {
			t.Fatalf("bound selection = %+v", snapshot.Selection)
		}
		if snapshot.Active.State != StateObserved || snapshot.Active.Unknown == nil ||
			*snapshot.Active.Unknown != 0 || snapshot.Active.Counts[Direct] != 1 ||
			snapshot.Active.Counts[AReality] != 1 {
			t.Fatalf("bound active = %+v", snapshot.Active)
		}
	})
}

func TestUnknownTokenIsNotBindable(t *testing.T) {
	_, err := New(Profile{
		Controller: "http://127.0.0.1:9090",
		Group:      "EVENT",
		Routes:     map[Role]string{UnknownRoute: "leaf"},
	}, "")
	if err == nil {
		t.Fatal("unknown token was accepted as a route binding target")
	}
	_, err = New(Profile{
		Controller: "http://127.0.0.1:9090",
		Group:      "EVENT",
		Routes:     map[Role]string{Role("not_a_token"): "leaf"},
	}, "")
	if err == nil {
		t.Fatal("unknown role string was accepted")
	}
}

func TestAmbiguousChainIsUnknown(t *testing.T) {
	observer := Observer{group: "EVENT", roles: map[string]Role{"primary": AReality, "backup": BHY2}}
	active := observer.active(json.RawMessage(`[
		{"chains":["EVENT","primary","backup"]}
	]`))
	if active.State != StateObserved || active.Counts[AReality] != 0 || active.Counts[BHY2] != 0 ||
		active.Unknown == nil || *active.Unknown != 1 {
		t.Fatalf("ambiguous chain = %+v", active)
	}
}

func TestConnectionShapes(t *testing.T) {
	observer := Observer{group: "EVENT", roles: map[string]Role{"primary": AReality}}
	tests := []struct {
		name   string
		body   string
		want   string
		reason string
	}{
		{"missing", "", StateUnknown, ReasonMalformedResponse},
		{"empty", "[]", StateObserved, ""},
		{"idle", "null", StateObserved, ""},
		{"wrong type", "{}", StateUnknown, ReasonMalformedResponse},
		{"bad chain", `[{"chains":["EVENT", null]}]`, StateUnknown, ReasonMalformedResponse},
		{"missing chain", "[{}]", StateUnknown, ReasonMalformedResponse},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			active := observer.active(json.RawMessage(tc.body))
			if active.State != tc.want || active.Reason != tc.reason {
				t.Fatalf("active = %+v, want state %q reason %q", active, tc.want, tc.reason)
			}
			if tc.want == StateObserved {
				if !reflect.DeepEqual(active.Counts, map[Role]int{AReality: 0}) ||
					active.Unknown == nil || *active.Unknown != 0 {
					t.Fatal("idle response did not produce confirmed zeros")
				}
			} else if active.Counts != nil || active.Unknown != nil {
				t.Fatal("unknown response produced counts")
			}
		})
	}
}

func TestSelectionRequiresResolvableMembership(t *testing.T) {
	observer := Observer{group: "EVENT", roles: map[string]Role{"primary": AReality}}
	tests := []map[string]*proxy{
		{"EVENT": {Now: "inner", All: []string{"inner"}}, "inner": {Now: "EVENT", All: []string{"EVENT"}}},
		{"EVENT": {Now: "primary", All: []string{"other"}}, "primary": {}},
		{"EVENT": {Now: "primary", All: []string{"primary"}}, "primary": nil},
		{"EVENT": {Now: "primary", All: []string{"primary"}}},
	}
	for i, proxies := range tests {
		selection := observer.selected(proxies)
		if selection.State != StateUnknown || selection.Role != "" || selection.Reason != ReasonRouteUnbound {
			t.Errorf("case %d yielded %+v", i, selection)
		}
	}
}

// TestIndependentSampling proves the two sources are sampled separately: one
// can be observed while the other is unavailable, and selecting one source only
// performs its own request.
func TestIndependentSampling(t *testing.T) {
	const secret = "independent-secret"
	var mu sync.Mutex
	paths := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"EVENT":{"now":"primary","all":["primary"]},"primary":{}}}`))
		case "/connections":
			_, _ = w.Write([]byte(`{"connections":null}`))
		}
	}))
	defer server.Close()
	observer := newTestObserver(t, server.URL, "EVENT", map[Role]string{AReality: "primary"}, secret)

	selection := observer.ObserveSelection(context.Background())
	if selection.State != StateObserved || selection.Role != AReality {
		t.Fatalf("selection = %+v", selection)
	}
	mu.Lock()
	sawSelection := append([]string(nil), paths...)
	mu.Unlock()
	if !reflect.DeepEqual(sawSelection, []string{"/proxies"}) {
		t.Fatalf("selection sampling requested %v", sawSelection)
	}

	active := observer.ObserveActive(context.Background())
	if active.State != StateObserved || active.Unknown == nil || *active.Unknown != 0 {
		t.Fatalf("active = %+v", active)
	}
	mu.Lock()
	sawActive := append([]string(nil), paths...)
	mu.Unlock()
	if !reflect.DeepEqual(sawActive, []string{"/proxies", "/connections"}) {
		t.Fatalf("active sampling requested %v", sawActive)
	}
	if selection.SampledAt == 0 || active.SampledAt == 0 ||
		selection.SampledAt > active.SampledAt {
		t.Fatalf("independent sample timestamps: selection=%d active=%d", selection.SampledAt, active.SampledAt)
	}
}

func TestFailureReasons(t *testing.T) {
	t.Run("controller auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()
		observer := newTestObserver(t, server.URL, "EVENT", map[Role]string{AReality: "primary"}, "secret")
		snapshot := observer.Collect(context.Background())
		if snapshot.Selection.State != StateUnavailable || snapshot.Selection.Reason != ReasonControllerAuth {
			t.Fatalf("selection = %+v", snapshot.Selection)
		}
		if snapshot.Active.State != StateUnavailable || snapshot.Active.Reason != ReasonControllerAuth {
			t.Fatalf("active = %+v", snapshot.Active)
		}
	})

	t.Run("controller unusable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		observer := newTestObserver(t, server.URL, "EVENT", map[Role]string{AReality: "primary"}, "")
		snapshot := observer.Collect(context.Background())
		for _, state := range []struct {
			name   string
			state  string
			reason string
		}{
			{"selection", snapshot.Selection.State, snapshot.Selection.Reason},
			{"active", snapshot.Active.State, snapshot.Active.Reason},
		} {
			if state.state != StateUnavailable || state.reason != ReasonControllerUnreachable {
				t.Fatalf("%s = %+v", state.name, state)
			}
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		endpoint := server.URL
		server.Close()
		observer := newTestObserver(t, endpoint, "EVENT", map[Role]string{AReality: "primary"}, "")
		snapshot := observer.Collect(context.Background())
		if snapshot.Selection.State != StateUnavailable || snapshot.Selection.Reason != ReasonControllerUnreachable {
			t.Fatalf("selection = %+v", snapshot.Selection)
		}
		if snapshot.Active.State != StateUnavailable || snapshot.Active.Reason != ReasonControllerUnreachable {
			t.Fatalf("active = %+v", snapshot.Active)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{not json"))
		}))
		defer server.Close()
		observer := newTestObserver(t, server.URL, "EVENT", map[Role]string{AReality: "primary"}, "")
		snapshot := observer.Collect(context.Background())
		if snapshot.Selection.State != StateUnknown || snapshot.Selection.Reason != ReasonMalformedResponse {
			t.Fatalf("selection = %+v", snapshot.Selection)
		}
		if snapshot.Active.State != StateUnknown || snapshot.Active.Reason != ReasonMalformedResponse {
			t.Fatalf("active = %+v", snapshot.Active)
		}
	})
}

func TestControllerMustBeLiteralLoopbackAndNoRedirect(t *testing.T) {
	profile := Profile{Group: "EVENT", Routes: map[Role]string{AReality: "primary"}}
	for _, endpoint := range []string{
		"http://localhost:9090", "http://192.0.2.1:9090", "http://127.0.0.1",
		"http://127.0.0.1:9090?debug", "http://tester@127.0.0.1:9090",
		"http://127.0.0.1:9090/proxies", "http://127.0.0.1:9090#",
	} {
		profile.Controller = endpoint
		if _, err := New(profile, ""); err == nil {
			t.Errorf("accepted %s", endpoint)
		}
	}

	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("observer followed a redirect")
	}))
	defer destination.Close()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer controller.Close()
	profile.Controller = controller.URL
	observer, err := New(profile, "never-forward")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := observer.Collect(context.Background())
	if snapshot.Selection.State != StateUnavailable || snapshot.Active.State != StateUnavailable ||
		snapshot.Selection.Reason != ReasonControllerUnreachable ||
		snapshot.Active.Reason != ReasonControllerUnreachable {
		t.Fatalf("redirect returned a usable observation: %+v", snapshot)
	}
}

func TestOversizeSourceIsUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			_, _ = w.Write([]byte(strings.Repeat(" ", maxBody+1)))
			return
		}
		_, _ = w.Write([]byte(`{"connections":null}`))
	}))
	defer server.Close()
	observer := newTestObserver(t, server.URL, "EVENT", map[Role]string{AReality: "primary"}, "")
	snapshot := observer.Collect(context.Background())
	if snapshot.Selection.State != StateUnknown || snapshot.Selection.Reason != ReasonMalformedResponse {
		t.Fatalf("selection state = %+v", snapshot.Selection)
	}
	if snapshot.Active.State != StateObserved {
		t.Fatalf("active state = %+v", snapshot.Active)
	}
}

func TestRouteNamesMustBeDistinct(t *testing.T) {
	_, err := New(Profile{
		Controller: "http://127.0.0.1:9090",
		Group:      "EVENT",
		Routes:     map[Role]string{AReality: "same", Direct: "same"},
	}, "")
	if err == nil {
		t.Fatal("duplicate route name accepted")
	}
	if strings.Contains(err.Error(), "same") {
		t.Fatalf("error echoed a local route name: %v", err)
	}
}
