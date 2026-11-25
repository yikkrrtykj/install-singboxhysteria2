package windowsobs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

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

	observer, err := New(Profile{
		Controller: server.URL,
		Group:      "EVENT",
		Routes:     map[Role]string{AReality: "primary", BHY2: "backup"},
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := observer.Collect(context.Background())
	if snapshot.Selection != (Selection{State: observed, Role: BHY2}) {
		t.Fatalf("selection = %+v", snapshot.Selection)
	}
	if snapshot.Active.State != observed || snapshot.Active.Unknown == nil || *snapshot.Active.Unknown != 2 ||
		!reflect.DeepEqual(snapshot.Active.Counts, map[Role]int{AReality: 1, BHY2: 1}) {
		t.Fatalf("active = %+v", snapshot.Active)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"EVENT", "inner", "primary", "backup", "private.example", "connection-id", "unmapped-node", secret} {
		if strings.Contains(string(body), raw) {
			t.Fatalf("raw controller value leaked: %q", raw)
		}
	}
}

func TestConnectionShapes(t *testing.T) {
	observer := Observer{group: "EVENT", roles: map[string]Role{"primary": AReality}}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"missing", "", unknown},
		{"empty", "[]", observed},
		{"idle", "null", observed},
		{"wrong type", "{}", unknown},
		{"bad chain", `[{"chains":["EVENT", null]}]`, unknown},
		{"missing chain", "[{}]", unknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			active := observer.active(json.RawMessage(tc.body))
			if active.State != tc.want {
				t.Fatalf("state = %q, want %q", active.State, tc.want)
			}
			if tc.want == observed {
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
		if selection := observer.selected(proxies); selection.State != unknown || selection.Role != "" {
			t.Errorf("case %d yielded %+v", i, selection)
		}
	}
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
	if snapshot.Selection.State != unavailable || snapshot.Active.State != unavailable {
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
	observer, err := New(Profile{Controller: server.URL, Group: "EVENT", Routes: map[Role]string{AReality: "primary"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := observer.Collect(context.Background())
	if snapshot.Selection.State != unknown || snapshot.Active.State != observed {
		t.Fatalf("unexpected source states: %+v", snapshot)
	}
}
