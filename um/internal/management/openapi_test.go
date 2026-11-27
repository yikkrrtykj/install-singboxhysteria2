package management

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOpenAPISpecMatchesRouteInventory(t *testing.T) {
	raw, err := os.ReadFile("../../docs/um-b4-admin-api.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.OpenAPI != "3.0.3" {
		t.Fatalf("openapi=%q", spec.OpenAPI)
	}
	documented := map[string]bool{}
	for path, methods := range spec.Paths {
		for method := range methods {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}
	inventory := map[string]bool{}
	for _, r := range AdminRouteInventory() {
		key := r.Method + " " + r.Path
		if inventory[key] {
			t.Fatalf("duplicate route in inventory: %s", key)
		}
		inventory[key] = true
	}
	if len(documented) != len(inventory) {
		t.Fatalf("documented=%d inventory=%d", len(documented), len(inventory))
	}
	for key := range documented {
		if !inventory[key] {
			t.Fatalf("documented endpoint missing from handler inventory: %s", key)
		}
	}
}

func TestOpenAPIDocumentShape(t *testing.T) {
	raw, err := os.ReadFile("../../docs/um-b4-admin-api.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Required   []string                   `json:"required"`
						Properties map[string]json.RawMessage `json:"properties"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for path, methods := range spec.Paths {
		for method, op := range methods {
			declared := map[string]bool{}
			for _, p := range op.Parameters {
				if p.In == "path" {
					declared[p.Name] = true
				}
			}
			for _, name := range pathTemplateNames(path) {
				if !declared[name] {
					t.Fatalf("%s %s missing path parameter %q", method, path, name)
				}
			}
			for status, resp := range op.Responses {
				if !strings.HasPrefix(status, "2") {
					continue
				}
				media, ok := resp.Content["application/json"]
				if !ok {
					t.Fatalf("%s %s status %s lacks JSON content", method, path, status)
				}
				required := map[string]bool{}
				for _, r := range media.Schema.Required {
					required[r] = true
				}
				if !required["v"] || !required["data"] {
					t.Fatalf("%s %s success envelope missing v/data: %+v", method, path, media.Schema)
				}
				if _, ok := media.Schema.Properties["data"]; !ok {
					t.Fatalf("%s %s success envelope has no data property", method, path)
				}
			}
			if (path == "/api/v1/events/{event_id}/tokens" || strings.HasSuffix(path, "/mapping/{windows_node_id}")) && method == "post" {
				if _, ok := op.Responses["201"]; !ok {
					t.Fatalf("%s %s POST should document 201", method, path)
				}
			}
		}
	}
	// Conflict/validation statuses must be present for the alias write where
	// optimistic concurrency is user-visible.
	if _, ok := spec.Paths["/api/v1/events/{event_id}/aliases/{target_type}/{target_key}"]["put"].Responses["409"]; !ok {
		t.Fatal("alias PUT lacks documented 409")
	}
}

func pathTemplateNames(path string) []string {
	var names []string
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			return names
		}
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			return names
		}
		names = append(names, path[start+1:start+end])
		path = path[start+end+1:]
	}
}
