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
