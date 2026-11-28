package management

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestOpenAPIResponseModelsMatchGoModels prevents the spec from drifting away
// from the actual JSON DTOs at field level (envelope/path checks alone do not
// catch missing or invented fields).
func TestOpenAPIResponseModelsMatchGoModels(t *testing.T) {
	raw, err := os.ReadFile("../../docs/um-b4-admin-api.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	models := map[string]any{
		"EventView":              EventView{},
		"EventList":              EventList{},
		"NodeView":               NodeView{},
		"NodeList":               NodeList{},
		"ConfigView":             ConfigView{},
		"EnrollmentTokenView":    EnrollmentTokenView{},
		"EnrollmentTokenCreated": EnrollmentTokenCreated{},
		"AliasView":              AliasView{},
		"MappingEntryView":       MappingEntryView{},
		"MappingVersionView":     MappingVersionView{},
		"PurgePreviewView":       PurgePreviewView{},
		"PurgeStatusView":        PurgeStatusView{},
		"CapacityView":           CapacityView{},
	}
	for schemaName, model := range models {
		schema, ok := spec.Components.Schemas[schemaName]
		if !ok {
			t.Fatalf("missing schema %s", schemaName)
		}
		actual := jsonFieldSet(reflect.TypeOf(model))
		for field := range actual {
			if _, ok := schema.Properties[field]; !ok {
				t.Fatalf("%s: Go model field %q missing from OpenAPI schema", schemaName, field)
			}
		}
		for field := range schema.Properties {
			if !actual[field] {
				t.Fatalf("%s: OpenAPI schema field %q is not returned by the Go model", schemaName, field)
			}
		}
	}
}

func jsonFieldSet(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out[name] = true
	}
	return out
}
