package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestRev7SchemaStageNegativeVectors executes the normative rev-7 negative
// vectors whose rejection stage is the JSON Schema itself. The semantic/platform/
// config-generation vectors require the implementation PR; this contract test
// validates the schema-stage subset against the actual overlay files so the
// vectors are behavior-tested, not merely parsed.
func TestRev7SchemaStageNegativeVectors(t *testing.T) {
	dir := filepath.Join(contractsDir, "rev7")
	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%q): %v", dir, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "negative-vectors.json"))
	if err != nil {
		t.Fatalf("read negative vectors: %v", err)
	}
	var doc struct {
		Bases   map[string]string `json:"bases"`
		Vectors []struct {
			ID     string           `json:"id"`
			Target string           `json:"target"`
			Stage  string           `json:"stage"`
			Base   string           `json:"base"`
			Patch  []map[string]any `json:"patch"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse negative vectors: %v", err)
	}
	expected := 0
	executed := 0
	for _, vector := range doc.Vectors {
		if vector.Stage != "json_schema" {
			continue
		}
		expected++
		basePath, ok := doc.Bases[vector.Base]
		if !ok {
			t.Fatalf("%s: unknown base %q", vector.ID, vector.Base)
		}
		// Base paths are repository-relative; the test package cwd is
		// um/internal/schema, so the worktree root is ../../..
		body, err := os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(basePath)))
		if err != nil {
			t.Fatalf("%s: read base %q: %v", vector.ID, basePath, err)
		}
		var document any
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s: base is not JSON: %v", vector.ID, err)
		}
		for _, patch := range vector.Patch {
			op, _ := patch["op"].(string)
			pointer, _ := patch["path"].(string)
			if err := applyJSONPointer(&document, op, pointer, patch["value"]); err != nil {
				t.Fatalf("%s: apply %s %s: %v", vector.ID, op, pointer, err)
			}
		}
		mutated, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("%s: marshal: %v", vector.ID, err)
		}
		schemaName := ""
		switch vector.Target {
		case "report-snapshot.rev7":
			schemaName = "report-snapshot.rev7.schema.json"
		case "agent-config.rev7":
			schemaName = "agent-config.rev7.schema.json"
		default:
			t.Fatalf("%s: unknown target %q", vector.ID, vector.Target)
		}
		if err := set.Validate(schemaName, mutated); err == nil {
			t.Fatalf("%s: schema-stage negative vector was accepted", vector.ID)
		}
		executed++
	}
	if executed != expected || executed == 0 {
		t.Fatalf("executed %d of %d schema-stage vectors", executed, expected)
	}
}

func applyJSONPointer(document *any, op, pointer string, value any) error {
	if pointer == "" {
		return fmt.Errorf("empty pointer")
	}
	if !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("pointer must start with /")
	}
	tokens := strings.Split(pointer[1:], "/")
	for i := range tokens {
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(tokens[i], "~1", "/"), "~0", "~")
	}
	updated, err := patchJSONValue(*document, tokens, op, value)
	if err != nil {
		return err
	}
	*document = updated
	return nil
}

func patchJSONValue(node any, tokens []string, op string, value any) (any, error) {
	token := tokens[0]
	switch typed := node.(type) {
	case map[string]any:
		if len(tokens) == 1 {
			switch op {
			case "replace", "add":
				typed[token] = value
			case "remove":
				delete(typed, token)
			default:
				return nil, fmt.Errorf("unsupported op %q", op)
			}
			return typed, nil
		}
		child, ok := typed[token]
		if !ok {
			return nil, fmt.Errorf("missing object member %q", token)
		}
		updated, err := patchJSONValue(child, tokens[1:], op, value)
		if err != nil {
			return nil, err
		}
		typed[token] = updated
		return typed, nil
	case []any:
		if last := len(tokens) == 1; last && token == "-" && op == "add" {
			return append(typed, value), nil
		}
		index, err := strconv.Atoi(token)
		if err != nil || index < 0 || index > len(typed) {
			return nil, fmt.Errorf("bad array index %q", token)
		}
		if len(tokens) == 1 {
			switch op {
			case "replace":
				if index >= len(typed) {
					return nil, fmt.Errorf("replace index out of range")
				}
				typed[index] = value
			case "add":
				typed = append(typed[:index], append([]any{value}, typed[index:]...)...)
			default:
				return nil, fmt.Errorf("unsupported array op %q", op)
			}
			return typed, nil
		}
		if index >= len(typed) {
			return nil, fmt.Errorf("index out of range")
		}
		updated, err := patchJSONValue(typed[index], tokens[1:], op, value)
		if err != nil {
			return nil, err
		}
		typed[index] = updated
		return typed, nil
	default:
		return nil, fmt.Errorf("pointer traverses a scalar at %q", token)
	}
}
