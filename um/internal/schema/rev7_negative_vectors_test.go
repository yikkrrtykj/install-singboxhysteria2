package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestRev7SchemaStageNegativeVectors executes the normative rev-7 negative
// vectors whose rejection stage is the JSON Schema itself. It covers the report
// snapshot, agent-config and monitor-v2 traffic-export schemas, plus the raw-body
// lexical vectors (which JSON Patch cannot represent because a JSON parser
// normalizes numeric tokens). The semantic/platform/config-generation vectors
// require the implementation PR; this contract test also pins their structure so
// a future runner cannot silently drop a stage.
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
		Bases       map[string]string `json:"bases"`
		GatingRules struct {
			Rule        string `json:"rule"`
			MinVersion  string `json:"min_rev7_agent_version"`
			CenterRule  string `json:"center_behaviour"`
			NotAuth     string `json:"not_authorization"`
			Description string `json:"comparison"`
		} `json:"gating_rules"`
		Vectors []struct {
			ID       string           `json:"id"`
			Target   string           `json:"target"`
			Stage    string           `json:"stage"`
			Base     string           `json:"base"`
			Patch    []map[string]any `json:"patch"`
			RawBody  string           `json:"raw_body"`
			Mutation string           `json:"mutation"`
			Scenario string           `json:"scenario"`
			Expected struct {
				Stage string `json:"stage"`
				Rule  string `json:"rule"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse negative vectors: %v", err)
	}

	// Structural assertions: a future runner must not silently drop a vector or
	// execute a vector under the wrong declared stage.
	allowedStages := map[string]bool{
		"json_schema":             true,
		"implementation_semantic": true,
		"platform_isolation":      true,
		"config_generation":       true,
	}
	if len(doc.Vectors) < 50 {
		t.Fatalf("only %d vectors; the rev-7 contract requires the full report/config/export set", len(doc.Vectors))
	}
	seenIDs := map[string]bool{}
	stageCount := map[string]int{}
	cfgRules := map[string]string{}
	for _, vector := range doc.Vectors {
		if seenIDs[vector.ID] {
			t.Fatalf("duplicate vector id %q", vector.ID)
		}
		seenIDs[vector.ID] = true
		if !allowedStages[vector.Stage] {
			t.Fatalf("%s: unknown stage %q", vector.ID, vector.Stage)
		}
		if vector.Expected.Stage != vector.Stage {
			t.Fatalf("%s: expected.stage %q != stage %q", vector.ID, vector.Expected.Stage, vector.Stage)
		}
		if vector.Mutation == "" && vector.RawBody == "" && vector.Scenario == "" {
			t.Fatalf("%s: vector has neither a mutation, scenario nor raw_body description", vector.ID)
		}
		stageCount[vector.Stage]++
		if vector.Expected.Rule != "" {
			if _, ok := cfgRules[vector.Expected.Rule]; ok {
				t.Fatalf("%s: duplicate CFG rule mapping %q", vector.ID, vector.Expected.Rule)
			}
			cfgRules[vector.Expected.Rule] = vector.ID
		}
	}
	for stage := range allowedStages {
		if stageCount[stage] == 0 {
			t.Fatalf("stage %q has no vectors", stage)
		}
	}
	if doc.GatingRules.Rule != "CFG-REV7" || doc.GatingRules.MinVersion != "1.1.0" ||
		doc.GatingRules.CenterRule == "" || doc.GatingRules.NotAuth == "" {
		t.Fatalf("gating_rules does not define the CFG-REV7 minimum version contract: %+v", doc.GatingRules)
	}
	for rule := range map[string]bool{
		"CFG-REV7-01": true, "CFG-REV7-02": true, "CFG-REV7-03": true,
		"CFG-REV7-04": true, "CFG-REV7-05": true,
	} {
		if cfgRules[rule] == "" {
			t.Fatalf("gating rule %s has no vector", rule)
		}
	}

	executed := 0
	rawSchemaAccepts := 0
	for _, vector := range doc.Vectors {
		schemaName := ""
		switch vector.Target {
		case "report-snapshot.rev7":
			schemaName = "report-snapshot.rev7.schema.json"
		case "agent-config.rev7":
			schemaName = "agent-config.rev7.schema.json"
		case "traffic-export.rev7":
			schemaName = "traffic-export.schema.json"
		default:
			t.Fatalf("%s: unknown target %q", vector.ID, vector.Target)
		}

		var body []byte
		if vector.RawBody != "" {
			// Raw-body vectors exist because JSON Patch normalizes numeric tokens
			// (1048576.0 -> 1048576). The committed string is the exact byte
			// sequence the implementation must feed and reject.
			body = []byte(vector.RawBody)
		} else {
			basePath, ok := doc.Bases[vector.Base]
			if !ok {
				t.Fatalf("%s: unknown base %q", vector.ID, vector.Base)
			}
			body, err = os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(basePath)))
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
			body, err = json.Marshal(document)
			if err != nil {
				t.Fatalf("%s: marshal: %v", vector.ID, err)
			}
		}

		validationErr := set.Validate(schemaName, body)
		switch {
		case vector.Stage == "json_schema":
			if validationErr == nil {
				t.Fatalf("%s: schema-stage negative vector was accepted", vector.ID)
			}
			executed++
		case vector.RawBody != "":
			// A raw implementation-semantic lexical vector must still be accepted
			// by JSON Schema: that is exactly why the implementation-stage rule
			// exists. Rejecting it here would mean the vector no longer documents
			// the schema/implementation split.
			if validationErr != nil {
				t.Fatalf("%s: raw lexical vector rejected by schema; it must remain schema-valid to document the split: %v",
					vector.ID, validationErr)
			}
			rawSchemaAccepts++
		}
	}
	if executed == 0 || rawSchemaAccepts == 0 {
		t.Fatalf("executed %d schema-stage vectors, %d raw schema-accepted vectors", executed, rawSchemaAccepts)
	}
	ids := make([]string, 0, len(seenIDs))
	for id := range seenIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Logf("validated %d vectors (%d schema-stage executed, %d raw lexical schema-accepted, stages %v), %s",
		len(ids), executed, rawSchemaAccepts, stageCount, strings.Join(ids, ","))
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
