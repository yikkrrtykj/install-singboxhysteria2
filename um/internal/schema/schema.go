// Package schema compiles the frozen Unified Monitor v1 JSON Schema contract
// files (draft 2020-12) and validates JSON documents against them.
//
// The contract files are read from disk at runtime; this package deliberately
// does not embed a copy of them, so the committed frozen files under
// docs/um/contracts/v1 remain the single source of truth.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Suffix is the file-name suffix of the frozen contract schema files.
const Suffix = ".schema.json"

// Set is an immutable collection of compiled contract schemas keyed by their
// file name, for example "report-snapshot.schema.json".
//
// A Set is read-only after Load returns and safe for concurrent Validate calls
// as long as the underlying jsonschema library is (its compiled schemas are).
type Set struct {
	dir     string
	schemas map[string]*jsonschema.Schema
	names   []string
}

// Load compiles every "*.schema.json" file in dir and returns the resulting
// Set. dir is resolved relative to the process working directory when it is
// relative; in tests that directory is typically
// "../../../docs/um/contracts/v1" (package-relative).
func Load(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("schema: read contracts dir %q: %w", dir, err)
	}

	compiler := jsonschema.NewCompiler()
	// Load the frozen contract files from disk at runtime, not from embedded
	// copies.
	compiler.UseLoader(jsonschema.FileLoader{})
	compiler.DefaultDraft(jsonschema.Draft2020)

	set := &Set{
		dir:     dir,
		schemas: make(map[string]*jsonschema.Schema),
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), Suffix) {
			continue
		}
		name := entry.Name()
		abs, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("schema: resolve %q: %w", name, err)
		}
		compiled, err := compiler.Compile(fileURL(abs))
		if err != nil {
			return nil, fmt.Errorf("schema: compile %q: %w", name, err)
		}
		set.schemas[name] = compiled
		set.names = append(set.names, name)
	}
	if len(set.names) == 0 {
		return nil, fmt.Errorf("schema: no %s files in %q", Suffix, dir)
	}
	sort.Strings(set.names)
	return set, nil
}

// Dir reports the directory the Set was loaded from.
func (s *Set) Dir() string { return s.dir }

// Names returns the sorted schema file names that compiled successfully.
func (s *Set) Names() []string {
	names := make([]string, len(s.names))
	copy(names, s.names)
	return names
}

// Has reports whether name is a compiled schema in the Set.
func (s *Set) Has(name string) bool {
	_, ok := s.schemas[name]
	return ok
}

// Validate validates body against the named schema. name is the schema file
// name, for example "report-snapshot.schema.json". The body is decoded with
// json.Number precision and then validated by the compiled draft 2020-12
// schema; this is real JSON Schema validation, not JSON parsing only.
//
// Before schema validation the body must pass CheckStrictJSON: exactly one
// top-level JSON value, no duplicate object member names, trailing whitespace
// allowed. The frozen contract forbids duplicate members because encoding/json
// silently overlays them (last value wins), so two consumers of the same bytes
// could otherwise disagree.
func (s *Set) Validate(name string, body []byte) error {
	compiled, ok := s.schemas[name]
	if !ok {
		return fmt.Errorf("schema: %q is not loaded (loaded: %s)", name, strings.Join(s.names, ", "))
	}
	if err := CheckStrictJSON(body); err != nil {
		return fmt.Errorf("schema %s: %w", name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("schema %s: invalid JSON: %w", name, err)
	}
	if err := compiled.Validate(doc); err != nil {
		return fmt.Errorf("schema %s: %w", name, err)
	}
	return nil
}

// ValidateFile reads path and validates its contents against the named schema.
func (s *Set) ValidateFile(name, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("schema %s: read %q: %w", name, path, err)
	}
	return s.Validate(name, body)
}

// Strict-JSON grammar errors. They are deliberately generic and never echo a
// member name or value: a duplicated credential-like key must not leak through
// an error message.
var (
	errStrictMalformed    = errors.New("strict JSON: malformed JSON")
	errStrictDuplicateKey = errors.New("strict JSON: duplicate object member name")
	errStrictTrailingData = errors.New("strict JSON: trailing data after the top-level JSON value")
)

// CheckStrictJSON enforces the wire grammar that encoding/json accepts but the
// frozen UM v1 contract forbids: duplicate object member names at any depth and
// more than one top-level JSON value. Whitespace around the single value,
// including after it, is allowed.
//
// The scan is streaming and O(n); object nesting is tracked with a decoder so
// nested duplicate members are found without materialising the document.
func CheckStrictJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errStrictMalformed
	}
	if err := scanStrictValue(decoder, token); err != nil {
		return err
	}
	// Token skips whitespace, so only trailing whitespace can yield io.EOF.
	_, err = decoder.Token()
	if err == nil {
		return errStrictTrailingData
	}
	if !errors.Is(err, io.EOF) {
		return errStrictTrailingData
	}
	return nil
}

// scanStrictValue consumes the remainder of token (which has already been read
// by the decoder) and recurses into containers.
func scanStrictValue(decoder *json.Decoder, token json.Token) error {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		// A scalar token; the tokenizer already validated its syntax.
		return nil
	}
	switch delimiter {
	case '{':
		return scanStrictObject(decoder)
	case '[':
		return scanStrictArray(decoder)
	default:
		return errStrictMalformed
	}
}

func scanStrictObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for {
		token, err := decoder.Token()
		if err != nil {
			return errStrictMalformed
		}
		if delimiter, isDelimiter := token.(json.Delim); isDelimiter {
			if delimiter == '}' {
				return nil
			}
			return errStrictMalformed
		}
		// Decoder.Token returns decoded strings, so escaped spellings of the
		// same member name ("a" vs "\u0061") are detected as duplicates.
		key, ok := token.(string)
		if !ok {
			return errStrictMalformed
		}
		if _, duplicate := seen[key]; duplicate {
			return errStrictDuplicateKey
		}
		seen[key] = struct{}{}
		valueToken, err := decoder.Token()
		if err != nil {
			return errStrictMalformed
		}
		if err := scanStrictValue(decoder, valueToken); err != nil {
			return err
		}
	}
}

func scanStrictArray(decoder *json.Decoder) error {
	for {
		token, err := decoder.Token()
		if err != nil {
			return errStrictMalformed
		}
		if delimiter, isDelimiter := token.(json.Delim); isDelimiter && delimiter == ']' {
			return nil
		}
		// A scalar element, or a nested container that scanStrictValue consumes
		// to its matching close delimiter.
		if err := scanStrictValue(decoder, token); err != nil {
			return err
		}
	}
}

// fileURL converts an absolute filesystem path to a file:// URL the
// jsonschema FileLoader understands on both Windows and Unix.
func fileURL(abs string) string {
	path := filepath.ToSlash(abs)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "file://" + path
}
