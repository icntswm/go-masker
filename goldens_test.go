package masker_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
)

type goldenOptions struct {
	MaxDepth      *int   `json:"max_depth"`
	MaxNodes      *int   `json:"max_nodes"`
	MaxInputBytes *int64 `json:"max_input_bytes"`
	MaskFragment  bool   `json:"mask_fragment"`
}

type goldenCase struct {
	Name          string          `json:"name"`
	Operation     string          `json:"operation"`
	Input         json.RawMessage `json:"input"`
	Output        json.RawMessage `json:"output"`
	ErrorCode     string          `json:"error_code"`
	ErrorExpected bool            `json:"error_expected"`
	Options       goldenOptions   `json:"options"`
}

type goldenFile struct {
	Cases []goldenCase `json:"cases"`
}

var goldenSentinels = map[string]error{
	"invalid_config":      masker.ErrInvalidConfig,
	"invalid_json":        masker.ErrInvalidJSON,
	"invalid_utf8":        masker.ErrInvalidUTF8,
	"input_limit":         masker.ErrInputLimit,
	"depth_limit":         masker.ErrDepthLimit,
	"node_limit":          masker.ErrNodeLimit,
	"cycle":               masker.ErrCycle,
	"unsupported_type":    masker.ErrUnsupportedType,
	"unsupported_map_key": masker.ErrUnsupportedKey,
	"field_conflict":      masker.ErrFieldConflict,
	"policy_failure":      masker.ErrPolicyFailure,
	"rule_failure":        masker.ErrRuleFailure,
	"panic":               masker.ErrPanic,
}

func TestSecurityDecisionGoldenFiles(t *testing.T) {
	entries, err := os.ReadDir("testdata/security_decisions")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata/security_decisions", name))
		if err != nil {
			t.Fatal(err)
		}
		cases, err := decodeGoldenFile(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, testCase := range cases {
			t.Run(name+"/"+testCase.Name, func(t *testing.T) {
				runGoldenCase(t, testCase)
			})
		}
	}
}

// decodeGoldenFile accepts grouped {"cases":[...]} files and legacy
// single-case objects such as basic_json.json.
func decodeGoldenFile(data []byte) ([]goldenCase, error) {
	var grouped goldenFile
	if err := json.Unmarshal(data, &grouped); err == nil && len(grouped.Cases) > 0 {
		return grouped.Cases, nil
	}
	var single goldenCase
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	if single.Operation == "" {
		return nil, errors.New("fixture has no operation")
	}
	return []goldenCase{single}, nil
}

func runGoldenCase(t *testing.T, c goldenCase) {
	t.Helper()
	core := newGoldenCore(t, c.Options)
	switch c.Operation {
	case "json":
		got, err := core.MaskJSON(c.Input)
		assertGoldenError(t, c, err)
		assertGoldenJSON(t, c.Output, got)
	case "json_error":
		var raw string
		if err := json.Unmarshal(c.Input, &raw); err != nil {
			t.Fatal(err)
		}
		got, err := core.MaskJSON([]byte(raw))
		assertGoldenError(t, c, err)
		assertGoldenJSON(t, c.Output, got)
	case "headers":
		var input map[string][]string
		if err := json.Unmarshal(c.Input, &input); err != nil {
			t.Fatal(err)
		}
		adapter := newGoldenAdapter(t, core, c.Options)
		got, err := adapter.Headers(http.Header(input))
		assertGoldenError(t, c, err)
		var want map[string][]string
		if err := json.Unmarshal(c.Output, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(map[string][]string(got), want) {
			t.Fatalf("header mismatch: got %#v want %#v", got, want)
		}
	case "url":
		var input string
		if err := json.Unmarshal(c.Input, &input); err != nil {
			t.Fatal(err)
		}
		adapter := newGoldenAdapter(t, core, c.Options)
		got, err := adapter.URLString(input)
		assertGoldenError(t, c, err)
		var want string
		if err := json.Unmarshal(c.Output, &want); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("url mismatch:\ngot  %s\nwant %s", got, want)
		}
	default:
		t.Fatalf("unknown operation %q", c.Operation)
	}
}

func assertGoldenError(t *testing.T, c goldenCase, err error) {
	t.Helper()
	switch {
	case c.ErrorCode != "":
		sentinel, known := goldenSentinels[c.ErrorCode]
		if !known {
			t.Fatalf("unknown error_code %q", c.ErrorCode)
		}
		if err == nil || !errors.Is(err, sentinel) {
			t.Fatalf("expected error %q, got %v", c.ErrorCode, err)
		}
	case c.ErrorExpected:
		if err == nil {
			t.Fatal("expected any error")
		}
	default:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func assertGoldenJSON(t *testing.T, wantRaw json.RawMessage, got []byte) {
	t.Helper()
	var want, have any
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &have); err != nil {
		t.Fatalf("masked output is not valid JSON: %v (%s)", err, got)
	}
	if !reflect.DeepEqual(have, want) {
		t.Fatalf("output mismatch:\ngot  %s\nwant %s", got, wantRaw)
	}
}

func newGoldenCore(t *testing.T, o goldenOptions) *masker.Masker {
	t.Helper()
	var opts []masker.Option
	if o.MaxDepth != nil {
		opts = append(opts, masker.WithMaxDepth(*o.MaxDepth))
	}
	if o.MaxNodes != nil {
		opts = append(opts, masker.WithMaxNodes(*o.MaxNodes))
	}
	if o.MaxInputBytes != nil {
		opts = append(opts, masker.WithMaxInputBytes(*o.MaxInputBytes))
	}
	m, err := masker.New(masker.DefaultPolicy(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newGoldenAdapter(t *testing.T, core *masker.Masker, o goldenOptions) *httpmask.Adapter {
	t.Helper()
	var opts []httpmask.Option
	if o.MaskFragment {
		opts = append(opts, httpmask.WithMaskFragment())
	}
	adapter, err := httpmask.New(core, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}
