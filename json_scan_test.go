package masker

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestJSONStreamingRejectsLargeInputAtNodeLimit(t *testing.T) {
	input := "[" + strings.TrimSuffix(strings.Repeat("0,", 40_000), ",") + "]"
	result, err := newTestMasker(t, WithMaxNodes(8)).MaskJSON([]byte(input))
	if string(result) != `"[REDACTED]"` {
		t.Fatalf("unexpected fallback: %s", result)
	}
	if !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("expected node limit, got %v", err)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
		t.Fatalf("expected one resource error, got %#v", err)
	}
	item := aggregate.Items[0]
	if item.Operation != "mask" || item.Path != "$[7]" || item.Depth != 1 {
		t.Fatalf("unexpected resource error: %#v", item)
	}
}

func TestJSONStreamingKeepsMalformedInputInvalid(t *testing.T) {
	input := "[" + strings.Repeat("0,", 40_000) + "not-json]"
	result, err := newTestMasker(t, WithMaxNodes(8)).MaskJSON([]byte(input))
	if string(result) != `"[REDACTED]"` || !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected invalid JSON fallback, result=%s err=%v", result, err)
	}
	if errors.Is(err, ErrNodeLimit) {
		t.Fatalf("malformed input was reported as resource limit: %v", err)
	}
}

func TestJSONStreamingRejectsMalformedObjectKeys(t *testing.T) {
	for _, input := range []string{
		`{password":"hunter2"}`,
		`{"a":1,token":"abcdefgh"}`,
	} {
		t.Run(input, func(t *testing.T) {
			result, err := newTestMasker(t).MaskJSON([]byte(input))
			if string(result) != `"[REDACTED]"` || !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("malformed key was accepted: result=%s err=%v", result, err)
			}
		})
	}
}

func TestJSONStreamingSkipsDeepValuesIteratively(t *testing.T) {
	const nesting = 100_000
	input := strings.Repeat("[", nesting) + "0" + strings.Repeat("]", nesting)
	result, err := newTestMasker(t, WithMaxDepth(1)).MaskJSON([]byte(input))
	if string(result) != `"[REDACTED]"` || err == nil {
		t.Fatalf("deep value was not rejected safely: result=%s err=%v", result, err)
	}
}

func TestJSONStreamingReportsDepthBeforeJSONValidatorLimit(t *testing.T) {
	const nesting = 10_001
	input := strings.Repeat("[", nesting) + "0" + strings.Repeat("]", nesting)
	result, err := newTestMasker(t).MaskJSON([]byte(input))
	if string(result) != `"[REDACTED]"` || !errors.Is(err, ErrDepthLimit) {
		t.Fatalf("expected depth limit: result=%s err=%v", result, err)
	}
	if errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("valid deep JSON was classified as invalid: %v", err)
	}
}

func TestJSONStreamingKeyCacheIsBounded(t *testing.T) {
	walker := &streamJSONWalker{}
	var data []byte
	for index := range streamJSONKeyCacheMaxEntries + 1_000 {
		key := `"field_` + strconv.Itoa(index) + `"`
		start := len(data)
		data = append(data, key...)
		got, ok := walker.streamObjectKey(data, start, len(data))
		if !ok || got != key[1:len(key)-1] {
			t.Fatalf("unexpected key at index %d: %q, ok=%v", index, got, ok)
		}
	}
	if walker.keyCacheEntries != streamJSONKeyCacheMaxEntries {
		t.Fatalf("unexpected cache size: got %d, want %d", walker.keyCacheEntries, streamJSONKeyCacheMaxEntries)
	}
	var cached int
	for _, entries := range walker.keys {
		cached += len(entries)
		if len(entries) > streamJSONKeyCacheMaxChain {
			t.Fatalf("cache chain is too long: %d", len(entries))
		}
	}
	if cached != streamJSONKeyCacheMaxEntries {
		t.Fatalf("unexpected cached entries: got %d, want %d", cached, streamJSONKeyCacheMaxEntries)
	}
}

func TestSkipJSONValueStateMachine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "empty object", input: `{}`, valid: true},
		{name: "nested object and array", input: `{"a":[true,{"b":null}]}`, valid: true},
		{name: "escaped string", input: `["a\"b"]`, valid: true},
		{name: "trailing whitespace", input: "123 \n", valid: true},
		{name: "trailing comma", input: `[0,]`, valid: false},
		{name: "invalid literal", input: `{"a":tru}`, valid: false},
		{name: "invalid escape", input: `["\q"]`, valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(test.input)
			end := skipJSONValue(data, 0)
			got := end >= 0 && skipJSONSpace(data, end) == len(data)
			if got != test.valid {
				t.Fatalf("unexpected validity: got %v, end=%d, input=%q", got, end, test.input)
			}
		})
	}
}

func TestRemoveStreamMemberUpdatesIndex(t *testing.T) {
	members := []streamJSONMember{
		{key: "a", start: 1, end: 2},
		{key: "b", start: 3, end: 4},
		{key: "c", start: 5, end: 6},
	}
	index := map[string]int{"a": 0, "b": 1, "c": 2}
	removeStreamMember(&members, &index, "b")
	if len(members) != 2 || members[0].key != "a" || members[1].key != "c" {
		t.Fatalf("unexpected members after removal: %#v", members)
	}
	if index["a"] != 0 || index["c"] != 1 {
		t.Fatalf("index was not compacted: %#v", index)
	}
	removeStreamMember(&members, &index, "missing")
	if len(members) != 2 {
		t.Fatalf("missing key changed members: %#v", members)
	}

	var noIndex map[string]int
	removeStreamMember(&members, &noIndex, "a")
	if len(members) != 1 || members[0].key != "c" {
		t.Fatalf("linear removal failed: %#v", members)
	}
}
