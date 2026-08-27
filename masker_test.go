package masker

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func newTestMasker(t *testing.T, opts ...Option) *Masker {
	t.Helper()
	m, err := New(DefaultPolicy(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNewRejectsEmptyPolicyChain(t *testing.T) {
	for _, policy := range []Policy{Chain(), Chain(Chain(Chain()))} {
		if _, err := New(policy); err == nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid empty policy chain, got %v", err)
		}
	}
}

func TestNewRejectsNilPolicyInChain(t *testing.T) {
	for _, policy := range []Policy{Chain(nil), Chain(Chain(nil), DefaultPolicy())} {
		if _, err := New(policy); err == nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid nil policy chain, got %v", err)
		}
	}
}

func TestPathForIndexFormat(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	tests := []struct {
		name  string
		index int
		want  string
	}{
		{name: "negative", index: -1, want: "$[-1]"},
		{name: "zero", index: 0, want: "$[0]"},
		{name: "large", index: 1_234_567_890, want: "$[1234567890]"},
		{name: "max int", index: maxInt, want: "$[" + strconv.FormatInt(int64(maxInt), 10) + "]"},
		{name: "min int", index: minInt, want: "$[" + strconv.FormatInt(int64(minInt), 10) + "]"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pathForIndex("$", test.index); got != test.want {
				t.Fatalf("unexpected index path: got %q want %q", got, test.want)
			}
		})
	}
}

func BenchmarkPathForIndex(b *testing.B) {
	var result string
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result = pathForIndex("$[items]", 1_234_567_890)
	}
	if result == "" {
		b.Fatal("empty path")
	}
}

func TestMaskAnyNestedAndDoesNotMutate(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())
	source := map[string]any{
		"User": map[string]any{
			"Password": "secret",
			"count":    4,
		},
	}
	original := source["User"].(map[string]any)["Password"]
	result, err := m.MaskAny(source)
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)["User"].(map[string]any)
	if masked["Password"] != DefaultRedactionMarker || masked["count"] != 4 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if source["User"].(map[string]any)["Password"] != original {
		t.Fatal("source was mutated")
	}
	if reflect.ValueOf(result).Pointer() == reflect.ValueOf(source).Pointer() {
		t.Fatal("result aliases source map")
	}
}

func TestMaskJSONPreservesNumberPrecision(t *testing.T) {
	m := newTestMasker(t)
	result, err := m.MaskJSON([]byte(`{"safe":900719925474099312345,"token":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"safe":900719925474099312345,"token":"[REDACTED]"}` {
		t.Fatalf("unexpected JSON: %s", result)
	}
}

func TestMaskJSONStreamingMatchesDOM(t *testing.T) {
	source := streamingJSONFixture(2_048)
	m := newTestMasker(t, WithPreserveSafeTypes())

	want, err := m.maskJSONDOM(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.MaskJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("streaming output differs:\n got: %s\nwant: %s", got, want)
	}
	if string(source) != string(streamingJSONFixture(2_048)) {
		t.Fatal("streaming masking mutated the input")
	}
}

func TestMaskJSONStreamingKeepsLastDuplicateKey(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())
	got, err := m.maskJSONStream([]byte(`{"b":1,"a":{"token":"old"},"a":{"safe":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"a":{"safe":2},"b":1}`
	if string(got) != want {
		t.Fatalf("unexpected duplicate-key output: got %s want %s", got, want)
	}
}

func TestMaskJSONStreamingEscapingMatchesDOM(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())
	source := []byte(`{"safe":"<>&\u2028\u0061","token":"secret"}`)

	want, err := m.maskJSONDOM(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.maskJSONStream(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("streaming escaping differs: got %s want %s", got, want)
	}
}

func TestMaskJSONStreamingDecodesEscapedRuleInput(t *testing.T) {
	var gotInput RuleInput
	rule, err := NewRule("capture", func(input RuleInput) (string, error) {
		gotInput = input
		return input.Redaction, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "token" {
			return Decision{Rule: rule}, nil
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.MaskJSON([]byte(`{"token":"a\u0062"}`))
	if err != nil || string(got) != `{"token":"[REDACTED]"}` {
		t.Fatalf("unexpected result: got=%s err=%v", got, err)
	}
	if gotInput.Value != "ab" {
		t.Fatalf("escaped rule input was not decoded: %#v", gotInput)
	}
}

func streamingJSONFixture(records int) []byte {
	var builder strings.Builder
	builder.Grow(records * 90)
	builder.WriteString(`{"users":[`)
	for index := 0; index < records; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		id := strconv.Itoa(index)
		builder.WriteString(`{"email":"user` + id + `@example.com","token":"secret","role":"admin"}`)
	}
	builder.WriteString(`]}`)
	return []byte(builder.String())
}

func TestSecurityJSONFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/security_decisions/basic_json.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
		Output    json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Operation != "json" {
		t.Fatalf("unexpected fixture operation: %q", fixture.Operation)
	}
	got, err := newTestMasker(t).MaskJSON(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, expectedValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.Output, &expectedValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, expectedValue) {
		t.Fatalf("fixture mismatch: got %s want %s", got, fixture.Output)
	}
}

func TestStructTagsAndJSONOmit(t *testing.T) {
	type payload struct {
		Password string `mask:"email"`
		Secret   string `mask:"omit"`
		Hidden   string `json:"-"`
	}
	m := newTestMasker(t)
	result, err := m.MaskAny(payload{Password: "alice@example.com", Secret: "x", Hidden: "y"})
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	if masked["Password"] != "a***@example.com" {
		t.Fatalf("unexpected tagged value: %#v", masked["Password"])
	}
	if _, ok := masked["Secret"]; ok {
		t.Fatal("omit tag was not applied")
	}
	if _, ok := masked["Hidden"]; ok {
		t.Fatal("json omit was not applied")
	}
}

func TestBuiltinRulesReuseSingletons(t *testing.T) {
	constructors := []func() Rule{
		PasswordRule,
		TokenRule,
		FullRule,
		EmailRule,
		PhoneRule,
		IDRule,
		CardRule,
	}
	for _, constructor := range constructors {
		first := constructor()
		if first != constructor() {
			t.Fatalf("%s rule was recreated", first.Name())
		}
	}
}

func TestWithStructTagKeepsBuiltinRules(t *testing.T) {
	type payload struct {
		Email string `redact:"email"`
	}
	result, err := newTestMasker(t, WithStructTag("redact")).MaskAny(payload{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["Email"] != "a***@example.com" {
		t.Fatalf("unexpected custom tag result: %#v", result)
	}
}

func TestStructMetadataCacheReuse(t *testing.T) {
	type payload struct {
		Email string `mask:"email"`
		Count int    `json:"count"`
	}
	m := newTestMasker(t)
	value := payload{Email: "alice@example.com", Count: 2}
	for range 2 {
		result, err := m.MaskAny(value)
		if err != nil {
			t.Fatal(err)
		}
		masked := result.(map[string]any)
		if masked["Email"] != "a***@example.com" || masked["count"] != "2" {
			t.Fatalf("unexpected cached result: %#v", masked)
		}
	}
	if builds := m.structMetadata.builds.Load(); builds != 1 {
		t.Fatalf("metadata was built %d times", builds)
	}
}

func TestStructMetadataCacheIsPerMasker(t *testing.T) {
	type payload struct {
		Value string `mask:"email" redact:"full"`
	}
	value := payload{Value: "alice@example.com"}
	defaultMasker := newTestMasker(t)
	customMasker := newTestMasker(t, WithStructTag("redact"))

	defaultResult, err := defaultMasker.MaskAny(value)
	if err != nil {
		t.Fatal(err)
	}
	customResult, err := customMasker.MaskAny(value)
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultResult.(map[string]any)["Value"]; got != "a***@example.com" {
		t.Fatalf("unexpected default tag result: %#v", got)
	}
	if got := customResult.(map[string]any)["Value"]; got != DefaultRedactionMarker {
		t.Fatalf("unexpected custom tag result: %#v", got)
	}
	if defaultMasker.structMetadata == customMasker.structMetadata {
		t.Fatal("maskers share metadata cache")
	}
}

func TestStructMetadataNilEmbeddedPointer(t *testing.T) {
	type embedded struct {
		Token string `mask:"token"`
	}
	type payload struct {
		*embedded
		Name string `json:"name"`
	}

	result, err := newTestMasker(t).MaskAny(payload{Name: "visible"})
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	if len(masked) != 1 || masked["name"] != "visible" {
		t.Fatalf("unexpected nil embedded result: %#v", masked)
	}
}

func TestMaskAnyCycleFailsClosed(t *testing.T) {
	m := newTestMasker(t)
	value := map[string]any{}
	value["self"] = value
	result, err := m.MaskAny(value)
	if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrCycle) {
		t.Fatalf("expected cycle fallback, result=%#v err=%v", result, err)
	}
}

func TestMaskAnyPointerCycleFailsClosed(t *testing.T) {
	type node struct{ Next *node }
	value := &node{}
	value.Next = value
	result, err := newTestMasker(t).MaskAny(value)
	if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrCycle) {
		t.Fatalf("expected pointer cycle fallback, result=%#v err=%v", result, err)
	}
}

func TestMaskStringReturnsMaskError(t *testing.T) {
	rule, err := NewRule("bad", func(RuleInput) (string, error) { return "", errors.New("unsafe detail") })
	if err != nil {
		t.Fatal(err)
	}
	_, err = newTestMasker(t).MaskString("secret", rule)
	var maskErr *MaskError
	if !errors.As(err, &maskErr) || maskErr.Code != CodeRuleFailure || strings.Contains(err.Error(), "unsafe detail") {
		t.Fatalf("expected safe typed error, got %T: %v", err, err)
	}
}

func TestMaskJSONInvalidAndLimitFailClosed(t *testing.T) {
	m := newTestMasker(t, WithMaxInputBytes(4))
	result, err := m.MaskJSON([]byte(`{"token":"secret"}`))
	if result == nil || err == nil || !json.Valid(result) || !errors.Is(err, ErrInputLimit) {
		t.Fatalf("expected JSON limit fallback, result=%s err=%v", result, err)
	}
	m = newTestMasker(t)
	result, err = m.MaskJSON([]byte(`{"token":`))
	if result == nil || err == nil || !json.Valid(result) || !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected invalid JSON fallback, result=%s err=%v", result, err)
	}
}

func TestMaskJSONDirectInputBoundaries(t *testing.T) {
	valid := []byte(`{"safe":1}`)
	m := newTestMasker(t, WithMaxInputBytes(int64(len(valid))))
	result, err := m.MaskJSON(valid)
	if err != nil || string(result) != string(valid) {
		t.Fatalf("exact limit failed: result=%s err=%v", result, err)
	}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "over limit", data: append(append([]byte(nil), valid...), ' '), want: ErrInputLimit},
		{name: "empty", data: nil, want: ErrInvalidJSON},
		{name: "trailing JSON", data: []byte(`{} {}`), want: ErrInvalidJSON},
		{name: "invalid UTF-8", data: []byte{'"', 0xff, '"'}, want: ErrInvalidUTF8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskJSON(test.data)
			if err == nil || !errors.Is(err, test.want) || !json.Valid(result) {
				t.Fatalf("unexpected boundary result: result=%s err=%v", result, err)
			}
		})
	}
}

func TestMaskJSONReaderMaxInt64Limit(t *testing.T) {
	m := newTestMasker(t, WithMaxInputBytes(int64(^uint64(0)>>1)))
	result, err := m.MaskJSONReader(strings.NewReader(`{"safe":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"safe":"true"}` {
		t.Fatalf("unexpected JSON: %s", result)
	}
}

func TestCustomRulePanicIsSafe(t *testing.T) {
	m := newTestMasker(t)
	rule, err := NewRule("panic", func(RuleInput) (string, error) { panic("secret value") })
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskString("secret", rule)
	if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrPanic) {
		t.Fatalf("expected safe panic handling, result=%q err=%v", result, err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error exposed source value")
	}
}

func TestChainUsesFirstOpinion(t *testing.T) {
	first := PolicyFunc(func(Field) (Decision, error) { return Decision{}, nil })
	second := PolicyFunc(func(Field) (Decision, error) { return Decision{Rule: FullRule()}, nil })
	m, err := New(Chain(first, second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskValue("field", "value")
	if err != nil || result != DefaultRedactionMarker {
		t.Fatalf("unexpected chain result: %#v, %v", result, err)
	}
}

func TestSharedDAGIsNotCycle(t *testing.T) {
	shared := map[string]any{"token": "secret"}
	result, err := newTestMasker(t).MaskAny([]any{shared, shared})
	if err != nil {
		t.Fatal(err)
	}
	items := result.([]any)
	for _, item := range items {
		if item.(map[string]any)["token"] != DefaultRedactionMarker {
			t.Fatalf("unexpected shared result: %#v", result)
		}
	}
}

func TestReflectionWalkerBoundsSiblingFailures(t *testing.T) {
	const width = maxMaskErrorsPerOperation * 4
	var calls int
	policy := PolicyFunc(func(field Field) (Decision, error) {
		calls++
		if field.Path == "$" {
			return Decision{}, nil
		}
		return Decision{}, errors.New("unsafe policy detail")
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]any, width)
	for i := range values {
		values[i] = i
	}

	result, err := m.MaskAny(values)
	if result != DefaultRedactionMarker || !errors.Is(err, ErrPolicyFailure) {
		t.Fatalf("unexpected fallback: result=%#v err=%v", result, err)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != maxMaskErrorsPerOperation {
		t.Fatalf("unexpected bounded aggregate: %#v", err)
	}
	if calls != width+1 {
		t.Fatalf("ordinary sibling traversal stopped at %d calls, want %d", calls, width+1)
	}
	if strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("aggregate exposed callback detail: %v", err)
	}
}

func TestReflectionWalkerResourceLimitsStopTraversal(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		opts      []Option
		wantCalls []string
		wantCode  ErrorCode
		wantPath  string
		wantDepth int
	}{
		{
			name:      "depth",
			value:     []any{[]any{0}, 1},
			opts:      []Option{WithMaxDepth(0)},
			wantCalls: []string{"$"},
			wantCode:  CodeDepthLimit,
			wantPath:  "$[0]",
			wantDepth: 1,
		},
		{
			name:      "nodes",
			value:     []any{0, 1, 2},
			opts:      []Option{WithMaxNodes(2)},
			wantCalls: []string{"$", "$[0]"},
			wantCode:  CodeNodeLimit,
			wantPath:  "$[1]",
			wantDepth: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			policy := PolicyFunc(func(field Field) (Decision, error) {
				calls = append(calls, field.Path)
				return Decision{}, nil
			})
			m, err := New(policy, test.opts...)
			if err != nil {
				t.Fatal(err)
			}
			result, err := m.MaskAny(test.value)
			if result != DefaultRedactionMarker {
				t.Fatalf("unexpected fallback: %#v", result)
			}
			var aggregate *MaskErrors
			if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
				t.Fatalf("expected one resource error, got %#v", err)
			}
			item := aggregate.Items[0]
			if item.Code != test.wantCode || item.Path != test.wantPath || item.Depth != test.wantDepth {
				t.Fatalf("unexpected resource error: %#v", item)
			}
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("policy reached sibling after limit: got %#v want %#v", calls, test.wantCalls)
			}
		})
	}
}

func TestReflectionWalkerWideContainersBoundResultCapacity(t *testing.T) {
	const maxNodes = 8

	wideMap := make(map[string]struct{}, 1<<16)
	for i := 0; i < 1<<16; i++ {
		wideMap[strconv.Itoa(i)] = struct{}{}
	}
	tests := []struct {
		name  string
		value any
	}{
		{name: "map", value: wideMap},
		{name: "slice", value: make([]struct{}, 1<<28)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestMasker(t, WithMaxNodes(maxNodes))
			w := &walker{masker: m}
			partial := w.walk(reflect.ValueOf(test.value), Field{Path: "$", Source: SourceAny}, 0, "")
			err := aggregateErrors(w.errs)
			if !errors.Is(err, ErrNodeLimit) {
				t.Fatalf("expected node limit, got %v", err)
			}
			switch result := partial.(type) {
			case map[string]any:
				if len(result) != maxNodes-1 {
					t.Fatalf("unexpected bounded map length: %d", len(result))
				}
			case []any:
				if len(result) != maxNodes-1 || cap(result) != maxNodes-1 {
					t.Fatalf("unexpected bounded slice shape: len=%d cap=%d", len(result), cap(result))
				}
			default:
				t.Fatalf("unexpected partial result type: %T", partial)
			}

			result, err := m.MaskAny(test.value)
			if result != DefaultRedactionMarker || !errors.Is(err, ErrNodeLimit) {
				t.Fatalf("expected fail-closed result, result=%#v err=%v", result, err)
			}
		})
	}
}

func TestReflectionWalkerPointerIndirectionLimit(t *testing.T) {
	value := reflect.ValueOf("safe")
	for i := 0; i < 128; i++ {
		pointer := reflect.New(value.Type())
		pointer.Elem().Set(value)
		value = pointer
	}

	result, err := newTestMasker(t, WithMaxNodes(8)).MaskAny(value.Interface())
	if result != DefaultRedactionMarker || !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("expected pointer indirection limit, result=%#v err=%v", result, err)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
		t.Fatalf("expected one terminal resource error, got %#v", err)
	}
	resource := aggregate.Items[0]
	if resource.Code != CodeNodeLimit || resource.Path != "$" || resource.Depth != 0 {
		t.Fatalf("unexpected pointer resource error: %#v", resource)
	}
}

func TestReflectionWalkerResourceLimitRemainsVisibleAtErrorCap(t *testing.T) {
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Path == "$" {
			return Decision{}, nil
		}
		return Decision{}, errors.New("unsafe policy detail")
	})
	m, err := New(policy, WithMaxNodes(maxMaskErrorsPerOperation+1))
	if err != nil {
		t.Fatal(err)
	}
	values := make([]int, maxMaskErrorsPerOperation+1)

	result, err := m.MaskAny(values)
	if result != DefaultRedactionMarker || !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("resource sentinel was lost at cap: result=%#v err=%v", result, err)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != maxMaskErrorsPerOperation {
		t.Fatalf("unexpected bounded aggregate: %#v", err)
	}
	resource := aggregate.Items[len(aggregate.Items)-1]
	if resource.Code != CodeNodeLimit || resource.Path != "$[64]" || resource.Depth != 1 {
		t.Fatalf("unexpected retained resource error: %#v", resource)
	}
	if strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("aggregate exposed callback detail: %v", err)
	}
}

func TestEmbeddedFieldConflictFailsClosed(t *testing.T) {
	type left struct{ Value string }
	type right struct{ Value string }
	type middle struct{ Value string }
	type payload struct {
		left
		right
		middle
	}
	result, err := newTestMasker(t).MaskAny(payload{left: left{Value: "a"}, right: right{Value: "b"}, middle: middle{Value: "c"}})
	if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("expected field conflict fallback, result=%#v err=%v", result, err)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != 2 {
		t.Fatalf("expected all conflicting fields, got %#v", aggregate)
	}
}

func TestMaskTagGrammarIsStrict(t *testing.T) {
	type payload struct {
		Secret string `mask:"-,omitempty"`
	}
	result, err := newTestMasker(t).MaskAny(payload{Secret: "secret"})
	if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected strict tag failure, result=%#v err=%v", result, err)
	}
}

func TestTagBeatsPolicyAndFullStaysFull(t *testing.T) {
	type payload struct {
		Secret string `mask:"full"`
		Email  string `mask:"email"`
	}
	policy, err := NewKeyPolicy(Binding{Keys: []string{"Secret", "Email"}, Rule: PhoneRule()})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskAny(payload{Secret: "s3cret", Email: "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	if masked["Secret"] != DefaultRedactionMarker {
		t.Fatalf("full tag was weakened by policy: %#v", masked["Secret"])
	}
	if masked["Email"] != "b***@example.com" {
		t.Fatalf("email tag did not override policy: %#v", masked["Email"])
	}
}

func TestExoticCaseFoldKeysStillMasked(t *testing.T) {
	m := newTestMasker(t)
	for _, tc := range []struct{ plain, exotic string }{
		{"PASSWORD", "PASSWORD"},
		{"api_key", "API_\u212AEY"}, // KELVIN SIGN in the k slot
		{"password", "pa\u017Fsword"},
	} {
		result, err := m.MaskValue(tc.exotic, "value")
		if err != nil || result != DefaultRedactionMarker {
			t.Fatalf("key %q was not masked: %#v, %v", tc.exotic, result, err)
		}
		kept, keptErr := m.MaskValue(tc.plain+"-unrelated", "keep-me")
		if keptErr != nil || kept != "keep-me" {
			t.Fatalf("sanity sibling failed: %#v, %v", kept, keptErr)
		}
	}
}

func TestPolicyRejectsConflictingRuleFuncs(t *testing.T) {
	first := RuleFunc(func(RuleInput) (string, error) { return "first", nil })
	second := RuleFunc(func(RuleInput) (string, error) { return "second", nil })
	if _, err := NewKeyPolicy(
		Binding{Keys: []string{"aa"}, Rule: first},
		Binding{Keys: []string{"AA"}, Rule: second},
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected conflicting RuleFunc bindings to fail: %v", err)
	}
}

func TestReflectionRejectsInvalidUTF8(t *testing.T) {
	result, err := newTestMasker(t).MaskAny(map[string]any{"note": "\xff\xfe"})
	if result != DefaultRedactionMarker || !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("invalid UTF-8 was accepted: result=%#v err=%v", result, err)
	}
}

func TestPolicyOmitRemovesMapField(t *testing.T) {
	policy := PolicyFunc(func(field Field) (Decision, error) {
		return Decision{Omit: field.Key == "drop"}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskAny(map[string]any{"drop": "secret", "keep": "value"})
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	if _, ok := masked["drop"]; ok || masked["keep"] != "value" {
		t.Fatalf("policy omit did not remove field: %#v", masked)
	}
}

func TestEmbeddedFieldPromotionMatchesJSONRules(t *testing.T) {
	type note string
	type holder struct {
		note
		Name string
	}
	result, err := newTestMasker(t, WithPreserveSafeTypes()).MaskAny(holder{note: note("ignored"), Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, map[string]any{"Name": "bob"}) {
		t.Fatalf("unexported embedded scalar was not ignored: %#v", result)
	}

	type left struct{ Value string }
	type right struct {
		Value string `json:"Value"`
	}
	type tagged struct {
		left
		right
	}
	result, err = newTestMasker(t).MaskAny(tagged{left: left{Value: "left"}, right: right{Value: "right"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, map[string]any{"Value": "right"}) {
		t.Fatalf("tagged embedded field did not win: %#v", result)
	}
}

func TestDigitRulesRejectAmbiguousFreeText(t *testing.T) {
	for _, rule := range []Rule{PhoneRule(), CardRule()} {
		for _, value := range []string{"1234", "John Smith 1234", "Visa 12345"} {
			result, err := newTestMasker(t).MaskString(value, rule)
			if err != nil || result != DefaultRedactionMarker {
				t.Fatalf("ambiguous value was not fully redacted: rule=%s value=%q result=%q err=%v", rule.Name(), value, result, err)
			}
		}
	}
	result, err := newTestMasker(t).MaskString("+1 (555) 123-4567", PhoneRule())
	if err != nil || result != "+* (***) ***-4567" {
		t.Fatalf("formatted phone behavior changed: result=%q err=%v", result, err)
	}
}

func TestKeyPolicyASCIIAndUnicodeParity(t *testing.T) {
	asciiPolicy, err := NewKeyPolicy(Binding{Keys: []string{"password"}, Rule: PasswordRule()})
	if err != nil {
		t.Fatal(err)
	}
	if !asciiPolicy.asciiOnly {
		t.Fatal("ASCII-only bindings were not recorded")
	}
	for _, test := range []struct {
		key      string
		wantRule bool
	}{
		{key: "PASSWORD", wantRule: true},
		{key: "pa\u017Fsword", wantRule: true},
		{key: "ordinary", wantRule: false},
		{key: "", wantRule: false},
	} {
		decision, decideErr := asciiPolicy.Decide(Field{Key: test.key})
		if decideErr != nil {
			t.Fatal(decideErr)
		}
		if (!isNilRule(decision.Rule)) != test.wantRule {
			t.Fatalf("unexpected ASCII-policy decision for %q: %#v", test.key, decision)
		}
	}

	unicodePolicy, err := NewKeyPolicy(Binding{Keys: []string{"api_\u212Aey"}, Rule: TokenRule()})
	if err != nil {
		t.Fatal(err)
	}
	if unicodePolicy.asciiOnly {
		t.Fatal("Unicode bindings were marked ASCII-only")
	}
	for _, key := range []string{"API_KEY", "API_\u212AEY"} {
		decision, decideErr := unicodePolicy.Decide(Field{Key: key})
		if decideErr != nil || isNilRule(decision.Rule) {
			t.Fatalf("Unicode fallback lost EqualFold parity for %q: %#v, %v", key, decision, decideErr)
		}
	}
}

func TestKeyPolicyRejectsConflictingDuplicateKeys(t *testing.T) {
	if _, err := NewKeyPolicy(
		Binding{Keys: []string{"api_key"}, Rule: PasswordRule()},
		Binding{Keys: []string{"API_\u212AEY"}, Rule: TokenRule()},
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected duplicate conflict error, got %v", err)
	}
	if _, err := NewKeyPolicy(
		Binding{Keys: []string{"secret", "SECRET"}, Rule: PasswordRule()},
	); err != nil {
		t.Fatalf("same-rule duplicates must be accepted, got %v", err)
	}
}

func TestMaskerConcurrentUse(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				result, err := m.MaskValue("token", "secret")
				if err != nil || result != DefaultRedactionMarker {
					t.Errorf("unexpected concurrent result: %#v, %v", result, err)
				}
			}
		}()
	}
	wg.Wait()
}
