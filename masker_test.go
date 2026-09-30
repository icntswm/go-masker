package masker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
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

func TestJSONDashCommaTagNamesField(t *testing.T) {
	type payload struct {
		Dash string `json:"-,"` //nolint:staticcheck // SA5008: the ambiguous tag is the case under test.
	}
	result, err := newTestMasker(t).MaskAny(payload{Dash: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]any)["-"]; got != "x" {
		t.Fatalf(`json:"-," must name the field "-", got %#v`, result)
	}
}

func TestWithMaxDepthIsBounded(t *testing.T) {
	if _, err := New(DefaultPolicy(), WithMaxDepth(maxDepthLimit+1)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid config above the depth ceiling, got %v", err)
	}
	m := newTestMasker(t, WithMaxDepth(maxDepthLimit), WithMaxNodes(1<<30))
	deep := strings.Repeat("[", maxDepthLimit+2) + strings.Repeat("]", maxDepthLimit+2)
	if _, err := m.MaskJSON([]byte(deep)); !errors.Is(err, ErrDepthLimit) {
		t.Fatalf("expected depth limit at the ceiling, got %v", err)
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

func TestPartialRulesRedactControlCharacters(t *testing.T) {
	m := newTestMasker(t)
	for _, tc := range []struct {
		rule  Rule
		value string
		want  string
	}{
		{EmailRule(), "a@example.com\x1b[2J", DefaultRedactionMarker},
		{EmailRule(), "\u202ea@example.com", DefaultRedactionMarker},
		{EmailRule(), "a@exa\u200bmple.com", DefaultRedactionMarker},
		{IDRule(), "SECRET\nPWN!", DefaultRedactionMarker},
		{IDRule(), "SECRET\u2028PWN!", DefaultRedactionMarker},
		{IDRule(), "SECRET\x00PWN!", DefaultRedactionMarker},
		{EmailRule(), "a@example.com\x7f", DefaultRedactionMarker},
		{EmailRule(), "a@example.com\t", DefaultRedactionMarker},
		{EmailRule(), "a\u00a0b@example.com", DefaultRedactionMarker},
		{EmailRule(), "a\u0085b@example.com", DefaultRedactionMarker},
		{EmailRule(), "a\u2029b@example.com", DefaultRedactionMarker},
		{EmailRule(), "a\xffb@example.com", DefaultRedactionMarker},
		{IDRule(), "SECRET\x7fPWN!", DefaultRedactionMarker},
		{EmailRule(), "alice@example.com", "a***@example.com"},
		{EmailRule(), "\u00e9lise@example.com", "\u00e9***@example.com"},
		{EmailRule(), "\ufffd@example.com", "\ufffd***@example.com"},
		{IDRule(), "user 8891", "**** 8891"},
		{IDRule(), "\u00e9t\u00e9-8891", "****8891"},
	} {
		got, err := m.MaskString(tc.value, tc.rule)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("MaskString(%q) = %q, want %q", tc.value, got, tc.want)
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

func TestWithTagRule(t *testing.T) {
	last2, err := NewRule("last2", func(input RuleInput) (string, error) {
		runes := []rune(input.Value)
		if len(runes) < 2 {
			return "**", nil
		}
		return string(runes[len(runes)-2:]), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	type flatPayload struct {
		Secret string `mask:"last2"`
	}
	type nestedPayload struct {
		Secret string            `mask:"last2"`
		Inner  map[string]string `json:"inner"`
	}

	t.Run("flat scalar struct", func(t *testing.T) {
		result, err := newTestMasker(t, WithTagRule("last2", last2)).MaskAny(flatPayload{Secret: "synthetic-secret"})
		if err != nil {
			t.Fatal(err)
		}
		if result.(map[string]any)["Secret"] != "et" {
			t.Fatalf("unexpected tagged value: %#v", result)
		}
	})

	t.Run("struct with nested map", func(t *testing.T) {
		result, err := newTestMasker(t, WithTagRule("last2", last2)).
			MaskAny(nestedPayload{Secret: "synthetic-secret", Inner: map[string]string{"note": "value"}})
		if err != nil {
			t.Fatal(err)
		}
		masked := result.(map[string]any)
		if masked["Secret"] != "et" {
			t.Fatalf("unexpected tagged value: %#v", masked["Secret"])
		}
		if masked["inner"].(map[string]any)["note"] != "value" {
			t.Fatalf("unexpected nested value: %#v", masked["inner"])
		}
	})

	t.Run("registration is not global", func(t *testing.T) {
		plain, err := New(DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		result, err := plain.MaskAny(flatPayload{Secret: "synthetic-secret"})
		if result != DefaultRedactionMarker || err == nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected unknown-tag failure on a second masker, result=%#v err=%v", result, err)
		}
	})

	t.Run("rejects invalid registrations", func(t *testing.T) {
		tests := []struct {
			name string
			opts []Option
		}{
			{name: "empty", opts: []Option{WithTagRule("", last2)}},
			{name: "reserved omit", opts: []Option{WithTagRule("omit", last2)}},
			{name: "builtin password", opts: []Option{WithTagRule("password", last2)}},
			{name: "builtin full", opts: []Option{WithTagRule("full", last2)}},
			{name: "comma", opts: []Option{WithTagRule("last2,x", last2)}},
			{name: "nil rule", opts: []Option{WithTagRule("last2", nil)}},
			{name: "nil RuleFunc", opts: []Option{WithTagRule("last2", RuleFunc(nil))}},
			{name: "duplicate", opts: []Option{WithTagRule("last2", last2), WithTagRule("last2", last2)}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if _, err := New(DefaultPolicy(), test.opts...); !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("expected ErrInvalidConfig, got %v", err)
				}
			})
		}
	})
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

type textMarshalerLevel int

func (l textMarshalerLevel) MarshalText() ([]byte, error) { return []byte("debug"), nil }

type failingTextMarshaler struct{}

func (failingTextMarshaler) MarshalText() ([]byte, error) {
	return nil, errors.New("unsafe detail")
}

type panickingTextMarshaler struct{}

func (panickingTextMarshaler) MarshalText() ([]byte, error) { panic("unsafe detail") }

type pointerReceiverTextMarshaler int

func (p *pointerReceiverTextMarshaler) MarshalText() ([]byte, error) {
	return []byte("pointer"), nil
}

func TestTextMarshalerAndBytes(t *testing.T) {
	at := time.Date(2026, 9, 28, 8, 30, 0, 0, time.UTC)
	m := newTestMasker(t, WithPreserveSafeTypes())

	payload := struct {
		At    time.Time
		IP    net.IP
		Raw   []byte
		Level textMarshalerLevel
	}{At: at, IP: net.IP{10, 0, 0, 1}, Raw: []byte{1, 2, 3}, Level: 2}
	result, err := m.MaskAny(payload)
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	if masked["At"] != at.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected time value: %#v", masked["At"])
	}
	if masked["IP"] != "10.0.0.1" {
		t.Fatalf("unexpected IP value: %#v", masked["IP"])
	}
	if masked["Raw"] != base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) {
		t.Fatalf("unexpected byte-slice value: %#v", masked["Raw"])
	}
	if masked["Level"] != "debug" {
		t.Fatalf("unexpected marshaler value: %#v", masked["Level"])
	}

	textResult, err := m.MaskValue("token", at)
	if err != nil {
		t.Fatal(err)
	}
	if textResult != DefaultRedactionMarker {
		t.Fatalf("unexpected masked time under a sensitive key: %#v", textResult)
	}

	failingResult, err := m.MaskAny(map[string]any{"a": failingTextMarshaler{}})
	if err == nil || !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected unsupported type for a failing marshaler, got %v", err)
	}
	if failingResult != DefaultRedactionMarker {
		t.Fatalf("expected root fallback, got %#v", failingResult)
	}

	panicResult, err := m.MaskAny(map[string]any{"a": panickingTextMarshaler{}})
	if err == nil || !errors.Is(err, ErrPanic) {
		t.Fatalf("expected panic category for a panicking marshaler, got %v", err)
	}
	if panicResult != DefaultRedactionMarker {
		t.Fatalf("expected root fallback, got %#v", panicResult)
	}

	pointerResult, err := m.MaskAny(&struct {
		V pointerReceiverTextMarshaler
	}{})
	if err != nil {
		t.Fatal(err)
	}
	if got := pointerResult.(map[string]any)["V"]; got != "pointer" {
		t.Fatalf("pointer receiver was not called: %#v", got)
	}

	arrayResult, err := m.MaskAny(map[string]any{"raw": [3]byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := arrayResult.(map[string]any)["raw"].([]any)
	if !ok || len(raw) != 3 {
		t.Fatalf("byte array was converted instead of being walked: %#v", arrayResult.(map[string]any)["raw"])
	}
}

func TestNilValuesAreDecidedLikeJSONNull(t *testing.T) {
	policy := Chain(PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "drop" {
			return Decision{Omit: true}, nil
		}
		return Decision{}, nil
	}), DefaultPolicy())
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := m.MaskJSON([]byte(`{"drop":null,"password":null,"user":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(fromJSON) != `{"password":"[REDACTED]","user":null}` {
		t.Fatalf("MaskJSON: %s", fromJSON)
	}

	var missing *string
	fromMap, err := m.MaskAny(map[string]any{"drop": nil, "password": missing, "user": nil})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"password": DefaultRedactionMarker, "user": nil}; !reflect.DeepEqual(fromMap, want) {
		t.Fatalf("map: got %#v, want %#v", fromMap, want)
	}

	// A tag decides a nil field too.
	fromStruct, err := m.MaskAny(struct {
		Drop *string `json:"drop"`
		Note *string `json:"note" mask:"full"`
		User *string `json:"user"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"note": DefaultRedactionMarker, "user": nil}; !reflect.DeepEqual(fromStruct, want) {
		t.Fatalf("struct: got %#v, want %#v", fromStruct, want)
	}
}

func TestUntypedNilIsDecidedByThePolicy(t *testing.T) {
	policy := Chain(PolicyFunc(func(field Field) (Decision, error) {
		return Decision{Omit: field.Key == "drop"}, nil
	}), DefaultPolicy())
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{"user": nil, "drop": nil, "password": DefaultRedactionMarker} {
		got, err := m.MaskValue(key, nil)
		if err != nil || got != want {
			t.Fatalf("%s: got %#v, %v; want %#v", key, got, err, want)
		}
	}
}

// TestInvalidJSONTagNameFailsClosed covers tag names encoding/json rejects:
// Go 1.26 writes such a field as its Go name and Go 1.27 as the name cut at
// the backslash or quote, so the walker cannot know the key and redacts it.
func TestInvalidJSONTagNameFailsClosed(t *testing.T) {
	type payload struct {
		Password string `json:"safe\\name"` //nolint:staticcheck // SA5008: the invalid tag name is the case under test.
		Plain    string `json:"a-b.c"`
	}
	type quoted struct {
		Token string `json:"quo\"te"` //nolint:staticcheck // SA5008: the invalid tag name is the case under test.
	}
	type omitted struct {
		Secret string `json:"x\\y" mask:"omit"` //nolint:staticcheck // SA5008: the invalid tag name is the case under test.
		Plain  string `json:"a-b.c"`
	}
	masker := newTestMasker(t)
	for _, value := range []any{payload{Password: "dummy-password", Plain: "kept"}, quoted{Token: "dummy-token"}} {
		result, err := masker.MaskAny(value)
		if result != DefaultRedactionMarker || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("MaskAny(%#v) = %#v, %v; want the marker and ErrInvalidConfig", value, result, err)
		}
	}
	// A mask tag decides the field without its name, so the tag still applies.
	result, err := masker.MaskAny(omitted{Secret: "dummy-secret", Plain: "kept"})
	if err != nil || !reflect.DeepEqual(result, map[string]any{"a-b.c": "kept"}) {
		t.Fatalf("got %#v, %v", result, err)
	}
}

func TestRawMessageIsDecidedAsJSON(t *testing.T) {
	jsonOnly := PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "password" && field.Source == SourceJSON {
			return Decision{Rule: FullRule()}, nil
		}
		return Decision{}, nil
	})
	m, err := New(jsonOnly)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskAny(map[string]any{"body": json.RawMessage(`{"password":"dummy-password"}`)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := result.(map[string]any)["body"].(map[string]any)
	if body["password"] != DefaultRedactionMarker {
		t.Fatalf("a JSON-scoped policy missed a RawMessage member: %#v", result)
	}
}

func TestRawMessageIsMaskedByKeys(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())
	nested := json.RawMessage(`[{"token":"dummy"}]`)

	payload := struct {
		Body   json.RawMessage
		Null   json.RawMessage
		Nested map[string]any
	}{
		Body:   json.RawMessage(`{"password":"dummy-raw","count":12345678901234567890,"ok":true}`),
		Null:   json.RawMessage(` null `),
		Nested: map[string]any{"doc": &nested},
	}
	result, err := m.MaskAny(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Body":{"count":12345678901234567890,"ok":true,"password":"[REDACTED]"},` +
		`"Nested":{"doc":[{"token":"[REDACTED]"}]},"Null":null}`
	if string(encoded) != want {
		t.Fatalf("unexpected masked document:\n got %s\nwant %s", encoded, want)
	}

	redacted, err := m.MaskValue("password", json.RawMessage(`{"a":"dummy"}`))
	if err != nil {
		t.Fatal(err)
	}
	if redacted != DefaultRedactionMarker {
		t.Fatalf("a sensitive key did not redact the whole document: %#v", redacted)
	}

	for _, invalid := range []json.RawMessage{{}, []byte(`{"a":`), []byte(`{} {}`), {'"', 0xff, '"'}} {
		got, err := m.MaskAny(map[string]any{"body": invalid})
		if err == nil {
			t.Fatalf("invalid message %q was accepted: %#v", invalid, got)
		}
		if got != DefaultRedactionMarker {
			t.Fatalf("invalid message %q did not fail closed: %#v", invalid, got)
		}
	}

	limited := newTestMasker(t, WithMaxInputBytes(8))
	if _, err := limited.MaskAny(map[string]any{"body": json.RawMessage(`{"a":"0123456789"}`)}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("a large message was not charged against the byte limit: %v", err)
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

// pausingReader returns (0, nil) between chunks. That is legal: it means
// "nothing happened", not end of input.
type pausingReader struct {
	chunks []string
	index  int
}

func (r *pausingReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	r.index++
	if chunk == "" {
		return 0, nil
	}
	return copy(p, chunk), nil
}

func TestMaskJSONReaderLimitSurvivesAPause(t *testing.T) {
	m := newTestMasker(t, WithMaxInputBytes(2))
	// Two bytes fill the limit exactly, then the reader pauses before offering
	// more. Reading the pause as EOF would mask the first document and discard
	// the rest without reporting the overrun.
	source := &pausingReader{chunks: []string{"{}", "", "{}"}}
	result, err := m.MaskJSONReader(source)
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("input limit was not reported: result=%s err=%v", result, err)
	}
	if !json.Valid(result) {
		t.Fatalf("fallback is not valid JSON: %s", result)
	}

	// A pause before a genuine end of input is still just a pause.
	within := &pausingReader{chunks: []string{"{}", ""}}
	result, err = m.MaskJSONReader(within)
	if err != nil {
		t.Fatalf("unexpected error for input within the limit: %v", err)
	}
	if string(result) != "{}" {
		t.Fatalf("unexpected JSON: %s", result)
	}
}

// stalledReader never makes progress: every read returns (0, nil).
type stalledReader struct{ reads int }

func (r *stalledReader) Read([]byte) (int, error) {
	r.reads++
	return 0, nil
}

func TestMaskJSONReaderFailsAStalledReader(t *testing.T) {
	m := newTestMasker(t, WithMaxInputBytes(1))
	for _, src := range []io.Reader{
		&stalledReader{},
		// The limit is filled, then the probe for more input stalls.
		io.MultiReader(strings.NewReader("1"), &stalledReader{}),
	} {
		result, err := m.MaskJSONReader(src)
		if !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("stalled reader was not rejected: result=%s err=%v", result, err)
		}
		if string(result) != `"[REDACTED]"` {
			t.Fatalf("unexpected fallback: %s", result)
		}
	}

	// Many pauses in a row that still end in progress are not a stall.
	chunks := append(make([]string, maxEmptyReads-1), "{}")
	result, err := newTestMasker(t).MaskJSONReader(&pausingReader{chunks: chunks})
	if err != nil || string(result) != "{}" {
		t.Fatalf("paused reader was rejected: result=%s err=%v", result, err)
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
	// A comparable type whose dynamic value is not: == on it panics.
	if _, err := NewKeyPolicy(
		Binding{Keys: []string{"a"}, Rule: boxedRule{inner: func() {}}},
		Binding{Keys: []string{"A"}, Rule: boxedRule{inner: func() {}}},
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected duplicate conflict error, got %v", err)
	}
}

type boxedRule struct{ inner any }

func (boxedRule) Name() string                          { return "boxed" }
func (boxedRule) Apply(input RuleInput) (string, error) { return input.Redaction, nil }

func TestKeyPolicyIgnoresSeparators(t *testing.T) {
	m := newTestMasker(t)
	for _, test := range []struct{ key, want string }{
		{key: "accessToken", want: DefaultRedactionMarker},
		{key: "access-token", want: DefaultRedactionMarker},
		{key: "AccessToken", want: DefaultRedactionMarker},
		{key: "ACCESS.TOKEN", want: DefaultRedactionMarker},
		// userId resolves to the ID rule, which keeps the last four units.
		{key: "userId", want: "*alue"},
		{key: "x_api_key", want: DefaultRedactionMarker},
		{key: "clientSecret", want: DefaultRedactionMarker},
		{key: "sessionId", want: DefaultRedactionMarker},
		{key: "CVV", want: DefaultRedactionMarker},
	} {
		result, err := m.MaskValue(test.key, "value")
		if err != nil || result != test.want {
			t.Fatalf("separator variant %q was not masked: %#v, %v", test.key, result, err)
		}
	}
	for _, key := range []string{"accessory", "tokens", "_", "-"} {
		kept, keptErr := m.MaskValue(key, "keep-me")
		if keptErr != nil || kept != "keep-me" {
			t.Fatalf("unmatched key %q was masked: %#v, %v", key, kept, keptErr)
		}
	}

	// Nothing in the defaults may collide cross-rule once separators are
	// stripped: DefaultPolicy silently drops a failing construction.
	if _, err := NewKeyPolicy(DefaultBindings()...); err != nil {
		t.Fatalf("default bindings failed normalized validation: %v", err)
	}
	if _, err := NewKeyPolicy(Binding{Keys: []string{"_-."}, Rule: TokenRule()}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("separator-only key must fail at construction: %v", err)
	}
	if _, err := NewKeyPolicy(
		Binding{Keys: []string{"api_key"}, Rule: PasswordRule()},
		Binding{Keys: []string{"apiKey"}, Rule: TokenRule()},
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("separated spellings must conflict like duplicates: %v", err)
	}

	masked, err := m.MaskJSON([]byte(`{"accessToken":"abc","clientSecret":"s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(masked); got != `{"accessToken":"[REDACTED]","clientSecret":"[REDACTED]"}` {
		t.Fatalf("separator keys not masked in JSON: %s", got)
	}
}

// largeObjectDocument builds a root object past the large-object threshold
// whose member count still fits the pooled member slice, which is what sends
// its buffers to the large buffer pool rather than the sync.Pool. The key
// policy matches whole keys, so the members are public and one real sensitive
// key carries the value an assertion can look for.
func largeObjectDocument() []byte {
	const members, valueLen = 150, 600
	var builder strings.Builder
	filler := strings.Repeat("x", valueLen)
	builder.WriteByte('{')
	for i := range members {
		fmt.Fprintf(&builder, `"display_name_%d":"public-%s-%d",`, i, filler, i)
	}
	builder.WriteString(`"token":"secret-in-wide-object"}`)
	return []byte(builder.String())
}

// TestLargeObjectBufferIsPooled covers the buffer pool kept for objects too
// large for the sync.Pool. It is process-wide state, so a leak or a wrongly
// reused buffer would surface as corruption in an unrelated document.
func TestLargeObjectBufferIsPooled(t *testing.T) {
	for len(streamObjectLargeBufferPool) > 0 {
		<-streamObjectLargeBufferPool
	}
	m := newTestMasker(t)
	document := largeObjectDocument()

	first, err := m.MaskJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(streamObjectLargeBufferPool) == 0 {
		t.Fatal("a large object did not return its buffer to the pool")
	}

	// The second pass runs on the recycled buffer and must produce the same
	// bytes as the first.
	second, err := m.MaskJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("masking through a recycled buffer changed the output")
	}
	if bytes.Contains(second, []byte("secret-in-wide-object")) {
		t.Fatalf("secret survived: %s", second[:64])
	}
}

type concurrentLeaf struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

type concurrentRecord struct {
	Password string           `json:"password"`
	Leaf     concurrentLeaf   `json:"leaf"`
	Leaves   []concurrentLeaf `json:"leaves"`
}

// TestMaskerConcurrentUse exercises the state shared across operations, which
// a scalar call would never reach: the struct metadata cache, the object
// buffer pool, and the separate pool for buffers grown past the large-object
// threshold. Run it under -race; on its own it only proves nothing panics.
func TestMaskerConcurrentUse(t *testing.T) {
	m := newTestMasker(t, WithPreserveSafeTypes())

	// Above streamObjectSmallScratchLimit, so the root object takes the large
	// buffer pool rather than the sync.Pool.
	wideDocument := largeObjectDocument()
	small := []byte(`{"items":[{"token":"secret","name":"public"}],"password":"secret"}`)

	record := concurrentRecord{
		Password: "secret",
		Leaf:     concurrentLeaf{Token: "secret", Name: "public"},
		Leaves:   []concurrentLeaf{{Token: "secret", Name: "public"}},
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := range 20 {
				switch (worker + j) % 4 {
				case 0:
					result, err := m.MaskValue("token", "secret")
					if err != nil || result != DefaultRedactionMarker {
						t.Errorf("scalar: %#v, %v", result, err)
					}
				case 1:
					result, err := m.MaskJSON(small)
					if err != nil || !json.Valid(result) || bytes.Contains(result, []byte("secret")) {
						t.Errorf("json: %s, %v", result, err)
					}
				case 2:
					result, err := m.MaskAny(record)
					if err != nil || strings.Contains(fmt.Sprint(result), "secret") {
						t.Errorf("reflection: %#v, %v", result, err)
					}
				case 3:
					// One worker in four touches the wide document, which is
					// enough to keep the large buffer pool contended without
					// making the suite slow.
					if worker%4 != 3 {
						continue
					}
					result, err := m.MaskJSON(wideDocument)
					if err != nil || !json.Valid(result) || bytes.Contains(result, []byte("secret-in-wide-object")) {
						t.Errorf("wide json: valid=%v err=%v", json.Valid(result), err)
					}
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestRuleFailureNamesTheRule(t *testing.T) {
	failing, err := NewRule("tenant-id", func(RuleInput) (string, error) {
		return "", errors.New("rule is broken")
	})
	if err != nil {
		t.Fatal(err)
	}
	panicking, err := NewRule("panicking", func(RuleInput) (string, error) {
		panic("rule exploded")
	})
	if err != nil {
		t.Fatal(err)
	}

	ruleFor := func(rule Rule) Policy {
		return PolicyFunc(func(field Field) (Decision, error) {
			if field.Key == "token" {
				return Decision{Rule: rule}, nil
			}
			return Decision{}, nil
		})
	}

	// The reflection walker, the JSON walkers and MaskString each report a rule
	// failure through their own path; all of them must name the rule.
	cases := []struct {
		name string
		rule Rule
		run  func(*Masker) error
	}{
		{name: "any", rule: failing, run: func(m *Masker) error {
			_, err := m.MaskAny(map[string]any{"token": "secret"})
			return err
		}},
		{name: "json", rule: failing, run: func(m *Masker) error {
			_, err := m.MaskJSON([]byte(`{"token":"secret"}`))
			return err
		}},
		{name: "json_reader", rule: failing, run: func(m *Masker) error {
			_, err := m.MaskJSONReader(strings.NewReader(`{"token":"secret"}`))
			return err
		}},
		{name: "field", rule: failing, run: func(m *Masker) error {
			_, err := m.MaskField(Field{Key: "token", Kind: KindString}, "secret")
			return err
		}},
		{name: "panic", rule: panicking, run: func(m *Masker) error {
			_, err := m.MaskAny(map[string]any{"token": "secret"})
			return err
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			m, err := New(ruleFor(testCase.rule))
			if err != nil {
				t.Fatal(err)
			}
			err = testCase.run(m)
			var masked *MaskError
			if !errors.As(err, &masked) {
				t.Fatalf("expected a MaskError, got %v", err)
			}
			if masked.Rule != testCase.rule.Name() {
				t.Fatalf("rule not named: %#v", masked)
			}
			if !strings.Contains(masked.Error(), "rule="+testCase.rule.Name()) {
				t.Fatalf("rule missing from message: %q", masked.Error())
			}
		})
	}

	m, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.MaskString("secret", failing)
	var masked *MaskError
	if !errors.As(err, &masked) || masked.Rule != "tenant-id" {
		t.Fatalf("MaskString did not name the rule: %v", err)
	}
}

func TestErrorPathsMatchWhetherOrNotPolicyNeedsPaths(t *testing.T) {
	broken, err := NewRule("broken", func(RuleInput) (string, error) {
		return "", errors.New("rule is broken")
	})
	if err != nil {
		t.Fatal(err)
	}

	// A KeyPolicy never reads Field.Path, so the walker skips building one.
	// Errors must still name the exact location.
	keyPolicy, err := NewKeyPolicy(Binding{Keys: []string{"token"}, Rule: broken})
	if err != nil {
		t.Fatal(err)
	}
	pathPolicy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "token" {
			return Decision{Rule: broken}, nil
		}
		return Decision{}, nil
	})

	type inner struct {
		Token string `json:"token"`
	}
	type outer struct {
		Items []map[string]inner `json:"items"`
	}
	value := outer{Items: []map[string]inner{{"account": {Token: "secret"}}}}

	paths := func(policy Policy) []string {
		m, newErr := New(policy)
		if newErr != nil {
			t.Fatal(newErr)
		}
		_, maskErr := m.MaskAny(value)
		var list *MaskErrors
		if !errors.As(maskErr, &list) {
			t.Fatalf("expected MaskErrors, got %v", maskErr)
		}
		collected := make([]string, 0, len(list.Items))
		for _, item := range list.Items {
			collected = append(collected, item.Path)
		}
		return collected
	}

	lazy, eager := paths(keyPolicy), paths(pathPolicy)
	if !reflect.DeepEqual(lazy, eager) {
		t.Fatalf("paths diverge: key policy %q, path policy %q", lazy, eager)
	}
	if len(lazy) == 0 || lazy[0] != "$[items][0][account][token]" {
		t.Fatalf("unexpected error path: %q", lazy)
	}
}

func TestDiagnosticsAreSafeToLog(t *testing.T) {
	m, err := New(PolicyFunc(func(field Field) (Decision, error) {
		return Decision{}, errors.New("policy is broken")
	}))
	if err != nil {
		t.Fatal(err)
	}

	// A record can be forged with more than an ASCII newline: C1 controls and
	// the Unicode line separators end a line for some readers, and a bidi
	// override makes a line render as something it is not.
	cases := []struct {
		name string
		key  string
	}{
		{name: "newline", key: "evil\nFATAL forged log entry"},
		{name: "control", key: "tab\there"},
		{name: "c1_next_line", key: "evil\u0085FATAL forged log entry"},
		{name: "c1_control_sequence", key: "evil\u009bFATAL forged log entry"},
		{name: "line_separator", key: "evil\u2028FATAL forged log entry"},
		{name: "paragraph_separator", key: "evil\u2029FATAL forged log entry"},
		{name: "bidi_override", key: "evil\u202eFATAL forged log entry"},
		{name: "zero_width", key: "evil\u200bFATAL forged log entry"},
		{name: "quote", key: `key="value"`},
		{name: "backslash", key: `key\path`},
		{name: "logfmt_field", key: "x=1 forged=true"},
		{name: "long_multibyte", key: strings.Repeat("ключ", 200)},
		{name: "long_trailing_backslash", key: strings.Repeat("a", 254) + `\`},
		{name: "long_quoted", key: strings.Repeat(`a"`, 200)},
		{name: "long_all_escaped", key: strings.Repeat("\u2028", 200)},
		{name: "printable_unicode", key: "ключ"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := m.MaskValue(testCase.key, "secret")
			var masked *MaskError
			if !errors.As(err, &masked) {
				t.Fatalf("expected a MaskError, got %v", err)
			}
			message := masked.Error()
			for _, r := range message {
				if !strconv.IsPrint(r) && r != ' ' {
					t.Fatalf("unprintable %U reached the message: %q", r, message)
				}
			}
			// A diagnostic is either the key verbatim, or a quoted form that
			// unquotes back to it. Anything else means the escaping mangled the
			// value or let a delimiter through. A bare quote or backslash does
			// not end a line, but it does end a logfmt value.
			// A secret the text detectors find in the key is redacted first.
			key := redactDiagnostic(testCase.key)
			switch field := masked.Field; {
			case strings.HasSuffix(field, "...(truncated)"):
				// A truncated diagnostic must still be well formed: a cut that
				// lands inside an escape sequence or before the closing quote
				// produces exactly the broken value the escaping prevents.
				body := strings.TrimSuffix(field, "...(truncated)")
				if strings.HasPrefix(body, `"`) {
					unquoted, unquoteErr := strconv.Unquote(body)
					if unquoteErr != nil {
						t.Fatalf("truncated diagnostic is not a valid quoted string: %q", body)
					}
					body = unquoted
				}
				if !strings.HasPrefix(key, body) {
					t.Fatalf("truncated diagnostic is not a prefix of the key: %q", body)
				}
			case field == key:
				// A quote or backslash closes a value early; a space starts a
				// new logfmt field. None may survive unquoted.
				if strings.ContainsAny(field, "\"\\ ") {
					t.Fatalf("raw delimiter left in the diagnostic: %q", message)
				}
			default:
				unquoted, unquoteErr := strconv.Unquote(field)
				if unquoteErr != nil {
					t.Fatalf("diagnostic is neither verbatim nor quoted: %q", field)
				}
				if unquoted != key {
					t.Fatalf("quoted diagnostic does not round-trip: %q", field)
				}
			}
			if !utf8.ValidString(message) {
				t.Fatalf("message is not valid UTF-8: %q", message)
			}
			// Escaping produces at most four output bytes per input byte, so
			// the escaped form is longer than the input bound but still
			// bounded.
			if limit := 4*maxDiagnosticLen + len(`""...(truncated)`); len(masked.Path) > limit {
				t.Fatalf("path was not truncated: %d bytes", len(masked.Path))
			}
		})
	}

	// Printable text must stay readable rather than being escaped away.
	_, err = m.MaskValue("ключ", "secret")
	var masked *MaskError
	if !errors.As(err, &masked) || !strings.Contains(masked.Error(), "ключ") {
		t.Fatalf("printable Unicode was mangled: %v", err)
	}
}

func TestKeyPolicyUnicodeFallbackDoesNotRebuildKeys(t *testing.T) {
	policy, err := NewKeyPolicy(DefaultBindings()...)
	if err != nil {
		t.Fatal(err)
	}
	// Stripping and lowering the field key are the only allocations; the
	// stored keys were normalized once in NewKeyPolicy.
	allocs := testing.AllocsPerRun(100, func() { _, _ = policy.Decide(Field{Key: "имя_поля"}) })
	if allocs > 2 {
		t.Fatalf("unicode miss allocated %.0f times", allocs)
	}
}

type textOctet uint8

func (textOctet) MarshalText() ([]byte, error) { return []byte("octet"), nil }

type mutatingBytesMarshaler []byte

func (b mutatingBytesMarshaler) MarshalText() ([]byte, error) {
	text := string(b)
	for index := range b {
		b[index] = 'x'
	}
	return []byte(text), nil
}

type nestedMutatingMarshaler struct {
	Items  []string
	Labels map[string]string
	Next   *nestedMutatingMarshaler
}

func (n *nestedMutatingMarshaler) MarshalText() ([]byte, error) {
	text := n.Items[0]
	n.Items[0] = "changed"
	n.Labels["k"] = "changed"
	if n.Next != nil {
		n.Next.Items = nil
	}
	return []byte(text), nil
}

type opaqueTextMarshaler struct {
	Name  string
	cache *string
}

func (opaqueTextMarshaler) MarshalText() ([]byte, error) {
	panic("an opaque receiver must not be called")
}

type cachingTextMarshaler struct{ calls int }

type byteBackedTextMarshaler []byte

func (byteBackedTextMarshaler) MarshalText() ([]byte, error) { return []byte("short"), nil }

func (c *cachingTextMarshaler) MarshalText() ([]byte, error) {
	c.calls++
	return []byte("cached"), nil
}

func TestTextMarshalerIsolation(t *testing.T) {
	m := newTestMasker(t)
	raw := mutatingBytesMarshaler("abc")
	if got, err := m.MaskAny(map[string]any{"v": raw}); err != nil || got.(map[string]any)["v"] != "abc" {
		t.Fatalf("byte-backed marshaler: %#v %v", got, err)
	}
	if string(raw) != "abc" {
		t.Fatalf("a value receiver mutated the input: %q", raw)
	}

	input := &struct{ Value nestedMutatingMarshaler }{
		Value: nestedMutatingMarshaler{Items: []string{"head"}, Labels: map[string]string{"k": "v"}},
	}
	want := map[string]any{"Value": map[string]any{
		"Items": []any{"head"}, "Labels": map[string]any{"k": "v"}, "Next": nil,
	}}
	if got, err := m.MaskAny(input); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("a marshaler holding pointers and maps was not walked: %#v %v", got, err)
	}
	if input.Value.Items[0] != "head" || input.Value.Labels["k"] != "v" {
		t.Fatalf("a pointer receiver mutated nested input: %#v", input.Value)
	}

	cached := "dummy-cache"
	got, err := m.MaskAny(map[string]any{"v": opaqueTextMarshaler{Name: "n", cache: &cached}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"v": map[string]any{"Name": "n"}}) {
		t.Fatalf("a receiver that cannot be isolated was not walked: %#v %v", got, err)
	}

	stamp := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	if got, err := m.MaskAny(map[string]any{"at": stamp}); err != nil || got.(map[string]any)["at"] != "2026-09-29T10:00:00Z" {
		t.Fatalf("time.Time: %#v %v", got, err)
	}
}

func TestTextMarshalerReviewCases(t *testing.T) {
	m := newTestMasker(t)
	scalar, err := m.MaskValue("level", textMarshalerLevel(2))
	if err != nil || scalar != "debug" {
		t.Fatalf("scalar fast path skipped MarshalText: %#v %v", scalar, err)
	}

	policy := PolicyFunc(func(field Field) (Decision, error) {
		switch field.Key {
		case "omitted":
			return Decision{Omit: true}, nil
		case "full":
			return Decision{Rule: FullRule()}, nil
		}
		return Decision{}, nil
	})
	decided, err := New(Chain(policy, DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := decided.MaskAny(map[string]any{
		"omitted":  failingTextMarshaler{},
		"full":     panickingTextMarshaler{},
		"password": failingTextMarshaler{},
		"token":    panickingTextMarshaler{},
		"kept":     "value",
	})
	if err != nil {
		t.Fatalf("a fully redacting decision ran MarshalText: %v", err)
	}
	masked := result.(map[string]any)
	if _, present := masked["omitted"]; present || masked["full"] != DefaultRedactionMarker ||
		masked["password"] != DefaultRedactionMarker || masked["token"] != DefaultRedactionMarker || masked["kept"] != "value" {
		t.Fatalf("unexpected decisions: %#v", masked)
	}

	partial, err := NewRule("first", func(input RuleInput) (string, error) { return input.Value[:1], nil })
	if err != nil {
		t.Fatal(err)
	}
	ruled, err := New(PolicyFunc(func(Field) (Decision, error) { return Decision{Rule: partial}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ruled.MaskValue("level", textMarshalerLevel(2)); err != nil || got != "d" {
		t.Fatalf("rule did not receive the rendered text: %#v %v", got, err)
	}

	octets, err := m.MaskAny(map[string]any{"o": []textOctet{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if got := octets.(map[string]any)["o"]; !reflect.DeepEqual(got, []any{"octet", "octet"}) {
		t.Fatalf("byte-kind marshalers were base64-encoded: %#v", got)
	}

	limited, err := New(DefaultPolicy(), WithMaxNodes(16), WithMaxInputBytes(1<<16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.MaskAny(map[string]any{"blob": make([]byte, 1<<20)}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("a large byte slice bypassed the byte limit: %v", err)
	}
	// One slice aliased from many places is charged every time it is encoded.
	shared := make([]byte, 1<<13)
	aliases := map[string]any{}
	for index := range 10 {
		aliases[strconv.Itoa(index)] = shared
	}
	if _, err := limited.MaskAny(aliases); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("aliased byte slices bypassed the byte limit: %v", err)
	}
	if got, err := newTestMasker(t).MaskAny(map[string]any{"blob": make([]byte, 200<<10)}); err != nil || got.(map[string]any)["blob"] == DefaultRedactionMarker {
		t.Fatalf("a 200 KiB byte slice failed under the default limits: %v", err)
	}
	if got, err := limited.MaskAny(map[string]any{"blob": []byte("hi")}); err != nil || got.(map[string]any)["blob"] != "aGk=" {
		t.Fatalf("a small byte slice within the limit: %#v %v", got, err)
	}
	input := &struct{ Value cachingTextMarshaler }{}
	if got, err := m.MaskAny(input); err != nil || got.(map[string]any)["Value"] != "cached" {
		t.Fatalf("pointer-receiver marshaler: %#v %v", got, err)
	}
	if input.Value.calls != 0 {
		t.Fatalf("MarshalText mutated the input: %d calls recorded", input.Value.calls)
	}

	if got, err := m.MaskAny(map[string]any{"blob": byteBackedTextMarshaler(make([]byte, 1<<10))}); err != nil ||
		got.(map[string]any)["blob"] != "short" {
		t.Fatalf("a byte-backed marshaler: %#v %v", got, err)
	}
	if _, err := limited.MaskAny(map[string]any{"blob": byteBackedTextMarshaler(make([]byte, 1<<20))}); !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("copying a large receiver bypassed the node limit: %v", err)
	}

	partialLimited, err := New(PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "blob" {
			return Decision{Rule: partial}, nil
		}
		return Decision{}, nil
	}), WithMaxInputBytes(16))
	if err != nil {
		t.Fatal(err)
	}
	_, err = partialLimited.MaskAny(map[string]any{"a": map[string]any{"blob": make([]byte, 64)}})
	var maskErr *MaskError
	if !errors.As(err, &maskErr) || maskErr.Code != CodeInputLimit || maskErr.Depth != 2 {
		t.Fatalf("ruled byte slice lost its depth: %#v", err)
	}
}

type largeTextArray [1 << 20]byte

func (largeTextArray) MarshalText() ([]byte, error) { return []byte("large"), nil }

type cyclicTextMap map[string]cyclicTextMap

func (cyclicTextMap) MarshalText() ([]byte, error) { return []byte("map"), nil }

type selfTextNode struct {
	Name string
	Next *selfTextNode
}

func (*selfTextNode) MarshalText() ([]byte, error) { return []byte("self"), nil }

type zeroSizedA struct{}

type zeroSizedB struct{}

type zeroSizedPointers struct {
	A *zeroSizedA
	B *zeroSizedB
}

func (zeroSizedPointers) MarshalText() ([]byte, error) { return []byte("zero"), nil }

func TestTextMarshalerCopyGraphs(t *testing.T) {
	core, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	limited, err := New(DefaultPolicy(), WithMaxNodes(16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.MaskAny(map[string]any{"blob": largeTextArray{}}); !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("a large array receiver was copied past the node limit: %v", err)
	}
	cyclic := cyclicTextMap{}
	cyclic["self"] = cyclic
	if _, err := core.MaskAny(map[string]any{"map": cyclic}); !errors.Is(err, ErrCycle) {
		t.Fatalf("a cyclic map receiver was not walked: %v", err)
	}
	got, err := core.MaskAny(map[string]any{
		"node": &selfTextNode{Name: "n"},
		"zero": zeroSizedPointers{A: &zeroSizedA{}, B: &zeroSizedB{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"node": map[string]any{"Name": "n", "Next": nil},
		"zero": map[string]any{"A": map[string]any{}, "B": map[string]any{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("receivers holding pointers or maps were not walked: got %#v, want %#v", got, want)
	}
}

type textChain struct {
	Next *textChain
}

func (*textChain) MarshalText() ([]byte, error) { return []byte("chain"), nil }

type textViews struct {
	A, B []int
}

func (v *textViews) MarshalText() ([]byte, error) {
	v.A[0]++
	return []byte(strconv.Itoa(v.B[0]) + "/" + strconv.Itoa(cap(v.A))), nil
}

func TestTextMarshalerCopyLimitsAndViews(t *testing.T) {
	shallow, err := New(DefaultPolicy(), WithMaxDepth(3))
	if err != nil {
		t.Fatal(err)
	}
	chain := &textChain{}
	for range 10 {
		chain = &textChain{Next: chain}
	}
	if _, err := shallow.MaskAny(map[string]any{"chain": chain}); !errors.Is(err, ErrDepthLimit) {
		t.Fatalf("a receiver deeper than the limit was copied: %v", err)
	}

	core, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	shared := make([]int, 1, 4)
	got, err := core.MaskAny(map[string]any{"v": &textViews{A: shared, B: shared}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"v": "1/4"}) {
		t.Fatalf("shared slice or capacity lost in the copy: %#v, %v", got, err)
	}
	if shared[0] != 0 {
		t.Fatalf("MarshalText mutated the input: %v", shared)
	}

	buffer := []int{0, 0, 0}
	if _, err := core.MaskAny(map[string]any{"v": &textViews{A: buffer[:2], B: buffer[1:]}}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("overlapping slices were copied apart: %v", err)
	}
}

func TestTextMarshalerCopyFailureDepth(t *testing.T) {
	shallow, err := New(DefaultPolicy(), WithMaxDepth(3))
	if err != nil {
		t.Fatal(err)
	}
	chain := &textChain{}
	for range 10 {
		chain = &textChain{Next: chain}
	}
	_, err = shallow.MaskAny(map[string]any{"chain": chain})
	var maskErr *MaskError
	if !errors.As(err, &maskErr) || maskErr.Code != CodeDepthLimit || maskErr.Depth != 4 {
		t.Fatalf("the depth failure lost the depth it occurred at: %#v", err)
	}
}

type lockedTextMarshaler struct {
	Name string
	mu   sync.Mutex
}

func (m *lockedTextMarshaler) MarshalText() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return []byte(m.Name), nil
}

type countedTextMarshaler struct {
	Name  string
	Count sync.WaitGroup
}

func (*countedTextMarshaler) MarshalText() ([]byte, error) { return []byte("counted"), nil }

func TestTextMarshalerWithLockIsNotCopied(t *testing.T) {
	core, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	held := &lockedTextMarshaler{Name: "n"}
	held.mu.Lock()
	done := make(chan any, 1)
	go func() {
		got, err := core.MaskAny(map[string]any{"v": held, "w": &countedTextMarshaler{Name: "c"}})
		if err != nil {
			done <- err
			return
		}
		done <- got
	}()
	select {
	case got := <-done:
		want := map[string]any{"v": map[string]any{"Name": "n"}, "w": map[string]any{"Name": "c", "Count": map[string]any{}}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("a marshaler holding a lock was not walked: %#v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MarshalText ran on a copy of a held lock")
	}
	held.mu.Unlock()
}

type Credentials struct{ Value string }

type reviewNamedEmbedding struct {
	Credentials `json:"Credentials"`
}

func TestNamedEmbeddingIsNotPromoted(t *testing.T) {
	m, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	value := reviewNamedEmbedding{Credentials{Value: "dummy-secret"}}
	got, err := m.MaskAny(value)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(want), `"Credentials":`) {
		t.Fatalf("encoding/json no longer names the embedding: %s", want)
	}
	if fmt.Sprint(got) != "map[Credentials:[REDACTED]]" {
		t.Fatalf("got %v", got)
	}
}

func TestFlatStructRejectsInvalidUTF8(t *testing.T) {
	m, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.MaskAny(struct{ Note string }{Note: string([]byte{0xff})})
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("err = %v, want ErrInvalidUTF8", err)
	}
}

func TestStreamRuleErrorsKeepTheirPaths(t *testing.T) {
	failing, err := NewRule("failing", func(RuleInput) (string, error) { return "", errors.New("dummy") })
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewKeyPolicy(Binding{Keys: []string{"token"}, Rule: failing})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.MaskJSON([]byte(`{"a":{"token":"dummy"},"b":{"token":"dummy"}}`))
	var multi *MaskErrors
	if !errors.As(err, &multi) || len(multi.Items) != 2 {
		t.Fatalf("err = %v, want two errors", err)
	}
	for i, path := range []string{"$[a][token]", "$[b][token]"} {
		if multi.Items[i].Path != path {
			t.Fatalf("error %d path = %q, want %q", i, multi.Items[i].Path, path)
		}
	}
}

// TestByteSliceContentIsInspected checks that base64 does not hide a secret:
// a byte slice that holds one as text becomes the marker in every walker,
// while binary content and harmless text keep their base64 form.
func TestByteSliceContentIsInspected(t *testing.T) {
	m := newTestMasker(t)
	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{name: "pair", value: []byte("password=dummy"), want: DefaultRedactionMarker},
		{name: "token", value: []byte("auth " + textDummyGitHub), want: DefaultRedactionMarker},
		{name: "json document", value: []byte(`{"token":"dummy"}`), want: DefaultRedactionMarker},
		{name: "harmless text", value: []byte("hi"), want: "aGk="},
		{name: "binary", value: []byte{0xff, 0x00, '='}, want: "/wA9"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := m.MaskAny(map[string]any{"blob": test.value})
			if err != nil {
				t.Fatal(err)
			}
			if blob := got.(map[string]any)["blob"]; blob != test.want {
				t.Fatalf("MaskAny = %#v, want %q", blob, test.want)
			}
			encoded, err := m.MaskJSONValue(map[string]any{"blob": test.value})
			if err != nil {
				t.Fatal(err)
			}
			if want := `{"blob":"` + test.want + `"}`; string(encoded) != want {
				t.Fatalf("MaskJSONValue = %s, want %s", encoded, want)
			}
		})
	}

	plain := newTestMasker(t, WithoutValueInspection())
	got, err := plain.MaskAny(map[string]any{"blob": []byte("password=dummy")})
	if err != nil {
		t.Fatal(err)
	}
	if blob := got.(map[string]any)["blob"]; blob != "cGFzc3dvcmQ9ZHVtbXk=" {
		t.Fatalf("without inspection the slice is plain base64: %#v", blob)
	}
}

// TestDiagnosticsRedactSecretsInKeys checks that a key carrying a secret does
// not reach the log through the error that names its location.
func TestDiagnosticsRedactSecretsInKeys(t *testing.T) {
	m := newTestMasker(t)
	for _, key := range []string{"password=dummy-secret", "Bearer " + textDummyGitHub, textDummyJWT} {
		_, err := m.MaskAny(map[string]any{key: make(chan int)})
		if err == nil {
			t.Fatalf("key %q: expected an error", key)
		}
		message := err.Error()
		for _, secret := range []string{"dummy-secret", textDummyGitHub, textDummyJWT} {
			if strings.Contains(message, secret) {
				t.Fatalf("key %q leaked into the diagnostic: %s", key, message)
			}
		}
		if !strings.Contains(message, DefaultRedactionMarker) {
			t.Fatalf("key %q: diagnostic lost its marker: %s", key, message)
		}
	}
}

// TestDefaultPolicyCommonSpellings covers key spellings that services use
// for credentials besides the canonical ones.
func TestDefaultPolicyCommonSpellings(t *testing.T) {
	m := newTestMasker(t)
	for _, key := range []string{"pwd", "api_token", "apiToken", "secret_key", "aws_secret_access_key", "secretAccessKey", "private_token", "PRIVATE-TOKEN", "otp", "X-Api-Token", "x-access-token"} {
		got, err := m.MaskValue(key, "dummy-value")
		if err != nil {
			t.Fatal(err)
		}
		if got != DefaultRedactionMarker {
			t.Fatalf("key %q was not masked: %#v", key, got)
		}
	}
}
