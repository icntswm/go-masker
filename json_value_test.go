package masker

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// plainTree mirrors what MaskJSONValue promises for named scalars: every
// named bool/int/uint/float/string becomes its underlying value.
func plainTree(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		if typed == nil {
			return nil
		}
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = plainTree(value)
		}
		return out
	case []any:
		if typed == nil {
			return nil
		}
		out := make([]any, len(typed))
		for index, value := range typed {
			out[index] = plainTree(value)
		}
		return out
	case json.Number:
		return typed
	}
	reflected := reflect.ValueOf(v)
	if !reflected.IsValid() {
		return v
	}
	switch reflected.Kind() {
	case reflect.Bool:
		return reflected.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return reflected.Uint()
	case reflect.Float64:
		return reflected.Float()
	case reflect.Float32:
		// Kept as float32 so json.Marshal formats it with 32 bits.
		return float32(reflected.Float())
	case reflect.String:
		return reflected.String()
	default:
		return v
	}
}

// referenceJSON is what MaskJSONValue promises: MaskAny's tree, with named
// scalars flattened, encoded by encoding/json.
func referenceJSON(m *Masker, v any) ([]byte, error) {
	masked, err := m.MaskAny(v)
	if err != nil {
		return m.safeJSONFallback(), err
	}
	out, marshalErr := json.Marshal(plainTree(masked))
	if marshalErr != nil {
		return m.safeJSONFallback(), marshalErr
	}
	return out, nil
}

type parityJSONString string

func (parityJSONString) MarshalJSON() ([]byte, error) { return []byte(`"leaked"`), nil }

type parityJSONInt int

func (parityJSONInt) MarshalJSON() ([]byte, error) { return []byte("999"), nil }

type parityEmbed struct{ City string }

type parityInner struct{ Note string }

type parityLeaf struct {
	Note string
	Seen bool
}

type parityMixed struct {
	parityEmbed
	Name     string
	Attempts int
	Ratio    float64
	Active   bool
	Password string
	Inner    *parityInner
	Leaves   []parityLeaf
	Excluded string `json:"-"`
	Renamed  string `json:"renamed"`
	Skipped  string `json:"skipped,omitempty"`
	Omitted  string `mask:"omit"`
	Alias    string `json:"zz_alias"`
	Full     string `mask:"full"`
	hidden   string
}

type parityFlat struct {
	Name  string
	Count int
	Ratio float64
	OK    bool
	// The tags reverse the order of the Go names, so key order is checked.
	First  string `json:"z_first"`
	Second int    `json:"a_second"`
}

type parityConflictLeft struct{ Value string }

type parityConflictRight struct{ Value string }

type parityConflict struct {
	parityConflictLeft
	parityConflictRight
}

type parityCycle struct {
	Next *parityCycle
}

type paritySecretTag struct {
	Token string `secret:"token"`
	Team  string
}

type parityLast4Tag struct {
	Card string `mask:"last4"`
}

type parityInput struct {
	name  string
	value any
}

func TestMaskJSONValueMatchesMaskAny(t *testing.T) {
	cycleMap := map[string]any{"self": nil}
	cycleMap["self"] = cycleMap
	cyclePtr := &parityCycle{}
	cyclePtr.Next = cyclePtr
	deep := map[string]any{}
	current := deep
	for range 10 {
		next := map[string]any{}
		current["next"] = next
		current = next
	}
	large := make([]map[string]any, 50)
	for i := range large {
		large[i] = map[string]any{"id": i, "name": "n"}
	}
	inner := &parityInner{Note: "n"}
	doubleInner := &inner

	inputs := []parityInput{
		{name: "nil", value: nil},
		{name: "string", value: "plain"},
		{name: "email", value: "alice@example.com"},
		{name: "int zero", value: 0},
		{name: "int 255", value: 255},
		{name: "int 256", value: 256},
		{name: "int -1", value: -1},
		{name: "int max", value: math.MaxInt64},
		{name: "uint max", value: uint64(math.MaxUint64)},
		{name: "float32", value: float32(1.5)},
		{name: "float 1e21", value: 1e21},
		{name: "float 1e-7", value: 1e-7},
		{name: "float -0", value: math.Copysign(0, -1)},
		{name: "float NaN", value: math.NaN()},
		{name: "float Inf", value: math.Inf(1)},
		{name: "true", value: true},
		{name: "number 12", value: json.Number("12")},
		{name: "number bad", value: json.Number("bad")},
		{name: "named string", value: parityJSONString("named")},
		{name: "named int", value: parityJSONInt(7)},
		{name: "bytes", value: []byte("x")},
		{name: "raw message", value: json.RawMessage(`{"password":"p","n":1}`)},
		{name: "time", value: time.Date(2026, 9, 28, 8, 30, 0, 0, time.UTC)},
		{name: "unsorted keys", value: map[string]any{"zeta": 1, "alpha": 2, "drop": "d", "password": "s", "token": "t"}},
		{name: "escaping", value: map[string]any{"a<b>&c": "v<>&", "sep": "x\u2028y", "key\u2028sep": "z"}},
		{name: "nested maps", value: map[string]any{"a": map[string]any{"b": map[string]any{"password": "p"}}}},
		{name: "empty map", value: map[string]any{}},
		{name: "nil map", value: map[string]any(nil)},
		{name: "nil slice", value: []any(nil)},
		{name: "mixed array", value: []any{nil, 1, "x"}},
		{name: "int array", value: [3]int{}},
		{name: "int key map", value: map[int]string{1: "a"}},
		{name: "func", value: func() {}},
		{name: "map cycle", value: cycleMap},
		{name: "pointer cycle", value: cyclePtr},
		{name: "deep maps", value: deep},
		{
			name: "mixed struct",
			value: parityMixed{
				Name:     "alice",
				Attempts: 3,
				Ratio:    0.5,
				Active:   true,
				Password: "s3cret",
				Inner:    &parityInner{Note: "n"},
				Leaves:   []parityLeaf{{Note: "a", Seen: true}, {Note: "b"}},
				Excluded: "excluded",
				Renamed:  "renamed",
				Omitted:  "omitted",
				Alias:    "alias",
				Full:     "full",
				hidden:   "hidden",
			},
		},
		{name: "flat struct", value: parityFlat{Name: "n", Count: 3, Ratio: 0.5, OK: true, First: "f", Second: 2}},
		{name: "conflict struct", value: parityConflict{parityConflictLeft{Value: "a"}, parityConflictRight{Value: "b"}}},
		{name: "struct pointer", value: &parityInner{Note: "n"}},
		{name: "double pointer", value: doubleInner},
		{name: "large array", value: large},
	}

	last4, err := NewRule("last4", func(input RuleInput) (string, error) {
		if len(input.Value) <= 4 {
			return "****", nil
		}
		return "****" + input.Value[len(input.Value)-4:], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	omitDrop := Chain(PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "drop" {
			return Decision{Omit: true}, nil
		}
		return Decision{}, nil
	}), DefaultPolicy())
	byPath := PolicyFunc(func(field Field) (Decision, error) {
		if field.Path == "$[items][1][name]" {
			return Decision{Rule: FullRule()}, nil
		}
		return Decision{}, nil
	})

	configs := []struct {
		name   string
		masker *Masker
		extra  []parityInput
	}{
		{name: "default", masker: newTestMasker(t)},
		{name: "preserve", masker: newTestMasker(t, WithPreserveSafeTypes())},
		{name: "redaction", masker: newTestMasker(t, WithRedaction("***"))},
		{name: "max depth", masker: newTestMasker(t, WithMaxDepth(3))},
		{name: "max nodes", masker: newTestMasker(t, WithMaxNodes(10))},
		{name: "omit drop", masker: mustParityMasker(t, omitDrop)},
		{name: "by path", masker: mustParityMasker(t, byPath), extra: []parityInput{
			{name: "items", value: map[string]any{"items": []any{
				map[string]any{"name": "first"},
				map[string]any{"name": "second", "password": "p"},
			}}},
		}},
		{name: "no inspection", masker: newTestMasker(t, WithoutValueInspection())},
		{name: "secret tag", masker: newTestMasker(t, WithStructTag("secret")), extra: []parityInput{
			{name: "tagged", value: paritySecretTag{Token: "t", Team: "core"}},
		}},
		{name: "last4 tag", masker: mustParityMasker(t, DefaultPolicy(), WithTagRule("last4", last4)), extra: []parityInput{
			{name: "tagged", value: parityLast4Tag{Card: "4111 1111 1111 1111"}},
		}},
	}

	for _, config := range configs {
		for _, input := range append(append([]parityInput{}, inputs...), config.extra...) {
			t.Run(config.name+"/"+input.name, func(t *testing.T) {
				got, gotErr := config.masker.MaskJSONValue(input.value)
				want, wantErr := referenceJSON(config.masker, input.value)
				if !bytes.Equal(got, want) {
					t.Fatalf("bytes differ:\nMaskJSONValue %s\nreference    %s", got, want)
				}
				if (gotErr == nil) != (wantErr == nil) {
					t.Fatalf("error presence differs: got %v, want %v", gotErr, wantErr)
				}
				var gotCode *MaskError
				var wantCode *MaskError
				gotHas := errors.As(gotErr, &gotCode)
				wantHas := errors.As(wantErr, &wantCode)
				if gotHas && wantHas && gotCode.Code != wantCode.Code {
					t.Fatalf("error codes differ: got %s, want %s", gotCode.Code, wantCode.Code)
				}
				if gotErr == nil && !json.Valid(got) {
					t.Fatalf("output is not valid JSON: %s", got)
				}
			})
		}
	}
}

func mustParityMasker(t *testing.T, policy Policy, opts ...Option) *Masker {
	t.Helper()
	m, err := New(policy, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMaskJSONValueNilMasker(t *testing.T) {
	var m *Masker
	result, err := m.MaskJSONValue(1)
	if string(result) != `"[REDACTED]"` || err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unexpected nil masker result: %s, %v", result, err)
	}
}

func TestMaskJSONValuePanickingPolicy(t *testing.T) {
	policy := PolicyFunc(func(Field) (Decision, error) { panic("unsafe detail") })
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, anyErr := m.MaskAny(map[string]any{"k": "v"})
	value, valueErr := m.MaskJSONValue(map[string]any{"k": "v"})
	var anyCode *MaskError
	var valueCode *MaskError
	if !errors.As(anyErr, &anyCode) || !errors.As(valueErr, &valueCode) {
		t.Fatalf("expected mask errors: MaskAny %v, MaskJSONValue %v", anyErr, valueErr)
	}
	if anyCode.Code != valueCode.Code {
		t.Fatalf("codes differ: MaskAny %s, MaskJSONValue %s", anyCode.Code, valueCode.Code)
	}
	if string(value) != string(m.safeJSONFallback()) {
		t.Fatalf("unexpected fallback: %s", value)
	}
	if strings.Contains(valueErr.Error(), "unsafe") {
		t.Fatalf("error exposed callback detail: %v", valueErr)
	}
}

func TestMaskJSONValueMapOverNodeLimit(t *testing.T) {
	m := newTestMasker(t, WithMaxNodes(3))
	input := map[string]any{"a": 1, "b": 2, "c": 3}
	_, anyErr := m.MaskAny(input)
	value, valueErr := m.MaskJSONValue(input)
	if !errors.Is(anyErr, ErrNodeLimit) || !errors.Is(valueErr, ErrNodeLimit) {
		t.Fatalf("expected node limit: MaskAny %v, MaskJSONValue %v", anyErr, valueErr)
	}
	if string(value) != `"[REDACTED]"` {
		t.Fatalf("unexpected fallback: %s", value)
	}
	// A map that fits the budget exactly is still written in full.
	fits := map[string]any{"a": 1, "b": 2}
	if value, err := m.MaskJSONValue(fits); err != nil || string(value) != `{"a":"1","b":"2"}` {
		t.Fatalf("unexpected result for a map at the limit: %s, %v", value, err)
	}
}
