package masker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestJSONWalkerScalarObjectArraySemantics(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "null root", input: `null`, want: `null`},
		{name: "string root", input: `"plain"`, want: `"plain"`},
		{name: "bool root", input: `true`, want: `"true"`},
		{name: "number root", input: `900719925474099312345`, want: `900719925474099312345`},
		{
			name:  "object",
			input: `{"safe":"plain","token":"secret","enabled":false}`,
			want:  `{"enabled":"false","safe":"plain","token":"[REDACTED]"}`,
		},
		{
			name:  "array",
			input: `[true,12345678901234567890,{"password":"secret"}]`,
			want:  `["true",12345678901234567890,{"password":"[REDACTED]"}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := newTestMasker(t).MaskJSON([]byte(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("unexpected JSON: got %s want %s", got, test.want)
			}
		})
	}
}

func TestJSONWalkerPreserveSafeAndCustomRedaction(t *testing.T) {
	var ruleInput RuleInput
	rule, err := NewRule("capture", func(input RuleInput) (string, error) {
		ruleInput = input
		return input.Redaction, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Key == "secret" {
			return Decision{Rule: rule}, nil
		}
		return Decision{}, nil
	})
	m, err := New(policy, WithPreserveSafeTypes(), WithRedaction("MASKED"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.MaskJSON([]byte(`{"safe_bool":true,"safe_number":900719925474099312345,"secret":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"safe_bool":true,"safe_number":900719925474099312345,"secret":"MASKED"}`
	if string(got) != want {
		t.Fatalf("unexpected JSON: got %s want %s", got, want)
	}
	wantInput := RuleInput{Value: "12345678901234567890", Kind: KindNumber, Redaction: "MASKED"}
	if ruleInput != wantInput {
		t.Fatalf("unexpected rule input: got %#v want %#v", ruleInput, wantInput)
	}
}

func TestJSONWalkerScalarRuleInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  RuleInput
	}{
		{name: "string", input: `"secret"`, want: RuleInput{Value: "secret", Kind: KindString, Redaction: "MASKED"}},
		{name: "bool", input: `true`, want: RuleInput{Value: "true", Kind: KindBool, Redaction: "MASKED"}},
		{
			name:  "number",
			input: `12345678901234567890`,
			want:  RuleInput{Value: "12345678901234567890", Kind: KindNumber, Redaction: "MASKED"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotInput RuleInput
			rule, err := NewRule("capture", func(input RuleInput) (string, error) {
				gotInput = input
				return input.Redaction, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			policy := PolicyFunc(func(Field) (Decision, error) {
				return Decision{Rule: rule}, nil
			})
			m, err := New(policy, WithRedaction("MASKED"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := m.MaskJSON([]byte(test.input))
			if err != nil || string(got) != `"MASKED"` {
				t.Fatalf("unexpected result: %s, %v", got, err)
			}
			if gotInput != test.want {
				t.Fatalf("unexpected rule input: got %#v want %#v", gotInput, test.want)
			}
		})
	}
}

func TestJSONWalkerNestedPolicyFields(t *testing.T) {
	var fields []Field
	policy := PolicyFunc(func(field Field) (Decision, error) {
		fields = append(fields, field)
		if field.Key == "secret" {
			return Decision{Rule: FullRule()}, nil
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.MaskJSON([]byte(`{"outer":{"items":[{"secret":"value"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"outer":{"items":[{"secret":"[REDACTED]"}]}}` {
		t.Fatalf("unexpected JSON: %s", got)
	}
	want := []Field{
		{Path: "$", Source: SourceJSON, Kind: KindObject},
		{Key: "outer", Path: "$[outer]", Source: SourceJSON, Kind: KindObject},
		{Key: "items", Path: "$[outer][items]", Source: SourceJSON, Kind: KindArray},
		{Path: "$[outer][items][0]", Source: SourceJSON, Kind: KindObject},
		{Key: "secret", Path: "$[outer][items][0][secret]", Source: SourceJSON, Kind: KindString},
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("unexpected policy fields:\ngot  %#v\nwant %#v", fields, want)
	}
}

func TestJSONWalkerContainerDecisions(t *testing.T) {
	var (
		fields    []Field
		ruleInput RuleInput
	)
	rule, err := NewRule("container", func(input RuleInput) (string, error) {
		ruleInput = input
		return "container-masked", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := PolicyFunc(func(field Field) (Decision, error) {
		fields = append(fields, field)
		switch field.Key {
		case "payload":
			return Decision{Rule: rule}, nil
		case "omitted":
			return Decision{Omit: true}, nil
		default:
			return Decision{}, nil
		}
	})
	m, err := New(policy, WithRedaction("MASKED"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.MaskJSON([]byte(`{"payload":{"secret":"value"},"omitted":["value"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"payload":"container-masked"}` {
		t.Fatalf("unexpected JSON: %s", got)
	}
	if ruleInput != (RuleInput{Kind: KindObject, Redaction: "MASKED"}) {
		t.Fatalf("unexpected container rule input: %#v", ruleInput)
	}
	for _, field := range fields {
		if strings.Contains(field.Path, "secret") || strings.Contains(field.Path, "[0]") {
			t.Fatalf("container descendants reached policy: %#v", fields)
		}
	}
}

func TestJSONWalkerContainerRuleFailureIsFailClosed(t *testing.T) {
	var fields []Field
	rule, err := NewRule("error", func(RuleInput) (string, error) {
		return "", errors.New("unsafe detail")
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := PolicyFunc(func(field Field) (Decision, error) {
		fields = append(fields, field)
		if field.Key == "payload" {
			return Decision{Rule: rule}, nil
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.MaskJSON([]byte(`{"payload":{"secret":"value"},"safe":"value"}`))
	if string(got) != `"[REDACTED]"` || err == nil || !errors.Is(err, ErrRuleFailure) {
		t.Fatalf("unexpected failure: result=%s err=%v", got, err)
	}
	for _, field := range fields {
		if field.Key == "secret" {
			t.Fatalf("failed container descendants reached policy: %#v", fields)
		}
	}
}

func TestJSONWalkerDoesNotApplyStructTags(t *testing.T) {
	policy := PolicyFunc(func(Field) (Decision, error) { return Decision{}, nil })
	m, err := New(policy, WithStructTag("redact"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.MaskJSON([]byte(`{"email":"alice@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"email":"alice@example.com"}` {
		t.Fatalf("struct tag configuration affected JSON: %s", got)
	}
}

func TestJSONWalkerBudgetBoundariesAndOrder(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		opts     []Option
		want     string
		wantCode ErrorCode
		wantPath string
		depth    int
	}{
		{name: "depth root boundary", input: `1`, opts: []Option{WithMaxDepth(0)}, want: `1`},
		{name: "depth child boundary", input: `{"a":1}`, opts: []Option{WithMaxDepth(1)}, want: `{"a":1}`},
		{
			name: "depth over limit checked before nodes", input: `{"a":1}`,
			opts: []Option{WithMaxDepth(0), WithMaxNodes(1)}, want: `"[REDACTED]"`,
			wantCode: CodeDepthLimit, wantPath: "$[a]", depth: 1,
		},
		{name: "node exact boundary", input: `{"a":1}`, opts: []Option{WithMaxNodes(2)}, want: `{"a":1}`},
		{
			name: "node over limit", input: `{"a":1}`, opts: []Option{WithMaxDepth(1), WithMaxNodes(1)},
			want: `"[REDACTED]"`, wantCode: CodeNodeLimit, wantPath: "$[a]", depth: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestMasker(t, test.opts...)
			got, err := m.MaskJSON([]byte(test.input))
			if string(got) != test.want {
				t.Fatalf("unexpected JSON: got %s want %s", got, test.want)
			}
			if test.wantCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertSingleJSONWalkError(t, err, test.wantCode, test.wantPath, test.depth)
		})
	}
}

func TestJSONWalkerInputContractAndDuplicateKeys(t *testing.T) {
	valid := []byte(`{"safe":1}`)
	exact := newTestMasker(t, WithMaxInputBytes(int64(len(valid))))
	got, err := exact.MaskJSON(valid)
	if err != nil || string(got) != string(valid) {
		t.Fatalf("exact byte limit failed: result=%s err=%v", got, err)
	}

	got, err = newTestMasker(t).MaskJSON([]byte("{\"safe\":1}\n\t"))
	if err != nil || string(got) != string(valid) {
		t.Fatalf("trailing whitespace failed: result=%s err=%v", got, err)
	}

	failures := []struct {
		name  string
		m     *Masker
		input []byte
		want  error
	}{
		{name: "malformed", m: newTestMasker(t), input: []byte(`{"safe":`), want: ErrInvalidJSON},
		{name: "empty", m: newTestMasker(t), input: nil, want: ErrInvalidJSON},
		{name: "trailing data", m: newTestMasker(t), input: []byte(`{} {}`), want: ErrInvalidJSON},
		{name: "invalid primitive", m: newTestMasker(t), input: []byte(`{"safe":nope}`), want: ErrInvalidJSON},
		{name: "invalid UTF-8", m: newTestMasker(t), input: []byte{'"', 0xff, '"'}, want: ErrInvalidUTF8},
		{name: "input limit", m: exact, input: append(append([]byte(nil), valid...), ' '), want: ErrInputLimit},
	}
	for _, test := range failures {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.m.MaskJSON(test.input)
			if string(result) != `"[REDACTED]"` || err == nil || !errors.Is(err, test.want) {
				t.Fatalf("unexpected failure: result=%s err=%v", result, err)
			}
		})
	}

	got, err = newTestMasker(t).MaskJSON([]byte(`{"value":"first","value":"second"}`))
	if err != nil || string(got) != `{"value":"second"}` {
		t.Fatalf("duplicate key semantics changed: result=%s err=%v", got, err)
	}

	got, err = newTestMasker(t).MaskJSON([]byte(`{"\u0070assword":"first","password":"second"}`))
	if err != nil || string(got) != `{"password":"[REDACTED]"}` {
		t.Fatalf("escaped key semantics changed: result=%s err=%v", got, err)
	}
}

func TestJSONStreamingRejectsInvalidPrimitiveWithResourceLimit(t *testing.T) {
	got, err := newTestMasker(t, WithMaxNodes(1)).MaskJSON([]byte(`[0,nope]`))
	if string(got) != `"[REDACTED]"` || !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("invalid JSON was not preferred over resource limit: result=%s err=%v", got, err)
	}
}

func TestJSONWalkerPolicyAndRuleFailures(t *testing.T) {
	ruleError, err := NewRule("error", func(RuleInput) (string, error) {
		return "", errors.New("unsafe rule detail")
	})
	if err != nil {
		t.Fatal(err)
	}
	rulePanic, err := NewRule("panic", func(RuleInput) (string, error) {
		panic("unsafe rule panic")
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		policy Policy
		want   error
	}{
		{
			name: "policy error",
			policy: PolicyFunc(func(Field) (Decision, error) {
				return Decision{}, errors.New("unsafe policy detail")
			}),
			want: ErrPolicyFailure,
		},
		{
			name: "policy panic",
			policy: PolicyFunc(func(Field) (Decision, error) {
				panic("unsafe policy panic")
			}),
			want: ErrPanic,
		},
		{
			name: "rule error",
			policy: PolicyFunc(func(Field) (Decision, error) {
				return Decision{Rule: ruleError}, nil
			}),
			want: ErrRuleFailure,
		},
		{
			name: "rule panic",
			policy: PolicyFunc(func(Field) (Decision, error) {
				return Decision{Rule: rulePanic}, nil
			}),
			want: ErrPanic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m, err := New(test.policy, WithRedaction("MASKED"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := m.MaskJSON([]byte(`"secret"`))
			if string(got) != `"MASKED"` || err == nil || !errors.Is(err, test.want) {
				t.Fatalf("unexpected failure: result=%s err=%v", got, err)
			}
			if strings.Contains(err.Error(), "unsafe") {
				t.Fatalf("error leaked callback detail: %v", err)
			}
		})
	}
}

func TestJSONWalkerAggregatesSiblingFailures(t *testing.T) {
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Kind == KindNumber {
			return Decision{}, errors.New("unsafe detail")
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.MaskJSON([]byte(`[1,2]`))
	if string(got) != `"[REDACTED]"` {
		t.Fatalf("unexpected fallback: %s", got)
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != 2 {
		t.Fatalf("unexpected aggregate: %#v", err)
	}
	for index, item := range aggregate.Items {
		wantPath := pathForIndex("$", index)
		if item.Code != CodePolicyFailure || item.Operation != "mask" || item.Path != wantPath || item.Field != "" || item.Depth != 0 {
			t.Fatalf("unexpected aggregate item %d: %#v", index, item)
		}
	}
}

func TestJSONWalkerBoundsSiblingFailures(t *testing.T) {
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

	var input strings.Builder
	input.WriteByte('{')
	for i := 0; i < width; i++ {
		if i > 0 {
			input.WriteByte(',')
		}
		input.WriteString(`"field`)
		input.WriteString(strconv.Itoa(i))
		input.WriteString(`":1`)
	}
	input.WriteByte('}')

	got, err := m.MaskJSON([]byte(input.String()))
	if string(got) != `"[REDACTED]"` || !errors.Is(err, ErrPolicyFailure) {
		t.Fatalf("unexpected fallback: result=%s err=%v", got, err)
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
	for _, item := range aggregate.Items {
		if item.Code != CodePolicyFailure || item.Operation != "mask" || !strings.HasPrefix(item.Path, "$[field") {
			t.Fatalf("unexpected aggregate item: %#v", item)
		}
	}
}

func TestJSONWalkerResourceLimitsStopTraversal(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		opts      []Option
		wantCalls []string
		wantCode  ErrorCode
		wantPath  string
		wantDepth int
	}{
		{
			name:      "depth",
			input:     `[[0],1]`,
			opts:      []Option{WithMaxDepth(0)},
			wantCalls: []string{"$"},
			wantCode:  CodeDepthLimit,
			wantPath:  "$[0]",
			wantDepth: 1,
		},
		{
			name:      "nodes",
			input:     `[0,1,2]`,
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
			got, err := m.MaskJSON([]byte(test.input))
			if string(got) != `"[REDACTED]"` {
				t.Fatalf("unexpected fallback: %s", got)
			}
			assertSingleJSONWalkError(t, err, test.wantCode, test.wantPath, test.wantDepth)
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("policy reached sibling after limit: got %#v want %#v", calls, test.wantCalls)
			}
		})
	}
}

func TestJSONWalkerWideAndDeepLimitsRemainSingleFailures(t *testing.T) {
	wide := "[" + strings.TrimSuffix(strings.Repeat("0,", 256), ",") + "]"
	got, err := newTestMasker(t, WithMaxNodes(8)).MaskJSON([]byte(wide))
	if string(got) != `"[REDACTED]"` {
		t.Fatalf("unexpected wide fallback: %s", got)
	}
	assertSingleJSONWalkError(t, err, CodeNodeLimit, "$[7]", 1)

	const nesting = 40
	deep := strings.Repeat("[", nesting) + "0" + strings.Repeat("]", nesting)
	got, err = newTestMasker(t, WithMaxDepth(8)).MaskJSON([]byte(deep))
	if string(got) != `"[REDACTED]"` {
		t.Fatalf("unexpected deep fallback: %s", got)
	}
	assertSingleJSONWalkError(t, err, CodeDepthLimit, "$"+strings.Repeat("[0]", 9), 9)
}

func TestJSONWalkerResourceLimitRemainsVisibleAtErrorCap(t *testing.T) {
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
	input := "[" + strings.TrimSuffix(strings.Repeat("0,", maxMaskErrorsPerOperation+2), ",") + "]"

	got, err := m.MaskJSON([]byte(input))
	if string(got) != `"[REDACTED]"` || !errors.Is(err, ErrNodeLimit) {
		t.Fatalf("resource sentinel was lost at cap: result=%s err=%v", got, err)
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

func TestJSONWalkerReusesDecoderContainers(t *testing.T) {
	decoded, err := decodeJSONDocument([]byte(`{"items":[true,1],"token":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	root := decoded.(map[string]any)
	items := root["items"].([]any)
	rootPointer := reflect.ValueOf(root).UnsafePointer()
	itemsPointer := reflect.ValueOf(items).Pointer()
	itemsCapacity := cap(items)

	m := newTestMasker(t)
	masked, err := m.maskJSONRoot(decoded, Field{Path: "$", Source: SourceJSON, Kind: KindObject})
	if err != nil {
		t.Fatal(err)
	}
	maskedRoot := masked.(map[string]any)
	maskedItems := maskedRoot["items"].([]any)
	if reflect.ValueOf(maskedRoot).UnsafePointer() != rootPointer {
		t.Fatal("JSON object was copied")
	}
	if reflect.ValueOf(maskedItems).Pointer() != itemsPointer || cap(maskedItems) != itemsCapacity || len(maskedItems) != len(items) {
		t.Fatal("JSON array allocation changed")
	}
	if maskedItems[0] != "true" || maskedRoot["token"] != DefaultRedactionMarker {
		t.Fatalf("unexpected in-place result: %#v", masked)
	}
}

func TestJSONDecoderOwnedTreeHasNoAliases(t *testing.T) {
	decoded, err := decodeJSONDocument([]byte(`{"left":[{"value":1}],"right":[{"value":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	root := decoded.(map[string]any)
	left := root["left"].([]any)
	right := root["right"].([]any)
	if reflect.ValueOf(left).Pointer() == reflect.ValueOf(right).Pointer() {
		t.Fatal("decoder aliased sibling arrays")
	}
	leftObject := left[0].(map[string]any)
	rightObject := right[0].(map[string]any)
	if reflect.ValueOf(leftObject).UnsafePointer() == reflect.ValueOf(rightObject).UnsafePointer() {
		t.Fatal("decoder aliased sibling objects")
	}
	leftObject["value"] = json.Number("2")
	if rightObject["value"] != json.Number("1") {
		t.Fatal("decoder-owned sibling mutation crossed branches")
	}
}

func TestJSONWalkerMatchesReflectionReference(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		factory func(*testing.T) *Masker
	}{
		{
			name:    "nested scalars",
			input:   `{"safe":true,"items":[12345678901234567890,{"email":"a@b.c"}]}`,
			factory: func(t *testing.T) *Masker { return newTestMasker(t) },
		},
		{
			name:    "preserve safe",
			input:   `[true,false,900719925474099312345]`,
			factory: func(t *testing.T) *Masker { return newTestMasker(t, WithPreserveSafeTypes()) },
		},
		{
			name:    "depth failure",
			input:   `{"a":{"b":1}}`,
			factory: func(t *testing.T) *Masker { return newTestMasker(t, WithMaxDepth(1)) },
		},
		{
			name:    "node failure",
			input:   `[1,2]`,
			factory: func(t *testing.T) *Masker { return newTestMasker(t, WithMaxNodes(2)) },
		},
		{
			name:  "path-aware policy",
			input: `{"outer":{"secret":"value"}}`,
			factory: func(t *testing.T) *Masker {
				policy := PolicyFunc(func(field Field) (Decision, error) {
					if field.Path == "$[outer][secret]" {
						return Decision{Rule: FullRule()}, nil
					}
					return Decision{}, nil
				})
				m, err := New(policy)
				if err != nil {
					t.Fatal(err)
				}
				return m
			},
		},
		{
			name:  "omit",
			input: `{"keep":1,"omit":{"secret":"value"}}`,
			factory: func(t *testing.T) *Masker {
				policy := PolicyFunc(func(field Field) (Decision, error) {
					return Decision{Omit: field.Key == "omit"}, nil
				})
				m, err := New(policy)
				if err != nil {
					t.Fatal(err)
				}
				return m
			},
		},
		{
			name:    "duplicate last wins",
			input:   `{"value":"first","value":"second"}`,
			factory: func(t *testing.T) *Masker { return newTestMasker(t) },
		},
		{
			name:  "policy failure",
			input: `{"bad":"value"}`,
			factory: func(t *testing.T) *Masker {
				policy := PolicyFunc(func(field Field) (Decision, error) {
					if field.Key == "bad" {
						return Decision{}, errors.New("unsafe detail")
					}
					return Decision{}, nil
				})
				m, err := New(policy)
				if err != nil {
					t.Fatal(err)
				}
				return m
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			direct, directErr := test.factory(t).MaskJSON([]byte(test.input))
			reference, referenceErr := maskJSONWithReflection(test.factory(t), []byte(test.input))
			if !bytes.Equal(direct, reference) {
				t.Fatalf("output differs:\ndirect    %s\nreflection %s", direct, reference)
			}
			if !reflect.DeepEqual(maskErrorDetails(directErr), maskErrorDetails(referenceErr)) {
				t.Fatalf("errors differ:\ndirect    %#v\nreflection %#v", directErr, referenceErr)
			}
		})
	}
}

func FuzzJSONWalkerMatchesReflection(f *testing.F) {
	seeds := []string{
		`{"outer":{"secret":"value"},"keep":1}`,
		`{"omit":{"secret":"value"},"keep":true}`,
		`{"value":"first","value":"second"}`,
		`{"fail":"value","safe":1}`,
		`[true,12345678901234567890,{"secret":"value"}]`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 || !json.Valid(data) || !utf8.Valid(data) {
			t.Skip()
		}
		policy := PolicyFunc(func(field Field) (Decision, error) {
			switch {
			case strings.HasSuffix(field.Path, "[secret]"):
				return Decision{Rule: FullRule()}, nil
			case strings.HasSuffix(field.Path, "[omit]"):
				return Decision{Omit: true}, nil
			case strings.HasSuffix(field.Path, "[fail]"):
				return Decision{}, errors.New("unsafe detail")
			default:
				return Decision{}, nil
			}
		})
		newMasker := func() *Masker {
			m, err := New(policy, WithPreserveSafeTypes())
			if err != nil {
				t.Fatal(err)
			}
			return m
		}

		direct, directErr := newMasker().MaskJSON(data)
		reference, referenceErr := maskJSONWithReflection(newMasker(), data)
		if !bytes.Equal(direct, reference) {
			t.Fatalf("output differs:\ndirect    %s\nreflection %s", direct, reference)
		}
		directDetails := sortedMaskErrorDetails(directErr)
		referenceDetails := sortedMaskErrorDetails(referenceErr)
		if !reflect.DeepEqual(directDetails, referenceDetails) {
			t.Fatalf("errors differ:\ndirect    %#v\nreflection %#v", directDetails, referenceDetails)
		}
	})
}

func assertSingleJSONWalkError(t *testing.T, err error, code ErrorCode, path string, depth int) {
	t.Helper()
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
		t.Fatalf("expected one walk error, got %#v", err)
	}
	item := aggregate.Items[0]
	if item.Code != code || item.Operation != "mask" || item.Path != path || item.Depth != depth {
		t.Fatalf("unexpected walk error: %#v", item)
	}
}

func decodeJSONDocument(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, err
	}
	return decoded, nil
}

func maskJSONWithReflection(m *Masker, data []byte) ([]byte, error) {
	decoded, err := decodeJSONDocument(data)
	if err != nil {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	masked, err := m.maskRoot(decoded, SourceJSON, Field{Path: "$", Source: SourceJSON, Kind: valueKindOf(decoded)})
	if err != nil {
		return m.safeJSONFallback(), err
	}
	encoded, err := json.Marshal(masked)
	if err != nil {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	return encoded, nil
}

func maskErrorDetails(err error) []MaskError {
	if err == nil {
		return nil
	}
	var aggregate *MaskErrors
	if !errors.As(err, &aggregate) {
		return []MaskError{{Code: "unexpected"}}
	}
	result := make([]MaskError, 0, len(aggregate.Items))
	for _, item := range aggregate.Items {
		if item != nil {
			result = append(result, *item)
		}
	}
	return result
}

func sortedMaskErrorDetails(err error) []MaskError {
	result := maskErrorDetails(err)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Code < result[j].Code
	})
	return result
}
