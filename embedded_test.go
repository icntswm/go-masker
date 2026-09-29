package masker

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestEmbeddedDocumentsSmoke is the smallest end-to-end proof of the three
// embedded document families: a URL, a JSON body and a form carried in an
// ordinary string value.
func TestEmbeddedDocumentsSmoke(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "url userinfo",
			key:   "url",
			value: "https://u:dummy@host/cb",
			want:  "https://%5BREDACTED%5D@host/cb",
		},
		{
			name:  "json body",
			key:   "body",
			value: `{"password":"dummy-secret"}`,
			want:  `{"password":"[REDACTED]"}`,
		},
		{
			name:  "form",
			key:   "form",
			value: "user=a&password=dummy",
			want:  "password=%5BREDACTED%5D&user=a",
		},
		{
			name:  "plain text",
			key:   "note",
			value: "hello world",
			want:  "hello world",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue(test.key, test.value)
			if err != nil {
				t.Fatal(err)
			}
			masked, ok := result.(string)
			if !ok {
				t.Fatalf("result is not a string: %#v", result)
			}
			if masked != test.want {
				t.Fatalf("unexpected result: got %q want %q", masked, test.want)
			}
		})
	}
}

func TestEmbeddedURLStrings(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "userinfo and sensitive query",
			value: "https://u:dummy@host/cb?token=dummy-token",
			want:  "https://%5BREDACTED%5D@host/cb?token=%5BREDACTED%5D",
		},
		{
			name:  "sensitive query parameter",
			value: "https://host/cb?token=dummy-token",
			want:  "https://host/cb?token=%5BREDACTED%5D",
		},
		{
			// The fragment is the marker on its own: an OAuth implicit-flow
			// token lives there and no policy key decides it.
			name:  "fragment without anything else masked",
			value: "https://host/cb#access_token=dummy",
			want:  "https://host/cb#%5BREDACTED%5D",
		},
		{
			// Re-encoding would sort the pairs; an unchanged string proves
			// the bytes were returned as they lay.
			name:  "harmless query keeps its original bytes",
			value: "https://host/cb?user=alice&admin=1",
			want:  "https://host/cb?user=alice&admin=1",
		},
		{
			name:  "nested URL in redirect_uri",
			value: "https://host/cb?redirect_uri=https://host2/cb?token=dummy-token",
			want:  "https://host/cb?redirect_uri=https%3A%2F%2Fhost2%2Fcb%3Ftoken%3D%255BREDACTED%255D",
		},
		{
			name:  "nested URL in escaped redirect_uri",
			value: "https://host/cb?redirect_uri=https%3A%2F%2Fu%3Adummy%40h%2F",
			want:  "https://host/cb?redirect_uri=https%3A%2F%2F%255BREDACTED%255D%40h%2F",
		},
		{
			name:  "relative URL is not a URL",
			value: "/cb?token=dummy-token",
			want:  "/cb?token=dummy-token",
		},
		{
			name:  "mailto URL is not a URL",
			value: "mailto:alice@example.com?token=dummy",
			want:  "mailto:alice@example.com?token=dummy",
		},
		{
			// Prose is not parsed as a URL; the text detectors still find the
			// token=... pair in it.
			name:  "URL with a space is prose",
			value: "https://host/cb?token=dummy token",
			want:  "https://host/cb?token=[REDACTED] token",
		},
		{
			// A URL-shaped string whose query does not parse fails closed:
			// the string becomes the marker and the call itself still
			// succeeds, because the policy never asked about this string.
			name:  "unparseable query becomes the marker",
			value: "https://h/?a=1;b=2",
			want:  "[REDACTED]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue("url", test.value)
			if err != nil {
				t.Fatal(err)
			}
			masked, ok := result.(string)
			if !ok {
				t.Fatalf("result is not a string: %#v", result)
			}
			if masked != test.want {
				t.Fatalf("unexpected result: got %q want %q", masked, test.want)
			}
		})
	}
}

func TestEmbeddedJSONStrings(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "sensitive key in object",
			value: `{"password":"dummy-secret","user":"alice"}`,
			want:  `{"password":"[REDACTED]","user":"alice"}`,
		},
		{
			name:  "sensitive key in array",
			value: `[{"token":"dummy-secret"}]`,
			want:  `[{"token":"[REDACTED]"}]`,
		},
		{
			// Re-serializing would normalize the whitespace and sort the
			// keys; an unchanged string proves nothing was masked.
			name:  "nothing sensitive keeps the original bytes",
			value: `{ "zebra" : "z" , "alpha":"a" }`,
			want:  `{ "zebra" : "z" , "alpha":"a" }`,
		},
		{
			name:  "invalid JSON is not a document",
			value: `{alice 42}`,
			want:  `{alice 42}`,
		},
		{
			// A JSON document inside a JSON document inside a string: the
			// innermost value is two embedded levels away and is masked
			// through the recursive inspection.
			name:  "JSON string inside JSON string",
			value: `{"inner":"{\"password\":\"dummy-secret\"}"}`,
			want:  `{"inner":"{\"password\":\"[REDACTED]\"}"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue("body", test.value)
			if err != nil {
				t.Fatal(err)
			}
			masked, ok := result.(string)
			if !ok {
				t.Fatalf("result is not a string: %#v", result)
			}
			if masked != test.want {
				t.Fatalf("unexpected result: got %q want %q", masked, test.want)
			}
		})
	}
}

func TestEmbeddedFormStrings(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "sensitive member",
			value: "user=a&password=dummy",
			want:  "password=%5BREDACTED%5D&user=a",
		},
		{
			name:  "single member",
			value: "password=dummy",
			want:  "password=%5BREDACTED%5D",
		},
		{
			name:  "harmless members in order",
			value: "a=1&b=2",
			want:  "a=1&b=2",
		},
		{
			// Re-encoding would sort the members; an unchanged string proves
			// the bytes were returned as they lay.
			name:  "harmless members keep their original order",
			value: "b=2&a=1",
			want:  "b=2&a=1",
		},
		{
			// Base64 padding looks like an empty member value and must not
			// be rewritten.
			name:  "base64 is not a form",
			value: "dGVzdA==",
			want:  "dGVzdA==",
		},
		{
			name:  "form with a space is prose",
			value: "a=b c",
			want:  "a=b c",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue("form", test.value)
			if err != nil {
				t.Fatal(err)
			}
			masked, ok := result.(string)
			if !ok {
				t.Fatalf("result is not a string: %#v", result)
			}
			if masked != test.want {
				t.Fatalf("unexpected result: got %q want %q", masked, test.want)
			}
		})
	}
}

func TestEmbeddedFormOmitDropsPair(t *testing.T) {
	policy := PolicyFunc(func(field Field) (Decision, error) {
		return Decision{Omit: field.Key == "secret"}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskValue("form", "user=a&secret=dummy&admin=1")
	if err != nil {
		t.Fatal(err)
	}
	if masked, ok := result.(string); !ok || masked != "admin=1&user=a" {
		t.Fatalf("omitted pair was not dropped: %#v", result)
	}
}

func TestEmbeddedDocumentsUnderMaskAny(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		key  string
		give string
		want string
	}{
		{"url", "https://u:dummy@host/cb?token=dummy-token", "https://%5BREDACTED%5D@host/cb?token=%5BREDACTED%5D"},
		{"body", `{"password":"dummy-secret"}`, `{"password":"[REDACTED]"}`},
		{"form", "user=a&password=dummy", "password=%5BREDACTED%5D&user=a"},
		{"note", "hello world", "hello world"},
	}
	values := map[string]any{}
	for _, test := range tests {
		values[test.key] = test.give
	}
	result, err := m.MaskAny(values)
	if err != nil {
		t.Fatal(err)
	}
	masked := result.(map[string]any)
	for _, test := range tests {
		if masked[test.key] != test.want {
			t.Fatalf("%s: got %#v want %q", test.key, masked[test.key], test.want)
		}
	}

	// The flat struct scalar fast path inspects like the deep walk does.
	type message struct {
		Note string
	}
	result, err = m.MaskAny(message{Note: `{"password":"dummy-secret"}`})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]any)["Note"]; got != `{"password":"[REDACTED]"}` {
		t.Fatalf("struct field: %#v", got)
	}

	// A masked string stays a string under WithPreserveSafeTypes.
	preserved := newTestMasker(t, WithPreserveSafeTypes())
	result, err = preserved.MaskAny(map[string]any{"url": "https://u:dummy@host/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := result.(map[string]any)["url"].(string); !ok || got != "https://%5BREDACTED%5D@host/cb" {
		t.Fatalf("preserved result: %#v", result)
	}
}

func TestEmbeddedDocumentsUnderMaskJSON(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "URL string",
			input: `{"url":"https://u:dummy@host/cb?token=dummy-token"}`,
			want:  `{"url":"https://%5BREDACTED%5D@host/cb?token=%5BREDACTED%5D"}`,
		},
		{
			name:  "JSON string inside JSON string inside JSON",
			input: `{"body":"{\"inner\":\"{\\\"password\\\":\\\"dummy-secret\\\"}\"}"}`,
			want:  `{"body":"{\"inner\":\"{\\\"password\\\":\\\"[REDACTED]\\\"}\"}"}`,
		},
		{
			name:  "form string",
			input: `{"form":"user=a&password=dummy"}`,
			want:  `{"form":"password=%5BREDACTED%5D\u0026user=a"}`,
		},
		{
			// The unparseable-query marker replaces only its own string;
			// the document around it is still masked and returned.
			name:  "document survives an unparseable query",
			input: `{"token":"dummy-secret","url":"https://h/?a=1;b=2"}`,
			want:  `{"token":"[REDACTED]","url":"[REDACTED]"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskJSON([]byte(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if string(result) != test.want {
				t.Fatalf("unexpected result: got %s want %s", result, test.want)
			}
		})
	}
}

// TestEmbeddedOuterDecisionWins checks that a rule or an omission on the field
// holding the string is terminal: the text inside is never offered to the
// policy.
func TestEmbeddedOuterDecisionWins(t *testing.T) {
	t.Run("rule on the outer key", func(t *testing.T) {
		var inspected []string
		recorder := PolicyFunc(func(field Field) (Decision, error) {
			inspected = append(inspected, field.Key)
			return Decision{}, nil
		})
		m, err := New(Chain(recorder, DefaultPolicy()))
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.MaskJSON([]byte(`{"password":"{\"x\":\"dummy-secret\"}"}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(result) != `{"password":"[REDACTED]"}` {
			t.Fatalf("unexpected result: %s", result)
		}
		for _, key := range inspected {
			if key == "x" {
				t.Fatal("the policy was asked about a key inside the ruled string")
			}
		}
	})

	t.Run("omit on the outer key", func(t *testing.T) {
		var inspected []string
		policy := PolicyFunc(func(field Field) (Decision, error) {
			inspected = append(inspected, field.Key)
			return Decision{Omit: field.Key == "body"}, nil
		})
		m, err := New(policy)
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.MaskJSON([]byte(`{"body":"{\"x\":\"dummy-secret\"}","user":"alice"}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(result) != `{"user":"alice"}` {
			t.Fatalf("unexpected result: %s", result)
		}
		for _, key := range inspected {
			if key == "x" {
				t.Fatal("the policy was asked about a key inside the omitted string")
			}
		}
	})

	t.Run("rule output is never inspected", func(t *testing.T) {
		var inspected []string
		document, err := NewRule("document", func(input RuleInput) (string, error) {
			return `{"password":"dummy-secret"}`, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		policy := PolicyFunc(func(field Field) (Decision, error) {
			inspected = append(inspected, field.Key)
			if field.Key == "note" {
				return Decision{Rule: document}, nil
			}
			return Decision{}, nil
		})
		m, err := New(policy)
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.MaskJSON([]byte(`{"note":"plain text"}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(result) != `{"note":"{\"password\":\"dummy-secret\"}"}` {
			t.Fatalf("unexpected result: %s", result)
		}
		for _, key := range inspected {
			if key == "password" {
				t.Fatal("the rule output was inspected")
			}
		}
	})
}

func TestEmbeddedDocumentFailures(t *testing.T) {
	t.Run("limit inside embedded JSON survives a full error list", func(t *testing.T) {
		policy := PolicyFunc(func(field Field) (Decision, error) {
			if strings.HasPrefix(field.Key, "bad") {
				return Decision{}, errors.New("dummy policy failure")
			}
			return Decision{}, nil
		})
		m, err := New(policy, WithMaxDepth(1))
		if err != nil {
			t.Fatal(err)
		}
		var document strings.Builder
		document.WriteString("{")
		for index := range maxMaskErrorsPerOperation {
			fmt.Fprintf(&document, `"bad%d":"x",`, index)
		}
		document.WriteString(`"body":"{\"x\":1}"}`)
		_, err = m.MaskJSON([]byte(document.String()))
		if !errors.Is(err, ErrDepthLimit) {
			t.Fatalf("the depth limit must not be dropped, got %v", err)
		}
	})
	t.Run("rule panic inside embedded JSON", func(t *testing.T) {
		policy := PolicyFunc(func(field Field) (Decision, error) {
			if field.Key == "password" {
				return Decision{Rule: RuleFunc(func(RuleInput) (string, error) {
					panic("dummy")
				})}, nil
			}
			return Decision{}, nil
		})
		m, err := New(policy)
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.MaskJSON([]byte(`{"body":"{\"password\":\"dummy-secret\"}"}`))
		if string(result) != `"[REDACTED]"` {
			t.Fatalf("expected the fallback, got %s", result)
		}
		if !errors.Is(err, ErrPanic) {
			t.Fatalf("expected a panic error, got %v", err)
		}
		// The failure is reported like the same failure on an ordinary
		// field: the member's own path names it.
		var aggregate *MaskErrors
		if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
			t.Fatalf("expected one failure, got %#v", err)
		}
		item := aggregate.Items[0]
		if item.Code != CodePanic || item.Operation != "mask" ||
			item.Path != "$[body][password]" || item.Field != "password" {
			t.Fatalf("unexpected failure: %#v", item)
		}
	})

	t.Run("node limit inside embedded JSON", func(t *testing.T) {
		m := newTestMasker(t, WithMaxNodes(2))
		result, err := m.MaskJSON([]byte(`{"body":"{\"password\":\"dummy\"}"}`))
		if string(result) != `"[REDACTED]"` {
			t.Fatalf("expected the fallback, got %s", result)
		}
		if !errors.Is(err, ErrNodeLimit) {
			t.Fatalf("expected a node limit error, got %v", err)
		}
		assertSingleJSONWalkError(t, err, CodeNodeLimit, "$[body]", 2)
	})

	t.Run("depth limit inside embedded JSON", func(t *testing.T) {
		m := newTestMasker(t, WithMaxDepth(1))
		result, err := m.MaskJSON([]byte(`{"body":"{\"password\":\"dummy\"}"}`))
		if string(result) != `"[REDACTED]"` {
			t.Fatalf("expected the fallback, got %s", result)
		}
		if !errors.Is(err, ErrDepthLimit) {
			t.Fatalf("expected a depth limit error, got %v", err)
		}
		assertSingleJSONWalkError(t, err, CodeDepthLimit, "$[body]", 2)
	})

	t.Run("candidate over the input limit", func(t *testing.T) {
		m := newTestMasker(t, WithMaxInputBytes(64))
		value := "https://example.com/cb?password=" + strings.Repeat("x", 64)
		result, err := m.MaskValue("note", value)
		if result != DefaultRedactionMarker {
			t.Fatalf("expected the marker, got %#v", result)
		}
		details := maskErrorDetails(err)
		if len(details) != 1 || details[0].Code != CodeInputLimit || details[0].Path != "$[note]" {
			t.Fatalf("unexpected error details: %#v", err)
		}
	})

	t.Run("policy failure on a URL member", func(t *testing.T) {
		policy := PolicyFunc(func(field Field) (Decision, error) {
			if field.Key == "token" {
				return Decision{}, errors.New("dummy policy break")
			}
			return Decision{}, nil
		})
		m, err := New(policy)
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.MaskJSON([]byte(`{"url":"https://host/cb?token=x"}`))
		if string(result) != `"[REDACTED]"` {
			t.Fatalf("expected the fallback, got %s", result)
		}
		if !errors.Is(err, ErrPolicyFailure) {
			t.Fatalf("expected a policy failure, got %v", err)
		}
		var aggregate *MaskErrors
		if !errors.As(err, &aggregate) || len(aggregate.Items) != 1 {
			t.Fatalf("expected one failure, got %#v", err)
		}
		item := aggregate.Items[0]
		if item.Code != CodePolicyFailure || item.Operation != "mask" ||
			item.Path != "$[url][token]" || item.Field != "token" || item.Depth != 0 {
			t.Fatalf("unexpected failure: %#v", item)
		}
	})
}

func TestWithoutValueInspection(t *testing.T) {
	m := newTestMasker(t, WithoutValueInspection())
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"url userinfo and query", "url", "https://u:dummy@host/cb?token=dummy-token"},
		{"unparseable query", "url", "https://h/?a=1;b=2"},
		{"json body", "body", `{"password":"dummy-secret"}`},
		{"nested json body", "body", `{"inner":"{\"password\":\"dummy-secret\"}"}`},
		{"form", "form", "user=a&password=dummy"},
		{"base64", "form", "dGVzdA=="},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue(test.key, test.value)
			if err != nil {
				t.Fatal(err)
			}
			if result != test.value {
				t.Fatalf("value leaked differently than before: got %#v want %q", result, test.value)
			}
		})
	}

	source := `{"body":"{\"password\":\"dummy-secret\"}","url":"https://u:dummy@host/cb?token=dummy-token"}`
	result, err := m.MaskJSON([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != source {
		t.Fatalf("unexpected result: got %s want %s", result, source)
	}
}

func TestEmbeddedJSONStreamMatchesDOM(t *testing.T) {
	panicking := func(t *testing.T) *Masker {
		policy := PolicyFunc(func(field Field) (Decision, error) {
			if field.Key == "password" {
				return Decision{Rule: RuleFunc(func(RuleInput) (string, error) {
					panic("dummy")
				})}, nil
			}
			return Decision{}, nil
		})
		m, err := New(policy)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	standard := func(t *testing.T) *Masker { return newTestMasker(t) }
	tests := []struct {
		name    string
		factory func(*testing.T) *Masker
		input   string
	}{
		{name: "url", factory: standard, input: `{"url":"https://u:dummy@host/cb?token=dummy-token"}`},
		{name: "url in array", factory: standard, input: `{"urls":["https://u:dummy@host/cb?token=dummy-token"]}`},
		{name: "fragment", factory: standard, input: `{"url":"https://host/cb#access_token=dummy"}`},
		{name: "json body", factory: standard, input: `{"body":"{\"inner\":\"{\\\"password\\\":\\\"dummy-secret\\\"}\"}"}`},
		{name: "form", factory: standard, input: `{"form":"user=a&password=dummy"}`},
		{name: "unparseable query", factory: standard, input: `{"url":"https://h/?a=1;b=2"}`},
		{name: "unchanged string", factory: standard, input: `{"url":"https://host/cb?user=alice&admin=1"}`},
		{name: "rule panic", factory: panicking, input: `{"body":"{\"password\":\"dummy-secret\"}"}`},
		{name: "node limit", factory: func(t *testing.T) *Masker { return newTestMasker(t, WithMaxNodes(2)) }, input: `{"body":"{\"password\":\"dummy\"}"}`},
		{name: "null password", factory: standard, input: `{"password":null,"note":null,"body":"{\"token\":null,\"note\":null}"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, wantErr := test.factory(t).maskJSONDOM([]byte(test.input))
			got, gotErr := test.factory(t).MaskJSON([]byte(test.input))
			if string(got) != string(want) {
				t.Fatalf("streaming output differs:\n got: %s\nwant: %s", got, want)
			}
			if !reflect.DeepEqual(maskErrorDetails(gotErr), maskErrorDetails(wantErr)) {
				t.Fatalf("errors differ:\n got: %#v\nwant: %#v", gotErr, wantErr)
			}
		})
	}
}
