package masker

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

var jsonEncoderBenchmarkSink []byte

const jsonEncoderSmallDoc = `{"user":{"email":"alice@example.com","phone":"15551234567"},"token":"t","count":3}`

func TestJSONTreeEncoderMatchesMarshal(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "null", value: nil},
		{name: "bool", value: true},
		{name: "string", value: "plain"},
		{
			name: "nested values",
			value: map[string]any{
				"z": []any{nil, true, false, "text", json.Number("-12.3400e+05")},
				"a": map[string]any{"second": "value", "first": json.Number("900719925474099312345")},
			},
		},
		{
			name: "escaped strings",
			value: map[string]any{
				"<key&>":  "<script>&\"quoted\"\\slash\b\f\n\r\t\x00",
				"unicode": "Привет, 世界 😀 \u2028 \u2029",
			},
		},
		{
			name: "numbers",
			value: []any{
				json.Number("0"),
				json.Number("-0"),
				json.Number("1.0"),
				json.Number("1e9"),
				json.Number("1E+09"),
				json.Number("123456789012345678901234567890"),
			},
		},
		{name: "typed nil containers", value: []any{map[string]any(nil), []any(nil)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := encodeJSONTree(test.value, len(want))
			if !ok {
				t.Fatal("custom encoder rejected safe tree")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoded JSON differs:\ngot  %s\nwant %s", got, want)
			}
		})
	}
}

func TestJSONTreeEncoderDuplicateKeyLastWins(t *testing.T) {
	decoded, err := decodeJSONDocument([]byte(`{"value":"first","value":"second","nested":{"key":1,"key":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := encodeJSONTree(decoded, len(want))
	if !ok {
		t.Fatal("custom encoder rejected decoded tree")
	}
	if !bytes.Equal(got, want) || string(got) != `{"nested":{"key":2},"value":"second"}` {
		t.Fatalf("duplicate-key output differs: got %s want %s", got, want)
	}
}

func TestJSONTreeEncoderRejectsImpossibleValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "unsupported type", value: 1},
		{name: "invalid leading zero", value: json.Number("01")},
		{name: "invalid fraction", value: json.Number("1.")},
		{name: "invalid exponent", value: json.Number("1e+")},
		{name: "non-finite number", value: json.Number("NaN")},
		{name: "nested unsupported type", value: map[string]any{"safe": []any{true, struct{}{}}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, ok := encodeJSONTree(test.value, 0); ok || got != nil {
				t.Fatalf("impossible value was encoded: %s", got)
			}
		})
	}
}

func BenchmarkJSONTreeEncoderSmall(b *testing.B) {
	benchmarkJSONTreeEncoder(b, []byte(jsonEncoderSmallDoc))
}

func BenchmarkJSONTreeEncoderLarge(b *testing.B) {
	benchmarkJSONTreeEncoder(b, jsonEncoderFixture(10_000))
}

func benchmarkJSONTreeEncoder(b *testing.B, src []byte) {
	b.Helper()
	decoded, err := decodeJSONDocument(src)
	if err != nil {
		b.Fatal(err)
	}
	m, err := New(DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	masked, err := m.maskJSONRoot(decoded, Field{Path: "$", Source: SourceJSON, Kind: jsonValueKind(decoded)})
	if err != nil {
		b.Fatal(err)
	}

	b.Run("json_marshal", func(b *testing.B) {
		b.SetBytes(int64(len(src)))
		b.ReportAllocs()
		for range b.N {
			jsonEncoderBenchmarkSink, err = json.Marshal(masked)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("custom", func(b *testing.B) {
		b.SetBytes(int64(len(src)))
		b.ReportAllocs()
		for range b.N {
			var ok bool
			jsonEncoderBenchmarkSink, ok = encodeJSONTree(masked, len(src))
			if !ok {
				b.Fatal("custom encoder rejected safe tree")
			}
		}
	})
}

func jsonEncoderFixture(records int) []byte {
	var builder strings.Builder
	builder.Grow(records * 80)
	builder.WriteString(`{"users":[`)
	for index := range records {
		if index > 0 {
			builder.WriteByte(',')
		}
		id := strconv.Itoa(index)
		builder.WriteString(`{"id":` + id + `,` +
			`"email":"user` + id + `@example.com",` +
			`"token":"eyJhbGciOiJIUzI1NiJ9",` +
			`"role":"admin"}`)
	}
	builder.WriteString(`],"total":` + strconv.Itoa(records) + `}`)
	return []byte(builder.String())
}

// TestJSONTreeEncoderInvalidUTF8 pins the encoder's own escaping for invalid
// UTF-8. encoding/json switched to a literal U+FFFD in Go 1.27, so this form is
// asserted directly instead of compared with json.Marshal.
func TestJSONTreeEncoderInvalidUTF8(t *testing.T) {
	got, ok := encodeJSONTree(map[string]any{"invalid": string([]byte{'a', 0xff, 'b'})}, 0)
	if !ok {
		t.Fatal("custom encoder rejected safe tree")
	}
	const want = `{"invalid":"a\ufffdb"}`
	if string(got) != want {
		t.Fatalf("invalid UTF-8 encoding differs:\ngot  %s\nwant %s", got, want)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded["invalid"] != "a\ufffdb" {
		t.Fatalf("decoded value differs: %q", decoded["invalid"])
	}
}
