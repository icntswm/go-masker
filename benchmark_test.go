package masker_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
)

var (
	benchmarkStringSink string
	benchmarkBytesSink  []byte
	benchmarkValueSink  any
)

func newBenchMasker(b *testing.B, opts ...masker.Option) *masker.Masker {
	b.Helper()
	m, err := masker.New(masker.DefaultPolicy(), opts...)
	if err != nil {
		b.Fatal(err)
	}
	return m
}

// --- built-in rules -------------------------------------------------------

func BenchmarkMaskStringFull(b *testing.B) {
	m := newBenchMasker(b)
	rule := masker.FullRule()
	value := "s3cret-value"
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkStringSink, err = m.MaskString(value, rule)
	}
	b.StopTimer()
	validateBenchmarkString(b, err)
}

func BenchmarkMaskStringEmail(b *testing.B) {
	m := newBenchMasker(b)
	rule := masker.EmailRule()
	value := "alice@example.com"
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkStringSink, err = m.MaskString(value, rule)
	}
	b.StopTimer()
	validateBenchmarkString(b, err)
}

func BenchmarkMaskStringCardFormatted(b *testing.B) {
	m := newBenchMasker(b)
	rule := masker.CardRule()
	value := "4111-1111-1111-1111"
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkStringSink, err = m.MaskString(value, rule)
	}
	b.StopTimer()
	validateBenchmarkString(b, err)
}

// --- policy lookup ---------------------------------------------------------

func benchmarkDecide(b *testing.B, key string, wantRule bool) {
	b.Helper()
	policy := masker.DefaultPolicy()
	field := masker.Field{Key: key, Source: masker.SourceMap, Kind: masker.KindObject}
	var (
		decision masker.Decision
		err      error
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision, err = policy.Decide(field)
		benchmarkValueSink = decision
	}
	b.StopTimer()
	if err != nil {
		b.Fatal(err)
	}
	if (decision.Rule != nil) != wantRule {
		b.Fatal("unexpected policy decision")
	}
}

func BenchmarkKeyPolicyHit(b *testing.B)  { benchmarkDecide(b, "password", true) }
func BenchmarkKeyPolicyMiss(b *testing.B) { benchmarkDecide(b, "ordinary_field_name", false) }
func BenchmarkKeyPolicyEmpty(b *testing.B) {
	benchmarkDecide(b, "", false)
}

func BenchmarkMaskValueScalarHit(b *testing.B) {
	m := newBenchMasker(b)
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskValue("access_token", "eyJhbGciOi")
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

func BenchmarkMaskValueScalarMiss(b *testing.B) {
	m := newBenchMasker(b)
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskValue("ordinary_field_name", "value")
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

// --- payloads --------------------------------------------------------------

const (
	benchUsers      = 100
	benchLargeUsers = 10_000
)

var (
	benchPayloadOnce sync.Once
	benchJSONMedium  []byte
	benchJSONLarge   []byte
	benchMapNested   map[string]any
)

func buildBenchPayloads() {
	benchPayloadOnce.Do(func() {
		var sb strings.Builder
		sb.WriteString(`{"users":[`)
		for i := range benchUsers {
			if i > 0 {
				sb.WriteByte(',')
			}
			id := strconv.Itoa(i)
			sb.WriteString(`{"id":` + id + `,` +
				`"email":"user` + id + `@example.com",` +
				`"phone":"15551234567",` +
				`"token":"eyJhbGciOiJIUzI1NiJ9",` +
				`"role":"admin",` +
				`"meta":{"active":true,"logins":42}}`)
		}
		sb.WriteString(`],"total":` + strconv.Itoa(benchUsers) + `}`)
		benchJSONMedium = []byte(sb.String())

		benchJSONLarge = scalingJSON(benchLargeUsers)

		users := make([]any, benchUsers)
		for i := range users {
			users[i] = map[string]any{
				"id":        i,
				"email":     "user" + strconv.Itoa(i) + "@example.com",
				"phone":     "15551234567",
				"token":     "eyJhbGciOiJIUzI1NiJ9",
				"role":      "admin",
				"meta":      map[string]any{"active": true, "logins": 42},
				"addresses": []any{map[string]any{"city": "moscow", "zip": "101000"}},
			}
		}
		benchMapNested = map[string]any{"users": users, "total": benchUsers}
	})
}

func mediumJSON() []byte {
	buildBenchPayloads()
	return benchJSONMedium
}

func largeJSON() []byte {
	buildBenchPayloads()
	return benchJSONLarge
}

func nestedMap() map[string]any {
	buildBenchPayloads()
	return benchMapNested
}

type benchStruct struct {
	Name     string `mask:"email"`
	Token    string `mask:"token"`
	Attempts int
	Active   bool
	Meta     map[string]string
	Nested   *benchInner
}

type benchInner struct {
	Phone string `mask:"phone"`
	Note  string
}

type benchWideStruct struct {
	A string
	B string
	C string
	D string
	E string
	F string
	G string
	H string
	I string
	J string
	K string
	L string
	M string
	N string
	O string
	P string
}

// --- reflection walk --------------------------------------------------------

func BenchmarkMaskAnyScalar(b *testing.B) {
	m := newBenchMasker(b)
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskAny("visible")
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

func BenchmarkMaskAnyFlatStruct(b *testing.B) {
	m := newBenchMasker(b)
	value := struct {
		Name     string
		Attempts int
		Active   bool
	}{Name: "visible", Attempts: 3, Active: true}
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskAny(value)
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

func BenchmarkMaskAnyWideStruct(b *testing.B) {
	m := newBenchMasker(b)
	value := benchWideStruct{
		A: "a", B: "b", C: "c", D: "d", E: "e", F: "f", G: "g", H: "h",
		I: "i", J: "j", K: "k", L: "l", M: "m", N: "n", O: "o", P: "p",
	}
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskAny(value)
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

func BenchmarkMaskAnySmallStruct(b *testing.B) {
	m := newBenchMasker(b)
	value := benchStruct{
		Name:     "a@b.c",
		Token:    "t",
		Attempts: 3,
		Active:   true,
		Meta:     map[string]string{"k": "v"},
		Nested:   &benchInner{Phone: "15551234567", Note: "n"},
	}
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskAny(value)
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

func BenchmarkMaskAnyNestedMap(b *testing.B) {
	m := newBenchMasker(b)
	value := nestedMap()
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, err = m.MaskAny(value)
	}
	b.StopTimer()
	validateBenchmarkValue(b, err)
}

// --- JSON -------------------------------------------------------------------

const smallJSONDoc = `{"user":{"email":"alice@example.com","phone":"15551234567"},"token":"t","count":3}`

func BenchmarkMaskJSONSmall(b *testing.B) {
	benchmarkMaskJSON(b, []byte(smallJSONDoc))
}

func BenchmarkMaskJSONMedium(b *testing.B) {
	benchmarkMaskJSON(b, mediumJSON())
}

func BenchmarkMaskJSONScaling(b *testing.B) {
	for _, records := range []int{1, 100, 1_000, 10_000} {
		b.Run("records_"+strconv.Itoa(records), func(b *testing.B) {
			benchmarkMaskJSON(b, scalingJSON(records))
		})
	}
}

func BenchmarkMaskJSONLarge(b *testing.B) {
	benchmarkMaskJSON(b, largeJSON())
}

func TestMaskJSONWideObject(t *testing.T) {
	source := wideObjectJSON(1_000)
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	masked, err := m.MaskJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(masked) || !strings.Contains(string(masked), `"token":"[REDACTED]"`) {
		t.Fatalf("wide object was not masked correctly: %s", masked[:min(len(masked), 120)])
	}
	if string(source) == string(masked) {
		t.Fatal("wide object was returned unchanged")
	}
}

func BenchmarkMaskJSONWideObject(b *testing.B) {
	for _, members := range []int{1_000, 4_000, 16_000, 40_000} {
		b.Run("members_"+strconv.Itoa(members), func(b *testing.B) {
			benchmarkMaskJSON(b, wideObjectJSON(members))
		})
		b.Run("collision_members_"+strconv.Itoa(members), func(b *testing.B) {
			benchmarkMaskJSON(b, wideObjectCollisionJSON(members))
		})
	}
}

func benchmarkMaskJSON(b *testing.B, src []byte) {
	b.Helper()
	m := newBenchMasker(b)
	var err error
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkBytesSink, err = m.MaskJSON(src)
	}
	b.StopTimer()
	if err != nil {
		b.Fatal(err)
	}
	if !json.Valid(benchmarkBytesSink) {
		b.Fatal("invalid JSON output")
	}
}

func scalingJSON(records int) []byte {
	var builder strings.Builder
	builder.Grow(records * 80)
	builder.WriteString(`{"users":[`)
	for i := 0; i < records; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		id := strconv.Itoa(i)
		builder.WriteString(`{"id":` + id + `,` +
			`"email":"user` + id + `@example.com",` +
			`"token":"eyJhbGciOiJIUzI1NiJ9",` +
			`"role":"admin"}`)
	}
	builder.WriteString(`],"total":` + strconv.Itoa(records) + `}`)
	return []byte(builder.String())
}

func wideObjectJSON(members int) []byte {
	var builder strings.Builder
	builder.Grow(members * 18)
	builder.WriteString(`{"token":"wide-secret"`)
	for i := 1; i < members; i++ {
		builder.WriteByte(',')
		builder.WriteString(`"field_`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`":"value_`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return []byte(builder.String())
}

func wideObjectCollisionJSON(members int) []byte {
	var builder strings.Builder
	builder.Grow(members * 24)
	builder.WriteString(`{"token":"wide-secret"`)
	for i := 1; i < members; i++ {
		builder.WriteByte(',')
		builder.WriteString(`"f`)
		_, _ = fmt.Fprintf(&builder, "%08d", i)
		builder.WriteString(`x":"value"`)
	}
	builder.WriteByte('}')
	return []byte(builder.String())
}

// --- httpmask -----------------------------------------------------------------

func benchmarkHeaders() http.Header {
	return http.Header{
		"Authorization": {"Bearer eyJhbGciOi"},
		"Cookie":        {"session=abc"},
		"Accept":        {"application/json", "text/html"},
		"X-Trace-Id":    {"trace"},
		"User-Agent":    {"go-masker-bench/1.0"},
		"X-Request-Id":  {"req"},
		"Content-Type":  {"application/json"},
		"Referer":       {"https://example.com/page"},
	}
}

func BenchmarkAdapterHeadersMixed(b *testing.B) {
	core := newBenchMasker(b)
	adapter, err := httpmask.New(core)
	if err != nil {
		b.Fatal(err)
	}
	headers := benchmarkHeaders()
	var operationErr error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, operationErr = adapter.Headers(headers)
	}
	b.StopTimer()
	validateBenchmarkValue(b, operationErr)
}

func benchmarkURL() *url.URL {
	u, err := url.Parse("https://alice:s3cret@example.com/api/v1/search?q=tokens&token=t1&token=t2&keep=1&page=2&limit=20#section")
	if err != nil {
		panic(err)
	}
	return u
}

func BenchmarkAdapterURLQuery(b *testing.B) {
	core := newBenchMasker(b)
	adapter, err := httpmask.New(core)
	if err != nil {
		b.Fatal(err)
	}
	raw := benchmarkURL()
	var operationErr error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkValueSink, operationErr = adapter.URL(raw)
	}
	b.StopTimer()
	validateBenchmarkValue(b, operationErr)
}

func validateBenchmarkString(b *testing.B, err error) {
	b.Helper()
	if err != nil {
		b.Fatal(err)
	}
	if benchmarkStringSink == "" {
		b.Fatal("empty benchmark output")
	}
}

func validateBenchmarkValue(b *testing.B, err error) {
	b.Helper()
	if err != nil {
		b.Fatal(err)
	}
	if benchmarkValueSink == nil {
		b.Fatal("nil benchmark output")
	}
}
