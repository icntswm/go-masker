package masker_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
)

var benchmarkMatrixSink any

type matrixCase struct {
	name    string
	options []masker.Option
	prepare func(testing.TB, *masker.Masker) func() (any, error)
	check   func(testing.TB, any, error)
	verify  func(testing.TB)
}

func TestBenchmarkMatrixCorrectness(t *testing.T) {
	cases := buildBenchmarkMatrix()
	const expectedCases = 260
	if len(cases) != expectedCases {
		t.Fatalf("unexpected benchmark matrix size: got %d, want %d", len(cases), expectedCases)
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			m, err := masker.New(masker.DefaultPolicy(), testCase.options...)
			if err != nil {
				t.Fatal(err)
			}
			run := testCase.prepare(t, m)
			result, runErr := run()
			testCase.check(t, result, runErr)
			if testCase.verify != nil {
				testCase.verify(t)
			}
		})
	}
}

func BenchmarkMaskMatrix(b *testing.B) {
	cases := buildBenchmarkMatrix()
	for _, testCase := range cases {
		b.Run(testCase.name, func(b *testing.B) {
			m := newBenchMasker(b, testCase.options...)
			run := testCase.prepare(b, m)
			var result any
			var err error
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err = run()
			}
			b.StopTimer()
			benchmarkMatrixSink = result
			testCase.check(b, result, err)
			if testCase.verify != nil {
				testCase.verify(b)
			}
		})
	}
}

func buildBenchmarkMatrix() []matrixCase {
	cases := make([]matrixCase, 0, 270)
	cases = append(cases, buildJSONMatrix()...)
	cases = append(cases, buildJSONCornerCases()...)
	cases = append(cases, buildAnyMatrix()...)
	cases = append(cases, buildURLMatrix()...)
	cases = append(cases, buildHeaderMatrix()...)
	cases = append(cases, buildDiverseMatrix()...)
	return cases
}

func buildJSONCornerCases() []matrixCase {
	cases := []matrixCase{
		jsonErrorCase("json/errors/empty", nil, masker.ErrInvalidJSON),
		jsonErrorCase("json/errors/truncated", []byte(`{"password":"secret`), masker.ErrInvalidJSON),
		jsonErrorCase("json/errors/trailing_garbage", []byte(`{"password":"secret"} garbage`), masker.ErrInvalidJSON),
		jsonErrorCase("json/errors/multiple_documents", []byte(`{} {}`), masker.ErrInvalidJSON),
		jsonExactCase("json/scalars/bool", []byte(`true`), []byte(`"true"`)),
		jsonExactCase("json/scalars/number", []byte(`9007199254740993`), []byte(`9007199254740993`)),
		jsonExactCase("json/scalars/null", []byte(`null`), []byte(`null`)),
		jsonExactCase("json/scalars/string", []byte(`"public-scalar"`), []byte(`"public-scalar"`)),
	}
	return cases
}

// --- JSON matrix -----------------------------------------------------------

func buildJSONMatrix() []matrixCase {
	layouts := []string{"flat", "nested", "array", "wide", "deep", "escaped"}
	sizes := []int{1, 10, 100, 1_000, 10_000}
	variants := []string{"compact", "whitespace", "unicode", "duplicate"}
	cases := make([]matrixCase, 0, len(layouts)*len(sizes)*len(variants))
	for layoutIndex, layout := range layouts {
		for sizeIndex, size := range sizes {
			for variantIndex, variant := range variants {
				id := "j" + strconv.Itoa(layoutIndex) + "_" + strconv.Itoa(sizeIndex) + "_" + strconv.Itoa(variantIndex)
				raw := matrixJSON(layout, size, variantIndex, id)
				caseName := "json/" + layout + "/records_" + strconv.Itoa(size) + "/" + variant
				options := []masker.Option(nil)
				if variantIndex == 2 {
					options = []masker.Option{masker.WithPreserveSafeTypes()}
				}
				if layout == "wide" || layout == "deep" {
					options = append(options, masker.WithMaxNodes(500_000))
				}
				if layout == "deep" {
					options = append(options, masker.WithMaxInputBytes(32<<20))
				}
				cases = append(cases, matrixCase{
					name:    caseName,
					options: options,
					prepare: prepareJSON(raw),
					check:   checkJSONSuccess("secret-"+id, "public-"+id, layout == "array" || layout == "wide"),
				})
			}
		}
	}
	return cases
}

func matrixJSON(layout string, size, variant int, id string) []byte {
	public := "public-" + id
	var builder strings.Builder
	builder.WriteString(`{"items":[`)
	for i := 0; i < size; i++ {
		if i != 0 {
			builder.WriteByte(',')
		}
		itemID := id + "-" + strconv.Itoa(i)
		itemSecret := "secret-" + itemID
		itemPublic := "public-" + itemID
		switch layout {
		case "flat":
			if variant == 3 && i == 0 {
				builder.WriteString(`{"password":"safe","password":"` + itemSecret + `","public":"` + itemPublic + `","count":` + strconv.Itoa(i) + `}`)
				continue
			}
			builder.WriteString(`{"password":"` + itemSecret + `","public":"` + itemPublic + `","count":` + strconv.Itoa(i) + `}`)
		case "nested":
			builder.WriteString(`{"profile":{"credentials":{"password":"` + itemSecret + `"},"public":"` + itemPublic + `"}}`)
		case "array":
			builder.WriteString(`{"values":[{"token":"` + itemSecret + `"},{"public":"` + itemPublic + `"}],"index":` + strconv.Itoa(i) + `}`)
		case "wide":
			builder.WriteString(`{"password":"` + itemSecret + `"`)
			for field := 0; field < 16; field++ {
				builder.WriteString(`,"field` + strconv.Itoa(field) + `":"` + itemPublic + `"`)
			}
			builder.WriteByte('}')
		case "deep":
			builder.WriteString(matrixDeepRecord(2+(sizeIndexForMatrixSize(size)*5), itemSecret, itemPublic))
		case "escaped":
			builder.WriteString(`{"password":"` + itemSecret + `\\\"quoted\\\n","public":"` + itemPublic + `","note":"line\\n\\tvalue"}`)
		default:
			panic("unknown JSON matrix layout: " + layout)
		}
	}
	builder.WriteString(`],"public":"` + public + `"}`)
	raw := builder.String()
	if variant == 2 {
		raw = strings.Replace(raw, `"public-`+id+`"`, `"public-`+id+`-λ"`, 1)
	}
	if variant == 1 {
		var indented bytes.Buffer
		if err := json.Indent(&indented, []byte(raw), "", "  "); err != nil {
			panic(err)
		}
		raw = indented.String()
	}
	return []byte(raw)
}

func sizeIndexForMatrixSize(size int) int {
	switch size {
	case 1:
		return 0
	case 10:
		return 1
	case 100:
		return 2
	case 1_000:
		return 3
	default:
		return 4
	}
}

func matrixDeepRecord(depth int, secret, public string) string {
	var builder strings.Builder
	for i := 0; i < depth; i++ {
		builder.WriteString(`{"level":`)
	}
	builder.WriteString(`{"password":"` + secret + `","public":"` + public + `"}`)
	for i := 0; i < depth; i++ {
		builder.WriteByte('}')
	}
	return builder.String()
}

func prepareJSON(raw []byte) func(testing.TB, *masker.Masker) func() (any, error) {
	return func(tb testing.TB, m *masker.Masker) func() (any, error) {
		tb.Helper()
		return func() (any, error) { return m.MaskJSON(raw) }
	}
}

func checkJSONSuccess(secret, public string, wantCollection bool) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected JSON error: %v", err)
		}
		output, ok := result.([]byte)
		if !ok || !json.Valid(output) {
			tb.Fatalf("invalid JSON output: %T %q", result, output)
		}
		if bytes.Contains(output, []byte(secret)) || !bytes.Contains(output, []byte(masker.DefaultRedactionMarker)) {
			tb.Fatalf("sensitive value was not masked: %s", output)
		}
		if !bytes.Contains(output, []byte(public)) {
			tb.Fatalf("safe value was lost: %s", output)
		}
		var decoded any
		if err := json.Unmarshal(output, &decoded); err != nil {
			tb.Fatalf("output cannot be decoded: %v", err)
		}
		if wantCollection {
			if _, ok := decoded.(map[string]any); !ok {
				tb.Fatalf("expected object output, got %T", decoded)
			}
		}
	}
}

func jsonErrorCase(name string, raw []byte, want error) matrixCase {
	return matrixCase{
		name:    name,
		prepare: prepareJSON(raw),
		check: func(tb testing.TB, result any, err error) {
			tb.Helper()
			output, ok := result.([]byte)
			if err == nil || !errors.Is(err, want) || !ok || !json.Valid(output) || string(output) != `"[REDACTED]"` {
				tb.Fatalf("unexpected JSON failure: result=%q err=%v", output, err)
			}
		},
	}
}

func jsonExactCase(name string, raw, want []byte) matrixCase {
	return matrixCase{
		name:    name,
		prepare: prepareJSON(raw),
		check: func(tb testing.TB, result any, err error) {
			tb.Helper()
			output, ok := result.([]byte)
			if err != nil || !ok || !bytes.Equal(output, want) {
				tb.Fatalf("unexpected JSON scalar: got=%q want=%q err=%v", output, want, err)
			}
		},
	}
}

// --- reflection matrix -----------------------------------------------------

type matrixTaggedStruct struct {
	Email    string `mask:"email"`
	Token    string `mask:"token"`
	Public   string
	Attempts int
	Active   bool
}

type matrixNestedStruct struct {
	Secret string `mask:"password"`
	Public string
	Child  *matrixNestedStruct
}

func buildAnyMatrix() []matrixCase {
	layouts := []string{"flat_map", "wide_map", "nested_map", "tagged_struct", "slice_map"}
	sizes := []int{1, 4, 8, 16, 24}
	cases := make([]matrixCase, 0, 35)
	for layoutIndex, layout := range layouts {
		for sizeIndex, size := range sizes {
			id := "a" + strconv.Itoa(layoutIndex) + "_" + strconv.Itoa(sizeIndex)
			value := matrixAnyValue(layout, size, id)
			cases = append(cases, matrixCase{
				name:    "any/" + layout + "/size_" + strconv.Itoa(size),
				prepare: prepareAny(value),
				check:   checkAnySuccess("secret-"+id, "public-"+id),
			})
		}
	}
	cases = append(cases,
		matrixErrorCase("any/cycle", prepareAny(matrixCycleValue()), masker.ErrCycle),
		matrixErrorCase("any/depth_limit", prepareAny(matrixDeepValue(40)), masker.ErrDepthLimit, masker.WithMaxDepth(8)),
		matrixErrorCase("any/node_limit", prepareAny(matrixFlatMap(128, "limit")), masker.ErrNodeLimit, masker.WithMaxNodes(8)),
		matrixErrorCase("any/unsupported_type", prepareAny(func() {}), masker.ErrUnsupportedType),
		matrixNilCase(),
	)
	return cases
}

func matrixAnyValue(layout string, size int, id string) any {
	switch layout {
	case "flat_map":
		return matrixFlatMap(size, id)
	case "wide_map":
		result := map[string]any{"password": "secret-" + id, "public": "public-" + id}
		for i := 0; i < size; i++ {
			result["field_"+strconv.Itoa(i)] = "public-" + id
		}
		return result
	case "nested_map":
		return matrixNestedMap(size, id)
	case "tagged_struct":
		return matrixTaggedStruct{Email: "user@" + id + ".example", Token: "secret-" + id, Public: "public-" + id, Attempts: size, Active: true}
	case "slice_map":
		items := make([]any, size)
		for i := range items {
			items[i] = map[string]any{"token": "secret-" + id, "public": "public-" + id, "index": i}
		}
		return map[string]any{"items": items, "public": "public-" + id}
	default:
		panic("unknown Any matrix layout: " + layout)
	}
}

func matrixFlatMap(size int, id string) map[string]any {
	result := map[string]any{"password": "secret-" + id, "public": "public-" + id}
	for i := 0; i < size; i++ {
		result["value_"+strconv.Itoa(i)] = i
	}
	return result
}

func matrixNestedMap(depth int, id string) map[string]any {
	root := map[string]any{"public": "public-" + id}
	current := root
	for i := 0; i < depth; i++ {
		next := map[string]any{"public": "public-" + id}
		current["level"] = next
		current = next
	}
	current["password"] = "secret-" + id
	return root
}

func matrixDeepValue(depth int) map[string]any {
	root := map[string]any{}
	current := root
	for i := 0; i < depth; i++ {
		next := map[string]any{}
		current["level"] = next
		current = next
	}
	current["password"] = "secret-deep"
	return root
}

func matrixCycleValue() *matrixNestedStruct {
	value := &matrixNestedStruct{Secret: "secret-cycle", Public: "public-cycle"}
	value.Child = value
	return value
}

func prepareAny(value any) func(testing.TB, *masker.Masker) func() (any, error) {
	return func(tb testing.TB, m *masker.Masker) func() (any, error) {
		tb.Helper()
		return func() (any, error) { return m.MaskAny(value) }
	}
}

func checkAnySuccess(secret, public string) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected Any error: %v", err)
		}
		if containsMatrixString(result, secret) || !containsMatrixString(result, public) || !containsMatrixString(result, masker.DefaultRedactionMarker) {
			tb.Fatalf("unexpected Any result: %#v", result)
		}
	}
}

func matrixErrorCase(name string, prepare func(testing.TB, *masker.Masker) func() (any, error), want error, options ...masker.Option) matrixCase {
	return matrixCase{
		name:    name,
		options: options,
		prepare: prepare,
		check: func(tb testing.TB, result any, err error) {
			tb.Helper()
			if err == nil || !errors.Is(err, want) {
				tb.Fatalf("unexpected error: %v, want %v", err, want)
			}
			if result != masker.DefaultRedactionMarker {
				tb.Fatalf("unexpected fail-closed result: %#v", result)
			}
		},
	}
}

func matrixFailureCase(name string, prepare func(testing.TB, *masker.Masker) func() (any, error)) matrixCase {
	return matrixCase{
		name:    name,
		prepare: prepare,
		check: func(tb testing.TB, result any, err error) {
			tb.Helper()
			if err == nil || result != masker.DefaultRedactionMarker {
				tb.Fatalf("unexpected fail-closed result: result=%#v err=%v", result, err)
			}
		},
	}
}

func matrixNilCase() matrixCase {
	return matrixCase{
		name:    "any/nil",
		prepare: prepareAny(nil),
		check: func(tb testing.TB, result any, err error) {
			tb.Helper()
			if err != nil || result != nil {
				tb.Fatalf("nil input changed: result=%#v err=%v", result, err)
			}
		},
	}
}

func containsMatrixString(value any, want string) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return typed == want
	case map[string]any:
		for key, child := range typed {
			if key == want || containsMatrixString(child, want) {
				return true
			}
		}
		return false
	case []any:
		for _, child := range typed {
			if containsMatrixString(child, want) {
				return true
			}
		}
		return false
	}
	valueOf := reflect.ValueOf(value)
	for valueOf.IsValid() && (valueOf.Kind() == reflect.Pointer || valueOf.Kind() == reflect.Interface) {
		if valueOf.IsNil() {
			return false
		}
		valueOf = valueOf.Elem()
	}
	if !valueOf.IsValid() {
		return false
	}
	if valueOf.Kind() == reflect.Struct {
		for i := range valueOf.NumField() {
			if containsMatrixString(valueOf.Field(i).Interface(), want) {
				return true
			}
		}
	}
	return false
}

func collectMatrixStrings(value any, found map[string]struct{}) {
	if value == nil {
		return
	}
	switch typed := value.(type) {
	case string:
		found[typed] = struct{}{}
	case map[string]any:
		for key, child := range typed {
			found[key] = struct{}{}
			collectMatrixStrings(child, found)
		}
	case []any:
		for _, child := range typed {
			collectMatrixStrings(child, found)
		}
	}
}

// --- diverse-key matrix ---------------------------------------------------

func buildDiverseMatrix() []matrixCase {
	cases := make([]matrixCase, 0, 50)
	jsonSizes := []int{1, 10, 100, 1_000, 10_000}
	jsonLayouts := []string{"diverse_flat", "diverse_nested"}
	jsonVariants := []string{"compact", "unicode", "mixed_case"}
	for layoutIndex, layout := range jsonLayouts {
		for sizeIndex, size := range jsonSizes {
			for variantIndex, variant := range jsonVariants {
				id := "dj" + strconv.Itoa(layoutIndex) + "_" + strconv.Itoa(sizeIndex) + "_" + strconv.Itoa(variantIndex)
				raw, secrets, publics := matrixDiverseJSON(layout, size, variantIndex, id)
				original := append([]byte(nil), raw...)
				options := []masker.Option(nil)
				if size >= 1_000 {
					options = []masker.Option{
						masker.WithMaxNodes(1_000_000),
						masker.WithMaxInputBytes(64 << 20),
					}
				}
				cases = append(cases, matrixCase{
					name:    "json/" + layout + "/records_" + strconv.Itoa(size) + "/" + variant,
					options: options,
					prepare: prepareJSON(raw),
					check:   checkJSONDiverseSuccess(secrets, publics),
					verify:  verifyBytesUnchanged(raw, original),
				})
			}
		}
	}

	anySizes := []int{1, 4, 8, 16, 24}
	anyLayouts := []string{"diverse_map", "diverse_nested"}
	for layoutIndex, layout := range anyLayouts {
		for sizeIndex, size := range anySizes {
			id := "da" + strconv.Itoa(layoutIndex) + "_" + strconv.Itoa(sizeIndex)
			value, secrets, publics := matrixDiverseAnyValue(layout, size, id)
			cases = append(cases, matrixCase{
				name:    "any/" + layout + "/size_" + strconv.Itoa(size),
				prepare: prepareAny(value),
				check:   checkAnyDiverseSuccess(secrets, publics),
				verify:  verifyAnyUnchanged(value),
			})
		}
	}

	urlSizes := []int{1, 10, 100, 1_000, 5_000}
	urlShapes := []string{"diverse_query", "diverse_encoded_query"}
	for shapeIndex, shape := range urlShapes {
		for sizeIndex, size := range urlSizes {
			id := "du" + strconv.Itoa(shapeIndex) + "_" + strconv.Itoa(sizeIndex)
			raw, secrets, publics := matrixDiverseURL(shape, size, id)
			cases = append(cases, matrixCase{
				name:    "url/" + shape + "/parts_" + strconv.Itoa(size),
				prepare: prepareURL(raw, false),
				check:   checkURLDiverseSuccess(secrets, publics),
			})
		}
	}
	return cases
}

func matrixDiverseJSON(layout string, size, variant int, id string) ([]byte, []string, []string) {
	rootPublic := "public-" + id + "-root"
	secrets := make([]string, 0, size*3)
	publics := []string{rootPublic}
	var builder strings.Builder
	builder.WriteString(`{"items":[`)
	for i := 0; i < size; i++ {
		if i != 0 {
			builder.WriteByte(',')
		}
		itemID := id + "-" + strconv.Itoa(i)
		passwordKey, tokenKey, emailKey := matrixDiverseKeys(variant, i)
		password := "secret-" + itemID + "-password"
		token := "secret-" + itemID + "-token"
		email := "user-" + itemID + "-secret@example.com"
		secrets = append(secrets, password, token, email)
		name := "public-" + itemID + "-name"
		trace := "public-" + itemID + "-trace"
		publics = append(publics, name, trace)

		if layout == "diverse_flat" {
			builder.WriteByte('{')
			matrixWriteJSONField(&builder, "record_id", itemID)
			matrixWriteJSONField(&builder, passwordKey, password)
			matrixWriteJSONField(&builder, tokenKey, token)
			matrixWriteJSONField(&builder, emailKey, email)
			matrixWriteJSONField(&builder, "display_name_"+strconv.Itoa(i), name)
			matrixWriteJSONField(&builder, "trace_"+strconv.Itoa(i), trace)
			builder.WriteString(`,"count":` + strconv.Itoa(i))
			builder.WriteString(`,"active":`)
			builder.WriteString(strconv.FormatBool(i%2 == 0))
			builder.WriteString(`,"metadata":{"region_` + strconv.Itoa(i) + `":"eu-` + strconv.Itoa(i%4) + `"}`)
			builder.WriteByte('}')
			continue
		}

		depth := 1 + i%6
		builder.WriteString(`{"record_id":`)
		matrixWriteJSONString(&builder, itemID)
		builder.WriteString(`,"depth":` + strconv.Itoa(depth) + `,"branch":`)
		for level := 0; level < depth; level++ {
			builder.WriteString(`{"level_` + strconv.Itoa(level) + `":`)
		}
		builder.WriteByte('{')
		matrixWriteJSONField(&builder, passwordKey, password)
		matrixWriteJSONField(&builder, tokenKey, token)
		matrixWriteJSONField(&builder, emailKey, email)
		matrixWriteJSONField(&builder, "display_name_"+strconv.Itoa(i), name)
		matrixWriteJSONField(&builder, "trace_"+strconv.Itoa(i), trace)
		builder.WriteString(`,"value_` + strconv.Itoa(i) + `":"safe-value-` + strconv.Itoa(i) + `"}`)
		for level := 0; level < depth; level++ {
			builder.WriteByte('}')
		}
		builder.WriteByte('}')
	}
	builder.WriteString(`],"root_public":`)
	matrixWriteJSONString(&builder, rootPublic)
	builder.WriteByte('}')
	return []byte(builder.String()), secrets, publics
}

func matrixDiverseKeys(variant, index int) (string, string, string) {
	switch (variant + index) % 3 {
	case 1:
		return "PASSWORD", "ToKeN", "E-Mail"
	case 2:
		return "passwd", "api_key", "e-mail"
	default:
		return "password", "token", "email"
	}
}

func matrixWriteJSONString(builder *strings.Builder, value string) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	builder.Write(encoded)
}

func matrixWriteJSONField(builder *strings.Builder, key, value string) {
	if builder.Len() > 0 && builder.String()[builder.Len()-1] != '{' && builder.String()[builder.Len()-1] != ',' {
		builder.WriteByte(',')
	}
	matrixWriteJSONString(builder, key)
	builder.WriteByte(':')
	matrixWriteJSONString(builder, value)
}

func checkJSONDiverseSuccess(secrets, publics []string) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected JSON error: %v", err)
		}
		output, ok := result.([]byte)
		if !ok || !json.Valid(output) {
			tb.Fatalf("invalid JSON output: %T %q", result, output)
		}
		var decoded any
		if err := json.Unmarshal(output, &decoded); err != nil {
			tb.Fatalf("output cannot be decoded: %v", err)
		}
		found := make(map[string]struct{})
		collectMatrixStrings(decoded, found)
		for _, secret := range secrets {
			if _, ok := found[secret]; ok {
				tb.Fatalf("sensitive value leaked: %q", secret)
			}
		}
		for _, public := range publics {
			if _, ok := found[public]; !ok {
				tb.Fatalf("safe value was lost: %q", public)
			}
		}
		if _, ok := found[masker.DefaultRedactionMarker]; !ok {
			tb.Fatalf("redaction marker is missing")
		}
	}
}

func matrixDiverseAnyValue(layout string, size int, id string) (any, []string, []string) {
	secrets := make([]string, 0, size*3)
	publics := []string{"public-" + id + "-root"}
	root := map[string]any{"root_public": publics[0]}
	for i := 0; i < size; i++ {
		itemID := id + "-" + strconv.Itoa(i)
		password := "secret-" + itemID + "-password"
		token := "secret-" + itemID + "-token"
		email := "user-" + itemID + "-secret@example.com"
		secrets = append(secrets, password, token, email)
		name := "public-" + itemID + "-name"
		trace := "public-" + itemID + "-trace"
		publics = append(publics, name, trace)
		passwordKey, tokenKey, emailKey := matrixDiverseKeys(0, i)
		leaf := map[string]any{
			"record_id":                       itemID,
			passwordKey:                       password,
			tokenKey:                          token,
			emailKey:                          email,
			"display_name_" + strconv.Itoa(i): name,
			"trace_" + strconv.Itoa(i):        trace,
			"count":                           i,
		}
		if layout == "diverse_map" {
			root["record_"+strconv.Itoa(i)] = leaf
			continue
		}
		depth := 1 + i%5
		branch := map[string]any{}
		current := branch
		for level := 0; level < depth; level++ {
			next := map[string]any{}
			current["level_"+strconv.Itoa(level)] = next
			current = next
		}
		for key, value := range leaf {
			current[key] = value
		}
		root["branch_"+strconv.Itoa(i)] = branch
	}
	return root, secrets, publics
}

func checkAnyDiverseSuccess(secrets, publics []string) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected Any error: %v", err)
		}
		for _, secret := range secrets {
			if containsMatrixString(result, secret) {
				tb.Fatalf("sensitive value leaked: %q", secret)
			}
		}
		for _, public := range publics {
			if !containsMatrixString(result, public) {
				tb.Fatalf("safe value was lost: %q", public)
			}
		}
		if !containsMatrixString(result, masker.DefaultRedactionMarker) {
			tb.Fatalf("redaction marker is missing")
		}
	}
}

func verifyBytesUnchanged(raw, original []byte) func(testing.TB) {
	return func(tb testing.TB) {
		tb.Helper()
		if !bytes.Equal(raw, original) {
			tb.Fatal("source JSON was mutated")
		}
	}
}

func verifyAnyUnchanged(value any) func(testing.TB) {
	original, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return func(tb testing.TB) {
		tb.Helper()
		current, err := json.Marshal(value)
		if err != nil {
			tb.Fatalf("source Any value cannot be inspected: %v", err)
		}
		if !bytes.Equal(current, original) {
			tb.Fatal("source Any value was mutated")
		}
	}
}

// --- URL matrix ------------------------------------------------------------

func buildURLMatrix() []matrixCase {
	shapes := []string{"userinfo", "query", "userinfo_query", "fragment", "encoded_query"}
	sizes := []int{1, 2, 5, 20, 100}
	cases := make([]matrixCase, 0, 30)
	for shapeIndex, shape := range shapes {
		for sizeIndex, size := range sizes {
			id := "u" + strconv.Itoa(shapeIndex) + "_" + strconv.Itoa(sizeIndex)
			raw := matrixURL(shape, size, id)
			cases = append(cases, matrixCase{
				name:    "url/" + shape + "/parts_" + strconv.Itoa(size),
				prepare: prepareURL(raw, shape == "fragment"),
				check:   checkURLSuccess("secret-"+id, shape == "userinfo" || shape == "userinfo_query", shape == "query" || shape == "userinfo_query" || shape == "encoded_query"),
			})
		}
	}
	cases = append(cases,
		matrixFailureCase("url/invalid_query", prepareURL("https://example.com/?token=%zz", false)),
		matrixFailureCase("url/opaque", prepareURL("mailto:user@example.com", false)),
	)
	return cases
}

func matrixURL(shape string, size int, id string) string {
	base := "https://user:secret-" + id + "@example.com/path"
	switch shape {
	case "userinfo":
		return base
	case "query":
		return "https://example.com/path?keep=public-" + id + "&token=secret-" + id
	case "userinfo_query":
		var query strings.Builder
		query.WriteString(base + "?")
		for i := 0; i < size; i++ {
			if i != 0 {
				query.WriteByte('&')
			}
			query.WriteString("token=secret-" + id + "&keep=public-" + id)
		}
		return query.String()
	case "fragment":
		return base + "#public-" + id
	case "encoded_query":
		return "https://example.com/path?token=secret-" + id + "&q=public-" + id + "%20value"
	default:
		panic("unknown URL matrix shape: " + shape)
	}
}

func prepareURL(raw string, maskFragment bool) func(testing.TB, *masker.Masker) func() (any, error) {
	return func(tb testing.TB, m *masker.Masker) func() (any, error) {
		tb.Helper()
		options := []httpmask.Option(nil)
		if maskFragment {
			options = append(options, httpmask.WithMaskFragment())
		}
		adapter, err := httpmask.New(m, options...)
		if err != nil {
			tb.Fatal(err)
		}
		return func() (any, error) { return adapter.URLString(raw) }
	}
}

func checkURLSuccess(secret string, hasUserinfo, wantPublic bool) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected URL error: %v", err)
		}
		output, ok := result.(string)
		if !ok || output == "" || strings.Contains(output, secret) {
			tb.Fatalf("unexpected URL output: %#v", result)
		}
		parsed, parseErr := url.Parse(output)
		if parseErr != nil {
			tb.Fatalf("masked URL cannot be parsed: %v", parseErr)
		}
		if hasUserinfo && (parsed.User == nil || parsed.User.Username() != masker.DefaultRedactionMarker) {
			tb.Fatalf("userinfo was not masked: %q", output)
		}
		if wantPublic && !strings.Contains(output, "public-") {
			tb.Fatalf("safe URL value was lost: %q", output)
		}
	}
}

func matrixDiverseURL(shape string, size int, id string) (string, []string, []string) {
	var builder strings.Builder
	builder.WriteString("https://example.com/data?")
	secrets := make([]string, 0, size*3)
	publics := []string{"public-" + id + "-root"}
	appendPair := func(key, value string) {
		if builder.Len() > len("https://example.com/data?") {
			builder.WriteByte('&')
		}
		builder.WriteString(url.QueryEscape(key))
		builder.WriteByte('=')
		builder.WriteString(url.QueryEscape(value))
	}
	appendPair("root", publics[0])
	for i := 0; i < size; i++ {
		itemID := id + "-" + strconv.Itoa(i)
		password := "secret-" + itemID + "-password"
		token := "secret-" + itemID + "-token"
		email := "user-" + itemID + "-secret@example.com"
		secrets = append(secrets, password, token, email)
		name := "public-" + itemID + "-name"
		trace := "public-" + itemID + "-trace"
		publics = append(publics, name, trace)
		passwordKey, tokenKey, emailKey := matrixDiverseKeys(0, i)
		appendPair(passwordKey, password)
		appendPair(tokenKey, token)
		appendPair(emailKey, email)
		appendPair("display_name_"+strconv.Itoa(i), name)
		appendPair("trace_"+strconv.Itoa(i), trace)
		value := "safe value " + itemID
		if shape == "diverse_encoded_query" {
			value += " λ"
		}
		appendPair("value_"+strconv.Itoa(i), value)
	}
	return builder.String(), secrets, publics
}

func checkURLDiverseSuccess(secrets, publics []string) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected URL error: %v", err)
		}
		output, ok := result.(string)
		if !ok || output == "" {
			tb.Fatalf("unexpected URL output: %#v", result)
		}
		parsed, parseErr := url.Parse(output)
		if parseErr != nil {
			tb.Fatalf("masked URL cannot be parsed: %v", parseErr)
		}
		query, queryErr := url.ParseQuery(parsed.RawQuery)
		if queryErr != nil {
			tb.Fatalf("masked query cannot be parsed: %v", queryErr)
		}
		for _, secret := range secrets {
			if strings.Contains(output, secret) {
				tb.Fatalf("sensitive URL value leaked: %q", secret)
			}
		}
		for _, public := range publics {
			if !matrixQueryHasValue(query, public) {
				tb.Fatalf("safe URL value was lost: %q", public)
			}
		}
		if !matrixQueryHasValue(query, masker.DefaultRedactionMarker) {
			tb.Fatalf("redaction marker is missing")
		}
	}
}

func matrixQueryHasValue(query url.Values, want string) bool {
	for _, values := range query {
		for _, value := range values {
			if value == want {
				return true
			}
		}
	}
	return false
}

// --- headers matrix --------------------------------------------------------

func buildHeaderMatrix() []matrixCase {
	layouts := []string{"cookies", "authorization", "mixed", "case", "safe"}
	sizes := []int{1, 2, 5, 20, 100}
	cases := make([]matrixCase, 0, 25)
	for layoutIndex, layout := range layouts {
		for sizeIndex, size := range sizes {
			id := "h" + strconv.Itoa(layoutIndex) + "_" + strconv.Itoa(sizeIndex)
			source := matrixHeaders(layout, size, id)
			original := source.Clone()
			cases = append(cases, matrixCase{
				name:    "headers/" + layout + "/values_" + strconv.Itoa(size),
				prepare: prepareHeaders(source),
				check:   checkHeaders(source, original, layout, id),
			})
		}
	}
	return cases
}

func matrixHeaders(layout string, size int, id string) http.Header {
	secret := "secret-" + id
	public := "public-" + id
	values := make([]string, size)
	for i := range values {
		values[i] = secret + "-" + strconv.Itoa(i)
	}
	switch layout {
	case "cookies":
		return http.Header{"Cookie": values, "Set-Cookie": values, "X-Public": {public}}
	case "authorization":
		for i := range values {
			values[i] = "Bearer " + values[i]
		}
		return http.Header{"Authorization": values, "X-Public": {public}}
	case "mixed":
		return http.Header{"Cookie": values, "Authorization": values, "X-Public": {public}, "X-Count": {strconv.Itoa(size)}}
	case "case":
		return http.Header{"cOoKiE": values, "aUtHoRiZaTiOn": values, "X-Public": {public}}
	case "safe":
		safe := make([]string, size)
		for i := range safe {
			safe[i] = public + "-" + strconv.Itoa(i)
		}
		return http.Header{"X-Public": safe, "Accept": {"application/json"}}
	default:
		panic("unknown header matrix layout: " + layout)
	}
}

func prepareHeaders(source http.Header) func(testing.TB, *masker.Masker) func() (any, error) {
	return func(tb testing.TB, m *masker.Masker) func() (any, error) {
		tb.Helper()
		adapter, err := httpmask.New(m)
		if err != nil {
			tb.Fatal(err)
		}
		return func() (any, error) { return adapter.Headers(source) }
	}
}

func checkHeaders(source, original http.Header, layout, id string) func(testing.TB, any, error) {
	return func(tb testing.TB, result any, err error) {
		tb.Helper()
		if err != nil {
			tb.Fatalf("unexpected headers error: %v", err)
		}
		output, ok := result.(http.Header)
		if !ok {
			tb.Fatalf("unexpected headers result: %#v", result)
		}
		if !reflect.DeepEqual(source, original) {
			tb.Fatal("source headers were mutated")
		}
		secret := "secret-" + id
		for key, values := range output {
			for _, value := range values {
				if layout != "safe" && strings.Contains(value, secret) {
					tb.Fatalf("secret leaked in header %q: %q", key, value)
				}
			}
		}
		if layout == "safe" {
			foundPublic := false
			for _, values := range output {
				for _, value := range values {
					if strings.Contains(value, "public-"+id) {
						foundPublic = true
					}
				}
			}
			if !foundPublic {
				tb.Fatalf("safe header changed: %#v", output)
			}
		}
	}
}
