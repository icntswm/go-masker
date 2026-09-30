package slogmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	masker "github.com/icntswm/go-masker"
)

func newCore(t *testing.T, policies ...masker.Policy) *masker.Masker {
	t.Helper()
	policies = append(policies, masker.DefaultPolicy())
	core, err := masker.New(masker.Chain(policies...))
	if err != nil {
		t.Fatal(err)
	}
	return core
}

// logRecord writes one record through a JSON handler wired to ReplaceAttr
// and returns the raw line and its decoded form.
func logRecord(t *testing.T, core *masker.Masker, attrs ...any) (string, map[string]any) {
	t.Helper()
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr(core)}))
	logger.Info("request handled", attrs...)
	decoded := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid log line %q: %v", buffer.String(), err)
	}
	return buffer.String(), decoded
}

func TestReplaceAttrMasksAttributes(t *testing.T) {
	core := newCore(t)
	wantEmail, err := core.MaskValue("email", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	line, record := logRecord(t, core,
		slog.String("password", "dummy-password"),
		slog.String("email", "alice@example.com"),
		slog.Int("count", 3),
		slog.Bool("ok", true),
		slog.Group("req", slog.String("token", "dummy-token")),
		slog.Any("err", errors.New("boom")),
		slog.Any("user", struct{ Name, Password string }{Name: "alice", Password: "dummy-password"}),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original secret reached the log: %s", line)
	}
	if record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("password: %#v", record["password"])
	}
	if record["email"] != wantEmail {
		t.Fatalf("email: got %#v, want %#v", record["email"], wantEmail)
	}
	if record["count"] != float64(3) || record["ok"] != true {
		t.Fatalf("safe scalars lost their type: count=%#v ok=%#v", record["count"], record["ok"])
	}
	if record["err"] != "boom" {
		t.Fatalf("err: %#v", record["err"])
	}
	user, ok := record["user"].(map[string]any)
	if !ok || user["Name"] != "alice" {
		t.Fatalf("user: %#v", record["user"])
	}
	if record["msg"] != "request handled" || record["level"] != "INFO" {
		t.Fatalf("built-in attributes changed: %#v", record)
	}
}

func TestReplaceAttrPassesGroupPath(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	recorder := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		mu.Lock()
		paths = append(paths, field.Path)
		mu.Unlock()
		return masker.Decision{}, nil
	})
	_, record := logRecord(t, newCore(t, recorder), slog.Group("req", slog.String("token", "dummy-token")))
	group, ok := record["req"].(map[string]any)
	if !ok || group["token"] == "dummy-token" {
		t.Fatalf("grouped token was not masked: %#v", record["req"])
	}
	// The message is decided first, and the group as an object before its
	// member.
	if !slices.Equal(paths, []string{"$[msg]", "$[req]", "$[req][token]"}) {
		t.Fatalf("unexpected policy paths: %q", paths)
	}
}

func TestReplaceAttrMasksSensitiveGroups(t *testing.T) {
	line, _ := logRecord(t, newCore(t),
		slog.Group("credentials", slog.String("value", "dummy-group")),
		slog.Any("secret", groupValuer{}),
		slog.Group("req", slog.Group("password", slog.Int("n", 7))),
	)
	for _, want := range []string{
		`"credentials":{"value":"[REDACTED]"}`,
		`"secret":{"value":"[REDACTED]"}`,
		`"req":{"password":{"n":"[REDACTED]"}}`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("sensitive group was not masked, want %s in %s", want, line)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr(newCore(t))}))
	logger.WithGroup("token").Info("m", "value", "dummy-with-group")
	if strings.Contains(buf.String(), "dummy-") {
		t.Fatalf("WithGroup under a sensitive name bypassed masking: %s", buf.String())
	}

	omit := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		return masker.Decision{Omit: field.Key == "internal" || field.Key == "trace"}, nil
	})
	// log/slog writes a broken line when every member of a group is dropped
	// and another attribute follows it, so an omitted group, or member,
	// becomes the marker; logRecord fails on a line that is not valid JSON.
	_, record := logRecord(t, newCore(t, omit),
		slog.Group("internal", slog.String("a", "dummy-internal")),
		slog.Group("req", slog.String("trace", "dummy-trace")),
		slog.String("b", "kept"),
	)
	internal, _ := record["internal"].(map[string]any)
	req, _ := record["req"].(map[string]any)
	if internal["a"] != masker.DefaultRedactionMarker || req["trace"] != masker.DefaultRedactionMarker || record["b"] != "kept" {
		t.Fatalf("omitted group members: %#v", record)
	}
}

type groupValuer struct{}

func (groupValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("value", "dummy-valuer"))
}

func TestReplaceAttrOmitAndFailure(t *testing.T) {
	failing, err := masker.NewRule("failing", func(masker.RuleInput) (string, error) {
		return "", errors.New("dummy-detail")
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		switch field.Key {
		case "drop":
			return masker.Decision{Omit: true}, nil
		case "note":
			return masker.Decision{Rule: failing}, nil
		}
		return masker.Decision{}, nil
	})
	line, record := logRecord(t, newCore(t, policy), slog.String("drop", "dummy-dropped"), slog.String("note", "dummy-note"))
	if _, present := record["drop"]; present {
		t.Fatalf("omitted attribute was logged: %s", line)
	}
	if record["note"] != masker.DefaultRedactionMarker {
		t.Fatalf("failing rule did not produce the marker: %#v", record["note"])
	}
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original value reached the log: %s", line)
	}
}

func TestReplaceAttrNilCoreRedactsEverything(t *testing.T) {
	_, record := logRecord(t, nil, slog.String("name", "alice"), slog.Int("count", 3))
	if record["name"] != masker.DefaultRedactionMarker || record["count"] != masker.DefaultRedactionMarker {
		t.Fatalf("nil core leaked values: %#v", record)
	}
	if record["msg"] != masker.DefaultRedactionMarker {
		t.Fatalf("nil core logged the message: %#v", record["msg"])
	}
}

func TestReplaceAttrSearchesMessage(t *testing.T) {
	for _, handler := range []struct {
		name string
		new  func(*bytes.Buffer, *slog.HandlerOptions) slog.Handler
	}{
		{"json", func(b *bytes.Buffer, o *slog.HandlerOptions) slog.Handler { return slog.NewJSONHandler(b, o) }},
		{"text", func(b *bytes.Buffer, o *slog.HandlerOptions) slog.Handler { return slog.NewTextHandler(b, o) }},
	} {
		t.Run(handler.name, func(t *testing.T) {
			var buffer bytes.Buffer
			logger := slog.New(handler.new(&buffer, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr(newCore(t))}))
			logger.Info("login failed: password=dummy-password user=alice")
			line := buffer.String()
			if strings.Contains(line, "dummy-password") {
				t.Fatalf("a secret in the message reached the log: %s", line)
			}
			if !strings.Contains(line, "login failed: password=[REDACTED] user=alice") {
				t.Fatalf("message was not masked in place: %s", line)
			}
		})
	}

	_, record := logRecord(t, newCore(t))
	if record["msg"] != "request handled" {
		t.Fatalf("a message without secrets changed: %#v", record["msg"])
	}

	omitMessage := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Path == "$[msg]" {
			return masker.Decision{Omit: true}, nil
		}
		return masker.Decision{}, nil
	})
	line, record := logRecord(t, newCore(t, omitMessage))
	if _, present := record["msg"]; present || record["level"] != "INFO" {
		t.Fatalf("an omitted message was logged: %s", line)
	}
}

type panickingValuer struct{}

func (panickingValuer) LogValue() slog.Value { panic("dummy-panic") }

func TestReplaceAttrRecoversPanics(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.Any("value", panickingValuer{}))
	if strings.Contains(line, "dummy-") || record["value"] == nil {
		t.Fatalf("panic was not replaced by a safe value: %s", line)
	}
}

type credentials struct{}

func (credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", "alice"), slog.String("password", "dummy-password"))
}

func TestReplaceAttrMasksResolvedLogValuer(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.Any("creds", credentials{}))
	if strings.Contains(line, "dummy-password") {
		t.Fatalf("a LogValue result bypassed masking: %s", line)
	}
	creds, ok := record["creds"].(map[string]any)
	if !ok || creds["user"] != "alice" || creds["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("creds: %#v", record["creds"])
	}
}

func TestReplaceAttrMasksLoggerContext(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr(newCore(t))}))
	logger.With("password", "dummy-password").WithGroup("req").With("token", "dummy-token").Info("request handled", "user", "alice")
	line := buffer.String()
	if strings.Contains(line, "dummy-") {
		t.Fatalf("an attribute added through With bypassed masking: %s", line)
	}
	record := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	req, ok := record["req"].(map[string]any)
	if !ok || req["token"] != masker.DefaultRedactionMarker || req["user"] != "alice" || record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("record: %s", line)
	}
}

type userRecord struct{ Name string }

type attemptCount int

func TestReplaceAttrBuiltinKeysNilsAndNamedTypes(t *testing.T) {
	line, record := logRecord(t, newCore(t),
		slog.Any("msg", map[string]any{"password": "dummy-password"}),
		slog.Any("level", "dummy-level"),
		slog.Any("user", (*userRecord)(nil)),
		slog.Any("count", attemptCount(3)),
	)
	if strings.Contains(line, "dummy-password") {
		t.Fatalf("attribute reusing a built-in key bypassed masking: %s", line)
	}
	if !strings.Contains(line, `"level":"INFO"`) {
		t.Fatalf("built-in level lost to a caller attribute: %s", line)
	}
	if user, present := record["user"]; !present || user != nil {
		t.Fatalf("typed nil attribute was not logged as null: %s", line)
	}
	if record["count"] != float64(3) {
		t.Fatalf("named integer lost its type: %#v", record["count"])
	}

	numbers := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Kind == masker.KindNumber {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	_, record = logRecord(t, newCore(t, numbers), slog.Int("n", 42), slog.Any("m", attemptCount(7)), slog.String("s", "text"))
	if record["n"] != masker.DefaultRedactionMarker || record["m"] != masker.DefaultRedactionMarker || record["s"] != "text" {
		t.Fatalf("policy did not see the value kind: %#v", record)
	}
}

func TestReplaceAttrMasksRawJSON(t *testing.T) {
	nested := json.RawMessage(`{"token":"dummy-token"}`)
	line, record := logRecord(t, newCore(t),
		slog.Any("body", json.RawMessage(`{"password":"dummy-password","n":1}`)),
		slog.Any("nested", map[string]any{"doc": &nested}),
		slog.Any("null", json.RawMessage(`null`)),
		slog.Any("empty", json.RawMessage(nil)),
		slog.Any("broken", json.RawMessage(`{"password":`)),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("embedded JSON bypassed masking: %s", line)
	}
	if !strings.Contains(line, `"body":{"n":1,"password":"[REDACTED]"}`) ||
		!strings.Contains(line, `"nested":{"doc":{"token":"[REDACTED]"}}`) {
		t.Fatalf("embedded JSON was not logged as masked JSON: %s", line)
	}
	for _, key := range []string{"null", "empty"} {
		if value, present := record[key]; !present || value != nil {
			t.Fatalf("null document %q was not logged as null: %s", key, line)
		}
	}
	if record["broken"] != masker.DefaultRedactionMarker {
		t.Fatalf("invalid embedded JSON did not fail closed: %s", line)
	}
}

type leakyCount int

func (leakyCount) MarshalJSON() ([]byte, error) { return []byte(`"dummy-leak"`), nil }

func (leakyCount) String() string { return "dummy-leak" }

type leakyHolder struct{ Count leakyCount }

func TestReplaceAttrNumbersPointersAndOmit(t *testing.T) {
	numbers := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Kind == masker.KindNumber {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	_, record := logRecord(t, newCore(t, numbers), slog.Any("n", json.Number("123")))
	if record["n"] != masker.DefaultRedactionMarker {
		t.Fatalf("json.Number bypassed a numeric policy: %#v", record["n"])
	}
	line, _ := logRecord(t, newCore(t), slog.Any("n", json.Number("123")))
	if !strings.Contains(line, `"n":123`) {
		t.Fatalf("json.Number was not logged as a number: %s", line)
	}

	preserving, err := masker.New(masker.DefaultPolicy(), masker.WithPreserveSafeTypes())
	if err != nil {
		t.Fatal(err)
	}
	line, record = logRecord(t, preserving,
		slog.Any("holder", leakyHolder{Count: 5}),
		slog.Any("list", []any{leakyCount(6)}),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("a preserved scalar ran its method in the handler: %s", line)
	}
	if holder, ok := record["holder"].(map[string]any); !ok || holder["Count"] != float64(5) {
		t.Fatalf("holder: %#v", record["holder"])
	}

	var missing *userRecord
	line, record = logRecord(t, newCore(t), slog.Any("user", &missing))
	if user, present := record["user"]; !present || user != nil {
		t.Fatalf("nil at the end of a pointer chain was not logged as null: %s", line)
	}

	var deep any = (*userRecord)(nil)
	for range 100 {
		next := deep
		deep = &next
	}
	line, record = logRecord(t, newCore(t), slog.Any("deep", deep))
	if value, present := record["deep"]; !present || value != nil {
		t.Fatalf("nil at the end of a long pointer chain was not logged as null: %s", line)
	}

	omit := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "drop" || field.Key == "dropSlice" {
			return masker.Decision{Omit: true}, nil
		}
		return masker.Decision{}, nil
	})
	line, record = logRecord(t, newCore(t, omit), slog.Any("drop", map[string]int(nil)), slog.Any("dropSlice", []int(nil)))
	if _, present := record["drop"]; present {
		t.Fatalf("an omitted nil map was logged: %s", line)
	}
	if _, present := record["dropSlice"]; present {
		t.Fatalf("an omitted nil slice was logged: %s", line)
	}
}

func TestReplaceAttrNilSourceAndZeroAttr(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.Any(slog.SourceKey, (*slog.Source)(nil)))
	if _, present := record[slog.SourceKey]; !present {
		t.Fatalf("nil source attribute was dropped: %s", line)
	}
	line, record = logRecord(t, nil, slog.Attr{}, slog.String("name", "alice"))
	if _, present := record[""]; present {
		t.Fatalf("zero attribute became a redacted field: %s", line)
	}
	if record["name"] != masker.DefaultRedactionMarker {
		t.Fatalf("nil core leaked a value: %s", line)
	}
}

type namedDuration time.Duration

func TestReplaceAttrDurationIsNumeric(t *testing.T) {
	numbers := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Kind == masker.KindNumber {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	_, record := logRecord(t, newCore(t, numbers),
		slog.Duration("elapsed", time.Second), slog.Any("named", namedDuration(time.Second)))
	if record["elapsed"] != masker.DefaultRedactionMarker || record["named"] != masker.DefaultRedactionMarker {
		t.Fatalf("a numeric policy missed a duration: %#v", record)
	}
	_, record = logRecord(t, newCore(t), slog.Duration("elapsed", time.Second))
	if record["elapsed"] != float64(time.Second) {
		t.Fatalf("an unmasked duration changed: %#v", record["elapsed"])
	}
}

func TestReplaceAttrMarkerEqualToText(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy(), masker.WithRedaction("1000000000"))
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr(core)}))
	logger.Info("request handled", slog.Duration("password", time.Second))
	if !strings.Contains(buffer.String(), "password=1000000000") {
		t.Fatalf("a marker equal to the duration text lost to the original value: %s", buffer.String())
	}
}

func TestReplaceAttrTypedNilUnderEmptyKey(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.Any("", (*userRecord)(nil)))
	if value, present := record[""]; !present || value != nil {
		t.Fatalf("a typed nil under an empty key was dropped: %s", line)
	}
}

func TestReplaceAttrLogsUntypedNilAsNull(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.Any("user", nil), slog.Any("password", nil))
	if value, present := record["user"]; !present || value != nil {
		t.Fatalf("user: want null, got %s", line)
	}
	if record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("password: want the marker, got %s", line)
	}
}

func TestReplaceAttrMasksEmbeddedURL(t *testing.T) {
	line, record := logRecord(t, newCore(t), slog.String("url", "https://u:dummy@h/cb?token=dummy-token"))
	if strings.Contains(line, "dummy") {
		t.Fatalf("the URL secrets reached the log: %s", line)
	}
	if record["url"] != "https://%5BREDACTED%5D@h/cb?token=%5BREDACTED%5D" {
		t.Fatalf("url: %#v", record["url"])
	}
}

// TestReplaceAttrInspectsByteSlices checks that a byte slice holding a secret
// as text is not logged as its reversible base64 form.
func TestReplaceAttrInspectsByteSlices(t *testing.T) {
	core := newCore(t)
	line, record := logRecord(t, core,
		slog.Any("body", []byte("password=dummy-password")),
		slog.Any("raw", []byte("hi")),
	)
	if strings.Contains(line, "cGFzc3dvcmQ9ZHVtbXktcGFzc3dvcmQ=") {
		t.Fatalf("a secret reached the log as base64: %s", line)
	}
	if record["body"] != masker.DefaultRedactionMarker {
		t.Fatalf("body: %#v", record["body"])
	}
	if record["raw"] != "aGk=" {
		t.Fatalf("raw: %#v", record["raw"])
	}
}
