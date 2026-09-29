package zapmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	masker "github.com/icntswm/go-masker"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newMasker(t *testing.T, policies ...masker.Policy) *masker.Masker {
	t.Helper()
	policies = append(policies, masker.DefaultPolicy())
	core, err := masker.New(masker.Chain(policies...))
	if err != nil {
		t.Fatal(err)
	}
	return core
}

// jsonCore is the inner core the logger tests are built on.
func jsonCore(buffer *bytes.Buffer) zapcore.Core {
	return zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(buffer), zapcore.DebugLevel)
}

// logFields writes one record through a JSON core wired to NewCore and
// returns the raw line and its decoded form.
func logFields(t *testing.T, core *masker.Masker, fields ...zapcore.Field) (string, map[string]any) {
	t.Helper()
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), core))
	logger.Info("request handled", fields...)
	decoded := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid log line %q: %v", buffer.String(), err)
	}
	return buffer.String(), decoded
}

func TestCoreMasksScalarFields(t *testing.T) {
	core := newMasker(t)
	wantEmail, err := core.MaskValue("email", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	line, record := logFields(t, core,
		zap.String("password", "dummy-password"),
		zap.String("user", "alice"),
		zap.Int("port", 8080),
		zap.Bool("ok", true),
		zap.Duration("elapsed", time.Second),
		zap.Time("when", time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.UTC)),
		zap.Float64("ratio", 0.5),
		zap.Uint8("small", 7),
		zap.ByteString("token", []byte("dummy-bytes")),
		zap.Binary("secret", []byte("dummy-secret")),
		zap.String("email", "alice@example.com"),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original secret reached the log: %s", line)
	}
	if record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("password: %#v", record["password"])
	}
	if record["user"] != "alice" {
		t.Fatalf("user: %#v", record["user"])
	}
	if record["port"] != float64(8080) || record["small"] != float64(7) {
		t.Fatalf("safe integers lost their type: port=%#v small=%#v", record["port"], record["small"])
	}
	if record["ok"] != true {
		t.Fatalf("ok: %#v", record["ok"])
	}
	// The production encoder writes a duration in seconds.
	if record["elapsed"] != float64(1) {
		t.Fatalf("elapsed: %#v", record["elapsed"])
	}
	// and a time as epoch seconds.
	if record["when"] != float64(time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.UTC).UnixNano())/1e9 {
		t.Fatalf("when: %#v", record["when"])
	}
	if record["ratio"] != float64(0.5) {
		t.Fatalf("ratio: %#v", record["ratio"])
	}
	if record["token"] != masker.DefaultRedactionMarker || record["secret"] != masker.DefaultRedactionMarker {
		t.Fatalf("token: %#v secret: %#v", record["token"], record["secret"])
	}
	if record["email"] != wantEmail {
		t.Fatalf("email: got %#v, want %#v", record["email"], wantEmail)
	}
}

func TestCoreMasksContextAndCallSite(t *testing.T) {
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), newMasker(t)))
	child := logger.With(zap.String("api_key", "dummy-key"))
	child.Info("request handled", zap.String("password", "dummy-pass"), zap.String("user", "alice"))
	line := buffer.String()
	if strings.Contains(line, "dummy-") {
		t.Fatalf("a context field bypassed masking: %s", line)
	}
	record := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["api_key"] != masker.DefaultRedactionMarker || record["password"] != masker.DefaultRedactionMarker || record["user"] != "alice" {
		t.Fatalf("record: %s", line)
	}
	if record["msg"] != "request handled" {
		t.Fatalf("message changed: %s", line)
	}
}

func TestCoreMasksNamespacePath(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	recorder := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		mu.Lock()
		paths = append(paths, field.Path)
		mu.Unlock()
		return masker.Decision{}, nil
	})
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), newMasker(t, recorder)))
	logger.With(zap.Namespace("req")).Info("request handled", zap.String("authorization", "Bearer dummy"), zap.String("user", "alice"))
	line := buffer.String()
	if strings.Contains(line, "dummy-") {
		t.Fatalf("a namespaced field bypassed masking: %s", line)
	}
	record := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	req, ok := record["req"].(map[string]any)
	if !ok || req["authorization"] != masker.DefaultRedactionMarker || req["user"] != "alice" {
		t.Fatalf("req: %s", line)
	}
	if !slices.Contains(paths, "$[req]") || !slices.Contains(paths, "$[req][authorization]") {
		t.Fatalf("unexpected policy paths: %q", paths)
	}
}

type nullableInline struct{}

func (nullableInline) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return enc.AddReflected("optional", (*string)(nil))
}

func TestCoreKeepsNulls(t *testing.T) {
	line, record := logFields(t, newMasker(t), zap.Any("empty", nil), zap.Reflect("pointer", (*string)(nil)), zap.Inline(nullableInline{}))
	for _, key := range []string{"empty", "pointer", "optional"} {
		if value, present := record[key]; !present || value != nil {
			t.Fatalf("%s: want null, got %s", key, line)
		}
	}
}

func TestCoreMasksSensitiveNamespaces(t *testing.T) {
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "internal" {
			return masker.Decision{Omit: true}, nil
		}
		return masker.Decision{}, nil
	})
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), newMasker(t, policy)))
	logger.With(zap.Namespace("req")).Info("request handled",
		zap.String("user", "alice"),
		zap.Namespace("credentials"),
		zap.String("login", "dummy-login"),
		zap.Namespace("nested"),
		zap.String("value", "dummy-nested"),
	)
	logger.With(zap.Namespace("token"), zap.String("kind", "dummy-kind")).Info("context", zap.String("id", "dummy-id"))
	logger.With(zap.Namespace("internal")).Info("omitted", zap.String("note", "dummy-note"))
	if strings.Contains(buffer.String(), "dummy-") {
		t.Fatalf("a field inside a sensitive namespace was logged: %s", buffer.String())
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %q", lines)
	}
	records := make([]map[string]any, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &records[i]); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := records[0]["req"].(map[string]any)
	credentials, _ := req["credentials"].(map[string]any)
	nested, _ := credentials["nested"].(map[string]any)
	if req["user"] != "alice" || credentials["login"] != masker.DefaultRedactionMarker || nested["value"] != masker.DefaultRedactionMarker {
		t.Fatalf("credentials namespace: %s", lines[0])
	}
	token, _ := records[1]["token"].(map[string]any)
	if token["kind"] != masker.DefaultRedactionMarker || token["id"] != masker.DefaultRedactionMarker {
		t.Fatalf("token namespace from With: %s", lines[1])
	}
	if internal, _ := records[2]["internal"].(map[string]any); len(internal) != 0 {
		t.Fatalf("omitted namespace kept its fields: %s", lines[2])
	}
}

func TestCoreMasksReflectedMap(t *testing.T) {
	_, record := logFields(t, newMasker(t), zap.Any("creds", map[string]any{"token": "dummy-t", "user": "alice"}))
	creds, ok := record["creds"].(map[string]any)
	if !ok || creds["token"] != masker.DefaultRedactionMarker || creds["user"] != "alice" {
		t.Fatalf("creds: %#v", record["creds"])
	}
}

type taggedEvent struct {
	User     string
	Stripe   string `mask:"token"`
	Password string
	Omitted  string `mask:"omit"`
}

func TestCoreMasksStructTags(t *testing.T) {
	line, record := logFields(t, newMasker(t), zap.Any("event", taggedEvent{
		User: "alice", Stripe: "dummy-stripe", Password: "dummy-password", Omitted: "dummy-omitted",
	}))
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original value reached the log: %s", line)
	}
	event, ok := record["event"].(map[string]any)
	if !ok {
		t.Fatalf("event: %#v", record["event"])
	}
	if event["User"] != "alice" {
		t.Fatalf("User: %#v", event["User"])
	}
	if event["Stripe"] != masker.DefaultRedactionMarker || event["Password"] != masker.DefaultRedactionMarker {
		t.Fatalf("tagged fields: %#v", event)
	}
	if _, present := event["Omitted"]; present {
		t.Fatalf("omitted field was logged: %s", line)
	}
}

type session struct{}

func (session) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("user", "alice")
	enc.AddString("password", "dummy-password")
	return nil
}

func TestCoreMasksMarshalers(t *testing.T) {
	line, record := logFields(t, newMasker(t),
		zap.Object("session", session{}),
		zap.Dict("req", zap.String("token", "dummy-t"), zap.String("user", "alice")),
		zap.Strings("credentials", []string{"dummy-a", "dummy-b"}),
		zap.Array("secret", zapcore.ArrayMarshalerFunc(func(enc zapcore.ArrayEncoder) error {
			enc.AppendString("dummy-c")
			return nil
		})),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("a marshaler bypassed masking: %s", line)
	}
	if sess, ok := record["session"].(map[string]any); !ok || sess["user"] != "alice" || sess["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("session: %#v", record["session"])
	}
	if req, ok := record["req"].(map[string]any); !ok || req["token"] != masker.DefaultRedactionMarker || req["user"] != "alice" {
		t.Fatalf("req: %#v", record["req"])
	}
	// A container under a sensitive key is replaced as a whole.
	if record["credentials"] != masker.DefaultRedactionMarker || record["secret"] != masker.DefaultRedactionMarker {
		t.Fatalf("sensitive arrays: credentials=%#v secret=%#v", record["credentials"], record["secret"])
	}
}

type inlineCredentials struct{}

func (inlineCredentials) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("password", "dummy-password")
	enc.AddString("user", "alice")
	return nil
}

func TestCoreMasksInlineMarshaler(t *testing.T) {
	line, record := logFields(t, newMasker(t), zap.Inline(inlineCredentials{}))
	if strings.Contains(line, "dummy-") {
		t.Fatalf("an inline marshaler bypassed masking: %s", line)
	}
	if record["password"] != masker.DefaultRedactionMarker || record["user"] != "alice" {
		t.Fatalf("inline members were not flattened into the record: %s", line)
	}
}

// verboseError renders extra detail through %+v, the way wrapped errors do,
// so zap would log an errorVerbose key beside the message.
type verboseError struct{ message string }

func (e verboseError) Error() string { return e.message }

func (e verboseError) Format(s fmt.State, verb rune) {
	if verb == 'v' {
		_, _ = fmt.Fprint(s, e.message+"\nverbose dummy detail")
		return
	}
	_, _ = fmt.Fprint(s, e.message)
}

func TestCoreLogsErrorTextWithoutVerbose(t *testing.T) {
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "masked" {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	line, record := logFields(t, newMasker(t, policy),
		zap.Error(errors.New("dummy failure")),
		zap.NamedError("wrapped", verboseError{message: "dummy wrapped"}),
		zap.NamedError("masked", errors.New("dummy-erred")),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original error text reached the log: %s", line)
	}
	if record["error"] != "dummy failure" || record["wrapped"] != "dummy wrapped" {
		t.Fatalf("errors were not logged as their text: %#v", record)
	}
	if _, present := record["errorVerbose"]; present {
		t.Fatalf("errorVerbose was logged: %s", line)
	}
	if _, present := record["wrappedVerbose"]; present {
		t.Fatalf("wrappedVerbose was logged: %s", line)
	}
	if record["masked"] != masker.DefaultRedactionMarker {
		t.Fatalf("masked error: %#v", record["masked"])
	}
}

type secretStringer struct{}

func (secretStringer) String() string { return "dummy-secret" }

func TestCoreMasksStringer(t *testing.T) {
	_, record := logFields(t, newMasker(t), zap.Stringer("password", secretStringer{}))
	if record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("password: %#v", record["password"])
	}
}

func TestCoreOmitsAndFailsClosed(t *testing.T) {
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
	line, record := logFields(t, newMasker(t, policy), zap.String("drop", "dummy-dropped"), zap.String("note", "dummy-note"))
	if _, present := record["drop"]; present {
		t.Fatalf("omitted field was logged: %s", line)
	}
	if record["note"] != masker.DefaultRedactionMarker {
		t.Fatalf("failing rule did not produce the marker: %#v", record["note"])
	}
	if strings.Contains(line, "dummy-") {
		t.Fatalf("original value reached the log: %s", line)
	}
}

func TestCoreNilMaskerRedactsEverything(t *testing.T) {
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), nil))
	logger.Info("request handled", zap.String("name", "alice"), zap.Int("count", 3))
	record := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["name"] != masker.DefaultRedactionMarker || record["count"] != masker.DefaultRedactionMarker {
		t.Fatalf("nil masker leaked values: %s", buffer.String())
	}
	if record["msg"] != "request handled" {
		t.Fatalf("message changed: %#v", record["msg"])
	}
}

func TestCoreCustomMarker(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy(), masker.WithRedaction("***"))
	if err != nil {
		t.Fatal(err)
	}
	_, record := logFields(t, core, zap.String("password", "dummy-password"))
	if record["password"] != "***" {
		t.Fatalf("masked value did not use the marker: %#v", record["password"])
	}
}

func TestCoreRecoversRulePanics(t *testing.T) {
	boomer, err := masker.NewRule("boomer", func(masker.RuleInput) (string, error) {
		panic("dummy-panic")
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "password" {
			return masker.Decision{Rule: boomer}, nil
		}
		return masker.Decision{}, nil
	})
	// The panicking policy comes first, so the boomer rule wins the chain
	// over the default password binding.
	core, err := masker.New(masker.Chain(policy, masker.DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	line, record := logFields(t, core, zap.String("password", "dummy-secret"), zap.String("user", "alice"))
	if record["password"] != masker.DefaultRedactionMarker || record["user"] != "alice" {
		t.Fatalf("a panicking rule broke the record: %s", line)
	}
}

type panickingObject struct{}

func (panickingObject) MarshalLogObject(zapcore.ObjectEncoder) error { panic("dummy-panic") }

type panickingStringer struct{}

func (panickingStringer) String() string { panic("dummy-panic") }

func TestCoreRecoversMarshalerPanics(t *testing.T) {
	line, record := logFields(t, newMasker(t),
		zap.Object("session", panickingObject{}),
		zap.Stringer("password", panickingStringer{}),
		zap.String("user", "alice"),
	)
	if strings.Contains(line, "dummy-") {
		t.Fatalf("panic output reached the log: %s", line)
	}
	if record["session"] != masker.DefaultRedactionMarker || record["password"] != masker.DefaultRedactionMarker || record["user"] != "alice" {
		t.Fatalf("a panicking field broke the record: %s", line)
	}
}

func TestCoreKeepsSampling(t *testing.T) {
	var buffer bytes.Buffer
	inner := zapcore.NewSamplerWithOptions(jsonCore(&buffer), time.Second, 1, 0)
	logger := zap.New(NewCore(inner, newMasker(t)))
	for range 5 {
		logger.Info("same message", zap.String("password", "dummy-pass"))
	}
	if lines := strings.Count(buffer.String(), "\n"); lines != 1 {
		t.Fatalf("sampler did not drop repeats: %d lines", lines)
	}
}

func TestCoreKeepsTeeLevels(t *testing.T) {
	var infoBuffer, errorBuffer bytes.Buffer
	infoCore := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&infoBuffer), zapcore.InfoLevel)
	errorCore := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&errorBuffer), zapcore.ErrorLevel)
	logger := zap.New(NewCore(zapcore.NewTee(infoCore, errorCore), newMasker(t)))
	logger.Info("login", zap.String("password", "dummy-pass"))
	if lines := strings.Count(infoBuffer.String(), "\n"); lines != 1 {
		t.Fatalf("info branch did not receive the entry: %d lines", lines)
	}
	if lines := strings.Count(errorBuffer.String(), "\n"); lines != 0 {
		t.Fatalf("error branch received an info entry: %d lines", lines)
	}
}

func TestCoreKeepsSamplingAndMaskingThroughWrapCore(t *testing.T) {
	var buffer bytes.Buffer
	inner := zapcore.NewSamplerWithOptions(jsonCore(&buffer), time.Second, 1, 0)
	logger := zap.New(inner, zap.WrapCore(func(c zapcore.Core) zapcore.Core {
		return NewCore(c, newMasker(t))
	}))
	for range 5 {
		logger.Info("same message", zap.String("password", "dummy-pass"))
	}
	if lines := strings.Count(buffer.String(), "\n"); lines != 1 {
		t.Fatalf("sampler did not drop repeats: %d lines", lines)
	}
	if !strings.Contains(buffer.String(), masker.DefaultRedactionMarker) {
		t.Fatalf("the sampled line was not masked: %s", buffer.String())
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCoreWriteReturnsWriteError(t *testing.T) {
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(errorWriter{err: errors.New("dummy-error")}), zapcore.DebugLevel)
	c := NewCore(inner, newMasker(t))
	entry := zapcore.Entry{Time: time.Now(), Level: zapcore.InfoLevel, Message: "login"}
	if err := c.Write(entry, []zapcore.Field{zap.String("user", "alice")}); err == nil {
		t.Fatal("write error was not returned")
	}
}

func TestCoreReportsWriteErrorToErrorOutput(t *testing.T) {
	var errBuffer bytes.Buffer
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(errorWriter{err: errors.New("dummy-error")}), zapcore.DebugLevel)
	logger := zap.New(NewCore(inner, newMasker(t)), zap.ErrorOutput(zapcore.AddSync(&errBuffer)))
	logger.Info("login", zap.String("user", "alice"))
	if !strings.Contains(errBuffer.String(), "dummy-error") {
		t.Fatalf("write error did not reach the error output: %q", errBuffer.String())
	}
}

func TestCoreWriteDoesNotModifyCallerFields(t *testing.T) {
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zapcore.DebugLevel)
	c := NewCore(inner, newMasker(t))
	fields := []zapcore.Field{zap.String("password", "dummy-pass"), zap.String("user", "alice")}
	want := append([]zapcore.Field(nil), fields...)
	entry := zapcore.Entry{Time: time.Now(), Level: zapcore.InfoLevel, Message: "login"}
	if err := c.Write(entry, fields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("caller fields were modified: %#v", fields)
	}
}

func TestCoreLevelDelegates(t *testing.T) {
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zapcore.WarnLevel)
	c := NewCore(inner, newMasker(t))
	if zapcore.LevelOf(c) != zapcore.WarnLevel {
		t.Fatalf("LevelOf: %v", zapcore.LevelOf(c))
	}
	m, ok := c.(*maskCore)
	if !ok {
		t.Fatal("NewCore did not return a maskCore")
	}
	if m.Level() != zapcore.WarnLevel {
		t.Fatalf("Level: %v", m.Level())
	}
	for _, level := range []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel, zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel} {
		if c.Enabled(level) != inner.Enabled(level) {
			t.Fatalf("Enabled(%v) did not delegate", level)
		}
	}
}

type syncWriter struct {
	bytes.Buffer
	synced int
}

func (w *syncWriter) Sync() error {
	w.synced++
	return nil
}

func TestCoreSyncForwards(t *testing.T) {
	dst := &syncWriter{}
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(dst), zapcore.DebugLevel)
	c := NewCore(inner, newMasker(t))
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if dst.synced != 1 {
		t.Fatalf("Sync calls: %d", dst.synced)
	}
}

func TestCoreConsoleEncoder(t *testing.T) {
	var buffer bytes.Buffer
	inner := zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buffer), zapcore.DebugLevel)
	logger := zap.New(NewCore(inner, newMasker(t)))
	logger.Info("login", zap.String("user", "alice"), zap.String("password", "dummy-pass"))
	if strings.Contains(buffer.String(), "dummy-pass") {
		t.Fatalf("secret reached the console output: %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), masker.DefaultRedactionMarker) {
		t.Fatalf("console output was not masked: %s", buffer.String())
	}
}

type lockedBuffer struct {
	mu     *sync.Mutex
	buffer *bytes.Buffer
}

func (w lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Write(p)
}

func TestCoreConcurrentEvents(t *testing.T) {
	var mu sync.Mutex
	var buffer bytes.Buffer
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(lockedBuffer{mu: &mu, buffer: &buffer}), zapcore.DebugLevel)
	logger := zap.New(NewCore(inner, newMasker(t)))
	child := logger.With(zap.String("api_key", "dummy-key"))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				logger.Info("login", zap.String("password", fmt.Sprintf("dummy-%d-%d", g, i)), zap.String("user", "alice"))
				child.Info("login", zap.String("password", fmt.Sprintf("dummy-%d-%d", g, i)), zap.String("user", "alice"))
			}
		}(g)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n")
	if len(lines) != 1600 {
		t.Fatalf("line count: %d", len(lines))
	}
	for _, line := range lines {
		record := map[string]any{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid log line %q: %v", line, err)
		}
		if strings.Contains(line, "dummy-") {
			t.Fatalf("secret reached the log: %s", line)
		}
	}
}

func TestCoreMasksSugaredLogger(t *testing.T) {
	var buffer bytes.Buffer
	logger := zap.New(NewCore(jsonCore(&buffer), newMasker(t)))
	logger.Sugar().Infow("login", "password", "dummy-p", "user", "alice")
	record := map[string]any{}
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["password"] != masker.DefaultRedactionMarker || record["user"] != "alice" || record["msg"] != "login" {
		t.Fatalf("sugared fields: %s", buffer.String())
	}
}
