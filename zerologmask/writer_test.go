package zerologmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	masker "github.com/icntswm/go-masker"
)

func newCore(t *testing.T, opts ...masker.Option) *masker.Masker {
	t.Helper()
	core, err := masker.New(masker.DefaultPolicy(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func write(t *testing.T, w io.Writer, line string) {
	t.Helper()
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("invalid log line %q: %v", line, err)
	}
	return decoded
}

type countingWriter struct {
	writes int
	buffer bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buffer.Write(p)
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestWriterMasksKeys(t *testing.T) {
	var buffer bytes.Buffer
	w := NewWriter(&buffer, newCore(t))
	line := `{"level":"info","password":"dummy-password","token":"dummy-token","user":"alice","message":"login"}` + "\n"
	if n, err := w.Write([]byte(line)); err != nil || n != len(line) {
		t.Fatalf("Write: %d, %v", n, err)
	}
	// Keys come out in the order MaskJSON emits them, sorted; the writer
	// drops no key and adds no key.
	want := `{"level":"info","message":"login","password":"[REDACTED]","token":"[REDACTED]","user":"alice"}` + "\n"
	if buffer.String() != want {
		t.Fatalf("masked line: got %s, want %s", buffer.String(), want)
	}
	if !strings.HasSuffix(buffer.String(), "\n") {
		t.Fatalf("line lost its newline: %s", buffer.String())
	}
}

func TestWriterMasksNestedValues(t *testing.T) {
	var buffer bytes.Buffer
	w := NewWriter(&buffer, newCore(t))
	write(t, w, `{"level":"info","user":{"token":"dummy-token","name":"alice"},"list":[{"secret":"dummy-secret"}]}`+"\n")
	record := decodeLine(t, buffer.String())
	user, ok := record["user"].(map[string]any)
	if !ok || user["token"] != masker.DefaultRedactionMarker || user["name"] != "alice" {
		t.Fatalf("user: %#v", record["user"])
	}
	list, ok := record["list"].([]any)
	if !ok || list[0].(map[string]any)["secret"] != masker.DefaultRedactionMarker {
		t.Fatalf("list: %#v", record["list"])
	}
	if strings.Contains(buffer.String(), "dummy-") {
		t.Fatalf("original secret reached the log: %s", buffer.String())
	}
}

func TestWriterMasksLinesInOneWrite(t *testing.T) {
	counting := &countingWriter{}
	w := NewWriter(counting, newCore(t))
	write(t, w, `{"level":"info","password":"dummy-one"}`+"\n"+`{"level":"info","password":"dummy-two"}`+"\n")
	lines := strings.Split(strings.TrimSuffix(counting.buffer.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count: %d", len(lines))
	}
	for i, line := range lines {
		if record := decodeLine(t, line); record["password"] != masker.DefaultRedactionMarker {
			t.Fatalf("line %d: %#v", i, record["password"])
		}
	}
	if counting.writes != 1 {
		t.Fatalf("underlying writes: %d", counting.writes)
	}
}

func TestWriterReplacesUnmaskableLines(t *testing.T) {
	limited := newCore(t, masker.WithMaxInputBytes(64))
	tests := []struct {
		name string
		core *masker.Masker
		line string
	}{
		{"malformed json", newCore(t), `{"password":`},
		{"invalid utf-8", newCore(t), "{\"password\":\"\xff\xfe\"}"},
		{"over the input limit", limited, `{"level":"info","password":"` + strings.Repeat("a", 80) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			write(t, NewWriter(&buffer, test.core), test.line+"\n")
			if buffer.String() != `{"message":"[REDACTED]"}`+"\n" {
				t.Fatalf("unmaskable line was not replaced: %q", buffer.String())
			}
			if strings.Contains(buffer.String(), "dummy-") || strings.Contains(buffer.String(), "aaaa") {
				t.Fatalf("original line reached the log: %s", buffer.String())
			}
		})
	}
}

func TestWriterCustomMarker(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy(), masker.WithRedaction("***"))
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	w := NewWriter(&buffer, core)
	write(t, w, `{"level":"info","password":"dummy-password"}`+"\n")
	if !strings.Contains(buffer.String(), `"password":"***"`) {
		t.Fatalf("masked value did not use the marker: %s", buffer.String())
	}
	write(t, w, "not json\n")
	if !strings.Contains(buffer.String(), `{"message":"***"}`) {
		t.Fatalf("fallback line did not use the marker: %s", buffer.String())
	}
}

func TestWriterNilCoreRedactsEverything(t *testing.T) {
	var buffer bytes.Buffer
	w := NewWriter(&buffer, nil)
	write(t, w, `{"level":"info","user":"alice"}`+"\n")
	if buffer.String() != `{"message":"[REDACTED]"}`+"\n" {
		t.Fatalf("nil core leaked values: %s", buffer.String())
	}
}

func TestWriterNilDestination(t *testing.T) {
	w := NewWriter(nil, newCore(t))
	n, err := w.Write([]byte(`{"level":"info"}` + "\n"))
	if err == nil || n != 0 {
		t.Fatalf("Write to a nil destination: %d, %v", n, err)
	}
}

func TestWriterPassesLinesThrough(t *testing.T) {
	counting := &countingWriter{}
	w := NewWriter(counting, newCore(t))
	if n, err := w.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty Write: %d, %v", n, err)
	}
	if counting.writes != 0 {
		t.Fatalf("empty Write reached the destination: %d", counting.writes)
	}
	write(t, w, "   \t\r\n")
	write(t, w, `{"b":1,"password":"dummy-secret","a":2}`)
	if !strings.HasPrefix(counting.buffer.String(), "   \t\r\n") {
		t.Fatalf("blank line changed: %q", counting.buffer.String())
	}
	if !strings.HasSuffix(counting.buffer.String(), `{"a":2,"b":1,"password":"[REDACTED]"}`) {
		t.Fatalf("line without a newline changed shape: %q", counting.buffer.String())
	}
	if strings.HasSuffix(counting.buffer.String(), "\n") {
		t.Fatalf("a trailing newline was added: %q", counting.buffer.String())
	}
	if strings.Contains(counting.buffer.String(), "dummy-") {
		t.Fatalf("original secret reached the log: %s", counting.buffer.String())
	}
}

func TestWriterRecoversPanics(t *testing.T) {
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
	var buffer bytes.Buffer
	write(t, NewWriter(&buffer, core), `{"level":"info","password":"dummy-secret"}`+"\n")
	if buffer.String() != `{"message":"[REDACTED]"}`+"\n" {
		t.Fatalf("panic was not replaced by the fallback line: %s", buffer.String())
	}
}

func TestWriterDestinationErrors(t *testing.T) {
	boom := errors.New("dummy-error")
	w := NewWriter(errorWriter{err: boom}, newCore(t))
	if n, err := w.Write([]byte(`{"level":"info"}` + "\n")); n != 0 || !errors.Is(err, boom) {
		t.Fatalf("destination error: %d, %v", n, err)
	}
	w = NewWriter(shortWriter{}, newCore(t))
	if n, err := w.Write([]byte(`{"level":"info"}` + "\n")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %d, %v", n, err)
	}
}

func TestWriterConcurrentWrites(t *testing.T) {
	var mu sync.Mutex
	var buffer bytes.Buffer
	w := NewWriter(lockedBuffer{mu: &mu, buffer: &buffer}, newCore(t))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				line := fmt.Sprintf(`{"level":"info","password":"dummy-%d-%d","goroutine":%d}`, g, i, g) + "\n"
				if _, err := w.Write([]byte(line)); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n")
	if len(lines) != 400 {
		t.Fatalf("line count: %d", len(lines))
	}
	for _, line := range lines {
		decodeLine(t, line)
		if strings.Contains(line, "dummy-") {
			t.Fatalf("secret reached the log: %s", line)
		}
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

func TestWriterSlogCompatibility(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(NewWriter(&buffer, newCore(t)), nil))
	logger.Info("login", "user", "alice", "password", "hunter2")
	record := decodeLine(t, buffer.String())
	if record["msg"] != "login" || record["user"] != "alice" {
		t.Fatalf("safe fields changed: %#v", record)
	}
	if strings.Contains(buffer.String(), "hunter2") {
		t.Fatalf("secret reached the log: %s", buffer.String())
	}
}
