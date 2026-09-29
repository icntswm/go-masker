package zerologcompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/zerologmask"
	"github.com/rs/zerolog"
)

func newCore(t *testing.T) *masker.Masker {
	t.Helper()
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func newLogger(t *testing.T, buffer *bytes.Buffer) zerolog.Logger {
	t.Helper()
	return zerolog.New(zerologmask.NewWriter(buffer, newCore(t)))
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("invalid log line %q: %v", line, err)
	}
	return decoded
}

func TestZerologMasksFields(t *testing.T) {
	var buffer bytes.Buffer
	logger := newLogger(t, &buffer)
	logger.Info().Str("password", "hunter2").Str("user", "alice").Msg("login")
	record := decodeLine(t, buffer.String())
	if record["password"] != masker.DefaultRedactionMarker {
		t.Fatalf("password: %#v", record["password"])
	}
	if record["user"] != "alice" || record["message"] != "login" || record["level"] != "info" {
		t.Fatalf("safe fields changed: %#v", record)
	}
}

func TestZerologMasksNestedAndRawValues(t *testing.T) {
	var buffer bytes.Buffer
	logger := newLogger(t, &buffer)
	logger.Info().
		Interface("creds", map[string]any{"token": "t-secret"}).
		Dict("req", zerolog.Dict().Str("authorization", "Bearer x")).
		RawJSON("body", []byte(`{"api_key":"k"}`)).
		Err(errors.New("boom")).
		Msg("login")
	line := buffer.String()
	for _, secret := range []string{"t-secret", "Bearer x", `"k"`} {
		if strings.Contains(line, secret) {
			t.Fatalf("secret reached the log: %s", line)
		}
	}
	record := decodeLine(t, line)
	if record["error"] != "boom" {
		t.Fatalf("error field changed: %#v", record["error"])
	}
	creds, ok := record["creds"].(map[string]any)
	if !ok || creds["token"] != masker.DefaultRedactionMarker {
		t.Fatalf("creds: %#v", record["creds"])
	}
	req, ok := record["req"].(map[string]any)
	if !ok || req["authorization"] != masker.DefaultRedactionMarker {
		t.Fatalf("req: %#v", record["req"])
	}
	body, ok := record["body"].(map[string]any)
	if !ok || body["api_key"] != masker.DefaultRedactionMarker {
		t.Fatalf("body: %#v", record["body"])
	}
}

func TestZerologMasksContextFields(t *testing.T) {
	var buffer bytes.Buffer
	logger := newLogger(t, &buffer).With().Str("session_id", "s-secret").Logger()
	logger.Info().Str("password", "hunter2").Msg("login")
	line := buffer.String()
	if strings.Contains(line, "secret") || strings.Contains(line, "hunter2") {
		t.Fatalf("secret reached the log: %s", line)
	}
	record := decodeLine(t, line)
	if record["session_id"] != masker.DefaultRedactionMarker {
		t.Fatalf("session_id: %#v", record["session_id"])
	}
	if record["message"] != "login" {
		t.Fatalf("message changed: %#v", record["message"])
	}
}

func TestZerologConsoleWriterBehindMasking(t *testing.T) {
	var buffer bytes.Buffer
	console := zerolog.ConsoleWriter{Out: &buffer, NoColor: true}
	logger := zerolog.New(zerologmask.NewWriter(console, newCore(t)))
	logger.Info().Str("password", "hunter2").Str("user", "alice").Msg("login")
	out := buffer.String()
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret reached the console: %s", out)
	}
	if !strings.Contains(out, "login") || !strings.Contains(out, masker.DefaultRedactionMarker) {
		t.Fatalf("console output lost the message or the marker: %s", out)
	}
}

func TestZerologConcurrentEvents(t *testing.T) {
	var mu sync.Mutex
	var buffer bytes.Buffer
	logger := zerolog.New(zerologmask.NewWriter(lockedBuffer{mu: &mu, buffer: &buffer}, newCore(t)))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				logger.Info().Str("password", "hunter2").Int("goroutine", g).Int("seq", i).Msg("login")
			}
		}(g)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n")
	if len(lines) != 1600 {
		t.Fatalf("event count: %d", len(lines))
	}
	for _, line := range lines {
		decodeLine(t, line)
		if strings.Contains(line, "hunter2") {
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
