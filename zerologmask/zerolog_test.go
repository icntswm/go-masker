package zerologmask

import (
	"bytes"
	"io"
	"testing"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/zapmask"
)

// The inputs below are lines the real logger wrote, captured with zerolog
// v1.35.1, so the package can check them without importing the logger.
// Recapture them when the logger changes its output format.

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

func maskLines(t *testing.T, core *masker.Masker, lines ...string) string {
	t.Helper()
	var buffer bytes.Buffer
	w := NewWriter(&buffer, core)
	for _, line := range lines {
		write(t, w, line+"\n")
	}
	return buffer.String()
}

func TestZerologLines(t *testing.T) {
	core := newCore(t)
	// logger.With().Str("session_id", …).Logger().Info().Str("user", "alice").Str("password", …).Msg("login")
	got := maskLines(t, core, `{"level":"info","session_id":"dummy-session","user":"alice","password":"dummy-password","message":"login"}`)
	want := `{"level":"info","message":"login","password":"[REDACTED]","session_id":"[REDACTED]","user":"alice"}` + "\n"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	// Interface, Dict, RawJSON and Err on one event.
	got = maskLines(t, core, `{"level":"info","session_id":"dummy-session","creds":{"token":"dummy-t"},"req":{"authorization":"Bearer dummy"},"body":{"api_key":"dummy-k"},"error":"boom","message":"nested"}`)
	want = `{"body":{"api_key":"[REDACTED]"},"creds":{"token":"[REDACTED]"},"error":"boom","level":"info","message":"nested","req":{"authorization":"[REDACTED]"},"session_id":"[REDACTED]"}` + "\n"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// TestReadmeZerologOutput pins the line shown in the README's zerolog
// section.
func TestReadmeZerologOutput(t *testing.T) {
	got := maskLines(t, newCore(t), `{"level":"info","user":"alice","password":"hunter2","message":"login"}`)
	want := `{"level":"info","message":"login","password":"[REDACTED]","user":"alice"}` + "\n"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

// TestZerologLeavesDiagnosticSuffixesAlone checks that zerolog, which writes
// no diagnostic keys, keeps a key such as tokenError as any other key: the
// zap suffix rule does not apply here, while zapmask decides the same key as
// its base.
func TestZerologLeavesDiagnosticSuffixesAlone(t *testing.T) {
	in := `{"level":"info","tokenError":"dummy-value","message":"x"}`
	got := maskLines(t, newCore(t), in)
	want := `{"level":"info","message":"x","tokenError":"dummy-value"}` + "\n"
	if got != want {
		t.Fatalf("zerolog: got %s, want %s", got, want)
	}
	var zapBuffer bytes.Buffer
	zapWriter := zapmask.NewWriteSyncer(&zapBuffer, newCore(t))
	write(t, zapWriter, in+"\n")
	zapGot := zapBuffer.String()
	zapWant := `{"level":"info","message":"x","tokenError":"[REDACTED]"}` + "\n"
	if zapGot != zapWant {
		t.Fatalf("zap: got %s, want %s", zapGot, zapWant)
	}
}
