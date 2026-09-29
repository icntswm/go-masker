package jsonlogmask

import (
	"bytes"
	"strings"
	"testing"

	masker "github.com/icntswm/go-masker"
)

// The inputs below are lines the real loggers wrote, captured with zap
// v1.27.0 (JSON encoder, production config without the timestamp) and zerolog
// v1.35.1, so the module can check them without importing either logger.
// Recapture them when a logger changes its output format.

func maskLines(t *testing.T, core *masker.Masker, lines ...string) string {
	t.Helper()
	var buffer bytes.Buffer
	w := NewWriter(&buffer, core)
	for _, line := range lines {
		write(t, w, line+"\n")
	}
	return buffer.String()
}

func TestZapLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// logger.With(zap.String("session_id", …)).Info("login", zap.String("user", "alice"), zap.String("password", …))
			name: "fields and context",
			in:   `{"level":"info","msg":"login","session_id":"dummy-session","user":"alice","password":"dummy-password"}`,
			want: `{"level":"info","msg":"login","password":"[REDACTED]","session_id":"[REDACTED]","user":"alice"}`,
		},
		{
			// zap.Namespace("credentials"), zap.String("value", …)
			name: "namespace",
			in:   `{"level":"info","msg":"ns","session_id":"dummy-session","credentials":{"value":"dummy-ns"}}`,
			want: `{"credentials":"[REDACTED]","level":"info","msg":"ns","session_id":"[REDACTED]"}`,
		},
		{
			// zap.Any("c", struct{ User, Password string }{…}), zap.Dict("d", zap.String("api_key", …))
			name: "any and dict",
			in:   `{"level":"info","msg":"any","session_id":"dummy-session","c":{"User":"alice","Password":"dummy-pw"},"d":{"api_key":"dummy-key"}}`,
			want: `{"c":{"Password":"[REDACTED]","User":"alice"},"d":{"api_key":"[REDACTED]"},"level":"info","msg":"any","session_id":"[REDACTED]"}`,
		},
		{
			// zap.Error(err), zap.NamedError("token", err) for errors printing a stack under %+v
			name: "verbose errors",
			in:   `{"level":"info","msg":"err","session_id":"dummy-session","error":"boom","errorVerbose":"boom\nstack detail","token":"dummy-token","tokenVerbose":"dummy-token\nstack detail"}`,
			want: `{"error":"boom","errorVerbose":"boom\nstack detail","level":"info","msg":"err","session_id":"[REDACTED]","token":"[REDACTED]","tokenVerbose":"[REDACTED]"}`,
		},
		{
			// zap.NamedError("token", multierr.Combine(…))
			name: "multi-error causes",
			in:   `{"level":"info","msg":"causes","session_id":"dummy-session","token":"dummy-a; dummy-b","tokenCauses":[{"error":"dummy-a"},{"error":"dummy-b","errorVerbose":"dummy-b\nstack detail"}]}`,
			want: `{"level":"info","msg":"causes","session_id":"[REDACTED]","token":"[REDACTED]","tokenCauses":"[REDACTED]"}`,
		},
		{
			// zap.Stringer("password", s) whose String method panics
			name: "panicking field",
			in:   `{"level":"info","msg":"panic","session_id":"dummy-session","passwordError":"PANIC=dummy-panic-secret"}`,
			want: `{"level":"info","msg":"panic","passwordError":"[REDACTED]","session_id":"[REDACTED]"}`,
		},
	}
	core := newCore(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskLines(t, core, tt.in); got != tt.want+"\n" {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestZapBufferedLines(t *testing.T) {
	// zapcore.BufferedWriteSyncer flushes several records in one Write.
	var buffer bytes.Buffer
	w := NewWriter(&buffer, newCore(t))
	write(t, w, `{"level":"info","msg":"b1","password":"dummy1"}`+"\n"+`{"level":"info","msg":"b2","password":"dummy2"}`+"\n")
	want := `{"level":"info","msg":"b1","password":"[REDACTED]"}` + "\n" + `{"level":"info","msg":"b2","password":"[REDACTED]"}` + "\n"
	if buffer.String() != want {
		t.Fatalf("got %q, want %q", buffer.String(), want)
	}
}

func TestZapConsoleLineIsReplaced(t *testing.T) {
	got := maskLines(t, newCore(t), "2026-09-29T10:00:00.000+0300\tINFO\tconsole\t{\"password\": \"dummy\"}")
	if got != `{"message":"[REDACTED]"}`+"\n" {
		t.Fatalf("console line: %q", got)
	}
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

func TestDiagnosticKeys(t *testing.T) {
	omitToken := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "token" {
			return masker.Decision{Omit: true}, nil
		}
		return masker.Decision{}, nil
	})
	omitCore, err := masker.New(omitToken)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		core *masker.Masker
		in   string
		want string
	}{
		{
			name: "diagnostic of an omitted key is dropped",
			core: omitCore,
			in:   `{"token":"dummy","tokenVerbose":"dummy\nstack","tokenCauses":[{"error":"dummy"}],"tokenError":"PANIC=dummy"}`,
			want: `{}`,
		},
		{
			name: "diagnostic without its base key is still decided",
			core: newCore(t),
			in:   `{"msg":"x","secretVerbose":"dummy"}`,
			want: `{"msg":"x","secretVerbose":"[REDACTED]"}`,
		},
		{
			name: "nested diagnostic",
			core: newCore(t),
			in:   `{"req":{"items":[{"tokenVerbose":"dummy"}]}}`,
			want: `{"req":{"items":[{"tokenVerbose":"[REDACTED]"}]}}`,
		},
		{
			name: "harmless base keys are left alone",
			core: newCore(t),
			in:   `{"lastError":"timeout","errorCauses":[{"error":"a","errorVerbose":"a\nstack"}],"Error":"x","Verbose":"y"}`,
			want: `{"Error":"x","Verbose":"y","errorCauses":[{"error":"a","errorVerbose":"a\nstack"}],"lastError":"timeout"}`,
		},
		{
			name: "html characters survive re-encoding",
			core: newCore(t),
			in:   `{"tokenVerbose":"dummy","note":"<a&b>"}`,
			want: `{"note":"<a&b>","tokenVerbose":"[REDACTED]"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskLines(t, tt.core, tt.in); got != tt.want+"\n" {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestDiagnosticRuleFailureFailsClosed(t *testing.T) {
	failing := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if strings.EqualFold(field.Key, "token") {
			return masker.Decision{Rule: masker.RuleFunc(func(masker.RuleInput) (string, error) {
				panic("dummy")
			})}, nil
		}
		return masker.Decision{}, nil
	})
	core, err := masker.New(failing)
	if err != nil {
		t.Fatal(err)
	}
	got := maskLines(t, core, `{"msg":"x","tokenVerbose":"dummy-secret"}`)
	if strings.Contains(got, "dummy-secret") || got != `{"message":"[REDACTED]"}`+"\n" {
		t.Fatalf("got %q", got)
	}
}
