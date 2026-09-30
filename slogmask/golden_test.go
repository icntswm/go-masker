package slogmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	masker "github.com/icntswm/go-masker"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden.txt")

type goldenStringer string

func (s goldenStringer) String() string { return "stringer:" + string(s) }

type goldenLevel int

type goldenUser struct {
	Name     string
	Email    string
	Password string
	Age      int
	Admin    bool
}

type goldenValuer struct{ token string }

func (v goldenValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token", v.token), slog.String("who", "bob"))
}

// goldenPolicy reads the path and the kind, so it keeps the adapter building
// full paths and passing the kind it normalizes each value to.
func goldenPolicy() masker.Policy {
	return masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		switch {
		case field.Path == "$[audit][actor]":
			return masker.Decision{Rule: masker.FullRule()}, nil
		case field.Key == "drop", field.Path == "$[scoped][gone]":
			return masker.Decision{Omit: true}, nil
		case field.Key == "hidden_group" && field.Kind == masker.KindObject:
			return masker.Decision{Omit: true}, nil
		case field.Key == "carded_group" && field.Kind == masker.KindObject:
			return masker.Decision{Rule: masker.CardRule()}, nil
		case field.Key == "count" && field.Kind == masker.KindNumber:
			return masker.Decision{Rule: masker.FullRule()}, nil
		case field.Key == "flag" && field.Kind == masker.KindBool:
			return masker.Decision{Rule: masker.FullRule()}, nil
		case field.Key == "last4":
			return masker.Decision{Rule: masker.CardRule()}, nil
		}
		return masker.Decision{}, nil
	})
}

// goldenRecords logs every attribute shape the adapter handles. The output
// is compared byte for byte, so any change in what reaches a log, including
// a value's JSON type, fails the test.
func goldenRecords(logger *slog.Logger) {
	secret := "dummy-s3cret-placeholder"
	logger.Info("scalars",
		"name", "alice", "attempt", 3, "big", int64(1)<<40, "unsigned", uint64(7),
		"ratio", 0.25, "ok", true, "wait", 1500*time.Millisecond,
		"at", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "empty", "", "ref", int64(4111111111111111))
	logger.Info("sensitive",
		"password", secret, "token", secret, "email", "alice@example.com",
		"phone", "+1 555 010 9999", "card", "4111 1111 1111 1111", "id", "user-12345678",
		"password", 123456, "token", true, "api_key", 2.5, "secret", time.Second)
	logger.Info("policy", "drop", secret, "count", 42, "flag", false, "last4", "4111111111111111",
		slog.Group("audit", "actor", "alice", "action", "login"),
		slog.Group("scoped", "gone", secret, "kept", "yes"),
		slog.Group("hidden_group", "value", secret),
		slog.Group("carded_group", "value", secret))
	logger.Info("groups",
		slog.Group("req", "method", "GET", "authorization", "Bearer "+secret),
		slog.Group("credentials", "user", "alice", "pass", secret),
		slog.Group("outer", slog.Group("inner", "api_key", secret, "safe", 1)))
	logger.With("session_id", secret, "tenant", "acme").WithGroup("ctx").Info("context", "cookie", secret, "trace", "abc")
	logger.Info("text password="+secret+" for alice",
		"note", "retry with token: "+secret,
		"callback", "https://user:"+secret+"@example.com/cb?token="+secret+"&page=2",
		"body", `{"user":"alice","password":"`+secret+`"}`,
		"form", "user=alice&password="+secret,
		"header", "Bearer "+secret)
	logger.Info("any",
		"user", goldenUser{Name: "Alice", Email: "alice@example.com", Password: secret, Age: 30, Admin: true},
		"ptr", &goldenUser{Name: "Bob", Password: secret},
		"map", map[string]any{"token": secret, "n": 1, "list": []any{"a", 2, true, nil}, "nested": map[string]any{}},
		"list", []string{"x", "y"},
		"raw", json.RawMessage(`{"password":"`+secret+`","n":1}`),
		"bytes", []byte("plain bytes"),
		"err", errors.New("login failed password="+secret),
		"stringer", goldenStringer("value"),
		"level", goldenLevel(4),
		"valuer", goldenValuer{token: secret},
		"nil", nil,
		"typed_nil", (*goldenUser)(nil))
	logger.Info("edge", "", "empty key", "marker", "[REDACTED]", "unicode", "élise@example.com",
		"password", "", "email", "not an email", "bad\xffkey", "v", "badvalue", "v\xff",
		slog.Group("bad\xffgroup", "inner", "v"))
}

func goldenConfigs(t *testing.T) []struct {
	name string
	core *masker.Masker
} {
	t.Helper()
	build := func(policy masker.Policy, opts ...masker.Option) *masker.Masker {
		core, err := masker.New(policy, opts...)
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	return []struct {
		name string
		core *masker.Masker
	}{
		{"default", build(masker.DefaultPolicy())},
		{"path policy", build(masker.Chain(goldenPolicy(), masker.DefaultPolicy()))},
		{"preserve types", build(masker.DefaultPolicy(), masker.WithPreserveSafeTypes())},
		{"card detection and marker", build(masker.DefaultPolicy(), masker.WithCardNumberDetection(), masker.WithRedaction("***"))},
		{"no inspection", build(masker.DefaultPolicy(), masker.WithoutValueInspection())},
		{"nil core", nil},
	}
}

func renderGolden(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	for _, config := range goldenConfigs(t) {
		replace := ReplaceAttr(config.core)
		opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return replace(groups, attr)
		}}
		for _, handler := range []string{"json", "text"} {
			var buffer bytes.Buffer
			var h slog.Handler = slog.NewJSONHandler(&buffer, opts)
			if handler == "text" {
				h = slog.NewTextHandler(&buffer, opts)
			}
			goldenRecords(slog.New(h))
			fmt.Fprintf(&out, "== %s / %s\n%s", config.name, handler, buffer.String())
		}
	}
	return out.String()
}

// TestReplaceAttrGolden pins the exact log output for every attribute shape
// under several configurations. Run with -update to accept a deliberate
// change, and review the diff of testdata/golden.txt.
func TestReplaceAttrGolden(t *testing.T) {
	got := renderGolden(t)
	path := filepath.Join("testdata", "golden.txt")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Go 1.27 writes the replacement for invalid UTF-8 as the character
	// itself where earlier releases escape it; the text is the same, so only
	// that spelling is folded before the byte comparison.
	got, wantText := foldReplacementEscape(got), foldReplacementEscape(string(want))
	if got != wantText {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(wantText, "\n")
		for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("golden mismatch at line %d:\n got: %s\nwant: %s", i+1, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("golden length differs: got %d lines, want %d", len(gotLines), len(wantLines))
	}
}

func foldReplacementEscape(s string) string {
	return strings.ReplaceAll(s, `\ufffd`, "\ufffd")
}
