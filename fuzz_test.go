package masker_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/icntswm/go-masker"
)

func newFuzzMasker(t *testing.T) *masker.Masker {
	t.Helper()
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// FuzzMaskJSON checks the core fail-closed contract on arbitrary bytes:
// the output is always valid JSON, errors always produce the marker, and a
// known secret never survives masking.
func FuzzMaskJSON(f *testing.F) {
	seeds := []string{
		`{"token":"synthetic-secret","safe":42}`,
		`{"password":"hunter2"}`,
		`{"API_` + "\u212a" + `EY":"v"}`,
		`{"user":{"email":"a@b.c","phone":"15551234567"}}`,
		`[1,2,{"card":"4111111111111111"}]`,
		`{"v":"first","v":"second"}`,
		`{"token":"x`,
		`{"a":1} trailing`,
		``,
		`null`,
		`123456789012345678901234567890`,
		string([]byte{0xff, 0xfe}),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := newFuzzMasker(t)
		out, err := m.MaskJSON(data)
		if len(out) == 0 || !json.Valid(out) {
			t.Fatalf("output is not valid JSON: %q (err=%v)", out, err)
		}
		if err != nil {
			if !bytes.Equal(out, []byte(`"[REDACTED]"`)) {
				t.Fatalf("error path must return the marker, got %q", out)
			}
			return
		}
		if !utf8.Valid(data) {
			t.Fatal("invalid UTF-8 input must fail closed")
		}
		var doc map[string]any
		if json.Unmarshal(data, &doc) != nil {
			return
		}
		secret, ok := doc["password"].(string)
		if !ok || secret == "" || strings.Contains(masker.DefaultRedactionMarker, secret) {
			return
		}
		var masked map[string]any
		if json.Unmarshal(out, &masked) == nil && masked["password"] == secret {
			t.Fatalf("secret %q leaked into output %s", secret, out)
		}
	})
}

// FuzzMaskString checks that built-in rules never panic, never error, and
// always return valid UTF-8 for arbitrary input strings.
func FuzzMaskString(f *testing.F) {
	f.Add("synthetic-secret")
	f.Add("alice@example.com")
	f.Add("4111-1111-1111-1111")
	f.Add("+1 (555) 123-4567")
	f.Add("AB-987654")
	f.Add("")
	f.Add("\xff\xfe broken utf8")
	f.Add("spaces \t\n inside")
	f.Add("stra\u00dfe")
	f.Fuzz(func(t *testing.T, value string) {
		m := newFuzzMasker(t)
		fullRules := map[string]bool{"password": true, "token": true, "full": true}
		rules := map[string]masker.Rule{
			"password": masker.PasswordRule(),
			"token":    masker.TokenRule(),
			"full":     masker.FullRule(),
			"email":    masker.EmailRule(),
			"phone":    masker.PhoneRule(),
			"id":       masker.IDRule(),
			"card":     masker.CardRule(),
		}
		for name, rule := range rules {
			out, err := m.MaskString(value, rule)
			if err != nil {
				t.Fatalf("built-in rule %q must not fail: %v", name, err)
			}
			if !utf8.ValidString(out) {
				t.Fatalf("rule %q produced invalid UTF-8: %q", name, out)
			}
			if fullRules[name] && out != masker.DefaultRedactionMarker {
				t.Fatalf("rule %q must fully redact, got %q", name, out)
			}
		}
	})
}

// FuzzKeyPolicyCaseFold pins Decide parity under ASCII case changes: keys
// that are strings.EqualFold must always receive the same rule.
func FuzzKeyPolicyCaseFold(f *testing.F) {
	f.Add("password")
	f.Add("API_KEY")
	f.Add("refresh_Token")
	f.Add("Card-Number")
	f.Add("plainkey")
	f.Add("pa\u017fsword")
	f.Fuzz(func(t *testing.T, key string) {
		if key == "" || !utf8.ValidString(key) {
			t.Skip()
		}
		runes := []rune(key)
		for i, r := range runes {
			switch {
			case r >= 'a' && r <= 'z':
				runes[i] = r - ('a' - 'A')
			case r >= 'A' && r <= 'Z':
				runes[i] = r + ('a' - 'A')
			}
		}
		variant := string(runes)
		if variant == key || !strings.EqualFold(key, variant) {
			t.Skip()
		}
		policy := masker.DefaultPolicy()
		first, err := policy.Decide(masker.Field{Key: key, Source: masker.SourceMap})
		if err != nil {
			t.Fatalf("Decide(%q) failed: %v", key, err)
		}
		second, err := policy.Decide(masker.Field{Key: variant, Source: masker.SourceMap})
		if err != nil {
			t.Fatalf("Decide(%q) failed: %v", variant, err)
		}
		nameOf := func(d masker.Decision) string {
			if d.Rule == nil {
				return ""
			}
			return d.Rule.Name()
		}
		if nameOf(first) != nameOf(second) {
			t.Fatalf("case-fold parity broken: %q -> %q, %q -> %q",
				key, nameOf(first), variant, nameOf(second))
		}
	})
}
