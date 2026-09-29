package masker

import (
	"encoding/json"
	"strings"
	"testing"
)

// Secret-looking values are built from "dummy" and padding, so no realistic
// credential is committed.
var (
	textDummyGitHub = "ghp_dummy" + strings.Repeat("0", 31)
	textDummyJWT    = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.dummy-signature"
	textDummyAWS    = "AKIADUMMY" + strings.Repeat("0", 11)
	textPEMHeader   = "-----" + "BEGIN " + "PRIVATE" + " KEY-----"
	textPEMFooter   = "-----" + "END " + "PRIVATE" + " KEY-----"
)

var textCases = []struct {
	name  string
	opts  []Option
	value string
	want  string
}{
	{
		name:  "password pair",
		value: "login failed: password=dummy-pass",
		want:  "login failed: password=[REDACTED]",
	},
	{
		name:  "quoted pair",
		value: `retry with password: "dummy value" later`,
		want:  `retry with password: "[REDACTED]" later`,
	},
	{
		name:  "bearer",
		value: "upstream said: Bearer dummy-token-placeholder rejected",
		want:  "upstream said: Bearer [REDACTED] rejected",
	},
	{
		name:  "authorization pair",
		value: "header Authorization: Bearer dummy-token-placeholder",
		want:  "header Authorization: [REDACTED]",
	},
	{
		name:  "jwt",
		value: "decoded " + textDummyJWT + " ok",
		want:  "decoded [REDACTED] ok",
	},
	{
		name:  "pem",
		value: "loaded " + textPEMHeader + "\ndummy\n" + textPEMFooter,
		want:  "loaded " + textPEMHeader + "[REDACTED]" + textPEMFooter,
	},
	{
		name:  "provider token",
		value: "use " + textDummyGitHub + " now",
		want:  "use [REDACTED] now",
	},
	{
		// The whole string is a form, so layer 1 re-encodes it, and the
		// undecided value is searched by the text detectors.
		name:  "provider token in a form",
		value: "note=" + textDummyGitHub,
		want:  "note=%5BREDACTED%5D",
	},
	{
		name:  "url userinfo in prose",
		value: "dial postgres://app:dummy@db:5432/app failed",
		want:  "dial postgres://[REDACTED]@db:5432/app failed",
	},
	{
		name:  "harmless pairs",
		value: "status: 200 in 12ms at 2026-09-29T21:00:00Z",
		want:  "status: 200 in 12ms at 2026-09-29T21:00:00Z",
	},
	{
		name:  "card off by default",
		value: "paid with 4111 1111 1111 1111",
		want:  "paid with 4111 1111 1111 1111",
	},
	{
		name:  "card",
		opts:  []Option{WithCardNumberDetection()},
		value: "paid with 4111 1111 1111 1111",
		want:  "paid with **** **** **** 1111",
	},
	{
		name:  "aws off by default",
		value: "key " + textDummyAWS,
		want:  "key " + textDummyAWS,
	},
	{
		name:  "aws",
		opts:  []Option{WithAWSKeyIDDetection()},
		value: "key " + textDummyAWS,
		want:  "key [REDACTED]",
	},
	{
		name:  "without text detectors",
		opts:  []Option{WithoutTextDetectors()},
		value: "login failed: password=dummy-pass, Bearer dummy-token-placeholder",
		want:  "login failed: password=dummy-pass, Bearer dummy-token-placeholder",
	},
	{
		name:  "without text detectors keeps documents",
		opts:  []Option{WithoutTextDetectors()},
		value: "user=a&password=dummy",
		want:  "password=%5BREDACTED%5D&user=a",
	},
	{
		name:  "without value inspection",
		opts:  []Option{WithoutValueInspection()},
		value: "https://u:dummy@host/cb?token=dummy-token",
		want:  "https://u:dummy@host/cb?token=dummy-token",
	},
}

func TestTextDetectors(t *testing.T) {
	for _, test := range textCases {
		t.Run(test.name, func(t *testing.T) {
			m := newTestMasker(t, test.opts...)
			result, err := m.MaskValue("message", test.value)
			if err != nil {
				t.Fatal(err)
			}
			if result != test.want {
				t.Fatalf("got %q want %q", result, test.want)
			}
		})
	}
}

// TestTextDetectorsWalkersAgree masks the same text in every walker: the
// stream and DOM JSON walkers, a map and a struct field.
func TestTextDetectorsWalkersAgree(t *testing.T) {
	type record struct {
		Message string `json:"message"`
	}
	for _, test := range textCases {
		t.Run(test.name, func(t *testing.T) {
			m := newTestMasker(t, test.opts...)
			document, err := json.Marshal(map[string]string{"message": test.value})
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(map[string]string{"message": test.want})
			if err != nil {
				t.Fatal(err)
			}

			masked, err := m.MaskJSON(document)
			if err != nil {
				t.Fatal(err)
			}
			if string(masked) != string(want) {
				t.Fatalf("MaskJSON: got %s want %s", masked, want)
			}

			var decoded any
			if err := json.Unmarshal(document, &decoded); err != nil {
				t.Fatal(err)
			}
			fromDOM := (&jsonWalker{masker: m}).walk(decoded, Field{Source: SourceJSON}, 0)
			if got := fromDOM.(map[string]any)["message"]; got != test.want {
				t.Fatalf("DOM walker: got %q want %q", got, test.want)
			}

			fromMap, err := m.MaskAny(map[string]any{"message": test.value})
			if err != nil {
				t.Fatal(err)
			}
			if got := fromMap.(map[string]any)["message"]; got != test.want {
				t.Fatalf("map: got %q want %q", got, test.want)
			}

			fromStruct, err := m.MaskAny(record{Message: test.value})
			if err != nil {
				t.Fatal(err)
			}
			if got := fromStruct.(map[string]any)["message"]; got != test.want {
				t.Fatalf("struct: got %#v want %q", fromStruct, test.want)
			}
		})
	}
}

func TestTextPairsReachPolicy(t *testing.T) {
	var seen []Field
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Source == SourceText {
			seen = append(seen, field)
			if field.Key == "session" {
				return Decision{Omit: true}, nil
			}
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskValue("message", "user=alice session=dummy")
	if err != nil {
		t.Fatal(err)
	}
	if result != "user=alice session=[REDACTED]" {
		t.Fatalf("an omitted text value must become the marker, got %q", result)
	}
	if len(seen) != 2 || seen[0].Key != "user" || seen[0].Path != "$[message][user]" ||
		seen[1].Key != "session" || seen[1].Kind != KindString {
		t.Fatalf("unexpected fields: %#v", seen)
	}
}

func TestTextPolicyFailureIsMarked(t *testing.T) {
	policy := PolicyFunc(func(field Field) (Decision, error) {
		if field.Source == SourceText {
			panic("dummy policy panic")
		}
		return Decision{}, nil
	})
	m, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.MaskValue("message", "retry user=alice")
	if err == nil {
		t.Fatal("a panicking policy must be reported")
	}
	if result != "retry user=[REDACTED]" && result != "[REDACTED]" {
		t.Fatalf("the failed pair must not leak, got %q", result)
	}
}
