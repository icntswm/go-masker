package detect

import (
	"slices"
	"strings"
	"testing"
)

// Secret-looking values are built from "dummy" and padding, so no realistic
// credential is committed.
var (
	dummyGitHub  = "ghp_dummy" + strings.Repeat("0", 31)
	dummyPAT     = "github_pat_dummy_" + strings.Repeat("0", 20)
	dummyGitLab  = "glpat-dummy" + strings.Repeat("0", 15)
	dummySlack   = "xoxb-dummy-000000"
	dummyStripe  = "sk_live_dummy" + strings.Repeat("0", 11)
	dummyGoogle  = "AIzadummy" + strings.Repeat("0", 30)
	dummyNPM     = "npm_dummy" + strings.Repeat("0", 31)
	dummyJWT     = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.dummy-signature"
	dummyAWS     = "AKIADUMMY" + strings.Repeat("0", 11)
	exampleCard  = "4111 1111 1111 1111" // the well-known test Visa number
	examplePlain = "4111111111111111"
)

// dummyPEM frames a dummy body in PEM lines for label; the lines are joined
// at run time so the source holds no key block.
func dummyPEM(label, body string, footer bool) string {
	text := "-----" + "BEGIN " + label + "-----" + body
	if footer {
		text += "-----" + "END " + label + "-----"
	}
	return text
}

var keyLabel = "RSA " + "PRIVATE" + " KEY"

type found struct {
	spans []string
	pairs [][2]string
}

func find(s string, set Set) found {
	spans, pairs := Find(s, set)
	var got found
	for _, span := range spans {
		got.spans = append(got.spans, s[span.Start:span.End])
	}
	for _, pair := range pairs {
		got.pairs = append(got.pairs, [2]string{s[pair.KeyStart:pair.KeyEnd], s[pair.ValueStart:pair.ValueEnd]})
	}
	return got
}

var detectCases = []struct {
	name  string
	text  string
	set   Set
	spans []string
	pairs [][2]string
}{
	{name: "bearer", text: "sent Bearer dummy-Token.placeholder= upstream", spans: []string{"dummy-Token.placeholder="}},
	{name: "basic mixed case", text: "BASIC ZHVtbXk6cGxhY2Vob2xkZXI=", spans: []string{"ZHVtbXk6cGxhY2Vob2xkZXI="}},
	{name: "bearer prose", text: "the bearer of information"},
	{name: "basic prose", text: "a basic idea"},
	{name: "bearer too short", text: "Bearer Dummy12"},
	{name: "bearer long lowercase", text: "Bearer " + strings.Repeat("dummy", 5), spans: []string{strings.Repeat("dummy", 5)}},
	{name: "bearer inside word", text: "xbearer DummyToken123"},
	{name: "pem", text: "key " + dummyPEM(keyLabel, "\ndummy\n", true) + " done", spans: []string{"\ndummy\n"}},
	{name: "pem cut off", text: dummyPEM(keyLabel, "\ndummy", false), spans: []string{"\ndummy"}},
	{name: "pem other footer", text: dummyPEM(keyLabel, "\ndummy\n", false) + "-----END X-----", spans: []string{"\ndummy\n-----END X-----"}},
	{name: "pem certificate", text: dummyPEM("CERTIFICATE", "\ndummy\n", true)},
	{name: "jwt", text: "token " + dummyJWT + " expired", spans: []string{dummyJWT}},
	{name: "jwt unsigned", text: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkdW1teSJ9.", spans: []string{"eyJhbGciOiJub25lIn0.eyJzdWIiOiJkdW1teSJ9."}},
	{name: "jwt short", text: "eyJhbGci.eyJzdWIi.dummy"},
	{name: "jwt inside word", text: "xeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.dummy"},
	{name: "github", text: "use " + dummyGitHub + " now", spans: []string{dummyGitHub}},
	{name: "github short", text: "ghp_dummy"},
	{name: "github inside word", text: "x" + dummyGitHub},
	{name: "github pat", text: dummyPAT, spans: []string{dummyPAT}},
	{name: "gitlab", text: dummyGitLab, spans: []string{dummyGitLab}},
	{name: "slack", text: "(" + dummySlack + ")", spans: []string{dummySlack}},
	{name: "stripe", text: dummyStripe, spans: []string{dummyStripe}},
	{name: "google", text: dummyGoogle, spans: []string{dummyGoogle}},
	{name: "google too long", text: dummyGoogle + "0"},
	{name: "npm", text: dummyNPM, spans: []string{dummyNPM}},
	{name: "userinfo", text: "dial postgres://dummy:placeholder@db/app failed", spans: []string{"dummy:placeholder"}},
	{name: "url without userinfo", text: "see http://host/path?a#b"},
	{name: "url with at in path", text: "see http://host/@dummy"},
	{name: "timestamp", text: "at 2026-09-29T21:00:00Z"},
	{name: "card off by default", text: "card " + exampleCard},
	{name: "card", text: "card " + exampleCard + ".", set: Set{Cards: true}, spans: []string{exampleCard}},
	{name: "card dashes", text: "4111-1111-1111-1111", set: Set{Cards: true}, spans: []string{"4111-1111-1111-1111"}},
	{name: "card plain", text: "n=" + examplePlain, set: Set{Cards: true}, spans: []string{examplePlain}, pairs: [][2]string{{"n", examplePlain}}},
	{name: "card luhn fails", text: "4111111111111112", set: Set{Cards: true}},
	{name: "card too short", text: "411111111111", set: Set{Cards: true}},
	{name: "card inside word", text: "x4111111111111111", set: Set{Cards: true}},
	{name: "aws off by default", text: dummyAWS},
	{name: "aws", text: "id " + dummyAWS, set: Set{AWSKeyIDs: true}, spans: []string{dummyAWS}},
	{name: "aws too long", text: dummyAWS + "0", set: Set{AWSKeyIDs: true}},
	{name: "aws lowercase", text: "AKIAdummy00000000000", set: Set{AWSKeyIDs: true}},
	{name: "pair equals", text: "login failed: password=dummy-pass", pairs: [][2]string{{"failed", "password=dummy-pass"}, {"password", "dummy-pass"}}},
	{name: "pair colon quoted", text: `password: "dummy value"`, pairs: [][2]string{{"password", "dummy value"}}},
	{name: "pair quoted key", text: `{"token": 'dummy'}`, pairs: [][2]string{{"token", "dummy"}}},
	{name: "pair unclosed quote", text: "secret='dummy value\nnext", pairs: [][2]string{{"secret", "dummy value"}}},
	{name: "pair escaped quote", text: `secret="dummy \" value"`, pairs: [][2]string{{"secret", `dummy \" value`}}},
	{
		name:  "pair scheme word",
		text:  "Authorization: Bearer dummy-token-placeholder",
		spans: []string{"dummy-token-placeholder"},
		pairs: [][2]string{{"Authorization", "Bearer dummy-token-placeholder"}},
	},
	{name: "pair url value", text: "url: https://x", pairs: [][2]string{{"url", "https://x"}}},
	{name: "no pair before slashes", text: "https://x"},
	{name: "pair list", text: "a=b&c=d", pairs: [][2]string{{"a", "b"}, {"c", "d"}}},
	{name: "pair nested", text: "a=b=c", pairs: [][2]string{{"a", "b=c"}, {"b", "c"}}},
	{name: "pair value holds token", text: "auth=" + dummyGitHub, spans: []string{dummyGitHub}, pairs: [][2]string{{"auth", dummyGitHub}}},
	{name: "pair escaped backslash", text: `password="C:\\", status=ok`, pairs: [][2]string{{"password", `C:\\`}, {"C", `\\`}, {"status", "ok"}}},
	{name: "pair underscore key", text: "login _token=dummy", pairs: [][2]string{{"_token", "dummy"}}},
	{name: "pair flag key", text: "run --password=dummy", pairs: [][2]string{{"--password", "dummy"}}},
	{name: "pair key without letter", text: "-- __=x -1=2"},
	{name: "pair digit key", text: "1a=b"},
	{name: "pair after slash", text: "/api/v1/orders?x"},
	{name: "pair empty value", text: "password=; next"},
	{name: "pair long key", text: strings.Repeat("k", 65) + "=v"},
	{name: "pair separator inside value", text: "password=dummy;pass,word&x", pairs: [][2]string{{"password", "dummy;pass,word&x"}}},
	{name: "pair separator before pair", text: "a=1,b=2;c=3", pairs: [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}}},
	{name: "pair separator before space", text: "password=dummy, next", pairs: [][2]string{{"password", "dummy"}}},
	{name: "pair separator at end", text: "password=dummy;", pairs: [][2]string{{"password", "dummy"}}},
	{name: "pair scheme credential with separator", text: "auth: Bearer dummy;token", pairs: [][2]string{{"auth", "Bearer dummy;token"}}},
	{name: "plain", text: "GET /api/v1/orders 200 in 12ms at 2026-09-29T21:00:00Z"},
}

func TestFind(t *testing.T) {
	for _, tc := range detectCases {
		t.Run(tc.name, func(t *testing.T) {
			got := find(tc.text, tc.set)
			if !slices.Equal(got.spans, tc.spans) {
				t.Errorf("spans = %q, want %q", got.spans, tc.spans)
			}
			if !slices.Equal(got.pairs, tc.pairs) {
				t.Errorf("pairs = %q, want %q", got.pairs, tc.pairs)
			}
		})
	}
}

func TestCandidateMatchesFind(t *testing.T) {
	sets := []Set{{}, {Cards: true, AWSKeyIDs: true}}
	for _, tc := range detectCases {
		for _, set := range sets {
			checkCandidate(t, tc.text, set)
		}
	}
}

func checkCandidate(t *testing.T, s string, set Set) {
	t.Helper()
	spans, pairs := Find(s, set)
	want := len(spans)+len(pairs) > 0
	if got := Candidate(s, set); got != want {
		t.Errorf("Candidate(%q, %+v) = %v, Find found %d spans and %d pairs", s, set, got, len(spans), len(pairs))
	}
	if got := Candidate([]byte(s), set); got != want {
		t.Errorf("Candidate([]byte(%q), %+v) = %v, want %v", s, set, got, want)
	}
}

func TestNoAllocOnMiss(t *testing.T) {
	plain := "GET /api/v1/orders 200 in 12ms at 2026-09-29T21:00:00Z"
	plainBytes := []byte(plain)
	set := Set{Cards: true, AWSKeyIDs: true}
	allocs := testing.AllocsPerRun(100, func() {
		if spans, pairs := Find(plain, set); spans != nil || pairs != nil {
			t.Fatal("unexpected match")
		}
		if Candidate(plain, set) || Candidate(plainBytes, set) {
			t.Fatal("unexpected candidate")
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs = %v, want 0", allocs)
	}
}

func FuzzCandidateMatchesFind(f *testing.F) {
	for _, tc := range detectCases {
		f.Add(tc.text, true)
	}
	f.Fuzz(func(t *testing.T, s string, optIn bool) {
		set := Set{Cards: optIn, AWSKeyIDs: optIn}
		spans, pairs := Find(s, set)
		last := -1
		for _, span := range spans {
			if span.Start < 0 || span.Start >= span.End || span.End > len(s) || span.Start <= last {
				t.Fatalf("bad span %+v after %d in %q", span, last, s)
			}
			last = span.Start
		}
		last = -1
		for _, pair := range pairs {
			if pair.KeyStart <= last || pair.KeyStart >= pair.KeyEnd || pair.KeyEnd > pair.ValueStart ||
				pair.ValueStart >= pair.ValueEnd || pair.ValueEnd > len(s) {
				t.Fatalf("bad pair %+v after %d in %q", pair, last, s)
			}
			last = pair.KeyStart
		}
		checkCandidate(t, s, set)
	})
}

// TestLinearOnRepeatedPatterns feeds inputs that restart a detector at every
// few bytes. A quadratic scan of these takes minutes; a linear one takes
// milliseconds, so a regression shows up as a test timeout.
func TestLinearOnRepeatedPatterns(t *testing.T) {
	const n = 1 << 18
	set := Set{Cards: true, AWSKeyIDs: true}
	for _, unit := range []string{"a=", "a:", "1 ", "1-", "a://", "Bearer ", "eyJ", `a="`, "k" + strings.Repeat("0", 70) + "=", "a=x;", "x;", ";a", ",k" + strings.Repeat("0", 70)} {
		text := strings.Repeat(unit, n/len(unit))
		Find(text, set)
		Candidate(text, set)
	}
}
