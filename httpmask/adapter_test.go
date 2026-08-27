package httpmask

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/icntswm/go-masker"
)

func TestHeaderPartialPolicyRuleForcedToFull(t *testing.T) {
	policy, err := masker.NewKeyPolicy(masker.Binding{
		Keys: []string{"email"},
		Rule: masker.EmailRule(),
	})
	if err != nil {
		t.Fatal(err)
	}
	core, err := masker.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := adapter.Headers(http.Header{"email": {"a@b.c"}})
	if err != nil {
		t.Fatal(err)
	}
	if headerValue(headers, "email") != masker.DefaultRedactionMarker {
		t.Fatalf("header rule was not forced to full redaction: %#v", headers)
	}
}

func TestNilAdapterURLFailsClosed(t *testing.T) {
	var adapter *Adapter
	masked, err := adapter.URL(nil)
	if err == nil {
		t.Fatal("expected nil adapter error")
	}
	if masked == nil || masked.Path != masker.DefaultRedactionMarker {
		t.Fatalf("unexpected safe URL: %#v", masked)
	}

	masked, err = (&Adapter{}).URL(nil)
	if err == nil {
		t.Fatal("expected nil core error")
	}
	if masked == nil || masked.Path != masker.DefaultRedactionMarker {
		t.Fatalf("unexpected safe URL: %#v", masked)
	}
}

func TestHeadersAndURL(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core, WithMaskFragment())
	if err != nil {
		t.Fatal(err)
	}
	headers, err := adapter.Headers(http.Header{
		"authorization": {"Bearer abc"},
		"X-API-Key":     {"secret"},
		"X-Trace":       {"trace"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if headerValue(headers, "authorization") != masker.DefaultRedactionMarker ||
		headerValue(headers, "X-API-Key") != masker.DefaultRedactionMarker || headerValue(headers, "X-Trace") != "trace" {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	urlValue, err := url.Parse("https://user:pass@example.com/path?token=secret&x=1#fragment")
	if err != nil {
		t.Fatal(err)
	}
	masked, err := adapter.URL(urlValue)
	if err != nil {
		t.Fatal(err)
	}
	if masked.Query().Get("token") != masker.DefaultRedactionMarker || masked.Query().Get("x") != "1" || masked.Fragment != masker.DefaultRedactionMarker {
		t.Fatalf("unexpected URL: %s", masked)
	}
	if urlValue.Query().Get("token") != "secret" {
		t.Fatal("source URL was mutated")
	}
}

func headerValue(headers http.Header, key string) string {
	for headerKey, values := range headers {
		if strings.EqualFold(headerKey, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func TestURLStringMatchesURL(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core, WithMaskFragment())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://user:pass@example.com/path",
		"https://user:pass@example.com/path?token=secret&keep=value#fragment",
	} {
		src, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		masked, err := adapter.URL(src)
		if err != nil {
			t.Fatal(err)
		}
		maskedString, err := adapter.URLString(raw)
		if err != nil {
			t.Fatal(err)
		}
		if maskedString != masked.String() {
			t.Fatalf("URLString mismatch for %q: got %q want %q", raw, maskedString, masked.String())
		}
	}
}

func TestHeadersPreserveMultiValueCaseAndInput(t *testing.T) {
	var seen []masker.Field
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		seen = append(seen, field)
		if strings.EqualFold(field.Key, "X-Contact") {
			return masker.Decision{Rule: masker.EmailRule()}, nil
		}
		return masker.Decision{}, nil
	})
	core, err := masker.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	source := http.Header{
		"cOoKiE":     {"session=first", "session=second"},
		"sEt-CoOkIe": {"session=first; Path=/", "session=second; Path=/"},
		"X-Contact":  {"alice@example.com", "bob@example.com"},
		"X-Safe":     {"one", "two"},
	}

	masked, err := adapter.Headers(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cOoKiE", "sEt-CoOkIe", "X-Contact"} {
		if !reflect.DeepEqual(masked[key], []string{masker.DefaultRedactionMarker, masker.DefaultRedactionMarker}) {
			t.Fatalf("header %q was not fully masked: %#v", key, masked[key])
		}
	}
	if !reflect.DeepEqual(masked["X-Safe"], []string{"one", "two"}) {
		t.Fatalf("safe multi-value header changed: %#v", masked["X-Safe"])
	}

	wantFields := map[string]masker.Field{
		"X-Contact": {Key: "X-Contact", Path: "$[X-Contact]", Source: masker.SourceHeader, Kind: masker.KindString},
		"X-Safe":    {Key: "X-Safe", Path: "$[X-Safe]", Source: masker.SourceHeader, Kind: masker.KindString},
	}
	counts := make(map[string]int)
	for _, field := range seen {
		want, ok := wantFields[field.Key]
		if !ok || field != want {
			t.Fatalf("unexpected policy field: %#v", field)
		}
		counts[field.Key]++
	}
	if counts["X-Contact"] != 2 || counts["X-Safe"] != 2 {
		t.Fatalf("unexpected policy calls: %#v", counts)
	}

	masked["X-Safe"][0] = "changed"
	masked["new"] = []string{"value"}
	if source["X-Safe"][0] != "one" || source.Get("new") != "" {
		t.Fatalf("source headers were mutated: %#v", source)
	}
}

func TestURLPreservesDuplicatesOrderingAndInput(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	source, err := url.Parse("https://user:pass@example.com/path?z=last&token=one&keep=first&token=two&keep=second&a=first#fragment")
	if err != nil {
		t.Fatal(err)
	}
	original := source.String()

	masked, err := adapter.URL(source)
	if err != nil {
		t.Fatal(err)
	}
	wantQuery := "a=first&keep=first&keep=second&token=%5BREDACTED%5D&token=%5BREDACTED%5D&z=last"
	if masked.RawQuery != wantQuery {
		t.Fatalf("unexpected query: got %q want %q", masked.RawQuery, wantQuery)
	}
	if masked.User == nil || masked.User.Username() != masker.DefaultRedactionMarker {
		t.Fatalf("userinfo was not masked: %#v", masked.User)
	}
	if _, ok := masked.User.Password(); ok {
		t.Fatal("masked userinfo retained a password")
	}
	if masked.Fragment != "fragment" {
		t.Fatalf("fragment changed without opt-in: %q", masked.Fragment)
	}
	if source.String() != original {
		t.Fatalf("source URL was mutated: got %q want %q", source.String(), original)
	}
}

func TestMaskQueryMatchesURLValuesSemantics(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		query   string
		want    string
		wantErr bool
	}{
		{
			name:  "sorts keys and preserves duplicate order",
			query: "z=last&token=one&keep=first&token=two&keep=second&a=first",
			want:  "a=first&keep=first&keep=second&token=%5BREDACTED%5D&token=%5BREDACTED%5D&z=last",
		},
		{
			name:  "unescapes and re-encodes values",
			query: "b=hello+world&a=1&token=secret",
			want:  "a=1&b=hello+world&token=%5BREDACTED%5D",
		},
		{
			name:  "skips empty parts and keys",
			query: "&&b&=ignored&a=&",
			want:  "a=&b=",
		},
		{
			name:    "rejects semicolon",
			query:   "a=1;b=2",
			wantErr: true,
		},
		{
			name:    "rejects invalid escape",
			query:   "a=%zz",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := adapter.maskQuery(test.query)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected query error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("masked query mismatch: got %q want %q", got, test.want)
			}
		})
	}
}

func TestURLInvalidQueryFailsClosed(t *testing.T) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	source := &url.URL{Scheme: "https", Host: "example.com", RawQuery: "token=%zz"}

	masked, err := adapter.URL(source)
	if err == nil || masked.Path != masker.DefaultRedactionMarker {
		t.Fatalf("invalid query did not fail closed: masked=%q err=%v", masked, err)
	}
	if source.RawQuery != "token=%zz" {
		t.Fatalf("source URL was mutated: %#v", source)
	}
}

func TestScalarFastPathFailuresFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		policy masker.Policy
		want   error
	}{
		{
			name: "policy error",
			policy: masker.PolicyFunc(func(masker.Field) (masker.Decision, error) {
				return masker.Decision{}, errors.New("unsafe detail")
			}),
			want: masker.ErrPolicyFailure,
		},
		{
			name: "policy panic",
			policy: masker.PolicyFunc(func(masker.Field) (masker.Decision, error) {
				panic("unsafe detail")
			}),
			want: masker.ErrPanic,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core, err := masker.New(test.policy)
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := New(core)
			if err != nil {
				t.Fatal(err)
			}

			masked, err := adapter.Headers(http.Header{"X-Value": {"secret"}})
			if err == nil || !errors.Is(err, test.want) || strings.Contains(err.Error(), "unsafe detail") {
				t.Fatalf("unexpected safe error: masked=%#v err=%v", masked, err)
			}
			if len(masked) != 0 {
				t.Fatalf("failure returned partial headers: %#v", masked)
			}
		})
	}
}

func TestURLScalarRuleFailuresFailClosed(t *testing.T) {
	tests := []struct {
		name string
		fn   masker.RuleFunc
		want error
	}{
		{
			name: "rule error",
			fn: func(masker.RuleInput) (string, error) {
				return "", errors.New("unsafe detail")
			},
			want: masker.ErrRuleFailure,
		},
		{
			name: "rule panic",
			fn: func(masker.RuleInput) (string, error) {
				panic("unsafe detail")
			},
			want: masker.ErrPanic,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule, err := masker.NewRule("failing", test.fn)
			if err != nil {
				t.Fatal(err)
			}
			policy := masker.PolicyFunc(func(masker.Field) (masker.Decision, error) {
				return masker.Decision{Rule: rule}, nil
			})
			core, err := masker.New(policy, masker.WithRedaction("<hidden>"))
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := New(core)
			if err != nil {
				t.Fatal(err)
			}
			source := &url.URL{Scheme: "https", Host: "example.com", RawQuery: "q=secret"}

			masked, err := adapter.URL(source)
			if err == nil || !errors.Is(err, test.want) || strings.Contains(err.Error(), "unsafe detail") {
				t.Fatalf("unexpected safe error: masked=%q err=%v", masked, err)
			}
			if masked.Path != "<hidden>" || source.RawQuery != "q=secret" {
				t.Fatalf("failure did not preserve marker/input: masked=%#v source=%#v", masked, source)
			}
		})
	}
}
