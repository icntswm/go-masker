package httpmask

import (
	"net/url"
	"strings"
	"testing"

	"github.com/icntswm/go-masker"
)

// FuzzURLString checks adapter safety on arbitrary URL strings: no panics,
// marker-only output on errors, re-parseable output on success, and no
// userinfo password leakage.
func FuzzURLString(f *testing.F) {
	f.Add("https://alice:s3cret@example.com/p?token=t1&keep=1#frag")
	f.Add("https://example.com/x?a=%zz&token=t")
	f.Add("mailto:user@example.com")
	f.Add("https://example.com")
	f.Add("")
	f.Add("https://user@host/p?q=" + "\u0442\u043e\u043a\u0435\u043d")
	f.Add("//no-scheme/path?token=x")
	f.Fuzz(func(t *testing.T, raw string) {
		core, err := masker.New(masker.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := New(core)
		if err != nil {
			t.Fatal(err)
		}
		out, err := adapter.URLString(raw)
		if err != nil {
			if out != masker.DefaultRedactionMarker {
				t.Fatalf("error path must return the marker, got %q", out)
			}
			return
		}
		parsedOut, perr := url.Parse(out)
		if perr != nil {
			t.Fatalf("masked URL is not re-parseable: %q: %v", out, perr)
		}
		source, serr := url.Parse(raw)
		if serr != nil || source.User == nil {
			return
		}
		password, ok := source.User.Password()
		if !ok || password == "" || strings.Contains(masker.DefaultRedactionMarker, password) {
			return
		}
		if parsedOut.User != nil {
			maskedPassword, hasMaskedPassword := parsedOut.User.Password()
			if hasMaskedPassword && maskedPassword == password {
				t.Fatalf("userinfo password leaked: %q", out)
			}
		}
	})
}
