// Command outputdigest hashes the output of a fixed corpus so that masking
// output can be compared across Go toolchains. PERFORMANCE.md records the
// digest; run it with each toolchain and compare:
//
//	go run ./internal/outputdigest
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
)

func main() {
	docs := []string{
		`{"password":"p","email":"a@b.co","count":42,"big":123456789012345678901234567890}`,
		`{"a":"<script>&\"q\"\\s\b\f\n\r\t\u0000","u":"Привет 世界 😀 \u2028 \u2029"}`,
		`{"nested":{"token":"t","arr":[1,true,null,"s",{"card":"4111111111111111"}]}}`,
		`{"dup":"first","dup":"second","z":1,"a":2,"M":3}`,
		`{"e":1e309,"n":-0.0,"x":1E+09}`,
		`  {"phone":"+7 (999) 123-45-67"}  `,
		`[]`, `{}`, `null`, `"plain"`, `123`,
		`{"bad":}`, `{tok":1}`, `{"unterminated":"x`, ``,
		strings.Repeat("[", 40) + strings.Repeat("]", 40),
	}
	h := sha256.New()
	emit := func(label string, b []byte, err error) {
		_, _ = fmt.Fprintf(h, "%s|%s|%v\n", label, b, err) // hash.Hash writes never fail
	}
	for _, marker := range []string{"", "[REDACTED]", `<"&>`, "🔒"} {
		opts := []masker.Option{}
		if marker != "" {
			opts = append(opts, masker.WithRedaction(marker))
		}
		m, err := masker.New(masker.DefaultPolicy(), opts...)
		if err != nil {
			panic(err)
		}
		for _, d := range docs {
			out, err := m.MaskJSON([]byte(d))
			emit("json:"+marker, out, err)
		}
		v, err := m.MaskAny(map[string]any{"password": "x", "n": 1, "s": []any{"a", true}})
		emit("any:"+marker, []byte(fmt.Sprintf("%v", v)), err)

		a, err := httpmask.New(m)
		if err != nil {
			panic(err)
		}
		for _, raw := range []string{
			"https://u:p@h/p?token=t&keep=1&x=%20a#f",
			"https://h/p?a=1&a=2&b=%D0%B0",
		} {
			s, err := a.URLString(raw)
			emit("url:"+marker, []byte(s), err)
			u, _ := url.Parse(raw)
			mu, err := a.URL(u)
			emit("urlp:"+marker, []byte(mu.String()), err)
		}
		hd, err := a.Headers(map[string][]string{
			"Authorization": {"Bearer x"}, "Cookie": {"a=b"}, "X-Api-Key": {"k"}, "Accept": {"*/*"},
		})
		emit("hdr:"+marker, []byte(fmt.Sprintf("%v", hd)), err)
	}
	fmt.Printf("%-9s digest=%s\n", runtime.Version(), hex.EncodeToString(h.Sum(nil)))
}
