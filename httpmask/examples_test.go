package httpmask_test

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
)

func ExampleAdapter_Headers() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	adapter, err := httpmask.New(core)
	if err != nil {
		panic(err)
	}

	masked, err := adapter.Headers(http.Header{
		"Authorization": {"Bearer synthetic-token"},
		"X-Trace":       {"trace-id"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(masked.Get("Authorization"), masked.Get("X-Trace"))
	// Output: [REDACTED] trace-id
}

func ExampleAdapter_URLString() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	adapter, err := httpmask.New(core, httpmask.WithMaskFragment())
	if err != nil {
		panic(err)
	}

	masked, err := adapter.URLString("https://alice:synthetic-password@example.com/?token=synthetic-token&keep=value#fragment")
	if err != nil {
		panic(err)
	}
	fmt.Println(masked)
	// Output: https://%5BREDACTED%5D@example.com/?keep=value&token=%5BREDACTED%5D#%5BREDACTED%5D
}

func ExampleAdapter_URL() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	adapter, err := httpmask.New(core)
	if err != nil {
		panic(err)
	}

	// The parsed form avoids a reparse when the caller already holds a URL.
	// Path and fragment are preserved by default; userinfo is always redacted.
	src, err := url.Parse("https://alice:synthetic-password@example.com/orders/42?api_key=synthetic-key&page=2#details")
	if err != nil {
		panic(err)
	}
	masked, err := adapter.URL(src)
	if err != nil {
		panic(err)
	}
	fmt.Println(masked)
	fmt.Println(src) // the input URL is never modified

	// Output:
	// https://%5BREDACTED%5D@example.com/orders/42?api_key=%5BREDACTED%5D&page=2#details
	// https://alice:synthetic-password@example.com/orders/42?api_key=synthetic-key&page=2#details
}

func ExampleWithMaskFragment() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	plain, err := httpmask.New(core)
	if err != nil {
		panic(err)
	}
	paranoid, err := httpmask.New(core, httpmask.WithMaskFragment())
	if err != nil {
		panic(err)
	}

	const raw = "https://example.com/app#access_token=synthetic-token"
	kept, err := plain.URLString(raw)
	if err != nil {
		panic(err)
	}
	hidden, err := paranoid.URLString(raw)
	if err != nil {
		panic(err)
	}
	fmt.Println(kept)
	fmt.Println(hidden)

	// Output:
	// https://example.com/app#access_token=synthetic-token
	// https://example.com/app#%5BREDACTED%5D
}

func ExampleAdapter_Headers_cookies() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	adapter, err := httpmask.New(core)
	if err != nil {
		panic(err)
	}

	// Cookie and Set-Cookie are always redacted whole: no attempt is made to
	// keep individual cookie names.
	masked, err := adapter.Headers(http.Header{
		"Cookie":     {"session=synthetic-session; theme=dark"},
		"Set-Cookie": {"session=synthetic-session; HttpOnly"},
		"Accept":     {"application/json"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(masked.Get("Cookie"))
	fmt.Println(masked.Get("Set-Cookie"))
	fmt.Println(masked.Get("Accept"))
	// Output:
	// [REDACTED]
	// [REDACTED]
	// application/json
}
