package zerologmask_test

import (
	"os"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/zerologmask"
)

func ExampleNewWriter() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	// With zerolog: logger := zerolog.New(zerologmask.NewWriter(os.Stdout, core))
	w := zerologmask.NewWriter(os.Stdout, core)
	if _, err := w.Write([]byte(`{"level":"info","user":"alice","password":"hunter2","message":"login"}` + "\n")); err != nil {
		panic(err)
	}
	// Output: {"level":"info","message":"login","password":"[REDACTED]","user":"alice"}
}
