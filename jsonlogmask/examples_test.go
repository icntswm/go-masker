package jsonlogmask_test

import (
	"os"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/jsonlogmask"
)

func ExampleNewWriter() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	// With zerolog: logger := zerolog.New(jsonlogmask.NewWriter(os.Stdout, core))
	w := jsonlogmask.NewWriter(os.Stdout, core)
	if _, err := w.Write([]byte(`{"level":"info","user":"alice","password":"hunter2","message":"login"}` + "\n")); err != nil {
		panic(err)
	}
	// Output: {"level":"info","message":"login","password":"[REDACTED]","user":"alice"}
}

func ExampleNewWriter_zap() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	// With zap: zapcore.AddSync(jsonlogmask.NewWriter(os.Stdout, core)) as the
	// core's write syncer. The line is what zap.NamedError("token", err) writes
	// for an error that prints a stack trace under %+v.
	w := jsonlogmask.NewWriter(os.Stdout, core)
	line := `{"level":"info","msg":"refresh","token":"dummy-token","tokenVerbose":"dummy-token\nstack"}` + "\n"
	if _, err := w.Write([]byte(line)); err != nil {
		panic(err)
	}
	// Output: {"level":"info","msg":"refresh","token":"[REDACTED]","tokenVerbose":"[REDACTED]"}
}
