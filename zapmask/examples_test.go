package zapmask_test

import (
	"os"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/zapmask"
)

func ExampleNewWriteSyncer() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	// With zap: zapcore.NewCore(zapcore.NewJSONEncoder(cfg),
	// zapmask.NewWriteSyncer(os.Stdout, core), zap.InfoLevel) as the core's
	// write syncer. The line is what zap.NamedError("token", err) writes
	// for an error that prints a stack trace under %+v.
	w := zapmask.NewWriteSyncer(os.Stdout, core)
	line := `{"level":"info","msg":"refresh","token":"dummy-token","tokenVerbose":"dummy-token\nstack"}` + "\n"
	if _, err := w.Write([]byte(line)); err != nil {
		panic(err)
	}
	// Output: {"level":"info","msg":"refresh","token":"[REDACTED]","tokenVerbose":"[REDACTED]"}
}
