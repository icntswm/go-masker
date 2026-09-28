package slogmask_test

import (
	"log/slog"
	"os"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/slogmask"
)

func ExampleReplaceAttr() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	mask := slogmask.ReplaceAttr(core)
	options := &slog.HandlerOptions{ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
		if len(groups) == 0 && attr.Key == slog.TimeKey {
			return slog.Attr{} // keep the output deterministic
		}
		return mask(groups, attr)
	}}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, options))
	logger.Info("login", slog.String("user", "alice"), slog.String("password", "hunter2"), slog.Int("attempt", 2))
	// Output: {"level":"INFO","msg":"login","user":"alice","password":"[REDACTED]","attempt":2}
}
