package zapmask_test

import (
	"os"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/zapmask"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func ExampleNewCore() {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "" // keep the output deterministic
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), os.Stdout, zapcore.InfoLevel)
	logger := zap.New(zapmask.NewCore(inner, core))
	logger.Info("login", zap.String("user", "alice"), zap.String("password", "hunter2"))
	// Output: {"level":"info","msg":"login","user":"alice","password":"[REDACTED]"}
}
