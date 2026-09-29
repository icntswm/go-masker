package zapmask

import (
	"io"
	"testing"

	masker "github.com/icntswm/go-masker"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func BenchmarkZapmaskInfo(b *testing.B) {
	core, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zapcore.InfoLevel)
	logger := zap.New(NewCore(inner, core))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("login", zap.String("user", "alice"), zap.String("email", "alice@example.com"), zap.String("password", "hunter2"), zap.Int("attempt", 2))
	}
}

func BenchmarkZapUnmasked(b *testing.B) {
	inner := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zapcore.InfoLevel)
	logger := zap.New(inner)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("login", zap.String("user", "alice"), zap.String("email", "alice@example.com"), zap.String("password", "hunter2"), zap.Int("attempt", 2))
	}
}
