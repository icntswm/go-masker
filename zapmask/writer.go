package zapmask

import (
	"io"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/internal/jsonline"
)

// WriteSyncer masks the JSON lines written by a zap core. It has the Write
// and Sync methods of zapcore.WriteSyncer, so it is passed to
// zapcore.NewCore directly, without zapcore.AddSync.
type WriteSyncer struct{ w jsonline.Writer }

// NewWriteSyncer returns a WriteSyncer that masks every JSON line written to
// w through core and writes the result to w. A line that cannot be masked is
// replaced by {"message":"<marker>"} and never passes through. Each Write
// must carry whole lines.
func NewWriteSyncer(w io.Writer, core *masker.Masker) WriteSyncer {
	return WriteSyncer{w: jsonline.New(w, core, jsonline.Options{Name: "zapmask", Diagnostics: true})}
}

// Write masks p and writes the result to the destination. A Write that fails
// reports the destination's error or io.ErrShortWrite, never the masked text.
func (s WriteSyncer) Write(p []byte) (int, error) { return s.w.Write(p) }

// Sync flushes the destination when it provides a Sync method, as *os.File
// does, and is a no-op otherwise.
func (s WriteSyncer) Sync() error { return s.w.Sync() }
