package zerologmask

import (
	"io"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/jsonlogmask"
)

// NewWriter returns jsonlogmask.NewWriter(w, core).
//
// Deprecated: use [jsonlogmask.NewWriter], which is the same writer under a
// name that fits zap and log/slog as well as zerolog.
func NewWriter(w io.Writer, core *masker.Masker) io.Writer {
	return jsonlogmask.NewWriter(w, core)
}
