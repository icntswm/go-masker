package zerologmask

import (
	"io"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/internal/jsonline"
)

// NewWriter returns a writer that masks each JSON line written by zerolog, or
// by any logger writing one JSON object per line, through core and writes the
// result to w. A line that cannot be masked is replaced by
// {"message":"<marker>"} and never passes through. Each Write must carry
// whole lines. Sync is forwarded when w has one.
func NewWriter(w io.Writer, core *masker.Masker) io.Writer {
	return jsonline.New(w, core, jsonline.Options{Name: "zerologmask"})
}
