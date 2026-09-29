package zerologmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	masker "github.com/icntswm/go-masker"
)

// NewWriter returns an io.Writer that masks every JSON line written to it
// through core and writes the result to w. A logger writing one JSON object
// per line, such as zerolog, produces masked lines; a line that cannot be
// masked is replaced by {"message":"<marker>"} and never passes through. The
// result is safe for concurrent use when w is, because the writer keeps no
// mutable state.
func NewWriter(w io.Writer, core *masker.Masker) io.Writer {
	r := writer{out: w, core: core, mark: masker.DefaultRedactionMarker}
	if core != nil {
		if mark, err := core.MaskString("", masker.FullRule()); err == nil && mark != "" {
			r.mark = mark
		}
	}
	return r
}

type writer struct {
	out  io.Writer
	core *masker.Masker
	mark string
}

func (r writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.out == nil {
		return 0, errors.New("zerologmask: nil writer")
	}
	masked := r.mask(p)
	n, err := r.out.Write(masked)
	if err != nil {
		return 0, err
	}
	if n < len(masked) {
		return 0, io.ErrShortWrite
	}
	// The caller's bytes are consumed regardless of how many bytes the
	// masked result took, so success reports the input length.
	return len(p), nil
}

// mask returns the masked form of p, keeping its newline separators exactly:
// every input line that ended in '\n' ends in '\n' in the result, and a final
// line without one gets none.
func (r writer) mask(p []byte) []byte {
	// The fast path covers a logger that writes exactly one line per Write,
	// such as zerolog: the masked line and its newline are one buffer and
	// the result is written without an intermediate copy.
	if bytes.IndexByte(p, '\n') == len(p)-1 {
		line := p[:len(p)-1]
		if blank(line) {
			return p
		}
		return append(r.line(line), '\n')
	}
	result := make([]byte, 0, len(p)+len(r.mark)+8)
	for {
		line := p
		terminated := false
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line, terminated = p[:i], true
		}
		if blank(line) {
			result = append(result, line...)
		} else {
			result = append(result, r.line(line)...)
		}
		if !terminated {
			return result
		}
		result = append(result, '\n')
		p = p[len(line)+1:]
	}
}

// line masks one line without its newline separator. A blank line passes
// through unchanged; a line the core cannot mask, including one that fails
// while masking, is replaced by the fallback line.
func (r writer) line(line []byte) (masked []byte) {
	if blank(line) {
		return line
	}
	if r.core == nil {
		return r.fallback()
	}
	// Masking runs caller rules, which may panic; the original line must
	// still stay out of the output.
	defer func() {
		if recover() != nil {
			masked = r.fallback()
		}
	}()
	out, err := r.core.MaskJSON(line)
	if err != nil {
		return r.fallback()
	}
	return out
}

// fallback is the line written when the payload cannot be masked: the
// redaction marker as the only field, so nothing of the original line
// remains.
func (r writer) fallback() []byte {
	mark, err := json.Marshal(r.mark)
	if err != nil {
		mark = []byte(`"[REDACTED]"`)
	}
	line := make([]byte, 0, len(`{"message":`)+len(mark)+1)
	line = append(line, `{"message":`...)
	line = append(line, mark...)
	return append(line, '}')
}

// blank reports a line that is empty or carries only whitespace a JSON
// document may be surrounded by, so it is copied unchanged.
func blank(line []byte) bool {
	for _, c := range line {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}
