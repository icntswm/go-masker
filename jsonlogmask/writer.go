package jsonlogmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"

	masker "github.com/icntswm/go-masker"
)

// NewWriter returns an io.Writer that masks every JSON line written to it
// through core and writes the result to w. A logger writing one JSON object
// per line, such as zerolog or zap's JSON encoder, produces masked lines; a
// line that cannot be masked is replaced by {"message":"<marker>"} and never
// passes through. A key ending in Verbose, Causes or Error is decided as its
// base key too, see the package documentation. Each
// Write must carry whole lines: a record split across two calls is masked as
// two broken documents and both halves are replaced. The result is safe for
// concurrent use when w is, because the writer keeps no mutable state. Its
// Sync method flushes w when w has one, so zapcore.AddSync keeps syncing the
// real destination.
func NewWriter(w io.Writer, core *masker.Masker) io.Writer {
	r := writer{out: w, core: core, mark: masker.DefaultRedactionMarker}
	if core != nil {
		if mark, err := core.MaskString("", masker.FullRule()); err == nil && mark != "" {
			r.mark = mark
		}
	}
	r.fallbackLine = fallbackLine(r.mark)
	return r
}

type writer struct {
	out          io.Writer
	core         *masker.Masker
	mark         string
	fallbackLine []byte
}

func (r writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.out == nil {
		return 0, errors.New("jsonlogmask: nil writer")
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

// Sync flushes the destination when it provides a Sync method, as *os.File
// does, and is a no-op otherwise.
func (r writer) Sync() error {
	if s, ok := r.out.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
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
	result := make([]byte, 0, len(p))
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
	if !mentionsDiagnostic(out) {
		return out
	}
	out, err = r.diagnostics(out)
	if err != nil {
		return r.fallback()
	}
	return out
}

// diagnosticSuffixes are the keys zap writes next to a field it could not
// log as a plain value: an error's %+v text under keyVerbose, the errors of a
// multi-error under keyCauses, and a panic while encoding the field under
// keyError. Each repeats the field's own content, so it must be masked as the
// field is, whatever the policy thinks of the suffixed key.
var diagnosticSuffixes = [...]string{"Verbose", "Causes", "Error"}

// mentionsDiagnostic reports whether a masked line may hold a diagnostic key.
// MaskJSON re-encodes every key, so a key spelled with escapes in the input
// comes out plain and a byte search finds it; a line without a match skips
// the decode.
func mentionsDiagnostic(line []byte) bool {
	for _, suffix := range diagnosticSuffixes {
		if bytes.Contains(line, []byte(suffix+`"`)) {
			return true
		}
	}
	return false
}

// diagnostics decides every diagnostic key in an already masked line as its
// base key, so that zap.NamedError("token", err) does not log the token's
// text again under tokenVerbose. A base key the policy lets through leaves
// the diagnostic unchanged.
func (r writer) diagnostics(line []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	changed, err := r.walkDiagnostics(document, "$")
	if err != nil || !changed {
		return line, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// walkDiagnostics rewrites the diagnostic keys of every object in value and
// reports whether anything changed.
func (r writer) walkDiagnostics(value any, path string) (bool, error) {
	changed := false
	switch value := value.(type) {
	case map[string]any:
		for key, member := range value {
			memberPath := path + "[" + key + "]"
			if base, ok := diagnosticBase(key); ok {
				masked, keep, err := r.maskDiagnostic(base, path+"["+base+"]", member)
				if err != nil {
					return false, err
				}
				switch {
				case !keep:
					delete(value, key)
					changed = true
					continue
				case !reflect.DeepEqual(masked, member):
					value[key] = masked
					changed = true
					continue
				}
			}
			memberChanged, err := r.walkDiagnostics(member, memberPath)
			if err != nil {
				return false, err
			}
			changed = changed || memberChanged
		}
	case []any:
		for i, element := range value {
			elementChanged, err := r.walkDiagnostics(element, path+"["+strconv.Itoa(i)+"]")
			if err != nil {
				return false, err
			}
			changed = changed || elementChanged
		}
	}
	return changed, nil
}

// diagnosticBase returns the key a diagnostic key belongs to.
func diagnosticBase(key string) (string, bool) {
	for _, suffix := range diagnosticSuffixes {
		if base, ok := strings.CutSuffix(key, suffix); ok && base != "" {
			return base, true
		}
	}
	return "", false
}

// maskDiagnostic decides value as if it were logged under base. A string is
// masked by base's rule, as the field itself was. Any other value, such as
// the array under keyCauses, is kept only when base passes a probe string
// unchanged, and becomes the marker otherwise: a partial rule cannot keep
// part of a structure. keep is false when the policy omits base.
func (r writer) maskDiagnostic(base, path string, value any) (masked any, keep bool, err error) {
	field := masker.Field{Key: base, Path: path, Source: masker.SourceJSON}
	text, isString := value.(string)
	if !isString {
		text = "diagnostic"
	}
	result, err := r.core.MaskField(field, text)
	if err != nil {
		return nil, false, err
	}
	switch {
	case result == nil:
		return nil, false, nil
	case isString:
		return result, true, nil
	case result == text:
		return value, true, nil
	default:
		return r.mark, true, nil
	}
}

// fallback is the line written when the payload cannot be masked: the
// redaction marker as the only field, so nothing of the original line
// remains. The line is shared between writes, so it is clipped: appending
// the newline copies it instead of writing into the shared array.
func (r writer) fallback() []byte {
	return slices.Clip(r.fallbackLine)
}

// fallbackLine builds the fallback line for mark once per writer.
func fallbackLine(mark string) []byte {
	encoded, err := json.Marshal(mark)
	if err != nil {
		encoded = []byte(`"[REDACTED]"`)
	}
	line := append([]byte(`{"message":`), encoded...)
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
