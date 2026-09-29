package masker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaskJSON masks exactly one JSON document and returns valid JSON on success.
func (m *Masker) MaskJSON(src []byte) (result []byte, err error) {
	if m == nil {
		return []byte(`"[REDACTED]"`), fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer m.recoverJSON(&result, &err)
	if int64(len(src)) > m.cfg.maxInputBytes {
		return m.safeJSONFallback(), maskError(CodeInputLimit, "mask_json", "$")
	}
	return m.maskJSON(src)
}

// MaskJSONReader reads, validates, masks, and encodes one JSON document.
// The reader is not closed and the complete input is held in memory.
func (m *Masker) MaskJSONReader(src io.Reader) (result []byte, err error) {
	if m == nil {
		return []byte(`"[REDACTED]"`), fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer m.recoverJSON(&result, &err)
	if src == nil {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	data, readErr := readLimited(src, m.cfg.maxInputBytes)
	if readErr != nil {
		if errors.Is(readErr, errInputLimit) {
			return m.safeJSONFallback(), maskError(CodeInputLimit, "mask_json", "$")
		}
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	return m.maskJSON(data)
}

func (m *Masker) maskJSON(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return m.safeJSONFallback(), maskError(CodeInvalidUTF8, "mask_json", "$")
	}
	return m.maskJSONStream(data)
}

// maskJSONDOM is a reference implementation used by streaming parity tests.
// Public JSON operations use maskJSONStream instead.
func (m *Masker) maskJSONDOM(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if decodeErr := decoder.Decode(&decoded); decodeErr != nil {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	var extra any
	if decodeErr := decoder.Decode(&extra); decodeErr != io.EOF {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}

	masked, maskErr := m.maskJSONRoot(decoded, Field{Path: "$", Source: SourceJSON, Kind: jsonValueKind(decoded)})
	if maskErr != nil {
		return m.safeJSONFallback(), maskErr
	}
	encoded, encodedOK := encodeJSONTree(masked, len(data))
	if !encodedOK {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	return encoded, nil
}

func (m *Masker) recoverJSON(result *[]byte, err *error) {
	if recover() != nil {
		*result, _ = json.Marshal(m.cfg.marker)
		*err = fmt.Errorf("%w: panic", errorSentinels[CodeInvalidJSON])
	}
}

var errInputLimit = fmt.Errorf("masker: input limit")

// maxEmptyReads is how many consecutive (0, nil) reads count as a stalled
// reader, the same bound bufio uses before it reports io.ErrNoProgress.
const maxEmptyReads = 100

// progressReader fails a reader that keeps returning (0, nil). Such a read
// consumes none of the input limit, so without this bound a hostile or broken
// reader would spin MaskJSONReader forever despite WithMaxInputBytes.
type progressReader struct {
	src io.Reader
}

func (r progressReader) Read(p []byte) (int, error) {
	for range maxEmptyReads {
		n, err := r.src.Read(p)
		if n > 0 || err != nil || len(p) == 0 {
			return n, err
		}
	}
	return 0, io.ErrNoProgress
}

func readLimited(src io.Reader, limit int64) ([]byte, error) {
	src = progressReader{src: src}
	data, err := io.ReadAll(io.LimitReader(src, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) < limit {
		return data, nil
	}
	// io.ReadFull rather than a bare Read: a Reader is allowed to return
	// (0, nil), which means "nothing happened", not end of input. Reading it as
	// EOF would accept a document that overruns the limit instead of rejecting
	// it, which is the one direction this package must never fail in.
	var probe [1]byte
	n, probeErr := io.ReadFull(src, probe[:])
	if n > 0 {
		return nil, errInputLimit
	}
	if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		return nil, probeErr
	}
	return data, nil
}

func (m *Masker) safeJSONFallback() []byte {
	result, err := json.Marshal(m.cfg.marker)
	if err != nil {
		return []byte(`"[REDACTED]"`)
	}
	return result
}
