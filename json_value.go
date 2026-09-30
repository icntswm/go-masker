package masker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// MaskJSONValue masks value as MaskAny does and returns the result encoded
// as JSON, without building the intermediate tree. Object keys are sorted,
// as encoding/json sorts map keys. With WithPreserveSafeTypes a safe number
// or boolean is written as a JSON number or boolean, a value of a named
// scalar type as its underlying value (its MarshalJSON method is never
// called), and a NaN or infinite float fails closed. On any error the
// result is the redaction marker encoded as JSON.
func (m *Masker) MaskJSONValue(value any) (result []byte, err error) {
	if m == nil {
		return []byte(`"[REDACTED]"`), fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer func() {
		if recover() != nil {
			result = m.safeJSONFallback()
			err = maskError(CodePanic, "mask", "$")
		}
	}()
	e := getJSONValueEmitter(m)
	defer putJSONValueEmitter(e)
	w := e.w
	if e.emit(reflect.ValueOf(value), Field{Path: "$", Source: SourceAny}, 0, "") {
		// An omitted root is null, as in MaskAny.
		e.enc.buf = append(e.enc.buf[:0], "null"...)
	}
	if err := aggregateErrors(w.errs); err != nil {
		return m.safeJSONFallback(), err
	}
	// The pooled buffer grew by doubling; the caller gets one copy of the
	// exact size, so a large document is not allocated several times over.
	return bytes.Clone(e.enc.buf), nil
}

// maxPooledJSONBuffer bounds the buffer an emitter keeps in the pool, so
// one huge document does not pin its memory for every later small one.
const maxPooledJSONBuffer = 4 << 20

// maxPooledScratch bounds each map-key scratch slice kept in the pool, for
// the same reason: a map with a raised WithMaxNodes must not leave its
// entries' backing array to every later small call.
const maxPooledScratch = 1 << 14

var jsonValueEmitters = sync.Pool{New: func() any { return new(jsonValueEmitter) }}

func getJSONValueEmitter(m *Masker) *jsonValueEmitter {
	e, ok := jsonValueEmitters.Get().(*jsonValueEmitter)
	if !ok {
		e = new(jsonValueEmitter)
	}
	e.walker = walker{masker: m, rootPath: "$"}
	e.w = &e.walker
	e.enc.buf = e.enc.buf[:0]
	return e
}

// putJSONValueEmitter returns the emitter to the pool. It runs deferred, also
// after a panic cut a map short, so it clears every scratch slice itself: a
// pooled emitter must pin no caller data.
func putJSONValueEmitter(e *jsonValueEmitter) {
	e.w = nil
	e.walker = walker{}
	for i := range e.entries {
		if cap(e.entries[i]) > maxPooledScratch {
			e.entries[i] = nil
			continue
		}
		clear(e.entries[i][:cap(e.entries[i])])
	}
	for i := range e.enc.keys {
		if cap(e.enc.keys[i]) > maxPooledScratch {
			e.enc.keys[i] = nil
			continue
		}
		clear(e.enc.keys[i][:cap(e.enc.keys[i])])
	}
	e.enc.deepKeys = nil
	if cap(e.enc.buf) > maxPooledJSONBuffer {
		e.enc.buf = nil
	}
	jsonValueEmitters.Put(e)
}

// jsonValueEmitter writes the masked JSON of one input tree into a single
// buffer: the walk's checks and decisions run through walker.enter and the
// shape is rendered directly, so no map[string]any or []any tree is built
// for encoding/json to walk a second time.
type jsonValueEmitter struct {
	w *walker
	// walker is the storage w points to, pooled with the emitter so a call
	// does not allocate one. Its slices start empty on every call: the errors
	// it collects escape in the returned error.
	walker  walker
	enc     jsonTreeEncoder
	entries [][]mapEntry
}

// mapEntry holds one pending map member while its key order is decided.
type mapEntry struct {
	key   string
	value reflect.Value
}

// emit appends the JSON of one node to enc.buf and reports that the node was
// omitted, so the caller can drop the key or member it belongs to.
func (e *jsonValueEmitter) emit(value reflect.Value, field Field, depth int, tag string) (omitted bool) {
	node, result, done := e.w.enter(value, field, depth, tag)
	if done {
		return e.appendResult(result, field, depth)
	}
	if node.textual {
		text, ok := e.w.renderText(node.value, node.field, depth)
		if !ok {
			e.w.releaseTracked(node.trackedStart)
			e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
			return false
		}
		if implementsTextMarshaler(node.value) && e.w.masker.inspectable(text) {
			if masked, changed := e.w.inspect(text, node.field, depth); changed {
				e.w.releaseTracked(node.trackedStart)
				e.enc.buf = appendJSONString(e.enc.buf, masked)
				return false
			}
		}
		e.w.releaseTracked(node.trackedStart)
		e.appendSafeScalar(reflect.ValueOf(text), node.field, depth)
		return false
	}
	var shapeOmitted bool
	switch node.value.Kind() {
	case reflect.Map:
		shapeOmitted = e.emitMap(node.value, node.field, depth)
	case reflect.Slice, reflect.Array:
		shapeOmitted = e.emitArray(node.value, node.field, depth)
	case reflect.Struct:
		shapeOmitted = e.emitStruct(node.value, node.field, depth)
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		shapeOmitted = e.emitScalar(node.value, node.field, depth)
	default:
		// dispatch fails the unsupported type and returns the marker.
		shapeOmitted = e.appendResult(e.w.dispatch(node, depth), node.field, depth)
	}
	e.w.releaseTracked(node.trackedStart)
	return shapeOmitted
}

// emitScalar writes a scalar dispatch would box, appending its JSON text
// directly instead.
func (e *jsonValueEmitter) emitScalar(value reflect.Value, field Field, depth int) (omitted bool) {
	if value.Kind() == reflect.String {
		if s, ok := e.w.masker.inspectableScalar(value); ok {
			if masked, changed := e.w.inspect(s, field, depth); changed {
				e.enc.buf = appendJSONString(e.enc.buf, masked)
				return false
			}
		}
	}
	e.appendSafeScalar(value, field, depth)
	return false
}

// appendResult encodes a final decision result, such as a rule's output, an
// embedded JSON tree, or a nil value, into the buffer. It reports that the
// result asked for the field to be omitted.
func (e *jsonValueEmitter) appendResult(result any, field Field, depth int) (omitted bool) {
	if isOmitted(result) {
		return true
	}
	switch result.(type) {
	case nil, bool, string, json.Number, map[string]any, []any:
		// objectDepth 0 reuses enc.keys[0], which is safe here: appendValue
		// finishes before this returns and emitMap nests into entries
		// instead of enc.keys, so recursion never re-enters the encoder.
		if !e.enc.appendValue(result, 0) {
			e.w.fail(CodeInvalidJSON, field, depth)
			e.enc.buf = append(e.enc.buf, "null"...)
		}
	default:
		// A concrete scalar returned under preserveSafe, or a named scalar
		// type a rule produced: its underlying value is written, and its
		// MarshalJSON is never called.
		e.appendSafeScalar(reflect.ValueOf(result), field, depth)
	}
	return false
}

// emitMap is the twin of mapValue: it decides the same children in the same
// order, sorted by key as encoding/json writes map keys, and appends the
// object text instead of building the map the result tree would box.
func (e *jsonValueEmitter) emitMap(value reflect.Value, field Field, depth int) (omitted bool) {
	if value.Type().Key().Kind() != reflect.String {
		e.w.fail(CodeUnsupportedKey, field, depth)
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
		return false
	}
	// Every child costs a node before any decision, so a map longer than the
	// remaining budget must fail: it fails here, before its entries are
	// copied and sorted, as mapValue stops at the first child over the limit.
	if value.Len() > e.w.masker.cfg.maxNodes-e.w.nodes {
		e.w.fail(CodeNodeLimit, field, depth)
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
		return false
	}
	for len(e.entries) <= depth {
		e.entries = append(e.entries, nil)
	}
	entries := e.entries[depth][:0]
	iter := value.MapRange()
	for iter.Next() {
		entries = append(entries, mapEntry{key: iter.Key().String(), value: iter.Value()})
	}
	slices.SortFunc(entries, func(a, b mapEntry) int { return strings.Compare(a.key, b.key) })
	buf := e.enc.buf
	buf = append(buf, '{')
	written := false
	for _, entry := range entries {
		if e.w.stop {
			break
		}
		childField := Field{Key: entry.key, Source: field.Source}
		if e.w.masker.cfg.needPaths {
			childField.Path = pathFor(field.Path, entry.key)
		}
		if childField.Source == SourceUnknown {
			childField.Source = SourceMap
		}
		mark := len(buf)
		if written {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, entry.key)
		buf = append(buf, ':')
		e.enc.buf = buf
		e.w.pushPath(entry.key)
		childOmitted := e.emit(entry.value, childField, depth+1, "")
		e.w.popPath()
		buf = e.enc.buf
		if childOmitted {
			// The key and its value vanish, exactly as mapValue drops them.
			buf = buf[:mark]
		} else {
			written = true
		}
	}
	buf = append(buf, '}')
	e.enc.buf = buf
	// The scratch is cleared so it does not pin caller data, and written
	// back so its capacity is kept for the next map at this depth.
	clear(entries)
	e.entries[depth] = entries
	return false
}

// emitArray is the twin of arrayValue.
func (e *jsonValueEmitter) emitArray(value reflect.Value, field Field, depth int) (omitted bool) {
	buf := e.enc.buf
	buf = append(buf, '[')
	for i := range value.Len() {
		if e.w.stop {
			break
		}
		childField := Field{Source: field.Source}
		if e.w.masker.cfg.needPaths {
			childField.Path = pathForIndex(field.Path, i)
		}
		if i > 0 {
			buf = append(buf, ',')
		}
		e.enc.buf = buf
		e.w.pushIndex(i)
		childOmitted := e.emit(value.Index(i), childField, depth+1, "")
		e.w.popPath()
		buf = e.enc.buf
		if childOmitted {
			// An omitted member of an array stays null, as MaskAny paints it.
			buf = append(buf, "null"...)
		}
	}
	buf = append(buf, ']')
	e.enc.buf = buf
	return false
}

// emitStruct is the twin of structValue: the fields are decided in the same
// order metadata.sorted gives, so the object written here is the encoding of
// the map the walker would return for the struct.
func (e *jsonValueEmitter) emitStruct(value reflect.Value, field Field, depth int) (omitted bool) {
	metadata := e.w.masker.structMetadata.load(value.Type(), e.w.masker.cfg.structTag, e.w.masker.cfg.tagRules, e.w.masker.policy)
	if !metadata.flatScalar {
		for _, conflict := range metadata.conflicts {
			for _, conflicting := range conflict.conflicting {
				conflictField := Field{Key: conflict.field, Source: SourceStruct}
				if e.w.masker.cfg.needPaths {
					conflictField.Path = pathFor(field.Path, conflict.field)
				}
				e.w.pushPath(conflict.field)
				e.w.failConflict(conflictField, conflicting)
				e.w.popPath()
			}
		}
	}
	buf := e.enc.buf
	buf = append(buf, '{')
	written := false
	for _, candidate := range metadata.sorted {
		if e.w.stop {
			break
		}
		childValue, ok := fieldByIndex(value, candidate.index)
		if !ok {
			continue
		}
		if candidate.jsonOmit || candidate.maskTag == "omit" {
			continue
		}
		childField := Field{Key: candidate.jsonName, Source: SourceStruct}
		if e.w.masker.cfg.needPaths {
			childField.Path = pathFor(field.Path, candidate.jsonName)
		}
		mark := len(buf)
		if written {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, candidate.jsonName)
		buf = append(buf, ':')
		e.enc.buf = buf
		e.w.pushPath(candidate.jsonName)
		var childOmitted bool
		if candidate.flatScalar {
			// A scalar field of a mixed struct takes the flat path, which
			// uses the decision compiled for its key instead of calling the
			// policy.
			childField.Kind = candidate.kind
			childOmitted = e.emitFlatScalar(childValue, childField, depth+1, candidate)
		} else {
			childOmitted = e.emit(childValue, childField, depth+1, candidate.maskTag)
		}
		e.w.popPath()
		buf = e.enc.buf
		if childOmitted {
			buf = buf[:mark]
		} else {
			written = true
		}
	}
	buf = append(buf, '}')
	e.enc.buf = buf
	return false
}

// emitFlatScalar is the twin of walkFlatScalar: the same checks in the same
// order, and the output is appended instead of boxed. A marker is written
// only after a failure was already recorded, and the caller discards the
// whole output when an error was recorded anywhere.
func (e *jsonValueEmitter) emitFlatScalar(value reflect.Value, field Field, depth int, metadata structFieldMetadata) (omitted bool) {
	if depth > e.w.masker.cfg.maxDepth {
		e.w.fail(CodeDepthLimit, field, depth)
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
		return false
	}
	e.w.nodes++
	if e.w.nodes > e.w.masker.cfg.maxNodes {
		e.w.fail(CodeNodeLimit, field, depth)
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
		return false
	}
	if value.Kind() == reflect.String && !utf8.ValidString(value.String()) {
		// enter rejects invalid UTF-8 before any decision; this fast path
		// must fail closed the same way.
		e.w.fail(CodeInvalidUTF8, field, depth)
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
		return false
	}
	if handled, decisionResult := e.w.applyCompiledFieldDecision(value, field, metadata, depth); handled {
		return e.appendResult(decisionResult, field, depth)
	}
	if value.Kind() == reflect.String {
		if s, ok := e.w.masker.inspectableScalar(value); ok {
			if masked, changed := e.w.inspect(s, field, depth); changed {
				e.enc.buf = appendJSONString(e.enc.buf, masked)
				return false
			}
		}
	}
	e.appendSafeScalar(value, field, depth)
	return false
}

// appendSafeScalar writes what safeScalar(value, preserveSafe, marker) would
// return, encoded as JSON text.
func (e *jsonValueEmitter) appendSafeScalar(value reflect.Value, field Field, depth int) {
	if !value.IsValid() {
		e.enc.buf = append(e.enc.buf, "null"...)
		return
	}
	if value.Type() == reflect.TypeOf(json.Number("")) {
		number := value.String()
		if validJSONNumber(number) {
			e.enc.buf = append(e.enc.buf, number...)
			return
		}
		e.w.fail(CodeInvalidJSON, field, depth)
		e.enc.buf = append(e.enc.buf, "null"...)
		return
	}
	preserve := e.w.masker.cfg.preserveSafe
	switch value.Kind() {
	case reflect.String:
		e.enc.buf = appendJSONString(e.enc.buf, value.String())
	case reflect.Bool:
		if preserve {
			if value.Bool() {
				e.enc.buf = append(e.enc.buf, "true"...)
			} else {
				e.enc.buf = append(e.enc.buf, "false"...)
			}
			return
		}
		if value.Bool() {
			e.enc.buf = append(e.enc.buf, `"true"`...)
		} else {
			e.enc.buf = append(e.enc.buf, `"false"`...)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if preserve {
			e.enc.buf = strconv.AppendInt(e.enc.buf, value.Int(), 10)
			return
		}
		e.enc.buf = append(e.enc.buf, '"')
		e.enc.buf = strconv.AppendInt(e.enc.buf, value.Int(), 10)
		e.enc.buf = append(e.enc.buf, '"')
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if preserve {
			e.enc.buf = strconv.AppendUint(e.enc.buf, value.Uint(), 10)
			return
		}
		e.enc.buf = append(e.enc.buf, '"')
		e.enc.buf = strconv.AppendUint(e.enc.buf, value.Uint(), 10)
		e.enc.buf = append(e.enc.buf, '"')
	case reflect.Float32, reflect.Float64:
		if preserve {
			encoded, ok := appendJSONFloat(e.enc.buf, value.Float(), value.Type().Bits())
			if !ok {
				// A NaN or infinite float fails closed, as json.Marshal of
				// the plain tree would.
				e.w.fail(CodeUnsupportedType, field, depth)
				e.enc.buf = append(e.enc.buf, "null"...)
				return
			}
			e.enc.buf = encoded
			return
		}
		e.enc.buf = append(e.enc.buf, '"')
		e.enc.buf = strconv.AppendFloat(e.enc.buf, value.Float(), 'g', -1, value.Type().Bits())
		e.enc.buf = append(e.enc.buf, '"')
	default:
		e.enc.buf = appendJSONString(e.enc.buf, e.w.masker.cfg.marker)
	}
}

// appendJSONFloat formats f the way encoding/json formats a float: 'f' unless
// the magnitude moves to an exponent, then 'e' with the exponent cleaned up.
// It reports false for NaN and infinity, which JSON cannot carry.
func appendJSONFloat(dst []byte, f float64, bits int) ([]byte, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return dst, false
	}
	abs := math.Abs(f)
	format := byte('f')
	if abs != 0 {
		if bits == 64 {
			if abs < 1e-6 || abs >= 1e21 {
				format = 'e'
			}
		} else if float32(abs) < 1e-6 || float32(abs) >= 1e21 {
			format = 'e'
		}
	}
	dst = strconv.AppendFloat(dst, f, format, -1, bits)
	if format == 'e' {
		// Clean up e-09 to e-9, as encoding/json does.
		n := len(dst)
		if n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst, true
}
