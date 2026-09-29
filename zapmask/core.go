package zapmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	masker "github.com/icntswm/go-masker"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewCore returns a zapcore.Core that masks every field through core before
// inner encodes it. Both the logger context and the call-site fields are
// masked, under the path they will have in the encoded output, and the result
// works with every encoder, including the console encoder. The entry itself is
// not masked: keep secrets out of the message and pass them as fields. A nil
// core redacts every field.
func NewCore(inner zapcore.Core, core *masker.Masker) zapcore.Core {
	if inner == nil {
		return zapcore.NewNopCore()
	}
	m := maskCore{inner: inner, core: core, mark: masker.DefaultRedactionMarker, prefix: "$"}
	if core != nil {
		if mark, err := core.MaskString("", masker.FullRule()); err == nil && mark != "" {
			m.mark = mark
		}
	}
	return &m
}

// maskCore wraps an inner core and masks every field it is asked to write. It
// is immutable after construction, so one core is safe for concurrent use.
type maskCore struct {
	inner zapcore.Core
	core  *masker.Masker
	// mark is the redaction marker the core is configured with.
	mark string
	// prefix is the path of the namespaces opened by earlier With calls, such
	// as $[req]; it is part of the path of every later field.
	prefix string
	// verdict is what the policy decided for those namespaces.
	verdict verdict
}

// verdict is the policy's decision for an open namespace, which applies to
// every field written into it.
type verdict uint8

const (
	keepFields   verdict = iota // each field is masked by its own key
	redactFields                // each field becomes the marker
	omitFields                  // each field is dropped
)

// Enabled reports whether the inner core logs the level.
func (c *maskCore) Enabled(level zapcore.Level) bool { return c.inner.Enabled(level) }

// Level returns the inner core's minimum enabled level, so zap.Logger.Level
// and zapcore.LevelOf report the level a caller would see without masking.
func (c *maskCore) Level() zapcore.Level { return zapcore.LevelOf(c.inner) }

// With returns a core that masks the given fields into its context and keeps
// the namespaces they open, so every later field is masked under the path and
// the decision those namespaces give it.
func (c *maskCore) With(fields []zapcore.Field) zapcore.Core {
	masked, prefix, verdict := c.mask(fields)
	return &maskCore{inner: c.inner.With(masked), core: c.core, mark: c.mark, prefix: prefix, verdict: verdict}
}

// Check adds the masking core to the checked entry when the level is enabled.
// The inner core is deliberately not added here: it is checked again in Write,
// after the fields are masked, so an unmasked field can never reach it.
func (c *maskCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write masks the fields and writes the entry through the inner core's own
// Check. The inner Check is what keeps sampling and the per-branch levels of a
// Tee working: zap.NewProduction applies zap.WrapCore on top of its sampler,
// so writing past the inner Check would silently disable sampling, and a
// Tee's Write writes to every branch regardless of its level.
func (c *maskCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	masked, _, _ := c.mask(fields)
	checked := c.inner.Check(ent, nil)
	if checked == nil {
		return nil
	}
	// CheckedEntry.Write reports an inner write error only through its
	// ErrorOutput, and the outer entry reports what Write returns to the
	// logger's own ErrorOutput, so the printed text is captured here and
	// returned as the error.
	var sink errorSink
	checked.ErrorOutput = &sink
	checked.Write(masked...)
	// checked has returned to zap's pool and must not be touched from here on.
	return sink.err()
}

// Sync flushes the inner core.
func (c *maskCore) Sync() error { return c.inner.Sync() }

// mask returns the masked form of fields without modifying the caller's
// slice: the input is returned unchanged when no field changed, and a new
// slice is allocated only when the first field changes. A namespace opened
// inside fields holds for every field after it; mask also returns the path
// and the decision in force after the last field, for With.
func (c *maskCore) mask(fields []zapcore.Field) ([]zapcore.Field, string, verdict) {
	prefix, verdict := c.prefix, c.verdict
	result := fields
	changed := false
	for i, field := range fields {
		if field.Type == zapcore.NamespaceType {
			if verdict == keepFields {
				verdict = c.namespace(prefix, field.Key)
			}
			prefix = path(prefix, field.Key)
			continue
		}
		if field.Type == zapcore.SkipType {
			continue
		}
		var masked zapcore.Field
		replace := true
		switch verdict {
		case keepFields:
			masked, replace = c.masked(field, prefix)
		case redactFields:
			masked = c.marker(field.Key)
		case omitFields:
			masked = zap.Skip()
		}
		if !replace {
			continue
		}
		if !changed {
			changed = true
			result = append([]zapcore.Field(nil), fields...)
		}
		result[i] = masked
	}
	return result, prefix, verdict
}

// namespace applies the policy to a namespace as an object. zap writes the
// fields after zap.Namespace into it, so without this a namespace named like a
// secret, such as credentials, would never be decided and its fields would be
// logged under their own, harmless keys.
func (c *maskCore) namespace(prefix, key string) (result verdict) {
	defer func() {
		if recover() != nil {
			result = redactFields
		}
	}()
	if c.core == nil {
		return redactFields
	}
	field := masker.Field{Key: key, Path: path(prefix, key), Source: masker.SourceMap, Kind: masker.KindObject}
	masked, err := c.core.MaskField(field, map[string]any{})
	switch masked.(type) {
	case map[string]any:
		if err == nil {
			return keepFields
		}
	case nil:
		if err == nil {
			return omitFields
		}
	}
	return redactFields
}

// masked masks one field and reports the field to log in its place, with
// replace reporting that the original field did not survive unchanged. Every
// path runs caller code: rules run through the masker, and Stringer and
// marshaler fields run their methods here, so a panic anywhere becomes the
// marker field and the sibling fields are still masked.
func (c *maskCore) masked(field zapcore.Field, prefix string) (result zapcore.Field, replace bool) {
	defer func() {
		if recover() != nil {
			result = c.marker(field.Key)
			replace = true
		}
	}()
	if c.core == nil {
		return c.marker(field.Key), true
	}
	mf := masker.Field{Key: field.Key, Path: path(prefix, field.Key), Source: masker.SourceMap}
	switch field.Type {
	case zapcore.StringType:
		return c.scalar(field, mf, masker.KindString, field.String, true)
	case zapcore.ByteStringType:
		bytes, ok := field.Interface.([]byte)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, string(bytes), true)
	case zapcore.BoolType:
		return c.scalar(field, mf, masker.KindBool, strconv.FormatBool(field.Integer == 1), true)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		return c.scalar(field, mf, masker.KindNumber, strconv.FormatInt(field.Integer, 10), true)
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type, zapcore.UintptrType:
		return c.scalar(field, mf, masker.KindNumber, strconv.FormatUint(uint64(field.Integer), 10), true) //nolint:gosec // G115: zap stores an unsigned value's bits in Integer.
	case zapcore.Float64Type:
		value := math.Float64frombits(uint64(field.Integer)) //nolint:gosec // G115: zap stores the float's bits in Integer.
		return c.scalar(field, mf, masker.KindNumber, strconv.FormatFloat(value, 'g', -1, 64), true)
	case zapcore.Float32Type:
		value := float64(math.Float32frombits(uint32(field.Integer))) //nolint:gosec // G115: zap stores the float's bits in Integer.
		return c.scalar(field, mf, masker.KindNumber, strconv.FormatFloat(value, 'g', -1, 32), true)
	case zapcore.DurationType:
		// A duration is an int64 of nanoseconds, the way the core and the
		// encoders both treat time.Duration.
		return c.scalar(field, mf, masker.KindNumber, strconv.FormatInt(field.Integer, 10), true)
	case zapcore.TimeType:
		t := time.Unix(0, field.Integer)
		if location, ok := field.Interface.(*time.Location); ok && location != nil {
			t = t.In(location)
		}
		return c.scalar(field, mf, masker.KindString, t.Format(time.RFC3339Nano), true)
	case zapcore.TimeFullType:
		t, ok := field.Interface.(time.Time)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, t.Format(time.RFC3339Nano), true)
	case zapcore.Complex128Type:
		value, ok := field.Interface.(complex128)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, fmt.Sprint(value), true)
	case zapcore.Complex64Type:
		value, ok := field.Interface.(complex64)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, fmt.Sprint(value), true)
	case zapcore.StringerType:
		// A Stringer is never kept in its original field: String could differ
		// on a second call, and the encoder would run it after masking.
		stringer, ok := field.Interface.(fmt.Stringer)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, stringer.String(), false)
	case zapcore.ErrorType:
		// The error is logged as its masked Error text, and never in its
		// original field, so zap's errorVerbose detail is dropped: it is text
		// the policy never saw.
		err, ok := field.Interface.(error)
		if !ok || err == nil {
			// zap.Error turns a nil error into a skipped field, so an
			// ErrorType field without an error is a caller mistake and fails
			// closed.
			return c.marker(field.Key), true
		}
		return c.scalar(field, mf, masker.KindString, err.Error(), false)
	case zapcore.BinaryType:
		bytes, ok := field.Interface.([]byte)
		if !ok {
			return c.marker(field.Key), true
		}
		return c.maskedAny(field, mf, bytes)
	case zapcore.ReflectType:
		return c.maskedAny(field, mf, field.Interface)
	case zapcore.ObjectMarshalerType:
		obj, ok := field.Interface.(zapcore.ObjectMarshaler)
		if !ok {
			return c.marker(field.Key), true
		}
		// The marshaler runs caller code and is run once, so its result is
		// masked and re-encoded instead of calling it again in the encoder.
		enc := zapcore.NewMapObjectEncoder()
		if err := obj.MarshalLogObject(enc); err != nil {
			return c.marker(field.Key), true
		}
		return c.maskedAny(field, mf, enc.Fields)
	case zapcore.ArrayMarshalerType:
		arr, ok := field.Interface.(zapcore.ArrayMarshaler)
		if !ok {
			return c.marker(field.Key), true
		}
		enc := zapcore.NewMapObjectEncoder()
		if err := enc.AddArray("v", arr); err != nil {
			return c.marker(field.Key), true
		}
		return c.maskedAny(field, mf, enc.Fields["v"])
	case zapcore.InlineMarshalerType:
		return c.maskedInline(field, prefix)
	default:
		return c.marker(field.Key), true
	}
}

// scalar masks the text form of a field under its kind. When the policy
// leaves the text unchanged the original field is kept, so its type survives,
// unless keep is false: a Stringer or an error re-rendered by the encoder
// could differ from the text that was masked, so the masked text is logged
// instead.
func (c *maskCore) scalar(field zapcore.Field, mf masker.Field, kind masker.ValueKind, text string, keep bool) (zapcore.Field, bool) {
	mf.Kind = kind
	masked, err := c.core.MaskField(mf, text)
	if err != nil {
		return c.marker(field.Key), true
	}
	if masked == nil {
		return zap.Skip(), true
	}
	maskedText, ok := masked.(string)
	switch {
	case !ok:
		return c.marker(field.Key), true
	case maskedText == text && maskedText != c.mark && keep:
		// A marker that happens to equal the text is still a redaction: the
		// original value could render differently, as a duration does.
		return field, false
	default:
		return zap.String(field.Key, maskedText), true
	}
}

// maskedAny masks an arbitrary value the way a reflected map member is
// masked. An Omit decision drops the field, but a value that is nil anyway is
// still logged as null.
func (c *maskCore) maskedAny(field zapcore.Field, mf masker.Field, raw any) (zapcore.Field, bool) {
	masked, err := c.core.MaskField(mf, maskInput(raw))
	if err != nil {
		return c.marker(field.Key), true
	}
	if masked == nil && !isNil(raw) {
		return zap.Skip(), true
	}
	if maskedText, ok := masked.(string); ok {
		return zap.String(field.Key, maskedText), true
	}
	return zap.Reflect(field.Key, plain(masked)), true
}

// maskedInline masks the members an inline marshaler writes as if each were a
// separate field of the current namespace, because zap writes them into the
// enclosing object. An Omit decision drops a member, and a member that cannot
// be masked becomes the marker text.
func (c *maskCore) maskedInline(field zapcore.Field, prefix string) (zapcore.Field, bool) {
	obj, ok := field.Interface.(zapcore.ObjectMarshaler)
	if !ok {
		return c.marker(field.Key), true
	}
	enc := zapcore.NewMapObjectEncoder()
	if err := obj.MarshalLogObject(enc); err != nil {
		return c.marker(field.Key), true
	}
	members := make(map[string]any, len(enc.Fields))
	for key, value := range enc.Fields {
		member := masker.Field{Key: key, Path: path(prefix, key), Source: masker.SourceMap}
		masked, err := c.core.MaskField(member, maskInput(value))
		if err != nil {
			members[key] = c.mark
			continue
		}
		if masked == nil {
			if isNil(value) {
				members[key] = nil
			}
			continue
		}
		members[key] = plain(masked)
	}
	return zap.Inline(maskedObject(members)), true
}

// maskedObject writes the masked members of an inline marshaler. Members are
// written in sorted key order and omitted members are absent, so an inline
// field can neither leak a member nor depend on map iteration order.
type maskedObject map[string]any

// MarshalLogObject implements zapcore.ObjectMarshaler.
func (m maskedObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if err := enc.AddReflected(key, m[key]); err != nil {
			return err
		}
	}
	return nil
}

func (c *maskCore) marker(key string) zapcore.Field { return zap.String(key, c.mark) }

// plain replaces every named scalar in a masked result with its underlying
// value. WithPreserveSafeTypes keeps the concrete scalar type, and the
// encoder would otherwise call its MarshalJSON or String method after masking.
func plain(masked any) any {
	switch typed := masked.(type) {
	case nil, string, bool, int64, uint64, float64, json.Number:
		return masked
	case map[string]any:
		for key, value := range typed {
			typed[key] = plain(value)
		}
		return typed
	case []any:
		for index, value := range typed {
			typed[index] = plain(value)
		}
		return typed
	}
	if basic, ok := basicScalar(masked); ok {
		return basic
	}
	return masked
}

// basicScalar converts a value of a named bool, integer, float, or string
// type to the value of its underlying type.
func basicScalar(raw any) (any, bool) {
	value := reflect.ValueOf(raw)
	switch value.Kind() {
	case reflect.Bool:
		return value.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint(), true
	case reflect.Float32, reflect.Float64:
		return value.Float(), true
	case reflect.String:
		return value.String(), true
	default:
		return nil, false
	}
}

// isNil reports a nil interface, or a pointer or interface chain that ends in
// nil, which masking normalizes to nil without an Omit decision. A nil map or
// slice is normalized to an empty container instead, so it does not count.
func isNil(raw any) bool {
	if raw == nil {
		return true
	}
	value := reflect.ValueOf(raw)
	var seen map[uintptr]struct{}
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return true
		}
		if value.Kind() == reflect.Pointer {
			// A pointer cycle such as `type P *P` never ends in nil.
			if seen == nil {
				seen = map[uintptr]struct{}{}
			}
			if _, cycle := seen[value.Pointer()]; cycle {
				return false
			}
			seen[value.Pointer()] = struct{}{}
		}
		value = value.Elem()
	}
	if message, ok := value.Interface().(json.RawMessage); ok {
		// The core masks a json.RawMessage that is nil or holds null to nil,
		// as encoding/json logs it.
		return message == nil || string(bytes.TrimSpace(message)) == "null"
	}
	return false
}

// maskInput passes an untyped nil, such as the value of zap.Any("k", nil), as
// a typed nil pointer: the core masks either to nil, but older core releases
// reject the untyped form as unsupported and would log the marker for null.
func maskInput(raw any) any {
	if raw == nil {
		return (*struct{})(nil)
	}
	return raw
}

// path joins a namespace prefix and a key into the bracketed form the
// diagnostics use, for example $[req][token].
func path(prefix string, key string) string {
	return prefix + "[" + key + "]"
}

// errorSink records the text CheckedEntry.Write prints on a write error.
//
// CheckedEntry.Write reports an inner write error only through its
// ErrorOutput, and the outer entry reports what maskCore.Write returns to the
// logger's own ErrorOutput, so the printed text is recorded here and returned
// as the error.
type errorSink struct {
	text []byte
}

// Write implements zapcore.WriteSyncer.
func (s *errorSink) Write(p []byte) (int, error) {
	s.text = append(s.text, p...)
	return len(p), nil
}

// Sync implements zapcore.WriteSyncer.
func (s *errorSink) Sync() error { return nil }

// err returns the recorded write error, or nil when nothing was printed. The
// trailing newline of the printed text is dropped.
func (s *errorSink) err() error {
	if len(s.text) == 0 {
		return nil
	}
	return errors.New(strings.TrimSuffix(string(s.text), "\n"))
}
