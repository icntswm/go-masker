package slogmask

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"

	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/internal/adapter"
)

// ReplaceAttr returns a slog.HandlerOptions.ReplaceAttr function that masks
// every attribute through core.
//
// Scalar values keep their type when the policy leaves them unchanged, so a
// safe number is still logged as a number; a masked value is logged as a
// string. An error value is masked as its Error text. An Omit decision drops
// the attribute. The message is masked like a string attribute named msg, so
// the text detectors search it; the time, level, and source attributes are
// passed through. A nil core redacts everything else, the message included.
func ReplaceAttr(core *masker.Masker) func(groups []string, attr slog.Attr) slog.Attr {
	r := replacer{core: core, mark: masker.DefaultRedactionMarker}
	if core != nil {
		if mark, err := core.MaskString("", masker.FullRule()); err == nil && mark != "" {
			r.mark = mark
		}
	}
	return r.replace
}

type replacer struct {
	core *masker.Masker
	mark string
}

func (r replacer) replace(groups []string, attr slog.Attr) (result slog.Attr) {
	if len(groups) == 0 && builtinAttr(attr) {
		return attr
	}
	if attr.Equal(slog.Attr{}) {
		// Handlers discard the zero attribute, so it carries nothing to mask.
		return attr
	}
	// log/slog writes a broken line when ReplaceAttr drops every member of a
	// group and another attribute follows it, so a group member is never
	// dropped. Resolve runs caller LogValue methods and masking runs caller
	// rules, which may panic; a panic, like a drop inside a group, must still
	// keep the line whole: an Omit decision there logs the marker instead.
	defer func() {
		if recover() != nil {
			result = r.marker(attr.Key)
			return
		}
		if len(groups) > 0 && result.Equal(slog.Attr{}) {
			result = r.marker(attr.Key)
		}
	}()
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		// The handler calls ReplaceAttr for each member of the group.
		return attr
	}
	if r.core == nil {
		return r.marker(attr.Key)
	}
	// slog calls ReplaceAttr only for the members of a group, never for the
	// group itself, so without this a sensitive group name such as
	// credentials, whether from slog.Group, WithGroup or a LogValue result,
	// would never be decided and its members would be logged under their
	// own, harmless keys. A group the policy masks or omits replaces each
	// member with the marker.
	if len(groups) > 0 {
		switch adapter.Group(r.core, groups) {
		case adapter.Omit:
			return slog.Attr{}
		case adapter.Fail:
			return r.marker(attr.Key)
		}
	}
	switch value.Kind() {
	case slog.KindString, slog.KindInt64, slog.KindUint64, slog.KindFloat64,
		slog.KindBool, slog.KindDuration, slog.KindTime:
		return r.scalar(groups, attr.Key, value)
	case slog.KindAny:
		return r.any(groups, attr.Key, value)
	default:
		return r.marker(attr.Key)
	}
}

// scalar decides and masks a scalar value through the core's scalar entry,
// without the reflection walk of MaskField. When the policy leaves the text
// unchanged the original value is kept, so its type survives.
func (r replacer) scalar(groups []string, key string, value slog.Value) slog.Attr {
	action, text := adapter.Scalar(r.core, groups, key, value)
	switch action {
	case adapter.Keep:
		return slog.Attr{Key: key, Value: value}
	case adapter.Replace:
		return slog.String(key, text)
	case adapter.Omit:
		return slog.Attr{}
	default:
		return r.marker(key)
	}
}

func (r replacer) any(groups []string, key string, value slog.Value) slog.Attr {
	raw := value.Any()
	if err, ok := raw.(error); ok {
		return r.scalar(groups, key, slog.StringValue(err.Error()))
	}
	// json.Number is a numeric value in a named string type; the core masks
	// it as a number and keeps it a json.Number, so it stays a JSON number.
	if _, ok := raw.(json.Number); ok {
		return r.masked(key, raw, masker.Field{Key: key, Path: path(groups, key), Source: masker.SourceMap})
	}
	// slog reports named scalar types as KindAny. Their underlying value is
	// logged instead of the named one, so a custom MarshalJSON or String
	// method cannot put text into the log that the policy never saw.
	if basic, ok := basicScalar(raw); ok {
		return r.scalar(groups, key, basic)
	}
	return r.masked(key, raw, masker.Field{Key: key, Path: path(groups, key), Source: masker.SourceMap})
}

func (r replacer) masked(key string, raw any, field masker.Field) slog.Attr {
	masked, err := r.core.MaskField(field, raw)
	if err != nil {
		return r.marker(key)
	}
	if masked == nil && !isNil(raw) {
		return slog.Attr{}
	}
	if masked == nil && key == "" {
		// slog.Any("", nil) is the zero attribute, which handlers discard; a
		// typed nil without methods still logs as null.
		return slog.Any(key, (*struct{})(nil))
	}
	if !adapter.PreservesTypes(r.core) {
		return slog.Any(key, masked)
	}
	return slog.Any(key, plain(masked))
}

// plain replaces every named scalar in a masked result with its underlying
// value. WithPreserveSafeTypes keeps the concrete scalar type, and a handler
// would otherwise call its MarshalJSON or String method after masking.
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
		return basic.Any()
	}
	return masked
}

func (r replacer) marker(key string) slog.Attr { return slog.String(key, r.mark) }

// builtinAttr reports a record's own time, level, or source attribute. The
// value type is checked as well as the key, so a caller attribute that merely
// reuses one of these keys is still masked. The message is not listed: it is
// masked like any string attribute.
func builtinAttr(attr slog.Attr) bool {
	switch attr.Key {
	case slog.TimeKey:
		return attr.Value.Kind() == slog.KindTime
	case slog.LevelKey:
		_, ok := attr.Value.Any().(slog.Level)
		return attr.Value.Kind() == slog.KindAny && ok
	case slog.SourceKey:
		// A handler dereferences the source, and AddSource never sends nil.
		source, ok := attr.Value.Any().(*slog.Source)
		return attr.Value.Kind() == slog.KindAny && ok && source != nil
	}
	return false
}

// basicScalar converts a value of a named bool, integer, float, or string
// type to the slog value of its underlying type.
func basicScalar(raw any) (slog.Value, bool) {
	value := reflect.ValueOf(raw)
	switch value.Kind() {
	case reflect.Bool:
		return slog.BoolValue(value.Bool()), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return slog.Int64Value(value.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return slog.Uint64Value(value.Uint()), true
	case reflect.Float32, reflect.Float64:
		return slog.Float64Value(value.Float()), true
	case reflect.String:
		return slog.StringValue(value.String()), true
	default:
		return slog.Value{}, false
	}
}

// isNil reports a nil interface, or a pointer or interface chain that ends in
// nil, which masking normalizes to nil without an Omit decision. A nil map or
// slice is normalized to an empty container instead, so it does not count,
// but a json.RawMessage that is nil or holds null masks to nil like encoding/json
// logs it.
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
		return message == nil || string(bytes.TrimSpace(message)) == "null"
	}
	return false
}

func path(groups []string, key string) string {
	var builder strings.Builder
	builder.WriteByte('$')
	for _, group := range groups {
		builder.WriteString("[" + group + "]")
	}
	builder.WriteString("[" + key + "]")
	return builder.String()
}
