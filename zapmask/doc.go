// Package zapmask adapts masker to go.uber.org/zap.
//
// NewCore wraps a zapcore.Core and sends every field through a core masker
// before the inner core encodes it. Fields added through logger.With and
// fields logged at the call site are masked the same way, and the policy sees
// the zap.Namespace keys in the field path, for example $[req][token]. Each
// namespace is also decided as an object: a masked namespace, such as
// credentials, replaces every field written into it with the marker, and an
// omitted one drops them. Every encoder works, including the console encoder.
//
// Use it through zap.WrapCore, so the logger's own options keep working:
//
//	core, err := masker.New(masker.DefaultPolicy())
//	logger, err := zap.NewProduction(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
//		return zapmask.NewCore(c, core)
//	}))
//
// The inner core keeps deciding what is written. Sampling, level filtering and
// the branches of a zapcore.Tee still apply, because an entry is written
// through the inner core's own Check. The entry itself (message, logger name,
// caller, stack) is not masked: keep secrets out of the message and pass them
// as fields.
//
// A field that cannot be masked, or whose masking panics, is replaced by the
// redaction marker, never the original value. An error field is logged as its
// masked Error text; zap's errorVerbose detail is dropped, because it is text
// the policy never saw.
package zapmask
