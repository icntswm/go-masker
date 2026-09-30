// Package adapter connects logger adapters to unexported masking code. The
// root package sets these functions in its init; the core is passed as any to
// avoid an import cycle.
package adapter

import "log/slog"

// Action is what an adapter does with a value.
type Action uint8

const (
	Keep    Action = iota // log the original value unchanged
	Replace               // log the returned text as a string
	Omit                  // drop the attribute
	Fail                  // log the redaction marker
)

var (
	// Scalar decides and masks a scalar slog value (KindString, KindInt64,
	// KindUint64, KindFloat64, KindBool, KindDuration, KindTime) of the
	// attribute key inside groups.
	Scalar func(core any, groups []string, key string, value slog.Value) (Action, string)
	// Group decides the enclosing groups of an attribute, outermost first,
	// and returns Keep when every group is kept, else Omit or Fail.
	Group func(core any, groups []string) Action
	// PreservesTypes reports whether the core was built with WithPreserveSafeTypes.
	PreservesTypes func(core any) bool
	// Text masks free text that no key names, such as a URL path, with the
	// core's embedded document checks and text detectors; no policy judges
	// it. Text with nothing to mask is returned as it is, without allocating.
	Text func(core any, path, text string) (string, error)
)
