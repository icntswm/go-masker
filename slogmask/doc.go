// Package slogmask adapts masker to log/slog.
//
// ReplaceAttr returns a function for slog.HandlerOptions.ReplaceAttr that
// sends every attribute through a core masker before the handler writes it.
// Attributes inside groups are matched by their own key, and the policy sees
// the group names in the field path, for example $[req][token].
//
// The built-in time, level, message, and source attributes are passed through
// unchanged, and so is the log message text: keep secrets out of the message
// and pass them as attributes. A caller attribute that reuses one of these
// keys is masked unless its value has the built-in type: a top-level string
// attribute named msg cannot be told apart from the message. A masking
// failure writes the redaction marker, never the original value.
package slogmask
