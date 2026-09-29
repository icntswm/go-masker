// Package slogmask adapts masker to log/slog.
//
// ReplaceAttr returns a function for slog.HandlerOptions.ReplaceAttr that
// sends every attribute through a core masker before the handler writes it.
// Attributes inside groups are matched by their own key, and the policy sees
// the group names in the field path, for example $[req][token]. Each group is
// also decided as an object first, because slog never passes a group itself
// to ReplaceAttr: a masked or omitted group replaces every member with the
// marker. An Omit decision drops a top-level attribute but logs the marker
// inside a group, because log/slog writes a broken line when ReplaceAttr drops
// every member of a group and another attribute follows it.
//
// The built-in time, level, message, and source attributes are passed through
// unchanged, and so is the log message text: keep secrets out of the message
// and pass them as attributes. A caller attribute that reuses one of these
// keys is masked unless its value has the built-in type: a top-level string
// attribute named msg cannot be told apart from the message. A masking
// failure writes the redaction marker, never the original value.
//
// A json.RawMessage attribute is logged as masked JSON, not as base64.
//
// Masking happens only in a handler that calls ReplaceAttr, such as
// slog.TextHandler and slog.JSONHandler. The default handler used before
// slog.SetDefault, and a third-party handler that ignores HandlerOptions,
// write attributes unmasked.
package slogmask
