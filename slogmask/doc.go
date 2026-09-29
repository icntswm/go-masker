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
// The message is masked like a string attribute named msg: the policy decides
// it by that key, and the embedded-document and text inspection of the core
// searches it, so a password=... pair or a bearer token interpolated into the
// message is replaced. That is a safety net, so still pass secrets as
// attributes. The built-in time, level, and source attributes are passed
// through unchanged; a caller attribute that reuses one of these keys is
// masked unless its value has the built-in type. A masking failure writes the
// redaction marker, never the original value.
//
// A json.RawMessage attribute is logged as masked JSON, not as base64.
//
// Masking happens only in a handler that calls ReplaceAttr, such as
// slog.TextHandler and slog.JSONHandler. The default handler used before
// slog.SetDefault, and a third-party handler that ignores HandlerOptions,
// write attributes unmasked.
package slogmask
