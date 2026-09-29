// Package zerologmask masks the JSON lines written by zerolog, or by any
// other logger that writes one JSON object per line.
//
// zerolog serializes its fields before any hook could change them, so masking
// happens on the output itself: NewWriter wraps the destination and masks
// every JSON line through a core masker before it is passed on. The package
// imports no logging library, and the module keeps no third-party dependency.
//
// With zerolog, use it as the logger's writer:
//
//	logger := zerolog.New(zerologmask.NewWriter(os.Stdout, core))
//
// For human-readable output put the masking writer in front of
// ConsoleWriter, so the console formats an already masked line:
//
//	logger := zerolog.New(zerologmask.NewWriter(zerolog.ConsoleWriter{Out: os.Stdout}, core))
//
// The writer also serves any other logger that writes one JSON object per
// line; log/slog users should prefer
// [github.com/icntswm/go-masker/slogmask], which masks attributes before the
// handler writes them.
//
// Every Write must carry whole lines. zerolog writes each record in one call;
// a record split across calls is replaced rather than buffered, because a
// buffered prefix would make the writer stateful.
//
// A writer that routes or filters by level, such as zerolog's
// MultiLevelWriter or FilteredLevelWriter, loses that when wrapped and
// receives every level, because NewWriter implements io.Writer only: wrap
// each destination instead. Keys are masked by the policy like any JSON
// document, and the re-encoded line lists them in sorted order. The message
// is searched by the core masker's text detectors like any other string,
// which catches a password=... or Bearer token written into it; that is a
// safety net, so still pass secrets as fields.
// A line that is not a JSON document, or that exceeds the masker's input
// limit, is replaced by {"message":"<marker>"}: the original line is never
// written. zerolog built with the binary_log tag writes CBOR rather than
// JSON, so every line is replaced.
package zerologmask
