// Package zerologmask adapts masker to github.com/rs/zerolog.
//
// zerolog serializes every field as it is added, and its hooks see the event
// before that serialization happens, so a hook cannot rewrite what reaches
// the output. Masking therefore happens on the output itself: NewWriter wraps
// the destination and masks every JSON line through a core masker before it
// is passed on. The package does not import zerolog, and any logger that
// writes one JSON object per line works, including log/slog's JSONHandler and
// zap's JSON encoder.
//
// Use it as the logger's writer:
//
//	logger := zerolog.New(zerologmask.NewWriter(os.Stdout, core))
//
// For human-readable output put the masking writer in front of
// ConsoleWriter, so the console formats an already masked line:
//
//	logger := zerolog.New(zerologmask.NewWriter(zerolog.ConsoleWriter{Out: os.Stdout}, core))
//
// Every Write must carry whole lines. zerolog, log/slog and zap write each
// record in one call; a record split across calls is replaced rather than
// buffered, because a buffered prefix would make the writer stateful.
//
// A writer that routes by level, such as zerolog's MultiLevelWriter, loses
// that routing when wrapped, because NewWriter implements io.Writer only:
// wrap each destination instead. Keys are masked by the policy like any JSON
// document; the message text itself is not inspected by key, so keep secrets
// out of the message. A line that is not a JSON document, or that exceeds the
// masker's input limit, is replaced by {"message":"<marker>"}: the original
// line is never written.
package zerologmask
