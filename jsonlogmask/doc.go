// Package jsonlogmask masks the output of loggers that write one JSON object
// per line, such as zerolog, zap's JSON encoder and log/slog's JSONHandler.
//
// Such a logger serializes its fields before any hook could change them, so
// masking happens on the output itself: NewWriter wraps the destination and
// masks every JSON line through a core masker before it is passed on. The
// package imports no logging library, and the module keeps no third-party
// dependency.
//
// With zerolog, use it as the logger's writer:
//
//	logger := zerolog.New(jsonlogmask.NewWriter(os.Stdout, core))
//
// For human-readable output put the masking writer in front of
// ConsoleWriter, so the console formats an already masked line:
//
//	logger := zerolog.New(jsonlogmask.NewWriter(zerolog.ConsoleWriter{Out: os.Stdout}, core))
//
// With zap, use it as the write syncer of a core with a JSON encoder:
//
//	sink := zapcore.AddSync(jsonlogmask.NewWriter(os.Stdout, core))
//	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(cfg), sink, zap.InfoLevel))
//
// Fields added through With, a zap.Namespace, zap.Dict and zap.Any values are
// masked like any nested JSON object, and sampling keeps working because a
// sampled-out entry is never encoded. zap's console encoder does not write
// JSON, so every one of its lines is replaced. zap writes three diagnostic
// keys next to a field: keyVerbose for an error's %+v text, keyCauses for the
// errors of a multi-error and keyError for a panic while encoding the field.
// Each repeats the field's content, so a key with one of these suffixes is
// also decided as its base key: with the default policy tokenVerbose is
// masked because token is.
//
// Every Write must carry whole lines. zerolog, log/slog and zap write each
// record in one call, and zapcore.BufferedWriteSyncer flushes whole records;
// a record split across calls is replaced rather than buffered, because a
// buffered prefix would make the writer stateful.
//
// A writer that routes or filters by level, such as zerolog's
// MultiLevelWriter or FilteredLevelWriter, loses that when wrapped and
// receives every level, because NewWriter implements io.Writer only: wrap
// each destination instead. Keys are masked by the policy like any JSON
// document, and the re-encoded line lists them in sorted order; the message
// text itself is not inspected by key, so keep secrets out of the message.
// A line that is not a JSON document, or that exceeds the masker's input
// limit, is replaced by {"message":"<marker>"}: the original line is never
// written. zerolog built with the binary_log tag writes CBOR rather than
// JSON, so every line is replaced.
package jsonlogmask
