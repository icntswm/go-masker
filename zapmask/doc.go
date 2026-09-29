// Package zapmask masks the JSON lines written by zap's JSON encoder.
//
// Masking happens after encoding: zap serializes its fields before any hook
// could change them, and the package masks every JSON line that leaves the
// core through a core masker before it is passed on. It does not mask fields
// before encoding and has no NewCore: a separate zapmask module is listed in
// the v0.4.0 notes, but it was never tagged and is gone. The package imports
// no zap package, and the module keeps no third-party dependency.
//
// Only the JSON encoder is supported. zap's console encoder does not write
// JSON, so every one of its lines is replaced by {"message":"<marker>"}: the
// original line is never written.
//
// Use it as the write syncer of a core with a JSON encoder:
//
//	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(cfg), zapmask.NewWriteSyncer(os.Stdout, core), zap.InfoLevel))
//
// Fields added through With, a zap.Namespace, zap.Dict and zap.Any values are
// masked like any nested JSON object, and sampling keeps working because a
// sampled-out entry is never encoded. zap writes three diagnostic keys next
// to a field: keyVerbose for an error's %+v text, keyCauses for the errors of
// a multi-error and keyError for a panic while encoding the field. Each
// repeats the field's content, so a key with one of these suffixes is also
// decided as its base key: with the default policy tokenVerbose is masked
// because token is.
//
// Every Write must carry whole lines. zap writes each record in one call, and
// zapcore.BufferedWriteSyncer flushes whole records; a record split across
// calls is replaced rather than buffered, because a buffered prefix would
// make the writer stateful. The re-encoded line lists its keys in sorted
// order. The message is searched by the core masker's text detectors like any
// other string; that is a safety net, so still pass secrets as fields.
package zapmask
