# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow semantic versioning; while the major version is `0` the public
API may still change, and every such change is listed here.

## [Unreleased]

## [0.6.1] - 2026-09-30

### Added

- The default policy also recognizes `pwd`, `api_token`, `secret_key`,
  `secret_access_key`, `aws_secret_access_key`, `private_token`, `otp`,
  `x-api-token` and `x-access-token`.

### Changed

- A `[]byte` value is searched for secrets like a string when it holds valid
  UTF-8 text, and becomes the marker when one is found. The content of the
  byte slices and `json.RawMessage` values one operation encodes or decodes
  is bounded by `WithMaxInputBytes`; past it the slice becomes the marker and
  the operation reports `ErrInputLimit` instead of `ErrNodeLimit`.
- The path of an embedded URL is searched by the text detectors, so a token
  written into it, such as a JWT in a reset link, becomes the marker.
  `httpmask` masks the request path the same way.
- In a `key=value` pair of free text, a `,`, `;` or `&` ends the value only
  when whitespace, the end of the text or another pair follows it, so
  `password=foo,bar` no longer leaves `bar` behind.
- A token after `Bearer` made only of lowercase letters is treated as a
  credential once it is 20 characters or longer.
- A string is read as a form only when every key is a plain name and no value
  holds a raw `=`; text that fails the form grammar goes to the text
  detectors, and a form in which nothing was masked is searched by them too.
- Keys in the `Path` and `Field` of an error have credentials recognizable by
  shape redacted before they are formatted.
- `MaskJSONValue` pools its walker with the output buffer and allocates one
  object less per call: a flat struct takes 128 bytes in 3 allocations
  instead of 256 bytes in 4.

### Fixed

- The base64 form of a byte slice is no longer parsed as a form, which could
  exhaust the node limit on large slices.
- `jsonline` ends a record it replaced by the fallback with a newline, so a
  split record no longer runs into the next one.

## [0.6.0] - 2026-09-30

### Added

- `MaskJSONValue` masks a Go value as `MaskAny` does and returns the result
  as JSON, written directly without the intermediate `map[string]any` tree.
  The output is what `json.Marshal` gives for the `MaskAny` result, with
  sorted keys; masking a struct and encoding it takes about half the time and
  a third of the allocations. With `WithPreserveSafeTypes` a named scalar is
  written as its underlying value, never through its `MarshalJSON` method,
  and a NaN or infinite float fails closed.

### Changed

- `slogmask` is faster: a scalar attribute and each enclosing group are
  decided without the reflection walker, and a number is formatted only when a
  rule or a detector needs its text. A record with nested groups takes about a
  third of the time and an eighth of the memory it did in 0.5.0. The log
  output is unchanged.
- A struct that holds nested values masks its scalar fields through the same
  compiled path as a flat struct, so a wide record with one nested struct
  takes about a third less time.
- `MaskAny` allocates less: the redaction marker, booleans and small integers
  are boxed once, and array indexes enter a path only when one is read. A
  list of 10,000 records takes about a tenth less time and a third fewer
  allocations.

## [0.5.0] - 2026-09-30

### Added

- Documents inside string values are masked: when the policy leaves a string
  field alone and the whole string is an absolute URL, one JSON object or
  array, or a strict `key=value&…` form, its userinfo, fragment, query
  parameters and members are masked by their own keys, so a callback URL or a
  request body logged as a string no longer leaks the secrets inside it. This
  is on by default in every API and adapter; `WithoutEmbeddedDocuments()`
  turns it off. A string is rewritten only when something in it was masked.
- Secrets inside free text are masked: a string that is not a whole document,
  such as a log message, is searched for `key=value` and `key: value` pairs,
  whose key the policy judges under the new `SourceText`, and for secrets
  recognizable by shape: the credential after `Bearer` or `Basic`, PEM private
  key bodies, JWTs, provider tokens with a documented prefix and URL userinfo.
  Only the secret is replaced. The log message is searched too, in
  `slogmask`, `zerologmask` and `zapmask`. `WithCardNumberDetection()` and
  `WithAWSKeyIDDetection()` add opt-in detectors; `WithoutTextDetectors()`
  turns the detectors off and `WithoutValueInspection()` turns off both
  detectors and embedded documents.
- `zapmask` package: `NewWriteSyncer(w, core)` masks the JSON lines zap's JSON
  encoder writes, after encoding. It has the `Write` and `Sync` methods of
  `zapcore.WriteSyncer`, so it goes to `zapcore.NewCore` directly. A key zap
  writes next to a field, `keyVerbose`, `keyCauses` or `keyError`, is also
  decided as its base key, so `zap.NamedError("token", err)` cannot log the
  token's `%+v` text, a multi-error's parts or a panic message under a key the
  policy does not know. A console-encoder line is replaced by the marker line.

### Changed

- `slogmask` masks the record message as a string attribute named `msg`
  instead of passing it through, so the policy sees it at `$[msg]` and may
  mask or omit it. With a nil core the message is replaced by the marker.
  Time, level and source are still passed through.
- `zerologmask` and `zapmask` share one line-masking engine; `zerologmask`
  keeps its API and serves zerolog and any other logger writing one JSON
  object per line.

### Removed

- The `zapmask` module listed under 0.4.0, which was never tagged: its
  `NewCore` masked fields before encoding and needed zap as a dependency. The
  `zapmask` import path is now a package of this module, with no dependency;
  a build that pinned a pseudo-version of the old module must drop that
  requirement. The test-only `internal/zerologcompat` module is gone too, so
  the repository has a single `go.mod`.

### Fixed

- A struct embedded under an explicit JSON tag name is masked as one field
  under that name, as `encoding/json` writes it, instead of having its fields
  promoted and decided under their own keys.
- The flat-struct fast path fails closed with `ErrInvalidUTF8` on a string
  field holding invalid UTF-8, as the general walker does.
- A rule failure reported by `MaskJSON` carries the path of the value it
  failed on; two such failures at different paths are no longer merged.
- `httpmask` documentation states that a query parameter is masked by its
  key's rule, which may keep part of the value.
- `EmailRule` and `IDRule` no longer look up Unicode tables for every ASCII
  character when checking for control characters; `EmailRule` is about four
  times faster than in 0.4.0.

## [0.4.0] - 2026-09-29

### Added

- `zapmask` module (`github.com/icntswm/go-masker/zapmask`, versioned
  separately): `NewCore(inner, core)` wraps a zap core and masks context and
  call-site fields before any encoder sees them. A `zap.Namespace` is decided
  by the policy as an object, like a group in `slogmask`, and sampling and
  `Tee` levels of the inner core keep working. Its first release,
  `zapmask/v0.1.0`, requires this release.

### Changed

- Reflection traversal decodes a `json.RawMessage` and masks it by its keys
  like any other map, instead of rendering it as base64: `encoding/json`
  embeds such a value as is, and base64 hid nothing that decoding could not
  recover. The message and its members are decided with `SourceJSON`, as
  `MaskJSON` decides the same document. A message that is not a single valid
  JSON value fails closed with `ErrInvalidJSON`. `slogmask` logs it as masked
  JSON, and a nil or `null` message as `null`.
- `EmailRule` and `IDRule` redact in full a value holding a control or format
  character or a line separator, such as an escape sequence, a newline or a
  bidirectional override: they keep part of their input verbatim, and that
  part could rewrite a log line or a terminal.

### Fixed

- `slogmask` applies the policy to every enclosing group. `log/slog` never
  calls `ReplaceAttr` for a group itself, so a member of a group with a
  sensitive name, such as `slog.Group("credentials", "value", …)`,
  `WithGroup("token")` or a `LogValue` group under a sensitive key, was logged
  under its own harmless key. A masked or omitted group now replaces each
  member with the marker.
- `slogmask` logs the marker for an `Omit` decision inside a group instead of
  dropping the attribute: `log/slog` (Go 1.23 through 1.27) writes a broken
  line, invalid JSON or a following attribute moved into the group, when
  `ReplaceAttr` drops every member of a group. A top-level `Omit` still drops
  the attribute.
- Reflection traversal applies the policy and struct tags to a nil value, as
  `MaskJSON` does for `null`: `Omit` drops the key and a redacting rule logs
  the marker, where the key was kept as `nil` before.
- `MaskJSONReader` fails with `ErrInvalidJSON` on a reader that returns
  `(0, nil)` 100 times in a row, instead of spinning forever: such reads
  consume none of the input limit.
- A manual run of the provenance workflow must be started from the tag it
  names and fails otherwise, instead of archiving the branch it was started
  from and attesting that branch.
- A struct field whose JSON tag name `encoding/json` rejects, such as one with
  a backslash or a quote, fails closed with `ErrInvalidConfig` unless a mask
  tag decides it. Go 1.26 writes such a field under its Go name and Go 1.27
  under the name cut at the backslash or quote, so no single key is right.
  Before, a `Password` field whose tag name held a backslash was matched under
  that name and logged unmasked.
- `MaskField` and `MaskValue` decide an untyped nil through the policy instead
  of failing with `ErrPanic`; `slog.Any("k", nil)` logs `null`.
- The `Policy` documentation states that a policy must be deterministic.

## [0.3.0] - 2026-09-29

### Added

- `zerologmask` package: `NewWriter(w, core)` masks JSON log lines from
  zerolog (or any logger writing one JSON object per line) before they reach
  w, and replaces a line it cannot parse with the redaction marker. Each
  `Write` must carry whole lines; `Sync` is forwarded to w, so zap's
  `zapcore.AddSync` keeps flushing the real destination.

### Changed

- `MaskJSON` allocates less for small documents: the key cache no longer
  allocates for objects with few distinct keys, and unescaped keys stay off
  the heap. One log line drops from 27 to 11 allocations.

## [0.2.0] - 2026-09-29

### Added

- `WithTagRule(name, rule)` option registers a custom rule under the struct
  tag grammar; built-in names and `omit` cannot be redefined.
- `slogmask` package: `ReplaceAttr(core)` masks `log/slog` attributes through
  a core masker and fails closed to the redaction marker.

### Changed

- Key comparison ignores the `_`, `-`, and `.` separators in addition to
  Unicode case, so `accessToken` and `access-token` are masked like
  `access_token`; the default bindings gained `client_secret`, `id_token`,
  `private_key`, `session_id`, `credentials`, `auth_token`, `x-csrf-token`,
  `cvv`, and `cvc`.
- Reflection traversal masks an `encoding.TextMarshaler` as its text and a
  `[]byte` as base64, matching `encoding/json`, instead of walking their fields
  or bytes. `MarshalText` runs on a copy of the value; a marshaler that holds
  pointers, maps, or locks is walked as before.

### Fixed

- `WithMaxDepth` rejects depths above 10,000. With both the depth and node
  limits raised, deeply nested JSON overflowed the goroutine stack, which is a
  fatal error rather than a recoverable failure.
- `NewKeyPolicy` no longer panics when two fold-equivalent keys use a
  comparable Rule type holding a non-comparable value, such as a func in an
  interface field; such keys are rejected as duplicates.
- A struct field tagged `json:"-,"` is kept under the name `-`, as
  `encoding/json` does, instead of being dropped.

## [0.1.1] - 2026-08-28

No change to the library: the shipped code is identical to `v0.1.0`. This
release exists so that the supply-chain work around it has something to apply
to.

### Changed

- Every GitHub Action is pinned by commit SHA rather than by tag, so a moved
  tag cannot change what CI executes.
- `main` is protected: no force pushes, no deletion, linear history, and a
  merge waits for the tests, the matrix, the linter, the vulnerability scan
  and CodeQL.
- CI runs CodeQL, and publishes an OpenSSF Scorecard analysis.
- A release now carries a source archive and a SLSA attestation, so the
  archive can be traced to the workflow and the tag that produced it. The
  attestation is verified with `slsa-verifier`; see RELEASING.md.

## [0.1.0] - 2026-08-28

First tagged release.

### Added

- Fail-closed masking for reflection values, JSON, HTTP headers, and URLs.
- Configurable policies, built-in rules, struct tags, traversal limits, and
  typed error categories.
- Security golden fixtures, fuzz targets, benchmarks, race tests, and godoc
  examples.
- Threat model, security reporting guidance, and release documentation.
- Committed CI, lint configuration, package examples, and a concise current
  performance reference.

### Changed

- `httpmask` redacts the URL fragment by default. An OAuth implicit-flow token
  arrives in the fragment, so a library that fails closed should not need an
  opt-in to keep it out of a log. `WithMaskFragment` is replaced by
  `WithPreserveFragment`, which keeps the fragment when it carries client-side
  routing state a reader needs.
- A policy `Decision{Omit: true}` now drops an HTTP header value or a query
  parameter instead of failing the whole operation. A header whose every value
  is omitted is dropped as well, because an empty value list would still be
  serialized as a header.
- Bounded reflection result preallocation and pointer dereference work by the
  configured node budget.
- Added single-pass streaming JSON validation and depth/node enforcement.
- Reduced email-rule temporary allocations by removing `strings.Split`.
- Added a buffer-based safe-tree JSON encoder to reduce output allocations.
- Added a one-pass URL query parser/writer with duplicate-key preservation.
- Added diverse-key benchmark coverage with input immutability checks.
- Replaced the JSON object key bucket with a full-key hash and bounded its
  per-document cache and collision chains.
- Rejected empty policy chains and chains containing nil policies during
  `Masker` construction.
- Renamed public error values to idiomatic `Err*` names and reserved the
  `Code*` prefix for `ErrorCode` constants.
- Widened linting beyond the golangci-lint defaults, covering error wrapping,
  exhaustive switches, unchecked type assertions and spelling.
- Added a `govulncheck` job and ran every supported Go minor release in CI.
- Built reflection paths lazily when the configured policy never reads
  `Field.Path`, which removes about a third of the allocations on nested
  documents masked through a `KeyPolicy`. Error paths are unchanged.

### Fixed

- Escaped every unprintable rune and invalid UTF-8 in the key, path and field
  names that appear in error messages. A key is attacker-controlled, so a
  newline in one could previously split a log record and let a forged entry be
  injected; C1 controls, the `U+2028` and `U+2029` line separators, and bidi
  overrides could forge or disguise one just as well; a bare quote or backslash
  ends a logfmt value early, and a space starts a new logfmt field, so a key
  could contribute a field of the attacker's choosing. Diagnostics are also
  truncated so one oversized key cannot dominate the output.
- Populated `MaskError.Rule` on every rule failure, so a caller can tell which
  of several configured rules produced the fallback value. The field was
  documented and formatted but never set.
- Enforced the input limit in `MaskJSONReader` against a reader that returns
  `(0, nil)`. That return means "nothing happened", not end of input, so a
  document overrunning the limit was masked and the remainder discarded
  instead of being reported as `input_limit`.
- Bounded the query pair buffer that `httpmask` sizes from the separator
  count. A query of nothing but `&` turned four megabytes of input into a
  hundred and twenty-eight megabytes of scratch.
- Rejected malformed JSON object keys that previously could return the original
  unmasked value under a truncated key.
- Replaced recursive skipped-value scanning with an iterative state machine to
  prevent stack exhaustion on deeply nested input.
- Corrected depth-limit classification for valid JSON deeper than 10,000
  levels.
- Made `phone` and `card` fully redact short or ambiguous values, including
  values containing control characters or unexpected free text.
- Applied policy `Omit` consistently across maps, structs, JSON objects,
  arrays, and root values.
- Rejected invalid UTF-8 in reflection keys and string values.
- Matched `encoding/json` embedded-field promotion and same-depth tag rules.
- Detected conflicting fold-equivalent bindings by Rule identity rather than
  Rule name.
- Compared the reader's input-limit sentinel with `errors.Is`, so a wrapped
  error is reported as `input_limit` instead of `invalid_json`.
- Read `json.Number` scalars directly instead of asserting through
  `reflect.Value.Interface`, which panics on a value reached through an
  unexported field.
- Fell back to a fresh value instead of panicking if the buffer pool or the
  struct-metadata cache ever returned an unexpected type.

### Security

- Closed a log-injection path through masked keys and paths, and made the URL
  fragment redacted by default.
- Closed a JSON logging leak where malformed object keys exposed the original
  secret with `err == nil`.
- Added default masking for `x-api-key`, `x-auth-token`, and
  `proxy-authorization`.
- Added regression coverage for malformed input, deep nesting, wide objects,
  invalid UTF-8, and custom-rule binding conflicts.

### Documentation

- Settled the public module path `github.com/icntswm/go-masker` and added
  release, contribution and agent-facing documentation.

[Unreleased]: https://github.com/icntswm/go-masker/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/icntswm/go-masker/releases/tag/v0.6.1
[0.6.0]: https://github.com/icntswm/go-masker/releases/tag/v0.6.0
[0.5.0]: https://github.com/icntswm/go-masker/releases/tag/v0.5.0
[0.4.0]: https://github.com/icntswm/go-masker/releases/tag/v0.4.0
[0.3.0]: https://github.com/icntswm/go-masker/releases/tag/v0.3.0
[0.2.0]: https://github.com/icntswm/go-masker/releases/tag/v0.2.0
[0.1.1]: https://github.com/icntswm/go-masker/releases/tag/v0.1.1
[0.1.0]: https://github.com/icntswm/go-masker/releases/tag/v0.1.0
