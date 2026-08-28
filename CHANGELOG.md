# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow semantic versioning; while the major version is `0` the public
API may still change, and every such change is listed here.

## [Unreleased]

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

- Escaped control characters and invalid UTF-8 in the key, path and field
  names that appear in error messages. A key is attacker-controlled, so a
  newline in one could previously split a log record and let a forged entry be
  injected. Diagnostics are also truncated so one oversized key cannot dominate
  the output.
- Populated `MaskError.Rule` on every rule failure, so a caller can tell which
  of several configured rules produced the fallback value. The field was
  documented and formatted but never set.
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
