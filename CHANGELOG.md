# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases will follow semantic versioning once the public import path is
chosen.

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

### Fixed

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

### Security

- Closed a JSON logging leak where malformed object keys exposed the original
  secret with `err == nil`.
- Added default masking for `x-api-key`, `x-auth-token`, and
  `proxy-authorization`.
- Added regression coverage for malformed input, deep nesting, wide objects,
  invalid UTF-8, and custom-rule binding conflicts.

### Documentation

- Added the public `github.com/icntswm/go-masker` module path, usage guide, FAQ,
  and release documentation.
