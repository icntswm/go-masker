# Security decision fixtures

Every `*.json` file in this directory is loaded by the golden runner in
`goldens_test.go`. A file is either a grouped set of cases
(`{"cases": [...]}`) or one legacy single-case object such as
`basic_json.json`.

Case schema:

```json
{
  "name": "short-case-name",
  "operation": "json",
  "options": {"max_depth": 1},
  "input": {"token": "synthetic-secret"},
  "output": {"token": "[REDACTED]"},
  "error_code": "optional_error_code",
  "error_expected": false
}
```

- `operation` is `json`, `json_error`, `headers`, or `url`.
  - `json`: `input` is the raw document passed to `MaskJSON`.
  - `json_error`: `input` is a JSON string; its content (possibly invalid)
    is the raw byte input to `MaskJSON`.
  - `headers`: object of header names to value lists; compared exactly.
  - `url`: raw URL string masked via `URLString`; compared as a string.
- `options` are optional: `max_depth`, `max_nodes`, `max_input_bytes` tune
  the core masker, `mask_fragment` enables paranoid fragment masking.
- `error_code` asserts a sentinel category through `errors.Is`. Use
  `error_expected: true` when the adapter reports an untyped error.
- On any failure the golden expectation is the safe fallback output.

Fixtures contain synthetic values only. Cases that cannot be expressed in
JSON — cycles, shared DAGs, struct tags and precedence — stay table-driven
in Go tests (`masker_test.go`, `adapter_test.go`).
