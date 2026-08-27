# go-masker

[![Go Reference](https://pkg.go.dev/badge/github.com/icntswm/go-masker.svg)](https://pkg.go.dev/github.com/icntswm/go-masker)
[![CI](https://github.com/icntswm/go-masker/actions/workflows/ci.yml/badge.svg)](https://github.com/icntswm/go-masker/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/icntswm/go-masker)](LICENSE)

`go-masker` is a Go library for fail-closed masking of sensitive data before
it reaches logs, diagnostics, traces, or other observability systems.

One `MaskJSON` call on a payload, with the default policy and no configuration:

| Field | In | Out |
| --- | --- | --- |
| `password` | `hunter2` | `[REDACTED]` |
| `card` | `4111 1111 1111 1111` | `**** **** **** 1111` |
| `email` | `alice@example.com` | `a***@example.com` |
| `user_id` | `884213` | `**4213` |
| `amount` | `1499` | `1499` |

Each field got the treatment its name implies, `amount` was left alone, and
nothing had to be listed by hand.

It provides one policy and rule model for:

- strings and scalar values;
- arbitrary nested Go values;
- JSON documents and readers;
- struct tags;
- HTTP headers and URLs through `httpmask`.

The core has no third-party runtime dependencies and does not depend on an HTTP
framework or logging library.

## Why a library instead of a field filter

A list of field names in a logger config covers the fields you remembered, at
the depth you remembered them. This library is built around the cases that
list misses:

- **Errors never fall back to the input.** Every operation returns a safe
  marker on failure. A filter that errors typically logs the raw value, which
  is the moment you needed it least.
- **Depth is not special.** The same policy applies to a nested JSON object, a
  struct field, a map inside a slice, a URL query parameter and an HTTP header.
- **Hostile input stays bounded.** Traversal depth, visited nodes and input
  size are capped; JSON is scanned iteratively, so deeply nested input cannot
  exhaust the goroutine stack.
- **Output does not drift.** Masking a fixed corpus under Go 1.23 through 1.27
  produces byte-identical results; the digests are recorded in
  [PERFORMANCE.md](PERFORMANCE.md).

It is not a substitute for not collecting the secret in the first place, and it
cannot prove that a custom rule you wrote is safe.

## Table of contents

- [Why a library instead of a field filter](#why-a-library-instead-of-a-field-filter)
- [Supported Go versions](#supported-go-versions)
- [Installation](#installation)
- [Quick start](#quick-start)
- [What is masked](#what-is-masked)
- [Core concepts](#core-concepts)
- [JSON](#json)
- [Struct tags](#struct-tags)
- [HTTP headers and URLs](#http-headers-and-urls)
- [Errors and fail-closed behavior](#errors-and-fail-closed-behavior)
- [Limits and security](#limits-and-security)
- [Performance](#performance)
- [Documentation map](#documentation-map)
- [Compatibility and stability](#compatibility-and-stability)
- [Contributing](#contributing)
- [License](#license)

## Supported Go versions

The library requires Go 1.23 or newer and uses only the standard library. The
CI workflow runs the tests, the race suite, the correctness matrix, and a fuzz
smoke pass on every supported minor release — 1.23.x, 1.24.x, 1.25.x, 1.26.x,
1.27.x — plus `stable`, so a new Go release is covered on the day it ships.

## Installation

```text
go get github.com/icntswm/go-masker
```

Import the core package as `masker`:

```go
import "github.com/icntswm/go-masker"
```

The HTTP adapter is a separate package:

```go
import "github.com/icntswm/go-masker/httpmask"
```

## Quick start

```go
package main

import (
	"fmt"

	"github.com/icntswm/go-masker"
)

func main() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	value, err := m.MaskValue("password", "correct-horse-battery-staple")
	if err != nil {
		panic(err)
	}
	fmt.Println(value)
	// Output: [REDACTED]
}
```

`Masker` instances are immutable and safe for concurrent use after successful
construction. Operations copy input containers and never mutate the source.

## What is masked

`DefaultPolicy` matches complete field names case-insensitively. Its default
bindings are:

| Keys | Rule |
| --- | --- |
| `password`, `passwd`, `passphrase` | full |
| `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `secret` | token |
| `email`, `e-mail` | email |
| `phone`, `phone_number`, `mobile` | phone |
| `id`, `user_id`, `customer_id` | ID |
| `card`, `card_number`, `pan` | card |
| `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `proxy-authorization` | full |

Built-in rules are available directly through `PasswordRule`, `TokenRule`,
`FullRule`, `EmailRule`, `PhoneRule`, `IDRule`, and `CardRule`.

Partial rules preserve only a deliberately limited safe shape. Short or
ambiguous phone/card values and values containing unexpected text are fully
redacted.

## Core concepts

Policies decide whether a field should be masked; rules transform the selected
scalar value. A policy can be assembled from bindings or written as a function:

```go
policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
	if field.Key == "tax_id" {
		return masker.Decision{Rule: masker.FullRule()}, nil
	}
	return masker.Decision{}, nil
})

m, err := masker.New(masker.Chain(masker.DefaultPolicy(), policy))
```

Policies in a `Chain` are evaluated in order. The first policy that gives an
opinion wins. `New` rejects empty chains and chains containing nil policies.

A zero `Decision` means "no opinion". `Decision{Omit: true}` removes an object
or map member entirely; array elements keep their position and become `null`,
so the shape of a list is never altered.

`NewKeyPolicy` rejects empty keys, nil rules, and fold-equivalent keys bound to
different rules, so an ambiguous configuration fails at construction instead of
resolving silently at run time.

Named custom rules make the rule name visible in diagnostics:

```go
rule, err := masker.NewRule("tenant-id", func(input masker.RuleInput) (string, error) {
	return input.Redaction, nil
})
```

Partial custom rules must slice on runes, not bytes: a byte offset can split a
multi-byte character, and the library rejects rule output that is not valid
UTF-8.

`Option` is intentionally a closed type. Use the exported `With*` constructors
rather than implementing options against the internal configuration type.

Reflection results are normalized for logging: safe scalars become strings
unless `WithPreserveSafeTypes` keeps booleans, integers, unsigned integers,
floats, and strings in their concrete types. Sensitive values are always
strings, and a non-sensitive `json.Number` is always retained as `json.Number`
to avoid precision loss.

Runnable examples for every exported constructor, option, rule, and adapter are
in the [package documentation](https://pkg.go.dev/github.com/icntswm/go-masker#pkg-examples).
They are executed and output-checked by `go test`, so they cannot drift from
the implementation.

## JSON

`MaskJSON` accepts exactly one valid JSON document and returns valid JSON. It
uses `json.Number` semantics for safe numbers, preserves last-wins behavior for
duplicate object keys, and uses a streaming walker with depth, node, and input
limits.

```go
input := []byte(`{"user":"alice","password":"secret","balance":9007199254740993}`)
output, err := m.MaskJSON(input)
if err != nil {
	// output is a safe JSON root fallback, never the original input.
}
fmt.Println(string(output))
// {"balance":9007199254740993,"password":"[REDACTED]","user":"alice"}
```

Object keys are sorted in the output, and `balance` keeps its exact value.
That number is 2^53+1, which `float64` rounds down to 2^53; safe numbers are
carried through as `json.Number` instead, so the digits survive.

`MaskJSONReader` reads the complete reader into memory before processing. Use
`WithMaxInputBytes` to bound accepted input:

```go
m, err := masker.New(masker.DefaultPolicy(), masker.WithMaxInputBytes(2<<20))
output, err := m.MaskJSONReader(reader)
```

There is intentionally no writer API in the current release: a writer cannot
retract an unsafe prefix if a later parse error is found.

## Struct tags

Struct tags select a built-in rule explicitly:

```go
type Event struct {
	User     string `json:"user"`
	Password string `mask:"password"`
	Internal string `json:"-"`
}

masked, err := m.MaskAny(Event{
	User: "alice", Password: "secret", Internal: "not logged",
})
```

Supported tag values are `full`, `email`, `phone`, `id`, `card`, `password`,
`token`, and `omit`. The precedence is:

1. `omit`;
2. `full` or another explicit tag rule;
3. the configured policy;
4. ordinary safe traversal.

The tag grammar is strict: an unsupported value or a comma-separated option is
a configuration error rather than a silent fallback. The result is normalized
to `map[string]any`/`[]any` containers. Struct field promotion follows the
relevant `encoding/json` rules, including same-depth tagged-field selection and
ignored unexported embedded non-struct fields.

## HTTP headers and URLs

The `httpmask` adapter copies headers and URLs before applying the core policy:

```go
core, err := masker.New(masker.DefaultPolicy())
adapter, err := httpmask.New(core, httpmask.WithMaskFragment())

headers, err := adapter.Headers(http.Header{
	"Authorization": {"Bearer secret"},
	"X-Trace":       {"trace-id"},
})
maskedURL, err := adapter.URLString(
	"https://user:password@example.com/?token=secret&keep=value#fragment",
)
```

`Cookie` and `Set-Cookie` values and URL userinfo are always fully redacted.
Sensitive query parameters use the core policy. Query keys are sorted and URL
escaping may be normalized. URL fragments are preserved by default and can be
masked with `WithMaskFragment`.

## Errors and fail-closed behavior

Every public operation returns a safe fallback on an error; it never returns
the original unsafe value. Use `errors.Is` for a category and `errors.As` for
safe operation context:

```go
var detail *masker.MaskError
output, err := m.MaskJSON([]byte(`{"password":`))
if err != nil && errors.Is(err, masker.ErrInvalidJSON) {
	fmt.Println(string(output)) // [REDACTED] as a JSON string
}
if errors.As(err, &detail) {
	fmt.Println(detail.Code, detail.Path)
}
```

Exported `Err*` values identify categories such as `ErrInvalidJSON`,
`ErrInvalidUTF8`, `ErrDepthLimit`, `ErrNodeLimit`, `ErrCycle`, and
`ErrPanic`. `ErrorCode` constants use the corresponding `Code*` names.

Never substitute the original input for an error result in application code or
in an adapter. The public operations already return a safe fallback, and
replacing it is the one change that reintroduces the leak the library prevents.

## Limits and security

Default limits are depth 32, 100,000 visited nodes, and 8 MiB of JSON input.
The JSON walker uses an iterative skipped-value scanner, so deep hostile input
cannot exhaust the Go call stack. Memory still grows with the input because the
public byte-slice and reader APIs retain the complete document during masking.

Review custom policies and rules as security-sensitive code. A custom rule's
output is checked for valid UTF-8, but the library cannot prove that arbitrary
custom logic removed every secret.

Read [SECURITY.md](SECURITY.md) for vulnerability reporting and
[THREAT_MODEL.md](THREAT_MODEL.md) for the security assumptions and failure
model.

## Performance

The streaming JSON walker, bounded key cache, direct encoder, and per-masker
reflection metadata cache are designed for predictable behavior on nested and
wide payloads. Current reference numbers and the methodology are in
[PERFORMANCE.md](PERFORMANCE.md).

Run local checks and benchmarks with:

```text
make test
make race
make bench
make bench-matrix
```

## Documentation map

- [package documentation](https://pkg.go.dev/github.com/icntswm/go-masker) —
  API reference and runnable examples for every exported symbol;
- [ARCHITECTURE.md](ARCHITECTURE.md) — implementation architecture and design
  decisions;
- [PERFORMANCE.md](PERFORMANCE.md) — benchmark methodology and references;
- [SECURITY.md](SECURITY.md) — vulnerability reporting and user expectations;
- [THREAT_MODEL.md](THREAT_MODEL.md) — threat model and security boundaries;
- [CHANGELOG.md](CHANGELOG.md) — unreleased and released changes;
- [CONTRIBUTING.md](CONTRIBUTING.md) — development and pull request workflow;
- [AGENTS.md](AGENTS.md) — the two checks in this repository that pass
  without running;
- [RELEASING.md](RELEASING.md) — tagging, the module proxy, and retractions.

The package godoc contains runnable examples for construction, JSON,
reflection, custom rules, struct tags, and HTTP adapters.

## Compatibility and stability

The project is pre-1.0. Public API changes will be called out in the changelog
before the first stable release. The supported Go window is Go 1.23 and newer
compatible releases.

## Contributing

Bug reports and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) before making changes. Security issues must
be reported privately according to [SECURITY.md](SECURITY.md).

## License

This project is licensed under the [MIT License](LICENSE).
