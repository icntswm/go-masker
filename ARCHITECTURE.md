# go-masker architecture

## 1. Scope and goals

`go-masker` is an independent open-source Go library for safe masking of
sensitive data before it reaches logs, diagnostics, or other observability
sinks.

The library is not coupled to an HTTP framework or a logger. The core is usable
by applications, middleware, and logger adapters without requiring any
particular logging implementation.

The initial scope includes:

- strings and scalar values;
- JSON documents;
- nested maps, slices, arrays, pointers, interfaces, and structs;
- built-in struct tags;
- HTTP headers and URLs through `httpmask`;
- logger adapters for `slog`, `zerolog`, and `zap` are out of scope for now.

The security properties are more important than preserving the exact input
shape or maximizing throughput:

- fail-closed behavior on errors;
- no mutation of input data;
- immutable, concurrency-safe `Masker` instances;
- case-insensitive field-key matching;
- valid Unicode output;
- bounded traversal depth and node count;
- cycle detection without confusing shared DAGs with cycles.

## 2. Version and module baseline

The minimum supported Go version is Go 1.23.

The root `go.mod` uses:

```text
go 1.23
```

There is no `toolchain` directive and no patch-version pinning. The package is
expected to remain compatible with Go 1.23.x and newer compatible Go releases.

The core uses only the Go standard library. Third-party logger dependencies are
not added to the core module.

## 3. Package structure

The current repository layout is:

```text
go-masker/
├── go.mod
├── README.md
├── LICENSE
├── SECURITY.md
├── THREAT_MODEL.md
├── CHANGELOG.md
├── ARCHITECTURE.md
├── doc.go
├── masker.go
├── options.go
├── policy.go
├── rule.go
├── rules_builtin.go
├── errors.go
├── walk.go
├── json.go
├── json_lex.go
├── json_encode.go
├── json_walk.go
├── json_stream.go
├── struct_metadata.go
├── PERFORMANCE.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── RELEASING.md
├── .golangci.yml
├── .github/
│   ├── workflows/ci.yml
│   ├── dependabot.yml
│   └── ISSUE_TEMPLATE/
├── httpmask/
│   ├── doc.go
│   ├── adapter.go
├── testdata/
│   └── security_decisions/
├── examples_test.go
├── fuzz_test.go
├── benchmark_test.go
├── benchmark_matrix_test.go
├── json_scan_test.go
└── goldens_test.go
```

The core remains a single root package. Splitting the walker into internal
packages is not required for the first implementation and could introduce
unnecessary dependency direction between the public policy types and the
traversal engine.

`httpmask` is a subpackage of the same module. It may use `net/http` and
`net/url`, but the core does not depend on an HTTP framework.

The module has no third-party dependencies, so the repository contains no
`go.sum`. Benchmarks live in the root package and add no dependency of their
own.

## 4. Core public API

The following signatures define the public contract implemented by the current
release candidate.

```go
const DefaultRedactionMarker = "[REDACTED]"
const DefaultStructTag = "mask"

type Masker struct{}
type Option func(*config) error

// Option is intentionally closed: callers use the exported With* constructors
// rather than implementing options against the internal configuration type.

func New(policy Policy, opts ...Option) (*Masker, error)

func (m *Masker) MaskString(value string, rule Rule) (string, error)
func (m *Masker) MaskValue(key string, value any) (any, error)
func (m *Masker) MaskField(field Field, value any) (any, error)
func (m *Masker) MaskAny(value any) (any, error)
func (m *Masker) MaskJSON(src []byte) ([]byte, error)
func (m *Masker) MaskJSONReader(src io.Reader) ([]byte, error)

func WithPreserveSafeTypes() Option
func WithRedaction(marker string) Option
func WithMaxDepth(depth int) Option
func WithMaxNodes(nodes int) Option
func WithMaxInputBytes(bytes int64) Option
func WithStructTag(name string) Option
```

`MaskValue` is a convenience wrapper over `MaskField` and uses
`SourceMap`:

```go
func (m *Masker) MaskValue(key string, value any) (any, error)
```

The normalized result contract is:

- maps become newly allocated `map[string]any` values;
- slices and arrays become newly allocated `[]any` values;
- structs are represented by maps using their visible field names;
- pointers and interfaces are unwrapped;
- unsupported values are never returned unchanged;
- on successful masking, no input container is reused in the result.

`WithPreserveSafeTypes` changes scalar behavior for reflection-based input:

- safe booleans, integers, unsigned integers, floats, and strings retain
  their concrete scalar type;
- sensitive values are still replaced with strings;
- containers remain copied normalized containers;
- the concrete type of a struct is not preserved.

This option exists to avoid breaking consumers that pass the safe result into
structured loggers or serializers expecting numeric and boolean values.

`json.Number` is special: a non-sensitive `json.Number` is always retained as
`json.Number`, regardless of `WithPreserveSafeTypes`. It must never be converted
through `float64`, because that can lose precision or truncate large values.

Each public symbol must have a godoc comment. Documentation and examples must
cover normal use, edge cases, thread safety, and performance/memory behavior.

## 5. Policy and Rule model

### 5.1 Field context

```go
type Source uint8

const (
    SourceUnknown Source = iota
    SourceAny
    SourceMap
    SourceStruct
    SourceJSON
    SourceHeader
    SourceURLQuery
    SourceURLUserInfo
    SourceURLFragment
)

type ValueKind uint8

const (
    KindInvalid ValueKind = iota
    KindNil
    KindString
    KindBool
    KindNumber
    KindObject
    KindArray
)

type Field struct {
    Key    string
    Path   string
    Source Source
    Kind   ValueKind
}
```

`Field.Path` is a human-readable hybrid path, such as
`$[user].orders[0][token]`. It is diagnostic context only; it is not RFC 6901
and is not a stable machine-readable matching protocol.

### 5.2 Policy

```go
type Decision struct {
    Rule Rule
    Omit bool
}

type Policy interface {
    Decide(Field) (Decision, error)
}

type PolicyFunc func(Field) (Decision, error)

func (f PolicyFunc) Decide(field Field) (Decision, error)

type Binding struct {
    Keys []string
    Rule Rule
}

type KeyPolicy struct{}

func NewKeyPolicy(bindings ...Binding) (*KeyPolicy, error)
func DefaultPolicy() Policy
func DefaultBindings() []Binding
func Chain(policies ...Policy) Policy
```

`DefaultBindings` returns a defensive copy. Sensitive key configuration must be
public and inspectable; there is no hidden immutable `sensitiveKeys` list.

Key matching is exact and case-insensitive using Unicode-aware
`strings.EqualFold`. Substring matching is not used. `KeyPolicy` resolves
common spellings through lowercase buckets and falls back to a direct
`EqualFold` scan for rare cross-script pairs (ASCII `k` versus KELVIN SIGN,
`s` versus long s); benchmarks measured this two-tier shape faster than
per-call canonicalization. Duplicate fold-equivalent bindings with different
rules are rejected during policy validation with a one-time full scan.
Invalid UTF-8 keys simply never match valid bindings.

`Chain` semantics are explicit:

- a zero `Decision` means `no opinion` and proceeds to the next policy;
- a non-nil Rule stops the chain;
- `Omit == true` stops the chain;
- an error stops the chain and causes fail-closed output.

`New` rejects empty chains and chains containing nil policies as invalid
configuration; a masker without a usable policy would otherwise silently pass
sensitive values through or fail only when processing data.

For map, struct, and JSON object members, `Omit == true` removes the member.
For array elements it preserves the array shape by producing `null`; omitting
the root produces `nil` for reflection and JSON `null` for JSON encoding.

Duplicate equal-fold bindings are accepted only when they refer to the same
comparable Rule instance; different custom callbacks are rejected rather than
silently resolved by declaration order.

### 5.3 Rule

```go
type RuleInput struct {
    Value     string
    Kind      ValueKind
    Redaction string
}

type Rule interface {
    Name() string
    Apply(RuleInput) (string, error)
}

type RuleFunc func(RuleInput) (string, error)

func NewRule(name string, fn RuleFunc) (Rule, error)

func PasswordRule() Rule
func EmailRule() Rule
func PhoneRule() Rule
func IDRule() Rule
func CardRule() Rule
func TokenRule() Rule
func FullRule() Rule
```

Built-in behavior:

- password, token, and full rules return the configured redaction marker;
- email preserves only a limited safe shape and fully redacts malformed input;
- phone and card rules preserve at most the last four ASCII digits and retain
  only ordinary formatting separators;
- ID preserves at most the last four units;
- values with four or fewer phone/card digits, or with unexpected free text,
  use full redaction;
- partial masking operates on runes, never raw byte offsets.

When a rule is selected for a non-scalar value, it replaces the entire
subtree. The rule receives empty scalar text for containers, so partial rules
conservatively produce their full-redaction fallback.

Custom rules are selected by `Policy.Decide`. They are not registered through
struct tags.

## 6. Struct tags and precedence

The supported grammar is intentionally small:

```go
mask:"email"
mask:"phone"
mask:"id"
mask:"card"
mask:"password"
mask:"token"
mask:"full"
mask:"omit"
```

The default tag name is `DefaultStructTag`, equal to `"mask"`. An empty
`WithStructTag("")` selects the default.

Rules:

- absent or empty tag delegates to Policy;
- `omit` removes the field;
- `full` replaces the field with the marker;
- a built-in named rule applies the corresponding rule;
- unknown tag values are errors and produce root redaction;
- `mask:"-"` and comma-separated options are also unknown values; the grammar
  is intentionally strict;
- `keep` and other bypass tags are not supported;
- `json:"-"` omits the field.

Priority is:

```text
omit > full > concrete built-in rule > Policy > ordinary traversal
```

An explicit `full` decision cannot be weakened by a partial policy or tag.

## 7. Errors and fail-closed behavior

Public errors are typed and must be documented:

```go
type ErrorCode string

type MaskError struct {
    Code              ErrorCode
    Operation         string
    Path              string
    Field             string
    ConflictingField  string
    Depth             int
    Rule              string
}

type MaskErrors struct {
    Items []*MaskError
}

func (e *MaskError) Error() string
func (e *MaskError) Unwrap() error
func (e *MaskErrors) Error() string
func (e *MaskErrors) Unwrap() []error
```

`MaskErrors.Unwrap() []error` is the aggregate contract. Each `MaskError`
unwraps to a safe sentinel corresponding to its `ErrorCode`. Raw errors from a
custom Policy, Rule, reader, or callback are not blindly included if their
message could contain sensitive data.

The sentinel set includes `ErrInvalidConfig`, `ErrInvalidJSON`,
`ErrInvalidUTF8`, `ErrInputLimit`, `ErrDepthLimit`, `ErrNodeLimit`, `ErrCycle`,
`ErrUnsupportedType`, `ErrUnsupportedKey`, `ErrFieldConflict`,
`ErrPolicyFailure`, `ErrRuleFailure`, and `ErrPanic`. `ErrorCode` constants use
the `Code*` prefix to remain distinct from these error values. For example,
`errors.Is(err, masker.ErrInvalidJSON)` checks the category, while
`errors.As(err, &maskError)` retrieves safe operation context.

The following behavior is mandatory:

- `errors.Is` works for sentinel categories;
- `errors.As` finds `*MaskError` inside a single or aggregate error;
- errors never include source values;
- any error returns a safe root fallback, never the original input;
- custom callback panics are converted into safe errors;
- resource exhaustion and unsupported values are not silently ignored.

Fallback forms are type-appropriate but safe:

- scalar/`any`: marker string;
- JSON: valid JSON string containing the marker;
- headers: empty new header map;
- URL: new URL containing only a marker representation.

The walkers collect ordinary sibling Policy, Rule, and field failures up to an
internal limit of 64 `MaskError` entries per operation. Once full, the
aggregate retains no additional errors or paths, while traversal remains
fail-closed. The public operation returns root redaction if the error list is
non-empty. This keeps diagnostics useful without allowing attacker-controlled
width to create an unbounded retained error graph.

Depth and node limit failures are terminal. The first such failure is retained
with its original code, path, and depth, including when the ordinary error cap
was already reached; traversal does not call Policy or Rule for sibling
branches afterward.

Callback panics use the dedicated `ErrPanic` error category. Partial-result
mode is intentionally not part of the current release.

There is no public severity enum. `ErrorCode` is sufficient for
metrics and adapter-level severity mapping without expanding the core API.

## 8. Reflection walker

The reflection walker produces a new safe representation and never assigns to
the input value.

Processing order:

1. validate the depth budget, then the node budget;
2. unwrap interfaces and pointers, including typed nil values, while charging
   pointer dereferences to an operation-wide internal indirection budget;
3. detect an active cycle;
4. apply the current field decision before descending;
5. process scalar, map, slice, array, or struct;
6. remove the current identity from the active stack.

Supported values include primitive scalar kinds, named aliases of those kinds,
maps with string keys, slices, arrays, pointers, interfaces, and structs.

Unexported ordinary struct fields are skipped. Anonymous embedded structs follow
the exported-field promotion semantics of `encoding/json`: exported fields are
eligible even when the embedded struct type itself is unexported.

Visible field-name conflicts are not silently resolved. The walker follows
`encoding/json`'s same-depth tagged-field tie-break and reports a `MaskError`
with `Field` and `ConflictingField` only when ambiguity remains, while the
public operation returns root redaction. Unexported anonymous non-struct
fields are ignored, matching `encoding/json`.

Methods such as `String`, `Error`, `MarshalJSON`, and `MarshalText` are not
automatically called by the reflection walker. Unsupported values such as
functions, channels, complex values, unsafe pointers, and arbitrary readers
are fail-closed.

### 8.1 Maps

Maps support `map[string]T` and aliases of string. Original map keys and
values are not modified; the output map is newly allocated. Initial map
capacity is capped by the remaining node budget instead of trusting the input
length. Slices and arrays use the same cap and grow by appending only completed
children. Struct result maps are presized from immutable reflection metadata,
also capped by the remaining node budget. Successful inputs retain their full
normalized shape, while a terminal resource failure discards the partial
representation through the public fail-closed result.

Integer map keys are deferred. If added later, only signed and unsigned
integer kinds should be converted to canonical decimal strings, with explicit
collision detection. Float, bool, struct, pointer, and interface map keys
remain unsupported.

### 8.2 Cycle identity

Cycle detection uses one internal identity helper. The target baseline does not
require a `reflect.Value.MapPointer()` API. For Go 1.23, map identity uses
`reflect.Value.UnsafePointer()` for map values, combined with kind and type.
Pointer and slice identities use their pointer information together with kind,
type, and the relevant slice shape.

Only identities currently on the recursion stack are considered. A shared
object reached through two sibling paths is therefore a shared DAG, not a
cycle. The operation-local identity map is allocated lazily when traversal
first encounters a non-nil pointer, map, or slice, so scalar and flat struct
paths do not allocate cycle state.

### 8.3 Limits

The implementation has configurable limits for:

- maximum recursion depth;
- maximum visited nodes;
- maximum JSON input bytes.

Reflection traversal also has an internal operation-wide pointer indirection
budget equal to the configured maximum node count. Pointer dereferences do not
change the existing visited-node or recursion-depth counters, but a chain that
exceeds this internal budget terminates with `ErrNodeLimit`. No separate public
option is exposed because the indirection limit is a hardening bound derived
from the existing traversal budget.

The first depth or node limit failure stops traversal of the remaining
branches. Successful inputs and ordinary sibling callback failures keep their
existing traversal semantics.

The defaults are depth 32, 100,000 nodes, and 8 MiB of JSON input. They are
chosen to be generous for ordinary observability payloads while keeping a
single hostile document bounded.

## 9. JSON

`MaskJSON` and `MaskJSONReader` use the same Policy contract as reflection
input, but a separate streaming tokenizer processes JSON values directly.
`MaskAny`, structs, maps, slices, pointers, and interfaces continue through
the reflection walker.

The JSON pipeline is:

1. validate UTF-8 and input size;
2. enforce value and depth limits while scanning;
3. validate primitive and container syntax in the streaming tokenizer;
4. accept exactly one JSON document and trailing whitespace only;
5. mask and encode values directly;
6. expose only the completed safe output.

The streaming walker avoids constructing the decoded DOM for any document. It
buffers only the current object's member values so it can retain sorted keys
and last-wins duplicate-key semantics, while arrays are written directly to
the output buffer.

Object-key reuse uses a full-key 64-bit hash. The per-document cache is capped
at 4,096 entries and each hash chain at eight entries; once a cap is reached,
keys are still handled correctly but are not retained in the cache.

The streaming walker validates structure and enforces depth and node limits in
one pass. If a resource limit stops traversal, the complete input is validated
only then to keep malformed JSON classified as `ErrInvalidJSON`.

The final safe tree is encoded by a dedicated buffer-based encoder rather than
reflection-based `json.Marshal`. It supports only the tree types produced by
the direct walker, sorts object keys, preserves exact `json.Number` text, and
matches standard JSON string escaping. An unsupported encoder value fails
closed instead of being emitted partially.

`json.Number` is retained for every non-sensitive numeric value. Sensitive
numbers are passed to the selected Rule as exact text and become strings after
masking.

### 9.1 Reader semantics

`MaskJSONReader` reads the entire input into memory before returning. It does
not close the reader. `MaxInputBytes` is the primary protection against
unbounded input, and the output is built before it is exposed to the caller.

There is intentionally no streaming `io.Writer` API: once a writer
has received a prefix, a later parse error cannot retract a potentially unsafe
operation.

### 9.2 Known JSON limitations

Duplicate object keys follow `encoding/json` behavior: the last value wins.
This is a documented limitation and a threat-model item.

All JSON documents use the streaming walker. The input itself is still held in
memory by `MaskJSON` and `MaskJSONReader`.

## 10. HTTP adapter

`httpmask` is a subpackage of the same module:

```go
package httpmask

type Adapter struct{}
type Option func(*config) error

func New(core *masker.Masker, opts ...Option) (*Adapter, error)
func WithMaskFragment() Option

func (a *Adapter) Headers(src http.Header) (http.Header, error)
func (a *Adapter) URL(src *url.URL) (*url.URL, error)
func (a *Adapter) URLString(raw string) (string, error)
```

Header behavior:

- header maps and value slices are copied;
- key comparison is case-insensitive;
- all values for headers whose policy matches are fully redacted, even when
  the selected policy rule is partial; this is intentional paranoid
  behavior for transport metadata;
- `Cookie` and `Set-Cookie` receive full redaction;
- `CookieNamePolicy` is deferred.

URL behavior:

- query parameters are processed through Policy with `SourceURLQuery`;
- duplicate query values are preserved as repeated values;
- userinfo is always fully redacted;
- fragment is preserved by default for compatibility with client-side routing;
- `WithMaskFragment()` enables paranoid fragment masking;
- path is preserved by default;
- query output is rebuilt by the adapter's one-pass query parser/writer; keys
  are sorted and escaping may be normalized (`+` may replace `%20`), matching
  the documented `url.Values` semantics;
- redaction markers containing reserved URL characters are percent-encoded;
  URL-heavy consumers may choose a URL-safe marker with `WithRedaction`;
- malformed or opaque URLs fail closed.

## 11. Thread safety and ownership

After successful construction, `Masker` is immutable and safe for concurrent
use from multiple goroutines. Policy and built-in Rule configuration is copied
or compiled during `New`; per-call traversal state is local to the invocation.

Each `Masker` owns a concurrent reflection metadata cache. Cache entries are
immutable after construction and are shared only by operations using that
`Masker`; different `Masker` instances do not share metadata or struct-tag
configuration.

The library never mutates input maps, slices, arrays, structs, headers, URLs,
or nested values. Returned containers do not alias input containers.

Custom Policies and Rules must be concurrency-safe. The library validates their
outputs but cannot make arbitrary user state safe.

## 12. Threat model

`THREAT_MODEL.md` documents the following release risks:

- accidental secret exposure through logs and diagnostics;
- malformed input, invalid UTF-8, duplicate JSON keys, and oversized input;
- cycles, deep nesting, unsupported reflection values, and map-key ambiguity;
- panic and error behavior of custom callbacks;
- limitations of `WithPreserveSafeTypes`;
- URL path and fragment defaults;
- Cookie full-redaction behavior;
- memory retention of source strings;
- the inability to prove arbitrary custom Rule semantic safety.

## 13. Testing and benchmarking

### 13.1 Security golden cases

`testdata/security_decisions` contains golden cases for approved masking
decisions, including:

- mixed-case keys;
- all built-in rules;
- numeric sensitive fields;
- struct tags and precedence;
- nested map/slice/struct input;
- cycle and depth fallback;
- headers, cookies, URLs, and paranoid fragments;
- invalid input and root redaction.

Golden files must never contain real credentials or production personal data.

### 13.2 Unit and property tests

Tests cover:

- `errors.Is` and `errors.As` for `MaskError` and `MaskErrors`;
- `json.Number` precision preservation;
- safe-type preservation;
- no mutation and no container aliasing;
- typed nil values;
- exported fields of embedded unexported structs;
- detailed embedded-field conflicts;
- string map keys and rejection of unsupported keys;
- pointer/map/slice cycles and shared DAGs;
- depth, node, and input limits;
- custom Rule invalid output and panic;
- concurrent use of one `Masker`.

### 13.3 Fuzzing

Fuzz targets include:

- `FuzzMaskJSON` for arbitrary JSON bytes;
- `FuzzMaskString` for arbitrary Unicode strings and built-in rules;
- `FuzzKeyPolicyCaseFold` for case-insensitive policy matching;
- `FuzzJSONWalkerMatchesReflection` for JSON/reflection parity;
- `FuzzURLString` for malformed URLs and query escaping.

Custom Rule and Policy panic paths are covered by unit tests rather than fuzz
targets.

Fuzz invariants include no panic, valid UTF-8, valid JSON where applicable,
root redaction on errors, and absence of the original sensitive value from
successful masked output.

### 13.4 Benchmarks and CI

The root package benchmarks built-in rules, reflection, JSON, headers, URLs,
policy lookup, and wide objects with both ordinary and collision-shaped keys.
The 260-case matrix in `benchmark_matrix_test.go` runs under
`make bench-matrix`. Each scenario validates its masked result after the timed
loop, so the matrix is a correctness gate as well as a benchmark. `go test`
does not run it, which is why CI has a separate matrix job.

Benchmarks use only the standard library. Comparisons against other masking
libraries are run out of tree so the repository never references or depends on
them.

The committed `.github/workflows/ci.yml` runs build, vet, formatting, tests,
the race suite, the correctness matrix, and short fuzz campaigns on every
supported Go minor release plus the current stable release. Linting runs on a
single pinned Go version because `golangci-lint` embeds `go/types` from the Go
release it was built with and fails on a newer toolchain.

## 14. Deferred work

The following items are outside the current scope:

- JSON Lines support;
- integer map keys;
- optional code generation;
- `slog`, `zerolog`, and `zap` adapters;
- CookieNamePolicy;
- partial-result mode that returns a safe partial tree together with local
  errors;
- streaming `io.Writer` API.

Policy key bindings are compiled into a case-folded lookup during
`NewKeyPolicy`. The per-`Masker` reflection metadata cache and direct JSON
walker are implemented work, not deferred work.

Future logger adapters must depend only on the stable core API and must never
fall back to the original value when masking returns an error.

## 15. Known limitations and disputed decisions

- `MaskAny` does not preserve the concrete struct type, even with
  `WithPreserveSafeTypes`.
- JSON duplicate keys use last-wins behavior from `encoding/json`.
- `MaskJSONReader` reads the entire document into memory.
- The streaming walker enforces JSON depth while scanning; the complete input
  is still held in memory by the public byte-slice and reader APIs.
- A `Masker` metadata cache retains encountered struct types and immutable
  field metadata for the lifetime of that `Masker`.
- Integer map keys are rejected because conversion can create collisions.
- Fragment is preserved by default; paranoid mode is required for stricter URL
  logging.
- Custom Rule output can be checked for format and validity, but not for
  semantic absence of secrets.
- Rune-safe masking guarantees valid Unicode boundaries but does not guarantee
  grapheme-cluster preservation.
- Default depth, node, and byte limits are 32, 100,000, and 8 MiB. They should
  still be validated against real payload distributions before release.
- JSON uses the streaming walker, but `MaskJSONReader` still reads the
  complete input into memory before processing.
- Safe booleans are converted to strings by default in every pipeline;
  `WithPreserveSafeTypes` is required to keep them typed. Only non-sensitive
  `json.Number` values are always retained as numbers.
- Phone and card values with four or fewer digits, or arbitrary free text
  around the digits, use full redaction; ordinary phone/card separators are
  retained only when there are more than four digits.
- Reflection inputs with invalid UTF-8 fail closed with `ErrInvalidUTF8`.
- A single JSON object with very many members uses a full-key hash for duplicate
  lookup and `slices.SortFunc`; the per-document key cache is bounded and each
  hash chain is capped, so object width does not create an unbounded quadratic
  duplicate-lookup path. Memory still grows with the input and sorting remains
  `O(n log n)` in the number of retained members.
- The default bare `id` binding intentionally favors secret-safety over log
  readability; consumers that need ordinary IDs should provide an explicit
  policy.
- The public module path is `github.com/icntswm/go-masker`; the project remains
  pre-1.0 until the first stable release.
