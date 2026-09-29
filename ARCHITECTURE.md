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
- `log/slog` attributes through `slogmask`;
- JSON log lines from zerolog and other JSON-line loggers through
  `zerologmask`, and from zap's JSON encoder through `zapmask`; both wrap the
  output writer and share `internal/jsonline`.

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
├── AGENTS.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── PERFORMANCE.md
├── RELEASING.md
├── SECURITY.md
├── THREAT_MODEL.md
├── ARCHITECTURE.md
├── Makefile
├── .golangci.yml
├── doc.go
├── embedded.go
├── text.go
├── text_isolation.go
├── errors.go
├── json.go
├── json_encode.go
├── json_lex.go
├── json_stream.go
├── json_walk.go
├── masker.go
├── options.go
├── policy.go
├── rule.go
├── rules_builtin.go
├── struct_metadata.go
├── walk.go
├── .github/
│   ├── workflows/            # ci, codeql, provenance, scorecard
│   ├── dependabot.yml
│   └── ISSUE_TEMPLATE/
├── httpmask/
│   ├── doc.go
│   ├── adapter.go
│   └── *_test.go
├── slogmask/
│   ├── doc.go
│   ├── replace.go
│   └── *_test.go
├── internal/jsonline/       # line-masking engine of both writers
├── internal/urlquery/       # query parser shared by httpmask and embedded.go
├── internal/detect/         # secret detectors for free text
├── zerologmask/
│   ├── doc.go
│   ├── writer.go
│   └── *_test.go
├── zapmask/
│   ├── doc.go
│   ├── writer.go
│   └── *_test.go
├── testdata/
│   └── security_decisions/
├── internal/
│   └── outputdigest/
├── benchmark_matrix_test.go
├── benchmark_test.go
├── examples_test.go
├── fuzz_test.go
├── goldens_test.go
├── json_encode_test.go
├── json_scan_test.go
├── json_walk_test.go
└── masker_test.go
```

The core remains a single root package. Splitting the walker into internal
packages is not required for the first implementation and could introduce
unnecessary dependency direction between the public policy types and the
traversal engine.

`httpmask` is a subpackage of the same module. It may use `net/http` and
`net/url`, but the core does not depend on an HTTP framework.

The module has no third-party dependencies, so the repository contains no
`go.sum`. Benchmarks live in the root package and add no dependency of their
own. `zerologmask` and `zapmask` are tested against lines captured from the real zerolog and
zap rather than against the loggers, so the tests need no dependency either;
the captured lines are recaptured when a logger changes its output format.

Logger adapters for zap and zerolog work on the encoded output, not on typed
fields. zap's `zapcore.Core`, `Encoder`, `ObjectMarshaler` and hooks all take
zap's own types, so masking fields before they are encoded would need a zap
import and with it a separate module. The writer needs only `io.Writer`, which
`zapcore.AddSync` accepts. The cost is that it sees JSON only: zap's console
encoder and zerolog's CBOR build lose every line to the fallback. zap writes
diagnostics next to a field under a suffixed key (`${key}Verbose`,
`${key}Causes`, `${key}Error`) that repeat the field's content; the writer
decides each of them as its base key as well, so a sensitive base keeps its
diagnostics masked whatever the policy says about the suffixed key.

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
func WithTagRule(name string, rule Rule) Option
```

`MaskValue` is a convenience wrapper over `MaskField` and uses
`SourceMap`:

```go
func (m *Masker) MaskValue(key string, value any) (any, error)
```

The normalized result contract is:

- maps become newly allocated `map[string]any` values;
- slices and arrays become newly allocated `[]any` values;
- structs are represented by maps using their visible field names; a field
  whose JSON tag name `encoding/json` rejects is written under a different key
  by Go 1.26 and by Go 1.27, so it fails closed with `CodeInvalidConfig` unless
  a mask tag decides it;
- pointers and interfaces are unwrapped;
- an `encoding.TextMarshaler` becomes its text and a non-nil `[]byte` its
  standard base64 form, as `encoding/json` renders them; a byte slice whose
  elements implement `MarshalText` is walked element by element instead, and
  a failing or panicking `MarshalText` fails closed;
- a `json.RawMessage` is decoded, with `json.Number` precision, and walked like
  any other map or slice, because `encoding/json` embeds it as is and base64
  would hide nothing a reader cannot decode. Its bytes are charged against the
  node limit before decoding, and a message that is not a single valid JSON
  value fails closed with `ErrInvalidJSON`;
- `MarshalText` runs on a copy of its receiver, so a method that updates its
  receiver cannot mutate the input. Only receivers without pointers, maps,
  channels, functions, interfaces, or locks are copied, and a slice in one
  must hold reference-free elements, such as `net.IP` or `[]byte`: such a
  value has no cycles or shared graph that a copy would have to rebuild. A
  slice that appears twice stays shared in the copy and every slice keeps its
  capacity; slices into overlapping but different storage, such as `buf[:2]`
  and `buf[1:]`, fail with `ErrUnsupportedType`. Any other marshaler —
  including one holding a reference in an unexported field or a lock such as
  `sync.Mutex`, whose held copy would never unlock — is walked like an
  ordinary value instead. `time.Time` and the `net/netip` address types are
  trusted to only read their receiver and are copied shallowly;
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

`Field.Path` is a human-readable bracketed path, such as
`$[user][orders][0][token]`. It is diagnostic context only; it is not RFC 6901
and is not a stable machine-readable matching protocol.

A policy that never reads `Field.Path` — a `KeyPolicy`, or a `Chain` of them —
lets the walkers skip building the string per node and keep only the cheap
stack of segments. An error still names its exact location: the path is
materialized at the point the error is recorded.

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
`strings.EqualFold`; the key text is first stripped of the separator
characters `_`, `-`, and `.`, so `access_token`, `access-token`, and
`accessToken` compare equal and a key of separators only never matches.
Substring matching is not used. `KeyPolicy` resolves
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

A nil value, whether a nil interface, including an untyped nil passed to
`MaskField` or `MaskValue`, or a nil pointer, is decided like JSON
`null`: the policy or a tag may omit it or apply a rule to empty text, so a
redacting rule logs the marker, and otherwise it stays `nil`. Reflection and
`MaskJSON` therefore agree on the same keys. In `slogmask` an omitted nil
attribute still logs `null`, because `MaskField` returns `nil` for both.

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
- email preserves only a limited safe shape and fully redacts malformed input,
  including input with a control or format character or a line separator;
- phone and card rules preserve at most the last four ASCII digits and retain
  only ordinary formatting separators;
- ID preserves at most the last four units, and fully redacts input with a
  control or format character or a line separator, since the kept units are
  written verbatim;
- values with four or fewer phone/card digits, or with unexpected free text,
  use full redaction;
- partial masking operates on runes, never raw byte offsets.

When a rule is selected for a non-scalar value, it replaces the entire
subtree. The rule receives empty scalar text for containers, so partial rules
conservatively produce their full-redaction fallback.

Custom rules are selected by `Policy.Decide`, or by a struct tag once they are
registered with `WithTagRule`.

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
omit > full > concrete built-in or registered rule > Policy > ordinary traversal
```

An explicit `full` decision cannot be weakened by a partial policy or tag.

`WithTagRule(name, rule)` adds a custom rule to the grammar at Masker
construction, so it is selected through the same precedence above. Built-in
names and `omit` cannot be redefined, and an empty name, a name already
registered, or a name containing a comma, a space, or a quote is rejected with
`ErrInvalidConfig`, mirroring the strict tag grammar. Registration is
construction-scoped: each Masker owns its tag-rule map, so one Masker's rules
never leak into another.

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

Methods such as `String`, `Error`, and `MarshalJSON` are not automatically
called by the reflection walker. `MarshalText` is: an `encoding.TextMarshaler`
is decided as a string, and its text is rendered only after an `omit`
decision or a fully redacting rule (`FullRule`, `PasswordRule`, `TokenRule`)
has had the chance to discard it, so such a decision never runs it. Unsupported values such as
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
not close the reader. `WithMaxInputBytes` is the primary protection against
unbounded input, and the output is built before it is exposed to the caller.
A read of `(0, nil)` consumes none of that limit, so 100 of them in a row fail
the call with `ErrInvalidJSON` rather than let a stalled reader spin forever.

There is intentionally no streaming `io.Writer` API for a single document:
once a writer has received a prefix, a later parse error cannot retract a
potentially unsafe operation. The logger writers do not break this rule. It masks
whole lines, each a complete document, and writes nothing of a line until the
line is masked; a record split across two `Write` calls is replaced by the
fallback line rather than buffered.

### 9.2 Known JSON limitations

Duplicate object keys follow `encoding/json` behavior: the last value wins.
This is a documented limitation and a threat-model item. Every member is still
masked, including one a later duplicate overwrites, so a masking error in an
overwritten member fails the whole document even though its value would not
reach the output. This is deliberate: deciding which duplicate survives before
masking would need a second pass, and failing closed costs only a rejected
document whose keys RFC 8259 says should be unique. A
`json.RawMessage` walked through reflection is decoded first, so only its last
value is masked.

All JSON documents use the streaming walker. The input itself is still held in
memory by `MaskJSON` and `MaskJSONReader`.

### 9.3 Documents inside strings

Every walker, and the scalar fast path, inspects a string whose field the
policy leaves without a rule (`embedded.go`). A cheap prefilter looks for a
leading `{` or `[`, `://` or `=` before any path is built, so an ordinary
string costs no allocation. A candidate is tried as an absolute URL, then as
one JSON document, then as a strict form, and the first grammar that accepts
the whole string wins:

- a URL keeps the `httpmask` treatment: userinfo and fragment become the
  marker, and each query value is decided by its key through
  `internal/urlquery`, the parser `httpmask` uses too;
- a JSON document is masked by a nested `streamJSONWalker` rooted at the
  string's path, so the result equals `MaskJSON` output;
- a form is decided pair by pair like a query.

A decoded value with no rule of its own is inspected again, so documents
nest. The nested work shares the outer node counter, error list and stop flag,
and runs one level deeper, so the traversal limits bound the total. A string is
rewritten only when something inside it changed; otherwise the original bytes
are kept. A URL whose query cannot be parsed becomes the marker without an
error, so one unusual link does not fail the surrounding document.
`WithoutEmbeddedDocuments()` disables the inspection.

### 9.4 Secrets inside text

A string that no document grammar accepts goes to the text detectors
(`text.go`, `internal/detect`). The prefilter is `detect.Candidate`, which is
exact rather than approximate: it runs the same scanners as `detect.Find`
and stops at the first hit, so a string pays for a path only when something
will be found. Both are generic over `~string | ~[]byte`, so the stream
walker checks a raw token without converting it, and neither allocates on a
miss.

`detect.Find` is one forward pass returning two lists:

- spans, secrets recognized by shape: the credential after `Bearer`/`Basic`,
  a PEM private key body, a JWT, provider tokens, URL userinfo, and, when
  enabled, Luhn-valid card numbers and AWS key ids. Scanning resumes after a
  span, never inside it;
- pairs, `key=value` or `key: value` with optional quotes. Scanning resumes at
  the value, so a token inside the value of an undecided key is still found.
  Nested values share one measured run, which keeps text such as `a=a=a=…`
  linear.

`inspectText` decides every pair through `decideMember`, the same routine that
decides a query pair (validity, depth, node count, policy, rule, errors),
with `SourceText`. Every decided pair and every span becomes an edit;
overlapping edits resolve to the outermost, so a decided pair covers a span
inside its value. An omitted pair value becomes the marker, a card number
keeps its last four digits, and the text between edits is copied unchanged.
`WithoutTextDetectors()` disables this layer and `WithoutValueInspection()`
both layers.

## 10. HTTP adapter

`httpmask` is a subpackage of the same module:

```go
package httpmask

type Adapter struct{}
type Option func(*config) error

func New(core *masker.Masker, opts ...Option) (*Adapter, error)
func WithPreserveFragment() Option

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
- a policy `Decision{Omit: true}` drops the value; a header whose every value
  is omitted is dropped with it, because an empty value list would still be
  serialized as a header;
- `CookieNamePolicy` is deferred.

URL behavior:

- query parameters are processed through Policy with `SourceURLQuery`;
- duplicate query values are preserved as repeated values;
- a policy `Decision{Omit: true}` drops the parameter from the query;
- userinfo is always fully redacted;
- the fragment is redacted by default, because an OAuth implicit-flow token
  arrives there;
- `WithPreserveFragment()` keeps the fragment when it carries client-side
  routing state a reader needs;
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
outputs but cannot make arbitrary user state safe. A Policy must also be
deterministic, returning the same Decision for the same Field: struct field
decisions are cached, and `slogmask` decides a group again for each member
written into it, so a policy that changes its answer could mask one member
and pass the next.

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
- the inability to prove arbitrary custom Rule semantic safety;
- secrets in free text that have neither a key nor a recognizable shape,
  which the text detectors cannot find.

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
- headers, cookies, URLs, and fragment handling;
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

The six fuzz targets are:

- `FuzzMaskJSON` for arbitrary JSON bytes;
- `FuzzMaskString` for arbitrary Unicode strings and built-in rules;
- `FuzzKeyPolicyCaseFold` for case-insensitive policy matching;
- `FuzzJSONWalkerMatchesReflection` for JSON/reflection parity;
- `FuzzURLString` for malformed URLs and query escaping;
- `FuzzCandidateMatchesFind` for the text detectors: well-formed spans and
  pairs, and `detect.Candidate` agreeing with `detect.Find`.

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
loop, so the matrix is a correctness gate as well as a benchmark.
`TestBenchmarkMatrixCorrectness` runs every scenario under `go test`;
`make bench-matrix` runs the same set as benchmarks for timing.

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

- JSON Lines input to `MaskJSON` and `MaskJSONReader` (only the logger
  writers split lines);
- integer map keys;
- optional code generation;
- CookieNamePolicy;
- partial-result mode that returns a safe partial tree together with local
  errors;
- streaming `io.Writer` API for a single document.

Policy key bindings are compiled into a case-folded lookup during
`NewKeyPolicy`. The per-`Masker` reflection metadata cache and direct JSON
walker are implemented work, not deferred work.

Future logger adapters must depend only on the stable core API and must never
fall back to the original value when masking returns an error.

## 15. Known limitations and disputed decisions

- `MaskAny` does not preserve the concrete struct type, even with
  `WithPreserveSafeTypes`.
- JSON duplicate keys use last-wins behavior from `encoding/json`.
- Scratch buffers for large objects live in a fixed-size process-wide pool of
  four buffers of up to 16 MiB, held until the process exits.
- `MaskJSONReader` reads the entire document into memory.
- The streaming walker enforces JSON depth while scanning; the complete input
  is still held in memory by the public byte-slice and reader APIs.
- A `Masker` metadata cache retains encountered struct types and immutable
  field metadata for the lifetime of that `Masker`.
- Integer map keys are rejected because conversion can create collisions.
- The fragment is redacted by default; keeping client-side routing state
  visible requires an opt-in.
- Custom Rule output can be checked for format and validity, but not for
  semantic absence of secrets.
- Rune-safe masking guarantees valid Unicode boundaries but does not guarantee
  grapheme-cluster preservation.
- JSON uses the streaming walker, but `MaskJSONReader` still reads the
  complete input into memory before processing.
- Safe booleans are converted to strings by default in every pipeline;
  `WithPreserveSafeTypes` is required to keep them typed. Only non-sensitive
  `json.Number` values are always retained as numbers.
- Phone and card values with four or fewer digits, or arbitrary free text
  around the digits, use full redaction; ordinary phone/card separators are
  retained only when there are more than four digits.
- Reflection inputs with invalid UTF-8 fail closed with `ErrInvalidUTF8`.
- `zerologmask` and `zapmask` mask whole lines only: a record split across two `Write`
  calls is replaced by the fallback line, and wrapping a level-routing or
  level-filtering destination such as zerolog's `MultiLevelWriter` or
  `FilteredLevelWriter` loses its routing. zerolog's `binary_log` build and
  zap's console encoder do not write JSON, and every such line is replaced.
- zap and zerolog are masked on their encoded output, not on typed fields, so
  a masked line is parsed and re-encoded and its keys come out sorted.
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
