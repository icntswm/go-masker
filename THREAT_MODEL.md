# go-masker threat model

`go-masker` is intended to reduce accidental exposure of secrets in logs,
diagnostics, and observability payloads. It is not a proof that arbitrary
application data or custom rules contain no sensitive information.

The public operations fail closed: a malformed document, unsupported value,
cycle, callback panic, policy failure, or resource limit returns a safe root
fallback and never returns the original input. Errors contain only categories,
paths, field names, and the name of the rule that failed; callback error text
is not propagated. Keys and paths reaching a message are escaped, because they
come from the document being masked.

The implementation bounds reflection depth, visited nodes, operation-wide
pointer dereferences, and JSON input bytes. The pointer indirection ceiling is
internally tied to the configured node limit and reports `node_limit` when
exceeded. JSON syntax, depth, and node limits are checked by the streaming
walker in one pass. Resource-limit skipping is iterative and does not consume
the Go call stack. If a resource limit stops traversal, the complete input is
validated then so malformed input remains classified as invalid JSON.
Duplicate JSON object keys follow `encoding/json` last-wins behavior.

JSON uses a direct streaming walker and never constructs a decoded DOM. It
buffers only the current object needed for sorted keys and last-wins duplicate
semantics. Encoding uses a dedicated safe-tree encoder with sorted keys, exact
numbers, and standard escaping; unsupported values fail closed.

The first depth or node limit failure is terminal for both direct JSON and
reflection traversal. Its safe code, path, and depth are retained, and Policy
or Rule callbacks are not invoked for remaining sibling branches. Ordinary
sibling failures remain aggregated, but at most 64 `MaskError` entries and
their paths are retained per operation. Additional callback errors are dropped
without retaining their values or messages, and every failure still produces
the root fallback.

Inputs are never mutated and output containers do not alias source containers.
Reflection map and slice result capacity is capped by the remaining node budget
before traversal, so an attacker-controlled container length cannot force a
proportional output preallocation before the node limit is checked. Successful
inputs still produce complete normalized copies; resource failures return only
the safe root fallback.

Object-member collection uses bounded scratch storage and map-assisted duplicate
lookup for wide objects. Members are sorted before encoding, so callers should
still apply input and node limits to untrusted payloads.
Cycle detection tracks only the active recursion path, so shared DAG nodes are
allowed. Unsupported map key types and reflection values are rejected.

Each `Masker` has a concurrent immutable-entry reflection metadata cache. The
cache is isolated from other `Masker` instances, but encountered `reflect.Type`
values and field metadata remain reachable for that `Masker`'s lifetime. Code
that constructs long-lived maskers for attacker-controlled streams of dynamic
struct types should account for this retention risk.

URLs preserve paths by default for compatibility. Userinfo is always redacted,
and so is the fragment unless the caller asks the HTTP adapter to keep it.
Cookies and Set-Cookie headers are fully redacted in the MVP.

`WithPreserveSafeTypes` retains safe primitive types but does not preserve
struct types. Source strings may remain live while an operation is running;
the package does not claim secure memory erasure. Custom rules can be checked
for valid output but their semantic safety cannot be proven by the library.
