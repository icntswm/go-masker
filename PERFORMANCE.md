# Performance and verification results

## How these numbers were produced

| Setting | Value |
|---|---|
| Hardware | Apple M3 Pro, darwin/arm64 |
| Go | go1.23.1 (cross-version results in [Verified Go versions](#verified-go-versions)) |
| Date | 2026-09-30 |
| Benchmark revision | `v0.5.0`; logger adapters and nested struct after `v0.5.0` |
| Verification revision | `2fe6986` |
| Core benchmarks | `make bench`, median of 5 runs |
| Matrix | `make bench-matrix MATRIX_FLAGS="-benchtime=20ms -count=3"`, median of 3 runs |

Benchmarks build their inputs before the timer starts, report allocations, and
retain results in package-level sinks. Every matrix case also validates the
masked output, so a timing run cannot pass while masking is wrong.

Numbers are indicative. Repeat them on the target hardware before using them
for capacity planning.

## Core operations

| Case | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `MaskString`, full redaction | 15.7 | 0 | 0 |
| `MaskString`, email rule | 65.8 | 16 | 1 |
| `MaskString`, formatted card | 128.0 | 24 | 1 |
| `KeyPolicy`, key matches | 33.9 | 24 | 1 |
| `KeyPolicy`, key does not match | 43.3 | 24 | 1 |
| `KeyPolicy`, empty key | 19.3 | 24 | 1 |
| `MaskValue`, scalar, rule applied | 107.1 | 32 | 2 |
| `MaskValue`, scalar, no rule | 151.0 | 40 | 2 |
| `MaskAny`, scalar | 116.1 | 16 | 1 |
| `MaskAny`, flat struct | 345.5 | 432 | 7 |
| `MaskAny`, wide struct | 1,708 | 1,736 | 20 |
| `MaskAny`, nested/tagged struct | 1,476 | 1,800 | 23 |
| `MaskAny`, nested map | 275,196 | 161,261 | 4,120 |
| `MaskJSON`, strings holding a URL and a JSON body | 2,401 | 1,569 | 35 |
| `httpmask.Headers`, mixed set | 2,172 | 1,072 | 35 |
| `httpmask.URL`, query | 1,404 | 848 | 25 |

Flat and wide structs use the specialized scalar-struct path with compiled
field metadata. A struct that also holds nested values takes the same path for
each of its scalar fields and pays the general reflection walker only for the
rest. A string
that no rule masks is inspected for embedded documents and secrets inside
text, which is most of the cost of the scalar rows without a rule; the scan
skips the inside of each word, so it stays linear and cheap on ordinary text.

## Logger adapters

Each row is one `Info` record, measured with the table above: four
attributes, two of them sensitive; five safe scalars of different kinds; one
struct; and nested groups holding a credential.

| Case | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `log/slog` JSON handler, no masking | 531 | 0 | 0 |
| `log/slog` JSON handler, `slogmask.ReplaceAttr` | 1,311 | 120 | 3 |
| `slogmask`, five safe scalars | 1,730 | 240 | 6 |
| `slogmask`, one struct | 2,072 | 1,043 | 24 |
| `slogmask`, nested groups | 2,347 | 810 | 13 |
| `zerologmask` writer, one 142-byte line | 1,260 | 248 | 11 |

`slogmask` masks each attribute, and the message, as it is written. A scalar
attribute and each enclosing group are decided without the reflection walker,
and a number is formatted only when a rule or a detector needs its text; the
allocations left in the scalar row are the handler's own float encoding. `zerologmask` and `zapmask` parse and
re-encode the finished line, which costs about as much as masking a
one-record JSON document below; the logger's own time is not included.

## JSON by document size

Measured with the tables above.

| Records | Time | Throughput | B/op | allocs/op |
|---:|---:|---:|---:|---:|
| 1 | 1.06 µs | 98 MB/s | 432 | 13 |
| 100 | 69.1 µs | 123 MB/s | 16,344 | 400 |
| 1,000 | 714 µs | 122 MB/s | 157,520 | 4,000 |
| 10,000 | 7.06 ms | 126 MB/s | 1,572,675 | 40,000 |

Throughput is flat from 100 records upward: cost is linear in input size.

## Wide objects

A single JSON object with many members. `collision-shaped` keys share length,
first byte, and last byte, which is the worst case for the key cache.

| Members | Ordinary keys | Collision-shaped keys |
|---:|---:|---:|
| 1,000 | 345 µs / 69 MB/s | 280 µs / 75 MB/s |
| 4,000 | 1.50 ms / 68 MB/s | 1.15 ms / 73 MB/s |
| 16,000 | 5.33 ms / 80 MB/s | 3.65 ms / 92 MB/s |
| 40,000 | 13.5 ms / 81 MB/s | 8.69 ms / 97 MB/s |

Throughput does not degrade with width. Duplicate lookup uses a full-key
64-bit hash with a bounded per-document cache and a capped collision chain;
retained members are sorted in `O(n log n)`. Collision-shaped input is not
slower because the chain cap stops the cache from growing.

## Output encoder

The safe-tree encoder replaces reflection-based `json.Marshal` on the
JSON output path.

| Document | `json.Marshal` | This encoder |
|---|---:|---:|
| Small | 686 ns / 464 B / 13 allocs | 326 ns / 352 B / 4 allocs |
| Large | 5.37 ms / 3.73 MB / 90,007 allocs | 1.92 ms / 893 KB / 3 allocs |

## Correctness and benchmark matrix

The matrix generates 260 scenarios. `TestBenchmarkMatrixCorrectness` runs
every one of them as a subtest under `go test` and asserts the case count, so
correctness is covered by the ordinary suite. `make bench-matrix` runs the
same scenarios as benchmarks to add the timing dimension.

| Area | Cases | Median ns/op | Min | Max | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| JSON | 158 | 71,564 | 59 | 54,039,958 | 18,708 | 111 |
| Reflection (`MaskAny`) | 40 | 3,320 | 23 | 72,784 | 2,614 | 48 |
| URL | 37 | 1,018 | 135 | 16,128,958 | 496 | 14 |
| HTTP headers | 25 | 1,113 | 527 | 23,227 | 720 | 18 |

The wide spread is expected: each area varies input size across several orders
of magnitude, from a single field to 10,000 records.

## Verified Go versions

All checks below were run locally at `2fe6986`, where coverage is 84.9 % for
the root package, 90.7 % for `httpmask`, and 88.6 % for `slogmask`. Timing
numbers above were not re-measured for this run.

| Go | build / vet / gofmt | `go test` | `-race` | `bench-matrix` | fuzz |
|---|---|---|---|---|---|
| 1.23.0 | OK | OK | OK | OK | OK |
| 1.23.1 | OK | OK | OK | OK | OK |
| 1.24.0 | OK | OK | OK | OK | OK |
| 1.24.3 | OK | OK | OK | OK | OK |
| 1.24.6 | OK | OK | OK | OK | OK |
| 1.25.0 | OK | OK | OK | OK | OK |
| 1.26.4 | OK | OK | OK | OK | OK |
| 1.27.0 | OK | OK | OK | OK | OK |

The fuzz column is a 20-second `FuzzMaskJSON` campaign per version; CI runs the
full `make fuzz`, all six targets at 200,000 executions each. CI also runs
build, vet, formatting, tests, the race suite and the correctness matrix on
every supported minor release plus `stable`.

### Output stability across Go versions

Masking output must not change when the Go toolchain changes. A fixed corpus
of 16 documents (valid, malformed, duplicate keys, escapes, `U+2028` and
`U+2029`, large numbers, deep nesting, empty input) was masked under four
redaction markers, together with `MaskAny`, `URL`, `URLString`, and `Headers`.
Every output and every returned error was hashed by
[`internal/outputdigest`](internal/outputdigest/main.go). `MaskAny` results are
hashed with their dynamic types, with and without `WithPreserveSafeTypes`, so
a number that turns into a string changes the digest:

| Go | SHA-256 of all outputs |
|---|---|
| 1.23.0 | `edf3fda6e1eebb30…9887bb59` |
| 1.24.6 | `edf3fda6e1eebb30…9887bb59` |
| 1.25.0 | `edf3fda6e1eebb30…9887bb59` |
| 1.26.4 | `edf3fda6e1eebb30…9887bb59` |
| 1.27.0 | `edf3fda6e1eebb30…9887bb59` |

Identical on every version, including Go 1.27, which reimplemented
`encoding/json`. Log output of `slogmask` is pinned separately, byte for byte,
by the golden file `slogmask/testdata/golden.txt`.

## Caveats

- Benchmarks measure a warm process on one machine. Container CPU limits, GC
  pressure from the host application, and colder caches all change absolute
  numbers.
- Allocation counts are more stable across machines than nanoseconds; prefer
  them when tracking regressions.
- Throughput figures use `SetBytes` on the raw input, so they describe input
  consumed per second, not masked output produced.
- Fuzzing, tests, and the correctness matrix run separately from timing and
  must pass before performance numbers are considered valid.
