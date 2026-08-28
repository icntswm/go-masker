# Performance and verification results

## How these numbers were produced

| | |
|---|---|
| Hardware | Apple M3 Pro, darwin/arm64 |
| Go | go1.23.1 (cross-version results in the last section) |
| Date | 2026-08-28 |
| Benchmark revision | `3f00cbb` |
| Verification revision | `5ac0219` |
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
| `MaskString`, full redaction | 15.1 | 0 | 0 |
| `MaskString`, email rule | 86.2 | 16 | 1 |
| `MaskString`, formatted card | 124.0 | 24 | 1 |
| `KeyPolicy`, key matches | 32.6 | 24 | 1 |
| `KeyPolicy`, key does not match | 47.5 | 24 | 1 |
| `KeyPolicy`, empty key | 18.6 | 24 | 1 |
| `MaskValue`, scalar, rule applied | 96.5 | 32 | 2 |
| `MaskValue`, scalar, no rule | 93.2 | 40 | 2 |
| `MaskAny`, scalar | 47.9 | 16 | 1 |
| `MaskAny`, flat struct | 261.5 | 432 | 7 |
| `MaskAny`, wide struct | 1,004 | 1,736 | 20 |
| `MaskAny`, nested/tagged struct | 1,453 | 1,832 | 27 |
| `MaskAny`, nested map | 231,923 | 161,262 | 4,120 |
| `httpmask.Headers`, mixed set | 1,474 | 1,032 | 42 |
| `httpmask.URL`, query | 1,204 | 840 | 24 |

Flat and wide structs use the specialized scalar-struct path with compiled
field metadata. The nested cases pay the general reflection walker.

## JSON by document size

| Records | Time | Throughput | B/op | allocs/op |
|---:|---:|---:|---:|---:|
| 1 | 1.53 µs | 68 MB/s | 1,921 | 27 |
| 100 | 67.9 µs | 125 MB/s | 17,830 | 414 |
| 1,000 | 656 µs | 132 MB/s | 159,006 | 4,014 |
| 10,000 | 6.67 ms | 133 MB/s | 1,574,149 | 40,014 |

Throughput is flat from 100 records upward: cost is linear in input size.

## Wide objects

A single JSON object with many members. `collision-shaped` keys share length,
first byte, and last byte, which is the worst case for the key cache.

| Members | Ordinary keys | Collision-shaped keys |
|---:|---:|---:|
| 1,000 | 282 µs / 84 MB/s | 245 µs / 86 MB/s |
| 4,000 | 1.22 ms / 83 MB/s | 1.02 ms / 82 MB/s |
| 16,000 | 4.14 ms / 103 MB/s | 3.08 ms / 109 MB/s |
| 40,000 | 10.1 ms / 109 MB/s | 7.09 ms / 118 MB/s |

Throughput does not degrade with width. Duplicate lookup uses a full-key
64-bit hash with a bounded per-document cache and a capped collision chain;
retained members are sorted in `O(n log n)`. Collision-shaped input is not
slower because the chain cap stops the cache from growing.

## Output encoder

The safe-tree encoder replaces reflection-based `json.Marshal` on the
JSON output path.

| Document | `json.Marshal` | This encoder |
|---|---:|---:|
| Small | 625 ns / 464 B / 13 allocs | 316 ns / 352 B / 4 allocs |
| Large | 4.84 ms / 3.73 MB / 90,007 allocs | 1.86 ms / 893 KB / 3 allocs |

## Correctness and benchmark matrix

The matrix generates 260 scenarios. `TestBenchmarkMatrixCorrectness` runs
every one of them as a subtest under `go test` and asserts the case count, so
correctness is covered by the ordinary suite. `make bench-matrix` runs the
same scenarios as benchmarks to add the timing dimension.

| Area | Cases | Median ns/op | Min | Max | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| JSON | 158 | 53,047 | 51 | 34,871,417 | 21,072 | 164 |
| Reflection (`MaskAny`) | 40 | 2,522 | 13 | 53,500 | 2,613 | 48 |
| URL | 37 | 714 | 117 | 12,208,188 | 496 | 14 |
| HTTP headers | 25 | 829 | 377 | 14,328 | 808 | 22 |

The wide spread is expected: each area varies input size across several orders
of magnitude, from a single field to 10,000 records.

## Verified Go versions

All checks below were run locally at `5ac0219`, where coverage is 83.3 % for
the root package and 90.7 % for `httpmask`. The benchmark numbers above come
from `3f00cbb`; the commits since then changed an error path and the tests, not
anything a benchmark measures.

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
full `make fuzz`, all five targets at 30 seconds each. CI also runs build, vet,
formatting, tests, the race suite and the correctness matrix on every supported
minor release plus `stable`.

### Output stability across Go versions

Masking output must not change when the Go toolchain changes. A fixed corpus
of 16 documents (valid, malformed, duplicate keys, escapes, `U+2028` and
`U+2029`, large numbers, deep nesting, empty input) was masked under four
redaction markers, together with `MaskAny`, `URL`, `URLString`, and `Headers`.
Every output and every returned error was hashed:

| Go | SHA-256 of all outputs |
|---|---|
| 1.23.0 | `69dc960c8bd6c8df…3a93b399` |
| 1.24.6 | `69dc960c8bd6c8df…3a93b399` |
| 1.25.0 | `69dc960c8bd6c8df…3a93b399` |
| 1.26.4 | `69dc960c8bd6c8df…3a93b399` |
| 1.27.0 | `69dc960c8bd6c8df…3a93b399` |

Identical on every version, including Go 1.27, which reimplemented
`encoding/json`.

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
