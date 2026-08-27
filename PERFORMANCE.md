# Performance and verification results

## How these numbers were produced

| | |
|---|---|
| Hardware | Apple M3 Pro, darwin/arm64 |
| Go | go1.23.1 (cross-version results in the last section) |
| Date | 2026-08-27 |
| Revision | not recorded; see the repository history |
| Core benchmarks | `make bench`, `-benchtime=1s -count=5`, median of 5 runs |
| Matrix | `make bench-matrix`, `-benchtime=20ms -count=3`, median of 3 runs |

Benchmarks build their inputs before the timer starts, report allocations, and
retain results in package-level sinks. Every matrix case also validates the
masked output, so a timing run cannot pass while masking is wrong.

Numbers are indicative. Repeat them on the target hardware before using them
for capacity planning.

## Core operations

| Case | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `MaskString`, full redaction | 15.4 | 0 | 0 |
| `MaskString`, email rule | 91.4 | 16 | 1 |
| `MaskString`, formatted card | 130.5 | 24 | 1 |
| `KeyPolicy`, key matches | 34.0 | 24 | 1 |
| `KeyPolicy`, key does not match | 50.9 | 24 | 1 |
| `KeyPolicy`, empty key | 19.0 | 24 | 1 |
| `MaskValue`, scalar, rule applied | 96.1 | 32 | 2 |
| `MaskValue`, scalar, no rule | 94.6 | 40 | 2 |
| `MaskAny`, scalar | 47.8 | 16 | 1 |
| `MaskAny`, flat struct | 249.4 | 416 | 6 |
| `MaskAny`, wide struct | 982.8 | 1,720 | 19 |
| `MaskAny`, nested/tagged struct | 1,598 | 1,872 | 32 |
| `MaskAny`, nested map | 269,065 | 194,644 | 5,418 |
| `httpmask.Headers`, mixed set | 1,485 | 1,032 | 42 |
| `httpmask.URL`, query | 1,202 | 840 | 24 |

Flat and wide structs use the specialized scalar-struct path with compiled
field metadata. The nested cases pay the general reflection walker.

## JSON by document size

| Records | Time | Throughput | B/op | allocs/op |
|---:|---:|---:|---:|---:|
| 1 | 1.51 µs | 69 MB/s | 1,921 | 27 |
| 100 | 65.6 µs | 130 MB/s | 17,830 | 414 |
| 1,000 | 668 µs | 130 MB/s | 159,008 | 4,014 |
| 10,000 | 6.62 ms | 134 MB/s | 1,574,146 | 40,014 |

Throughput is flat from 100 records upward: cost is linear in input size.

## Wide objects

A single JSON object with many members. `collision-shaped` keys share length,
first byte, and last byte, which is the worst case for the key cache.

| Members | Ordinary keys | Collision-shaped keys |
|---:|---:|---:|
| 1,000 | 276 µs / 86 MB/s | 248 µs / 85 MB/s |
| 4,000 | 1.20 ms / 85 MB/s | 1.01 ms / 83 MB/s |
| 16,000 | 4.04 ms / 105 MB/s | 3.01 ms / 112 MB/s |
| 40,000 | 10.0 ms / 109 MB/s | 7.50 ms / 112 MB/s |

Throughput does not degrade with width. Duplicate lookup uses a full-key
64-bit hash with a bounded per-document cache and a capped collision chain;
retained members are sorted in `O(n log n)`. Collision-shaped input is not
slower because the chain cap stops the cache from growing.

## Output encoder

The safe-tree encoder replaces reflection-based `json.Marshal` on the
JSON output path.

| Document | `json.Marshal` | This encoder |
|---|---:|---:|
| Small | 626 ns / 464 B / 13 allocs | 303 ns / 320 B / 4 allocs |
| Large | 5.02 ms / 3.73 MB / 90,007 allocs | 1.89 ms / 893 KB / 3 allocs |

## Correctness and benchmark matrix

The matrix generates 260 scenarios. `TestBenchmarkMatrixCorrectness` runs
every one of them as a subtest under `go test` and asserts the case count, so
correctness is covered by the ordinary suite. `make bench-matrix` runs the
same scenarios as benchmarks to add the timing dimension.

| Area | Cases | Median ns/op | Min | Max | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| JSON | 158 | 55,450 | 59 | 41,946,708 | 21,035 | 164 |
| Reflection (`MaskAny`) | 40 | 3,060 | 13 | 69,514 | 2,886 | 51 |
| URL | 37 | 824 | 135 | 12,242,750 | 496 | 14 |
| HTTP headers | 25 | 910 | 428 | 16,069 | 808 | 22 |

The wide spread is expected: each area varies input size across several orders
of magnitude, from a single field to 10,000 records.

## Verified Go versions

All checks below were run locally against the same commit. Coverage is 81.2 %
for the root package and 87.8 % for `httpmask`.

| Go | build / vet / gofmt | `go test` | `-race` | `bench-matrix` | `make fuzz` |
|---|---|---|---|---|---|
| 1.23.0 | OK | OK | OK | OK | OK |
| 1.23.1 | OK | OK | — | — | — |
| 1.24.0 | OK | OK | — | — | — |
| 1.24.3 | OK | OK | — | — | — |
| 1.24.6 | OK | OK | OK | OK | — |
| 1.25.0 | OK | OK | OK | OK | OK |
| 1.26.4 | OK | OK | — | — | OK |
| 1.27.0 | OK | OK | OK | OK | OK |

CI runs build, vet, formatting, tests, the race suite, the correctness matrix,
and short fuzz campaigns on every supported minor release plus `stable`.

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
