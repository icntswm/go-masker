# Performance and verification results

## How these numbers were produced

| | |
|---|---|
| Hardware | Apple M3 Pro, darwin/arm64 |
| Go | go1.23.1 (cross-version results in the last section) |
| Date | 2026-08-28 |
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
| `MaskString`, email rule | 86.0 | 16 | 1 |
| `MaskString`, formatted card | 123.4 | 24 | 1 |
| `KeyPolicy`, key matches | 32.3 | 24 | 1 |
| `KeyPolicy`, key does not match | 46.6 | 24 | 1 |
| `KeyPolicy`, empty key | 18.8 | 24 | 1 |
| `MaskValue`, scalar, rule applied | 97.1 | 32 | 2 |
| `MaskValue`, scalar, no rule | 97.0 | 40 | 2 |
| `MaskAny`, scalar | 48.8 | 16 | 1 |
| `MaskAny`, flat struct | 261.8 | 432 | 7 |
| `MaskAny`, wide struct | 1,002 | 1,736 | 20 |
| `MaskAny`, nested/tagged struct | 1,457 | 1,832 | 27 |
| `MaskAny`, nested map | 234,884 | 161,262 | 4,120 |
| `httpmask.Headers`, mixed set | 1,494 | 1,032 | 42 |
| `httpmask.URL`, query | 1,221 | 840 | 24 |

Flat and wide structs use the specialized scalar-struct path with compiled
field metadata. The nested cases pay the general reflection walker.

## JSON by document size

| Records | Time | Throughput | B/op | allocs/op |
|---:|---:|---:|---:|---:|
| 1 | 1.52 µs | 69 MB/s | 1,921 | 27 |
| 100 | 65.5 µs | 130 MB/s | 17,827 | 414 |
| 1,000 | 647 µs | 134 MB/s | 159,006 | 4,014 |
| 10,000 | 6.57 ms | 135 MB/s | 1,574,144 | 40,014 |

Throughput is flat from 100 records upward: cost is linear in input size.

## Wide objects

A single JSON object with many members. `collision-shaped` keys share length,
first byte, and last byte, which is the worst case for the key cache.

| Members | Ordinary keys | Collision-shaped keys |
|---:|---:|---:|
| 1,000 | 275 µs / 86 MB/s | 240 µs / 87 MB/s |
| 4,000 | 1.21 ms / 84 MB/s | 997 µs / 84 MB/s |
| 16,000 | 4.06 ms / 105 MB/s | 3.05 ms / 110 MB/s |
| 40,000 | 10.1 ms / 109 MB/s | 6.97 ms / 121 MB/s |

Throughput does not degrade with width. Duplicate lookup uses a full-key
64-bit hash with a bounded per-document cache and a capped collision chain;
retained members are sorted in `O(n log n)`. Collision-shaped input is not
slower because the chain cap stops the cache from growing.

## Output encoder

The safe-tree encoder replaces reflection-based `json.Marshal` on the
JSON output path.

| Document | `json.Marshal` | This encoder |
|---|---:|---:|
| Small | 640 ns / 464 B / 13 allocs | 309 ns / 352 B / 4 allocs |
| Large | 4.84 ms / 3.73 MB / 90,007 allocs | 1.87 ms / 893 KB / 3 allocs |

## Correctness and benchmark matrix

The matrix generates 260 scenarios. `TestBenchmarkMatrixCorrectness` runs
every one of them as a subtest under `go test` and asserts the case count, so
correctness is covered by the ordinary suite. `make bench-matrix` runs the
same scenarios as benchmarks to add the timing dimension.

| Area | Cases | Median ns/op | Min | Max | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| JSON | 158 | 55,523 | 53 | 35,782,583 | 21,075 | 164 |
| Reflection (`MaskAny`) | 40 | 2,621 | 14 | 57,673 | 2,614 | 48 |
| URL | 37 | 820 | 126 | 12,458,104 | 496 | 14 |
| HTTP headers | 25 | 877 | 403 | 15,469 | 808 | 22 |

The wide spread is expected: each area varies input size across several orders
of magnitude, from a single field to 10,000 records.

## Verified Go versions

All checks below were run locally against the same commit. Coverage is 82.4 %
for the root package and 90.7 % for `httpmask`.

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
