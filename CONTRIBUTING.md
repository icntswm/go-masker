# Contributing

Bug reports and pull requests are welcome. Security issues are different: do
not open an issue for them, follow [SECURITY.md](SECURITY.md) instead.

## Getting set up

The project needs Go 1.23 or newer and nothing else. There are no third-party
dependencies and therefore no `go.sum`.

```text
git clone https://github.com/icntswm/go-masker
cd go-masker
make test
```

`golangci-lint` is only needed for `make lint`. Install the version CI pins,
currently `v2.11.4`; see [Linting](#linting) for why the version matters.

## Running checks

```text
make fmt           # gofmt -w .
make fmt-check     # fail if gofmt would change anything
make vet           # go vet ./...
make lint          # golangci-lint config verify + run
make test          # go test ./...
make race          # go test -race ./...
make bench         # root benchmarks, 5 runs each
make bench-matrix  # 260 masking scenarios, each result checked
make fuzz          # all five fuzz targets, 30s each
make vulncheck     # govulncheck against the standard library
```

The 260 masking scenarios run twice. `make test` executes them through
`TestBenchmarkMatrixCorrectness`, which checks every masked result and asserts
the case count. `make bench-matrix` runs the same scenarios as benchmarks, so
use it when a change could affect performance rather than correctness.

To run a single test or example:

```text
go test -run TestKeyPolicyASCIIAndUnicodeParity ./...
go test -run ExampleMasker_MaskJSON ./...
```

To run one fuzz target for longer than the smoke pass:

```text
go test -run '^$' -fuzz FuzzMaskJSON -fuzztime 5m .
```

## What CI runs

Five jobs, all required. Each one runs a Makefile target, so a local run and
a CI run cannot diverge:

| Job | What it does |
| --- | --- |
| `Tests & checks` | `make vet`, `make fmt-check`, `make test`, `make race` — on Go 1.23.x through 1.27.x plus `stable` |
| `Masking matrix` | `make bench-matrix` on the same six versions |
| `Fuzz smoke` | `make fuzz`, all five targets at 30s each, on the same six versions |
| `Vulnerability scan` | `make vulncheck` on a recent toolchain |
| `Lint` | `golangci-lint` on one pinned Go version |

Two more workflows run beside these. `CodeQL` looks for exploitable patterns
rather than style, and `Scorecard` scores the repository rather than the code.
Both report into the Security tab, and neither gates a merge.

### Linting

The lint job pins Go 1.23.x on purpose. `golangci-lint` statically links
`go/types` from the Go release it was built with, and it panics when it meets
standard-library sources from a newer toolchain. Keep the lint job's Go version
at or below the release that built the pinned linter, and bump both together.

`make lint` runs `golangci-lint config verify` before `golangci-lint run`,
because `run` ignores unknown configuration keys while the CI action rejects
them. Without the verify step a broken `.golangci.yml` passes locally and fails
in CI.

### When Fuzz smoke fails

Fuzzing is not deterministic, so a fuzz job can fail on a pull request that did
not introduce the bug. Do not just re-run it. Download the failing input from
the job's artifacts or reproduce locally, commit it to `testdata/fuzz/<Target>/`
as a regression seed, and fix the cause. A committed seed is replayed by every
later `go test`, so the same input can never regress silently.

## Writing tests

- Add a regression test for every parser, policy, or fail-closed change.
- Golden cases for JSON, headers and URLs go in
  `testdata/security_decisions/`; the schema is documented in the
  [README there](testdata/security_decisions/README.md). Adding or removing a
  case fails `TestSecurityDecisionGoldenFiles` until its counts and the figures
  in `README.md` are updated together. Cases that cannot be
  expressed as JSON — cycles, shared DAGs, struct-tag precedence — stay
  table-driven in Go.
- Never use real credentials or production data in tests, benchmarks, examples
  or fixtures. Use `example.com` addresses and clearly synthetic values.

### Examples

Every `Example*` function must end with an `// Output:` block. Without one, Go
compiles the example but never runs it, so it silently stops matching the
implementation. Put the block inside the function body, not after the closing
brace, and take the expected text from a real run rather than writing it by
hand.

## Benchmarks

Prepare inputs before `b.ResetTimer()`, call `b.ReportAllocs()`, and assign
results to a package-level sink so the compiler cannot optimize the work away.
Allocation counts travel between machines much better than nanoseconds; prefer
them when arguing that a change is a regression. Reference numbers and the
measurement method are in [PERFORMANCE.md](PERFORMANCE.md).

Timing flags come from `BENCH_FLAGS` and `MATRIX_FLAGS`, so a measurement
recorded in the documentation can be repeated without retyping the command:

```text
make bench-matrix MATRIX_FLAGS="-benchtime=20ms -count=3"
```

The matrix default stays short because CI runs it on every supported Go
version.

## Pull requests

- Keep changes focused, and say what the security or compatibility effect is.
- Explain user-visible behavior changes in the description, not only in code.
- Update `CHANGELOG.md` for anything a user would notice: fixes, security
  changes, and API changes.
- Public API changes need an explicit note while the project is pre-1.0; the
  package name stays `masker` even though the module is `go-masker`, following
  the usual Go convention.
- Documentation lives close to the code it describes. Prefer a runnable example
  over a markdown snippet: examples are compiled and output-checked, prose is
  not.
