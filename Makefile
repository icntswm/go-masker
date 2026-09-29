.PHONY: fmt fmt-check vet lint vulncheck test race compat zapmask bench bench-matrix fuzz fuzz-core fuzz-http fuzz-json fuzz-string fuzz-policy fuzz-json-parity

fmt:
	gofmt -w .

# Same check CI runs: report files that gofmt would change, do not rewrite them.
fmt-check:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

# config verify mirrors the CI action, which rejects an invalid config schema.
lint:
	golangci-lint config verify
	golangci-lint run
	cd zapmask && golangci-lint run

# Reports standard-library advisories on code paths this module actually calls.
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Runs zerologmask against the real zerolog; the nested module keeps the
# dependency out of the library.
compat:
	cd internal/zerologcompat && go test -race ./...

# zapmask is a separate module so the library keeps no third-party
# dependency; the root ./... does not reach it.
zapmask:
	cd zapmask && go vet ./... && test -z "$$(gofmt -l .)" && go test -race ./...

test:
	go test ./...

race:
	go test -race ./...

# Timing flags live in variables so a documented measurement can be reproduced
# without retyping the command: make bench-matrix MATRIX_FLAGS="-benchtime=20ms -count=3"
BENCH_FLAGS ?= -benchtime=1s -count=5
MATRIX_FLAGS ?= -benchtime=10ms

# Run with -benchmem to track allocations in hot paths.
bench:
	go test -run '^$$' -skip '^BenchmarkMaskMatrix$$' -bench . -benchmem $(BENCH_FLAGS) ./...

# Run all generated matrix cases with correctness checks and short timings.
bench-matrix:
	go test -run '^$$' -bench '^BenchmarkMaskMatrix$$' -benchmem $(MATRIX_FLAGS) ./...

# Run all fuzz targets. The smoke pass is bounded by executions, not time:
# a time limit trips a race in the Go fuzzer that fails a clean run with
# "context deadline exceeded". Raise FUZZTIME for real campaigns.
FUZZTIME ?= 200000x

fuzz: fuzz-core fuzz-http

fuzz-core: fuzz-json fuzz-string fuzz-policy fuzz-json-parity

fuzz-json:
	go test -run '^$$' -fuzz FuzzMaskJSON -fuzztime $(FUZZTIME) .

fuzz-string:
	go test -run '^$$' -fuzz FuzzMaskString -fuzztime $(FUZZTIME) .

fuzz-policy:
	go test -run '^$$' -fuzz FuzzKeyPolicyCaseFold -fuzztime $(FUZZTIME) .

fuzz-json-parity:
	go test -run '^$$' -fuzz FuzzJSONWalkerMatchesReflection -fuzztime $(FUZZTIME) .

fuzz-http:
	go test -run '^$$' -fuzz FuzzURLString -fuzztime $(FUZZTIME) ./httpmask
