.PHONY: fmt fmt-check vet lint vulncheck test race bench bench-matrix fuzz fuzz-core fuzz-http fuzz-json fuzz-string fuzz-policy fuzz-json-parity

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

# Reports standard-library advisories on code paths this module actually calls.
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

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

# Run all root fuzz targets; extend -fuzztime for real campaigns.
fuzz: fuzz-core fuzz-http

fuzz-core: fuzz-json fuzz-string fuzz-policy fuzz-json-parity

fuzz-json:
	go test -run '^$$' -fuzz FuzzMaskJSON -fuzztime 30s .

fuzz-string:
	go test -run '^$$' -fuzz FuzzMaskString -fuzztime 30s .

fuzz-policy:
	go test -run '^$$' -fuzz FuzzKeyPolicyCaseFold -fuzztime 30s .

fuzz-json-parity:
	go test -run '^$$' -fuzz FuzzJSONWalkerMatchesReflection -fuzztime 30s .

fuzz-http:
	go test -run '^$$' -fuzz FuzzURLString -fuzztime 30s ./httpmask
