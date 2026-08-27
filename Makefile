.PHONY: fmt vet lint test race bench bench-matrix fuzz fuzz-core fuzz-http fuzz-json fuzz-string fuzz-policy fuzz-json-parity

fmt:
	gofmt -w .

vet:
	go vet ./...

# config verify mirrors the CI action, which rejects an invalid config schema.
lint:
	golangci-lint config verify
	golangci-lint run

test:
	go test ./...

race:
	go test -race ./...

# Run with -benchmem to track allocations in hot paths.
bench:
	go test -run '^$$' -skip '^BenchmarkMaskMatrix$$' -bench . -benchmem ./...

# Run all generated matrix cases with correctness checks and short timings.
bench-matrix:
	go test -run '^$$' -bench '^BenchmarkMaskMatrix$$' -benchmem -benchtime=10ms ./...

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
