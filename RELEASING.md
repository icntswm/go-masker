# Releasing

Releases are Git tags. There is no build step and nothing to upload: the Go
module proxy serves the tagged source directly.

## Versioning

The project follows semantic versioning. While the major version is `0` the
API may still change; say so explicitly in the changelog when it does.

Tags are `vMAJOR.MINOR.PATCH`, for example `v0.2.0`. The `v` prefix is required
by the Go tooling. A `v2` or later major version would additionally need the
major suffix in the module path (`github.com/icntswm/go-masker/v2`), so avoid
reaching for it without a real reason.

## Before tagging

Run the full local suite; CI covers the same ground on every supported Go
release, but a failure found locally is cheaper.

```text
make fmt
make lint
make test
make race
make bench-matrix
make fuzz
```

Then check the things CI cannot:

- `CHANGELOG.md` has an entry for every user-visible change, and the
  `[Unreleased]` heading is replaced by the version and date.
- The supported Go window in `README.md` matches the CI matrix in
  `.github/workflows/ci.yml`.
- `PERFORMANCE.md` numbers were re-measured if the release changes anything on
  a hot path. Stale benchmark tables are worse than none.
- Examples still pass: they are executed by `go test`, so a green suite is
  enough, but a new exported symbol should get one.

## Tagging

```text
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

Create a GitHub release from the tag and paste that version's changelog
section as the release notes.

Pushing the tag starts the provenance workflow, which attaches a source archive
and a SLSA attestation to the release, creating a placeholder release if the
tag arrives first. The run has to happen on the tag ref for the attestation to
record the tag, so a release whose tag predates this workflow cannot get one:
`v0.1.0` has no attestation for that reason.

A consumer checks a release with:

```text
slsa-verifier verify-artifact go-masker-vX.Y.Z.tar.gz \
  --provenance-path go-masker-vX.Y.Z.tar.gz.intoto.jsonl \
  --source-uri github.com/icntswm/go-masker --source-tag vX.Y.Z
```

## After tagging

Ask the module proxy to fetch the version, which also makes it appear on
pkg.go.dev:

```text
GOPROXY=https://proxy.golang.org go list -m github.com/icntswm/go-masker@v0.2.0
```

Documentation on pkg.go.dev is generated from the tagged source, so a
documentation-only fix is not visible until the next tag.

## A tag is permanent

The module proxy caches a version the first time anyone fetches it, including
its content hash. Moving or deleting a tag afterwards does not change what
users receive, and a changed tag produces a checksum mismatch that breaks
builds. If a release is wrong, publish the next patch version; never
re-tag.

For the same reason, do not tag from a branch that still needs a fixup commit.

## Retracting a release

If a version must not be used, say a masking bug that exposes data, add a
`retract` directive to `go.mod`, then tag a new patch version containing it:

```text
retract v0.2.0 // Leaks header values under SourceHeader.
```

Users on the retracted version see a warning from `go list -u -m all` and the
Go tooling stops selecting it automatically. The old version stays downloadable
by design, so a retraction is a signal, not a deletion. Announce the reason in
the changelog and, when the cause is a vulnerability, in a security advisory.
