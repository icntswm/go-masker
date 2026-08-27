# Security policy

## Scope

`go-masker` reduces accidental exposure of sensitive values in logs,
diagnostics, and observability payloads. It is not a replacement for access
control, encryption, secret storage, or review of application-specific
policies and custom rules.

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/icntswm/go-masker/security/advisories/new).
Do not report them in a public issue or pull request. Do not include real
credentials, production personal data, or unredacted payloads. Synthetic
reproductions and the smallest affected input are preferred.

Reports should include the affected operation, Go version, a minimal
reproduction, and whether the issue can expose the original value after an
error. Maintainers should acknowledge reports, assess severity, and publish a
fix or mitigation before discussing details publicly.

## Security expectations for users

- Treat custom `Policy` and `Rule` implementations as security-sensitive code.
- Keep fail-closed behavior; never replace an error result with the original
  value in an adapter.
- Review default key bindings, especially the conservative bare `id` binding,
  against the application's data model.
- Do not use real secrets in tests, benchmarks, examples, or golden fixtures.
