# Notes for agents

Two things here fail quietly: the obvious command reports success while the
check you wanted never ran. Everything else — commands, CI layout, test
conventions — is in [CONTRIBUTING.md](CONTRIBUTING.md) and is not repeated.

## An example without `// Output:` is never executed

Go compiles an `Example` function with no `// Output:` block but does not run
it, so it stops matching the implementation without any signal. The block must
sit inside the function body: placed after the closing brace it is a floating
comment, the example silently stops running, and the whole suite still passes.

## Do not raise the Go version of the lint job

`golangci-lint` links `go/types` from the Go release that built it and panics
on standard-library sources from a newer toolchain. The lint job pins an older
Go on purpose. Raising it to `stable` produces a confusing panic rather than a
lint failure; the linter version and that pin move together.

## Where the rest lives

- [CONTRIBUTING.md](CONTRIBUTING.md) — commands, CI layout, test conventions.
- [ARCHITECTURE.md](ARCHITECTURE.md) — design decisions and invariants.
- Package documentation — the API, with runnable examples for every exported
  symbol.
