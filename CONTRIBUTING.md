# Contributing

Thanks for helping make PortWarden better. This is a small, deliberately
conservative tool; the bar for contributions is "safe by default, honest
about failure, reproducible offline."

## Development setup

```sh
uv sync                 # environment + dev tools
uv run pytest           # offline test suite
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy             # strict
```

Python 3.10+ is supported; the runtime must stay on the standard library
with zero dependencies. Do not add runtime dependencies.

## Ground rules

- **No scanning.** PortWarden never opens network connections. Scanner
  integration means converting output files the operator already produced.
- **Fail loudly.** Anything ambiguous in an inventory is rejected, not
  coerced. Never guess: a missing observation is not a closed port, an
  unknown age is `null`, a mismatched fingerprint withholds the
  comparison.
- **Operator decisions are explicit.** Destructive or cross-scope actions
  need flags (`--force`, `--allow-scope-change`, `--allow-partial`), and
  the CLI exit-status contract in `docs/cli-output-contract.md` is stable.
- **Docs are the spec.** The documents in `docs/` describe implemented
  behavior; change code and docs together.

## Tests

- Every bug fix and feature ships with tests. Fixtures live in
  `tests/fixtures/`; nothing may open a socket or touch files outside the
  test's temporary directory.
- CLI conformance tests use in-process invocation with captured output.
- Run the full suite before pushing: `uv run pytest`.

## Submitting changes

1. Keep commits atomic with imperative subjects
   (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`).
2. Update `CHANGELOG.md` for user-visible changes.
3. Ensure CI is green: lint, format, strict type check, tests, build.

## Reporting problems

Security issues: see [SECURITY.md](SECURITY.md). Everything else: open a
GitHub issue with the version, command line, and a minimal input file.
