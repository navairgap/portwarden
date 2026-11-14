# Changelog

All notable changes to PortWarden are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-14

First stable release: a finished, offline baseline-comparison tool for
authorized service inventories.

### Added

- Subcommand CLI: `compare`, `validate`, `accept`, `fingerprint`, and
  `import-nmap`, with a documented exit-status contract (0/1/2/4/5) and
  strict stdout/stderr stream discipline.
- Inventory format v1: explicit scope (IP literals, hostnames, and CIDR
  subnets), per-port observation states (`open`, `closed`, `filtered`,
  `unreachable`, `not_scanned`, `error`), RFC 3339 `scanned_at` with an
  explicit UTC offset requirement, `scan_parameters`, `provenance`, and a
  self-verifying `scope_fingerprint`.
- Deterministic comparison into added, removed, changed, and unverified
  categories. A baseline service is removed only when the current scan
  observed the port closed; missing or unknown observations never erase an
  accepted service.
- Scope fingerprinting (canonical JSON + SHA-256) gating comparisons:
  differing fingerprints withhold the comparison with exit status 5 unless
  `--allow-scope-change` is passed.
- Comparison reports: a stable JSON envelope (`--json`) and a bounded,
  deterministic text report with JSON-quoted service names, plus a
  snapshot-age policy via `--max-age`.
- nmap XML adapter: offline conversion of `nmap -oX` output with an
  authoritative declared scope, coverage parameters taken from `scaninfo`,
  conservative state mapping, and partial-run refusal.
- Atomic baseline writes (temp file, fsync, mode 0600, rename) with
  explicit `--force` confirmation before replacing an accepted baseline,
  and a 64 MiB size ceiling on inventory reads.
- Installable package: src layout, `portwarden` console script,
  `python -m portwarden`, `py.typed`, zero runtime dependencies
  (Python 3.10+ standard library only).
- Continuous integration: lint, format check, strict type check, and tests
  on Python 3.10-3.14, plus sdist/wheel build artifacts.
- Comprehensive offline test suite (150+ tests) including an end-to-end
  operator workflow, with nmap XML fixtures.

### Changed

- Scope targets are validated with the same strictness as service hosts,
  and surrounding whitespace is normalized instead of silently kept.
- The comparison exit status for scope incompatibility moved from 2 to 5
  (withheld) to distinguish it from invalid input.

### Fixed

- Non-UTF-8 inventory files no longer crash with a traceback; they are
  reported as input errors.
- The nmap command line (including the `-oX` output filename) no longer
  leaks into the scope fingerprint, so identical scans remain compatible.

[1.0.0]: https://github.com/navairgap/portwarden/releases/tag/v1.0.0
