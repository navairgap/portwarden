# Architecture

PortWarden is an offline, dependency-free Python package. This map shows
where each responsibility lives and which specification governs it.

## Module map

| Module | Responsibility | Specification |
| --- | --- | --- |
| `errors.py` | Exception hierarchy: `InventoryError`, `IncompleteInventoryError`, `ScopeMismatchError` | exit-status contract |
| `hosts.py` | Target validation: IP literals, hostnames, CIDR subnets; scope membership | inventory v1 field rules |
| `models.py` | `Service`, `ScanParameters`, `Inventory`: strict parsing and validation of documents | docs/inventory-v1.md |
| `timestamps.py` | Strict RFC 3339 parsing (explicit offset required), UTC normalization, ages | docs/inventory-v1.md |
| `fingerprint.py` | Canonical scope document, SHA-256 fingerprinting, scan-parameter normalization | docs/scan-scope-fingerprint.md |
| `diff.py` | Deterministic comparison into added/removed/changed/unverified | docs/scan-result-semantics.md |
| `report.py` | JSON envelope and human-readable text, staleness policy, label quoting | docs/cli-output-contract.md |
| `storage.py` | Size-limited loading, deterministic serialization, atomic writes (0600) | docs/baseline-import-export.md |
| `nmap.py` | nmap XML to inventory adapter with authoritative scope checking | docs/inventory-v1.md |
| `cli.py` | Subcommands, exit statuses, stream discipline, operator flags | docs/cli-output-contract.md |

## Data flow

```text
nmap XML ──nmap.py──▶ inventory document ──models.py──▶ Inventory
                            │                              │
                            ▼                              ▼
                    storage.py (atomic write)         diff.py compare()
                                                           │
                                                           ▼
                                                    report.py ──▶ stdout
```

Parsing is the single gate: every consumer (compare, accept, fingerprint,
validate) loads files through `Inventory.load`, so validation, the
fingerprint self-check, and timestamp rules apply identically everywhere.
The nmap adapter validates its own output through the same pipeline.

## Design invariants

1. **Strict by default.** Ambiguity is rejected, never coerced; unknown
   major schema versions are refused; duplicates are errors.
2. **Removals require evidence.** Only a `closed` observation removes a
   baseline service; missing/unknown states are unverified.
3. **Compatibility is computed, not assumed.** Scope text plus requested
   work (protocols, ports, options) form the fingerprint; scanner identity
   and command lines are provenance and stay out of it.
4. **Destructive actions are explicit.** `--force` replaces a baseline,
   `--allow-scope-change` overrides a fingerprint mismatch, and partial
   snapshots are refused unless `--allow-partial`.
5. **Streams are contracts.** `--json` is exactly one object on stdout;
   every diagnostic goes to stderr.
6. **Zero runtime dependencies.** Standard library only, Python 3.10+.

## Testing

`tests/` is fully offline. Fixtures provide nmap XML; CLI conformance runs
in-process with captured streams; `tests/test_workflow.py` exercises the
whole operator journey end to end. CI (`.github/workflows/ci.yml`) runs the
suite on Python 3.10-3.14 with lint, format check, and strict typing.
