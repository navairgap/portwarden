# CLI output and exit status contract

This is the implemented, stable CLI boundary. Scripts may rely on every
rule below; conformance is covered by offline tests.

## Commands

`compare BASELINE CURRENT`, `validate FILE`, `accept CURRENT --to BASELINE`,
`fingerprint FILE`, and `import-nmap NMAP_XML --scope TARGETS`.

## Output streams

- Human-readable mode writes the report to stdout and diagnostics
  (warnings, refusals) to stderr.
- `compare --json` writes exactly one JSON object followed by a newline to
  stdout. Warnings and diagnostics are never mixed into that stream; they
  go to stderr.
- The JSON envelope carries `schema_version`, `kind`, `tool`,
  `tool_version`, `status` (`changes_detected` or `no_changes`),
  `scope_fingerprint` (null when unknown or mismatched),
  `baseline_scanned_at`, `current_scanned_at`, `stale` (`true`, `false`,
  or `null` when the policy is not applied or an age is unknown),
  `counts`, and the `added`/`removed`/`changed`/`unverified` lists.
  Counts always equal the corresponding list lengths.
- A failed or partial snapshot remains distinguishable from a successful
  scan that found no services: `status` reflects findings only, while
  `unverified` entries carry the reason (missing observation, filtered,
  unreachable, not scanned, or error).
- Service names are remote-controlled text. They are validated at parse
  time (printable, bounded) and JSON-quoted in text output, so they stay
  inert in terminals and logs.
- Target identity, configured scope, and resolved addresses are kept
  separate; nothing infers additional targets from service responses or a
  baseline file.

## Exit statuses

| Code | Meaning |
| --- | --- |
| 0 | Success: no changes (compare), valid file (validate), or the operation completed |
| 1 | Comparison found changes (added, removed, or changed) |
| 2 | Invalid command line, unreadable file, or invalid inventory |
| 3 | Reserved for scan failure (PortWarden does not scan) |
| 4 | A partial inventory was used where a completed one is required, or an incomplete nmap run was refused |
| 5 | Comparison withheld: scope mismatch, or differing scope fingerprints without `--allow-scope-change` |

`unverified` entries alone do not set exit status 1: they are verification
gaps, not observed changes. Review them in the report.

## Baseline safety

Nothing replaces the accepted baseline implicitly. `accept` refuses partial
scans (exit 4), refuses to overwrite an existing baseline without `--force`
(exit 2), and writes atomically with mode 0600. `import-nmap --output`
follows the same overwrite rules for the file it produces.

## Conformance

Offline fixtures verify: JSON mode emits exactly one parseable object with
no progress text; diagnostics go to stderr; a comparison with findings exits
1 and a clean one exits 0; partial inventories exit 4 where completeness is
required; incompatible scope or fingerprints withhold the comparison with
exit 5 and empty stdout; and service names are quoted and bounded in text
output.
