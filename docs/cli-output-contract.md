# CLI output and exit status contract (proposed)

PortWarden is still in the design stage. This document defines a script-friendly
CLI boundary for the first implementation; it does not imply that commands or
scanning behavior already exist.

## Output streams

- Human-readable mode writes the summary to stdout and diagnostic context to
  stderr.
- JSON mode writes exactly one JSON object followed by a newline to stdout.
  Progress bars, warnings, and debug logs must never be mixed into that stream.
- A failed or partial scan must remain distinguishable from a successful scan
  that found no services.
- Do not include raw service banners by default. They are remote-controlled
  input and must be escaped and size-limited before display.
- Keep target identity, configured scope, and resolved addresses separate.
  Never infer additional targets from service responses or a baseline file.

## Suggested JSON envelope

```json
{
  "schema_version": 1,
  "scan_id": "local-000001",
  "target": "192.0.2.10",
  "status": "complete",
  "started_at": "2026-11-02T12:00:00Z",
  "finished_at": "2026-11-02T12:00:04Z",
  "scope_fingerprint": "sha256:...",
  "counts": {
    "requested": 3,
    "completed": 3,
    "failed": 0
  },
  "services": [],
  "errors": []
}
```

The example is illustrative. The implementation must document the exact
fingerprint algorithm and timestamp format before calling this schema stable.
Unavailable values should be omitted or represented as null, never guessed.

## Exit status proposal

| Code | Meaning |
| --- | --- |
| 0 | Scan completed; findings may be present |
| 2 | Invalid command line or configuration |
| 3 | Scan failed before a trustworthy inventory could be produced |
| 4 | Scan was partial or cancelled |
| 5 | Comparison was withheld because scope or baseline compatibility failed |

A non-empty service diff is not itself an execution error. Callers should read
the structured result to distinguish newly observed services from failures.

## Baseline safety

Producing output must not silently replace the accepted baseline. Baseline
creation or replacement is a separate, explicit operation, with confirmation
when an existing file would be overwritten. An incomplete scan must never be
promoted to a complete baseline.

## Conformance tests

Use offline fixtures and a fake scanner adapter to verify:

- JSON mode emits one parseable object and no progress text on stdout.
- Diagnostics are written to stderr.
- A complete scan with findings exits successfully.
- Partial, cancelled, and failed scans use their documented statuses.
- Incompatible scope prevents a comparison and does not modify the baseline.
- Remote-controlled labels are escaped and bounded before human-readable output.
