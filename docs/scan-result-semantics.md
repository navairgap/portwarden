# Scan result semantics (implemented)

Represent scan completion explicitly: `complete`, `partial` (plus
`failed`/`cancelled`, which must not produce inventory files at all). Only
compare baselines when the scan scope is compatible and the scan completed
successfully. Treat an unreachable target as unknown rather than as having
no services. Record transport and port alongside service observations. Show
evidence and timestamps for changes, and require confirmation before
replacing a trusted baseline.

## Stable target identity

Every inventory carries the exact requested target identifiers (whitespace
trimmed) in `scope`. Resolved addresses are observations of a scan, not
identity: a hostname is never silently replaced with one resolved IP in a
baseline, because DNS changes would otherwise look like a target change.
The scope fingerprint (docs/scan-scope-fingerprint.md) covers the requested
work, and comparisons are refused when fingerprints differ.

## Per-port observation states

Each recorded port carries an explicit state: `open`, `closed`,
`filtered`, `unreachable`, `not_scanned`, or `error`. A missing observation
is not equivalent to a closed port. The transport protocol stays with the
port number so TCP and UDP observations are never compared as if they were
the same service.

A service is reported as removed only when the target was reachable, the
same protocol and port were actually checked, the current observation is
`closed`, and both scans are complete with compatible scope. A filtered,
unreachable, not-scanned, or errored observation — or a missing one — stays
**unverified** and never erases a previously accepted service from the
baseline. Importers map scanner-specific states conservatively: nmap's
combined `open|filtered` becomes `filtered`, the unknown side.
