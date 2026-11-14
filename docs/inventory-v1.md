# PortWarden inventory format v1

PortWarden compares files; it does not discover hosts or open network
connections. Generate these files only from scans of assets you own or are
authorized to assess. This document is the authoritative format reference
and matches the implementation.

## Example

```json
{
  "schema_version": 1,
  "status": "complete",
  "scope": ["192.0.2.10", "203.0.113.0/24"],
  "scanned_at": "2026-11-14T08:00:05Z",
  "scan_parameters": {
    "protocols": ["tcp"],
    "ports": [22, 80, 443]
  },
  "scope_fingerprint": "sha256:48b0ca5b...",
  "provenance": {
    "scanner": "nmap",
    "scanner_version": "7.95",
    "scan_args": "nmap -oX scan.xml -p 22,80,443 192.0.2.10 203.0.113.0/24"
  },
  "services": [
    {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "name": "https", "state": "open"}
  ]
}
```

## Field rules

- `schema_version` must be exactly `1`. Readers reject other major versions
  rather than silently misreading them.
- `status` is `complete` or `partial`. Failed and cancelled runs must not
  produce inventory files. Only complete inventories may be compared or
  promoted to a baseline; `validate` accepts partial files so they can be
  inspected, and `compare`/`accept` refuse them (exit status 4).
- `scope` is a non-empty list of unique target identifiers after whitespace
  trimming: IP literals, hostnames, or CIDR subnets. A prefix with host bits
  set (for example `203.0.113.1/24`) is invalid. Targets are compared as
  exact normalized text; the same targets listed in a different order are
  the same scope.
- `services` is a list. Each entry requires `host`, `port` (integer 1-65535,
  not a boolean), and `protocol` (`tcp` or `udp`); `name` is optional
  (printable, at most 80 characters, no control characters) and `state`
  defaults to `open`. The `(host, port, protocol)` tuple appears at most
  once; duplicates are rejected instead of last-write-wins.
- Every service host must belong to the scope: an exact target match, or an
  IP literal inside a CIDR target. Hostnames never match subnets implicitly;
  DNS resolution is an observation, not an identity.
- `scanned_at`, when present, is an RFC 3339 timestamp with an explicit UTC
  offset (`Z` or `±HH:MM`). Timezone-naive values are rejected. It is
  observation metadata for display and age policy — never proof of currency.
- `scan_parameters`, when present, may contain `protocols` (`tcp`/`udp`,
  lowercased), `ports` (integers or `"a-b"` range strings, expanded),
  and `options` (flat scalar or list-of-scalar values). These describe the
  *requested work* and are part of the scope fingerprint.
- `scope_fingerprint`, when present, must be `sha256:` followed by 64 hex
  characters and must match the value recomputed from the file contents;
  a mismatch rejects the file at load time.
- `provenance`, when present, records scanner identity and command line.
  It is deliberately **outside** `scan_parameters`: an output filename in a
  command line must not change scope compatibility.
- Unknown fields are ignored by readers and preserved by tools that rewrite
  an inventory (`accept` re-serializes the original document).

## Per-port states

`open`, `closed`, `filtered`, `unreachable`, `not_scanned`, and `error`.
Importers map scanner-specific states to these; combined states such as
nmap's `open|filtered` map to the unknown side (`filtered`), never the
optimistic side. A missing observation is not a closed port.

## Comparison semantics

Comparing two complete inventories with identical normalized scope yields:

- **added** — open now, not an open service in the baseline.
- **removed** — open in the baseline, observed `closed` now.
- **changed** — open in both, different `name`.
- **unverified** — open in the baseline and missing from the current
  inventory, or observed in an unknown state. Baselines are never erased
  by unverified observations.

Results are sorted by host, then numerically by port. Both inventories must
carry the same scope; when both declare scope fingerprints and the
fingerprints differ, the comparison is withheld.

## Commands

```sh
portwarden import-nmap scan.xml --scope 192.0.2.10,203.0.113.0/24
portwarden validate snapshot.json
portwarden accept snapshot.json --to baseline.json
portwarden compare baseline.json current.json --json
portwarden fingerprint snapshot.json
```

Exit statuses are documented in docs/cli-output-contract.md. A changed
mapping is a prompt for human review, not proof of a vulnerability. Keep
baselines local and confirm the scope before accepting a new snapshot.
