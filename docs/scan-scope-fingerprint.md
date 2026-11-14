# Scan scope fingerprint (implemented)

A comparison is meaningful only when two inventories describe the same
requested work. PortWarden computes a deterministic scope fingerprint and
persists it in inventory files; the algorithm below is part of the stable
contract and is covered by fixture tests.

## Included inputs

- The schema version of the inventory format.
- The configured target identity, preserved exactly as entered after
  whitespace trimming, then deduplicated and sorted for canonicalization.
- The requested transport protocols, normalized to lowercase, deduplicated,
  and sorted.
- The requested port selection: range strings expanded, values validated
  against 1-65535, deduplicated, and sorted numerically.
- Coverage-affecting options supplied by the scanner adapter (flat scalar
  or list-of-scalar values only).

## Deliberately excluded inputs

- Transient results: resolved IP addresses, elapsed time, and the set of
  ports that happened to answer.
- Scanner identity and command lines (kept in `provenance`): an output
  filename such as `-oX later.xml` describes bookkeeping, not coverage, and
  must never make two identical scans incompatible.

## Canonicalization and hashing

1. Build the canonical document:
   `{"schema_version": <int>, "scope": [...], "scan_parameters": {...}}`,
   omitting `scan_parameters` entirely when the file records none.
2. Serialize with `json.dumps(canonical, sort_keys=True, separators=(",", ":"),
   ensure_ascii=True)` and encode as UTF-8.
3. Hash with SHA-256 and prefix the lowercase hex digest with `sha256:`.

## Comparison rules

- Compare automatically only when scope text matches and both scans are
  complete.
- When both inventories declare fingerprints and they differ, the
  comparison is withheld (exit status 5) and the differing values are shown
  on stderr. `compare --allow-scope-change` records an explicit operator
  decision; a genuine scope-text mismatch is never overridden.
- An inventory that declares a fingerprint is verified at load time: the
  declared value must equal the value recomputed from its contents, or the
  file is rejected.
- When only one side declares a fingerprint, the comparison proceeds but
  stderr carries a warning that compatibility could not be verified.
- A partial result remains partial even when its successful probes match
  the prior baseline.
- The fingerprint is a compatibility aid, not a security signature. It does
  not prove that a scan was authorized or that a baseline was not modified.

## Fixture cases covered

Equivalent port ordering and scope ordering produce the same fingerprint; a
changed target, protocol, port set, option, or schema version produces a
different one; invalid and duplicate port inputs are rejected; declared
fingerprints must match file contents. All tests run offline and never
initiate network connections.
