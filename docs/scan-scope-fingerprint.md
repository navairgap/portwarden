# Scan scope fingerprint (proposed)

A comparison is meaningful only when two inventories describe the same requested work. PortWarden should compute a deterministic scope fingerprint before starting a scan and persist the inputs used to produce it.

## Included inputs

- The configured target identity, preserved exactly as entered after documented whitespace normalization.
- The requested transport protocols and normalized port sets or ranges.
- Scanner options that can change coverage, such as connect timeout, retry count, and probe mode.
- The scanner schema/version that defines how observations are represented.

Do not include transient results such as resolved IP addresses, elapsed time, or the set of ports that happened to answer. Store resolved addresses separately as observations. This lets an operator see DNS changes without silently redefining the configured target.

## Canonicalization

Serialize the scope fields in a fixed key order and normalize protocol names to lowercase. Expand and sort port selections numerically, remove duplicate ports, and reject values outside 1–65535. Do not sort or merge target names in a way that changes their identity. Encode the canonical representation as UTF-8 and hash it with a documented algorithm such as SHA-256.

The fingerprint is a compatibility aid, not a security signature. It does not prove that a scan was authorized or that a baseline was not modified.

## Comparison rules

- Compare automatically only when fingerprints match and both scans are complete.
- When fingerprints differ, show the differing scope fields and require an explicit operator decision.
- A partial result must remain partial even when its successful probes match the prior baseline.
- Preserve the original scope data alongside the fingerprint so operators can inspect why two scans differ.

## Fixture cases

Use deterministic fixtures to verify that equivalent port ordering produces the same fingerprint, while a changed target, protocol, port set, or coverage-affecting option produces a different one. Include invalid and duplicate port inputs. All tests should run offline and must not initiate network connections.