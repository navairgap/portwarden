# PortWarden baseline format (draft v1)

This document defines a local JSON format for comparing authorized service inventories. It is a proposal until an implementation and fixture tests exist.

## Example

```json
{
  "schema_version": 1,
  "created_at": "2026-10-20T12:00:00Z",
  "target": "192.0.2.10",
  "scanner": { "name": "portwarden", "version": "0.1.0" },
  "complete": true,
  "services": [
    {
      "protocol": "tcp",
      "port": 443,
      "state": "open",
      "service_hint": "https"
    }
  ]
}
```

## Required rules

- `schema_version` is an integer; readers must reject unknown major versions rather than silently misread them.
- `created_at` is an RFC 3339 UTC timestamp.
- `target` identifies one explicitly configured host or address; never infer additional scan targets from a baseline.
- `complete` is false when any requested port or probe failed. An incomplete scan must not be reported as a clean comparison.
- Each service key is the pair `(protocol, port)`; protocol is currently `tcp` or `udp`, and port is 1–65535.
- Unknown fields may be ignored by readers but should be preserved by tools that rewrite a baseline where practical.
- Baselines are local data. Export or upload must be an explicit operator action.

## Canonicalization and ambiguity

- Reject duplicate `(protocol, port)` keys after protocol normalization; never use last-write-wins, because it can hide a changed service.
- Validate each service as an object before comparing it. Unknown `state` values and non-integer ports are invalid rather than silently coerced.
- A baseline with `complete: true` must represent every requested probe; if the implementation records failed probes, a non-empty failure list requires `complete: false`.
- Do not normalize hostnames into IP addresses implicitly. Keep the configured target identity in the baseline and report any resolved address separately.

## Diff semantics

Compare only complete inventories by default. Report added, removed, and changed service keys separately. If either inventory is incomplete, label the result partial and list the failed probes. A missing service in a partial scan is not evidence that the service disappeared.

## Deterministic comparison output

Sort service observations by protocol and numeric port before serialization or display. Numeric ordering matters: port 80 must sort before port 443, regardless of string formatting. When duplicate keys are present, reject the baseline instead of choosing the first or last record. Keep the original target identifier visible in every comparison report, and include the baseline timestamps so operators can identify stale snapshots.

## Fixture tests to add with the implementation

Cover valid v1 input, unknown schema versions, invalid ports, duplicate service keys, invalid timestamps, and incomplete scans. Keep tests offline and use checked-in fixtures.

## Timestamp freshness

Treat the creation timestamp as observation metadata, not proof that a scan is current. A comparison report should show the age of both snapshots and allow callers to apply an explicit maximum age. Do not silently discard an older but complete baseline; label it stale according to the caller's policy and preserve it for manual review. Parse timestamps with an explicit UTC offset and reject invalid or timezone-naive values.
