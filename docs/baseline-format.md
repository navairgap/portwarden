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

## Diff semantics

Compare only complete inventories by default. Report added, removed, and changed service keys separately. If either inventory is incomplete, label the result partial and list the failed probes. A missing service in a partial scan is not evidence that the service disappeared.

## Fixture tests to add with the implementation

Cover valid v1 input, unknown schema versions, invalid ports, duplicate service keys, invalid timestamps, and incomplete scans. Keep tests offline and use checked-in fixtures.
