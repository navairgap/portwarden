# PortWarden baseline format (superseded)

This draft described a single-target format with `complete`/`target`
fields and per-service `state`/`service_hint` entries. It was never
implemented and has been superseded.

**The implemented format is documented in [inventory-v1.md](inventory-v1.md).**
It generalizes this draft to an explicit scope list, replaces the
`complete` boolean with an explicit `status` field, and keeps per-port
observation states with the same safety intent: incomplete scans are never
reported as clean comparisons, duplicate keys are rejected rather than
last-write-wins, and timestamps are RFC 3339 with an explicit UTC offset.
