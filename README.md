# PortWarden

A planned, local-first monitor for changes in services exposed by devices on a network you administer.

> **Status: design stage.** This repository currently contains project documentation only; the monitor is not implemented yet.

## Problem

Services appear and disappear over time: a development server is left running, a device enables remote access, or a router configuration changes. PortWarden is intended to record an authorized baseline and make later differences easy to review.

## Intended workflow

1. Configure an explicit list of devices or an authorized subnet.
2. Run a low-rate inventory and save the baseline locally.
3. Compare later inventories with the baseline.
4. Report new, removed, and changed services with timestamps.
5. Optionally notify through a user-configured local or webhook channel.

## Design constraints

- Only scan targets explicitly configured by the operator.
- Use conservative timeouts and concurrency by default.
- Never change firewall rules or disable services automatically.
- Keep inventory data local unless the operator enables a notification integration.
- Make errors and partial scans visible; do not treat an incomplete scan as a clean result.

## Planned milestones

- [ ] Define a versioned baseline format.
- [ ] Implement a scanner adapter and input validation.
- [ ] Add deterministic diffing and unit tests using fixture data.
- [ ] Add CLI output and JSON export.
- [ ] Document permissions, rate controls, and safe deployment.

## Scope

PortWarden is a change monitor, not a port-knocking daemon or an access-control system. It should complement—not replace—host firewalls, asset management, and vulnerability management.

## Development

The first implementation should keep network access behind a small interface so tests can run offline. Contributions should include reproducible examples and tests for edge cases.

## License

MIT. See [LICENSE](LICENSE).


## Inventory correctness

Only compare baselines from completed scans with compatible scope. Represent partial or failed scans explicitly so unreachable targets are not mistaken for removed services. Require confirmation before replacing an accepted baseline.


## Maintenance and verification notes

Clarify inventory semantics: failed or partial scans must not be interpreted as removed services; compare only compatible completed scans and require confirmation before baseline replacement.
