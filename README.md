# PortWarden

A local-first monitor for changes in services exposed by devices on a network
you administer.

PortWarden records an authorized baseline of the services your devices expose
and makes later differences easy to review: new services, removed services,
and renamed services, each reported with timestamps and a staleness policy.
It is a change monitor, not a scanner, an access-control system, or a
vulnerability manager — it complements host firewalls, asset management, and
vulnerability management.

[![CI](https://github.com/navairgap/portwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/navairgap/portwarden/actions/workflows/ci.yml)

## How it works

PortWarden **never scans networks and never opens connections**. You run your
own scanner (for example `nmap`) against assets you are authorized to assess,
and PortWarden converts the output into a versioned inventory, promotes
reviewed snapshots to a baseline, and compares later snapshots against it —
entirely offline.

```text
nmap -oX scan.xml -p 22,80,443 192.0.2.10 192.0.2.11
  │
  ▼
portwarden import-nmap scan.xml --scope 192.0.2.10,192.0.2.11
  │            (strict validation, scope-fingerprinted snapshot)
  ▼
portwarden accept snapshot.json --to baseline.json
  │            (your reviewed baseline, written atomically, mode 0600)
  ▼
portwarden compare baseline.json snapshot-next-week.json
               (added / removed / changed / unverified, exit code for CI)
```

## Install

PortWarden has **zero runtime dependencies** — it runs on the Python
standard library (Python 3.10+).

```sh
uv tool install .            # or: pipx install .
portwarden --version
```

From a checkout, without installing:

```sh
uv run portwarden --version  # or: python -m portwarden --version
```

## Quickstart

```sh
# 1. Run your own scan of assets you are authorized to assess.
nmap -oX scan.xml -p 22,80,443 192.0.2.10 192.0.2.11

# 2. Convert it into an inventory. The scope you declare is authoritative:
#    hosts in the XML outside the scope are refused, never inferred.
portwarden import-nmap scan.xml --scope 192.0.2.10,192.0.2.11 \
    --output snapshot.json

# 3. Validate and review the snapshot, then accept it as the baseline.
portwarden validate snapshot.json
portwarden accept snapshot.json --to baseline.json

# 4. Later: convert the new scan the same way and compare.
nmap -oX scan2.xml -p 22,80,443 192.0.2.10 192.0.2.11
portwarden import-nmap scan2.xml --scope 192.0.2.10,192.0.2.11 \
    --output snapshot2.json
portwarden compare baseline.json snapshot2.json --max-age 86400
```

`compare` prints a report listing **Added**, **Removed**, **Changed**, and
**Unverified** services. Add `--json` for exactly one machine-readable
report object on stdout.

## Commands

| Command | Purpose |
| --- | --- |
| `portwarden import-nmap SCAN.xml --scope T1,T2` | Convert nmap XML output into an inventory. |
| `portwarden validate FILE` | Strictly validate an inventory and summarize it. |
| `portwarden accept CURRENT --to BASELINE` | Promote a completed inventory to the accepted baseline. |
| `portwarden compare BASELINE CURRENT` | Compare two inventories; the core report. |
| `portwarden fingerprint FILE` | Print the scope fingerprint of an inventory. |

Useful flags: `compare --json`, `compare --max-age SECONDS`,
`compare --allow-scope-change`, `import-nmap --include-closed`,
`import-nmap --allow-partial`, and `accept --force`.

## What the report tells you

- **Added** — a service is open now and was not in the baseline.
- **Removed** — the current scan observed the port **closed**. A service is
  only reported removed when the scan actually checked and closed the door.
- **Changed** — the same endpoint reports a different service name.
- **Unverified** — the baseline service could not be confirmed this scan
  (not observed, or filtered/unreachable/errored). A missing observation is
  never treated as evidence that a service vanished, so partial scans can
  never erase your baseline.

Snapshots record when they were taken; `--max-age SECONDS` labels a report
**stale** when either snapshot is older than the policy. Ages the scanner did
not record are reported as unknown, never guessed.

## Exit statuses

| Code | Meaning |
| --- | --- |
| 0 | Success; no changes found (compare) or the file is valid (validate) |
| 1 | Comparison found changes |
| 2 | Invalid command line, unreadable file, or invalid inventory |
| 3 | Reserved (scan failure; PortWarden does not scan) |
| 4 | A partial inventory was used where a completed one is required |
| 5 | Comparison withheld: scope or fingerprint incompatibility |

## Safety model

- Only explicitly configured targets are ever considered. Service responses
  never add targets; a scanned host outside your declared scope is an error.
- Comparisons are gated on a documented [scope fingerprint](docs/scan-scope-fingerprint.md)
  over the requested work (targets, protocols, ports). Differing
  fingerprints withhold the comparison (exit 5) unless you pass
  `--allow-scope-change`.
- Baselines are written atomically with restrictive permissions (0600), and
  an existing baseline is only replaced with an explicit `--force`.
- Partial scans are refused as baselines and refused for import by default;
  incomplete work stays visible instead of masquerading as a clean result.
- Baseline files describe your devices; treat them as sensitive local data.
  Nothing is exported or uploaded unless you do it yourself.

The data format, validation rules, and comparison semantics are specified in
[docs/](docs/), along with a [baseline review checklist](docs/baseline-review-checklist.md).

## Development

```sh
uv sync          # create the environment and install dev tools
uv run pytest    # run the offline test suite
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy      # strict type check
uv build         # sdist + wheel
```

Tests are fully offline: fixtures include nmap XML, and no test opens a
network connection. Contributions should include reproducible examples and
tests for edge cases; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for reporting guidance and the trust model
of baseline files.

## License

MIT. See [LICENSE](LICENSE).
