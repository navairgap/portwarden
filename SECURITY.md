# Security Policy

PortWarden is an offline comparison tool for authorized service
inventories. Its threat model and reporting process are documented here.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Trust model

- **PortWarden does not scan.** It never opens network connections; every
  network action is yours, under your authorization.
- **Inventory files are data, not code.** They are parsed with strict
  validation, size limits, and stdlib-only decoding (no dynamic code
  execution, no external entity resolution in XML).
- **Baseline files are sensitive.** They describe exposed services on your
  devices. Keep them local, keep them mode 0600 (PortWarden writes them
  that way), and never commit them to shared repositories.
- **Service names are remote-controlled text.** They are bounded and
  stripped of control characters at parse time and JSON-quoted in
  human-readable output. Do not paste report content into a shell.
- **The scope fingerprint is a compatibility aid, not a signature.** An
  unsigned local file can be modified by anyone with write access; it is
  not tamper-proof. For provenance, use a separately managed signing key
  over the file.
- **Operator decisions are explicit.** Replacing a baseline requires
  `--force`; comparing across differing fingerprints requires
  `--allow-scope-change`; partial snapshots are refused by default.

## Reporting a vulnerability

Please open a private security advisory via GitHub's "Report a
vulnerability" button on the repository's Security tab, or contact the
maintainers directly. Please do not open public issues for exploitable
problems.

Include the version, the command line, a minimal input file demonstrating
the issue, and the expected versus actual behavior. Tests are appreciated;
this repository's suite is fully offline and new tests should be too.

## Scope

In scope: input parsing and validation, file handling, report generation,
CLI behavior, and packaging. Out of scope: the safety or authorization of
scans the operator chooses to run, and the security of external scanners
such as nmap.
