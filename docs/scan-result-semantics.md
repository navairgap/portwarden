# scan result semantics

Represent scan completion explicitly: complete, partial, failed, or cancelled. Only compare baselines when the scan scope is compatible and the scan completed successfully. Treat an unreachable target as unknown rather than as having no services. Record transport and port alongside service observations. Show evidence and timestamps for changes, and require confirmation before replacing a trusted baseline.

## Stable target identity

Every result should carry the exact requested target identifier and the resolved addresses observed during that scan as separate fields. Do not silently replace a hostname with one resolved IP in the baseline, because DNS changes can otherwise look like a target change. Comparison reports should show the scan scope fingerprint (target set, protocols, port range, and relevant options) and refuse automatic diffs when fingerprints differ.


## Per-port observation states

Represent each checked port with an explicit state: `open`, `closed`, `filtered`, `unreachable`, `not_scanned`, or `error`. A missing observation is not equivalent to a closed port. Keep the transport protocol with the port number so TCP and UDP observations are never compared as if they were the same service.

A service may be reported as removed only when the target was reachable, the same protocol and port were actually checked, the current observation is `closed`, and both scans have compatible scope fingerprints. A filtered, unreachable, skipped, or errored observation remains unknown and must not erase a previously accepted service from the baseline.
