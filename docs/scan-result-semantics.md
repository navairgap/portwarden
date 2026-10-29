# scan result semantics

Represent scan completion explicitly: complete, partial, failed, or cancelled. Only compare baselines when the scan scope is compatible and the scan completed successfully. Treat an unreachable target as unknown rather than as having no services. Record transport and port alongside service observations. Show evidence and timestamps for changes, and require confirmation before replacing a trusted baseline.

## Stable target identity

Every result should carry the exact requested target identifier and the resolved addresses observed during that scan as separate fields. Do not silently replace a hostname with one resolved IP in the baseline, because DNS changes can otherwise look like a target change. Comparison reports should show the scan scope fingerprint (target set, protocols, port range, and relevant options) and refuse automatic diffs when fingerprints differ.
