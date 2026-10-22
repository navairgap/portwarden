# scan result semantics

Represent scan completion explicitly: complete, partial, failed, or cancelled. Only compare baselines when the scan scope is compatible and the scan completed successfully. Treat an unreachable target as unknown rather than as having no services. Record transport and port alongside service observations. Show evidence and timestamps for changes, and require confirmation before replacing a trusted baseline.
