# Baseline import and export (implemented)

Baseline files can reveal device names, addresses, and exposed services.
Treat them as security-sensitive local inventory, even when they contain no
credentials.

## Import validation (implemented)

1. Enforce a maximum file size before parsing (64 MiB by default).
2. Decode UTF-8 strictly and parse one JSON object.
3. Validate the schema version, status, timestamp, scope, and every service
   entry before accepting the file.
4. Reject duplicate service keys, invalid ports, unsupported protocols,
   malformed timestamps, invalid CIDR prefixes, and declared fingerprints
   that do not match file contents.
5. Keep imported snapshots separate from the accepted baseline until
   `accept` promotes them.

Unknown optional fields are retained for forward compatibility (the
original document is re-serialized verbatim), but unknown major schema
versions are rejected rather than silently interpreted.

## Export behavior (implemented)

Export only on an explicit operator action (`import-nmap --output`,
`accept --to`). Writes go to a temporary file in the destination directory,
are flushed and fsynced, receive mode 0600, and atomically replace the
requested output only after the complete serialization succeeds. An
existing file is never overwritten without `--force`. The temporary file is
removed on any failure.

Service names may contain remote-controlled text. They are bounded and
stripped of control characters at parse time, and JSON-quoted in
human-readable reports.

## Integrity and provenance

Inventories record the tool-visible schema version, creation time,
configured scope, scope fingerprint, and completion state; `provenance`
keeps scanner identity and the command line outside the fingerprint. The
fingerprint detects scope incompatibility and accidental content drift, but
it is not proof of origin: an unsigned local file is not tamper-proof.

## Tests

Offline fixtures cover oversized input, malformed UTF-8, invalid schema
versions, duplicate services, refused overwrites, partial scans, temporary
file cleanup, and permission bits. Nothing destructive runs against a
real inventory.
