# Baseline import and export (proposed)

Baseline files can reveal device names, addresses, and exposed services. Treat them as security-sensitive local inventory, even when they contain no credentials.

## Import validation

1. Enforce a maximum file size before parsing.
2. Decode UTF-8 strictly and parse one JSON object.
3. Validate the schema version, timestamp, target identity, completion state, and every service entry before accepting the file.
4. Reject duplicate service keys, invalid ports, unsupported protocols, malformed timestamps, and contradictory completion metadata.
5. Keep the imported data separate from the currently accepted baseline until validation and operator review finish.

Unknown optional fields may be retained for forward compatibility, but unknown major schema versions must not be silently interpreted as the current format.

## Export behavior

Export only on an explicit operator action. Write to a temporary file in the destination directory, flush it, and atomically replace the requested output after the complete serialization succeeds. Do not overwrite an existing baseline without confirmation. Use restrictive file permissions where the platform supports them.

Service banners and labels may contain remote-controlled text. Redact credentials and control characters before including them in human-readable exports; keep any raw evidence opt-in and clearly marked as untrusted.

## Integrity and provenance

Record the tool version, schema version, creation time, configured target, scope fingerprint, and completion state. A checksum can detect accidental corruption, but it is not proof of origin unless the file is authenticated by a separately managed signing key. Do not describe an unsigned local file as tamper-proof.

## Tests

Use temporary files to cover oversized input, malformed UTF-8, invalid schema versions, duplicate services, failed writes, preservation of an existing baseline, and cleanup of temporary files. Never test destructive replacement against a user's real inventory.