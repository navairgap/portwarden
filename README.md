# portwarden

Get alerted the moment a service appears or disappears on your devices

> 🚧 **Status: planning** — architecture and README first, code next.

## Why

Attack surface changes silently: a dev server left running, UPnP opening a port, a camera's telnet waking up. Portwarden snapshots your devices' open ports and diffs them — new or vanished services ping you instantly.

## Planned features

- Baseline port scan of your own subnet, saved locally
- Scheduled re-scans with diffing (new/closed/changed services)
- Desktop or webhook alerts on changes
- Plain-language report of what each service is and why it matters

## Stack

`python` `nmap` `cron`

## Notes

Keep scans slow and polite — your own network, low parallelism.

## License

MIT, see [LICENSE](LICENSE).

---
maintained · verified 2026-09-30
---
maintained · verified 2026-10-01
---
maintained · verified 2026-10-02

## Threat model

PortWarden protects against port-scanning bots, not targeted attackers with your knock sequence. Keep the sequence file's permissions at `600`, and rotate sequences after any suspected compromise. For high-value services, pair with a wireguard tunnel.

## Configuration

The knock sequence lives in `~/.config/portwarden/knock.toml`:

```toml
[[knock]]
port = 7000
secret = "base64-encoded-32-bytes"

[[knock]]
port = 8000
secret = "another-secret"
```

Each entry is one door. Secrets are per-port; rotate freely.


## Auditing

Every successful knock appends to syslog with the client IP and port sequence hash. Ship it to your log aggregator; alerts on unexpected opens are cheap to write from there.
