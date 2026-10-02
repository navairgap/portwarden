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
