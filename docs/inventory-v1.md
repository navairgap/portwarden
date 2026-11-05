# PortWarden inventory format v1

PortWarden compares files; it does not discover hosts or open network
connections. Generate these files only from scans of assets you own or are
authorized to assess.

A usable snapshot must be marked `status: complete`. Partial,
timed-out, or failed scans must never be used to infer that a service vanished.

```json
{
  "schema_version": 1,
  "status": "complete",
  "scope": ["192.0.2.10"],
  "services": [
    {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "name": "https"}
  ]
}
```

The scope is an explicit list of target identifiers. Every service entry must
belong to it. Each host/port/protocol tuple may appear once. Ports are integers
from 1 through 65535; protocols are `tcp` or `udp`.

Run a comparison with:

```sh
python3 portwarden.py baseline.json current.json
```

Exit status is 0 for no changes, 1 when additions/removals are reported, and 2
for invalid input. A changed mapping is a prompt for human review, not proof of
a vulnerability. Keep the baseline locally and confirm the scope before
accepting a new snapshot.
