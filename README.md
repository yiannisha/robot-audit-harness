# boundary-audit

`boundary-audit` exercises an IoT/robotic device, records its network and host
behavior, and produces replayable evidence for later analysis.

The working deployment is:

```text
 Controller host
       │ direct LAN gRPC
       ▼
 Device host
   ├─ simulator or DUT
   └─ monitoring agent
       ├─ dumpcap PCAP capture
       ├─ DNS/TLS metadata
       ├─ process/socket snapshots
       ├─ firewall snapshot
       └─ durable evidence bundle
```

The device host owns collection. The controller host sends actions over gRPC
and downloads a fresh snapshot after every action; the controller does not
need an SSH tunnel.

## Install

```bash
uv sync --extra dev
```

For a Debian-based device host, install the collection tools:

```bash
./scripts/pi/install.sh
```

This installs and verifies `dumpcap`, `tcpdump`, and `tshark`, plus the
optional firewall/DNS/AP tools. See [docs/device-host.md](docs/device-host.md)
and the [Raspberry Pi profile](docs/raspberry-pi.md).

## Device host simulator and monitoring

On the device host, from a writable checkout directory:

```bash
uv sync
./scripts/pi/install.sh

uv run python -m boundary_audit.grpc_sdk \
  --bind 0.0.0.0 \
  --port 50051 \
  --monitor-interface any \
  --monitor-root "$PWD/runs"
```

Do not use an assumed home path unless it exists and is writable by the
service account. The current gRPC service is intentionally simple and uses
insecure transport; keep port `50051` on the trusted LAN.

## Controller host demo

From the controller host, connect directly to the device host's address:

```bash
uv run python scripts/remote_robot_demo.py \
  <DEVICE-IP> \
  --output pi-evidence \
  --boot
```

The script starts a monitored run, executes simulator actions over gRPC,
stops collection, and downloads the bundle locally.

Inspect the result:

```bash
RUN=$(find pi-evidence -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
cat "$RUN/layers.json"
cat "$RUN/api-results.jsonl"
cat "$RUN/dns.jsonl"
cat "$RUN/tls.jsonl"
tcpdump -nn -r "$RUN/packets.pcap"
```

The default `boot` action contacts configured `pool.ntp.org` and `example.com`
endpoints and can produce DNS, UDP, and TLS observations when Internet access
is available.

## Security console

The controller-side security console focuses on outside communication and
possible interference rather than generic robot telemetry. It shows external
and unattributed flows, DNS/TLS observations, action/event timing, layer
coverage, recent runs, and guarded robot controls.

To browse downloaded device evidence without controlling a device:

```bash
uv run python scripts/security_console.py \
  --runs-root pi-evidence \
  --port 8080
```

Open `http://127.0.0.1:8080`.

To control the device host directly from the console:

```bash
uv run python scripts/security_console.py \
  --runs-root pi-evidence \
  --device <DEVICE-IP>:50051 \
  --port 8080
```

The console starts monitoring automatically when the robot is available and
keeps a session active. The control panel stays disabled until both the robot
connection and monitoring session are confirmed. Each action is recorded, the
active evidence is refreshed, and the investigation view updates immediately.
Clear the run when you are done; the evidence is finalized, the active view is
reset, and a new monitoring session starts automatically. The completed run
remains in History. The External Communication panel has removable IP filter
tags pre-filled with the controller-host address, device-host address, and
loopback addresses.
Remove a tag to inspect that traffic or type an IP and press Enter to add one.
Unattributed flows, unsolicited inbound traffic, new destinations, blocked
traffic, and degraded capture layers are intentionally prominent.

## What the results mean

Each run contains raw evidence, normalized flows, event/API correlation,
layer statuses, differential analysis, a generated policy, and a checksum
manifest. Read [docs/results.md](docs/results.md) for the artifact reference
and status semantics.

## Other components

The repository also contains:

- device action models;
- flow normalization, attribution, and policy generation;
- gRPC control and artifact APIs;
- nftables ownership abstractions;
- device-host installation and deployment guidance;
- tests for virtual runs, gRPC, real loopback capture, and evidence bundles.

See [docs/architecture.md](docs/architecture.md),
[docs/methodology.md](docs/methodology.md),
[docs/results.md](docs/results.md), and
[docs/threat-model.md](docs/threat-model.md).
