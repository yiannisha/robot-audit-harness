# boundary-audit

`boundary-audit` exercises an IoT/robotic device, records its network and host
behavior, and produces replayable evidence for later analysis.

The working deployment is:

```text
 Laptop controller
       │ direct LAN gRPC
       ▼
 Raspberry Pi
   ├─ robot simulator or DUT
   └─ monitoring agent
       ├─ dumpcap PCAP capture
       ├─ DNS/TLS metadata
       ├─ process/socket snapshots
       ├─ firewall snapshot
       └─ durable evidence bundle
```

The Pi owns collection. The laptop starts actions and downloads completed
artifacts. The virtual backend remains available for deterministic, offline
CI and demos.

## Install

```bash
uv sync --extra dev
```

For Raspberry Pi/Debian collection tools:

```bash
./scripts/pi/install.sh
```

This installs and verifies `dumpcap`, `tcpdump`, and `tshark`, plus the
optional firewall/DNS/AP tools. See [docs/raspberry-pi.md](docs/raspberry-pi.md).

## Virtual simulation demo

This path needs no Pi or public Internet:

```bash
./scripts/demo.sh
```

Open a generated report:

```bash
open runs/*/report.html
```

Useful commands:

```bash
uv run python -m boundary_audit.cli doctor
uv run python -m boundary_audit.cli scenarios list
uv run python -m boundary_audit.cli run camera --mode observe
uv run python -m boundary_audit.cli run full_matrix --mode airgap
uv run python -m boundary_audit.cli run full_matrix --mode enforce
```

## Pi simulator and monitoring

On the Pi, from a writable checkout directory:

```bash
uv sync
./scripts/pi/install.sh

uv run python -m boundary_audit.grpc_sdk \
  --bind 0.0.0.0 \
  --port 50051 \
  --monitor-interface any \
  --monitor-root "$PWD/runs"
```

Do not use an assumed `/home/pi` path unless it exists and is writable by the
service account. The current gRPC service is intentionally simple and uses
insecure transport; keep port `50051` on the trusted LAN.

## Laptop controller demo

From the laptop, connect directly to the Pi's address:

```bash
uv run python scripts/remote_robot_demo.py \
  192.168.1.168 \
  --output pi-evidence \
  --boot
```

The script starts a monitored run, executes real simulator actions over gRPC,
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

## What the results mean

Each run contains raw evidence, normalized flows, event/API correlation,
layer statuses, differential analysis, a generated policy, and a checksum
manifest. Read [docs/results.md](docs/results.md) for the artifact reference
and status semantics.

## Other components

The repository also contains:

- deterministic virtual evidence generation;
- scenario/action models and repeated baseline comparison;
- flow normalization, attribution, and policy generation;
- gRPC control and artifact APIs;
- HTML/text reports and a web dashboard;
- nftables ownership abstractions;
- Raspberry Pi installation and deployment guidance;
- tests for virtual runs, gRPC, real loopback capture, and evidence bundles.

See [docs/architecture.md](docs/architecture.md),
[docs/methodology.md](docs/methodology.md),
[docs/results.md](docs/results.md), and
[docs/threat-model.md](docs/threat-model.md).
