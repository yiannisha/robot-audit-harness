# Raspberry Pi robot monitor

Target Raspberry Pi 5 / Raspberry Pi OS or Debian. The simulator/DUT and the
monitoring agent run on the Pi; the controller can connect directly to the
gRPC port from a laptop.

Install the capture and decoding tools:

```bash
cd ~/robot-audit-harness
./scripts/pi/install.sh
tshark --version
```

`tcpdump` supplies raw packets. `tshark` is used during replay to populate
`dns.jsonl` and `tls.jsonl`. If `tshark` is missing, those layers are reported
as `unavailable`; the run is not allowed to pretend they were collected.

Copy `config.example.yaml`, set the interfaces, and review every change.
`setup.sh` and `teardown.sh` are deliberately non-destructive guidance stubs:
production deployment must create a uniquely named nftables table, preserve
unrelated rules, and restore temporary forwarding/AP/DNS state on exit. Never
use `flush ruleset` on a shared gateway.

Start the robot simulator and monitor service for direct LAN gRPC control:

```bash
uv run python -m boundary_audit.grpc_sdk \
  --bind 0.0.0.0 \
  --port 50051 \
  --monitor-interface any \
  --monitor-root "$PWD/runs"
```

Use `wlan0` or `eth0` instead of `any` when the capture should be restricted
to one interface. Open TCP port `50051` in the Pi firewall if needed.

From the laptop, run:

```bash
uv run python scripts/remote_robot_demo.py <PI-IP> --output pi-evidence --boot
```

The script executes actions over gRPC, stops the Pi-side monitor, and downloads
the evidence bundle. Inspect `layers.json`, `flows.json`, `dns.jsonl`,
`tls.jsonl`, and `packets.pcap` in the downloaded run directory.
