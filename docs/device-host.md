# Device-host deployment

`boundary-audit` is hardware agnostic at its integration boundary. The
monitored device host runs the DUT or simulator and the monitoring agent. A
separate controller host connects to that agent over gRPC. The device host can
be a Raspberry Pi, an embedded Linux computer, an industrial PC, or another
Linux system with the required capture privileges.

```text
Controller host  ── direct LAN gRPC ──>  Device host
                                      ├─ DUT or simulator
                                      └─ monitoring agent
```

## Device-host requirements

The device host needs:

- Python and this repository installed with `uv`;
- a writable evidence directory;
- `dumpcap` or `tcpdump` for packet capture;
- `tshark` for packet-level DNS/TLS decoding;
- optional `nftables`, `iproute2`, and DNS/AP tools for additional layers;
- permission to capture on the selected network interface.

On Debian-based systems, the convenience installer is:

```bash
uv sync
./scripts/pi/install.sh
```

The script name reflects the original Raspberry Pi deployment, but the
packages and monitoring service are not Raspberry Pi-specific.

## Start the device service

Run from a writable checkout directory on the device host:

```bash
uv run python -m boundary_audit.grpc_sdk \
  --bind 0.0.0.0 \
  --port 50051 \
  --monitor-interface any \
  --monitor-root "$PWD/runs"
```

Use a specific interface such as `eth0` or `wlan0` when unrelated traffic
should be excluded. The current gRPC service uses insecure transport and is
intended for a trusted test network.

## Connect from the controller host

Run the remote demo:

```bash
uv run python scripts/remote_robot_demo.py \
  <DEVICE-IP> \
  --output device-evidence \
  --boot
```

Or start the security console:

```bash
uv run python scripts/security_console.py \
  --runs-root device-evidence \
  --device <DEVICE-IP>:50051 \
  --port 8080
```

Monitoring starts automatically when the device is reachable. The console
enables actions only after the device and monitoring session are ready. Each
action updates the active evidence; `Clear run` finalizes the current bundle,
clears the active view, preserves the run in History, and starts the next
monitoring session.

The existing `--robot` option remains accepted as a compatibility alias for
`--device`.
