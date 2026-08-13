# Raspberry Pi deployment

The Pi hosts both the simulator/DUT and the monitoring agent. The laptop
connects directly to the gRPC service over the LAN; no SSH tunnel is required.

## Install

On Raspberry Pi OS/Debian:

```bash
cd ~/side/dimensional/robot-audit-harness
uv sync
./scripts/pi/install.sh
tshark --version
dumpcap --version
```

The installer installs `dumpcap`, `tcpdump`, `tshark`, `nftables`, `iproute2`,
and the optional DNS/AP tools. It does not change firewall or forwarding state.

The capture process needs permission to open the interface. Verify:

```bash
sudo -n true
sudo -n dumpcap -i any -a duration:1 -w /tmp/capture-test.pcapng
```

## Start properly

Run from a writable repository directory. Do not use `/home/pi` unless that is
the actual home directory of the account running the service.

```bash
cd ~/side/dimensional/robot-audit-harness
mkdir -p runs

uv run python -m boundary_audit.grpc_sdk \
  --bind 0.0.0.0 \
  --port 50051 \
  --monitor-interface any \
  --monitor-root "$PWD/runs"
```

Use `wlan0` or `eth0` instead of `any` to reduce unrelated traffic. Open TCP
port `50051` on the Pi firewall if necessary. The current gRPC transport is
unauthenticated/insecure, so restrict access to the trusted test LAN.

## Control from the laptop

From the laptop repository:

```bash
uv run python scripts/remote_robot_demo.py \
  <PI-IP> \
  --output pi-evidence \
  --boot
```

The script starts monitoring remotely, executes `boot`, `stand`,
`move_forward`, `camera_stream`, and `camera_stop`, stops the session, and
downloads the evidence bundle.

The default `boot` action uses `pool.ntp.org` and `example.com` endpoints. It
can therefore produce DNS, UDP, and TLS traffic when the Pi has Internet
access. `network_errors` in the action result reports connection failures.

See [results.md](results.md) for artifact and status interpretation.
