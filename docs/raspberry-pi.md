# Raspberry Pi deployment

The Raspberry Pi hosts both the simulator/DUT and the monitoring agent. A
controller host connects directly to the gRPC service over the LAN; no SSH
tunnel is required.

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

## Control from the controller host

From the controller-host repository:

```bash
uv run python scripts/remote_robot_demo.py \
  <DEVICE-IP> \
  --output pi-evidence \
  --boot
```

The script starts monitoring remotely, executes `boot`, `stand`,
`move_forward`, `camera_stream`, and `camera_stop`, stops the session, and
downloads the evidence bundle.

For the interactive UI, run the console on the controller host:

```bash
uv run python scripts/security_console.py \
  --runs-root pi-evidence \
  --device <DEVICE-IP>:50051 \
  --port 8080
```

Open `http://127.0.0.1:8080`. Monitoring starts automatically after the Pi
connects. The action controls remain disabled until the session is active.
Each action refreshes the evidence and External Communication panel. `Clear
run` finalizes the current bundle, clears the active view, preserves the run
in History, and starts the next monitoring session automatically.

The default `boot` action uses `pool.ntp.org` and `example.com` endpoints. It
can therefore produce DNS, UDP, and TLS traffic when the Pi has Internet
access. `network_errors` in the action result records connection failures.

See [results.md](results.md) for artifact and status interpretation.
