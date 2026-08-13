# Device-host demo

Install the project on both the device host and controller host:

```bash
uv sync
```

On the device host, install the Linux collection tools and start the gRPC
service as described in [device-host.md](device-host.md). Then, from the
controller host, run the live demo:

```bash
uv run python scripts/remote_robot_demo.py \
  <DEVICE-IP> \
  --output device-evidence \
  --boot
```

The demo performs real simulator actions over gRPC and downloads the evidence
bundle produced by the device-resident monitor. It requires the device host's
network capture permissions and does not use an SSH tunnel.

For the live security console, run `scripts/security_console.py` on the controller host
with `--device <DEVICE-IP>:50051`. It starts monitoring automatically after the device host
connects, refreshes evidence after every action, and keeps completed runs in
History after `Clear run`.
