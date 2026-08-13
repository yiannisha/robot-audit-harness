# Reproducible demo

Install the project with `uv` and run the deterministic virtual demo:

```bash
uv sync --extra dev
./scripts/demo.sh
./scripts/verify_demo.sh
```

No public DNS, SaaS, cloud credentials, or external services are used by the virtual path. For the host-backed path, install `iproute2`, `tcpdump`, `tshark`, `nftables`, `dnsmasq`, and (for Wi-Fi AP mode) `hostapd`. On Debian-based device hosts, run `scripts/pi/install.sh`; it verifies both `tcpdump` and `tshark`. The remote device demo is run from the controller host with `scripts/remote_robot_demo.py <DEVICE-IP> --output device-evidence`.

For the live security console, run `scripts/security_console.py` on the controller host
with `--device <DEVICE-IP>:50051`. It starts monitoring automatically after the device host
connects, refreshes evidence after every action, and keeps completed runs in
History after `Clear run`.
