# Reproducible demo

On Ubuntu or Debian, install Python 3.9+ and run:

```bash
cd boundary-audit
python3 -m pip install -e '.[dev]'
./scripts/demo.sh
./scripts/verify_demo.sh
```

No public DNS, SaaS, cloud credentials, or external services are used by the virtual path. For the host-backed path, install `iproute2`, `tcpdump`, `tshark`, `nftables`, `dnsmasq`, and (for Wi-Fi AP mode) `hostapd`. The demo prints the report directory and verification emits machine-readable JSON.

