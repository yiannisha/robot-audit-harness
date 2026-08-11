# Raspberry Pi gateway

Target Raspberry Pi 5 / Raspberry Pi OS or Debian. Copy `config.example.yaml`, set the upstream and isolated interfaces, and review every change. Run `scripts/pi/install.sh` to install dependencies. `setup.sh` and `teardown.sh` are deliberately non-destructive guidance stubs: production deployment must create a uniquely named nftables table, preserve unrelated rules, and restore temporary forwarding/AP/DNS state on exit. Never use `flush ruleset` on a shared gateway.

Capture the isolated interface with `tcpdump -i <dut-interface> -s 0 -w packets.pcap`, collect DNS resolver logs, and use the same JSON schemas as the virtual backend.

