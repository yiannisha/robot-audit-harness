#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nftables tcpdump tshark dnsmasq hostapd iproute2
command -v tcpdump >/dev/null
command -v tshark >/dev/null
echo "Packet/DNS/TLS capture tools: $(tcpdump --version 2>&1 | head -1) / $(tshark --version 2>&1 | head -1)"
echo "Dependencies installed. No firewall or forwarding state was changed."
