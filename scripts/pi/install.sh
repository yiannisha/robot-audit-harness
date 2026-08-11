#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nftables tcpdump tshark dnsmasq hostapd iproute2
echo "Dependencies installed. No firewall or forwarding state was changed."
