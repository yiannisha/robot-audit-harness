#!/usr/bin/env bash
set -euo pipefail
CONFIG="${1:-config.yaml}"
test -f "$CONFIG" || { echo "missing config: $CONFIG" >&2; exit 2; }
echo "Review $CONFIG, then apply forwarding/AP/DNS configuration explicitly."
echo "This script intentionally does not flush firewall rules or alter persistent state."
echo "Suggested manual sequence: enable temporary forwarding, configure hostapd/dnsmasq, install a unique nftables table, start tcpdump."
