#!/usr/bin/env bash
set -euo pipefail
echo "Remove only the boundary-audit-owned nft table and temporary service configuration."
echo "No global nft flush is performed; inspect with: sudo nft list ruleset"
