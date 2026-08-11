#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -rf runs
uv run python -m boundary_audit.cli lab up
uv run python -m boundary_audit.cli run full_matrix --mode observe --repeats 3
./scripts/verify_demo.sh
echo "demo complete; reports are under $ROOT/runs"
