#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); runs = sorted((root / "runs").glob("*"))
assert runs, "no run artifacts"
seen = set()
for run in runs:
    analysis = json.loads((run / "analysis.json").read_text())
    seen.update(analysis["scenarios"])
    for name in ("metadata.json", "events.jsonl", "packets.pcap", "dns.jsonl", "tls.jsonl", "firewall.jsonl", "flows.json", "analysis.json"):
        assert (run / name).exists(), f"missing {name}"
assert {"boot", "camera_stream", "read_robot_state", "stand", "shutdown"} <= seen
print(json.dumps({"ok": True, "runs": len(runs), "scenarios": sorted(seen)}))
PY
