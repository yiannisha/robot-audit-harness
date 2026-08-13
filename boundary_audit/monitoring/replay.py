"""Re-run normalization and analysis from a stored evidence bundle."""

import json
from pathlib import Path

from ..analysis import differential, generate_policy
from ..live import extract_flows
from .collectors import decode_with_tshark


def replay_run(run_dir: Path) -> Path:
    metadata = json.loads((run_dir / "metadata.json").read_text())
    decoded = decode_with_tshark(run_dir / "packets.pcap", run_dir / "dns.jsonl", run_dir / "tls.jsonl")
    flows = extract_flows(run_dir, dut_ip=json.loads((run_dir / "metadata.json").read_text()).get("dut_ip"))
    objects = [type("Flow", (), value)() for value in flows]
    analysis = differential(objects)
    (run_dir / "flows.json").write_text(json.dumps(flows, indent=2), encoding="utf-8")
    (run_dir / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    (run_dir / "generated-policy.nft").write_text(generate_policy(objects), encoding="utf-8")
    layers = {
        "raw_packets": {"status": "collected" if (run_dir / "packets.pcap").exists() and (run_dir / "packets.pcap").stat().st_size > 24 else "failed", "pcap": "packets.pcap", "recovery": metadata.get("capture_recovery", False)},
        "flows": {"status": "collected", "count": len(flows)},
        "dns": {"status": decoded["dns"], "count": decoded.get("dns_count", 0)},
        "tls": {"status": decoded["tls"], "count": decoded.get("tls_count", 0)},
        "firewall": {"status": "collected" if (run_dir / "firewall.jsonl").read_text().strip() else "not_collected", "count": sum(1 for _ in (run_dir / "firewall.jsonl").read_text().splitlines())},
        "processes": {"status": "collected", "count": sum(1 for _ in (run_dir / "processes.jsonl").read_text().splitlines())},
        "sockets": {"status": "collected", "count": sum(1 for _ in (run_dir / "sockets.jsonl").read_text().splitlines())},
        "local_network": {"status": "collected", "count": sum(1 for f in flows if f.get("scope") == "local")},
        "os": {"status": "collected", "source": "robot host metadata"},
        "events": {"status": "collected", "count": sum(1 for _ in (run_dir / "events.jsonl").read_text().splitlines())},
        "api": {"status": "collected", "count": sum(1 for _ in (run_dir / "api-results.jsonl").read_text().splitlines())},
    }
    (run_dir / "layers.json").write_text(json.dumps(layers, indent=2), encoding="utf-8")
    return run_dir
