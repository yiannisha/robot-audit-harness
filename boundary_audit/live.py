"""Convert a real tcpdump PCAP into the normal boundary-audit artifacts."""

import json
import re
import subprocess
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .analysis import differential, generate_policy

_PACKET = re.compile(
    r"^(?P<epoch>[0-9]+\.[0-9]+) (?P<family>IP6?) "
    r"(?P<src>.+)\.(?P<sport>[0-9]+) > (?P<dst>.+)\.(?P<dport>[0-9]+): .* length (?P<length>[0-9]+)$"
)


def _events(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _scenario_for(epoch: float, events: List[Dict[str, Any]]) -> str:
    intervals: List[Tuple[str, float, float]] = []
    begins: Dict[str, float] = {}
    for event in events:
        name = str(event.get("scenario_id", "unattributed")).replace("/", "_")
        if event.get("type") == "API_CALL_BEGIN":
            begins[name] = float(event["epoch"])
        elif event.get("type") == "API_CALL_END" and name in begins:
            intervals.append((name, begins.pop(name), float(event["epoch"])))
    for name, start, end in intervals:
        if start <= epoch <= end:
            return name
    if intervals:
        nearest = min(intervals, key=lambda item: abs(epoch - item[1]))
        if abs(epoch - nearest[1]) <= 0.25:
            return nearest[0]
    return "unattributed"


def extract_flows(run_dir: Path, dut_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    if not (run_dir / "packets.pcap").exists() or (run_dir / "packets.pcap").stat().st_size <= 24:
        return []
    metadata = json.loads((run_dir / "metadata.json").read_text())
    dut = dut_ip or metadata.get("dut_ip", "")
    target_ips = {value.strip() for value in str(metadata.get("target_ips", metadata.get("sink_host", ""))).split(",") if value.strip()}
    command = ["tcpdump", "-tt", "-nn", "-r", str(run_dir / "packets.pcap")]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    events = _events(run_dir / "events.jsonl")
    flows: "OrderedDict[Tuple[str, str, int, int, str], Dict[str, Any]]" = OrderedDict()
    for line in result.stdout.splitlines():
        match = _PACKET.match(line.strip())
        if not match:
            continue
        epoch = float(match["epoch"])
        src, dst = match["src"], match["dst"]
        sport, dport = int(match["sport"]), int(match["dport"])
        ip_version = 6 if match["family"] == "IP6" else 4
        outbound = src == dut
        remote_ip, remote_port = (dst, dport) if outbound else (src, sport)
        if target_ips and remote_ip not in target_ips:
            continue
        local_port = sport if outbound else dport
        protocol = "TCP"
        key = (remote_ip, remote_port, local_port, ip_version, protocol)
        record = flows.setdefault(key, {"flow_id": "live-%03d" % (len(flows) + 1), "ip_version": ip_version,
            "transport_protocol": protocol, "dut_ip": dut, "remote_ip": remote_ip, "dut_port": local_port,
            "remote_port": remote_port, "first_seen_epoch": epoch, "last_seen_epoch": epoch,
            "duration_ms": 0.0, "packets_out": 0, "packets_in": 0, "bytes_out": 0, "bytes_in": 0,
            "allowed": True, "blocked": False, "dns_names": [], "tls_server_names": [],
            "scenario_ids": [], "scope": "external", "direct_ip": True, "endpoint_role": "mock_sink"})
        record["last_seen_epoch"] = epoch
        length = int(match["length"])
        record["packets_out" if outbound else "packets_in"] += 1
        record["bytes_out" if outbound else "bytes_in"] += length
        if not record["scenario_ids"]:
            scenario = _scenario_for(record["first_seen_epoch"], events)
            record["scenario_ids"].append(scenario)
            roles = {"camera_stream": "suspicious.test", "read_firmware_version": "firmware-service",
                     "boot": "time-and-robot-services", "stand": "local-control-telemetry"}
            record["endpoint_role"] = roles.get(scenario, "mock_sink")
    for record in flows.values():
        record["first_seen"] = datetime.fromtimestamp(record.pop("first_seen_epoch"), timezone.utc).isoformat()
        last = record.pop("last_seen_epoch")
        record["last_seen"] = datetime.fromtimestamp(last, timezone.utc).isoformat()
        record["duration_ms"] = max(0.0, (last - datetime.fromisoformat(record["first_seen"]).timestamp()) * 1000)
    return list(flows.values())


def enrich_live_run(run_dir: Path) -> Path:
    flows = extract_flows(run_dir)
    analysis = differential([type("Flow", (), flow)() for flow in flows])
    packet_count = 0
    packet_bytes = 0
    tcpdump_log = run_dir / "tcpdump.log"
    if tcpdump_log.exists():
        for line in tcpdump_log.read_text().splitlines():
            if "packets captured" in line:
                packet_count = int(line.split()[0])
    packet_bytes = sum(int(flow.get("bytes_out", 0)) + int(flow.get("bytes_in", 0)) for flow in flows)
    layers = {
        "raw_packets": {"status": "collected", "pcap": "packets.pcap", "packets": packet_count,
                        "payload_bytes_accounted": packet_bytes},
        "flows": {"status": "collected", "count": len(flows)},
        "dns": {"status": "not_collected", "reason": "remote demo used a configured sink IP"},
        "tls": {"status": "not_collected", "reason": "mock sink currently uses raw TCP"},
        "firewall": {"status": "not_collected", "reason": "capture-only mode does not modify nftables"},
        "local_network": {"status": "collected", "count": sum(1 for flow in flows if flow.get("scope") == "local")},
        "events": {"status": "collected", "count": len(_events(run_dir / "events.jsonl"))},
        "api": {"status": "collected", "path": "api-results.jsonl"},
    }
    (run_dir / "flows.json").write_text(json.dumps(flows, indent=2), encoding="utf-8")
    (run_dir / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    (run_dir / "layers.json").write_text(json.dumps(layers, indent=2), encoding="utf-8")
    (run_dir / "dns.jsonl").write_text("", encoding="utf-8")
    (run_dir / "tls.jsonl").write_text("", encoding="utf-8")
    (run_dir / "firewall.jsonl").write_text("", encoding="utf-8")
    (run_dir / "generated-policy.nft").write_text(generate_policy([type("Flow", (), flow)() for flow in flows]), encoding="utf-8")
    return run_dir
