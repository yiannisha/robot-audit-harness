"""Offline deterministic experiment runner.

The virtual evidence provider models what a gateway would observe. It is
deliberately separate from the DUT adapter and never consults ground truth in
the analysis path; the provider is the lab's packet/flow evidence source.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from .analysis import classify_scope, differential, generate_policy
from .device import DeviceAdapter
from .models import DnsObservation, Event, Flow, NetworkMode, RunMetadata, TlsObservation
from .pydantic_compat import model_dump


def _write_jsonl(path: Path, values: List[object]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            value = model_dump(value)
            handle.write(json.dumps(value, sort_keys=True, default=str) + "\n")


def _empty_scenario_analysis() -> dict:
    return {
        "destinations": [],
        "new_destinations": [],
        "physical_destinations": [],
        "bytes_out": 0,
        "blocked": 0,
        "flows": 0,
    }


class VirtualGateway:
    """A gateway-side test observer for the unprivileged virtual backend.

    The real backend observes packets outside the DUT.  This provider is only
    used when no network namespace or packet capture is available; it models
    the gateway's view, not the DUT's API response.
    """

    NETWORK_BEHAVIOR = {
        "baseline": [("telemetry.vendor.test", "198.18.0.9", 443, 240)],
        "boot": [("time.vendor.test", "198.18.0.10", 123, 96),
                 ("telemetry.vendor.test", "198.18.0.9", 443, 180)],
        "state_read": [("telemetry.vendor.test", "198.18.0.9", 443, 96)],
        "motion": [("telemetry.vendor.test", "198.18.0.9", 443, 128)],
        "camera_stream": [("suspicious.test", "198.18.0.20", 443, 8_000_000)],
        "read_firmware_version": [],
        "update": [("updates.vendor.test", "198.18.0.11", 443, 1024)],
        "local_discovery": [("", "10.77.0.3", 5353, 160)],
        "ipv6": [("v6.suspicious.test", "fd00::20", 443, 512)],
    }

    def __init__(self, mode: NetworkMode) -> None:
        self.mode = mode

    def flows_for(self, scenario: str, occurrence: int, start: datetime) -> List[Flow]:
        values = self.NETWORK_BEHAVIOR.get(scenario, [])
        flows: List[Flow] = []
        for index, item in enumerate(values):
            hostname, remote_ip, remote_port, bytes_out = item
            ip_version = 6 if ":" in remote_ip else 4
            local = classify_scope(remote_ip)
            blocked = self.mode in (NetworkMode.AIRGAP, NetworkMode.ENFORCE) and (scenario in ("camera_stream", "ipv6") or remote_ip == "198.18.0.9")
            allowed = not blocked
            timestamp = start + timedelta(milliseconds=200 + index * 40)
            hostname = str(hostname)
            flow = Flow(flow_id="f-%s-%02d-%02d" % (scenario, occurrence, index), ip_version=ip_version,
                        transport_protocol="UDP" if int(remote_port) in (123, 5353) else "TCP",
                        dut_ip="10.77.0.2", remote_ip=remote_ip, dut_port=40000 + index,
                        remote_port=int(remote_port), first_seen=timestamp, last_seen=timestamp + timedelta(milliseconds=25),
                        duration_ms=25.0, packets_out=4, packets_in=3, bytes_out=0 if blocked else int(bytes_out),
                        bytes_in=0 if blocked else 128, allowed=allowed, blocked=blocked,
                        dns_names=[] if not hostname else [hostname], tls_server_names=[] if int(remote_port) != 443 else ([hostname] if hostname else []),
                        scenario_ids=[scenario], scope="local" if local == "local" and remote_ip != "fd00::20" else "external",
                        direct_ip=not bool(hostname))
            flows.append(flow)
        return flows


def run_experiment(scenario: str, mode: NetworkMode, output_root: Path, device: DeviceAdapter,
                  repeats: int = 3, seed: int = 1337) -> Path:
    run_id = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ") + "_%s_%s_%s" % (scenario, mode.value, uuid.uuid4().hex[:6])
    directory = output_root / run_id
    directory.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc)
    metadata = RunMetadata(tool_version="0.1.0", backend="virtual", mode=mode, scenario=scenario, command="boundary-audit run %s --mode %s" % (scenario, mode.value), start=started, random_seed=seed)
    events: List[Event] = []
    flows: List[Flow] = []
    dns: List[DnsObservation] = []
    tls: List[TlsObservation] = []
    device.reset()
    selected = ["baseline", scenario] if scenario != "baseline" else ["baseline"]
    for name in selected:
        for occurrence in range(repeats):
            point = started + timedelta(seconds=len(events) * 0.001)
            events.append(Event(type="SCENARIO_BEGIN", scenario_id=name, timestamp=point, monotonic_ms=len(events), details={"repeat": occurrence + 1}))
            events.append(Event(type="BASELINE_BEGIN", scenario_id=name, timestamp=point, monotonic_ms=len(events)))
            result = device.execute(type("Action", (), {"name": name, "parameters": {}})())
            events.append(Event(type="API_CALL_SUCCESS" if result.ok else "API_CALL_FAILURE", scenario_id=name, timestamp=point, monotonic_ms=len(events), details={"status": result.status_code}))
            events.append(Event(type="OBSERVATION_BEGIN", scenario_id=name, timestamp=point, monotonic_ms=len(events)))
            observed = VirtualGateway(mode).flows_for(name, occurrence, point)
            flows.extend(observed)
            for flow in observed:
                for hostname in flow.dns_names:
                    dns.append(DnsObservation(query_name=hostname, response_records=[flow.remote_ip], timestamp=flow.first_seen))
                if flow.tls_server_names:
                    tls.append(TlsObservation(flow_id=flow.flow_id, timestamp=flow.first_seen, tls_version="TLS 1.3", sni=flow.tls_server_names[0], alpn="h2", certificate_subject="CN=%s" % flow.tls_server_names[0], certificate_sans=[flow.tls_server_names[0]], certificate_issuer="boundary-audit lab CA"))
            events += [Event(type="OBSERVATION_END", scenario_id=name, timestamp=point, monotonic_ms=len(events)), Event(type="COOLDOWN_BEGIN", scenario_id=name, timestamp=point, monotonic_ms=len(events)), Event(type="SCENARIO_END", scenario_id=name, timestamp=point, monotonic_ms=len(events))]
    analysis = differential(flows)
    for name in selected:
        analysis["scenarios"].setdefault(name, _empty_scenario_analysis())
    metadata.end = datetime.now(timezone.utc)
    (directory / "metadata.json").write_text(json.dumps(model_dump(metadata), indent=2, default=str), encoding="utf-8")
    _write_jsonl(directory / "events.jsonl", events)
    _write_jsonl(directory / "dns.jsonl", dns)
    _write_jsonl(directory / "tls.jsonl", tls)
    (directory / "flows.json").write_text(json.dumps([model_dump(flow) for flow in flows], indent=2, default=str), encoding="utf-8")
    (directory / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    (directory / "layers.json").write_text(json.dumps({
        "raw_packets": {"status": "collected", "pcap": "packets.pcap", "packets": "virtual-evidence"},
        "flows": {"status": "collected", "count": len(flows)},
        "dns": {"status": "collected", "count": len(dns)},
        "tls": {"status": "collected", "count": len(tls)},
        "firewall": {"status": "collected", "count": len(flows)},
        "local_network": {"status": "collected", "count": sum(1 for flow in flows if flow.scope == "local")},
        "events": {"status": "collected", "count": len(events)},
        "api": {"status": "collected", "count": len(events)},
    }, indent=2), encoding="utf-8")
    (directory / "firewall.jsonl").write_text("\n".join(json.dumps({"flow_id": f.flow_id, "verdict": "blocked" if f.blocked else "allowed"}) for f in flows) + "\n", encoding="utf-8")
    (directory / "packets.pcap").write_bytes(b"boundary-audit virtual evidence placeholder; use Linux backend for authoritative tcpdump PCAP\n")
    (directory / "generated-policy.nft").write_text(generate_policy(flows), encoding="utf-8")
    return directory
