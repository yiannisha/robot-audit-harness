"""Deterministic normalization, differential analysis, attribution, and policy."""

from collections import defaultdict
from statistics import median
from typing import Any, Dict, Iterable, List, Mapping

from .models import Flow


def classify_scope(remote_ip: str, dut_ip: str = "10.77.0.2") -> str:
    if remote_ip.startswith(("10.", "192.168.", "172.16.")) or remote_ip == dut_ip or remote_ip.startswith("fd00:"):
        return "local"
    return "external"


def differential(flows: Iterable[Flow], baseline_scenarios: Iterable[str] = ("baseline",)) -> Dict[str, Any]:
    records = list(flows)
    def key(flow: Flow) -> str:
        return getattr(flow, "endpoint_role", None) or flow.remote_ip
    baseline = {key(f) for f in records if any(x in baseline_scenarios for x in f.scenario_ids)}
    by_scenario: Dict[str, List[Flow]] = defaultdict(list)
    for flow in records:
        for scenario in flow.scenario_ids:
            by_scenario[scenario].append(flow)
    result: Dict[str, Any] = {"baseline_destinations": sorted(baseline), "scenarios": {}}
    for name, selected in sorted(by_scenario.items()):
        destinations = {key(f) for f in selected}
        result["scenarios"][name] = {
            "destinations": sorted(destinations),
            "new_destinations": sorted(destinations - baseline),
            "physical_destinations": sorted({f.remote_ip for f in selected}),
            "bytes_out": sum(f.bytes_out for f in selected),
            "blocked": sum(1 for f in selected if f.blocked),
            "flows": len(selected),
        }
    return result


def attribute(repetitions: Mapping[str, List[Flow]], baseline: Mapping[str, List[Flow]]) -> List[Dict[str, Any]]:
    """Apply the documented >=2/3 present and >=2/3 absent heuristic."""
    output: List[Dict[str, Any]] = []
    names = sorted(set(repetitions) | set(baseline))
    for destination in names:
        action_runs = repetitions.get(destination, [])
        baseline_runs = baseline.get(destination, [])
        action_count = len(action_runs)
        base_count = len(baseline_runs)
        if action_count >= 2 and base_count <= 1:
            times = [getattr(f, "duration_ms", 0.0) for f in action_runs]
            output.append({"destination": destination, "action_runs": action_count, "baseline_runs": base_count,
                           "classification": "strongly_action_correlated", "median_latency_ms": median(times) if times else 0})
    return output


def generate_policy(flows: Iterable[Flow], table: str = "boundary_audit") -> str:
    lines = ["#!/usr/sbin/nft -f", "", "table inet %s {" % table, "  chain forward {", "    type filter hook forward priority 0; policy drop;", "    ct state established,related accept"]
    seen: set = set()
    for flow in flows:
        key = (flow.remote_ip, flow.remote_port, flow.transport_protocol)
        if flow.allowed and not flow.blocked and key not in seen and flow.scope == "external":
            seen.add(key)
            proto = flow.transport_protocol.lower()
            lines.append("    ip%s daddr %s %s dport %d accept" % ("6" if flow.ip_version == 6 else "", flow.remote_ip, proto, flow.remote_port))
    lines += ["    # default deny is intentional", "  }", "}", ""]
    return "\n".join(lines)
