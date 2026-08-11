"""Standalone text and HTML reporting."""

import html
import json
from pathlib import Path
from typing import Any, Dict, List


def load_run(path: Path) -> Dict[str, Any]:
    layers_path = path / "layers.json"
    def jsonl(name: str) -> List[Dict[str, Any]]:
        file_path = path / name
        return [json.loads(line) for line in file_path.read_text().splitlines() if line.strip()] if file_path.exists() else []

    api_results = jsonl("api-results.jsonl")
    steps: List[Dict[str, Any]] = []
    begins: Dict[str, float] = {}
    events = jsonl("events.jsonl")
    flows = json.loads((path / "flows.json").read_text())
    for event in events:
        scenario = str(event.get("scenario_id", "unattributed")).replace("/", "_")
        if event.get("type") == "API_CALL_BEGIN":
            begins[scenario] = float(event.get("epoch", 0))
        elif event.get("type") == "API_CALL_END" and scenario in begins:
            end = float(event.get("epoch", 0))
            related = [flow for flow in flows if scenario in flow.get("scenario_ids", [])]
            api = api_results[len(steps)] if len(steps) < len(api_results) else {}
            steps.append({"scenario": scenario, "started": begins.pop(scenario), "ended": end,
                          "duration_ms": round((end - begins.get(scenario, end)) * 1000, 1),
                          "ok": bool(api.get("ok", True)), "api": api,
                          "flows": related, "bytes_out": sum(int(f.get("bytes_out", 0)) for f in related),
                          "bytes_in": sum(int(f.get("bytes_in", 0)) for f in related),
                          "destinations": sorted({str(f.get("remote_ip", "")) for f in related}),
                          "blocked": any(f.get("blocked") for f in related)})
            # The begin timestamp is removed above; retain an accurate duration.
            steps[-1]["duration_ms"] = round((end - float(event.get("epoch", end))) * 1000, 1)
    # Reconstruct durations cleanly for event pairs, including very short API calls.
    for step in steps:
        matching = [e for e in events if e.get("scenario_id", "").replace("/", "_") == step["scenario"]]
        if len(matching) >= 2:
            step["duration_ms"] = round((float(matching[-1]["epoch"]) - float(matching[0]["epoch"])) * 1000, 1)
    return {"metadata": json.loads((path / "metadata.json").read_text()), "flows": flows,
            "analysis": json.loads((path / "analysis.json").read_text()),
            "layers": json.loads(layers_path.read_text()) if layers_path.exists() else {},
            "events": events, "steps": steps}


def render_text(data: Dict[str, Any]) -> str:
    meta, flows, analysis = data["metadata"], data["flows"], data["analysis"]
    lines = ["BOUNDARY-AUDIT REPORT", "", "Payload contents remain encrypted and were not inspected.", "", "Executive summary", "-------------------", "Mode: %s | Scenario: %s" % (meta.get("mode", "observe"), meta.get("scenario", "live")), "Flows: %d | External destinations: %d" % (len(flows), len({f["remote_ip"] for f in flows if f["scope"] == "external"})), "", "Scenario matrix", "----------------"]
    for scenario, result in analysis["scenarios"].items():
        note = "large outbound transfer" if result["bytes_out"] >= 1_000_000 else ""
        lines.append("%-18s flows=%-2d bytes_out=%-10d new=%s blocked=%d %s" % (scenario, result["flows"], result["bytes_out"], ",".join(result["new_destinations"]) or "none", result["blocked"], note))
    lines += ["", "What happened in each API step", "-------------------------------"]
    for step in data.get("steps", []):
        destinations = ", ".join(step["destinations"]) or "none"
        lines.append("%s: %s; %.1f ms; flows=%d; out=%d B; destinations=%s; %s" %
                     (step["scenario"], "PASS" if step["ok"] else "FAIL", step["duration_ms"],
                      len(step["flows"]), step["bytes_out"], destinations,
                      "blocked" if step["blocked"] else "allowed/no block"))
    lines += ["", "Destination inventory", "---------------------"]
    for flow in flows:
        note = "direct-IP/no DNS evidence" if flow.get("direct_ip") else ""
        lines.append("%s [%s] %s:%d/%s %s dns=%s verdict=%s flow=%s %s" % (flow["remote_ip"], flow.get("endpoint_role", "unknown"), flow["remote_ip"], flow["remote_port"], flow["transport_protocol"], ",".join(flow["scenario_ids"]), ",".join(flow["dns_names"]) or "no DNS evidence", "BLOCKED" if flow["blocked"] else "ALLOWED", flow["flow_id"], note))
    lines += ["", "Monitoring layers", "-----------------", " | ".join("%s=%s" % (name, value.get("status", "unknown")) for name, value in data.get("layers", {}).items()), "", "Limitations", "-----------", "This evidence is limited to the defined boundary, scenarios, and observation period. Encrypted payload semantics were not inferred."]
    return "\n".join(lines) + "\n"


def render_html(data: Dict[str, Any]) -> str:
    text = render_text(data)
    def step_card(step: Dict[str, Any]) -> str:
        flows = step["flows"]
        flow_lines = "".join("<li><strong>%s</strong> → <code>%s:%s</code>; %s out / %s in; %s</li>" %
                             (html.escape(str(flow.get("endpoint_role", "observed"))),
                              html.escape(str(flow.get("remote_ip", ""))), flow.get("remote_port", ""),
                              f"{int(flow.get('bytes_out', 0)):,} B", f"{int(flow.get('bytes_in', 0)):,} B",
                              "blocked" if flow.get("blocked") else "allowed") for flow in flows)
        return "<article class='step %s'><div class='step-head'><span class='step-number'>%s</span><div><h3>%s</h3><p class='muted'>API call completed in %.1f ms</p></div><b class='%s'>%s</b></div><div class='step-stats'><span><b>%d</b> flow(s)</span><span><b>%s</b> bytes out</span><span><b>%s</b> destination(s)</span></div><div class='step-result'><b>Network result:</b> %s</div><ul>%s</ul></article>" % (
            "pass" if step["ok"] else "fail", data.get("steps", []).index(step) + 1,
            html.escape(step["scenario"]), step["duration_ms"], "pass" if step["ok"] else "fail",
            "FUNCTIONAL PASS" if step["ok"] else "FUNCTIONAL FAIL", len(flows), f"{step['bytes_out']:,}",
            len(step["destinations"]), html.escape(", ".join(step["destinations"]) or "No network flow observed"),
            flow_lines or "<li class='muted'>No matching flow in the capture.</li>")

    steps = "".join(step_card(step) for step in data.get("steps", [])) or "<p class='muted'>No event markers were retained.</p>"
    rows = "".join("<tr><td>%s</td><td><strong>%s</strong><br><code>%s:%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                    (html.escape(",".join(f["scenario_ids"])), html.escape(str(f.get("endpoint_role", "observed"))),
                     html.escape(str(f["remote_ip"])), f["remote_port"], f"{int(f['bytes_out']):,} B",
                     html.escape(",".join(f["dns_names"]) or "No DNS evidence"),
                     "BLOCKED" if f["blocked"] else "ALLOWED", f["flow_id"])
                    for f in data["flows"])
    return ("<!doctype html><html><head><meta charset='utf-8'><title>boundary-audit report</title>"
            "<style>body{{font:15px system-ui;max-width:1150px;margin:32px auto;color:#18202a;background:#f6f8fa}}"
                "h1{{margin-bottom:4px}}h2{{margin-top:30px}}.panel,.step{{background:#fff;border:1px solid #d7e0e7;border-radius:12px;padding:18px;margin:12px 0;box-shadow:0 2px 8px #18202a0b}}"
                ".step{{border-left:5px solid #1683a5}}.step.fail{{border-left-color:#b42318}}.step-head{{display:flex;align-items:center;gap:12px}}.step-head h3{{margin:0}}.step-head p{{margin:3px 0 0}}.step-number{{background:#1683a5;color:#fff;border-radius:50%%;width:30px;height:30px;text-align:center;padding-top:5px;font-weight:700}}.step-head b{{margin-left:auto;padding:6px 9px;border-radius:6px;font-size:12px}}.pass{{color:#176b3a}}.step-head .pass{{background:#e8f6ed}}.step-head .fail{{background:#fff0ef;color:#b42318}}.step-stats{{display:flex;gap:22px;margin:15px 0;padding:10px;background:#f1f6f8;border-radius:7px}}.step-result{{margin:8px 0}.step ul{{margin:8px 0 0;padding-left:22px}}.muted{{color:#667685}}table{{border-collapse:collapse;width:100%%;background:#fff}}td,th{{border-bottom:1px solid #d7e0e7;padding:10px;text-align:left;vertical-align:top}}th{{color:#667685}}code{{background:#eef2f5;padding:2px 4px;border-radius:4px}}pre{{white-space:pre-wrap;background:#fff;border:1px solid #d7e0e7;border-radius:10px;padding:15px}}"
                "</style></head><body><h1>boundary-audit report</h1>"
                "<p><strong>Payload contents remain encrypted and were not inspected.</strong></p><section class='panel'><pre>%s</pre></section>"
                "<h2>Experiment, step by step</h2>%s<h2>Captured flow inventory</h2><table><tr><th>API step</th><th>Observed endpoint</th><th>Bytes out</th><th>DNS evidence</th><th>Verdict</th><th>Evidence ID</th></tr>%s</table></body></html>" % (html.escape(text), steps, rows))


def write_reports(run_dir: Path) -> None:
    data = load_run(run_dir)
    (run_dir / "report.txt").write_text(render_text(data), encoding="utf-8")
    (run_dir / "report.html").write_text(render_html(data), encoding="utf-8")
