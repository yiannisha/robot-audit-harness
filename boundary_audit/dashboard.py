"""Generate a standalone visual index for immutable run artifacts.

The dashboard intentionally uses inline SVG and CSS only. It can be opened
from disk, copied into a presentation, or hosted by any static file server.
"""

import html
import json
from pathlib import Path
from typing import Any, Dict, List


def _run_summary(path: Path) -> Dict[str, Any]:
    metadata = json.loads((path / "metadata.json").read_text())
    flows_path = path / "flows.json"
    flows = json.loads(flows_path.read_text()) if flows_path.exists() else []
    layers_path = path / "layers.json"
    scenario_bytes: Dict[str, int] = {}
    for flow in flows:
        for scenario in flow.get("scenario_ids", ["unattributed"]):
            scenario_bytes[scenario] = scenario_bytes.get(scenario, 0) + int(flow.get("bytes_out", 0))
    return {
        "id": path.name,
        "metadata": metadata,
        "flows": flows,
        "bytes_out": sum(int(flow.get("bytes_out", 0)) for flow in flows),
        "external": len({flow.get("remote_ip") for flow in flows if flow.get("scope") == "external"}),
        "blocked": sum(1 for flow in flows if flow.get("blocked")),
        "scenario_bytes": scenario_bytes,
        "layers": json.loads(layers_path.read_text()) if layers_path.exists() else {},
        "findings": [{"scenario": ", ".join(flow.get("scenario_ids", [])),
                      "role": flow.get("endpoint_role", flow.get("remote_ip")),
                      "physical_ip": flow.get("remote_ip"),
                      "bytes_out": flow.get("bytes_out", 0),
                      "reason": "large outbound transfer" if int(flow.get("bytes_out", 0)) >= 1_000_000 else "direct IP/no DNS evidence" if flow.get("direct_ip") else "observed"}
                     for flow in flows if int(flow.get("bytes_out", 0)) >= 1_000_000 or flow.get("direct_ip")],
    }


def _bar_chart(scenarios: Dict[str, int], width: int = 900) -> str:
    if not scenarios:
        return "<p class='muted'>No normalized flow data in the latest run.</p>"
    height = 54 + 34 * len(scenarios)
    maximum = max(scenarios.values()) or 1
    bars = []
    for index, (name, amount) in enumerate(sorted(scenarios.items(), key=lambda item: item[1], reverse=True)):
        y = 30 + index * 34
        bar_width = max(2, int(560 * amount / maximum))
        label = html.escape(name)
        bars.append("<text x='0' y='{0}' class='chart-label'>{1}</text>"
                    "<rect x='170' y='{1}' width='{2}' height='18' rx='4' class='bar'/><text x='{3}' y='{4}' class='chart-value'>{5:,} B</text>".format(
                        y + 14, label, bar_width, 180 + bar_width, y + 14, amount))
    return "<svg viewBox='0 0 {0} {1}' role='img' aria-label='Bytes out by scenario'>{2}</svg>".format(width, height, "".join(bars))


def _history_chart(summaries: List[Dict[str, Any]], width: int = 900) -> str:
    selected = summaries[:12]
    if not selected:
        return "<p class='muted'>No runs yet.</p>"
    maximum = max(item["bytes_out"] for item in selected) or 1
    bars = []
    bar_width = max(20, min(58, int(700 / len(selected))))
    for index, item in enumerate(selected):
        height = max(3, int(180 * item["bytes_out"] / maximum))
        x = 40 + index * (bar_width + 10)
        y = 205 - height
        short_id = html.escape(item["id"].split("_")[0].replace("T", " "))
        bars.append("<a href='runs/{0}/report.html'><title>{1}: {2:,} bytes</title><rect x='{3}' y='{4}' width='{5}' height='{6}' rx='4' class='bar-history'/></a><text transform='translate({3},{7}) rotate(-45)' class='axis-label'>{1}</text>".format(
            html.escape(item["id"]), short_id, item["bytes_out"], x, y, bar_width, height, 236))
    return "<svg viewBox='0 0 900 260' role='img' aria-label='Bytes out by retained run'><line x1='30' y1='205' x2='880' y2='205' class='axis'/>{}</svg>".format("".join(bars))


def _flow_rows(item: Dict[str, Any]) -> str:
    rows = []
    for flow in sorted(item["flows"], key=lambda value: int(value.get("bytes_out", 0)), reverse=True):
        scenarios = html.escape(", ".join(flow.get("scenario_ids", [])))
        destination = "{}:{}".format(flow.get("remote_ip", ""), flow.get("remote_port", ""))
        flags = []
        if flow.get("direct_ip"):
            flags.append("direct IP")
        if int(flow.get("bytes_out", 0)) >= 1_000_000:
            flags.append("large transfer")
        if flow.get("blocked"):
            flags.append("blocked")
        rows.append("<tr><td>{}</td><td><code>{}</code></td><td>{:,}</td><td>{}</td><td>{}</td></tr>".format(
            scenarios, html.escape(destination), int(flow.get("bytes_out", 0)),
            html.escape(", ".join(flow.get("dns_names", [])) or "no DNS evidence"),
            html.escape(", ".join(flags) or "observed")))
    return "".join(rows) or "<tr><td colspan='5' class='muted'>No flows</td></tr>"


def render_dashboard(runs_root: Path) -> str:
    summaries: List[Dict[str, Any]] = []
    if runs_root.exists():
        for path in sorted(runs_root.iterdir(), reverse=True):
            if path.is_dir() and (path / "metadata.json").exists():
                summaries.append(_run_summary(path))
    latest = summaries[0] if summaries else {"id": "none", "flows": [], "bytes_out": 0, "external": 0, "blocked": 0, "scenario_bytes": {}, "metadata": {}}
    total_bytes = sum(item["bytes_out"] for item in summaries)
    total_destinations = len({flow.get("remote_ip") for item in summaries for flow in item["flows"]})
    run_rows = []
    for item in summaries:
        metadata = item["metadata"]
        run_rows.append("<tr><td><a href='runs/{0}/report.html'>{0}</a></td><td>{1}</td><td>{2}</td>"
                        "<td>{3}</td><td>{4}</td><td>{5:,}</td><td>{6}</td><td><a href='runs/{0}/packets.pcap'>PCAP</a></td></tr>".format(
                            html.escape(item["id"]), html.escape(str(metadata.get("backend", ""))),
                            html.escape(str(metadata.get("scenario", ""))), len(item["flows"]),
                            item["external"], item["bytes_out"], item["blocked"]))
    latest_meta = latest["metadata"]
    latest_name = html.escape(str(latest.get("id", "none")))
    return """<!doctype html><html><head><meta charset="utf-8"><title>boundary-audit dashboard</title>
<style>
:root{{--ink:#17202a;--muted:#617180;--line:#d8e0e7;--blue:#087ea4;--purple:#7654a5;--red:#b42318;--bg:#f5f7fa}}
*{{box-sizing:border-box}}body{{font:15px system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--ink)}}
main{{max-width:1240px;margin:0 auto;padding:32px}}h1{{margin:0 0 5px;font-size:30px}}h2{{margin:30px 0 12px;font-size:20px}}
.subtitle,.muted{{color:var(--muted)}}.subtitle{{margin:0 0 28px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}
.card{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 2px 8px #17202a0b}}.metric{{font-size:28px;font-weight:700;margin-top:8px}}.metric-label{{color:var(--muted);font-size:13px}}
.panel{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px;overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}th{{color:var(--muted);font-weight:600}}a{{color:#075985;text-decoration:none}}a:hover{{text-decoration:underline}}code{{background:#eef2f5;padding:3px 5px;border-radius:4px}}
.bar{{fill:var(--blue)}}.bar-history{{fill:var(--purple)}}.chart-label{{font-size:13px;fill:var(--ink)}}.chart-value{{font-size:12px;fill:var(--muted)}}.axis{{stroke:var(--line);stroke-width:2}}.axis-label{{font-size:10px;fill:var(--muted)}}
.latest{{border-left:4px solid var(--blue)}}@media(max-width:800px){{main{{padding:18px}}.grid{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><main><h1>boundary-audit</h1>
<p class="subtitle">Evidence dashboard for retained runs. Payload contents remain encrypted and were not inspected.</p>
<section class="grid"><div class="card"><div class="metric-label">Retained runs</div><div class="metric">{0}</div></div>
<div class="card"><div class="metric-label">Total bytes out</div><div class="metric">{1:,}</div></div>
<div class="card"><div class="metric-label">Unique destinations</div><div class="metric">{2}</div></div>
<div class="card"><div class="metric-label">Blocked flows</div><div class="metric">{3}</div></div></section>
<h2>Latest run: <code>{4}</code></h2><section class="grid"><div class="card latest"><div class="metric-label">Backend / mode</div><div>{5} / {6}</div></div>
<div class="card"><div class="metric-label">Scenario</div><div>{7}</div></div><div class="card"><div class="metric-label">Flows</div><div class="metric">{8}</div></div>
<div class="card"><div class="metric-label">Bytes out</div><div class="metric">{9:,}</div></div></section>
<h2>Latest-run traffic volume</h2><section class="panel">{10}</section>
<h2>Run history</h2><section class="panel">{11}</section>
<h2>Latest-run flow inventory</h2><section class="panel"><table><thead><tr><th>Scenario</th><th>Destination</th><th>Bytes out</th><th>DNS evidence</th><th>Finding flags</th></tr></thead><tbody>{12}</tbody></table></section>
<h2>All retained runs</h2><section class="panel"><table><thead><tr><th>Run</th><th>Backend</th><th>Scenario</th><th>Flows</th><th>Destinations</th><th>Bytes out</th><th>Blocked</th><th>Evidence</th></tr></thead><tbody>{13}</tbody></table></section>
<p class="subtitle">Latest run: {14}. Reports and raw PCAPs remain linked from the tables.</p></main></body></html>""".format(
        len(summaries), total_bytes, total_destinations, sum(item["blocked"] for item in summaries), latest_name,
        html.escape(str(latest_meta.get("backend", "unknown"))), html.escape(str(latest_meta.get("mode", "unknown"))),
        html.escape(str(latest_meta.get("scenario", "unknown"))), len(latest["flows"]), latest["bytes_out"],
        _bar_chart(latest["scenario_bytes"]), _history_chart(summaries), _flow_rows(latest), "".join(run_rows), latest_name)


def write_dashboard(runs_root: Path, output: Path) -> Path:
    output.write_text(render_dashboard(runs_root), encoding="utf-8")
    return output
