"""Small controller-side security console for robot evidence and gRPC control."""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from .grpc_sdk import DutGrpcClient


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                values.append({"parse_error": True, "raw": line})
    return values


def _run_summary(path: Path) -> Dict[str, Any]:
    metadata = json.loads((path / "metadata.json").read_text()) if (path / "metadata.json").exists() else {}
    layers = json.loads((path / "layers.json").read_text()) if (path / "layers.json").exists() else {}
    flows = json.loads((path / "flows.json").read_text()) if (path / "flows.json").exists() else []
    events = _read_jsonl(path / "events.jsonl")
    return {"id": path.name, "metadata": metadata, "layers": layers, "flows": flows,
            "events": events, "api": _read_jsonl(path / "api-results.jsonl"),
            "dns": _read_jsonl(path / "dns.jsonl"), "tls": _read_jsonl(path / "tls.jsonl"),
            "bytes_out": sum(int(flow.get("bytes_out", 0)) for flow in flows),
            "external_flows": [flow for flow in flows if flow.get("scope") == "external"],
            "unattributed_flows": [flow for flow in flows if not flow.get("scenario_ids") or
                                   "unattributed" in flow.get("scenario_ids", [])]}


class SecurityConsole:
    def __init__(self, runs_root: Path, robot_target: Optional[str] = None) -> None:
        self.runs_root = runs_root
        self.robot = DutGrpcClient(robot_target) if robot_target else None
        self.lock = threading.Lock()
        self.monitoring = False
        self.active_run_id: Optional[str] = None

    def runs(self) -> List[Dict[str, Any]]:
        if not self.runs_root.exists():
            return []
        return [_run_summary(path) for path in sorted(self.runs_root.iterdir(), reverse=True)
                if path.is_dir() and (path / "metadata.json").exists()]

    def action(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self.robot:
            raise RuntimeError("UI was started without --robot HOST:PORT")
        with self.lock:
            if not self.monitoring:
                raise RuntimeError("start monitoring before executing robot actions")
            return self.robot.execute(str(request["action"]), str(request.get("category", "background")),
                                      dict(request.get("parameters", {})))

    def start_monitor(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self.robot:
            raise RuntimeError("UI was started without --robot HOST:PORT")
        with self.lock:
            if self.monitoring:
                raise RuntimeError("a monitoring run is already active")
            result = self.robot.start_monitor(str(request.get("scenario", "ui_run")),
                                              str(request.get("mode", "observe")))
            self.monitoring = True
            self.active_run_id = str(result["run_id"])
            return result

    def stop_monitor(self) -> Dict[str, Any]:
        if not self.robot:
            raise RuntimeError("UI was started without --robot HOST:PORT")
        with self.lock:
            result = self.robot.stop_monitor()
            self.monitoring = False
            self._download_run(str(result["run_id"]))
            self.active_run_id = None
            return result

    def _download_run(self, run_id: str) -> None:
        if not self.robot:
            return
        output = self.runs_root / run_id
        output.mkdir(parents=True, exist_ok=True)
        for name in ("metadata.json", "events.jsonl", "api-results.jsonl", "packets.pcap",
                     "flows.json", "layers.json", "dns.jsonl", "tls.jsonl", "firewall.jsonl",
                     "processes.jsonl", "sockets.jsonl", "analysis.json", "manifest.json"):
            try:
                (output / name).write_bytes(self.robot.get_artifact(name))
            except Exception:
                continue

    def state(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"monitoring": self.monitoring, "active_run_id": self.active_run_id}
        if self.robot:
            try:
                result["robot"] = self.robot.health()
                result["monitor"] = self.robot.monitor_status()
            except Exception as error:
                result["robot_error"] = str(error)
        return result


HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>boundary-audit security console</title>
<style>
:root{color-scheme:dark;font:14px system-ui;background:#0a0f1d;color:#edf2ff}*{box-sizing:border-box}body{margin:0}header{padding:24px 5vw;background:linear-gradient(110deg,#111d38,#18284a);border-bottom:1px solid #33466f}h1,h2,h3{margin:0 0 8px}main{padding:24px 5vw;max-width:1500px;margin:auto}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;color:#91a9d8;font-weight:700}.intro{max-width:760px;color:#b9c6e2;line-height:1.5}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel{background:#111a2e;border:1px solid #2a3b62;border-radius:10px;padding:16px;box-shadow:0 6px 20px #0002}.metric{font-size:28px;font-weight:750}.metric-label{color:#aab8d5;margin-top:2px}.muted{color:#98a8c8}.danger{color:#ff817e}.warn{color:#ffd166}.good{color:#70e1a1}.panel{margin-top:16px}.panel-head{display:flex;justify-content:space-between;gap:16px;align-items:start;margin-bottom:12px}.help{color:#aab8d5;line-height:1.45;max-width:800px}.callout{padding:12px 14px;background:#172440;border-left:4px solid #6f9cff;border-radius:6px;margin:12px 0;line-height:1.45}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #263655;font-size:13px}th{color:#9fb0d2;font-size:11px;text-transform:uppercase;letter-spacing:.06em}tr.clickable{cursor:pointer}tr.clickable:hover{background:#192744}button,select,input{background:#192744;color:#edf2ff;border:1px solid #48618f;border-radius:6px;padding:9px 10px}button{cursor:pointer;font-weight:650}button.primary{background:#3d6fd1;border-color:#6592ef}button.danger-button{background:#642e3c;border-color:#a85360}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.timeline{display:flex;gap:6px;overflow-x:auto;padding:5px 0 12px;min-height:58px}.event{min-width:125px;padding:9px;border-radius:6px;background:#253657;border-top:3px solid #607da9}.event.action{border-top-color:#42b8ce}.event.alert{border-top-color:#ff817e}.event small{color:#aebbd4}.coverage{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.layer{padding:10px;border-radius:6px;background:#1a2947;border-left:4px solid #8797b4}.layer.collected{border-color:#70e1a1}.layer.not_observed,.layer.partial{border-color:#ffd166}.layer.failed,.layer.unavailable{border-color:#ff817e}@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.coverage{grid-template-columns:repeat(2,1fr)}}
</style></head><body><header><div class="eyebrow">Robot boundary security</div><h1>Outside communication console</h1><div class="intro">Use this screen to answer: what contacted the robot, what did the robot contact, when did it happen, and can the traffic be tied to an intentional action?</div></header><main>
<section class="grid" id="metrics"></section>
<section class="panel"><div class="panel-head"><div><div class="eyebrow">Control plane</div><h2>Run a controlled observation</h2></div><div id="state" class="muted">Connecting…</div></div><div class="help">Start monitoring before sending actions. The console downloads the completed Pi evidence automatically when you stop the run.</div><div class="row"><input id="scenario" value="ui_security_run" aria-label="Scenario name"><button class="primary" onclick="startRun()">Start monitoring</button><select id="category" aria-label="Action category"><option>lifecycle</option><option>motion</option><option>perception</option><option>diagnostics</option><option>background</option></select><input id="action" value="stand" aria-label="Action name"><button onclick="executeAction()">Send action</button><button class="danger-button" onclick="stopRun()">Stop &amp; analyze</button></div><div id="control" class="muted"></div></section>
<section class="panel"><div class="eyebrow">Investigation summary</div><h2>What needs attention?</h2><div id="findings" class="callout">Select a completed run to see findings.</div></section>
<section class="panel"><div class="panel-head"><div><div class="eyebrow">Network boundary</div><h2>External communication</h2></div><div class="help">Unattributed or inbound flows deserve investigation. “Allowed” only describes the observed verdict; it does not mean expected.</div></div><table><thead><tr><th>Direction</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Action link</th><th>Bytes out</th><th>Verdict</th></tr></thead><tbody id="flows"></tbody></table></section>
<section class="panel"><div class="panel-head"><div><div class="eyebrow">Correlation</div><h2>Action timeline</h2></div><div class="help">Look for traffic outside action windows or without an action marker.</div></div><div id="timeline" class="timeline"></div></section>
<section class="panel"><div class="panel-head"><div><div class="eyebrow">Trust in the evidence</div><h2>Collection coverage</h2></div><div class="help">A degraded layer is a limitation, not an empty result.</div></div><div id="coverage" class="coverage"></div></section>
<section class="panel"><div class="panel-head"><div><div class="eyebrow">History</div><h2>Completed runs</h2></div><div class="help">Select a run to investigate it. External flows and unattributed traffic are counted below.</div></div><table><thead><tr><th>Run</th><th>Scenario</th><th>External flows</th><th>Unattributed</th><th>Bytes out</th></tr></thead><tbody id="runs"></tbody></table></section>
</main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function get(u){let r=await fetch(u);return r.json()} async function post(u,b){let r=await fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b||{})});let x=await r.json();if(!r.ok)throw Error(x.error);return x}
let current=null;
function statusClass(s){return ['collected'].includes(s)?'good':['not_observed','partial'].includes(s)?'warn':'danger'}
function render(x){current=x;let ext=x.external_flows||[],un=x.unattributed_flows||[];document.querySelector('#metrics').innerHTML=[['External flows',ext.length,''],['Unattributed',un.length,un.length?'danger':''],['New DNS names',(x.dns||[]).length,''],['Bytes out',Number(x.bytes_out||0).toLocaleString(),'']].map(m=>`<div class="card"><div class="muted">${m[0]}</div><div class="metric ${m[2]}">${m[1]}</div></div>`).join('');document.querySelector('#findings').innerHTML=(un.length?`<span class="danger">${un.length} unattributed flow(s) require investigation.</span>`:'<span class="good">No unattributed flows in this run.</span>')+` <span class="muted">DNS records: ${(x.dns||[]).length}; TLS handshakes: ${(x.tls||[]).length}</span>`;document.querySelector('#flows').innerHTML=ext.map(f=>`<tr><td>${f.packets_in?'in/out':'out'}</td><td><code>${esc(f.remote_ip)}</code></td><td>${f.remote_port}</td><td>${esc(f.transport_protocol)}</td><td>${esc((f.scenario_ids||[]).join(', '))}</td><td>${Number(f.bytes_out||0).toLocaleString()}</td><td class="${f.blocked?'danger':'good'}">${f.blocked?'blocked':'allowed'}</td></tr>`).join('')||'<tr><td colspan="7" class="muted">No external flows.</td></tr>';document.querySelector('#timeline').innerHTML=(x.events||[]).map(e=>`<div class="event ${(e.type||'').includes('API')?'action':''} ${(e.type||'').includes('FAIL')?'alert':''}">${esc(e.type)}<br><small>${esc(e.scenario_id)}</small></div>`).join('')||'<span class="muted">No events.</span>';document.querySelector('#coverage').innerHTML=Object.entries(x.layers||{}).map(([k,v])=>`<div class="layer ${statusClass(v.status)}"><strong>${esc(k)}</strong><br>${esc(v.status)}<br><small>${esc(v.count??'')}</small></div>`).join('');}
async function refresh(){let rs=await get('/api/runs');document.querySelector('#runs').innerHTML=rs.map(x=>`<tr class="clickable" onclick="load('${encodeURIComponent(x.id)}')"><td><code>${esc(x.id)}</code></td><td>${esc(x.metadata?.scenario)}</td><td>${(x.external_flows||[]).length}</td><td>${(x.unattributed_flows||[]).length}</td><td>${Number(x.bytes_out||0).toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="5" class="muted">No completed runs yet.</td></tr>';if(!current&&rs[0])render(rs[0]);}
async function refreshState(){try{let s=await get('/api/state');document.querySelector('#state').textContent=(s.robot?.ok?'Robot connected':'Robot unavailable')+' · '+(s.monitoring?'Monitoring active':'Monitoring idle');}catch(e){document.querySelector('#state').textContent='Controller unavailable';}}
async function load(id){render(await get('/api/runs/'+id))} async function startRun(){try{let x=await post('/api/monitor/start',{scenario:document.querySelector('#scenario').value});document.querySelector('#control').textContent='Monitoring '+x.run_id;refreshState();}catch(e){alert(e)}} async function executeAction(){try{let x=await post('/api/action',{action:document.querySelector('#action').value,category:document.querySelector('#category').value});document.querySelector('#control').textContent=x.ok?'Action completed.':'Action failed: '+x.detail;refreshState();}catch(e){alert(e)}} async function stopRun(){try{let x=await post('/api/monitor/stop');document.querySelector('#control').textContent='Evidence downloaded for '+x.run_id;current=null;await refresh();refreshState();}catch(e){alert(e)}} refresh();refreshState();setInterval(refresh,3000);setInterval(refreshState,1500);
</script></body></html>"""


def make_handler(console: SecurityConsole):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, value: Any, status: int = 200) -> None:
            data = json.dumps(value).encode("utf-8") if not isinstance(value, bytes) else value
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if not isinstance(value, bytes) else "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            try:
                if path == "/":
                    self._send(HTML.encode("utf-8"))
                    return
                if path == "/api/runs":
                    self._send(console.runs())
                    return
                if path == "/api/state":
                    self._send(console.state())
                    return
                if path.startswith("/api/runs/"):
                    run_id = unquote(path.split("/", 3)[3])
                    run = console.runs_root / run_id
                    if not run.is_dir():
                        self._send({"error": "run not found"}, 404)
                        return
                    self._send(_run_summary(run))
                    return
                self._send({"error": "not found"}, 404)
            except Exception as error:
                self._send({"error": str(error)}, 500)

        def do_POST(self) -> None:
            try:
                body = self._body()
                path = urlparse(self.path).path
                if path == "/api/monitor/start":
                    self._send(console.start_monitor(body))
                    return
                if path == "/api/action":
                    self._send(console.action(body))
                    return
                if path == "/api/monitor/stop":
                    self._send(console.stop_monitor())
                    return
                self._send({"error": "not found"}, 404)
            except Exception as error:
                self._send({"error": str(error)}, 500)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def serve(runs_root: Path, host: str = "127.0.0.1", port: int = 8080,
          robot_target: Optional[str] = None) -> None:
    console = SecurityConsole(runs_root, robot_target)
    server = ThreadingHTTPServer((host, port), make_handler(console))
    print("boundary-audit security console: http://%s:%d" % (host, port), flush=True)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="boundary-audit security console")
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument("--robot", help="Pi gRPC target, e.g. 192.168.1.168:50051")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    serve(args.runs_root, args.bind, args.port, args.robot)


if __name__ == "__main__":
    main()
