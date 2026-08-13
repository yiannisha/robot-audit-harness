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
            return result

    def stop_monitor(self) -> Dict[str, Any]:
        if not self.robot:
            raise RuntimeError("UI was started without --robot HOST:PORT")
        with self.lock:
            result = self.robot.stop_monitor()
            self.monitoring = False
            return result


HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>boundary-audit security console</title>
<style>
:root{color-scheme:dark;font:14px system-ui;background:#0b1020;color:#e9edf7}body{margin:0}header{padding:18px 28px;background:#121a31;border-bottom:1px solid #2c385b}h1,h2{margin:0 0 10px}main{padding:20px 28px;max-width:1500px;margin:auto}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel{background:#121a31;border:1px solid #2c385b;border-radius:8px;padding:14px}.metric{font-size:25px;font-weight:700}.muted{color:#9aa8c7}.danger{color:#ff817e}.warn{color:#ffd166}.good{color:#70e1a1}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #283451;font-size:13px}button,select,input{background:#1b2747;color:#e9edf7;border:1px solid #40527d;border-radius:5px;padding:8px}button{cursor:pointer}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.panel{margin-top:14px}.pill{display:inline-block;padding:3px 7px;border-radius:10px;background:#263557;margin:2px}.timeline{display:flex;gap:4px;align-items:center;min-height:42px}.event{padding:7px 9px;border-radius:5px;background:#263557}.event.action{background:#27576a}.event.alert{background:#703b46}.coverage{display:grid;grid-template-columns:repeat(5,1fr);gap:5px}.layer{padding:8px;border-radius:5px;background:#263557}.layer.collected{border-left:4px solid #70e1a1}.layer.not_observed,.layer.partial{border-left:4px solid #ffd166}.layer.failed,.layer.unavailable{border-left:4px solid #ff817e}
</style></head><body><header><h1>boundary-audit security console</h1><div class="muted">Outside communication, interference, and evidence coverage</div></header><main>
<section class="grid" id="metrics"></section>
<section class="panel"><h2>Robot control</h2><div class="row"><input id="scenario" value="ui_security_run"><button onclick="startRun()">Start monitoring</button><select id="category"><option>lifecycle</option><option>motion</option><option>perception</option><option>diagnostics</option><option>background</option></select><input id="action" value="stand"><button onclick="executeAction()">Execute action</button><button onclick="stopRun()">Stop and analyze</button><span id="control" class="muted"></span></div></section>
<section class="panel"><h2>Security findings</h2><div id="findings" class="muted">No completed run loaded.</div></section>
<section class="panel"><h2>External communication</h2><table><thead><tr><th>Direction</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Action</th><th>Bytes out</th><th>Verdict</th></tr></thead><tbody id="flows"></tbody></table></section>
<section class="panel"><h2>Action / communication timeline</h2><div id="timeline" class="timeline"></div></section>
<section class="panel"><h2>Evidence coverage</h2><div id="coverage" class="coverage"></div></section>
<section class="panel"><h2>Recent runs</h2><table><thead><tr><th>Run</th><th>Scenario</th><th>External flows</th><th>Unattributed</th><th>Bytes out</th></tr></thead><tbody id="runs"></tbody></table></section>
</main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function get(u){let r=await fetch(u);return r.json()} async function post(u,b){let r=await fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b||{})});let x=await r.json();if(!r.ok)throw Error(x.error);return x}
let current=null;
function statusClass(s){return ['collected'].includes(s)?'good':['not_observed','partial'].includes(s)?'warn':'danger'}
function render(x){current=x;let ext=x.external_flows||[],un=x.unattributed_flows||[];document.querySelector('#metrics').innerHTML=[['External flows',ext.length,''],['Unattributed',un.length,un.length?'danger':''],['New DNS names',(x.dns||[]).length,''],['Bytes out',Number(x.bytes_out||0).toLocaleString(),'']].map(m=>`<div class="card"><div class="muted">${m[0]}</div><div class="metric ${m[2]}">${m[1]}</div></div>`).join('');document.querySelector('#findings').innerHTML=(un.length?`<span class="danger">${un.length} unattributed flow(s) require investigation.</span>`:'<span class="good">No unattributed flows in this run.</span>')+` <span class="muted">DNS records: ${(x.dns||[]).length}; TLS handshakes: ${(x.tls||[]).length}</span>`;document.querySelector('#flows').innerHTML=ext.map(f=>`<tr><td>${f.packets_in?'in/out':'out'}</td><td><code>${esc(f.remote_ip)}</code></td><td>${f.remote_port}</td><td>${esc(f.transport_protocol)}</td><td>${esc((f.scenario_ids||[]).join(', '))}</td><td>${Number(f.bytes_out||0).toLocaleString()}</td><td class="${f.blocked?'danger':'good'}">${f.blocked?'blocked':'allowed'}</td></tr>`).join('')||'<tr><td colspan="7" class="muted">No external flows.</td></tr>';document.querySelector('#timeline').innerHTML=(x.events||[]).map(e=>`<div class="event ${(e.type||'').includes('API')?'action':''} ${(e.type||'').includes('FAIL')?'alert':''}">${esc(e.type)}<br><small>${esc(e.scenario_id)}</small></div>`).join('')||'<span class="muted">No events.</span>';document.querySelector('#coverage').innerHTML=Object.entries(x.layers||{}).map(([k,v])=>`<div class="layer ${statusClass(v.status)}"><strong>${esc(k)}</strong><br>${esc(v.status)}<br><small>${esc(v.count??'')}</small></div>`).join('');}
async function refresh(){let rs=await get('/api/runs');document.querySelector('#runs').innerHTML=rs.map(x=>`<tr onclick="load('${encodeURIComponent(x.id)}')"><td><code>${esc(x.id)}</code></td><td>${esc(x.metadata?.scenario)}</td><td>${(x.external_flows||[]).length}</td><td>${(x.unattributed_flows||[]).length}</td><td>${Number(x.bytes_out||0).toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="5" class="muted">No runs found.</td></tr>';if(!current&&rs[0])render(rs[0]);}
async function load(id){render(await get('/api/runs/'+id))} async function startRun(){try{let x=await post('/api/monitor/start',{scenario:document.querySelector('#scenario').value});document.querySelector('#control').textContent='Monitoring '+x.run_id;}catch(e){alert(e)}} async function executeAction(){try{let x=await post('/api/action',{action:document.querySelector('#action').value,category:document.querySelector('#category').value});document.querySelector('#control').textContent=JSON.stringify(x);}catch(e){alert(e)}} async function stopRun(){try{let x=await post('/api/monitor/stop');document.querySelector('#control').textContent='Completed '+x.run_id;current=null;await refresh();}catch(e){alert(e)}} refresh();setInterval(refresh,3000);
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
