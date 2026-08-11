"""Small local web application for live run monitoring and deployment."""

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

from .dashboard import _run_summary

_SAFE_REMOTE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_./~:@+-]+$")


class WebState:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.runs = root / "runs"
        self.jobs = root / ".web-jobs"
        self.jobs.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.processes: Dict[str, subprocess.Popen] = {}
        self.job_meta: Dict[str, Dict[str, Any]] = {}

    def run_summaries(self) -> list:
        if not self.runs.exists():
            return []
        return [_run_summary(path) for path in sorted(self.runs.iterdir(), reverse=True)
                if path.is_dir() and (path / "metadata.json").exists()]

    def start(self, config: Dict[str, Any]) -> str:
        backend = str(config.get("backend", "virtual"))
        job_id = uuid.uuid4().hex[:8]
        log_path = self.jobs / (job_id + ".log")
        env = os.environ.copy()
        if backend == "remote":
            raise ValueError("remote DUT workflow was removed; run the DUT on the capture host directly")
        else:
            scenario = str(config.get("scenario", "full_matrix"))
            mode = str(config.get("mode", "observe"))
            if not re.match(r"^[a-z_]+$", scenario) or mode not in ("observe", "airgap", "enforce"):
                raise ValueError("invalid virtual run configuration")
            command = [sys.executable, "-m", "boundary_audit.cli", "run", scenario, "--mode", mode]
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT)
        with self.lock:
            self.processes[job_id] = process
            self.job_meta[job_id] = {"id": job_id, "backend": backend, "status": "running",
                                     "log": str(log_path.relative_to(self.root))}
        return job_id

    def job_list(self) -> list:
        result = []
        with self.lock:
            for job_id, process in list(self.processes.items()):
                status = "running" if process.poll() is None else (
                    "completed" if process.returncode == 0 else "failed")
                self.job_meta[job_id]["status"] = status
                self.job_meta[job_id]["returncode"] = process.returncode
                log_path = self.root / self.job_meta[job_id]["log"]
                self.job_meta[job_id]["log_tail"] = log_path.read_text(encoding="utf-8", errors="replace")[-2000:] if log_path.exists() else ""
                result.append(dict(self.job_meta[job_id]))
        return result


def page() -> str:
    return """<!doctype html><html><head><meta charset='utf-8'>
<title>boundary-audit live</title><style>
:root{--bg:#f4f7fa;--ink:#17202a;--muted:#667685;--line:#d9e2ea;--blue:#087ea4;--red:#b42318}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font:14px system-ui;color:var(--ink)}
main{max-width:1400px;margin:auto;padding:28px}h1{margin:0}.sub{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.card,.panel{background:white;border:1px solid var(--line);border-radius:12px;padding:16px}
.metric{font-size:27px;font-weight:700}.muted{color:var(--muted)}h2{font-size:19px;margin:26px 0 10px}
button{background:var(--blue);border:0;color:white;padding:9px 14px;border-radius:7px;cursor:pointer}
input,select{padding:8px;border:1px solid #bac8d3;border-radius:6px;margin:4px;width:220px}
table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--muted)}.bar{fill:var(--blue)}.layer{display:inline-block;border-radius:8px;padding:8px 11px;margin:4px;background:#e9f4f8}
.layer.missing{background:#fff1f0;color:var(--red)}.job{padding:7px 0;border-bottom:1px solid var(--line)}
a{color:#075985;text-decoration:none}code{background:#eef2f5;padding:2px 4px;border-radius:4px}
@media(max-width:800px){main{padding:15px}.grid{grid-template-columns:repeat(2,1fr)}input,select{width:95%}}
</style></head><body><main><h1>boundary-audit live</h1>
<p class='sub'>Live run control and evidence explorer. Refreshes every two seconds.</p>
<section class='panel'><h2>Deploy a run</h2><form id='deploy'>
<input type='hidden' id='backend' value='virtual'>
<input id='scenario' placeholder='virtual scenario' value='full_matrix'>
<select id='mode'><option>observe</option><option>airgap</option><option>enforce</option></select>
<button>Start run</button></form><div id='jobs' class='muted'></div></section>
<section id='metrics' class='grid'></section><h2>Latest run</h2><section class='panel'><div id='latest'></div></section>
<h2>Adversarial findings</h2><section class='panel'><table><thead><tr><th>Action</th><th>Endpoint role</th><th>Physical destination</th><th>Bytes out</th><th>Reason</th></tr></thead><tbody id='findings'></tbody></table></section>
<h2>Layer breakdown</h2><section class='panel'><div id='layers'></div></section>
<h2>Traffic visualizations</h2><section class='panel'><div id='charts'></div></section>
<h2>All runs</h2><section class='panel'><table><thead><tr><th>Run</th><th>Backend</th>
<th>Scenario</th><th>Flows</th><th>Bytes out</th><th>Evidence</th></tr></thead>
<tbody id='runs'></tbody></table></section></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function get(path){return (await fetch(path)).json()}
function metric(label,value){return "<div class='card'><div class='muted'>"+esc(label)+"</div><div class='metric'>"+esc(value)+"</div></div>"}
function drawBars(flows){let by={};for(const f of flows)for(const s of (f.scenario_ids||['unattributed']))by[s]=(by[s]||0)+(f.bytes_out||0);let a=Object.entries(by).sort((x,y)=>y[1]-x[1]),m=Math.max(1,...a.map(x=>x[1]));return "<svg viewBox='0 0 900 "+(70+a.length*38)+"' width='100%'>"+a.map((x,i)=>{let y=30+i*38,w=Math.max(3,600*x[1]/m);return "<text x='0' y='"+(y+16)+"'>"+esc(x[0])+"</text><rect x='180' y='"+y+"' width='"+w+"' height='20' rx='4' class='bar'/><text x='"+(190+w)+"' y='"+(y+16)+"'>"+x[1].toLocaleString()+" B</text>"}).join("")+"</svg>"}
function drawDestinations(flows){let by={};for(const f of flows){let k=f.endpoint_role||f.remote_ip;by[k]=(by[k]||0)+(f.bytes_out||0)}return Object.entries(by).sort((a,b)=>b[1]-a[1]).map(x=>"<tr><td><code>"+esc(x[0])+"</code></td><td>"+x[1].toLocaleString()+" B</td></tr>").join("")}
async function refresh(){let data=await get("/api/runs"),jobs=await get("/api/jobs"),latest=data[0]||{flows:[],bytes_out:0};document.querySelector("#metrics").innerHTML=metric("Retained runs",data.length)+metric("Total bytes out",data.reduce((a,x)=>a+x.bytes_out,0).toLocaleString())+metric("Destinations",new Set(data.flatMap(x=>x.flows.map(f=>f.remote_ip))).size)+metric("Active jobs",jobs.filter(x=>x.status==="running").length);document.querySelector("#jobs").innerHTML=jobs.map(x=>"<div class='job'>"+esc(x.id)+" — "+esc(x.backend)+" — <strong>"+esc(x.status)+"</strong> <code>"+esc(x.log)+"</code></div>").join("");document.querySelector("#latest").innerHTML="<strong>"+esc(latest.id||"No runs")+"</strong> · "+esc(latest.metadata?.backend||"")+" · "+esc(latest.metadata?.scenario||"")+" · <a href='/runs/"+encodeURIComponent(latest.id||"")+"/report.html'>open report</a> · <a href='/runs/"+encodeURIComponent(latest.id||"")+"/packets.pcap'>PCAP</a>";document.querySelector("#findings").innerHTML=(latest.findings||[]).map(f=>"<tr><td>"+esc(f.scenario)+"</td><td><strong>"+esc(f.role)+"</strong></td><td><code>"+esc(f.physical_ip)+"</code></td><td>"+Number(f.bytes_out).toLocaleString()+"</td><td>"+esc(f.reason)+"</td></tr>").join("")||"<tr><td colspan='5' class='muted'>No adversarial finding flags in this run.</td></tr>";document.querySelector("#charts").innerHTML="<h3>Bytes out by action</h3>"+drawBars(latest.flows||[])+"<h3>Bytes out by destination role</h3><table><tr><th>Role</th><th>Bytes</th></tr>"+drawDestinations(latest.flows||[])+"</table>";let layers=latest.layers||{};document.querySelector("#layers").innerHTML=Object.entries(layers).map(([k,v])=>{let detail=Object.entries(v).filter(x=>x[0]!=="status").map(x=>x[0]+"="+x[1]).join(" · ");return "<span class='layer "+(v.status==="not_collected"?"missing":"")+"' title='"+esc(JSON.stringify(v))+"'><strong>"+esc(k)+"</strong>: "+esc(v.status)+(detail?" · "+esc(detail):"")+"</span>"}).join("")||"<span class='muted'>No layer data yet.</span>";document.querySelector("#runs").innerHTML=data.map(x=>"<tr><td><a href='/runs/"+encodeURIComponent(x.id)+"/report.html'>"+esc(x.id)+"</a></td><td>"+esc(x.metadata?.backend||"")+"</td><td>"+esc(x.metadata?.scenario||"")+"</td><td>"+x.flows.length+"</td><td>"+x.bytes_out.toLocaleString()+"</td><td><a href='/runs/"+encodeURIComponent(x.id)+"/packets.pcap'>PCAP</a></td></tr>").join("")}
document.querySelector("#deploy").addEventListener("submit",async e=>{e.preventDefault();let body={backend:"virtual",scenario:scenario.value,mode:mode.value};let r=await fetch("/api/deploy",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});if(!r.ok)alert(await r.text());refresh()});refresh();setInterval(refresh,2000);
</script></body></html>"""


def serve(root: Path, host: str, port: int) -> None:
    state = WebState(root)

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, value: Any, status: int = 200) -> None:
            body = json.dumps(value, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                body = page().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/api/runs":
                self.send_json(state.run_summaries())
            elif path.startswith("/api/runs/"):
                run_id = path[len("/api/runs/"):].strip("/")
                run = state.runs / run_id
                if not run.is_dir() or run.resolve().parent != state.runs.resolve():
                    self.send_json({"error": "run not found"}, 404)
                    return
                payload: Dict[str, Any] = {}
                for name in ("metadata", "analysis", "layers"):
                    file_path = run / (name + ".json")
                    if file_path.exists():
                        payload[name] = json.loads(file_path.read_text())
                for name in ("events", "dns", "tls", "firewall"):
                    file_path = run / (name + ".jsonl")
                    if file_path.exists():
                        payload[name] = [json.loads(line) for line in file_path.read_text().splitlines() if line.strip()]
                flow_path = run / "flows.json"
                payload["flows"] = json.loads(flow_path.read_text()) if flow_path.exists() else []
                self.send_json(payload)
            elif path == "/api/jobs":
                self.send_json(state.job_list())
            elif path.startswith("/runs/"):
                requested = path[len("/runs/"):].split("/", 1)
                run = state.runs / requested[0]
                if not run.is_dir():
                    self.send_error(404)
                    return
                relative = requested[1] if len(requested) > 1 else "report.html"
                target = (run / relative).resolve()
                if run.resolve() not in target.parents or not target.exists():
                    self.send_error(404)
                    return
                content_type = "text/html" if target.suffix == ".html" else "application/octet-stream"
                body = target.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/api/deploy":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                config = json.loads(self.rfile.read(length))
                job_id = state.start(config)
                self.send_json({"job_id": job_id}, 202)
            except (ValueError, json.JSONDecodeError) as error:
                self.send_json({"error": str(error)}, 400)

        def log_message(self, format_string: str, *args: object) -> None:
            print("web", format_string % args, flush=True)

    server = ThreadingHTTPServer((host, port), Handler)
    print("boundary-audit web app: http://%s:%d" % (host, port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
