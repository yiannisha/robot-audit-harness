import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from boundary_audit.ui_server import SecurityConsole, make_handler


def test_security_console_serves_run_data(tmp_path):
    run = tmp_path / "run-1"
    run.mkdir()
    (run / "metadata.json").write_text(json.dumps({"scenario": "security"}))
    (run / "layers.json").write_text(json.dumps({"raw_packets": {"status": "collected"}}))
    (run / "flows.json").write_text(json.dumps([{"scope": "external", "remote_ip": "203.0.113.8",
                                                   "remote_port": 443, "transport_protocol": "TCP",
                                                   "bytes_out": 12, "scenario_ids": ["unattributed"]}]))
    for name in ("events.jsonl", "api-results.jsonl", "dns.jsonl", "tls.jsonl"):
        (run / name).write_text("")

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(SecurityConsole(tmp_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port)
        connection.request("GET", "/api/runs")
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())[0]["unattributed_flows"]
    finally:
        server.shutdown()
        thread.join(timeout=2)
