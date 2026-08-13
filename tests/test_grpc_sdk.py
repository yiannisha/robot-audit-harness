from boundary_audit.dut_simulator import DutSimulator
from boundary_audit.grpc_sdk import DutGrpcClient, serve


def test_remote_grpc_sdk_controls_dut():
    server = serve(DutSimulator(network_enabled=False), "127.0.0.1", 0)
    try:
        client = DutGrpcClient("127.0.0.1:%d" % server.bound_port)
        assert client.health()["ok"] is True
        assert "stand" in client.capabilities()["actions"]
        result = client.execute("stand", category="motion")
        assert result["ok"] is True
        assert result["response"]["action"] == "stand"
    finally:
        server.stop(0)


def test_remote_grpc_monitor_lifecycle_and_artifact_access(tmp_path):
    server = serve(DutSimulator(network_enabled=False), "127.0.0.1", 0, monitor_root=tmp_path, monitor_interface="lo")
    try:
        client = DutGrpcClient("127.0.0.1:%d" % server.bound_port)
        started = client.start_monitor("grpc-run")
        assert started["status"] == "running"
        client.mark_event("API_CALL_BEGIN", "grpc-run", {"action": "stand"})
        client.execute("stand", category="motion")
        stopped = client.stop_monitor()
        assert stopped["status"] == "complete"
        assert b"grpc-run" in client.get_artifact("events.jsonl")
        assert b'"action": "stand"' in client.get_artifact("api-results.jsonl")
        assert b"boundary-audit.evidence/v1" in client.get_artifact("manifest.json")
    finally:
        server.stop(0)
