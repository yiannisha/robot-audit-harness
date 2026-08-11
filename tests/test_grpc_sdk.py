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
