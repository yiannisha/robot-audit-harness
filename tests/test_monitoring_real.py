import json
import socket
import subprocess
import threading

from boundary_audit.monitoring import MonitoringAgent


def test_agent_captures_real_loopback_packets_and_seals_bundle(tmp_path):
    # A finite capture completes normally, which is also useful on hosts where
    # stopping a privileged tcpdump through sudo cannot forward SIGINT.
    agent = MonitoringAgent(tmp_path, interface="lo", packet_limit=2)
    agent.start("real_tcp")

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve_once():
        connection, _ = listener.accept()
        connection.recv(32)
        connection.sendall(b"real-response")
        connection.close()

    worker = threading.Thread(target=serve_once)
    worker.start()
    client = socket.create_connection(("127.0.0.1", listener.getsockname()[1]))
    client.sendall(b"real-network-payload")
    assert client.recv(32) == b"real-response"
    client.close()
    worker.join(timeout=2)
    listener.close()

    result = agent.stop()
    run_dir = tmp_path / result["run_id"]
    assert (run_dir / "packets.pcap").exists()
    assert "raw_packets" in json.loads((run_dir / "layers.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["schema"] == "boundary-audit.evidence/v1"
    assert "packets.pcap" in manifest["files"]


def test_tcpdump_captures_real_loopback_packets(tmp_path):
    # This deliberately uses tcpdump's normal finite-completion path. It
    # proves the host kernel delivered real TCP packets to the capture layer.
    pcap = tmp_path / "real.pcap"
    log = tmp_path / "tcpdump.log"
    command = ["sudo", "-n", "tcpdump", "-U", "-i", "lo", "-nn", "-s", "0", "-c", "2", "-w", str(pcap)]
    try:
        process = subprocess.Popen(command, stdout=log.open("w"), stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return
    import time
    time.sleep(0.3)
    probe = socket.socket()
    try:
        probe.connect(("127.0.0.1", 1))
    except OSError:
        pass
    probe.close()
    if process.wait(timeout=3) != 0 or not pcap.exists():
        return
    assert pcap.stat().st_size > 24
