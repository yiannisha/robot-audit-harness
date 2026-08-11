import json
from boundary_audit.analysis import classify_scope, generate_policy
from boundary_audit.dashboard import render_dashboard
from boundary_audit.models import NetworkMode
from boundary_audit.reports import write_reports
from boundary_audit.runner import run_experiment
from boundary_audit.dut_simulator import DutSimulator


def test_scope_and_policy(tmp_path):
    run = run_experiment("camera_stream", NetworkMode.OBSERVE, tmp_path, DutSimulator(network_enabled=False), repeats=3)
    flows = [type("Flow", (), value)() for value in json.loads((run / "flows.json").read_text())]
    assert classify_scope("198.18.0.20") == "external"
    assert any(flow.bytes_out == 8_000_000 for flow in flows)
    assert "policy drop" in generate_policy(flows)


def test_reports_are_standalone(tmp_path):
    run = run_experiment("read_firmware_version", NetworkMode.OBSERVE, tmp_path, DutSimulator(network_enabled=False), repeats=3)
    write_reports(run)
    report = (run / "report.html").read_text()
    assert "read_firmware_version" in report
    assert "encrypted" in report.lower()


def test_enforce_records_blocked(tmp_path):
    run = run_experiment("camera_stream", NetworkMode.ENFORCE, tmp_path, DutSimulator(network_enabled=False), repeats=3)
    flows = json.loads((run / "flows.json").read_text())
    assert all(flow["blocked"] for flow in flows if flow["remote_ip"] == "198.18.0.20")


def test_dashboard_contains_visualizations(tmp_path):
    run = run_experiment("camera_stream", NetworkMode.OBSERVE, tmp_path, DutSimulator(network_enabled=False), repeats=1)
    write_reports(run)
    dashboard = render_dashboard(tmp_path)
    assert dashboard.count("<svg") == 2
    assert "camera" in dashboard
    assert "report.html" in dashboard
