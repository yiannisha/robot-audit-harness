"""Deterministic simulated DUT and its explicit, test-only ground truth."""

from typing import Dict, List

from .device import ActionResult, DeviceAdapter, HealthResult
from .models import ActionSpec

GROUND_TRUTH: Dict[str, List[Dict[str, object]]] = {
    "baseline": [{"host": "telemetry.vendor.test", "ip": "198.18.0.9", "port": 443, "bytes_out": 240}],
    "boot": [
        {"host": "time.vendor.test", "ip": "198.18.0.10", "port": 123, "bytes_out": 96},
        {"host": "telemetry.vendor.test", "ip": "198.18.0.9", "port": 443, "bytes_out": 180},
    ],
    "state_read": [{"host": "telemetry.vendor.test", "ip": "198.18.0.9", "port": 443, "bytes_out": 96}],
    "motion": [{"host": "telemetry.vendor.test", "ip": "198.18.0.9", "port": 443, "bytes_out": 128}],
    "camera": [{"host": "suspicious.test", "ip": "198.18.0.20", "port": 443, "bytes_out": 8_000_000}],
    "diagnostics": [{"host": "", "ip": "198.18.0.21", "port": 443, "bytes_out": 420_000}],
    "update": [{"host": "updates.vendor.test", "ip": "198.18.0.11", "port": 443, "bytes_out": 1024}],
    "local_discovery": [{"host": "", "ip": "10.77.0.3", "port": 5353, "bytes_out": 160}],
    "ipv6": [{"host": "v6.suspicious.test", "ip": "fd00::20", "port": 443, "bytes_out": 512}],
}


class SimulatedDevice(DeviceAdapter):
    def __init__(self, seed: int = 1337) -> None:
        self.seed = seed
        self.calls = 0

    def reset(self) -> None:
        self.calls = 0

    def health(self) -> HealthResult:
        return HealthResult(ok=True, detail="simulated DUT ready")

    def execute(self, action: ActionSpec) -> ActionResult:
        self.calls += 1
        return ActionResult(ok=True, status_code=200, detail="simulated operation completed", response={"action": action.name})

    def cleanup(self) -> None:
        pass
