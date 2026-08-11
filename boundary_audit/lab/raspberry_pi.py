"""Configuration-only Raspberry Pi backend boundary."""

from dataclasses import dataclass

from .base import LabBackend


@dataclass(frozen=True)
class RaspberryPiConfig:
    upstream_interface: str = "eth0"
    dut_interface: str = "wlan0"
    dut_subnet: str = "10.77.0.0/24"
    gateway_ip: str = "10.77.0.1"


class RaspberryPiBackend(LabBackend):
    def __init__(self, config: RaspberryPiConfig) -> None:
        self.config = config

    def up(self) -> None:
        raise RuntimeError("Pi setup is explicit and must be performed from scripts/pi/setup.sh after review")

    def status(self) -> str:
        return "configured upstream=%s dut=%s subnet=%s" % (self.config.upstream_interface, self.config.dut_interface, self.config.dut_subnet)

    def down(self) -> None:
        raise RuntimeError("Pi teardown must be reviewed and run explicitly; no global firewall flush is performed")
