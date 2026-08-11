"""Linux namespace lifecycle primitives.

Commands are argument arrays and resource names are validated. The backend is
not auto-run by the DUT simulator; use it on a Linux host with
root/CAP_NET_ADMIN after reviewing the topology.
"""

import re
import subprocess

from .base import LabBackend

_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")


class VirtualNamespaceLab(LabBackend):
    def __init__(self, dut_namespace: str = "ba-dut", internet_namespace: str = "ba-net") -> None:
        for name in (dut_namespace, internet_namespace):
            if not _NAME.match(name):
                raise ValueError("invalid namespace name")
        self.dut_namespace = dut_namespace
        self.internet_namespace = internet_namespace

    def _run(self, *args: str) -> None:
        subprocess.run(list(args), check=True)

    def up(self) -> None:
        self._run("ip", "netns", "add", self.dut_namespace)
        try:
            self._run("ip", "netns", "add", self.internet_namespace)
        except Exception:
            self.down()
            raise

    def status(self) -> str:
        result = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True)
        return result.stdout

    def down(self) -> None:
        for name in (self.dut_namespace, self.internet_namespace):
            subprocess.run(["ip", "netns", "del", name], check=False)
