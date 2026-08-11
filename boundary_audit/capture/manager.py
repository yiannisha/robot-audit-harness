"""Safe tcpdump process lifecycle."""

import subprocess
from pathlib import Path
from typing import Optional


class CaptureManager:
    def __init__(self, interface: str, output: Path) -> None:
        if not interface or any(char in interface for char in " ;|&$\n"):
            raise ValueError("invalid capture interface")
        self.interface = interface
        self.output = output
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(["tcpdump", "-i", self.interface, "-nn", "-s", "0", "-w", str(self.output)])

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None
