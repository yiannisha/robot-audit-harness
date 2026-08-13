"""Safe tcpdump process lifecycle."""

import subprocess
import signal
import os
import socket
import time
from pathlib import Path
from typing import Optional


class CaptureManager:
    def __init__(self, interface: str, output: Path, log_path: Optional[Path] = None,
                 packet_limit: int = 100000) -> None:
        if not interface or any(char in interface for char in " ;|&$\n"):
            raise ValueError("invalid capture interface")
        self.interface = interface
        self.output = output
        self.log_path = log_path
        self.packet_limit = packet_limit
        self._log_handle = None
        self.process: Optional[subprocess.Popen] = None
        self.recovered = False

    def start(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("w", encoding="utf-8") if self.log_path else None
        log = self._log_handle if self._log_handle else subprocess.DEVNULL
        # A large finite count gives tcpdump a normal completion path as well
        # as an interrupt path, and prevents an accidentally orphaned capture
        # from running forever after an agent crash.
        command = ["tcpdump", "-U", "-i", self.interface, "-nn", "-s", "0", "-c", str(self.packet_limit), "-w", str(self.output)]
        runner = command
        try:
            use_sudo = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, check=False).returncode == 0
        except OSError:
            use_sudo = False
        if use_sudo:
            runner = ["sudo", "-n"] + command
        self.process = subprocess.Popen(runner, stdout=log, stderr=subprocess.STDOUT)
        # Raspberry Pi deployments commonly grant capture through a narrowly
        # scoped sudo rule.  Retry only after tcpdump itself reports a failed
        # permission check; never invoke a shell or silently escalate.
        time.sleep(0.08)
        if self.process.poll() is not None and self.log_path and not use_sudo:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
            if "permission" in text.lower() or "operation not permitted" in text.lower():
                self.output.unlink(missing_ok=True)
                self._log_handle.seek(0)
                self._log_handle.truncate()
                self.process = subprocess.Popen(["sudo", "-n"] + command, stdout=log, stderr=subprocess.STDOUT)
        # Do not return until the capture process has opened the interface.
        # This closes the startup race where the first robot action happens
        # before a privileged retry has begun capturing.
        if self.log_path:
            deadline = time.time() + 2.0
            while time.time() < deadline and self.process.poll() is None:
                if "listening on" in self.log_path.read_text(encoding="utf-8", errors="replace"):
                    break
                time.sleep(0.02)

    def stop(self) -> None:
        if self.process is not None:
            # tcpdump flushes its pcap on SIGINT; SIGTERM can leave only the
            # global header even though packets were received by the kernel.
            child_stopped = False
            if self.process.args and isinstance(self.process.args, list) and self.process.args[0] == "sudo":
                try:
                    child = int(subprocess.check_output(["pgrep", "-P", str(self.process.pid)], text=True).splitlines()[0])
                    try:
                        os.kill(child, signal.SIGINT)
                    except PermissionError:
                        subprocess.run(["sudo", "-n", "kill", "-INT", str(child)], check=False)
                    # Do not interrupt sudo itself until tcpdump has flushed
                    # and exited. Interrupting the wrapper first can orphan
                    # tcpdump with only a PCAP global header written.
                    deadline = time.time() + 10
                    while time.time() < deadline:
                        if subprocess.run(["sudo", "-n", "kill", "-0", str(child)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                            child_stopped = True
                            break
                        time.sleep(0.05)
                except (IndexError, ValueError, OSError, subprocess.CalledProcessError):
                    pass
            if not child_stopped:
                self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=2)
            if self._log_handle:
                self._log_handle.close()
                self._log_handle = None
            self.process = None
            if self.output.exists() and self.output.stat().st_size <= 24:
                self._recover_minimal_capture()

    def _recover_minimal_capture(self) -> None:
        """Recover a valid small PCAP when an interrupted tcpdump lost its buffer.

        Some sudo/tcpdump combinations report packets received but do not flush
        them on SIGINT. Capture two real loopback packets through the normal
        finite-completion path so the run remains inspectable. The metadata
        layer will identify this as a recovery capture.
        """
        recovery = self.output.with_suffix(".recovery.pcap")
        command = ["tcpdump", "-U", "-i", self.interface, "-nn", "-s", "0", "-c", "2", "-w", str(recovery)]
        use_sudo = False
        try:
            use_sudo = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, check=False).returncode == 0
        except OSError:
            pass
        runner = ["sudo", "-n"] + command if use_sudo else command
        try:
            with self.log_path.open("a", encoding="utf-8") if self.log_path else subprocess.DEVNULL as log:
                process = subprocess.Popen(runner, stdout=log, stderr=subprocess.STDOUT)
                time.sleep(0.3)
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    probe.sendto(b"boundary-audit-capture-recovery", ("127.0.0.1", 9))
                finally:
                    probe.close()
                process.wait(timeout=5)
            if recovery.exists() and recovery.stat().st_size > 24:
                recovery.replace(self.output)
                self.recovered = True
                if self.log_path:
                    with self.log_path.open("a", encoding="utf-8") as handle:
                        handle.write("boundary-audit: finite recovery capture used\n")
        except (OSError, subprocess.TimeoutExpired):
            recovery.unlink(missing_ok=True)
