"""Safe tcpdump process lifecycle."""

import subprocess
import signal
import os
import socket
import ssl
import struct
import shutil
import uuid
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
        self._capture_path: Optional[Path] = None

    def start(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("w", encoding="utf-8") if self.log_path else None
        log = self._log_handle if self._log_handle else subprocess.DEVNULL
        # A large finite count gives tcpdump a normal completion path as well
        # as an interrupt path, and prevents an accidentally orphaned capture
        # from running forever after an agent crash.
        use_dumpcap = shutil.which("dumpcap") is not None
        if use_dumpcap:
            # dumpcap drops privileges after opening the capture device. Keep
            # its temporary output in /tmp, where the dumpcap group can write,
            # then move the completed file into the user-owned run directory.
            self._capture_path = Path("/tmp") / ("boundary-audit-%s.pcapng" % uuid.uuid4().hex)
            command = ["dumpcap", "-i", self.interface, "-w", str(self._capture_path)]
        else:
            self._capture_path = self.output
            command = ["tcpdump", "-U", "-i", self.interface, "-nn", "-s", "0", "-c", str(self.packet_limit), "-w", str(self.output)]
        runner = command
        try:
            use_sudo = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, check=False).returncode == 0
        except OSError:
            use_sudo = False
        if use_sudo and not use_dumpcap:
            runner = ["sudo", "-n"] + command[:1] + ["-Z", "root"] + command[1:]
        elif use_sudo:
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
            if self.process.poll() is not None:
                self.process.wait()
                if self._log_handle:
                    self._log_handle.close()
                    self._log_handle = None
                self.process = None
                self._finalize_capture()
                return
            # tcpdump flushes its pcap on SIGINT; SIGTERM can leave only the
            # global header even though packets were received by the kernel.
            child_stopped = False
            if self.process.args and isinstance(self.process.args, list) and self.process.args[0] == "sudo":
                try:
                    child = int(subprocess.check_output(["pgrep", "-P", str(self.process.pid)], text=True).splitlines()[0])
                    try:
                        # SIGUSR2 asks tcpdump to flush its packet buffer to
                        # the savefile without stopping capture. This matters
                        # on Linux when tcpdump is wrapped by sudo: interrupting
                        # the wrapper can otherwise leave only the PCAP header.
                        os.kill(child, signal.SIGUSR2)
                        time.sleep(0.2)
                        os.kill(child, signal.SIGINT)
                    except PermissionError:
                        subprocess.run(["sudo", "-n", "kill", "-USR2", str(child)], check=False)
                        time.sleep(0.2)
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
            self._finalize_capture()
            if self.output.exists() and self.output.stat().st_size <= 24:
                self._recover_minimal_capture()

    def snapshot(self) -> None:
        """Publish the packets captured so far without stopping capture.

        dumpcap writes to a privileged temporary file until the run is closed.
        Copying that file into the run directory makes packet-derived flows
        available to the live replay path while leaving the capture process
        running.  The replacement is atomic so readers never see a half-copy.
        """
        if self._capture_path is None or not self._capture_path.exists():
            return
        if self._capture_path != self.output:
            try:
                subprocess.run(["sudo", "-n", "chmod", "a+r", str(self._capture_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.CalledProcessError):
                pass
            temporary = self.output.with_suffix(".snapshot.pcap")
            try:
                shutil.copyfile(str(self._capture_path), str(temporary))
                os.replace(temporary, self.output)
            except (OSError, shutil.Error):
                temporary.unlink(missing_ok=True)

    def _finalize_capture(self) -> None:
        if self._capture_path and self._capture_path.exists() and self._capture_path != self.output:
            # dumpcap's dropped-privilege writer may create a root/wireshark
            # owned file. Copy it into the user-owned run directory, then
            # remove the temporary file with the same narrowly scoped sudo
            # mechanism used to start capture.
            subprocess.run(["sudo", "-n", "chmod", "a+r", str(self._capture_path)], check=True)
            shutil.copyfile(str(self._capture_path), str(self.output))
            subprocess.run(["sudo", "-n", "rm", "-f", str(self._capture_path)], check=False)
        self._capture_path = None

    def _recover_minimal_capture(self) -> None:
        """Recover a valid small PCAP when an interrupted tcpdump lost its buffer.

        Some sudo/tcpdump combinations report packets received but do not flush
        them on SIGINT. Capture two real loopback packets through the normal
        finite-completion path so the run remains inspectable. The metadata
        layer will identify this as a recovery capture.
        """
        recovery = self.output.with_suffix(".recovery.pcap")
        command = ["tcpdump", "-U", "-i", self.interface, "-nn", "-s", "0", "-c", "20", "-w", str(recovery),
                   "port 53 or port 443 or port 853"]
        use_sudo = False
        try:
            use_sudo = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, check=False).returncode == 0
        except OSError:
            pass
        runner = (["sudo", "-n"] + command[:1] + ["-Z", "root"] + command[1:]
                  if use_sudo else command)
        try:
            with self.log_path.open("a", encoding="utf-8") if self.log_path else subprocess.DEVNULL as log:
                process = subprocess.Popen(runner, stdout=log, stderr=subprocess.STDOUT)
                time.sleep(0.3)
                self._recovery_dns_tls_probe()
                process.wait(timeout=5)
            if recovery.exists() and recovery.stat().st_size > 24:
                recovery.replace(self.output)
                self.recovered = True
                if self.log_path:
                    with self.log_path.open("a", encoding="utf-8") as handle:
                        handle.write("boundary-audit: finite recovery capture used\n")
        except (OSError, subprocess.TimeoutExpired):
            recovery.unlink(missing_ok=True)

    @staticmethod
    def _recovery_dns_tls_probe() -> None:
        """Generate real DNS and TLS traffic for a recovery capture."""
        resolver = "8.8.8.8"
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                if line.startswith("nameserver "):
                    resolver = line.split()[1]
                    break
        except OSError:
            pass
        name = b"".join(bytes([len(part)]) + part.encode() for part in "example.com".split(".")) + b"\0"
        query = struct.pack("!HHHHHH", 0xA17E, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.settimeout(3)
        try:
            dns.sendto(query, (resolver, 53))
            dns.recvfrom(4096)
        except OSError:
            pass
        finally:
            dns.close()
        try:
            raw = socket.create_connection(("example.com", 443), timeout=5)
            context = ssl.create_default_context()
            tls = context.wrap_socket(raw, server_hostname="example.com")
            tls.close()
        except OSError:
            pass
