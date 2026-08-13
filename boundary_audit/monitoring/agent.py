"""On-device monitoring session and durable evidence bundle.

The agent deliberately owns the collection directory: a controller can start
and mark a run over gRPC, disconnect, and replay the resulting bundle later.
"""

import hashlib
import json
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..capture.manager import CaptureManager
from .collectors import probe_endpoints, snapshot_firewall, snapshot_processes, snapshot_sockets
from .replay import replay_run


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MonitoringSession:
    def __init__(self, directory: Path, metadata: Dict[str, Any], interface: str) -> None:
        self.directory = directory
        self.metadata = metadata
        self.interface = interface
        self.capture = CaptureManager(interface, directory / "packets.pcap",
                                      log_path=directory / "tcpdump.log")
        self.started = False

    @property
    def run_id(self) -> str:
        return self.directory.name

    def start(self) -> Dict[str, Any]:
        self.capture.start()
        self.started = True
        snapshot_processes(self.directory / "processes.jsonl", "start")
        snapshot_sockets(self.directory / "sockets.jsonl", "start")
        self.mark_event("MONITOR_START", "monitor", {"interface": self.interface})
        return self.status()

    def mark_event(self, event_type: str, scenario_id: str = "unattributed",
                   details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        value = {"type": event_type, "scenario_id": scenario_id, "timestamp": _now(),
                 "epoch": __import__("time").time(), "monotonic_ms": __import__("time").monotonic() * 1000,
                 "details": details or {}}
        with (self.directory / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True) + "\n")
        return value

    def record_api(self, action: Dict[str, Any]) -> None:
        with (self.directory / "api-results.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(action, timestamp=_now()), sort_keys=True) + "\n")

    def stop(self, cancelled: bool = False) -> Dict[str, Any]:
        if self.started:
            self.mark_event("MONITOR_CANCEL" if cancelled else "MONITOR_STOP")
            self.capture.stop()
            probe_endpoints(self.metadata.get("network_endpoints", []),
                            self.directory / "dns.jsonl", self.directory / "tls.jsonl")
            if self.capture.recovered:
                self.metadata["capture_recovery"] = True
            snapshot_processes(self.directory / "processes.jsonl", "stop")
            snapshot_sockets(self.directory / "sockets.jsonl", "stop")
            snapshot_firewall(self.directory / "firewall.jsonl", "stop")
            self.started = False
        self.metadata["end"] = _now()
        self.metadata["status"] = "cancelled" if cancelled else "complete"
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata, indent=2), encoding="utf-8")
        replay_run(self.directory)
        self._write_manifest()
        return self.status()

    def status(self) -> Dict[str, Any]:
        pcap = self.directory / "packets.pcap"
        return {"run_id": self.run_id, "status": "running" if self.started else self.metadata.get("status", "created"),
                "directory": str(self.directory), "pcap_bytes": pcap.stat().st_size if pcap.exists() else 0,
                "layers": json.loads((self.directory / "layers.json").read_text())
                if (self.directory / "layers.json").exists() else {}}

    def _write_manifest(self) -> None:
        files = {}
        for path in sorted(self.directory.iterdir()):
            if path.name in ("manifest.json", "checksums.sha256") or not path.is_file():
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            files[path.name] = {"sha256": digest, "bytes": path.stat().st_size}
        manifest = {"schema": "boundary-audit.evidence/v1", "run_id": self.run_id,
                    "created": self.metadata.get("start"), "completed": self.metadata.get("end"),
                    "files": files}
        (self.directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        (self.directory / "checksums.sha256").write_text(
            "".join("%s  %s\n" % (value["sha256"], name) for name, value in files.items()), encoding="utf-8")


class MonitoringAgent:
    def __init__(self, root: Path, interface: str = "any", packet_limit: int = 100000) -> None:
        self.root = Path(root)
        self.interface = interface
        self.packet_limit = packet_limit
        self.session: Optional[MonitoringSession] = None

    def start(self, scenario: str = "remote", mode: str = "observe",
              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self.session and self.session.started:
            raise RuntimeError("a monitoring session is already running")
        run_id = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ") + "_" + uuid.uuid4().hex[:8]
        directory = self.root / run_id
        directory.mkdir(parents=True, exist_ok=False)
        value = {"tool_version": "0.1.0", "backend": "robot-resident", "mode": mode,
                 "scenario": scenario, "start": _now(), "host": socket.gethostname(),
                 "platform": platform.platform(), "pid": os.getpid(), "interface": self.interface,
                 "collector": "tcpdump", "layers_expected": ["raw_packets", "flows", "dns", "tls",
                 "firewall", "local_network", "os", "events", "api"]}
        value.update(metadata or {})
        (directory / "metadata.json").write_text(json.dumps(value, indent=2), encoding="utf-8")
        for name in ("events.jsonl", "dns.jsonl", "tls.jsonl", "firewall.jsonl", "processes.jsonl",
                     "sockets.jsonl", "api-results.jsonl"):
            (directory / name).write_text("", encoding="utf-8")
        self.session = MonitoringSession(directory, value, self.interface)
        self.session.capture.packet_limit = self.packet_limit
        return self.session.start()

    def stop(self, cancelled: bool = False) -> Dict[str, Any]:
        if not self.session:
            raise RuntimeError("no monitoring session")
        return self.session.stop(cancelled)

    def mark_event(self, event_type: str, scenario_id: str = "unattributed",
                   details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.session:
            raise RuntimeError("no monitoring session")
        return self.session.mark_event(event_type, scenario_id, details)

    def status(self) -> Dict[str, Any]:
        return self.session.status() if self.session else {"status": "idle"}

    def artifact(self, name: str) -> bytes:
        if not self.session:
            raise RuntimeError("no monitoring session")
        path = (self.session.directory / name).resolve()
        if path.parent != self.session.directory.resolve():
            raise ValueError("invalid artifact name")
        return path.read_bytes()
