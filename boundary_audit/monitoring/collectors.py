"""Best-effort host-side layer collectors used by a monitoring session."""

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict


def _append(path: Path, value: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


def snapshot_processes(path: Path, phase: str) -> int:
    count = 0
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(entry.name)
            command = (entry / "comm").read_text(errors="replace").strip()
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            _append(path, {"timestamp": time.time(), "phase": phase, "pid": pid,
                           "command": command, "cmdline": cmdline})
            count += 1
        except (OSError, ValueError):
            continue
    return count


def snapshot_sockets(path: Path, phase: str) -> int:
    count = 0
    for protocol, source in (("tcp", "/proc/net/tcp"), ("udp", "/proc/net/udp"),
                             ("tcp6", "/proc/net/tcp6"), ("udp6", "/proc/net/udp6")):
        try:
            lines = Path(source).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            _append(path, {"timestamp": time.time(), "phase": phase, "protocol": protocol,
                           "local": fields[1], "remote": fields[2], "state": fields[3]})
            count += 1
    return count


def snapshot_firewall(path: Path, phase: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(["nft", "-j", "list", "ruleset"], check=False,
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        value = {"timestamp": time.time(), "phase": phase, "status": "failed", "error": str(error)}
    else:
        value = ({"timestamp": time.time(), "phase": phase, "status": "failed",
                  "error": result.stderr.strip() or "nft exited unsuccessfully"}
                 if result.returncode else
                 {"timestamp": time.time(), "phase": phase, "status": "collected",
                  "ruleset": json.loads(result.stdout or "{}")})
    _append(path, value)
    return value


def decode_with_tshark(pcap: Path, dns_path: Path, tls_path: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {"dns": "not_collected", "tls": "not_collected"}
    if not pcap.exists() or pcap.stat().st_size <= 24:
        result["reason"] = "PCAP is empty or incomplete"
        return result
    for layer, output, fields in (
        ("dns", dns_path, ["frame.time_epoch", "dns.qry.name", "dns.qry.type", "dns.a"]),
        ("tls", tls_path, ["frame.time_epoch", "tls.handshake.extensions_server_name", "tls.handshake.type"]),
    ):
        try:
            command = ["tshark", "-r", str(pcap), "-T", "fields"]
            for field in fields:
                command += ["-e", field]
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            result[layer] = "unavailable"
            continue
        if completed.returncode:
            result[layer] = "failed"
            continue
        count = 0
        for line in completed.stdout.splitlines():
            values = line.split("\t")
            if not any(values[1:]):
                continue
            if layer == "dns":
                record = {"timestamp_epoch": values[0], "query_name": values[1],
                          "query_type": values[2], "response_records": [x for x in values[3].split(",") if x]}
            else:
                record = {"timestamp_epoch": values[0], "sni": values[1], "handshake_type": values[2]}
            _append(output, record)
            count += 1
        result[layer] = "collected" if count else "not_observed"
        result[layer + "_count"] = count
    return result
