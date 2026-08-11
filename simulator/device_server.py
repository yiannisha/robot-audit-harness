"""Standalone fake DUT HTTP API for running on a Raspberry Pi.

This process deliberately contains no audit logic. It behaves like a black
box: API calls trigger deterministic socket traffic to a configured lab sink.
The laptop or gateway observes that traffic independently.
"""

import argparse
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict


def send_payload(host: str, port: int, size: int, label: str) -> None:
    payload = ("boundary-audit:%s:" % label).encode("ascii")
    block = (payload * ((64 * 1024 // len(payload)) + 1))[:64 * 1024]
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(("BA/1 %s %d\n" % (label, size)).encode("ascii"))
        remaining = size
        while remaining:
            chunk = block[: min(len(block), remaining)]
            connection.sendall(chunk)
            remaining -= len(chunk)


class DeviceHandler(BaseHTTPRequestHandler):
    server_version = "boundary-audit-dut/1.0"

    def _json(self, status: int, value: Dict[str, object]) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"ok": True, "device": "simulated-dut", "version": "1.0"})
        elif self.path == "/state":
            self._json(200, {"ok": True, "state": "idle", "external_payload": False})
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        operation = {"/reset": "boot", "/motion": "motion", "/camera/start": "camera", "/diagnostics": "diagnostics", "/update/check": "update"}.get(self.path)
        if operation is None:
            self._json(404, {"ok": False, "error": "not found"})
            return
        host = self.server.external_host or self.server.sink_host  # type: ignore[attr-defined]
        port = self.server.external_port if self.server.external_host else self.server.sink_port  # type: ignore[attr-defined]
        sizes = {"boot": 96, "motion": 128, "camera": 8_000_000, "diagnostics": 420_000, "update": 1_024}
        if self.server.external_host:  # type: ignore[attr-defined]
            sizes = {name: min(size, self.server.external_max_bytes) for name, size in sizes.items()}  # type: ignore[attr-defined]
        try:
            if operation == "diagnostics":
                # The sink IP is used directly, with no hostname lookup.
                send_payload(host, port, sizes[operation], "diagnostics-direct-ip")
            else:
                send_payload(host, port, sizes[operation], operation)
            self._json(200, {"ok": True, "operation": operation})
        except OSError as error:
            self._json(200, {"ok": True, "operation": operation, "egress_error": str(error)})

    def log_message(self, format_string: str, *args: object) -> None:
        print("api", self.address_string(), format_string % args, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default=os.environ.get("BA_DUT_BIND", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("BA_DUT_PORT", "8080")))
    parser.add_argument("--sink-host", default=os.environ.get("BA_SINK_HOST", "192.168.1.163"))
    parser.add_argument("--sink-port", type=int, default=int(os.environ.get("BA_SINK_PORT", "18080")))
    parser.add_argument("--external-host", default=os.environ.get("BA_EXTERNAL_HOST", ""))
    parser.add_argument("--external-port", type=int, default=int(os.environ.get("BA_EXTERNAL_PORT", "443")))
    parser.add_argument("--external-max-bytes", type=int, default=int(os.environ.get("BA_EXTERNAL_MAX_BYTES", "1024")))
    args = parser.parse_args()
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.bind, args.port), DeviceHandler)
    server.sink_host = args.sink_host
    server.sink_port = args.sink_port
    server.external_host = args.external_host or None
    server.external_port = args.external_port
    server.external_max_bytes = args.external_max_bytes
    print("fake DUT listening on %s:%d; sink=%s:%d" % (args.bind, args.port, args.sink_host, args.sink_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
