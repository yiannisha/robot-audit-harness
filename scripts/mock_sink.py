#!/usr/bin/env python3
"""Receive synthetic DUT traffic on the laptop and retain a small log."""

import argparse
import json
import socketserver
import time


class SinkHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        header = self.request.recv(128)
        total = len(header)
        while True:
            chunk = self.request.recv(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
        record = {"timestamp": time.time(), "client": self.client_address[0], "header": header.decode("ascii", "replace"), "bytes": total}
        print(json.dumps(record, sort_keys=True), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    with socketserver.ThreadingTCPServer((args.bind, args.port), SinkHandler) as server:
        server.allow_reuse_address = True
        print("mock sink listening on %s:%d" % (args.bind, args.port), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
