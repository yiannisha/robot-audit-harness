#!/usr/bin/env python3
"""Run robot actions through gRPC while the robot-resident monitor captures them."""

import argparse
import json
from pathlib import Path

from boundary_audit.dut_simulator import DutSimulator
from boundary_audit.grpc_sdk import DutGrpcClient, serve


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="any", help="capture interface, e.g. lo or wlan0")
    parser.add_argument("--output", type=Path, default=Path("runs"))
    parser.add_argument("--boot", action="store_true", help="also run boot, which performs configured service networking")
    args = parser.parse_args()

    server = serve(DutSimulator(network_enabled=True), "127.0.0.1", 0,
                   monitor_root=args.output, monitor_interface=args.interface,
                   # The demo completes tcpdump normally after a handful of
                   # packets, making it convenient on sudo-managed hosts.
                   monitor_packet_limit=32)
    client = DutGrpcClient("127.0.0.1:%d" % server.bound_port)
    try:
        print("Robot health:", client.health())
        started = client.start_monitor("manual_demo")
        print("Monitoring run:", started["run_id"])

        actions = ([ ("boot", "lifecycle") ] if args.boot else []) + [("stand", "motion"), ("move_forward", "motion"),
                   ("camera_stream", "perception"), ("camera_stop", "perception")]
        for action, category in actions:
            client.mark_event("API_CALL_BEGIN", "manual_demo", {"action": action})
            result = client.execute(action, category=category)
            client.mark_event("API_CALL_END", "manual_demo",
                              {"action": action, "ok": result.get("ok", False)})
            print("%s: %s" % (action, json.dumps(result, sort_keys=True)))

        finished = client.stop_monitor()
        run_dir = Path(finished["directory"])
        print("\nEvidence written to:", run_dir)
        print("Inspect with:")
        print("  cat %s/layers.json" % run_dir)
        print("  cat %s/flows.json" % run_dir)
        print("  tcpdump -nn -r %s/packets.pcap" % run_dir)
    finally:
        server.stop(0)


if __name__ == "__main__":
    main()
