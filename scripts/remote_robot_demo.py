#!/usr/bin/env python3
"""Control a robot-resident simulator and monitor remotely over gRPC."""

import argparse
from pathlib import Path

from boundary_audit.grpc_sdk import DutGrpcClient


ARTIFACTS = (
    "metadata.json", "events.jsonl", "api-results.jsonl", "packets.pcap",
    "flows.json", "layers.json", "dns.jsonl", "tls.jsonl", "firewall.jsonl",
    "processes.jsonl", "sockets.jsonl", "analysis.json", "manifest.json",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Pi hostname or IP address")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--output", type=Path, default=Path("remote-evidence"))
    parser.add_argument("--boot", action="store_true", help="run boot before the motion actions")
    args = parser.parse_args()

    client = DutGrpcClient("%s:%d" % (args.host, args.port))
    print("Robot:", client.health())
    run = client.start_monitor("laptop_remote_demo")
    print("Monitoring run:", run["run_id"])

    actions = [("stand", "motion"), ("move_forward", "motion"),
               ("camera_stream", "perception"), ("camera_stop", "perception")]
    if args.boot:
        actions.insert(0, ("boot", "lifecycle"))

    try:
        for action, category in actions:
            result = client.execute(action, category=category)
            print("%s: %s" % (action, result))
        finished = client.stop_monitor()
    except BaseException:
        client.stop_monitor(cancelled=True)
        raise

    output = args.output / finished["run_id"]
    output.mkdir(parents=True, exist_ok=True)
    for name in ARTIFACTS:
        try:
            (output / name).write_bytes(client.get_artifact(name))
            print("downloaded", name)
        except Exception as error:
            print("skipped %s: %s" % (name, error))

    print("\nEvidence downloaded to:", output)
    print("Inspect with:")
    print("  cat %s/layers.json" % output)
    print("  cat %s/api-results.jsonl" % output)
    print("  tcpdump -nn -r %s/packets.pcap" % output)


if __name__ == "__main__":
    main()
