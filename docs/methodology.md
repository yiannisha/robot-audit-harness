# Methodology

1. Start a monitoring session on the robot host.
2. Establish a baseline or invoke a selected robot action.
3. Record API requests, results, and high-resolution event markers.
4. Capture packets through the action and cooldown window.
5. Collect host process, socket, and firewall state.
6. Resolve configured service names and perform configured TLS handshakes.
7. Preserve raw evidence and replay it into normalized flows and layer data.
8. Repeat scenarios and compare destinations, volume, timing, and status.
9. Generate analysis and a candidate nftables policy.

The virtual runner uses repeated baseline/action observations and produces
deterministic evidence for development. The Pi path records what the robot
host observed during the real run.

Correlation is not causation. The default attribution heuristic classifies a
destination as strongly action-correlated when it is present in at least two
of three action repetitions and absent in at least two of three baseline
repetitions.

Active DNS/TLS metadata proves that the robot host could resolve/connect to a
configured endpoint during collection. It is not a claim that every packet in
that observation belongs to one particular action. Use event timestamps,
flows, and repetitions for attribution.
