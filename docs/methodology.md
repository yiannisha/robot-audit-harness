# Methodology

1. Start the device-resident monitoring session; the security console does this
   automatically when the device host is connected.
2. Establish a baseline or invoke a selected robot action.
3. Record API requests, results, and high-resolution event markers.
4. Capture packets through the action and cooldown window.
5. Collect host process, socket, and firewall state.
6. Resolve configured service names and perform configured TLS handshakes.
7. Preserve raw evidence and replay it into normalized flows and layer data
   after each action and again when the run is finalized.
8. Repeat scenarios and compare destinations, volume, timing, and status.
9. Generate analysis and a candidate nftables policy.

The virtual runner uses repeated baseline/action observations and produces
deterministic evidence for development. The device-host path records what the
DUT host observed during the real run.

Correlation is not causation. Live flow attribution links every packet that
falls inside an action window to that action, including packets from an
already-open or loopback connection. The virtual differential analysis also
classifies a destination as strongly action-correlated when it is present in at
least two of three action repetitions and absent in at least two of three
baseline repetitions.

Active DNS/TLS metadata proves that the device host could resolve/connect to a
configured endpoint during collection. It is not a claim that every packet in
that observation belongs to one particular action. Use event timestamps,
flows, and repetitions for attribution.
