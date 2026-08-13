# Architecture

The current working architecture puts the simulator/DUT and the monitoring
agent on the same Raspberry Pi. A laptop acts as the controller and connects
directly to the Pi's gRPC service over the LAN.

```text
 Laptop controller
   └─ gRPC: health, actions, monitor lifecycle, artifact download
                  │
                  ▼
 Raspberry Pi / robot host
   ├─ DutSimulator or physical DUT adapter
   └─ MonitoringAgent
       ├─ dumpcap packet capture
       ├─ active DNS resolution metadata
       ├─ active TLS handshake metadata
       ├─ process snapshots
       ├─ socket snapshots
       ├─ nftables ruleset snapshot
       ├─ API/event correlation
       └─ durable evidence bundle
                  │
                  ▼
        replay, normalization, analysis, reports
```

The controller does not need to remain online during collection: the Pi owns
the run directory and can finalize it locally. The laptop can download the
completed artifacts through `GetArtifact`.

## Collection and analysis

At monitor start, the Pi creates a run directory and starts `dumpcap`. During
the run, gRPC actions are recorded in `api-results.jsonl` and receive automatic
`API_CALL_BEGIN`/`API_CALL_END` markers. At stop, the Pi finalizes the PCAP,
collects process/socket/firewall snapshots, actively resolves configured robot
service hostnames, performs TLS handshakes for TLS endpoints, and replays the
bundle into flows, layer status, analysis, and policy artifacts.

`dumpcap` writes to a temporary path because its capture privilege is dropped;
the completed capture is copied into the user-owned run directory as
`packets.pcap`. `tshark` is used when decoding packet-level DNS/TLS evidence is
available. Active DNS/TLS records are explicitly labelled with their source in
`dns.jsonl` and `tls.jsonl`.

The virtual backend remains available for deterministic CI. It produces the
same normalized evidence/report contracts without requiring a Pi or Internet
access.

The gRPC service currently uses insecure transport. It is suitable for a
trusted test LAN; add TLS/authentication before exposing it beyond that scope.
