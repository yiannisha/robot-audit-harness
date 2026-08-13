# Architecture

The architecture puts the simulator/DUT and the monitoring agent on the same
device host. A separate controller host connects directly to the device host's
gRPC service over the network.

```text
 Controller host
   └─ gRPC: health, actions, monitor lifecycle, artifact download
                  │
                  ▼
 Device host
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
        replay, normalization, analysis, policy
```

The controller does not need to remain online during collection: the device host owns
the run directory and can finalize it locally. While the controller host is connected,
the security console downloads updated artifacts after each action through
`GetArtifact`; the controller host can also download the completed bundle later.

## Collection and analysis

At monitor start, the device host creates a run directory and starts `dumpcap`. During
the run, gRPC actions are recorded in `api-results.jsonl` and receive automatic
`API_CALL_BEGIN`/`API_CALL_END` markers. After each action, the device host publishes
the packets captured so far, actively probes configured endpoints, and replays
the bundle into current flows, layer status, analysis, and policy artifacts.
The final clear/stop operation flushes the capture, collects process/socket/
firewall snapshots, writes the manifest and checksums, and closes the run.

`dumpcap` writes to a temporary path because its capture privilege is dropped;
the completed capture is copied into the user-owned run directory as
`packets.pcap`. `tshark` is used when decoding packet-level DNS/TLS evidence is
available. Active DNS/TLS records are explicitly labelled with their source in
`dns.jsonl` and `tls.jsonl`. Flow attribution checks every packet in an
aggregated flow against action windows, so long-lived and loopback connections
can still be linked to later actions.

The gRPC service currently uses insecure transport. It is suitable for a
trusted test LAN; add TLS/authentication before exposing it beyond that scope.
