# Understanding results

Every run is stored in a directory named with its UTC timestamp and run ID.
The important files are:

| File | Meaning |
|---|---|
| `metadata.json` | Host, interface, scenario, collector, endpoint, and timing metadata |
| `packets.pcap` | Raw packet capture; readable with `tcpdump` or `tshark` |
| `events.jsonl` | Monitor lifecycle and action begin/end markers |
| `api-results.jsonl` | Every gRPC action request and returned result |
| `dns.jsonl` | DNS observations, including active resolver records when used |
| `tls.jsonl` | TLS handshake/SNI/version/cipher observations |
| `processes.jsonl` | Process snapshots at session start and stop |
| `sockets.jsonl` | `/proc/net` socket snapshots at session start and stop |
| `firewall.jsonl` | nftables ruleset snapshot and collection status |
| `flows.json` | Normalized bidirectional network flows |
| `layers.json` | Collection status and counts for each evidence layer |
| `analysis.json` | Baseline/action differential analysis |
| `generated-policy.nft` | Candidate nftables policy from observed allowed flows |
| `manifest.json` | Bundle schema, file sizes, and SHA-256 checksums |

## Layer statuses

- `collected`: evidence was written for that layer.
- `not_observed`: the collector ran, but no matching DNS/TLS records were found.
- `unavailable`: the required decoder/tool was not installed or could not run.
- `failed`: collection or capture failed; do not interpret the layer as empty.
- `partial`: only some expected observations were available.

For example, `dns.status = not_observed` means no DNS record was found in the
PCAP or active endpoint probe. It does not prove that the robot never used
DNS. Check `metadata.json`, `events.jsonl`, and the capture log before drawing
that conclusion.

`raw_packets.recovery: true` means the primary capture did not finalize
normally and a recovery capture was used. Treat the run as degraded and repeat
it after fixing capture privileges/process lifecycle.

Typical inspection commands:

```bash
cat RUN/layers.json
cat RUN/api-results.jsonl
cat RUN/dns.jsonl
cat RUN/tls.jsonl
tcpdump -nn -r RUN/packets.pcap
```
