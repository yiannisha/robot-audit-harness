# Architecture

The trusted controller invokes a generic `DeviceAdapter`; it does not inspect device internals. The DUT sits on an isolated LAN whose only intended path is the trusted gateway. The gateway is the observation plane: packet capture, DNS records, TLS handshake metadata, firewall verdicts, and local-network classification are retained as evidence. The analysis plane normalizes those observations into flows, correlates them with event intervals, compares repetitions against baseline, and renders reports.

The virtual backend provides deterministic evidence for CI and presentations. A Linux namespace backend can replace that evidence source with veth pairs, tcpdump, and nftables without changing the adapter or report contracts.

