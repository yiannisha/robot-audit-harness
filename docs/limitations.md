# Limitations

The evidence describes observed behavior, not payload meaning. TLS 1.3 and
encrypted client hello can reduce metadata. DNS attribution is time-aware
evidence, not proof that a hostname owns an IP. Flow/action attribution is a
time-correlation heuristic, not proof of causation. The virtual
`packets.pcap` is a small evidence marker; authoritative packet capture
requires the Linux backend and dumpcap/tshark.
