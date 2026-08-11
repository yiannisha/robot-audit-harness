# Methodology

1. Isolate the DUT behind a gateway-owned boundary.
2. Establish repeated baseline observations.
3. Invoke one high-level action.
4. Capture before invocation and through cooldown.
5. Normalize packets into bidirectional flows and preserve raw evidence.
6. Correlate observations to high-resolution event markers.
7. Repeat the action and compare presence, latency, destinations, and volume.
8. Generate evidence-based labels such as `new_destination` and `strongly_action_correlated`.
9. Restrict egress with a reviewed allowlist.
10. Retest functionality and record block-and-retest evidence.

Correlation is not causation. The heuristic used here is intentionally clear: a destination present in at least two of three action repetitions and absent in at least two of three baseline repetitions is strongly action-correlated.

