# Development report

Implemented the initial `boundary-audit` architecture: typed evidence schemas, generic device adapter, capability-driven black-box robotic OS simulator, scenario matrix, virtual observe/airgap/enforce runs, event/DNS/TLS/firewall/flow artifacts, differential analysis, policy generation, standalone text/HTML reports, CLI, demo verification, safety-focused Linux guidance, threat model, and tests.

Demo command: `./scripts/demo.sh` from `boundary-audit/`.

The current host is macOS with Python 3.9. The deterministic virtual path is runnable without Linux networking tools; namespace/tcpdump/nftables integration must be validated on a fresh Debian/Ubuntu host. The next logical step is wiring a real Linux namespace backend and then a physical-device `DeviceAdapter`, keeping the gateway observation and analysis contracts unchanged.

## Live Pi validation

On 2026-08-11, the fake DUT ran on Raspberry Pi 5 / Debian 13 ARM64 and sent
real TCP traffic to the laptop sink at `192.168.1.163:18080`. The Pi captured
`847` packets with `0` kernel drops in
`runs/2026-08-11T17-02-49Z_rpi_actual/packets.pcap`. The capture included the
small boot/motion/update flows, a roughly 8 MB camera flow, and a roughly 420
KB diagnostics flow. This validates actual API-to-socket-to-PCAP behavior;
the capture point was the Pi's `eth0`, so an independent gateway boundary is
still the next deployment step.
