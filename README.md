# boundary-audit

`boundary-audit` places an untrusted IoT/robotic device behind an independently controlled network boundary, exercises its functional API, captures network behavior, and performs differential analysis across actions and network policies.

```text
 upstream / Internet
          |
   trusted gateway  <- capture, DNS, nftables, flow evidence
          |
   isolated DUT LAN
          |
   black-box DUT + high-level API
```

The controller never asks the DUT what it sent. Observation happens at the gateway, outside the DUT trust boundary. Encrypted payloads are not decrypted or interpreted.

Use the project environment for all commands in this README. The simplest path
is `uv run ...`; alternatively activate `.venv` after `uv sync`. The system
`python3` may not have dependencies such as `grpcio` installed.

## 60-second demo

The virtual backend is deterministic and needs no public Internet:

```bash
uv sync --extra dev
./scripts/demo.sh            # sudo is only needed for the Linux namespace backend; virtual mode works unprivileged
open runs/*/report.html      # or open the HTML file in any browser
```

Useful commands:

```bash
uv run python -m boundary_audit.cli doctor
uv run python -m boundary_audit.cli scenarios list
uv run python -m boundary_audit.cli run camera --mode observe
uv run python -m boundary_audit.cli run full_matrix --mode airgap
uv run python -m boundary_audit.cli run full_matrix --mode enforce
```

Modes are `observe` (allow the lab's mock Internet), `airgap` (record attempted egress as blocked), and `enforce` (default deny with approved flows represented by generated policy). A run directory is immutable evidence: raw packet capture placeholder/PCAP, JSONL logs, normalized flows, analysis, policy, and standalone reports are retained together.

## Project status

The virtual backend and analysis pipeline are the supported reproducible path in this initial release. The Linux backend boundary is intentionally explicit and conservative; Raspberry Pi scripts do not silently flush a user's firewall. Configure interfaces in `config.yaml` before adapting the scripts to a real gateway.

See [docs/architecture.md](docs/architecture.md), [docs/methodology.md](docs/methodology.md), [docs/threat-model.md](docs/threat-model.md), [docs/demo.md](docs/demo.md), and [docs/raspberry-pi.md](docs/raspberry-pi.md).

Run the black-box DUT process on the machine being observed:

```bash
uv run python -m boundary_audit.dut_simulator
```

It accepts JSON-line SDK actions on stdin and performs local control traffic
plus configured real service calls. Capture the host externally with the
Linux backend or an independently controlled gateway.

For remote SDK control from another device on the same network:

```bash
uv run python -m boundary_audit.grpc_sdk --bind 0.0.0.0 --port 50051
```

```python
from boundary_audit.grpc_sdk import DutGrpcClient

robot = DutGrpcClient("robot-host:50051")
print(robot.capabilities())
robot.execute("stand", category="motion")
```

For live monitoring and run deployment from a browser:

```bash
uv run python -m boundary_audit.cli dashboard-serve
open http://127.0.0.1:8765
```

The web app polls run artifacts and job status every two seconds. It exposes
the raw PCAP, normalized flows, event markers, analysis, and per-layer
evidence through the UI and `/api/runs/<RUN_ID>`. Remote deployment requires
non-interactive SSH authentication such as an SSH key or agent.

## Example finding

The virtual backend exercises the capability matrix. It is a development
observer; authoritative findings require capture outside the DUT process.

## Future adapters

The `DeviceAdapter` interface is vendor-neutral. A future physical robotics adapter can invoke a device's high-level API without changing gateway capture, evidence schemas, differential analysis, or reports.
