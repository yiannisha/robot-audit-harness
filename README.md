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

## 60-second demo

The virtual backend is deterministic and needs no public Internet:

```bash
cd boundary-audit
python3 -m pip install -e '.[dev]'
sudo ./scripts/demo.sh       # sudo is only needed for the Linux namespace backend; virtual mode works unprivileged
open runs/*/report.html       # or open the HTML file in any browser
```

Useful commands:

```bash
python3 -m boundary_audit.cli doctor
python3 -m boundary_audit.cli scenarios list
python3 -m boundary_audit.cli run camera --mode observe
python3 -m boundary_audit.cli run full_matrix --mode airgap
python3 -m boundary_audit.cli run full_matrix --mode enforce
```

Modes are `observe` (allow the lab's mock Internet), `airgap` (record attempted egress as blocked), and `enforce` (default deny with approved flows represented by generated policy). A run directory is immutable evidence: raw packet capture placeholder/PCAP, JSONL logs, normalized flows, analysis, policy, and standalone reports are retained together.

## Project status

The virtual backend and analysis pipeline are the supported reproducible path in this initial release. The Linux backend boundary is intentionally explicit and conservative; Raspberry Pi scripts do not silently flush a user's firewall. Configure interfaces in `config.yaml` before adapting the scripts to a real gateway.

See [docs/architecture.md](docs/architecture.md), [docs/methodology.md](docs/methodology.md), [docs/threat-model.md](docs/threat-model.md), [docs/demo.md](docs/demo.md), and [docs/raspberry-pi.md](docs/raspberry-pi.md).

For a real fake DUT running on the Raspberry Pi with the laptop receiving
synthetic traffic and retaining the Pi's PCAP, see
[docs/rpi-live-capture.md](docs/rpi-live-capture.md).

The one-command remote workflow is:

```bash
BA_REMOTE_HOST=yiannis@192.168.1.168 \
BA_REMOTE_DIR='~/side/dimensional/boundary-audit' \
BA_SINK_HOST=192.168.1.163 \
./scripts/remote_demo.sh
```

It starts the laptop sink, starts the generic fake DUT remotely, captures
actual egress, pulls the immutable run, derives flows/reports from the PCAP,
and regenerates `dashboard.html` across all retained runs. SSH keys are
recommended; otherwise SSH will prompt for the remote password.

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

The simulator's camera action produces a repeatable large flow to `suspicious.test`; diagnostics demonstrates a direct-IP flow without DNS evidence; update checking is an expected hostname-attributed TLS flow; and a separate IPv6 attempt is reported. These are synthetic lab findings, not claims about a vendor device.

## Future adapters

The `DeviceAdapter` interface is vendor-neutral. A future physical robotics adapter can invoke a device's high-level API without changing gateway capture, evidence schemas, differential analysis, or reports.
