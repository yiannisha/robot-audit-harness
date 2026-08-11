# Live Raspberry Pi capture

This is the current practical split workflow for a real Pi and laptop. It
captures actual Pi egress without changing routing, NAT, forwarding, or
firewall state. It is therefore useful for validating the fake DUT and PCAP
pipeline, but it is not yet a complete independent gateway boundary.

## Laptop

Find the laptop's LAN address. In this example it is `192.168.1.163`.

```bash
cd boundary-audit
python3 scripts/mock_sink.py --bind 0.0.0.0 --port 18080
```

Keep this terminal open. The sink prints one JSON record for each DUT
connection and does not persist payload contents.

For the complete automated flow, configure SSH access and run from the
project root:

```bash
BA_REMOTE_HOST=yiannis@192.168.1.168 \
BA_REMOTE_DIR='~/side/dimensional/boundary-audit' \
BA_SINK_HOST=192.168.1.163 \
./scripts/remote_demo.sh
```

This also derives `flows.json`, `analysis.json`, `report.html`, and the global
dashboard from the captured PCAP.

## Browser dashboard

The laptop can host the live run UI:

```bash
uv run python -m boundary_audit.cli dashboard-serve
open http://127.0.0.1:8765
```

The Deploy form starts either a virtual run or the generic remote-device
workflow. The dashboard refreshes job state and newly completed run artifacts
automatically. For browser-triggered remote runs, configure SSH keys/agent
access first because a browser job cannot answer an interactive SSH password
prompt.

## Raspberry Pi

Copy the project to `~/side/dimensional/boundary-audit`, install tcpdump once,
and start the fake DUT:

```bash
ssh yiannis@192.168.1.168
sudo apt-get update
sudo apt-get install -y tcpdump
cd ~/side/dimensional/boundary-audit
nohup python3 simulator/device_server.py \
  --bind 0.0.0.0 --port 8080 \
  --sink-host 192.168.1.163 --sink-port 18080 \
  >/tmp/boundary-audit-dut.log 2>&1 </dev/null &
```

From another laptop terminal, start the real capture/action sequence:

```bash
ssh yiannis@192.168.1.168 \
  'cd ~/side/dimensional/boundary-audit && ./scripts/rpi_actual_capture.sh'
```

The script captures `eth0` before calling the fake API and stops after the
cooldown. It exercises `/reset`, `/motion`, `/camera/start`, `/diagnostics`,
and `/update/check`. The capture directory is printed by the script.

Pull it back for analysis/archive:

```bash
scp -r yiannis@192.168.1.168:\
  ~/side/dimensional/boundary-audit/runs/<RUN_ID> ./runs/
tcpdump -nn -r ./runs/<RUN_ID>/packets.pcap | less
```

Expected evidence includes traffic from `192.168.1.168` to the laptop sink,
with the camera flow substantially larger than motion or update. The sink
receives deterministic synthetic bytes only; no real camera data or
credentials are used.

Stop the temporary processes after the experiment:

```bash
ssh yiannis@192.168.1.168 'pkill -f "simulator/device_server.py" || true'
```

The next hardening step is to move the capture point to a dedicated Pi
gateway interface or a Linux laptop gateway, then add DNS/nftables/tls
metadata ingestion to the remote run artifact. Capturing the Pi's own `eth0`
is real packet evidence, but does not by itself prove that another DUT route
could not bypass the boundary.
