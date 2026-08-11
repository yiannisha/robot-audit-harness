#!/usr/bin/env bash
set -euo pipefail

# Generic remote-device demo. The remote target can be a Pi, VM, or Linux
# host; no vendor or board-specific assumptions are made here.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_HOST="${BA_REMOTE_HOST:?Set BA_REMOTE_HOST, e.g. yiannis@192.168.1.168}"
REMOTE_DIR="${BA_REMOTE_DIR:-~/side/dimensional/boundary-audit}"
SINK_HOST="${BA_SINK_HOST:?Set BA_SINK_HOST to the laptop LAN address}"
SINK_PORT="${BA_SINK_PORT:-18080}"
CAPTURE_IF="${BA_CAPTURE_IF:-eth0}"
EXTERNAL_HOST="${BA_EXTERNAL_HOST:-}"
CONTROL_PATH="/tmp/ba-ssh-%C"
SSH_OPTS=""
if test "${BA_NONINTERACTIVE:-0}" = "1"; then
  SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10"
fi
mkdir -p "$ROOT/runs"

cleanup() {
  stop_remote || true
  if test -n "${SINK_PID:-}"; then kill "$SINK_PID" 2>/dev/null || true; fi
  ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" -O exit "$REMOTE_HOST" 2>/dev/null || true
}
stop_remote() {
  ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" "$REMOTE_HOST" "if test -f /tmp/boundary-audit-dut.pid; then kill \$(cat /tmp/boundary-audit-dut.pid) 2>/dev/null || true; rm -f /tmp/boundary-audit-dut.pid; fi" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 "$ROOT/scripts/mock_sink.py" --bind 0.0.0.0 --port "$SINK_PORT" >"$ROOT/remote-sink.log" 2>&1 &
SINK_PID=$!

ssh $SSH_OPTS -o ControlMaster=auto -o ControlPersist=5m -o ControlPath="$CONTROL_PATH" -fnNT "$REMOTE_HOST"
if [[ "$REMOTE_DIR" == "~/"* ]]; then
  REMOTE_DIR_SUFFIX="${REMOTE_DIR#\~/}"
  REMOTE_DIR_RESOLVED="$(ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" "$REMOTE_HOST" "printf '%s/%s' \"\$HOME\" '$REMOTE_DIR_SUFFIX'")"
else
  REMOTE_DIR_RESOLVED="$REMOTE_DIR"
fi
ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" "$REMOTE_HOST" "set -eu; test -d '$REMOTE_DIR_RESOLVED'; if test -f /tmp/boundary-audit-dut.pid; then OLD_PID=\$(cat /tmp/boundary-audit-dut.pid); kill \"\$OLD_PID\" 2>/dev/null || true; rm -f /tmp/boundary-audit-dut.pid; fi; cd '$REMOTE_DIR_RESOLVED'; nohup env BA_SINK_HOST='$SINK_HOST' BA_SINK_PORT='$SINK_PORT' BA_EXTERNAL_HOST='$EXTERNAL_HOST' BA_EXTERNAL_MAX_BYTES=1024 python3 simulator/device_server.py --bind 0.0.0.0 --port 8080 --sink-host '$SINK_HOST' --sink-port '$SINK_PORT' --external-host '$EXTERNAL_HOST' --external-port 443 --external-max-bytes 1024 >/tmp/boundary-audit-dut.log 2>&1 </dev/null & DUT_PID=\$!; echo \"\$DUT_PID\" >/tmp/boundary-audit-dut.pid; sleep 1; kill -0 \"\$DUT_PID\" 2>/dev/null || { cat /tmp/boundary-audit-dut.log; exit 1; }; curl --fail --silent http://127.0.0.1:8080/health >/dev/null"
ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" "$REMOTE_HOST" "set -eu; cd '$REMOTE_DIR_RESOLVED'; RPI_CAPTURE_IF='$CAPTURE_IF' BA_SINK_HOST='$SINK_HOST' BA_EXTERNAL_HOST='$EXTERNAL_HOST' ./scripts/rpi_actual_capture.sh"
RUN_ID="$(ssh $SSH_OPTS -o ControlPath="$CONTROL_PATH" "$REMOTE_HOST" "cd '$REMOTE_DIR_RESOLVED' && ls -td runs/*_rpi_actual | head -1 | xargs basename")"
scp $SSH_OPTS -o ControlPath="$CONTROL_PATH" -r "$REMOTE_HOST:$REMOTE_DIR_RESOLVED/runs/$RUN_ID" "$ROOT/runs/"
stop_remote
uv run python -m boundary_audit.cli enrich-live "$RUN_ID"
uv run python -m boundary_audit.cli dashboard
echo "live run: $ROOT/runs/$RUN_ID"
echo "dashboard: $ROOT/dashboard.html"
