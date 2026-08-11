#!/usr/bin/env bash
set -euo pipefail

# Reversible actual-data experiment. This captures Pi egress but does not
# change routes, forwarding, NAT, or firewall rules.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="$(date -u +%Y-%m-%dT%H-%M-%SZ)_rpi_actual"
RUN_DIR="$ROOT/runs/$RUN_ID"
CAPTURE_IF="${RPI_CAPTURE_IF:-eth0}"
DUT_URL="${BA_DUT_URL:-http://127.0.0.1:8080}"
SINK_HOST="${BA_SINK_HOST:-192.168.1.163}"
EXTERNAL_HOST="${BA_EXTERNAL_HOST:-}"
DEVICE_IP="$(hostname -I | awk '{print $1}')"
TARGET_IPS="$SINK_HOST"
if test -n "$EXTERNAL_HOST"; then
  TARGET_IPS="$(getent ahostsv4 "$EXTERNAL_HOST" | awk 'NR==1 {print $1}')"
fi
mkdir -p "$RUN_DIR"

printf '{"backend":"raspberry_pi_capture","capture_interface":"%s","dut_url":"%s","dut_ip":"%s","sink_host":"%s","external_host":"%s","target_ips":"%s","mode":"observe","scenario":"remote_demo","start":"%s"}\n' \
  "$CAPTURE_IF" "$DUT_URL" "$DEVICE_IP" "$SINK_HOST" "$EXTERNAL_HOST" "$TARGET_IPS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RUN_DIR/metadata.json"
touch "$RUN_DIR/events.jsonl"

sudo tcpdump -i "$CAPTURE_IF" -nn -s 0 -w "$RUN_DIR/packets.pcap" >"$RUN_DIR/tcpdump.log" 2>&1 &
CAPTURE_PID=$!
cleanup() { kill "$CAPTURE_PID" 2>/dev/null || true; wait "$CAPTURE_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
sleep 1

curl --fail --silent "$DUT_URL/health" >"$RUN_DIR/health.json"
for action in reset motion camera/start diagnostics update/check; do
  printf '{"type":"API_CALL_BEGIN","scenario_id":"%s","epoch":%.6f}\n' "$action" "$(date +%s.%N)" >>"$RUN_DIR/events.jsonl"
  curl --fail --silent -X POST "$DUT_URL/$action" -H 'Content-Type: application/json' -d '{}' >>"$RUN_DIR/api-results.jsonl"
  printf '\n' >>"$RUN_DIR/api-results.jsonl"
  printf '{"type":"API_CALL_END","scenario_id":"%s","epoch":%.6f}\n' "$action" "$(date +%s.%N)" >>"$RUN_DIR/events.jsonl"
done
sleep 2
echo "actual capture written to $RUN_DIR"
