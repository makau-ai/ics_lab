#!/usr/bin/env bash
# Generates ongoing lab traffic so Wireshark always has something to show:
#   1) a short delay for services to settle,
#   2) a one-time INTRUSION DEMO (MQTT anonymous eavesdrop+inject, DNP3 trip),
#   3) then a steady DNP3 integrity poll every 25s (MQTT telemetry is continuous).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"
RUN="/tmp/icslab"; mkdir -p "$RUN"

sleep 14
echo "== startup demo: DNP3 supervised close =="
python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --close 2>&1
sleep 4
echo "== startup demo: MQTT anonymous eavesdrop + command injection =="
BROKER=localhost python3 "$LAB/mqtt/attacker.py" 2>&1
echo "== startup demo: DNP3 unauthenticated trip (frame-27 story) =="
python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --attack 2>&1

# steady heartbeat so the analyzer always has fresh DNP3 traffic
while true; do
  sleep 25
  python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --close 2>&1
done
