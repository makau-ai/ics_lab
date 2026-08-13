#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run-local.sh — run the lab as plain localhost processes so you can watch it
# LIVE on the 'lo' interface in Wireshark (the simplest GUI path in Codespaces).
#
#   ./lab/run-local.sh up      # start broker (1883) + DNP3 outstation (20000)
#   ./lab/run-local.sh mqtt    # MQTT publish/subscribe + anonymous attacker
#   ./lab/run-local.sh dnp3    # DNP3 integrity poll + supervised close + rogue trip
#   ./lab/run-local.sh status  # what's running
#   ./lab/run-local.sh down    # stop broker + outstation
#
# Capture in Wireshark on interface 'lo' (ports 1883 / 20000), or open the
# provided pcaps in pcaps/.  For the multi-container lab use docker compose.
# ---------------------------------------------------------------------------
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
RUN="/tmp/icslab"; mkdir -p "$RUN"

_up() {
  pkill -f "mosquitto -c $LAB/mosquitto" 2>/dev/null; pkill -f "dnp3/outstation.py" 2>/dev/null; sleep 1
  nohup mosquitto -c "$LAB/mosquitto/mosquitto.insecure.conf" >"$RUN/broker.log" 2>&1 &
  echo $! >"$RUN/broker.pid"
  nohup python3 "$LAB/dnp3/outstation.py" >"$RUN/outstation.log" 2>&1 &
  echo $! >"$RUN/outstation.pid"
  sleep 1
  echo "Started: MQTT broker on 1883, DNP3 outstation on 20000 (localhost)."
  echo "Now open Wireshark ( ./lab/open-wireshark.sh ), capture on 'lo', then:"
  echo "  ./lab/run-local.sh mqtt   |   ./lab/run-local.sh dnp3"
}

_mqtt() {
  echo "[MQTT] HMI subscriber + field sensor + pump-controller, then the anonymous attacker..."
  BROKER=localhost timeout 14 python3 "$LAB/mqtt/subscriber.py" >"$RUN/sub.log" 2>&1 &
  sleep 1
  BROKER=localhost nohup python3 "$LAB/mqtt/pump-controller.py" >"$RUN/pump.log" 2>&1 &
  PUMP=$!
  BROKER=localhost timeout 14 python3 "$LAB/mqtt/publisher.py" >"$RUN/pub.log" 2>&1 &
  sleep 2
  BROKER=localhost python3 "$LAB/mqtt/attacker.py"
  sleep 1; kill "$PUMP" 2>/dev/null
  echo "--- pump-controller reaction to the injected command ---"
  grep "COMMAND" "$RUN/pump.log" | tail -1 || echo "(none)"
}

_dnp3() {
  echo "[DNP3] integrity poll + supervised SELECT/OPERATE close..."
  python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --close
  echo
  echo "[DNP3] rogue unauthenticated DIRECT_OPERATE trip (frame-27 story)..."
  python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --attack
  echo "Outstation log:"; grep "CONTROL" "$RUN/outstation.log" | tail -3
}

case "${1:-help}" in
  up)     _up ;;
  mqtt)   _mqtt ;;
  dnp3)   _dnp3 ;;
  status)
    for p in broker outstation; do
      if [ -f "$RUN/$p.pid" ] && kill -0 "$(cat "$RUN/$p.pid")" 2>/dev/null; then echo "$p: running (pid $(cat "$RUN/$p.pid"))"; else echo "$p: stopped"; fi
    done ;;
  down)
    for p in broker outstation; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null; rm -f "$RUN/$p.pid"; done
    pkill -f "mosquitto -c $LAB/mosquitto" 2>/dev/null; pkill -f "dnp3/outstation.py" 2>/dev/null
    echo "Stopped broker + outstation." ;;
  *) sed -n '2,20p' "$0" ;;
esac
