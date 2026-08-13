#!/usr/bin/env bash
# =============================================================================
# autostart.sh — runs on every Codespace start (devcontainer postStartCommand).
# Brings the whole lab up automatically and returns fast (slow parts are
# backgrounded), so the student opens the Codespace and everything is live:
#   - MQTT broker + DNP3 outstation
#   - continuous MQTT telemetry (sensor), HMI subscriber, pump-controller actuator
#   - Wireshark on the noVNC desktop, already capturing on 'lo'
#   - a traffic heartbeat (periodic DNP3 poll + a one-time intrusion demo)
# =============================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LAB="$ROOT/lab"
RUN="/tmp/icslab"; mkdir -p "$RUN"

# --- clean any previous run (idempotent across restarts) ---
pkill -f "mosquitto -c $LAB/mosquitto" 2>/dev/null || true
pkill -f "dnp3/outstation.py"          2>/dev/null || true
pkill -f "mqtt/publisher.py"           2>/dev/null || true
pkill -f "mqtt/subscriber.py"          2>/dev/null || true
pkill -f "mqtt/pump-controller.py"     2>/dev/null || true
pkill -f "heartbeat.sh"                2>/dev/null || true
pkill -f "http.server 8080"            2>/dev/null || true
sleep 1

# --- Learning Path web hub: serve the kit over HTTP so the interactive levels
#     (curriculum/index.html) auto-open as the Codespace front door on port 8080 ---
( cd "$ROOT" && nohup python3 -m http.server 8080 >"$RUN/webhub.log" 2>&1 & echo $! >"$RUN/webhub.pid" )

# --- core services ---
nohup mosquitto -c "$LAB/mosquitto/mosquitto.insecure.conf" >"$RUN/broker.log" 2>&1 &
echo $! >"$RUN/broker.pid"
nohup python3 "$LAB/dnp3/outstation.py" >"$RUN/outstation.log" 2>&1 &
echo $! >"$RUN/outstation.pid"
sleep 1

# --- steady MQTT: HMI subscriber + actuator + continuously-publishing sensor ---
BROKER=localhost nohup python3 "$LAB/mqtt/subscriber.py"       >"$RUN/sub.log"  2>&1 &
BROKER=localhost nohup python3 "$LAB/mqtt/pump-controller.py"  >"$RUN/pump.log" 2>&1 &
BROKER=localhost nohup python3 "$LAB/mqtt/publisher.py"        >"$RUN/pub.log"  2>&1 &

# --- backgrounded: wait for the noVNC X display, then launch Wireshark on lo ---
nohup bash "$HERE/wait-and-launch-gui.sh"  >"$RUN/gui.log"       2>&1 &

# --- backgrounded: startup intrusion demo + periodic DNP3 poll ---
nohup bash "$HERE/heartbeat.sh"            >"$RUN/heartbeat.log" 2>&1 &

echo "[autostart] Lab is live: broker(1883) + outstation(20000) + steady MQTT telemetry."
echo "[autostart] Learning Path front door: http://localhost:8080/  (auto-opens; start at Level 0)."
echo "[autostart] Wireshark will open on the noVNC desktop (port 6080) and capture on 'lo'."
exit 0
