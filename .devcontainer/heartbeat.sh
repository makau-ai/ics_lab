#!/usr/bin/env bash
# Generates ongoing lab traffic so Wireshark always has DNP3 *and* MQTT to show.
#
# Key fix: the steady DNP3 poll loop is started FIRST and in the BACKGROUND, and
# every poll is wrapped in `timeout`, so it can never be blocked or delayed by the
# one-time intrusion demo. (Previously the recurring poll sat *after* the demo, so
# if the demo's MQTT attacker step stalled, DNP3 traffic never started.)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"
RUN="/tmp/icslab"; mkdir -p "$RUN"

sleep 8   # let the broker (1883) and outstation (20000) finish binding

# --- STEADY DNP3 POLL LOOP (independent + guarded; DNP3 hits the wire every ~12s) ---
(
  while true; do
    timeout 8 python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --close >>"$RUN/dnp3-poll.log" 2>&1 || true
    sleep 12
  done
) &
echo "[heartbeat] steady DNP3 poll loop started (every ~12s)"

# --- ONE-TIME INTRUSION DEMO (runs after; timeout-guarded so it can't wedge anything) ---
sleep 6
echo "[heartbeat] == startup demo: DNP3 supervised close =="
timeout 10 python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --close >>"$RUN/demo.log" 2>&1 || true
echo "[heartbeat] == startup demo: MQTT anonymous eavesdrop + command injection =="
timeout 15 bash -c "BROKER=localhost python3 '$LAB/mqtt/attacker.py'" >>"$RUN/demo.log" 2>&1 || true
echo "[heartbeat] == startup demo: DNP3 unauthenticated trip (frame-27 story) =="
timeout 10 python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --attack >>"$RUN/demo.log" 2>&1 || true
echo "[heartbeat] startup demo complete — steady DNP3 poll continues in the background."
