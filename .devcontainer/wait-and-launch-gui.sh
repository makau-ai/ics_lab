#!/usr/bin/env bash
# Launch Wireshark on the desktop-lite X display (:1), already capturing on 'lo'
# and PRE-FILTERED to the lab ports. The capture filter is essential: on the noVNC
# desktop, loopback carries the desktop's own VNC video (tens of thousands of
# packets), which would otherwise bury the lab's DNP3/MQTT traffic.
#
# Idempotent + robust: safe to call from postStart AND postAttach — it no-ops if
# our filtered capture is already running, and waits for the X display to appear.
export DISPLAY=:1
FILT="tcp port 1883 or tcp port 20000"

# Already running our filtered capture? Nothing to do.
if pgrep -f "wireshark.*1883" >/dev/null 2>&1; then
  echo "Filtered Wireshark already running — nothing to do."
  exit 0
fi

# Wait (up to ~4 min) for the desktop-lite X display to come up.
for _ in $(seq 1 120); do
  xdpyinfo -display :1 >/dev/null 2>&1 && break
  sleep 2
done
if ! xdpyinfo -display :1 >/dev/null 2>&1; then
  echo "X display :1 not ready yet — once the 6080 desktop is up, run:  ./lab/open-wireshark.sh"
  exit 0
fi

# -i lo : capture loopback (all localhost lab traffic)
# -k    : start capturing immediately
# -f    : CAPTURE filter — only the lab ports (drops the noVNC/VNC noise)
# -Y    : display filter — DNP3 or MQTT
nohup wireshark -i lo -k -f "$FILT" -Y "dnp3 || mqtt" >/tmp/wireshark.log 2>&1 &
echo "Wireshark launched on :1 — capturing lo, pre-filtered to DNP3/MQTT."
