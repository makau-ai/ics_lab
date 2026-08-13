#!/usr/bin/env bash
# Wait for the desktop-lite X display (:1) to come up, then launch Wireshark
# already capturing on 'lo'. If the display never appears (e.g. desktop-lite
# still starting), the student can run ./lab/open-wireshark.sh manually.
export DISPLAY=:1
for _ in $(seq 1 90); do
  if xdpyinfo -display :1 >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
xdpyinfo -display :1 >/dev/null 2>&1 || { echo "X display :1 not ready — skipping auto-launch"; exit 0; }

pkill -f "wireshark" 2>/dev/null || true
sleep 1
# -i lo: capture on loopback (all localhost lab traffic)
# -k    : start capturing immediately
# -f    : capture filter (only the lab ports)   -Y : display filter (dnp3 or mqtt)
nohup wireshark -i lo -k \
  -f "tcp port 1883 or tcp port 20000" \
  -Y "dnp3 || mqtt" >/tmp/wireshark.log 2>&1 &
echo "Wireshark launched on :1, capturing on lo."
