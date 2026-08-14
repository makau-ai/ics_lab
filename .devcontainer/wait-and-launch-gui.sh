#!/usr/bin/env bash
# Bring up the noVNC desktop's two moving parts, in order:
#   1. the CLIPBOARD BRIDGE (autocutsel) — so you can paste into Wireshark/xterm
#   2. Wireshark on 'lo', already capturing and PRE-FILTERED to the lab ports.
#
# The capture filter is essential: on the noVNC desktop, loopback also carries the
# desktop's own VNC video (tens of thousands of packets), which would otherwise bury
# the lab's DNP3/MQTT traffic.
#
# Idempotent + robust: safe to call from postStart AND postAttach — every step
# no-ops if it is already done, and it waits for the X display to appear first.
export DISPLAY=:1
FILT="tcp port 1883 or tcp port 20000"

# --- Wait (up to ~4 min) for the desktop-lite X display to come up. -----------------
# Done FIRST so the clipboard bridge below is ensured even when Wireshark is already up.
for _ in $(seq 1 120); do
  xdpyinfo -display :1 >/dev/null 2>&1 && break
  sleep 2
done
if ! xdpyinfo -display :1 >/dev/null 2>&1; then
  echo "X display :1 not ready yet — once the 6080 desktop is up, run:  ./lab/open-wireshark.sh"
  exit 0
fi

# --- 1. CLIPBOARD BRIDGE ------------------------------------------------------------
# desktop-lite ships TigerVNC + noVNC 1.6.0 but no selection bridge, so text put on
# the noVNC clipboard never reaches the X selections that Wireshark (CLIPBOARD, via
# Ctrl+V) and xterm (PRIMARY, via middle-click / Shift+Insert) actually paste from.
# autocutsel bridges them — one daemon per selection. Guarded so re-runs never
# spawn duplicates. Verify from a terminal with:  DISPLAY=:1 xclip -selection clipboard -o
if command -v autocutsel >/dev/null 2>&1; then
  pgrep -f "autocutsel -fork"              >/dev/null 2>&1 || autocutsel -fork
  pgrep -f "autocutsel -selection PRIMARY" >/dev/null 2>&1 || autocutsel -selection PRIMARY -fork
  echo "Clipboard bridge up on :1 — noVNC clipboard synced to X CLIPBOARD + PRIMARY."
else
  echo "autocutsel not installed — clipboard paste into the noVNC desktop will be limited."
fi

# --- 2. WIRESHARK -------------------------------------------------------------------
# Already running our filtered capture? Then the GUI is up — nothing more to do.
if pgrep -f "wireshark.*1883" >/dev/null 2>&1; then
  echo "Filtered Wireshark already running — nothing to do."
  exit 0
fi

# -i lo : capture loopback (all localhost lab traffic)
# -k    : start capturing immediately
# -f    : CAPTURE filter — only the lab ports (drops the noVNC/VNC noise)
# -Y    : display filter — DNP3 or MQTT
nohup wireshark -i lo -k -f "$FILT" -Y "dnp3 || mqtt" >/tmp/wireshark.log 2>&1 &
echo "Wireshark launched on :1 — capturing lo, pre-filtered to DNP3/MQTT."
