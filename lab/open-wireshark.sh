#!/usr/bin/env bash
# Launch the Wireshark GUI on the noVNC desktop (DISPLAY :1).
#   ./lab/open-wireshark.sh                         # empty Wireshark — Capture ▸ lo
#   ./lab/open-wireshark.sh pcaps/dnp3_substation.pcap   # open a capture
export DISPLAY="${DISPLAY:-:1}"
if ! command -v wireshark >/dev/null 2>&1; then
  echo "Wireshark isn't installed here. Are you inside the Codespaces devcontainer?"
  echo "For headless analysis use tshark, e.g.:  tshark -r pcaps/dnp3_substation.pcap -Y dnp3"
  exit 1
fi
if [ "$#" -eq 0 ]; then
  # No file given → live capture on lo, PRE-FILTERED to the lab ports so the
  # noVNC desktop's own VNC traffic on loopback doesn't bury the lab packets.
  nohup wireshark -i lo -k -f "tcp port 1883 or tcp port 20000" -Y "dnp3 || mqtt" \
    >/tmp/wireshark.log 2>&1 &
  echo "Wireshark launched — live capture on 'lo', pre-filtered to DNP3/MQTT."
else
  nohup wireshark "$@" >/tmp/wireshark.log 2>&1 &
  echo "Wireshark launched on the noVNC desktop."
fi
echo "  -> Open the forwarded port 6080 in your browser (password: vscode) to see it."
echo "  -> If you ever capture unfiltered, just type  mqtt or dnp3  in the filter bar."
