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
nohup wireshark "$@" >/tmp/wireshark.log 2>&1 &
echo "Wireshark launched on the noVNC desktop."
echo "  -> Open the forwarded port 6080 in your browser (password: vscode) to see it."
echo "  -> Live capture: double-click interface 'lo'. Filter: dnp3  or  mqtt"
