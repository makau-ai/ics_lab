#!/usr/bin/env bash
# Fetch real, APPROVED-SOURCE captures into pcaps/real/. Attribution: pcaps/real/NOTICE.md
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/pcaps/real"; mkdir -p "$DEST"

echo "== DNP3  —  CISA (US CISA / INL), BSD-3-Clause =="
if [ -f "$DEST/dnp3_cisa_example.pcap" ]; then
  echo "  present: pcaps/real/dnp3_cisa_example.pcap"
else
  tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/cisagov/icsnpp-dnp3 "$tmp/x" >/dev/null 2>&1; then
    cp "$tmp/x/testing/traces/dnp3_example.pcap" "$DEST/dnp3_cisa_example.pcap" 2>/dev/null \
      && cp "$tmp/x/LICENSE.txt" "$DEST/DNP3_CISA_LICENSE.txt" 2>/dev/null \
      && echo "  fetched: pcaps/real/dnp3_cisa_example.pcap"
  else
    echo "  (offline) get testing/traces/dnp3_example.pcap from https://github.com/cisagov/icsnpp-dnp3"
  fi
  rm -rf "$tmp"
fi

echo ""
echo "== MQTT  —  CICIoMT2024, Canadian Institute for Cybersecurity (UNB) — approved source =="
echo "  Terms permit redistribution WITH the required citation (see pcaps/real/NOTICE.md)."
echo "  Open-download portal — grab the Wi-Fi/MQTT benign + attack .pcap files"
echo "  (Connect Flood / Publish Flood / Malformed Data) into pcaps/real/:"
echo "      https://www.unb.ca/cic/datasets/iomt-dataset-2024.html"
echo "      http://cicresearch.ca/IOTDataset/CICIoMT2024/"
echo "  Not auto-downloaded: the dataset archives are multi-GB — take only the MQTT pcaps you need."
echo ""
echo "Analyze, e.g.:  tshark -r pcaps/real/<file>.pcap -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c"
