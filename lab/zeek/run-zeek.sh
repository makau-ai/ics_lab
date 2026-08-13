#!/usr/bin/env bash
# Parse a capture with Zeek + CISA ICSNPP (DNP3) and the built-in MQTT analyzer.
#   run-zeek <pcap> [output-dir]
set -e
PCAP="${1:?usage: run-zeek <pcap> [outdir]}"
OUT="${2:-./zeek_out}"
mkdir -p "$OUT"; cd "$OUT"
echo "[run-zeek] parsing $PCAP ..."
zeek -C -r "$PCAP" icsnpp-dnp3
echo "[run-zeek] logs in $(pwd):"
ls -1 ./*.log 2>/dev/null
echo
echo "Tip: DNP3 controls ->  cat dnp3_control.log | zeek-cut -C ts id.orig_h function_code operation_type"
echo "     MQTT connects ->  cat mqtt_connect.log | zeek-cut -C ts id.orig_h client_id connect_status"
