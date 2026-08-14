#!/usr/bin/env bash
# run_selftest.sh -- exercise every detector in lab/detect/ against the shipped
# teaching captures and the benign-only slices, and assert the expected verdicts.
#
#   attack captures  -> each detector MUST alert (exit 1) and flag the known frame
#   benign slices    -> each detector MUST be clean (exit 0)
#   evasion fixture  -> naive rule MISSES; grammar/off-baseline invariants SURVIVE
#
# Exits 0 iff every expectation held.
set -u
cd "$(dirname "$0")"

PCAPS="../../pcaps"
S="samples"
fail=0

expect() {   # expect <wanted_exit> <label> <cmd...>
    local want="$1"; local label="$2"; shift 2
    "$@" >/dev/null 2>&1; local got=$?
    if [ "$got" = "$want" ]; then
        echo "  PASS  ($got) $label"
    else
        echo "  FAIL  (got $got, want $want) $label"; fail=1
    fi
}

# regenerate the evasion fixture if scapy is present (idempotent)
[ -f "$S/dnp3_master_ip_spoof.pcap" ] || python3 make_evasion_pcap.py >/dev/null 2>&1

echo "== attack captures: detectors MUST alert =="
expect 1 "dnp3_link_spoof / substation"      python3 dnp3_link_spoof.py     "$PCAPS/dnp3_substation.pcap"
expect 1 "dnp3_select_operate / substation"  python3 dnp3_select_operate.py "$PCAPS/dnp3_substation.pcap"
expect 1 "dnp3_rogue_master / substation"    python3 dnp3_rogue_master.py   "$PCAPS/dnp3_substation.pcap"
expect 1 "mqtt_abuse / iot_telemetry"        python3 mqtt_abuse.py          "$PCAPS/mqtt_iot_telemetry.pcap"

echo "== benign-only slices: detectors MUST be clean =="
expect 0 "dnp3_link_spoof / benign"      python3 dnp3_link_spoof.py     "$S/dnp3_benign.pcap"
expect 0 "dnp3_select_operate / benign"  python3 dnp3_select_operate.py "$S/dnp3_benign.pcap"
expect 0 "dnp3_rogue_master / benign"    python3 dnp3_rogue_master.py   "$S/dnp3_benign.pcap"
expect 0 "mqtt_abuse / benign"           python3 mqtt_abuse.py          "$S/mqtt_benign.pcap"

echo "== red-team evasion: master-IP-spoof fixture =="
expect 0 "naive_ip_rule MISSES evasion"        python3 naive_ip_rule.py      "$S/dnp3_master_ip_spoof.pcap"
expect 0 "link<->IP read MISSES evasion"       python3 dnp3_link_spoof.py    "$S/dnp3_master_ip_spoof.pcap"
expect 1 "off-baseline-func SURVIVES evasion"  python3 dnp3_rogue_master.py  "$S/dnp3_master_ip_spoof.pcap"
expect 1 "SELECT-before-OPERATE SURVIVES"      python3 dnp3_select_operate.py "$S/dnp3_master_ip_spoof.pcap"

echo
if [ "$fail" = 0 ]; then echo "SELF-TEST: ALL PASS"; else echo "SELF-TEST: FAILURES ABOVE"; fi
exit $fail
