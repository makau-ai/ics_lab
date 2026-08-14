#!/usr/bin/env python3
"""
make_evasion_pcap.py -- build the RED-TEAM EVASION fixture.

Takes the shipped DNP3 substation capture and produces a variant in which the
attacker ALSO spoofs the master's source IP: every packet the rogue host
(10.20.0.66) sent is rewritten to appear to come from the real master
(10.20.0.5), and the outstation's replies are re-addressed to match. The
attacker's control frames keep their own distinct TCP session (src port 40666)
-- a blind/offset injection, NOT part of the master's real polling session.

Result: dnp3_master_ip_spoof.pcap, in which
  * ip.src of the injected control == the master's IP (defeats source-IP rules),
  * dnp3.src link 100 now appears from ONLY one IP (defeats the naive
    "one IP per link address" reading), yet
  * the injected DIRECT_OPERATE / COLD_RESTART still have NO SELECT handshake in
    their session -> the SELECT-before-OPERATE + off-baseline-func invariants
    survive.

This is the ONLY script in lab/detect/ that uses scapy; the detectors do not.
Run once to (re)generate the fixture:
    ./make_evasion_pcap.py
"""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "pcaps", "dnp3_substation.pcap")
OUT = os.path.join(os.path.dirname(__file__), "samples", "dnp3_master_ip_spoof.pcap")

ROGUE = "10.20.0.66"
MASTER = "10.20.0.5"


def main():
    try:
        from scapy.all import rdpcap, wrpcap, IP, TCP
    except Exception as exc:  # pragma: no cover
        sys.stderr.write("ERROR: scapy required to build the fixture: %s\n" % exc)
        return 2

    pkts = rdpcap(SRC)
    n = 0
    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        touched = False
        if ip.src == ROGUE:
            ip.src = MASTER
            touched = True
        if ip.dst == ROGUE:
            ip.dst = MASTER
            touched = True
        if touched:
            n += 1
            # Force checksum recomputation on write.
            del ip.len
            del ip.chksum
            if p.haslayer(TCP):
                del p[TCP].chksum
    wrpcap(OUT, pkts)
    print("rewrote %d packets (%s -> %s); wrote %s" % (n, ROGUE, MASTER, OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
