#!/usr/bin/env python3
"""
detector.py  (REFERENCE SOLUTION — instructors only; do not ship to students)

Part 2 of the MP: a deterministic detector that flags the malicious frame(s) in a
capture using invariants, not hard-coded IPs. Usage:

    python3 detector.py <capture.pcap>

Prints one line per detection:
    ALERT frame=<n> reason=<...>

Invariants used:
  DNP3  — a data-link SOURCE address that appears from more than one IP is
          impersonation; flag frames where a link address arrives from a
          minority (unexpected) source IP.  (Catches the spoofed UNSOLICITED
          RESPONSE: link 10 from 10.30.0.66 while the real outstation is .20.)
  MQTT  — a client that CONNECTed anonymously (no username) and then PUBLISHed a
          RETAINED message to a command topic is an unauthorized, persistent
          command injection.  (Catches the anonymous CONNECT and the retained
          command PUBLISH.)
"""
import sys
import subprocess
from collections import defaultdict, Counter


def fields(pcap, flds, dfilter=None):
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in flds:
        cmd += ["-e", f]
    if dfilter:
        cmd += ["-Y", dfilter]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(flds) - len(parts))
        rows.append(parts)
    return rows


def detect_dnp3(pcap):
    rows = fields(pcap, ["frame.number", "ip.src", "dnp3.src", "dnp3.al.func"], "dnp3")
    link_ips = defaultdict(Counter)
    for fn, ip, link, func in rows:
        if link:
            link_ips[link][ip] += 1
    for fn, ip, link, func in rows:
        if not link:
            continue
        ips = link_ips[link]
        if len(ips) > 1:
            major = ips.most_common(1)[0][0]
            if ip != major:
                print(f"ALERT frame={fn} reason=DNP3 link address {link} from unexpected source {ip} "
                      f"(that link address is otherwise used only from {major})")


def detect_mqtt(pcap):
    rows = fields(pcap, ["frame.number", "ip.src", "mqtt.msgtype", "mqtt.username",
                         "mqtt.topic", "mqtt.retain"], "mqtt")
    anon_ips = set()
    for fn, ip, mt, user, topic, retain in rows:
        if mt == "1" and not user:
            anon_ips.add(ip)
            print(f"ALERT frame={fn} reason=MQTT anonymous CONNECT from {ip} (no username)")
    for fn, ip, mt, user, topic, retain in rows:
        if mt == "3" and str(retain).lower() in ("1", "true") and "command" in (topic or "") and ip in anon_ips:
            print(f"ALERT frame={fn} reason=MQTT retained PUBLISH to command topic '{topic}' "
                  f"from anonymous client {ip} (persistent unauthorized command)")


def main():
    if len(sys.argv) != 2:
        print("usage: python3 detector.py <capture.pcap>", file=sys.stderr)
        sys.exit(2)
    pcap = sys.argv[1]
    detect_dnp3(pcap)
    detect_mqtt(pcap)


if __name__ == "__main__":
    main()
