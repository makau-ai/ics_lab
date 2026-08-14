#!/usr/bin/env python3
"""
dnp3_link_spoof.py -- DNP3 "link address seen from more than one IP".

INVARIANT
    In a healthy DNP3 network each data-link address is owned by exactly one
    station, so a given dnp3.src (source link address) must always arrive from
    ONE ip.src. When the same link address is sourced from two or more IPs, one
    of them is forging that station's identity (a spoofed / rogue master).

WHY THIS AND NOT A SOURCE-IP RULE
    The DNP3 modules warn that "control must come from the master IP" survives
    the teaching capture only by luck. The link<->IP binding is the durable
    signal: it needs no allow-list of "good" IPs, it just asserts that identity
    is consistent. It fires the moment an attacker reuses a real station's link
    address from a new socket -- which is exactly what the substation capture's
    frame 27 does (link 100, normally 10.20.0.5, arrives from 10.20.0.66).

    (It is defeated only if the attacker ALSO spoofs the master's IP -- see
    RED_TEAM_EVASION.md, which is why we ship dnp3_select_operate.py too.)

USAGE
    ./dnp3_link_spoof.py <capture.pcap>
    exit 0 = clean, 1 = alert, 2 = usage/error
"""
import sys
import detect_common as dc


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: %s <capture.pcap>\n" % argv[0])
        return 2
    pcap = argv[1]

    dc.banner("DNP3 link-address / source-IP binding check",
              "each DNP3 link address (dnp3.src) is sourced from exactly one ip.src")

    rows = dc.tshark_fields(
        pcap,
        ["frame.number", "ip.src", "ip.dst", "tcp.stream",
         "dnp3.src", "dnp3.dst", "dnp3.al.func"],
        display_filter="dnp3.src",
        extra_opts=["-o", "dnp3.desegment:TRUE"],
    )

    # Map link address -> {ip -> [frames]}
    seen = {}          # link_src -> { ip_src -> [frame numbers] }
    for r in rows:
        link = r["dnp3.src"]
        ip = r["ip.src"]
        if not link:
            continue
        seen.setdefault(link, {}).setdefault(ip, []).append(r)

    alerts = 0
    for link, ipmap in sorted(seen.items(), key=lambda kv: int(kv[0])):
        if len(ipmap) <= 1:
            continue
        # The IP that sourced the FEWEST frames is the likely impostor, but we
        # report the full spread so the analyst decides. Establish baseline as
        # the earliest-seen IP for this link address.
        first_frame_by_ip = {ip: int(fr[0]["frame.number"]) for ip, fr in ipmap.items()}
        baseline_ip = min(first_frame_by_ip, key=first_frame_by_ip.get)
        print("\n[SPOOFED LINK ADDRESS] dnp3.src=%s seen from %d IPs:"
              % (link, len(ipmap)))
        for ip, frs in sorted(ipmap.items(), key=lambda kv: first_frame_by_ip[kv[0]]):
            tag = "baseline (first seen)" if ip == baseline_ip else "IMPOSTOR"
            frames = ", ".join(f["frame.number"] for f in frs)
            print("    ip.src=%-14s %-22s frames: %s" % (ip, tag, frames))
        for ip, frs in ipmap.items():
            if ip == baseline_ip:
                continue
            for f in frs:
                alerts += 1
                fn = dc.func_name(f["dnp3.al.func"]) if f["dnp3.al.func"] else "(no app layer)"
                print("    WHY frame=%s: link %s->%s spoofed from ip.src=%s "
                      "(owner is %s), app func=%s"
                      % (f["frame.number"], link, f["dnp3.dst"], ip,
                         baseline_ip, fn))

    return dc.verdict(alerts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
