#!/usr/bin/env python3
"""
naive_ip_rule.py -- the NAIVE rule the modules warn about, shipped so students
can watch it fail.

RULE (deliberately brittle)
    "DNP3 control is legitimate as long as it comes from the known master IP."
    Alert on any control-class request (OPERATE/DIRECT_OPERATE) whose ip.src is
    not the master IP. That's it -- identity by source IP alone.

This is exactly the discriminator dnp3_module.md says "survives this capture only
by luck." It catches the plain rogue-master capture (attacker at 10.20.0.66) but
MISSES the master-IP-spoof variant (samples/dnp3_master_ip_spoof.pcap), where the
attacker sends control from the master's own IP. Run it against both, then run
the invariant detectors, and see RED_TEAM_EVASION.md.

USAGE
    ./naive_ip_rule.py <capture.pcap> [--master 10.20.0.5]
    exit 0 = clean, 1 = alert, 2 = usage/error
"""
import sys
import detect_common as dc

DEFAULT_MASTER = "10.20.0.5"


def main(argv):
    master = DEFAULT_MASTER
    args = argv[1:]
    if "--master" in args:
        i = args.index("--master")
        master = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("usage: %s <capture.pcap> [--master IP]\n" % argv[0])
        return 2
    pcap = args[0]

    dc.banner("NAIVE source-IP control rule (intentionally brittle)",
              "control is OK iff ip.src == master %s" % master)

    rows = dc.tshark_fields(
        pcap,
        ["frame.number", "ip.src", "dnp3.al.func"],
        display_filter="dnp3.al.func && dnp3.ctl.prm==1",
        extra_opts=["-o", "dnp3.desegment:TRUE"],
    )

    alerts = 0
    for r in rows:
        f = r["dnp3.al.func"]
        try:
            func = int(f)
        except (TypeError, ValueError):
            continue
        if func in dc.DNP3_CONTROL_FUNCS and r["ip.src"] != master:
            alerts += 1
            print("\n[NAIVE ALERT] frame=%s func=%s from ip.src=%s (!= master %s)"
                  % (r["frame.number"], dc.func_name(func), r["ip.src"], master))

    if not alerts:
        print("\n(no control seen from a non-master IP -- naive rule is satisfied)")
    return dc.verdict(alerts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
