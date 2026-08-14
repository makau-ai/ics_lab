#!/usr/bin/env python3
"""
dnp3_rogue_master.py -- DNP3 control from outside the known-master allow-set,
and off-baseline function codes.

TWO INVARIANTS (asset-inventory bound)
    1. ALLOW-SET: control-class requests (OPERATE / DIRECT_OPERATE(_NR)) must
       originate only from an IP in the known-master set. A control frame from
       any other source is a rogue master -- regardless of what link address it
       claims.
    2. BASELINE FUNCTION CODES: a steady-state polling master emits only
       CONFIRM/READ/SELECT/OPERATE (0,1,3,4). Anything else in a REQUEST
       (COLD_RESTART, WARM_RESTART, DIRECT_OPERATE, STOP_APPL, ...) is
       off-baseline and worth an alert on its own -- these are the "disruptive"
       function codes an attacker reaches for.

    Durable OT detection binds alerts to an asset inventory (NIST SP 800-82r3 /
    IEC 62443). The master allow-set is that inventory; pass your own with
    --masters, or edit the default below.

WHY NOT JUST "SOURCE IP != MASTER"
    A pure source-IP rule (invariant 1 alone) is evaded the instant the attacker
    spoofs the master's IP. Invariant 2 (off-baseline function code) still fires
    on the COLD_RESTART even then, because it keys on WHAT was asked, not WHO
    asked -- see RED_TEAM_EVASION.md.

USAGE
    ./dnp3_rogue_master.py <capture.pcap> [--masters 10.20.0.5,10.20.0.6]
    exit 0 = clean, 1 = alert, 2 = usage/error
"""
import sys
import detect_common as dc

# Default known-master allow-set for the shipped substation capture.
# The legitimate FEP/master polls from 10.20.0.5. Override with --masters.
DEFAULT_MASTERS = {"10.20.0.5"}


def main(argv):
    masters = set(DEFAULT_MASTERS)
    args = argv[1:]
    if "--masters" in args:
        i = args.index("--masters")
        try:
            masters = {ip.strip() for ip in args[i + 1].split(",") if ip.strip()}
        except IndexError:
            sys.stderr.write("--masters needs a comma-separated IP list\n")
            return 2
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("usage: %s <capture.pcap> [--masters ip1,ip2]\n" % argv[0])
        return 2
    pcap = args[0]

    dc.banner("DNP3 rogue-master / off-baseline-function check",
              "control comes only from masters %s; requests stay within baseline "
              "func codes {CONFIRM,READ,SELECT,OPERATE}" % sorted(masters))

    rows = dc.tshark_fields(
        pcap,
        ["frame.number", "ip.src", "dnp3.src", "dnp3.dst",
         "dnp3.al.func", "dnp3.ctl.prm"],
        display_filter="dnp3.al.func && dnp3.ctl.prm==1",  # requests only
        extra_opts=["-o", "dnp3.desegment:TRUE"],
    )

    alerts = 0
    for r in rows:
        f = r["dnp3.al.func"]
        if not f:
            continue
        try:
            func = int(f)
        except ValueError:
            continue
        ip = r["ip.src"]
        name = dc.func_name(func)

        # Invariant 1: control from outside the master allow-set.
        if func in dc.DNP3_CONTROL_FUNCS and ip not in masters:
            alerts += 1
            print("\n[ROGUE MASTER] frame=%s func=%s(%d)" % (r["frame.number"], name, func))
            print("    WHY frame=%s: control-class request from ip.src=%s, which is "
                  "NOT in the known-master set %s (claims link %s->%s)"
                  % (r["frame.number"], ip, sorted(masters), r["dnp3.src"], r["dnp3.dst"]))

        # Invariant 2: off-baseline function code (fires regardless of source).
        if func not in dc.DNP3_BASELINE_FUNCS:
            alerts += 1
            print("\n[OFF-BASELINE FUNCTION] frame=%s func=%s(%d)" % (r["frame.number"], name, func))
            print("    WHY frame=%s: %s is outside the steady-state baseline "
                  "{CONFIRM,READ,SELECT,OPERATE} (ip.src=%s, link %s->%s)"
                  % (r["frame.number"], name, ip, r["dnp3.src"], r["dnp3.dst"]))

    return dc.verdict(alerts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
