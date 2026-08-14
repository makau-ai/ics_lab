#!/usr/bin/env python3
"""
dnp3_select_operate.py -- DNP3 control without a preceding SELECT in-window.

INVARIANT
    DNP3 supervised control is a two-step handshake: SELECT (fc=3) arms a point,
    then OPERATE (fc=4) fires it, and the OPERATE must arrive within a short arm
    timeout on the SAME association/session. Two things violate this:
      * an OPERATE (fc=4) with no matching SELECT within the window, and
      * a DIRECT_OPERATE / DIRECT_OPERATE_NR (fc=5/6), which fires with NO select
        phase at all -- legitimate in some setups, but off-baseline where the
        operating policy is SELECT-before-OPERATE.

WHY THIS SURVIVES ADVERSARIAL REALITY
    This detector keys on the PROTOCOL GRAMMAR, not on identity. Even an attacker
    who perfectly spoofs the master's IP and link address still cannot inject an
    OPERATE that a real SELECT preceded -- their injected control lands in a new
    session / out of sequence with no arming SELECT. That is why, in
    RED_TEAM_EVASION.md, this rule keeps firing after the source-IP and even the
    link<->IP rules have been evaded.

    Association key = (dnp3.src -> dnp3.dst) on a given tcp.stream. The SELECT and
    the OPERATE must share the association AND the TCP session, because the
    arm-latch is per session.

USAGE
    ./dnp3_select_operate.py <capture.pcap> [--window SECONDS]
    default window = 10.0 s (typical DNP3 SELECT-arm timeout is a few seconds)
    exit 0 = clean, 1 = alert, 2 = usage/error
"""
import sys
import detect_common as dc


def main(argv):
    window = 10.0
    args = argv[1:]
    if "--window" in args:
        i = args.index("--window")
        try:
            window = float(args[i + 1])
        except (IndexError, ValueError):
            sys.stderr.write("--window needs a numeric SECONDS value\n")
            return 2
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("usage: %s <capture.pcap> [--window SECONDS]\n" % argv[0])
        return 2
    pcap = args[0]

    dc.banner("DNP3 SELECT-before-OPERATE check",
              "every OPERATE has a SELECT on the same session within %.1fs; "
              "DIRECT_OPERATE has no SELECT phase and is off-baseline" % window)

    rows = dc.tshark_fields(
        pcap,
        ["frame.number", "frame.time_epoch", "ip.src", "tcp.stream",
         "dnp3.src", "dnp3.dst", "dnp3.al.func"],
        display_filter="dnp3.al.func",
        extra_opts=["-o", "dnp3.desegment:TRUE"],
    )

    # Record the most recent SELECT per (stream, master_link, outstation_link).
    last_select = {}   # key -> (epoch, frame)
    alerts = 0

    for r in rows:
        func = r["dnp3.al.func"]
        if not func:
            continue
        try:
            func = int(func)
            t = float(r["frame.time_epoch"])
        except ValueError:
            continue
        key = (r["tcp.stream"], r["dnp3.src"], r["dnp3.dst"])

        if func == dc.DNP3_SELECT_FUNC:
            last_select[key] = (t, r["frame.number"])
            continue

        if func in dc.DNP3_DIRECT_FUNCS:
            alerts += 1
            print("\n[CONTROL WITHOUT SELECT] frame=%s func=%s(%d)"
                  % (r["frame.number"], dc.func_name(func), func))
            print("    WHY frame=%s: %s fires the point with NO SELECT handshake "
                  "(ip.src=%s, link %s->%s). Off-baseline for a SELECT/OPERATE plant."
                  % (r["frame.number"], dc.func_name(func), r["ip.src"],
                     r["dnp3.src"], r["dnp3.dst"]))
            continue

        if func == 4:  # OPERATE -- must have an in-window SELECT on this key
            prior = last_select.get(key)
            if prior is None or (t - prior[0]) > window or (t - prior[0]) < 0:
                alerts += 1
                if prior is None:
                    reason = "no SELECT ever seen on this association/session"
                else:
                    reason = ("nearest SELECT (frame=%s) was %.2fs earlier, "
                              "outside the %.1fs arm window"
                              % (prior[1], t - prior[0], window))
                print("\n[OPERATE WITHOUT SELECT] frame=%s func=OPERATE(4)"
                      % r["frame.number"])
                print("    WHY frame=%s: %s (ip.src=%s, link %s->%s)"
                      % (r["frame.number"], reason, r["ip.src"],
                         r["dnp3.src"], r["dnp3.dst"]))
            # else: legitimate SELECT->OPERATE pair, no alert

    return dc.verdict(alerts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
