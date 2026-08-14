#!/usr/bin/env python3
"""
mqtt_abuse.py -- MQTT broker-abuse invariants:
  (A) anonymous CONNECT (no username flag),
  (B) wildcard SUBSCRIBE to '#' (or a top-level '+'), and
  (C) PUBLISH to a command topic from a non-controller.

INVARIANTS
    A. Every station on this plant broker authenticates: a CONNECT (msgtype=1)
       must set the User Name flag. A CONNECT with no username is anonymous and
       forbidden on an operational broker.
    B. Operational subscribers name their topics. A SUBSCRIBE (msgtype=8) whose
       filter is '#' (everything) or a bare '+' is a firehose eavesdrop, not a
       point subscription.
    C. Only a known controller may PUBLISH to a command topic. A PUBLISH
       (msgtype=3) to a topic matching the command pattern from an ip.src outside
       the controller allow-set is an unauthorized actuation.

WHY NOT THE NAIVE DISCRIMINATORS
    The MQTT module kills "flag anonymous by empty Will fields" and "flag the '#'
    string" as brittle: a smarter attacker sets a Will or subscribes to a broad
    but non-'#' filter. These three invariants are the durable core -- identity
    (A), scope (B), and authorization-of-actuation (C). C in particular does not
    care what the client id or Will looks like; it binds WHO may command WHAT.

USAGE
    ./mqtt_abuse.py <capture.pcap>
        [--controllers 10.10.20.20,...] [--command-re 'command|cmd|ctrl|setpoint']
    exit 0 = clean, 1 = alert, 2 = usage/error
"""
import re
import sys
import detect_common as dc

# Known controllers permitted to PUBLISH to command topics. In the shipped
# telemetry capture no legitimate device commands (the sensor only publishes
# telemetry, the HMI only subscribes), so the allow-set is empty by default:
# any PUBLISH to a command topic is unauthorized. Override with --controllers.
DEFAULT_CONTROLLERS = set()
DEFAULT_COMMAND_RE = r"command|/cmd|ctrl|setpoint|/set$|/set/"


def main(argv):
    controllers = set(DEFAULT_CONTROLLERS)
    command_re = DEFAULT_COMMAND_RE
    args = argv[1:]
    if "--controllers" in args:
        i = args.index("--controllers")
        controllers = {ip.strip() for ip in args[i + 1].split(",") if ip.strip()}
        del args[i:i + 2]
    if "--command-re" in args:
        i = args.index("--command-re")
        command_re = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("usage: %s <capture.pcap> [--controllers ip1,ip2] "
                         "[--command-re REGEX]\n" % argv[0])
        return 2
    pcap = args[0]
    cmd_pat = re.compile(command_re, re.IGNORECASE)

    dc.banner("MQTT broker-abuse check",
              "CONNECT authenticates; SUBSCRIBE is scoped (no '#'); command "
              "PUBLISH only from controllers %s" % (sorted(controllers) or "<none>"))

    rows = dc.tshark_fields(
        pcap,
        ["frame.number", "ip.src", "mqtt.msgtype", "mqtt.clientid",
         "mqtt.conflag.uname", "mqtt.topic", "mqtt.retain"],
        display_filter="mqtt",
    )

    alerts = 0
    for r in rows:
        mt = r["mqtt.msgtype"]
        if not mt:
            continue
        try:
            mt = int(mt)
        except ValueError:
            continue
        ip = r["ip.src"]

        # (A) anonymous CONNECT
        if mt == dc.MQTT_CONNECT:
            uname_flag = r["mqtt.conflag.uname"]
            authed = str(uname_flag).lower() in ("1", "true")
            if not authed:
                alerts += 1
                print("\n[ANONYMOUS CONNECT] frame=%s clientid=%r"
                      % (r["frame.number"], r["mqtt.clientid"]))
                print("    WHY frame=%s: CONNECT from ip.src=%s carries NO User "
                      "Name flag -- unauthenticated session on an operational broker."
                      % (r["frame.number"], ip))

        # (B) wildcard SUBSCRIBE
        elif mt == dc.MQTT_SUBSCRIBE:
            topic = r["mqtt.topic"] or ""
            if topic == "#" or topic == "+" or topic.endswith("/#") or topic == "":
                # topic=='' can indicate a multi-topic subscribe row; still a hit
                # only when the wildcard is truly '#'. Guard on the '#' presence.
                if "#" in topic or topic in ("+",):
                    alerts += 1
                    print("\n[WILDCARD SUBSCRIBE] frame=%s topic=%r"
                          % (r["frame.number"], topic))
                    print("    WHY frame=%s: ip.src=%s subscribed to the wildcard "
                          "'%s' -- firehose eavesdrop across every topic, not a "
                          "scoped subscription." % (r["frame.number"], ip, topic))

        # (C) command PUBLISH from a non-controller
        elif mt == dc.MQTT_PUBLISH:
            topic = r["mqtt.topic"] or ""
            if topic and cmd_pat.search(topic) and ip not in controllers:
                alerts += 1
                print("\n[UNAUTHORIZED COMMAND PUBLISH] frame=%s topic=%r"
                      % (r["frame.number"], topic))
                print("    WHY frame=%s: PUBLISH to command topic '%s' from "
                      "ip.src=%s, which is NOT in the controller allow-set %s -- "
                      "an unauthorized actuation."
                      % (r["frame.number"], topic, ip, sorted(controllers) or "<none>"))

    return dc.verdict(alerts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
