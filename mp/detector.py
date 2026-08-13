#!/usr/bin/env python3
"""
detector.py — Part 2 of the MP.  ***YOU implement this.***

Usage:
    python3 detector.py <capture.pcap>

Print exactly one line per malicious frame you detect, in this form:
    ALERT frame=<n> reason=<short reason>

The autograder (grade.py) runs your detector on captures/dnp3_assessment.pcap and
captures/mqtt_assessment.pcap and checks that you flag the malicious frame in each.

Detect by INVARIANT, not by hard-coding frame numbers or IPs:
  * DNP3 : a data-link SOURCE address (dnp3.src) that appears from more than one
           ip.src is impersonation — flag the frame from the unexpected IP.
  * MQTT : a client that CONNECTed with no username (mqtt.username empty) and then
           PUBLISHed a RETAINED message (mqtt.retain == True) to a command topic is
           a persistent unauthorized command.

Hint — shell out to tshark with -T fields, e.g.:
    tshark -r <pcap> -Y dnp3 -T fields -e frame.number -e ip.src -e dnp3.src
    tshark -r <pcap> -Y mqtt -T fields -e frame.number -e ip.src -e mqtt.msgtype \
                                       -e mqtt.username -e mqtt.topic -e mqtt.retain
    (note: mqtt.retain prints True/False, not 1/0)
"""
import sys
import subprocess  # noqa: F401  (you'll likely want this)


def main():
    if len(sys.argv) != 2:
        print("usage: python3 detector.py <capture.pcap>", file=sys.stderr)
        sys.exit(2)
    pcap = sys.argv[1]

    # TODO: read the capture with tshark and print `ALERT frame=<n> reason=...`
    #       for each malicious frame, using the invariants described above.
    _ = pcap


if __name__ == "__main__":
    main()
