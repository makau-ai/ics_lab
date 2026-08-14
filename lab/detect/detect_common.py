#!/usr/bin/env python3
"""
detect_common.py -- shared, dependency-light helpers for the invariant detectors
in lab/detect/.

Design rules (mirrors the modules' "detection under adversarial reality"):
  * Everything here is stdlib + the `tshark` binary. No scapy, no pip installs,
    for the detectors themselves. (The red-team evasion pcap builder uses scapy,
    but the detectors do not.)
  * Detectors key on a PROTOCOL INVARIANT, never on a hard-coded frame number.
  * Field extraction goes through `tshark -T fields` so the same code reads any
    capture, not just the shipped teaching pcaps.

Exit-code convention used by every detector:
    0  -> clean: the invariant held, no alert
    1  -> alert: at least one frame violated the invariant
    2  -> usage / environment error (e.g. tshark missing, unreadable pcap)
"""
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# DNP3 application-layer function codes (subset we reason about).
# Source: IEEE 1815 (DNP3) application function codes.
# ---------------------------------------------------------------------------
DNP3_FUNC = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    18: "STOP_APPL",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
}

# Control-class requests that actuate the outstation. A control frame from an
# unexpected source, or without the SELECT handshake, is the whole game.
DNP3_CONTROL_FUNCS = {4, 5, 6}          # OPERATE / DIRECT_OPERATE / DIRECT_OPERATE_NR
DNP3_SELECT_FUNC = 3                    # SELECT arms; OPERATE within window fires
DNP3_DIRECT_FUNCS = {5, 6}             # DIRECT_OPERATE(_NR): fire with NO select phase
# "Off-baseline" == outside what a normal polling master emits in steady state.
# The teaching master only ever sends CONFIRM/READ/SELECT/OPERATE (0,1,3,4).
DNP3_BASELINE_FUNCS = {0, 1, 3, 4, 129, 130}

# MQTT control packet types.
MQTT_CONNECT = 1
MQTT_PUBLISH = 3
MQTT_SUBSCRIBE = 8


def func_name(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "?"
    return DNP3_FUNC.get(code, "FUNC_0x%02X" % code)


def require_tshark():
    if shutil.which("tshark") is None:
        sys.stderr.write("ERROR: tshark not found on PATH. Install Wireshark/tshark.\n")
        sys.exit(2)


def check_pcap(path):
    if not path or not os.path.isfile(path):
        sys.stderr.write("ERROR: pcap not found: %r\n" % path)
        sys.exit(2)


def tshark_fields(pcap, fields, display_filter=None, extra_opts=None):
    """Run `tshark -T fields ...` and yield one dict per row.

    `fields` is a list of field names; each yielded dict maps field name -> str
    ("" when tshark emits nothing for that field on that row). Rows are returned
    in capture order, so time-window logic downstream is stable.
    """
    require_tshark()
    check_pcap(pcap)
    cmd = ["tshark", "-r", pcap, "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    if extra_opts:
        cmd += extra_opts
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write("ERROR: tshark failed: %s\n" % (exc.stderr or exc))
        sys.exit(2)
    rows = []
    for line in out.stdout.splitlines():
        if line == "":
            continue
        parts = line.split("\t")
        # pad short rows (trailing empty fields get dropped by split)
        parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts)))
    return rows


def banner(title, invariant):
    print("=" * 72)
    print(title)
    print("INVARIANT: %s" % invariant)
    print("=" * 72)


def verdict(alerts):
    """Print a summary line and return the process exit code."""
    if alerts:
        print("-" * 72)
        print("RESULT: ALERT -- %d frame(s) violated the invariant." % alerts)
        return 1
    print("-" * 72)
    print("RESULT: clean -- invariant held, no alert.")
    return 0
