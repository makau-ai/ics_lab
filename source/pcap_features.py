# -*- coding: utf-8 -*-
"""pcap_features.py — the bridge between a pcap and a detector.

Turns a capture into per-frame feature dicts (`to_frames`) and per-conversation
flow records (`to_flows`), so a detector never has to re-parse raw packets. It
emits exactly the fields the DNP3/MQTT levels reason about:

  common : frame, time, ip.src, ip.dst, proto (l4), app ("dnp3"/"mqtt"/None), summary
  dnp3   : dnp3.src, dnp3.dst, dnp3.al.func (+ human func name), dnp3.ctl.prm
  mqtt   : mqtt.msgtype (+ human name), mqtt.topic, mqtt.retain, mqtt.username, mqtt.clientid

Field extraction is delegated to tshark (Wireshark 4.2.x), the same dissector the
curriculum uses, so features match what a student sees on the wire.

Library use:
    from pcap_features import to_frames, to_flows
    rows = to_frames("pcaps/dnp3_substation.pcap")          # list[dict]
    flows = to_flows("pcaps/mqtt_iot_telemetry.pcap")       # list[dict]

CLI:
    python3 build/pcap_features.py pcaps/dnp3_substation.pcap          # feature table
    python3 build/pcap_features.py pcaps/mqtt_iot_telemetry.pcap --flows
    python3 build/pcap_features.py pcaps/dnp3_substation.pcap --csv > frames.csv
"""
import csv
import io
import subprocess
import sys

# ---- human-readable code maps (protocol-accurate) ---------------------------
DNP3_FUNC = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
    5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 13: "COLD_RESTART",
    14: "WARM_RESTART", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE",
}
MQTT_MSGTYPE = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
    6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
    11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
}

# tshark field order for the -T fields extraction. Keep in sync with _COLUMNS.
_TSHARK_FIELDS = [
    "frame.number", "frame.time_relative", "ip.src", "ip.dst",
    "_ws.col.Protocol", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dnp3.src", "dnp3.dst", "dnp3.al.func", "dnp3.ctl.prm",
    "mqtt.msgtype", "mqtt.topic", "mqtt.retain", "mqtt.username", "mqtt.clientid",
]


def _to_int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _to_bool(s):
    """tshark renders boolean fields as '1'/'0' or 'True'/'False' depending on version."""
    if not s:
        return None
    return s.strip().lower() in ("1", "true")


def to_frames(pcap):
    """Return a list of per-frame feature dicts for `pcap` (one dict per frame)."""
    out = subprocess.run(
        ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
        + sum((["-e", f] for f in _TSHARK_FIELDS), []),
        capture_output=True, text=True,
    )
    rows = []
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        c = line.split("\t")
        c += [""] * (len(_TSHARK_FIELDS) - len(c))  # pad short rows
        (fno, trel, ipsrc, ipdst, proto, tsp, tdp, usp, udp_,
         d_src, d_dst, d_func, d_prm,
         m_type, m_topic, m_ret, m_user, m_cid) = c[:len(_TSHARK_FIELDS)]

        l4 = "tcp" if tsp or tdp else ("udp" if usp or udp_ else "")
        sport = _to_int(tsp) or _to_int(usp)
        dport = _to_int(tdp) or _to_int(udp_)

        app = None
        if d_func or d_src:
            app = "dnp3"
        elif m_type:
            app = "mqtt"

        func = _to_int(d_func)
        mtype = _to_int(m_type)
        row = {
            "frame": _to_int(fno),
            "time": float(trel) if trel else None,
            "ip.src": ipsrc or None,
            "ip.dst": ipdst or None,
            "l4": l4 or None,
            "sport": sport,
            "dport": dport,
            "proto": proto or None,
            "app": app,
            # DNP3
            "dnp3.src": _to_int(d_src),
            "dnp3.dst": _to_int(d_dst),
            "dnp3.func": func,
            "dnp3.func_name": DNP3_FUNC.get(func) if func is not None else None,
            "dnp3.prm": _to_bool(d_prm),
            # MQTT
            "mqtt.msgtype": mtype,
            "mqtt.msgtype_name": MQTT_MSGTYPE.get(mtype) if mtype is not None else None,
            "mqtt.topic": m_topic or None,
            "mqtt.retain": _to_bool(m_ret),
            "mqtt.username": m_user or None,
            "mqtt.clientid": m_cid or None,
        }
        # a compact human summary of the frame's meaning
        if app == "dnp3":
            dirn = "rsp" if func in (129, 130) else "req"
            row["summary"] = f"DNP3 {row['dnp3.func_name'] or row['dnp3.func']} " \
                             f"link {row['dnp3.src']}->{row['dnp3.dst']} ({dirn})"
        elif app == "mqtt":
            t = f" {row['mqtt.topic']}" if row["mqtt.topic"] else ""
            r = " retain" if row["mqtt.retain"] else ""
            row["summary"] = f"MQTT {row['mqtt.msgtype_name'] or row['mqtt.msgtype']}{t}{r}"
        else:
            row["summary"] = f"{proto} {l4} {sport}->{dport}".strip()
        rows.append(row)
    return rows


def to_flows(pcap):
    """Aggregate frames into directionless conversations keyed by {a,b}+l4+port.

    Returns one dict per flow with packet counts and the app-layer message
    vocabulary seen (DNP3 func names / MQTT msgtype names + counts)."""
    from collections import Counter, defaultdict
    frames = to_frames(pcap)
    flows = {}
    verbs = defaultdict(Counter)
    for f in frames:
        a, b = f["ip.src"], f["ip.dst"]
        if not a or not b:
            continue
        # canonical (endpoint-pair, service-port) key, direction-independent
        endpoints = tuple(sorted([a, b]))
        svc = max(x for x in [f["sport"], f["dport"]] if x is not None) if (f["sport"] or f["dport"]) else None
        key = (endpoints, f["l4"], svc)
        fl = flows.setdefault(key, {
            "endpoints": list(endpoints), "l4": f["l4"], "service_port": svc,
            "packets": 0, "app": None, "apps": set(),
        })
        fl["packets"] += 1
        if f["app"]:
            fl["apps"].add(f["app"])
            if f["app"] == "dnp3" and f["dnp3.func_name"]:
                verbs[key][f["dnp3.func_name"]] += 1
            elif f["app"] == "mqtt" and f["mqtt.msgtype_name"]:
                verbs[key][f["mqtt.msgtype_name"]] += 1
    result = []
    for key, fl in flows.items():
        fl["app"] = "/".join(sorted(fl["apps"])) or None
        fl["apps"] = sorted(fl["apps"])
        fl["messages"] = dict(verbs[key])
        result.append(fl)
    result.sort(key=lambda r: -r["packets"])
    return result


# ---- CSV + table rendering --------------------------------------------------
_COLUMNS = ["frame", "time", "app", "ip.src", "ip.dst",
            "dnp3.src", "dnp3.func_name", "mqtt.msgtype_name",
            "mqtt.topic", "mqtt.retain", "mqtt.username", "summary"]


def to_csv(pcap):
    buf = io.StringIO()
    rows = to_frames(pcap)
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else _COLUMNS)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def _print_table(rows):
    cols = _COLUMNS
    widths = {c: len(c) for c in cols}
    disp = []
    for r in rows:
        d = {c: ("" if r.get(c) in (None, "") else str(r.get(c))) for c in cols}
        for c in cols:
            widths[c] = min(28, max(widths[c], len(d[c])))
        disp.append(d)
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    print(line)
    print("  ".join("-" * widths[c] for c in cols))
    for d in disp:
        print("  ".join(d[c][:widths[c]].ljust(widths[c]) for c in cols))


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    pcap = argv[1]
    if "--csv" in argv:
        sys.stdout.write(to_csv(pcap))
        return 0
    if "--flows" in argv:
        flows = to_flows(pcap)
        print(f"# {pcap}: {len(flows)} conversation(s)\n")
        for fl in flows:
            a, b = fl["endpoints"]
            msgs = ", ".join(f"{k}x{v}" for k, v in sorted(fl["messages"].items())) or "-"
            print(f"{a} <-> {b}  {fl['l4'] or '?'}/{fl['service_port']}  "
                  f"{fl['packets']} pkts  app={fl['app'] or '-'}  [{msgs}]")
        return 0
    rows = to_frames(pcap)
    app_rows = [r for r in rows if r["app"]]
    show = app_rows if app_rows else rows
    print(f"# {pcap}: {len(rows)} frames, {len(app_rows)} app-layer (DNP3/MQTT)\n")
    _print_table(show)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
