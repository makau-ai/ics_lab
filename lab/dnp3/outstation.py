#!/usr/bin/env python3
"""
outstation.py -- a minimal DNP3 outstation (substation RTU) for the lab.

Listens on TCP/20000, answers polls with canned substation data, and OBEYS
control commands from anyone who can reach it -- printing a loud log line so
students can watch unauthenticated command injection happen in real time.

Run:  python3 outstation.py            (listens on 0.0.0.0:20000)
Then point master.py at it, capture with Wireshark/tcpdump, and try the
attacker mode of master.py to see the outstation execute an unauthenticated trip.
"""
import socket, threading, time, sys
import dnp3lib as d

OUTSTN_ADDR = 10
LISTEN = ("0.0.0.0", 20000)

# canned "current state" of the substation
BINARY = [1, 1, 0, 0]          # breaker closed, disconnect closed, ground open, alarm clear
ANALOG = [13245, 452, 6001]    # bus volts, line amps, frequency*100
breaker_state = {"closed": True}


def handle(conn, peer):
    print(f"[outstation] connection from {peer[0]}:{peer[1]}", flush=True)
    seq = 0
    try:
        while True:
            frame = d.read_frame(conn)
            if frame is None:
                break
            ctrl, dest, src, user = frame
            parsed = d.parse_app(user)
            if not parsed:
                continue
            ac, func, name, objs = parsed
            print(f"[outstation] <- {name} (fc=0x{func:02x}) from {peer[0]} (DNP3 src addr {src})", flush=True)

            if func == 0x01:  # READ / class poll -> respond with data
                resp = d.obj_binary_inputs(BINARY) + d.obj_analog_inputs(ANALOG)
                conn.sendall(d.msg(d.CTRL_OUTSTN, src, OUTSTN_ADDR, seq,
                                   d.appctl(seq), 0x81, resp, iin=(0x00, 0x00)))
                seq = (seq + 1) & 0x0F

            elif func in (0x03, 0x04, 0x05):  # SELECT / OPERATE / DIRECT_OPERATE (CROB)
                # objs = [group, var, qual, count, index, control_code, ...]
                cc = objs[5] if len(objs) > 5 else 0
                action = "TRIP (open)" if (cc & 0xC0) == 0x80 else ("CLOSE" if (cc & 0xC0) == 0x40 else "op")
                authed = "  <<< NOTE: no authentication -- executed on request!" if func == 0x05 else ""
                if func in (0x04, 0x05):
                    breaker_state["closed"] = not ((cc & 0xC0) == 0x80)
                print(f"[outstation] *** CONTROL {name} CROB {action} from {peer[0]} "
                      f"-> breaker now {'CLOSED' if breaker_state['closed'] else 'OPEN'}{authed}", flush=True)
                echo = objs if objs else d.crob(0, cc, status=0)
                conn.sendall(d.msg(d.CTRL_OUTSTN, src, OUTSTN_ADDR, seq,
                                   d.appctl(seq), 0x81, echo, iin=(0x00, 0x00)))
                seq = (seq + 1) & 0x0F

            elif func == 0x0D:  # COLD_RESTART
                print(f"[outstation] *** COLD RESTART requested by {peer[0]} -- going down (availability attack)", flush=True)
                conn.sendall(d.msg(d.CTRL_OUTSTN, src, OUTSTN_ADDR, seq,
                                   d.appctl(seq), 0x81, d.obj_time_delay(30000), iin=(0x80, 0x00)))
                seq = (seq + 1) & 0x0F

            else:
                conn.sendall(d.msg(d.CTRL_OUTSTN, src, OUTSTN_ADDR, seq,
                                   d.appctl(seq), 0x81, b"", iin=(0x00, 0x00)))
                seq = (seq + 1) & 0x0F
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()
        print(f"[outstation] {peer[0]} disconnected", flush=True)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN)
    s.listen(5)
    print(f"[outstation] DNP3 outstation (addr {OUTSTN_ADDR}) listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    while True:
        conn, peer = s.accept()
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
