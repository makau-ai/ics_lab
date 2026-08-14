#!/usr/bin/env python3
"""
gateway.py -- the DNP3 outstation GATEWAY fronting the PLC (dnp3-gw, addr 10).

Re-skins the lab outstation.py server loop, but instead of canned substation
values it mirrors the LIVE wet-well image polled from OpenPLC over Modbus, and
maps DNP3 controls back down to Modbus writes:

  * integrity poll (READ 0x01) -> g1 [P1,P2,HLA,fault] + g30 [level,flow,psi]
                                  + g40 [LEAD_START, STOP] setpoints
  * SELECT 0x03 / OPERATE 0x04 (g12v1 CROB) -> start/stop a pump coil in OpenPLC
  * WRITE 0x02 (g41 analog output)          -> LEAD_START/STOP setpoint (%MW10/11)
  * a rising HLA emits an UNSOLICITED 0x82 (report-by-exception)

Two behaviours, switched by env HARDEN (and SAV5):
  HARDEN=0  obey-on-request (today's teaching "before" -- CWE-306 live)
  HARDEN=1  SELECT arm-latch (OPERATE only within 2 s of a matching SELECT on
            the same association); DIRECT_OPERATE (0x05/0x06) refused for
            consequential points; object/range + link-address allow-list.
  SAV5=1    additionally require a valid SAv5 aggressive-mode HMAC on control FCs,
            with a monotonic Challenge Sequence Number (CSQ) folded into the HMAC
            input so a captured control frame is REJECTED on replay (freshness /
            anti-replay). A control is accepted only if its CSQ is strictly greater
            than the last accepted CSQ for that DNP3 association (session).

Usage:
  python gateway.py --modbus-host openplc --listen 0.0.0.0:20000 --outstn-addr 10
"""
import argparse
import os
import socket
import struct
import threading
import time

import dnp3lib as d
from modbus_tcp import ModbusClient

# ---- Modbus addresses the gateway polls -----------------------------------
# PLC_MAP selects the source register map:
#   "sim"     (default) -> plant-sim's raw addresses; works out-of-the-box, and
#             also matches OpenPLC's INPUT-register map (%IW100.. == IR 100..).
#   "openplc" -> OpenPLC bit map: %IX100.0/%QX100.0 live at Modbus bit offset 800
#             (100*8). Set MODBUS_HOST=openplc PLC_MAP=openplc once the OpenPLC
#             slave-device + server map is confirmed (see README bring-up caveat).
PLC_MAP = os.environ.get("PLC_MAP", "sim")
_BITBASE = 800 if PLC_MAP == "openplc" else 0
MB_IR_LEVEL, MB_IR_FLOW, MB_IR_PSI = 100, 101, 102          # %IW100..102
MB_DI_LSHH, MB_DI_LSL = _BITBASE + 0, _BITBASE + 1          # %IX100.0/.1
MB_CO_P1, MB_CO_P2, MB_CO_HLA = _BITBASE + 0, _BITBASE + 1, _BITBASE + 2  # %QX100.0..2
MB_HR_LEAD_START, MB_HR_STOP = 10, 11            # setpoints %MW10/11 (g41 write target)
# %MW12 REMOTE_CMD -- SHARED CONTRACT with the OpenPLC ST decode. Per-pump momentary
# command codes: 0=no command (auto); 1=START P1, 2=START P2, 3=STOP P1, 4=STOP P2,
# 5=STOP ALL. The ST latches the code on a rising edge, applies it, then writes %MW12
# back to 0 (auto-revert) so one command cannot pin the loop out of automatic.
MB_HR_REMOTE_CMD = 12

HARDEN = os.environ.get("HARDEN", "0").strip() in ("1", "true", "yes", "on")
SAV5 = os.environ.get("SAV5", "0").strip() in ("1", "true", "yes", "on")
ARM_TIMEOUT_S = 2.0

# live process image, refreshed by the Modbus poll thread
image = {"level": 0, "flow": 0, "psi": 0, "lshh": False, "lsl": True,
         "p1": False, "p2": False, "hla": False, "fault": False,
         "lead_start": 6000, "stop": 2000, "online": False}
image_lock = threading.Lock()
_hla_prev = {"v": False}
unsol_pending = threading.Event()


def poll_openplc(host, port):
    """Continuously mirror OpenPLC's Modbus image into `image` (resilient)."""
    while True:
        cli = ModbusClient(host, port, timeout=2.0)
        try:
            cli.connect()
            while True:
                irs = cli.read_input_registers(MB_IR_LEVEL, 3)          # level,flow,psi
                dis = cli.read_discrete_inputs(MB_DI_LSHH, 2)           # lshh,lsl
                cos = cli.read_coils(MB_CO_P1, 3)                       # p1,p2,hla
                hrs = cli.read_holding_registers(MB_HR_LEAD_START, 2)   # lead_start,stop
                with image_lock:
                    image.update(level=irs[0], flow=irs[1], psi=irs[2],
                                 lshh=dis[0], lsl=dis[1],
                                 p1=cos[0], p2=cos[1], hla=cos[2],
                                 lead_start=hrs[0], stop=hrs[1], online=True)
                if cos[2] and not _hla_prev["v"]:      # HLA rising edge
                    unsol_pending.set()
                _hla_prev["v"] = cos[2]
                time.sleep(1.0)
        except (OSError, IOError, ConnectionError) as e:
            with image_lock:
                image["online"] = False
            print(f"[dnp3-gw] modbus poll to {host}:{port} unavailable ({e}); retrying", flush=True)
            time.sleep(2.0)
        finally:
            cli.close()


def build_poll_response():
    with image_lock:
        bi = [image["p1"], image["p2"], image["hla"], image["fault"]]
        ai = [image["level"], image["flow"], image["psi"]]
        ao = [image["lead_start"], image["stop"]]
    return (d.obj_binary_inputs(bi) + d.obj_analog_inputs(ai)
            + d.obj_analog_output_status(ao))


# ---- SAv5 aggressive-mode stand-in WITH freshness (anti-replay) ------------
# Wire layout of a SAv5-sealed control object block:
#     core-objects || CSQ (4 bytes, big-endian) || HMAC tag (SAV5_TAG_LEN)
# The 32-bit Challenge Sequence Number (CSQ) is folded into the HMAC input
# (ac||func||core||CSQ) so it is authenticated -- an attacker cannot replay a
# captured frame with a bumped CSQ without also forging the tag. The gateway
# accepts a control only if its CSQ is STRICTLY GREATER than the last accepted
# CSQ for that association (session). This is what makes the documented
# anti-replay control real: a captured hardened SELECT+OPERATE pair replays
# verbatim (same CSQ) and is rejected for freshness.
SAV5_CSQ_LEN = 4


def sav5_seal(ac, func, core, csq):
    """ENCODE side: wrap core control objects with a CSQ + HMAC tag.

    Returns core || CSQ(4, big-endian) || tag. The tag authenticates the CSQ,
    so freshness cannot be tampered without breaking the HMAC. This is the
    encoder the SAv5-aware master (and the unit test) uses to build a control
    the HARDEN+SAV5 gateway will accept.
    """
    csq_bytes = struct.pack(">I", csq & 0xFFFFFFFF)
    tag = d.sav5_tag(bytes([ac, func]) + bytes(core) + csq_bytes)
    return bytes(core) + csq_bytes + tag


def sav5_verify(ac, func, objs, core_len, last_csq):
    """VERIFY side. Returns (ok, reason, csq).

    ok is True when SAV5 is disabled, or the trailing tag authenticates
    (ac||func||core||CSQ) AND the CSQ is strictly greater than last_csq
    (None means "no control accepted yet on this session"). Otherwise ok is
    False with reason in {short-frame, bad-hmac, stale-csq}.
    """
    if not SAV5:
        return True, "sav5-off", None
    need = core_len + SAV5_CSQ_LEN + d.SAV5_TAG_LEN
    if len(objs) < need:
        return False, "short-frame", None
    core = bytes(objs[:core_len])
    csq_bytes = bytes(objs[core_len:core_len + SAV5_CSQ_LEN])
    tag = bytes(objs[core_len + SAV5_CSQ_LEN:need])
    if not d.sav5_check(bytes([ac, func]) + core + csq_bytes, tag):
        return False, "bad-hmac", None
    csq = struct.unpack(">I", csq_bytes)[0]
    if last_csq is not None and csq <= last_csq:
        return False, "stale-csq", csq          # replay / non-monotonic
    return True, "ok", csq


def crob_to_mw12(index, pump_on):
    """Translate a DNP3 CROB (index, op) into the %MW12 REMOTE_CMD code.

    SHARED CONTRACT (must match the OpenPLC ST decode exactly):
      index 0 -> pump P1, index 1 -> pump P2;
      CLOSE / LATCH_ON  -> START, TRIP / LATCH_OFF -> STOP.
    %MW12 codes: 1=START P1, 2=START P2, 3=STOP P1, 4=STOP P2, 5=STOP ALL.
    """
    if pump_on:
        return 1 if index == d.CROB_P1 else 2     # START P1 / START P2
    return 3 if index == d.CROB_P1 else 4         # STOP  P1 / STOP  P2


def crob_is_start(cc):
    """CLOSE (TCC=01) or LATCH_ON (op-code 3) mean START; TRIP/LATCH_OFF mean STOP."""
    tcc = cc & 0xC0
    op = cc & 0x0F
    return tcc == 0x40 or (tcc == 0x00 and op == 0x03)


class Gateway:
    def __init__(self, modbus_host, modbus_port, outstn_addr):
        self.modbus_host = modbus_host
        self.modbus_port = modbus_port
        self.addr = outstn_addr
        self._wcli = None

    def _write_openplc(self, kind, index, value):
        """Push a control down to OpenPLC over Modbus (best-effort)."""
        try:
            if self._wcli is None:
                self._wcli = ModbusClient(self.modbus_host, self.modbus_port, timeout=2.0)
                self._wcli.connect()
            if kind == "coil":
                self._wcli.write_coil(index, value)
            else:
                self._wcli.write_register(index, value)
            return True
        except (OSError, IOError, ConnectionError) as e:
            self._wcli = None
            print(f"[dnp3-gw] WARN modbus write failed ({e})", flush=True)
            return False

    def handle(self, conn, peer):
        print(f"[dnp3-gw] connection from {peer[0]}:{peer[1]} (HARDEN={int(HARDEN)} SAV5={int(SAV5)})", flush=True)
        seq = 0
        arm = {}       # index -> (t, association) SELECT arm-latch
        sav5_csq = {}  # src (association) -> last accepted CSQ (anti-replay freshness)
        last_hla = False
        conn.settimeout(1.0)
        try:
            while True:
                try:
                    frame = d.read_frame(conn)
                except socket.timeout:
                    # idle window: emit an UNSOLICITED 0x82 if HLA just rose
                    if unsol_pending.is_set() and not last_hla:
                        with image_lock:
                            hla = image["hla"]
                        if hla:
                            uns = d.obj_binary_inputs([image["p1"], image["p2"], True, image["fault"]])
                            conn.sendall(d.msg(d.CTRL_OUTSTN, 100, self.addr, seq,
                                               d.appctl(seq, uns=1), 0x82, uns, iin=(0x00, 0x00)))
                            seq = (seq + 1) & 0x0F
                            last_hla = True
                            print(f"[dnp3-gw] -> UNSOLICITED 0x82 HLA to {peer[0]}", flush=True)
                    continue
                if frame is None:
                    break
                ctrl, dest, src, user = frame
                parsed = d.parse_app(user)
                if not parsed:
                    continue
                ac, func, name, objs = parsed
                print(f"[dnp3-gw] <- {name} (fc=0x{func:02x}) from {peer[0]} (DNP3 src {src})", flush=True)

                # ---- HARDEN: DNP3 link-address allow-list ----
                if HARDEN and src not in d.ALLOWED_MASTER_ADDRS:
                    print(f"[dnp3-gw] DROP: src addr {src} not in allow-list {d.ALLOWED_MASTER_ADDRS}", flush=True)
                    continue

                if func == 0x01:                        # READ / integrity poll
                    resp = build_poll_response()
                    conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq,
                                       d.appctl(seq), 0x81, resp, iin=(0x00, 0x00)))
                    seq = (seq + 1) & 0x0F

                elif func in (0x03, 0x04, 0x05, 0x06):   # SELECT/OPERATE/DIRECT_OPERATE CROB
                    self._handle_crob(conn, peer, src, seq, ac, func, name, objs, arm, sav5_csq)
                    seq = (seq + 1) & 0x0F

                elif func == 0x02:                       # WRITE (g41 setpoint)
                    self._handle_setpoint(conn, src, seq, ac, func, objs, sav5_csq)
                    seq = (seq + 1) & 0x0F

                elif func == 0x0D:                       # COLD_RESTART
                    if HARDEN:
                        print(f"[dnp3-gw] REJECT COLD_RESTART from {peer[0]} (HARDEN)", flush=True)
                        conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq,
                                           d.appctl(seq), 0x81, b"", iin=(0x00, 0x10)))  # IIN2.4 func-not-supported
                    else:
                        print(f"[dnp3-gw] *** COLD RESTART requested by {peer[0]} (availability)", flush=True)
                        conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq,
                                           d.appctl(seq), 0x81, d.obj_time_delay(30000), iin=(0x80, 0x00)))
                    seq = (seq + 1) & 0x0F

                else:
                    conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq,
                                       d.appctl(seq), 0x81, b"", iin=(0x00, 0x00)))
                    seq = (seq + 1) & 0x0F
        except (ConnectionError, OSError):
            pass
        finally:
            conn.close()
            print(f"[dnp3-gw] {peer[0]} disconnected", flush=True)

    def _handle_crob(self, conn, peer, src, seq, ac, func, name, objs, arm, sav5_csq):
        index, cc = d.crob_index_code(objs)
        status = 0                          # 0 = success
        # ---- SAv5 authenticity + CSQ freshness (anti-replay) -------------
        # Evaluated first so an authentic, fresh control burns its CSQ; a replay
        # (identical CSQ) or a non-monotonic/unauthenticated frame is rejected.
        sav5_bad = False
        if HARDEN and SAV5:
            ok, reason, csq = sav5_verify(ac, func, objs, 16, sav5_csq.get(src))
            if not ok:
                sav5_bad = True
                print(f"[dnp3-gw] REJECT {name}: SAv5 {reason} "
                      f"(anti-replay: CSQ must exceed last accepted for src {src})", flush=True)
            else:
                sav5_csq[src] = csq          # accept -> advance the session CSQ high-water mark
                print(f"[dnp3-gw] SAv5 OK {name} CSQ={csq} (fresh > last) src {src}", flush=True)
        # ---- object/range allow-list + arm-latch --------------------------
        if HARDEN and (index not in d.ALLOWED_OBJECTS.get((12, 1), set())):
            print(f"[dnp3-gw] REJECT CROB index {index} not in point map", flush=True)
            status = 4                       # not-supported
        elif HARDEN and func in (0x05, 0x06):
            print(f"[dnp3-gw] REJECT {name}: DIRECT_OPERATE refused for control points (HARDEN)", flush=True)
            status = 2                       # no-select / not-authorized
        elif sav5_bad:
            status = 2
        elif func == 0x03:                   # SELECT -> arm the latch
            arm[index] = (time.time(), src)
            print(f"[dnp3-gw] SELECT armed idx {index} for src {src}", flush=True)
        elif func in (0x04, 0x05, 0x06):     # OPERATE / DIRECT_OPERATE -> act
            if HARDEN and func == 0x04:      # OPERATE must follow a fresh SELECT
                t_assoc = arm.get(index)
                if not t_assoc or (time.time() - t_assoc[0]) > ARM_TIMEOUT_S or t_assoc[1] != src:
                    print(f"[dnp3-gw] REJECT OPERATE idx {index}: no fresh matching SELECT (arm-latch)", flush=True)
                    status = 2
                else:
                    arm.pop(index, None)
            if status == 0:
                pump_on = crob_is_start(cc)              # CLOSE/LATCH_ON=start, TRIP/LATCH_OFF=stop
                # Supervised control writes the PLC's REMOTE_CMD register (%MW12) using the
                # SHARED CONTRACT per-pump code; the ST loop latches on rising edge, applies
                # it, then auto-reverts %MW12 to 0. index 0 -> P1, index 1 -> P2.
                remote_val = crob_to_mw12(index, pump_on)
                ok = self._write_openplc("holding", MB_HR_REMOTE_CMD, remote_val)
                authed = "" if HARDEN else "   <<< no authentication -- executed on request!"
                print(f"[dnp3-gw] *** CONTROL {name} pump{index+1} -> "
                      f"{'START' if pump_on else 'STOP'} via %MW12={remote_val} (modbus_ok={ok}){authed}", flush=True)
        echo = objs[:16] if len(objs) >= 16 else (objs if objs else d.crob(index or 0, cc or 0, status=status))
        conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq,
                           d.appctl(seq), 0x81, echo, iin=(0x00, 0x00)))

    def _handle_setpoint(self, conn, src, seq, ac, func, objs, sav5_csq):
        parsed = d.parse_g41_write(objs)
        if not parsed:
            conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq, d.appctl(seq), 0x81, b"", iin=(0x00, 0x00)))
            return
        index, value = parsed
        status_ok = True
        # SAv5 authenticity + CSQ freshness first (shares the association's CSQ
        # high-water mark with the CROB path -- one monotonic counter per session).
        sav5_bad = False
        if HARDEN and SAV5:
            # g41 v1 Analog Output Block core = [41,1,0x17,1,index,<i value>,<B status>] = 10 bytes.
            ok, reason, csq = sav5_verify(ac, func, objs, 10, sav5_csq.get(src))
            if not ok:
                sav5_bad = True
                print(f"[dnp3-gw] REJECT g41 write: SAv5 {reason} "
                      f"(anti-replay: CSQ must exceed last accepted for src {src})", flush=True)
            else:
                sav5_csq[src] = csq
                print(f"[dnp3-gw] SAv5 OK g41 write CSQ={csq} (fresh > last) src {src}", flush=True)
        if HARDEN and index not in d.ALLOWED_OBJECTS.get((41, 1), set()):
            print(f"[dnp3-gw] REJECT g41 setpoint index {index} not in point map", flush=True)
            status_ok = False
        elif sav5_bad:
            status_ok = False
        if status_ok:
            reg = MB_HR_LEAD_START if index == d.AO_LEAD_START else MB_HR_STOP
            # NOTE: the setpoint CLAMP is enforced in the PLC ladder (hardened_wetwell.st),
            # not here -- the gateway only allow-lists the point. Oldsmar move stays visible.
            ok = self._write_openplc("holding", reg, value & 0xFFFF)
            print(f"[dnp3-gw] *** SETPOINT g41 idx {index} <- {value} (={value/100.0:.1f}%) modbus_ok={ok}", flush=True)
        conn.sendall(d.msg(d.CTRL_OUTSTN, src, self.addr, seq, d.appctl(seq), 0x81,
                           d.obj_analog_output(index, value), iin=(0x00, 0x00)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modbus-host", default=os.environ.get("MODBUS_HOST", "openplc"))
    ap.add_argument("--modbus-port", type=int, default=int(os.environ.get("MODBUS_PORT", "502")))
    ap.add_argument("--listen", default="0.0.0.0:20000")
    ap.add_argument("--outstn-addr", type=int, default=10)
    args = ap.parse_args()
    host, port = args.listen.split(":")
    port = int(port)

    threading.Thread(target=poll_openplc, args=(args.modbus_host, args.modbus_port), daemon=True).start()

    gw = Gateway(args.modbus_host, args.modbus_port, args.outstn_addr)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"[dnp3-gw] DNP3 outstation (addr {args.outstn_addr}) on {host}:{port}, "
          f"mirroring modbus://{args.modbus_host}:{args.modbus_port} | HARDEN={int(HARDEN)} SAV5={int(SAV5)}", flush=True)
    while True:
        conn, peer = s.accept()
        threading.Thread(target=gw.handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
