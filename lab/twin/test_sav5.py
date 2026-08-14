#!/usr/bin/env python3
"""
test_sav5.py -- dependency-free unit test for the DNP3 gateway's SAv5
anti-replay (CSQ freshness) control and the %MW12 CROB mapping contract.

What it proves (InfoSec finding review_1 / PANEL_REVIEW P1 item 5):
  * A valid SAv5-sealed control (HMAC over ac||func||core||CSQ) is ACCEPTED.
  * REPLAYING the identical frame (same CSQ) is REJECTED for freshness.
  * A fresh, strictly-higher-CSQ frame is ACCEPTED again.
  * A tampered tag is rejected (authenticity, unchanged behaviour).
  * The DNP3 CROB (index, op) -> %MW12 code mapping matches the SHARED CONTRACT.

Runs headless with only the standard library + the kit's own dnp3lib/gateway
(no pytest, no network, no Modbus). Exit code is non-zero on any failure.

  python3 test_sav5.py
"""
import os
import sys

# HARDEN + SAV5 are read at gateway import time -- set them BEFORE importing.
os.environ["HARDEN"] = "1"
os.environ["SAV5"] = "1"

# gateway.py and dnp3lib.py live in ./dnp3/ next to this test.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnp3"))

import dnp3lib as d          # noqa: E402
import gateway as gw         # noqa: E402

_FAILS = []


def check(cond, label):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}")
    if not cond:
        _FAILS.append(label)
    return cond


# ---------------------------------------------------------------------------
class FakeConn:
    """Minimal socket stand-in: capture what the gateway echoes back."""
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)


def build_crob(func, index, start, csq):
    """Build a SAv5-sealed CROB control object block for (index, start) @ CSQ."""
    ac = d.appctl(csq & 0x0F)
    cc = d.CROB_CLOSE_PULSE if start else d.CROB_TRIP_PULSE
    core = d.crob(index, cc)
    objs = gw.sav5_seal(ac, func, core, csq)
    return ac, objs


# ---------------------------------------------------------------------------
def test_freshness_primitive():
    print("[1] SAv5 CSQ freshness at the verify primitive (sav5_verify):")
    # a valid SELECT for P1-STOP at CSQ=100
    ac, objs = build_crob(0x03, d.CROB_P1, start=False, csq=100)

    ok, reason, csq = gw.sav5_verify(ac, 0x03, objs, 16, last_csq=None)
    check(ok and csq == 100, f"valid control ACCEPTED (reason={reason}, csq={csq})")

    # REPLAY: identical frame, session already saw CSQ=100
    ok, reason, csq = gw.sav5_verify(ac, 0x03, objs, 16, last_csq=100)
    check((not ok) and reason == "stale-csq", f"replay (same CSQ) REJECTED (reason={reason})")

    # a non-monotonic (lower) CSQ is also stale
    ac_lo, objs_lo = build_crob(0x03, d.CROB_P1, start=False, csq=99)
    ok, reason, _ = gw.sav5_verify(ac_lo, 0x03, objs_lo, 16, last_csq=100)
    check((not ok) and reason == "stale-csq", f"lower CSQ REJECTED (reason={reason})")

    # a fresh, strictly-higher CSQ is accepted
    ac_hi, objs_hi = build_crob(0x03, d.CROB_P1, start=False, csq=101)
    ok, reason, csq = gw.sav5_verify(ac_hi, 0x03, objs_hi, 16, last_csq=100)
    check(ok and csq == 101, f"higher CSQ ACCEPTED (reason={reason}, csq={csq})")

    # tampered tag -> authenticity failure (freshness never reached)
    tampered = bytearray(objs)
    tampered[-1] ^= 0xFF
    ok, reason, _ = gw.sav5_verify(ac, 0x03, bytes(tampered), 16, last_csq=None)
    check((not ok) and reason == "bad-hmac", f"tampered tag REJECTED (reason={reason})")


def test_mw12_mapping():
    print("[2] %MW12 CROB mapping contract (crob_to_mw12 / crob_is_start):")
    check(gw.crob_to_mw12(d.CROB_P1, True) == 1, "index0 CLOSE -> %MW12=1 (START P1)")
    check(gw.crob_to_mw12(d.CROB_P2, True) == 2, "index1 CLOSE -> %MW12=2 (START P2)")
    check(gw.crob_to_mw12(d.CROB_P1, False) == 3, "index0 TRIP  -> %MW12=3 (STOP P1)")
    check(gw.crob_to_mw12(d.CROB_P2, False) == 4, "index1 TRIP  -> %MW12=4 (STOP P2)")
    check(gw.crob_is_start(d.CROB_CLOSE_PULSE) is True, "CLOSE pulse decodes as START")
    check(gw.crob_is_start(d.CROB_TRIP_PULSE) is False, "TRIP pulse decodes as STOP")


def test_end_to_end_gateway():
    print("[3] End-to-end via Gateway._handle_crob (accept -> replay -> fresh):")
    g = gw.Gateway("test-noop", 0, outstn_addr=10)
    writes = []
    # stub the Modbus write so no network/PLC is needed
    g._write_openplc = lambda kind, index, value: (writes.append((kind, index, value)) or True)

    conn = FakeConn()
    src = 100                 # allow-listed master link address
    arm = {}
    sav5_csq = {}

    # --- legit supervised STOP P1: SELECT(csq=10) then OPERATE(csq=11).
    # Keep the exact (ac, objs) bytes so the replay below is byte-identical. ---
    ac_sel, objs_sel = build_crob(0x03, d.CROB_P1, start=False, csq=10)
    g._handle_crob(conn, ("m", 0), src, 0, ac_sel, 0x03, "SELECT", objs_sel, arm, sav5_csq)
    check(sav5_csq.get(src) == 10 and 0 in arm, "SELECT csq=10 ACCEPTED and armed idx0")

    ac_op, objs_op = build_crob(0x04, d.CROB_P1, start=False, csq=11)
    g._handle_crob(conn, ("m", 0), src, 1, ac_op, 0x04, "OPERATE", objs_op, arm, sav5_csq)
    check(writes == [("holding", gw.MB_HR_REMOTE_CMD, 3)],
          f"OPERATE csq=11 ACCEPTED -> %MW12=3 written (writes={writes})")
    check(sav5_csq.get(src) == 11, "session CSQ high-water advanced to 11")

    # --- REPLAY the IDENTICAL captured SELECT+OPERATE pair (same bytes, same CSQ) ---
    g._handle_crob(conn, ("m", 0), src, 2, ac_sel, 0x03, "SELECT", objs_sel, arm, sav5_csq)
    g._handle_crob(conn, ("m", 0), src, 3, ac_op, 0x04, "OPERATE", objs_op, arm, sav5_csq)
    check(writes == [("holding", gw.MB_HR_REMOTE_CMD, 3)],
          f"replayed pair REJECTED for freshness -> no new %MW12 write (writes={writes})")
    check(sav5_csq.get(src) == 11, "session CSQ NOT advanced by replay (still 11)")

    # --- fresh higher-CSQ control: START P2 at csq 12/13 ---
    ac, objs = build_crob(0x03, d.CROB_P2, start=True, csq=12)
    g._handle_crob(conn, ("m", 0), src, 4, ac, 0x03, "SELECT", objs, arm, sav5_csq)
    ac, objs = build_crob(0x04, d.CROB_P2, start=True, csq=13)
    g._handle_crob(conn, ("m", 0), src, 5, ac, 0x04, "OPERATE", objs, arm, sav5_csq)
    check(writes == [("holding", gw.MB_HR_REMOTE_CMD, 3), ("holding", gw.MB_HR_REMOTE_CMD, 2)],
          f"fresh SELECT/OPERATE csq=12/13 ACCEPTED -> %MW12=2 (START P2) (writes={writes})")


def main():
    print("=== DNP3 gateway SAv5 anti-replay (CSQ freshness) + %MW12 mapping ===")
    print(f"    HARDEN={int(gw.HARDEN)} SAV5={int(gw.SAV5)} "
          f"CSQ_LEN={gw.SAV5_CSQ_LEN} TAG_LEN={d.SAV5_TAG_LEN}")
    test_freshness_primitive()
    test_mw12_mapping()
    test_end_to_end_gateway()
    print("-" * 60)
    if _FAILS:
        print(f"RESULT: FAIL ({len(_FAILS)} failing check(s): {_FAILS})")
        return 1
    print("RESULT: PASS (all checks green)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
