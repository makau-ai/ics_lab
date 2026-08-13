"""
build_dnp3.py -- craft a curated DNP3 teaching capture on TCP/20000.

Scenario: an electric distribution substation monitored from a control center.
  master     10.20.0.5     SCADA master / control center     (DNP3 link addr 100)
  outstation 10.20.0.20    substation RTU/IED                 (DNP3 link addr 10)
  attacker   10.20.0.66    rogue host with DNP3 reachability  (spoofs master addr)

Benign traffic: integrity poll (READ class 1/2/3/0) + RESPONSE with binary &
analog objects, a Class-0 static poll, an UNSOLICITED_RESPONSE + CONFIRM, and a
SELECT-before-OPERATE control of a breaker (CROB).
Labeled anomalies: an unauthenticated DIRECT_OPERATE trip (command injection)
and a COLD_RESTART (availability attack) -- both obeyed because base DNP3 has
no authentication (contrast: DNP3-SA / IEEE 1815-2012).

Frame structure per DNP Users Group "DNP3 Primer" and IEEE 1815-2012.
"""
import struct
from pcap_util import Host, Capture, TCPStream

# ---------- DNP3 CRC (CRC-16/DNP: poly 0x3D65, reflected, init 0, xorout 0xFFFF) ----------

def dnp3_crc(data):
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC     # 0xA6BC = bit-reflection of 0x3D65
            else:
                crc >>= 1
    crc ^= 0xFFFF
    return crc & 0xFFFF

def _crc2(b):
    c = dnp3_crc(b)
    return bytes([c & 0xFF, (c >> 8) & 0xFF])   # transmitted low byte first

# self-test against the CRC-16/DNP catalog check value
assert dnp3_crc(b"123456789") == 0xEA82, "DNP3 CRC self-test failed"

# ---------- data-link / transport framing ----------

def link_frame(ctrl, dest, src, userdata):
    """Wrap transport+application 'userdata' in DNP3 data-link framing w/ CRCs."""
    length = 5 + len(userdata)            # control + dest(2) + src(2) + userdata
    assert length <= 255
    header = bytes([0x05, 0x64, length, ctrl,
                    dest & 0xFF, (dest >> 8) & 0xFF,
                    src & 0xFF, (src >> 8) & 0xFF])
    out = header + _crc2(header)
    i = 0
    while i < len(userdata):
        chunk = userdata[i:i + 16]
        out += chunk + _crc2(chunk)
        i += 16
    return out

def transport(seq, fir=1, fin=1):
    return bytes([((fin & 1) << 7) | ((fir & 1) << 6) | (seq & 0x3F)])

def appctl(seq, fir=1, fin=1, con=0, uns=0):
    return ((fir & 1) << 7) | ((fin & 1) << 6) | ((con & 1) << 5) | ((uns & 1) << 4) | (seq & 0x0F)

CTRL_MASTER = 0xC3   # DIR=1, PRM=1, func=3 (unconfirmed user data)
CTRL_OUTSTN = 0x43   # DIR=0, PRM=1, func=3

def msg(ctrl, dest, src, tseq, ac, func, objects=b"", iin=None):
    app = bytes([ac, func])
    if iin is not None:
        app += bytes([iin[0] & 0xFF, iin[1] & 0xFF])   # IIN1, IIN2 (responses only)
    app += objects
    return link_frame(ctrl, dest, src, transport(tseq) + app)

# ---------- application objects ----------

def obj_class_poll():
    # READ g60 v2,v3,v4,v1 (Class 1,2,3,0) qualifier 0x06 = all objects
    return bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06, 60, 1, 0x06])

def obj_class0():
    return bytes([60, 1, 0x06])

def obj_binary_inputs(states, start=0):
    # g1v2 (binary input w/ flags); each point = flags octet, bit0 ONLINE, bit7 STATE
    hdr = bytes([1, 2, 0x00, start, start + len(states) - 1])
    body = bytes([0x01 | (0x80 if s else 0x00) for s in states])
    return hdr + body

def obj_analog_inputs(values, start=0):
    # g30v1 (32-bit analog input w/ flag); per point = flag octet + int32 LE
    hdr = bytes([30, 1, 0x00, start, start + len(values) - 1])
    body = b"".join(bytes([0x01]) + struct.pack("<i", v) for v in values)
    return hdr + body

def obj_counter(value, start=0):
    # g20v1 (32-bit counter w/ flag)
    hdr = bytes([20, 1, 0x00, start, start])
    return hdr + bytes([0x01]) + struct.pack("<I", value)

def obj_binary_event(index, state):
    # g2v1 binary input event, qualifier 0x17 = 1-byte index prefix + 1-byte count
    return bytes([2, 1, 0x17, 1, index, 0x01 | (0x80 if state else 0x00)])

def crob(index, control_code, count=1, on_ms=1000, off_ms=0, status=0):
    # g12v1 CROB, qualifier 0x17 (1-byte index prefix + 1-byte count)
    body = bytes([control_code, count]) + struct.pack("<I", on_ms) + struct.pack("<I", off_ms) + bytes([status])
    return bytes([12, 1, 0x17, 1, index]) + body

def obj_time_delay(ms):
    # g52v2 time delay fine (16-bit), qualifier 0x07 = 1-byte count
    return bytes([52, 2, 0x07, 1]) + struct.pack("<H", ms)

# CROB control codes: bits7-6 TCC (01=close,10=trip), bits3-0 op (1=pulse on)
CROB_CLOSE_PULSE = 0x41
CROB_TRIP_PULSE  = 0x81

# ---------- scenario ----------

def main():
    cap = Capture()
    master  = Host("10.20.0.5",  "02:00:00:00:00:05", "master")
    outstn  = Host("10.20.0.20", "02:00:00:00:00:20", "outstation")
    attacker = Host("10.20.0.66", "02:00:00:00:00:66", "attacker")
    M, O = 100, 10   # DNP3 link addresses

    # ===== master <-> outstation session =====
    s = TCPStream(cap, master, 52100, outstn, 20000, client_isn=1000, server_isn=700000)

    # 1) integrity poll: READ Class 1/2/3/0
    s.c2s(msg(CTRL_MASTER, O, M, 0, appctl(0), 0x01, obj_class_poll()))
    # 2) RESPONSE with binary inputs (breaker/switch status) + analog inputs
    resp1 = obj_binary_inputs([1, 1, 0, 0]) + obj_analog_inputs([13245, 452, 6001])
    s.s2c(msg(CTRL_OUTSTN, M, O, 0, appctl(0), 0x81, resp1, iin=(0x00, 0x00)))

    cap.gap(2.0)
    # 3) Class-0 static poll
    s.c2s(msg(CTRL_MASTER, O, M, 1, appctl(1), 0x01, obj_class0()))
    # 4) RESPONSE with binary + analog + counter
    resp2 = obj_binary_inputs([1, 1, 0, 0]) + obj_analog_inputs([13240, 455, 6000]) + obj_counter(148213)
    s.s2c(msg(CTRL_OUTSTN, M, O, 1, appctl(1), 0x81, resp2, iin=(0x00, 0x00)))

    cap.gap(3.5)
    # 5) UNSOLICITED_RESPONSE: breaker aux contact opened (binary input event)
    s.s2c(msg(CTRL_OUTSTN, M, O, 2, appctl(2, con=1, uns=1), 0x82,
              obj_binary_event(0, 0), iin=(0x02, 0x00)))   # IIN1.1 = Class 1 data available
    # 6) master CONFIRM
    s.c2s(msg(CTRL_MASTER, O, M, 2, appctl(2, con=0, uns=1), 0x00))

    cap.gap(2.5)
    # 7) SELECT breaker close (CROB) ... 8) outstation echoes (select ack)
    s.c2s(msg(CTRL_MASTER, O, M, 3, appctl(3), 0x03, crob(0, CROB_CLOSE_PULSE)))
    s.s2c(msg(CTRL_OUTSTN, M, O, 3, appctl(3), 0x81, crob(0, CROB_CLOSE_PULSE, status=0), iin=(0x00, 0x00)))
    # 9) OPERATE ... 10) outstation echoes (operate ack -> breaker closes)
    s.c2s(msg(CTRL_MASTER, O, M, 4, appctl(4), 0x04, crob(0, CROB_CLOSE_PULSE)))
    s.s2c(msg(CTRL_OUTSTN, M, O, 4, appctl(4), 0x81, crob(0, CROB_CLOSE_PULSE, status=0), iin=(0x00, 0x00)))

    cap.gap(4.0)

    # ===== rogue host session -- anomalies =====
    z = TCPStream(cap, attacker, 40666, outstn, 20000, client_isn=5000, server_isn=900000)
    # ANOMALY 1: unauthenticated DIRECT_OPERATE trip (spoofs master link addr 100)
    z.c2s(msg(CTRL_MASTER, O, M, 0, appctl(0), 0x05, crob(0, CROB_TRIP_PULSE)))
    z.s2c(msg(CTRL_OUTSTN, M, O, 0, appctl(0), 0x81, crob(0, CROB_TRIP_PULSE, status=0), iin=(0x00, 0x00)))
    cap.gap(1.5)
    # ANOMALY 2: COLD_RESTART (availability attack)
    z.c2s(msg(CTRL_MASTER, O, M, 1, appctl(1), 0x0D))
    z.s2c(msg(CTRL_OUTSTN, M, O, 1, appctl(1), 0x81, obj_time_delay(30000), iin=(0x80, 0x00)))  # IIN1.7 = device restart

    cap.gap(1.0)
    s.fin()

    out = "/root/icsnpp_kit/pcaps/dnp3_substation.pcap"
    cap.write(out)
    print("wrote", out, "frames:", len(cap.packets))

if __name__ == "__main__":
    main()
