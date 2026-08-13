"""
dnp3lib.py -- tiny, dependency-free DNP3 helper for the teaching lab.

Pure standard library so it runs in any python:3.x container. Implements the
DNP3 data-link CRC, framing, and just enough object building/parsing for a
master and outstation to hold a realistic conversation students can capture.

NOT a production stack -- it is deliberately small and readable. For a fuller
stack see dnp3-python (VOLTTRON) or opendnp3; see the lab README.
"""
import struct

# ---- CRC-16/DNP (poly 0x3D65, reflected, init 0, xorout 0xFFFF) ----
def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (c ^ 0xFFFF) & 0xFFFF

def _crc2(b):
    v = crc(b)
    return bytes([v & 0xFF, (v >> 8) & 0xFF])

# ---- framing ----
def link_frame(ctrl, dest, src, userdata):
    hdr = bytes([0x05, 0x64, 5 + len(userdata), ctrl,
                 dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    out = hdr + _crc2(hdr)
    for i in range(0, len(userdata), 16):
        chunk = userdata[i:i + 16]
        out += chunk + _crc2(chunk)
    return out

def transport(seq, fir=1, fin=1):
    return bytes([((fin & 1) << 7) | ((fir & 1) << 6) | (seq & 0x3F)])

def appctl(seq, fir=1, fin=1, con=0, uns=0):
    return ((fir & 1) << 7) | ((fin & 1) << 6) | ((con & 1) << 5) | ((uns & 1) << 4) | (seq & 0x0F)

CTRL_MASTER = 0xC3
CTRL_OUTSTN = 0x43

def msg(ctrl, dest, src, tseq, ac, func, objects=b"", iin=None):
    app = bytes([ac, func])
    if iin is not None:
        app += bytes([iin[0] & 0xFF, iin[1] & 0xFF])
    app += objects
    return link_frame(ctrl, dest, src, transport(tseq) + app)

# ---- objects ----
def obj_class_poll():
    return bytes([60, 2, 6, 60, 3, 6, 60, 4, 6, 60, 1, 6])

def obj_binary_inputs(states, start=0):
    hdr = bytes([1, 2, 0x00, start, start + len(states) - 1])
    return hdr + bytes([0x01 | (0x80 if s else 0) for s in states])

def obj_analog_inputs(values, start=0):
    hdr = bytes([30, 1, 0x00, start, start + len(values) - 1])
    return hdr + b"".join(bytes([0x01]) + struct.pack("<i", v) for v in values)

def crob(index, control_code, count=1, on_ms=1000, off_ms=0, status=0):
    body = bytes([control_code, count]) + struct.pack("<I", on_ms) + struct.pack("<I", off_ms) + bytes([status])
    return bytes([12, 1, 0x17, 1, index]) + body

def obj_time_delay(ms):
    return bytes([52, 2, 0x07, 1]) + struct.pack("<H", ms)

CROB_CLOSE_PULSE = 0x41
CROB_TRIP_PULSE = 0x81

FUNC = {0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE", 0x03: "SELECT", 0x04: "OPERATE",
        0x05: "DIRECT_OPERATE", 0x06: "DIRECT_OPERATE_NR", 0x0D: "COLD_RESTART",
        0x81: "RESPONSE", 0x82: "UNSOLICITED_RESPONSE"}

# ---- read one frame from a socket ----
def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def read_frame(sock):
    """Return (ctrl, dest, src, userdata) or None on close."""
    head = recvall(sock, 10)                 # 8-byte header + 2-byte CRC
    if not head or head[0:2] != b"\x05\x64":
        return None
    length = head[2]
    ctrl = head[3]
    dest = head[4] | (head[5] << 8)
    src = head[6] | (head[7] << 8)
    user_len = length - 5
    userdata = b""
    remaining = user_len
    while remaining > 0:
        n = min(16, remaining)
        block = recvall(sock, n + 2)          # data + CRC
        if not block:
            return None
        userdata += block[:n]
        remaining -= n
    return ctrl, dest, src, userdata

def parse_app(userdata):
    """Return (app_control, func, func_name, remaining_objects_bytes)."""
    if len(userdata) < 3:
        return None
    ac = userdata[1]           # userdata[0] is the transport octet
    func = userdata[2]
    return ac, func, FUNC.get(func, f"0x{func:02x}"), userdata[3:]
