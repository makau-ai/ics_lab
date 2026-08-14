"""
dnp3lib.py -- tiny, dependency-free DNP3 helper (TWIN edition).

Extends the base lab library with exactly what the wet-well twin needs:
  * g41 Analog Output Block builder/parser (setpoint WRITE -- the Oldsmar move)
  * g40 Analog Output Status builder (report setpoints back)
  * an UNSOLICITED (0x82) helper contract (via appctl(uns=1) + func 0x82)
  * the HARDEN=1 primitives: a SAv5 aggressive-mode HMAC (teaching approximation)
    and the object/range + link-address allow-list definitions.

Everything else is byte-for-byte the base lab library so master.py / outstation.py
keep working unchanged. Pure standard library; readable, ICSNPP-parseable on the
wire (plaintext), NOT a production stack. See the lab README for opendnp3 / dnp3-python.
"""
import hashlib
import hmac
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

def obj_analog_output_status(values, start=0):
    """g40 v1 (32-bit analog output status) -- report current setpoints back."""
    hdr = bytes([40, 1, 0x00, start, start + len(values) - 1])
    return hdr + b"".join(bytes([0x01]) + struct.pack("<i", v) for v in values)

def obj_analog_output(index, value, status=0):
    """g41 v1 (32-bit Analog Output Block) WRITE -- setpoint change (Oldsmar move).

    Qualifier 0x17 = 1-byte count + 1-byte index prefix, count 1.
    Body = <i value><B status>.
    """
    body = struct.pack("<i", int(value)) + bytes([status & 0xFF])
    return bytes([41, 1, 0x17, 1, index & 0xFF]) + body

def crob(index, control_code, count=1, on_ms=1000, off_ms=0, status=0):
    body = bytes([control_code, count]) + struct.pack("<I", on_ms) + struct.pack("<I", off_ms) + bytes([status])
    return bytes([12, 1, 0x17, 1, index]) + body

def obj_time_delay(ms):
    return bytes([52, 2, 0x07, 1]) + struct.pack("<H", ms)

CROB_CLOSE_PULSE = 0x41   # start pump  (CLOSE / latch-on)
CROB_TRIP_PULSE = 0x81    # stop pump   (TRIP / latch-off)

FUNC = {0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE", 0x03: "SELECT", 0x04: "OPERATE",
        0x05: "DIRECT_OPERATE", 0x06: "DIRECT_OPERATE_NR", 0x0D: "COLD_RESTART",
        0x81: "RESPONSE", 0x82: "UNSOLICITED_RESPONSE"}

# ---- DNP3 water point map (mirrors DIGITAL_TWIN 5) ----
BI_P1, BI_P2, BI_HLA, BI_FAULT = 0, 1, 2, 3     # g1 binary inputs
AI_LEVEL, AI_FLOW, AI_PSI = 0, 1, 2             # g30 analog inputs (index)
CROB_P1, CROB_P2 = 0, 1                         # g12v1 control indices
AO_LEAD_START, AO_STOP = 0, 1                   # g41 analog output (setpoint) indices

# ---- HARDEN=1 primitives (SEC layer -- teaching approximations) ----
# SAv5 aggressive-mode HMAC: the outstation executes a control only if the frame
# carries a valid HMAC over the app-data. This is a truncated HMAC-SHA256 over a
# pre-shared key -- a deliberate teaching stand-in for the full opendnp3 SA stack
# (see CIE_HARDENING 7 "scoping honesty"). Plaintext stays default so ICSNPP can
# still parse; the tag is appended only on hardened control frames.
SAV5_KEY = b"twin-preshared-sav5-key-change-me"
SAV5_TAG_LEN = 8

def sav5_tag(appdata, key=SAV5_KEY):
    return hmac.new(key, appdata, hashlib.sha256).digest()[:SAV5_TAG_LEN]

def sav5_check(appdata, tag, key=SAV5_KEY):
    try:
        return hmac.compare_digest(sav5_tag(appdata, key), tag)
    except (TypeError, ValueError):
        return False

# Object/range allow-list: the exact point map the RTU is allowed to speak/accept
# (group, variation) -> set of legal indices. Anything else is dropped + logged.
ALLOWED_OBJECTS = {
    (12, 1): {CROB_P1, CROB_P2},      # CROB controls
    (41, 1): {AO_LEAD_START, AO_STOP},  # analog output setpoints
}

# DNP3 link-address allow-list: the only source address the outstation answers.
ALLOWED_MASTER_ADDRS = {100}

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

def parse_g41_write(objs):
    """Parse a g41 v1 Analog Output Block write -> (index, value) or None.

    Expects [41, 1, 0x17, count, index, <i value>, <B status>]. Returns the
    first point only (the twin writes one setpoint per frame).
    """
    if len(objs) < 5 or objs[0] != 41 or objs[1] != 1:
        return None
    index = objs[4]
    if len(objs) < 5 + 4:
        return None
    value = struct.unpack("<i", bytes(objs[5:9]))[0]
    return index, value

def crob_index_code(objs):
    """From a CROB control frame body -> (index, control_code) or (None, None)."""
    # [12,1,0x17,count,index, control_code, count8, on(4), off(4), status]
    if len(objs) < 6 or objs[0] != 12:
        return None, None
    return objs[4], objs[5]
