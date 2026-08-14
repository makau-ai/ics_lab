"""
modbus_tcp.py -- tiny, dependency-free Modbus/TCP for the digital twin.

Pure Python standard library (no pymodbus), same philosophy as the kit's
dnp3lib.py: small enough to read, real enough to capture. Implements the MBAP
header + the function codes the twin actually uses, on both sides:

  * ModbusServer  -- used by plant-sim (the wet-well physics is the Modbus slave
                     that OpenPLC's "slave devices" master polls).
  * ModbusClient  -- used by dnp3-gw and iiot-gw (they poll OpenPLC:502 for the
                     live process image).

Wire format is standard Modbus/TCP, so it interoperates with OpenPLC's own
Modbus master/server and is fully parseable in Wireshark (display filter: mbtcp).

Supported function codes:
  0x01 Read Coils            0x02 Read Discrete Inputs
  0x03 Read Holding Regs     0x04 Read Input Registers
  0x05 Write Single Coil     0x06 Write Single Register
  0x0F Write Multiple Coils  0x10 Write Multiple Registers

NOT a production stack -- deliberately minimal and readable for teaching.
"""
import socket
import struct
import threading

# ---- Modbus exception codes ----
EX_ILLEGAL_FUNCTION = 0x01
EX_ILLEGAL_ADDRESS = 0x02
EX_ILLEGAL_VALUE = 0x03


class Datastore:
    """Thread-safe Modbus data model (0-based addressing).

    Four separate address spaces, exactly as Modbus defines them:
      coils            -- read/write bits   (FC 01 / 05 / 0F)
      discrete_inputs  -- read-only bits    (FC 02)
      holding_registers-- read/write words  (FC 03 / 06 / 10)
      input_registers  -- read-only words   (FC 04)
    """

    def __init__(self, coils=64, discrete_inputs=64, holding=128, input_regs=128):
        self.lock = threading.Lock()
        self.coils = [False] * coils
        self.discrete_inputs = [False] * discrete_inputs
        self.holding_registers = [0] * holding
        self.input_registers = [0] * input_regs

    # -- convenience helpers used by plant_sim.py (all take the lock) --
    def set_input_register(self, addr, value):
        with self.lock:
            self.input_registers[addr] = int(value) & 0xFFFF

    def set_discrete_input(self, addr, value):
        with self.lock:
            self.discrete_inputs[addr] = bool(value)

    def get_coil(self, addr):
        with self.lock:
            return self.coils[addr]

    def get_holding(self, addr):
        with self.lock:
            return self.holding_registers[addr]

    def set_holding(self, addr, value):
        with self.lock:
            self.holding_registers[addr] = int(value) & 0xFFFF


def _bits_to_bytes(bits):
    """Pack a list of bools LSB-first into Modbus response bytes."""
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= (1 << (i % 8))
    return bytes(out)


def _bytes_to_bits(data, count):
    bits = []
    for i in range(count):
        bits.append(bool(data[i // 8] & (1 << (i % 8))))
    return bits


class ModbusServer:
    """Threaded Modbus/TCP server backed by a Datastore."""

    def __init__(self, store, host="0.0.0.0", port=502):
        self.store = store
        self.host = host
        self.port = port
        self._sock = None

    def serve_forever(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        print(f"[modbus] slave listening on {self.host}:{self.port}", flush=True)
        while True:
            conn, peer = self._sock.accept()
            threading.Thread(target=self._handle, args=(conn, peer), daemon=True).start()

    def _handle(self, conn, peer):
        try:
            while True:
                head = _recvall(conn, 7)          # MBAP header
                if not head:
                    break
                txn, proto, length, unit = struct.unpack(">HHHB", head)
                pdu = _recvall(conn, length - 1)   # length counts unit + PDU
                if pdu is None:
                    break
                resp_pdu = self._dispatch(pdu)
                mbap = struct.pack(">HHHB", txn, 0, len(resp_pdu) + 1, unit)
                conn.sendall(mbap + resp_pdu)
        except (ConnectionError, OSError):
            pass
        finally:
            conn.close()

    def _dispatch(self, pdu):
        fc = pdu[0]
        try:
            if fc in (0x01, 0x02):                 # read bits
                start, qty = struct.unpack(">HH", pdu[1:5])
                src = self.store.coils if fc == 0x01 else self.store.discrete_inputs
                with self.store.lock:
                    if start + qty > len(src):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    bits = src[start:start + qty]
                body = _bits_to_bytes(bits)
                return bytes([fc, len(body)]) + body
            if fc in (0x03, 0x04):                 # read words
                start, qty = struct.unpack(">HH", pdu[1:5])
                src = self.store.holding_registers if fc == 0x03 else self.store.input_registers
                with self.store.lock:
                    if start + qty > len(src):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    regs = src[start:start + qty]
                body = b"".join(struct.pack(">H", r & 0xFFFF) for r in regs)
                return bytes([fc, len(body)]) + body
            if fc == 0x05:                         # write single coil
                addr, val = struct.unpack(">HH", pdu[1:5])
                with self.store.lock:
                    if addr >= len(self.store.coils):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    self.store.coils[addr] = (val == 0xFF00)
                return pdu[:5]
            if fc == 0x06:                         # write single register
                addr, val = struct.unpack(">HH", pdu[1:5])
                with self.store.lock:
                    if addr >= len(self.store.holding_registers):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    self.store.holding_registers[addr] = val & 0xFFFF
                return pdu[:5]
            if fc == 0x0F:                         # write multiple coils
                start, qty = struct.unpack(">HH", pdu[1:5])
                data = pdu[6:]
                bits = _bytes_to_bits(data, qty)
                with self.store.lock:
                    if start + qty > len(self.store.coils):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    for i, b in enumerate(bits):
                        self.store.coils[start + i] = b
                return pdu[:5]
            if fc == 0x10:                         # write multiple registers
                start, qty = struct.unpack(">HH", pdu[1:5])
                data = pdu[6:]
                with self.store.lock:
                    if start + qty > len(self.store.holding_registers):
                        return self._exc(fc, EX_ILLEGAL_ADDRESS)
                    for i in range(qty):
                        self.store.holding_registers[start + i] = struct.unpack(
                            ">H", data[i * 2:i * 2 + 2])[0]
                return struct.pack(">HH", start, qty)
            return self._exc(fc, EX_ILLEGAL_FUNCTION)
        except (struct.error, IndexError):
            return self._exc(fc, EX_ILLEGAL_VALUE)

    @staticmethod
    def _exc(fc, code):
        return bytes([fc | 0x80, code])


class ModbusClient:
    """Minimal Modbus/TCP client (used by dnp3-gw and iiot-gw)."""

    def __init__(self, host, port=502, unit=1, timeout=3.0):
        self.host = host
        self.port = port
        self.unit = unit
        self.timeout = timeout
        self._sock = None
        self._txn = 0

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.host, self.port))

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _txn_next(self):
        self._txn = (self._txn + 1) & 0xFFFF
        return self._txn

    def _request(self, pdu):
        if self._sock is None:
            self.connect()
        txn = self._txn_next()
        mbap = struct.pack(">HHHB", txn, 0, len(pdu) + 1, self.unit)
        self._sock.sendall(mbap + pdu)
        head = _recvall(self._sock, 7)
        if not head:
            raise ConnectionError("modbus: no response header")
        rtxn, proto, length, unit = struct.unpack(">HHHB", head)
        body = _recvall(self._sock, length - 1)
        if body is None:
            raise ConnectionError("modbus: short response")
        if body[0] & 0x80:
            raise IOError(f"modbus exception fc=0x{body[0] & 0x7f:02x} code={body[1]}")
        return body

    # -- reads --
    def read_input_registers(self, start, qty):
        body = self._request(struct.pack(">BHH", 0x04, start, qty))
        n = body[1]
        return list(struct.unpack(">" + "H" * (n // 2), body[2:2 + n]))

    def read_holding_registers(self, start, qty):
        body = self._request(struct.pack(">BHH", 0x03, start, qty))
        n = body[1]
        return list(struct.unpack(">" + "H" * (n // 2), body[2:2 + n]))

    def read_discrete_inputs(self, start, qty):
        body = self._request(struct.pack(">BHH", 0x02, start, qty))
        return _bytes_to_bits(body[2:], qty)

    def read_coils(self, start, qty):
        body = self._request(struct.pack(">BHH", 0x01, start, qty))
        return _bytes_to_bits(body[2:], qty)

    # -- writes --
    def write_coil(self, addr, value):
        val = 0xFF00 if value else 0x0000
        self._request(struct.pack(">BHH", 0x05, addr, val))

    def write_register(self, addr, value):
        self._request(struct.pack(">BHH", 0x06, addr, int(value) & 0xFFFF))


def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None if not buf else buf
        buf += chunk
    return buf
