"""
pcap_util.py  -- small helper for crafting clean, deterministic teaching PCAPs.

Builds full Ethernet/IPv4/TCP frames with correct sequence/acknowledgement
numbers so the resulting capture opens in Wireshark with NO retransmission or
"ACKed unseen segment" warnings, and "Follow TCP Stream" works cleanly.

Timestamps are deterministic (fixed base epoch) so frame timing is stable
across rebuilds -- good for courseware that references specific frames.
"""
from scapy.all import Ether, IP, TCP, Raw, wrpcap

# Deterministic base time: 2026-08-13 14:00:00 UTC (epoch seconds).
BASE_TIME = 1755093600.0


class Host:
    """A network endpoint (IP + MAC)."""
    def __init__(self, ip, mac, name=""):
        self.ip = ip
        self.mac = mac
        self.name = name


class Capture:
    """Accumulates packets with a monotonic clock, then writes a pcap."""
    def __init__(self, base_time=BASE_TIME):
        self.packets = []
        self.t = base_time

    def gap(self, seconds):
        """Advance the clock (models idle time between logical phases)."""
        self.t += seconds

    def add(self, pkt):
        pkt.time = self.t
        self.t += 0.0008  # ~0.8 ms between adjacent frames
        self.packets.append(pkt)
        return pkt

    def write(self, path):
        wrpcap(path, self.packets)
        return path


class TCPStream:
    """
    One TCP connection between a client and a server, with correct seq/ack
    bookkeeping. Emits the 3-way handshake on construction.
    """
    def __init__(self, cap, client, cport, server, sport,
                 client_isn=1000, server_isn=500000, win=64240):
        self.cap = cap
        self.c = client
        self.s = server
        self.cport = cport
        self.sport = sport
        self.cseq = client_isn      # next seq the client will send
        self.sseq = server_isn      # next seq the server will send
        self.win = win
        self._handshake()

    def _emit(self, src, dst, sport, dport, flags, seq, ack, payload=b""):
        p = (Ether(src=src.mac, dst=dst.mac) /
             IP(src=src.ip, dst=dst.ip, ttl=64) /
             TCP(sport=sport, dport=dport, flags=flags, seq=seq,
                 ack=ack, window=self.win))
        if payload:
            p = p / Raw(load=payload)
        return self.cap.add(p)

    def _handshake(self):
        # SYN  (client -> server)
        self._emit(self.c, self.s, self.cport, self.sport, "S", self.cseq, 0)
        self.cseq += 1
        # SYN,ACK  (server -> client)
        self._emit(self.s, self.c, self.sport, self.cport, "SA", self.sseq, self.cseq)
        self.sseq += 1
        # ACK  (client -> server)
        self._emit(self.c, self.s, self.cport, self.sport, "A", self.cseq, self.sseq)

    def c2s(self, payload, ack=True):
        """Client -> server application data (PSH,ACK); optional server ACK."""
        p = self._emit(self.c, self.s, self.cport, self.sport, "PA",
                       self.cseq, self.sseq, payload)
        self.cseq += len(payload)
        if ack:
            self._emit(self.s, self.c, self.sport, self.cport, "A", self.sseq, self.cseq)
        return p

    def s2c(self, payload, ack=True):
        """Server -> client application data (PSH,ACK); optional client ACK."""
        p = self._emit(self.s, self.c, self.sport, self.cport, "PA",
                       self.sseq, self.cseq, payload)
        self.sseq += len(payload)
        if ack:
            self._emit(self.c, self.s, self.cport, self.sport, "A", self.cseq, self.sseq)
        return p

    def fin(self):
        """Graceful close initiated by the client."""
        self._emit(self.c, self.s, self.cport, self.sport, "FA", self.cseq, self.sseq)
        self.cseq += 1
        self._emit(self.s, self.c, self.sport, self.cport, "FA", self.sseq, self.cseq)
        self.sseq += 1
        self._emit(self.c, self.s, self.cport, self.sport, "A", self.cseq, self.sseq)
