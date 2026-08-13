"""
build_mqtt.py -- craft a curated MQTT (v3.1.1) teaching capture on TCP/1883.

Scenario: a small water/utility plant telemetry deployment.
  broker    10.10.20.10:1883   Mosquitto broker
  hmi       10.10.20.30        SCADA/HMI dashboard (subscriber, max QoS 1)
  sensor    10.10.20.7         field telemetry sensor (publisher, uses LWT)
  attacker  10.10.20.66        rogue host on the OT LAN

Benign traffic: CONNECT/CONNACK (cleartext creds), SUBSCRIBE/SUBACK, a QoS-0
telemetry PUBLISH (fan-out at QoS 0), a QoS-1 telemetry PUBLISH (acknowledged
both hops), and a keepalive PING. Labeled anomalies: anonymous CONNECT,
'#' wildcard subscribe (eavesdrop), unauthorized command PUBLISH.

QoS note: delivery QoS to a subscriber is min(publish QoS, subscription max QoS)
per MQTT 3.1.1 [MQTT-3.8.4-8]; a broker may downgrade but never upgrade QoS.
"""
from pcap_util import Host, Capture, TCPStream

# ---------- MQTT 3.1.1 control-packet builders ----------

def rlen(n):
    """Remaining Length variable-byte integer encoding."""
    out = b""
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out += bytes([d])
        if n == 0:
            return out

def mstr(s):
    """UTF-8 string with 2-byte big-endian length prefix."""
    b = s.encode() if isinstance(s, str) else s
    return bytes([(len(b) >> 8) & 0xFF, len(b) & 0xFF]) + b

def connect(client_id, keepalive=60, username=None, password=None, clean=True,
            will_topic=None, will_payload=None, will_qos=0, will_retain=False):
    flags = 0
    if username is not None:  flags |= 0x80
    if password is not None:  flags |= 0x40
    if will_retain:           flags |= 0x20
    flags |= (will_qos & 0x03) << 3
    if will_topic is not None: flags |= 0x04
    if clean:                 flags |= 0x02
    vh = mstr("MQTT") + bytes([0x04]) + bytes([flags]) + bytes([(keepalive >> 8) & 0xFF, keepalive & 0xFF])
    payload = mstr(client_id)
    if will_topic is not None:
        payload += mstr(will_topic) + mstr(will_payload)
    if username is not None:
        payload += mstr(username)
    if password is not None:
        payload += mstr(password)
    body = vh + payload
    return bytes([0x10]) + rlen(len(body)) + body

def connack(rc=0, session_present=False):
    return bytes([0x20, 0x02, 0x01 if session_present else 0x00, rc])

def subscribe(packet_id, topics):     # topics: list of (topic, qos)
    vh = bytes([(packet_id >> 8) & 0xFF, packet_id & 0xFF])
    payload = b""
    for t, q in topics:
        payload += mstr(t) + bytes([q & 0x03])
    body = vh + payload
    return bytes([0x82]) + rlen(len(body)) + body   # 0x82: SUBSCRIBE, reserved flags 0b0010

def suback(packet_id, codes):
    body = bytes([(packet_id >> 8) & 0xFF, packet_id & 0xFF]) + bytes(codes)
    return bytes([0x90]) + rlen(len(body)) + body

def publish(topic, payload, qos=0, packet_id=None, retain=False, dup=False):
    b1 = 0x30 | (0x08 if dup else 0) | ((qos & 0x03) << 1) | (0x01 if retain else 0)
    vh = mstr(topic)
    if qos > 0:
        vh += bytes([(packet_id >> 8) & 0xFF, packet_id & 0xFF])
    pl = payload.encode() if isinstance(payload, str) else payload
    body = vh + pl
    return bytes([b1]) + rlen(len(body)) + body

def puback(packet_id):
    return bytes([0x40, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF])

def pingreq():    return bytes([0xC0, 0x00])
def pingresp():   return bytes([0xD0, 0x00])
def disconnect(): return bytes([0xE0, 0x00])

# ---------- scenario ----------

def main():
    cap = Capture()
    broker   = Host("10.10.20.10", "02:00:00:00:10:10", "broker")
    hmi      = Host("10.10.20.30", "02:00:00:00:20:30", "hmi")
    sensor   = Host("10.10.20.7",  "02:00:00:00:20:07", "sensor")
    attacker = Host("10.10.20.66", "02:00:00:00:20:66", "attacker")

    # ===== Session A: HMI dashboard connects and subscribes (max QoS 1) =====
    a = TCPStream(cap, hmi, 49512, broker, 1883, client_isn=1000, server_isn=3001000)
    a.c2s(connect("hmi-scada-01", keepalive=60,
                  username="hmi_operator", password="Plant!ntel2024"))   # cleartext creds
    a.s2c(connack(rc=0))
    a.c2s(subscribe(1, [("plant/+/telemetry", 1)]))                      # single-level wildcard, max QoS 1
    a.s2c(suback(1, [0x01]))                                             # granted QoS 1

    cap.gap(0.35)

    # ===== Session B: field sensor connects (with Last Will) and publishes =====
    b = TCPStream(cap, sensor, 50120, broker, 1883, client_isn=2000, server_isn=3102000)
    b.c2s(connect("field-sensor-07", keepalive=30,
                  username="sensor_svc", password="s3ns0r-pw",
                  will_topic="plant/tank1/status", will_payload="offline", will_qos=1))
    b.s2c(connack(rc=0))

    # reading #1 at QoS 0 (fire-and-forget) -> broker delivers to HMI at QoS 0 (min(0,1)=0)
    r1 = '{"level_pct":72.4,"temp_c":21.6,"flow_lpm":11.8}'
    b.c2s(publish("plant/tank1/telemetry", r1, qos=0))
    a.s2c(publish("plant/tank1/telemetry", r1, qos=0))            # broker -> HMI, QoS 0, no PUBACK

    cap.gap(0.20)
    # reading #2 at QoS 1 -> acknowledged on both hops
    r2 = '{"level_pct":73.1,"temp_c":21.7,"flow_lpm":12.0}'
    b.c2s(publish("plant/tank1/telemetry", r2, qos=1, packet_id=15))
    b.s2c(puback(15))                                            # broker -> sensor PUBACK
    a.s2c(publish("plant/tank1/telemetry", r2, qos=1, packet_id=41))  # broker -> HMI, QoS 1
    a.c2s(puback(41))                                            # HMI -> broker PUBACK

    # keepalive
    cap.gap(0.30)
    b.c2s(pingreq())
    b.s2c(pingresp())

    cap.gap(0.40)

    # ===== Session C: rogue host -- anomalies =====
    c = TCPStream(cap, attacker, 51888, broker, 1883, client_isn=3000, server_isn=3203000)
    # ANOMALY 1: anonymous CONNECT (no username/password) accepted -> allow_anonymous misconfig
    c.c2s(connect("mqtt-explorer-x", keepalive=60, clean=True))
    c.s2c(connack(rc=0))
    # ANOMALY 2: subscribe to '#' -- multi-level wildcard, receives every topic on the broker
    c.c2s(subscribe(1, [("#", 0)]))
    c.s2c(suback(1, [0x00]))
    # sensor reading #3 at QoS 0 -> broker leaks it to the HMI AND to the eavesdropper
    cap.gap(0.15)
    r3 = '{"level_pct":73.6,"temp_c":21.7,"flow_lpm":12.1}'
    b.c2s(publish("plant/tank1/telemetry", r3, qos=0))
    a.s2c(publish("plant/tank1/telemetry", r3, qos=0))           # broker -> HMI (QoS 0)
    c.s2c(publish("plant/tank1/telemetry", r3, qos=0))           # broker -> attacker (data leak)
    # ANOMALY 3: unauthorized command PUBLISH (no topic ACL stops it)
    cap.gap(0.20)
    c.c2s(publish("plant/tank1/command",
                  '{"actuator":"pump1","cmd":"START","valve":"open"}', qos=0))
    c.c2s(disconnect(), ack=True)

    cap.gap(0.30)
    # tidy teardown of the legitimate sessions
    b.fin()
    a.fin()

    out = "/root/icsnpp_kit/pcaps/mqtt_iot_telemetry.pcap"
    cap.write(out)
    print("wrote", out, "frames:", len(cap.packets))

if __name__ == "__main__":
    main()
