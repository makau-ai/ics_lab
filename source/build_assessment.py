# -*- coding: utf-8 -*-
"""
build_assessment.py -- craft two UNSEEN assessment captures (different techniques
than the teaching pcaps), per the instructional-design spec.

  dnp3_assessment.pcap  -- "Two masters, one lie": a spoofed UNSOLICITED_RESPONSE
                           feeding false breaker/frequency status, amid traffic
                           from TWO legitimate masters (T0856 Spoof Reporting Msg).
  mqtt_assessment.pcap  -- "The broker remembers": retained-message harvest +
                           a retained command injection (RETAIN abuse).

These are graded on unseen material — students have not walked these frames.
"""
import struct
from pcap_util import Host, Capture, TCPStream
import build_dnp3 as bd
import build_mqtt as bm


# ---------- extra DNP3 object: 16-bit analog input event (g32v2) ----------
def obj_analog_event16(index, value):
    return bytes([32, 2, 0x17, 1, index, 0x01]) + struct.pack("<h", value)


def build_dnp3_assessment():
    cap = Capture()
    m1 = Host("10.30.0.5",  "02:00:00:00:30:05", "master1")   # primary master, link 100
    m2 = Host("10.30.0.6",  "02:00:00:00:30:06", "master2")   # secondary read-only, link 101
    os_ = Host("10.30.0.20", "02:00:00:00:30:20", "outstation")  # link 10
    rogue = Host("10.30.0.66", "02:00:00:00:30:66", "rogue")
    M1, M2, OS = 100, 101, 10

    # Stream A: M1 (client) <-> OS (server:20000) — poll, response, GENUINE unsolicited, confirm
    a = TCPStream(cap, m1, 52101, os_, 20000, client_isn=1000, server_isn=400000)
    a.c2s(bd.msg(bd.CTRL_MASTER, OS, M1, 0, bd.appctl(0), 0x01, bd.obj_class_poll()))
    a.s2c(bd.msg(bd.CTRL_OUTSTN, M1, OS, 0, bd.appctl(0), 0x81,
                 bd.obj_binary_inputs([1, 1, 0, 0]) + bd.obj_analog_inputs([13800, 420, 6000]),
                 iin=(0x00, 0x00)))
    cap.gap(1.5)
    a.c2s(bd.msg(bd.CTRL_MASTER, OS, M1, 1, bd.appctl(1), 0x01, bd.obj_class0()))
    a.s2c(bd.msg(bd.CTRL_OUTSTN, M1, OS, 1, bd.appctl(1), 0x81,
                 bd.obj_binary_inputs([1, 1, 0, 0]) + bd.obj_analog_inputs([13802, 419, 6000]),
                 iin=(0x00, 0x00)))
    cap.gap(2.0)
    # GENUINE unsolicited: from the real OS (IP 10.30.0.20, link 10) — disconnect switch opens
    a.s2c(bd.msg(bd.CTRL_OUTSTN, M1, OS, 2, bd.appctl(2, con=1, uns=1), 0x82,
                 bd.obj_binary_event(1, 0), iin=(0x02, 0x00)))
    a.c2s(bd.msg(bd.CTRL_MASTER, OS, M1, 2, bd.appctl(2, con=0, uns=1), 0x00))

    cap.gap(1.0)
    # Stream B: M2 (secondary, link 101) read-only polls
    b = TCPStream(cap, m2, 52102, os_, 20000, client_isn=2000, server_isn=410000)
    b.c2s(bd.msg(bd.CTRL_MASTER, OS, M2, 0, bd.appctl(0), 0x01, bd.obj_class0()))
    b.s2c(bd.msg(bd.CTRL_OUTSTN, M2, OS, 0, bd.appctl(0), 0x81,
                 bd.obj_binary_inputs([1, 1, 0, 0]) + bd.obj_analog_inputs([13801, 421, 6000]),
                 iin=(0x00, 0x00)))

    cap.gap(1.5)
    # THE INJECTION: rogue connects to M1's DNP3 port (dial-in model) and sends a SPOOFED
    # unsolicited response — IP src 10.30.0.66, but DNP3 link src forged to 10 (the outstation).
    # False data: breaker (point 0) = 0 (falsely "tripped") + frequency event 58.50 Hz.
    z = TCPStream(cap, rogue, 40777, m1, 20000, client_isn=3000, server_isn=420000)
    z.c2s(bd.msg(bd.CTRL_OUTSTN, M1, OS, 3, bd.appctl(3, con=1, uns=1), 0x82,
                 bd.obj_binary_event(0, 0) + obj_analog_event16(2, 5850), iin=(0x02, 0x00)))

    cap.gap(0.5)
    a.fin()
    out = "/root/icsnpp_kit/pcaps/dnp3_assessment.pcap"
    cap.write(out)
    return out, len(cap.packets)


def build_mqtt_assessment():
    cap = Capture()
    broker = Host("10.40.0.10", "02:00:00:00:40:10", "broker")
    hmi = Host("10.40.0.30", "02:00:00:00:40:30", "hmi")
    s1 = Host("10.40.0.7", "02:00:00:00:40:07", "sensor1")
    s2 = Host("10.40.0.8", "02:00:00:00:40:08", "sensor2")
    ctl = Host("10.40.0.9", "02:00:00:00:40:09", "controller")
    rogue = Host("10.40.0.66", "02:00:00:00:40:66", "rogue")

    # HMI subscribes plant/#
    h = TCPStream(cap, hmi, 49001, broker, 1883, client_isn=1000, server_isn=500000)
    h.c2s(bm.connect("hmi-line", keepalive=60, username="hmi_operator", password="Plant!ntel2024"))
    h.s2c(bm.connack(rc=0))
    h.c2s(bm.subscribe(1, [("plant/#", 1)]))
    h.s2c(bm.suback(1, [0x01]))

    cap.gap(0.2)
    # Controller publishes THREE retained messages (config, command=STOP, site info)
    c = TCPStream(cap, ctl, 49002, broker, 1883, client_isn=2000, server_isn=510000)
    c.c2s(bm.connect("plc-line1", keepalive=60, username="plc_svc", password="plc-pw"))
    c.s2c(bm.connack(rc=0))
    c.c2s(bm.publish("plant/line1/config", '{"fw":"1.4.2","mode":"auto","hi_setpoint":80}', qos=0, retain=True))
    c.c2s(bm.publish("plant/line1/command", '{"actuator":"pump1","cmd":"STOP"}', qos=0, retain=True))
    c.c2s(bm.publish("plant/site/info", '{"gw":"edge-gw-3","mqtt_user":"svc_ingest"}', qos=0, retain=True))

    cap.gap(0.2)
    # Sensors publish live telemetry (retain 0); broker fans out to HMI
    s = TCPStream(cap, s1, 49003, broker, 1883, client_isn=3000, server_isn=520000)
    s.c2s(bm.connect("line1-sensor", keepalive=30, username="sensor_svc", password="s3ns0r-pw"))
    s.s2c(bm.connack(rc=0))
    s.c2s(bm.publish("plant/line1/telemetry", '{"level_pct":64.2,"temp_c":22.1}', qos=0))
    h.s2c(bm.publish("plant/line1/telemetry", '{"level_pct":64.2,"temp_c":22.1}', qos=0))

    cap.gap(0.4)
    # THE INTRUSION: rogue connects anonymously, subscribes '#', HARVESTS retained msgs, then injects a retained command
    z = TCPStream(cap, rogue, 51888, broker, 1883, client_isn=4000, server_isn=530000)
    z.c2s(bm.connect("mqtt-recon", keepalive=60, clean=True))          # anonymous
    z.s2c(bm.connack(rc=0))                                            # accepted
    z.c2s(bm.subscribe(1, [("#", 0)]))
    z.s2c(bm.suback(1, [0x00]))
    # broker immediately delivers the THREE RETAINED messages (retain flag = 1)
    z.s2c(bm.publish("plant/line1/config", '{"fw":"1.4.2","mode":"auto","hi_setpoint":80}', qos=0, retain=True))
    z.s2c(bm.publish("plant/line1/command", '{"actuator":"pump1","cmd":"STOP"}', qos=0, retain=True))
    z.s2c(bm.publish("plant/site/info", '{"gw":"edge-gw-3","mqtt_user":"svc_ingest"}', qos=0, retain=True))
    cap.gap(0.2)
    # live telemetry also fans out to the rogue (retain 0)
    s.c2s(bm.publish("plant/line1/telemetry", '{"level_pct":64.5,"temp_c":22.1}', qos=0))
    z.s2c(bm.publish("plant/line1/telemetry", '{"level_pct":64.5,"temp_c":22.1}', qos=0))
    cap.gap(0.3)
    # THE INJECTION: rogue publishes a RETAINED command (persists, replaces the legit STOP)
    z.c2s(bm.publish("plant/line1/command", '{"actuator":"pump1","cmd":"START","valve":"open"}', qos=0, retain=True))
    z.c2s(bm.disconnect(), ack=True)

    cap.gap(0.3)
    s.fin()
    h.fin()
    out = "/root/icsnpp_kit/pcaps/mqtt_assessment.pcap"
    cap.write(out)
    return out, len(cap.packets)


if __name__ == "__main__":
    for fn, n in [build_dnp3_assessment(), build_mqtt_assessment()]:
        print("wrote", fn, "frames:", n)
