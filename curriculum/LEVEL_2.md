# Level 2 — What kind of messages?

*Message types & the request/response rhythm — the envelope*

**Difficulty:** Introductory &nbsp;·&nbsp; **Time:** ~25 min &nbsp;·&nbsp; **Prerequisite:** Level 1.

**Goal.** Classify the control packets / function codes and see the protocol's rhythm — still on the surface, not yet inside the fields.

## What you'll be able to do

- Filter to a single protocol and read the Info column.
- Count the message types (MQTT control packets; DNP3 function codes).
- Tell request from response, and spot the control (write) messages among the reads.

## Background

Every protocol has a small vocabulary of message types. MQTT: CONNECT/CONNACK, SUBSCRIBE/SUBACK, PUBLISH/PUBACK, PINGREQ/PINGRESP, DISCONNECT. DNP3: READ, RESPONSE, UNSOLICITED RESPONSE, SELECT, OPERATE, DIRECT OPERATE, COLD RESTART, CONFIRM. Learn to count them — anomalies often show up as the *wrong type* in the wrong place.

## Do this

```bash
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c
```
> **Expected:** 3 CONNECT(1), 3 CONNACK(2), 8 PUBLISH(3), 2 PUBACK(4), 2 SUBSCRIBE(8), 2 SUBACK(9), 1 PINGREQ(12), 1 PINGRESP(13), 1 DISCONNECT(14).

```bash
tshark -r pcaps/dnp3_substation.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c
```
> **Expected:** READ(1)x2, SELECT(3), OPERATE(4), DIRECT_OPERATE(5), COLD_RESTART(13), RESPONSE(129)x6, UNSOL(130), CONFIRM(0).

- **In Wireshark:** Apply `mqtt` then `dnp3` in Wireshark and read the **Info** column top-to-bottom — you can follow the whole story without expanding a packet.
- **Note:** Controls are the dangerous ones: MQTT PUBLISH to a command topic, and DNP3 SELECT/OPERATE/DIRECT_OPERATE (function codes 3/4/5). Note how few there are — they're easy to enumerate.

## Check yourself

1. **How many PUBLISH vs SUBSCRIBE packets are in the MQTT capture, and why so many more PUBLISH?**
   <details><summary>answer</summary>8 PUBLISH vs 2 SUBSCRIBE — telemetry is published repeatedly and fanned out by the broker, while a client subscribes once.</details>

2. **Which DNP3 function codes are *controls*, and how many are there?**
   <details><summary>answer</summary>SELECT (3), OPERATE (4), DIRECT OPERATE (5) — three control messages. (COLD RESTART 13 is an admin control too.)</details>

3. **Which single DNP3 function code is the outstation talking without being asked?**
   <details><summary>answer</summary>UNSOLICITED RESPONSE (130) — a report-by-exception event.</details>

**Level up:** You can enumerate message types for both protocols and point to the control messages — the surface is fully mapped.
