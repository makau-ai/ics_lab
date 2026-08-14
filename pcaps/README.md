# Sample captures — manifest

The documented DNP3 & MQTT sample pcaps to learn from. Open any file in Wireshark, or point
`tshark` at it. Every capture here is **synthetic, deterministic, and CRC-verified** (see
`../verification/`) except the one real government-origin trace in `real/`.

| File | What it is | Frames | Transport | Key hosts | Use |
|---|---|---|---|---|---|
| `dnp3_substation.pcap` | DNP3 substation SCADA — integrity poll, unsolicited response, a supervised SELECT→OPERATE breaker **close**, then a spoofed-link **DIRECT_OPERATE trip** + **COLD_RESTART** from a rogue host | 37 | TCP/20000 | master `10.20.0.5` · outstation `10.20.0.20` · rogue `10.20.0.66` | **Teaching** (Levels 1–5) |
| `mqtt_iot_telemetry.pcap` | MQTT plant telemetry — CONNECT/SUBSCRIBE/PUBLISH, QoS 0 & 1, PING, then an **anonymous CONNECT** + **`#` wildcard** eavesdrop + an **unauthorized command PUBLISH** | 61 | TCP/1883 | broker `10.10.20.10` · hmi `10.10.20.30` · sensor `10.10.20.7` · rogue `10.10.20.66` | **Teaching** (Levels 1–5) |
| `dnp3_assessment.pcap` | **Unseen** DNP3 assessment capture for the Machine Problem — a *different* technique than the teaching set. Do not pre-analyze; work it only under assessment. | 30 | TCP/20000 | *(unseen)* | **Graded** (see `../mp/`) |
| `mqtt_assessment.pcap` | **Unseen** MQTT assessment capture for the Machine Problem — a *different* technique than the teaching set. Do not pre-analyze; work it only under assessment. | 66 | TCP/1883 | *(unseen)* | **Graded** (see `../mp/`) |
| `real/dnp3_cisa_example.pcap` | CISA ICSNPP DNP3 parser test trace — real, government-origin, **BSD-3-Clause** (attribution in `real/NOTICE.md`) | 834 | TCP/20000 | — | **Reference** (real data) |

## 30-second start

```bash
# Who is talking, on what ports?
tshark -r dnp3_substation.pcap -q -z conv,tcp

# DNP3 function codes at a glance (READ=1 SELECT=3 OPERATE=4 DIRECT_OPERATE=5 RESPONSE=129)
tshark -r dnp3_substation.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c

# The injection: an IP that isn't the master, carrying the master's forged link address
tshark -r dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5,13}" \
       -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func

# MQTT: the anonymous CONNECT and the '#' wildcard subscribe
tshark -r mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid
tshark -r mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==8" -T fields -e frame.number -e mqtt.topic
```

## Notes

- The two **teaching** captures are the ones the modules and the seven levels annotate frame by
  frame — start there. The two **assessment** captures are graded unseen material; the
  autograder in `../mp/` uses them, so don't walk them ahead of time.
- Provenance and license for the real capture are in `real/NOTICE.md` / `real/DNP3_CISA_LICENSE.txt`.
- More government/university captures you can practice the same skills on are listed in
  `../EXTERNAL_CAPTURES.md`; fetch the approved-source set with `../lab/fetch_real_captures.sh`.
- Want to make your own? `../verification/` shows a freshly-captured live pcap and the exact
  commands; `../projects/STARTER_AI_PROMPTS.md` has you build and capture your own ICS/OT app.
