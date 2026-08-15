# Formal Verification Artifacts — proof the platform works

This folder holds **platform-generated evidence** that the kit's DNP3 & MQTT sample
captures — and the runnable lab that produces them — behave exactly as the modules and
curriculum claim. Everything here is **reproducible** from the shipped sources with the
commands in §5. Nothing was hand-edited; every figure below came out of `tshark`,
`verify_all.py`, or the lab's own scripts.

**Why this exists.** The whole kit began with a co-instructor's simple, concrete ask:
*documented DNP3 and MQTT sample pcaps to learn from and to start building course
material.* This folder is the assurance that those sample pcaps are correct, that the
behaviors they teach are real, and that a student (or a grader) can regenerate the same
evidence on demand. Precision over adjectives: each claim below is backed by a file you
can open.

## Artifact index

| Artifact | What it proves | Regenerate with |
|---|---|---|
| `evidence/00_verify_all.txt` | The reproducible verification pass: **21/21 checks**, **63/63 DNP3 CRCs** recomputed, curriculum commands re-run against expected output, MP autograder (blank 10/100, solution 100/100). | `cd source && python3 verify_all.py` |
| `evidence/20_dnp3_substation.txt` | The **DNP3 sample pcap** decodes to the documented endpoints, function-code mix, and the forged-link-address command injection (frame 27). | `tshark -r pcaps/dnp3_substation.pcap …` |
| `evidence/21_mqtt_iot.txt` | The **MQTT sample pcap** decodes to the documented control-packet mix, the anonymous CONNECT, and the `#` wildcard eavesdrop. | `tshark -r pcaps/mqtt_iot_telemetry.pcap …` |
| `live_lab.pcap` + `evidence/10–13_live_*.txt` | The **runnable lab, executed live**, generates the same DNP3 control lifecycle + rogue trip and MQTT anonymous-connect/eavesdrop/inject behavior — captured off the wire, not scripted. | `lab/run-local.sh up; …dnp3; …mqtt` while capturing on `lo` |

All four sample captures ship in `pcaps/` (`dnp3_substation.pcap`, `mqtt_iot_telemetry.pcap`,
and the two unseen assessment captures `dnp3_assessment.pcap`, `mqtt_assessment.pcap`).

## 1. The reproducible verification pass

`source/verify_all.py` is the single source of truth for "does the kit hold together." It
reads the shipped captures, **recomputes every DNP3 data-link CRC from raw bytes**, re-runs
the exact `tshark` commands the curriculum tells students to run and diffs them against the
documented expected output, checks that every documented frame exists in its capture, and
runs the Machine-Problem autograder against both a blank submission and the reference
solution. Latest run (`evidence/00_verify_all.txt`):

```
Section A: 5/5   Section B: 4/4   Section C: 4/4   Section D: 6/6   Section E: 2/2
TOTAL: 21/21 checks passed   (CRC 63/63)
```

## 2. The documented sample pcaps (the co-instructor's core ask)

**DNP3 — `pcaps/dnp3_substation.pcap`** (`evidence/20_dnp3_substation.txt`). Three hosts:
a SCADA master (`10.20.0.5`), a substation outstation (`10.20.0.20`), and a rogue host
(`10.20.0.66`). The function-code histogram shows a clean integrity poll, an
UNSOLICITED_RESPONSE, a supervised SELECT→OPERATE breaker close, and then the teaching
moment — the control lifecycle table makes the attack legible:

```
frame  ip.src        dnp3.src(link)  func
16     10.20.0.5     100             3   SELECT     (legitimate master)
20     10.20.0.5     100             4   OPERATE    (legitimate master)
27     10.20.0.66    100             5   DIRECT_OPERATE  ← ip is the rogue host, but the
                                                          link address is forged to 100
31     10.20.0.66    100            13   COLD_RESTART
```

Frame 27 is the whole point: base DNP3 authenticates neither the IP nor the 16-bit link
address, so a host that never authenticated issues a breaker TRIP that the outstation obeys.

**MQTT — `pcaps/mqtt_iot_telemetry.pcap`** (`evidence/21_mqtt_iot.txt`). A broker
(`10.10.20.10`), HMI (`.30`), sensor (`.7`), and rogue host (`.66`). The control-packet
histogram shows CONNECT/CONNACK, SUBSCRIBE/SUBACK, QoS-0/1 PUBLISH, and PINGs; the evidence
isolates the **anonymous CONNECT** (frame 38, client `mqtt-explorer-x`, no username) and the
**`#` wildcard SUBSCRIBE** (frame 42) — cleartext, no authorization, full topic eavesdrop.

## 3. Live platform capture — the lab actually runs

`live_lab.pcap` was captured off the loopback interface while the lab ran as plain processes
(`lab/run-local.sh up`, then `dnp3`, then `mqtt`). It is **not** a replay of the sample
pcaps — it is fresh traffic the platform generated, proving the runnable lab produces the
documented behavior. 108 frames; protocol hierarchy = 10 DNP3 + 33 MQTT over TCP.

DNP3 (`evidence/11_live_dnp3.txt`) — the control lifecycle appears exactly as taught: a
SELECT (frame 8) + OPERATE (frame 11) supervised close on one connection, then a lone
DIRECT_OPERATE (frame 24) on a **separate** connection with no preceding SELECT — the
unauthenticated rogue trip. The outstation log from the run:

```
[outstation] *** CONTROL SELECT CROB CLOSE      -> breaker now CLOSED
[outstation] *** CONTROL OPERATE CROB CLOSE     -> breaker now CLOSED
[outstation] *** CONTROL DIRECT_OPERATE CROB TRIP -> breaker now OPEN   <<< no authentication
```

MQTT (`evidence/12_live_mqtt.txt`, `13_live_injected_payload.txt`) — four CONNECTs (two with
no username, including the attacker `mqtt-explorer-x`), a `#` wildcard SUBSCRIBE (frame 68),
and an unauthorized PUBLISH to `plant/tank1/command`. The injected payload decodes to:

```
{"actuator":"pump1","cmd":"START","valve":"open"}
```

and the pump-controller subscriber **acted on it** — the physical impact an unauthorized
publish would cause on a real plant.

## 4. Digital-twin verification path

The multi-container digital twin (`lab/twin/`) is verified at two levels:

- **Static (done here):** `docker compose -f lab/twin/docker-compose.twin.yml config` parses
  clean (base and with the hardened override), all twin Python compiles, and the `zone-fw`
  nftables ruleset passes `nft -c`. The twin re-uses the same DNP3/MQTT substrate verified
  above, so the protocol behavior is already proven; only the containerization, the Modbus
  wet-well loop, and the zone firewall are net-new.
- **Live (run in the Codespace):** `bash lab/twin/launch-twin.sh` brings the plant up;
  `--attack` drives the injection and the **spill** counter (Sanitary-Sewer-Overflow gallons)
  climbs; `--hardened` re-runs the *same* attack and the spill **stays 0** — the
  Cyber-Informed-Engineering "even-if" acceptance test. Watch it in the twin's own capture
  plane (Wireshark on `:3000`) so every conduit crossing stays visible. The one manual step
  is seeding the OpenPLC ST program on first boot (`lab/twin/README.md` §7).

## 5. Reproduce everything

```bash
# 1) the reproducible verification pass (21/21)
cd source && python3 verify_all.py && cd ..

# 2) evidence from the sample pcaps
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5,13}" \
       -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" \
       -T fields -e frame.number -e mqtt.clientid

# 3) generate a fresh live capture yourself
tcpdump -i lo -U -w my_live.pcap 'tcp port 1883 or tcp port 20000' &
bash lab/run-local.sh up && bash lab/run-local.sh dnp3 && bash lab/run-local.sh mqtt
kill %1; bash lab/run-local.sh down
tshark -r my_live.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c
```

## 6. Grading

These artifacts are also the **worked exemplar** for the artifact-grading rubric
(`../projects/ARTIFACT_RUBRIC.md`): a student who forward-engineers their own ICS/OT/IoT
app and reverse-engineers it is expected to submit the same *class* of evidence — a captured
pcap, a decoded protocol narrative, an identified weakness with frame-level proof, and a
reproducibility recipe. The rubric dimensions map onto §1–§3 above.
