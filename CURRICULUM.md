# ICS/OT Protocol Analysis — Leveled Learning Path

From first packet to a university-style Machine Problem. Work the levels in order. Every command and expected output here was verified with tshark against the shipped captures (`pcaps/dnp3_substation.pcap`, `pcaps/mqtt_iot_telemetry.pcap`).

**The arc:** tooling → endpoints → message types → inside the packet → find the attack → detection → Machine Problem.

| Level | Title | Difficulty | Time |
|---|---|---|---|
| 0 | [Orientation — see it running](#level-0) | Start here | ~10 min |
| 1 | [Who is talking?](#level-1) | Introductory | ~25 min |
| 2 | [What kind of messages?](#level-2) | Introductory | ~25 min |
| 3 | [Inside the packet](#level-3) | Intermediate | ~40 min |
| 4 | [Find the attack](#level-4) | Intermediate | ~35 min |
| 5 | [Catch it automatically](#level-5) | Advanced | ~40 min |
| 6 | [Machine Problem — ICS Intrusion Analysis](#level-6) | University-level capstone | ~120 min |

> Prefer a clickable, progress-tracking version? Open `curriculum/index.html` (auto-opens in the Codespace).

---

<a id="level-0"></a>

# Level 0 — Orientation — see it running

*One click, and the lab is already live*

**Difficulty:** Start here &nbsp;·&nbsp; **Time:** ~10 min &nbsp;·&nbsp; **Prerequisite:** None — this is the first level.

**Goal.** Confirm the environment is up and watch real DNP3 + MQTT packets move.

## What you'll be able to do

- Open the noVNC desktop and confirm Wireshark is capturing on 'lo'.
- Recognize that you are watching a live conversation between real endpoints.

## Background

This Codespace auto-started everything: an MQTT broker, a DNP3 outstation, a publishing sensor, a subscriber, a pump-controller, and Wireshark already capturing. You don't set anything up — you observe.

Two protocols are flowing. **MQTT** is publish/subscribe messaging (IoT/IIoT telemetry). **DNP3** is a SCADA protocol (electric/water utilities). By the end of this path you'll read both down to the byte and catch an intruder in them.

## Do this

- **Note:** Open the forwarded port **6080** ('noVNC Desktop', password `vscode`). Wireshark is already open and capturing.
- **In Wireshark:** In Wireshark's green display-filter bar, type `mqtt` and press Enter. Watch the telemetry. Then clear it and type `dnp3`.
```bash
# prefer the terminal? watch it headless:
tshark -i lo -c 10 -f "tcp port 1883 or tcp port 20000"
```
> **Expected:** 10 packets summarised — a mix of MQTT (1883) and DNP3 (20000).

```bash
# re-run the attacks any time and watch them appear:
./lab/intrude.sh
```
> **Expected:** MQTT anonymous connect + command injection, then a DNP3 trip.


## Check yourself

1. **What are the two protocols you see, and what TCP ports identify them?**
   <details><summary>answer</summary>MQTT on TCP/1883 and DNP3 on TCP/20000.</details>

2. **Did you have to install or start anything?**
   <details><summary>answer</summary>No — the devcontainer auto-built and auto-started the whole lab.</details>

**Level up:** You can see live `mqtt` and `dnp3` traffic in Wireshark (or tshark). Continue to Level 1.


---

<a id="level-1"></a>

# Level 1 — Who is talking?

*Endpoints & conversations — the map before the message*

**Difficulty:** Introductory &nbsp;·&nbsp; **Time:** ~25 min &nbsp;·&nbsp; **Prerequisite:** Level 0.

**Goal.** Identify every host, which ports they use, and who connects to whom — without opening a single packet's guts.

## What you'll be able to do

- List the IP endpoints in a capture and rank them by traffic.
- Identify TCP conversations and the server port that names the protocol.
- Spot the 'hub' (MQTT broker / DNP3 master↔outstation) and any host that looks out of place.

## Background

Before you read bytes, understand the **graph**: who are the endpoints and who talks to whom. This is exactly how a real analyst starts triage. Two protocols, two shapes: MQTT is a **star** (every client talks to one broker); DNP3 is usually a **master↔outstation** pair. Anything that breaks the expected shape is a lead.

## Do this

```bash
tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z endpoints,ip
```
> **Expected:** 10.10.20.10  (61 pkts)  <- the broker (busiest)
10.10.20.30  (22)   <- HMI
10.10.20.7   (22)   <- sensor
10.10.20.66  (17)   <- rogue

```bash
tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z conv,tcp
```
> **Expected:** three TCP conversations, all to 10.10.20.10:1883 — the broker is the hub.

- **In Wireshark:** In Wireshark: **Statistics ▸ Conversations** (TCP tab) and **Statistics ▸ Endpoints** (IPv4). Then **Statistics ▸ Protocol Hierarchy** to see mqtt under tcp.
```bash
tshark -r pcaps/dnp3_substation.pcap -q -z conv,tcp
```
> **Expected:** the master (10.20.0.5) ↔ outstation (10.20.0.20:20000), plus a second session from 10.20.0.66 — the rogue.


## Check yourself

1. **In the MQTT capture, which IP is the broker, and how did you know from endpoints alone?**
   <details><summary>answer</summary>10.10.20.10 — it has the most packets and is the common endpoint of every TCP conversation (the star center).</details>

2. **Which port tells you a conversation is MQTT? DNP3?**
   <details><summary>answer</summary>TCP/1883 = MQTT; TCP/20000 = DNP3 (the server side of each conversation).</details>

3. **Which host looks out of place in each capture, before you've read any payload?**
   <details><summary>answer</summary>10.10.20.66 (MQTT) and 10.20.0.66 (DNP3) — extra endpoints that aren't the expected broker/master/outstation.</details>

**Level up:** You can name the endpoints, the protocol ports, the hub, and the odd host out — using only conversation/endpoint statistics.


---

<a id="level-2"></a>

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


---

<a id="level-3"></a>

# Level 3 — Inside the packet

*Fields & layers — now we open it up*

**Difficulty:** Intermediate &nbsp;·&nbsp; **Time:** ~40 min &nbsp;·&nbsp; **Prerequisite:** Level 2. This is where 'endpoints' turns into 'internals'.

**Goal.** Read specific fields inside the packets: MQTT credentials/topics/QoS/retain, and DNP3's three layers, addresses, IIN, and control objects.

## What you'll be able to do

- Expand the protocol tree and read named fields; use Apply as Column.
- Extract exact field values with `tshark -T fields -e <field>`.
- Read a DNP3 CROB control code and distinguish the DNP3 link address from the IP address.

## Background

Now we dive in. In Wireshark, click a frame and expand the protocol tree in the middle pane; **hover a field** to see its filter name in the status bar, and **right-click ▸ Apply as Column** to pull it up. On the CLI, `-T fields -e <name>` prints exact values — the analyst's scalpel.

DNP3 is layered: **data link** (0x0564 start, addresses, CRC) → **pseudo-transport** → **application** (function code, IIN, objects). The Control Relay Output Block (group 12 var 1) is the object that moves a breaker.

## Do this

```bash
# MQTT: read the cleartext login straight off the wire
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.clientid -e mqtt.username -e mqtt.passwd
```
> **Expected:** hmi-scada-01  hmi_operator  Plant!ntel2024   (…and the sensor's creds). Cleartext — no TLS.

```bash
# MQTT: topic, QoS and the RETAIN flag on each publish
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==3 -T fields -e frame.number -e mqtt.topic -e mqtt.qos -e mqtt.retain
```
> **Expected:** plant/tank1/telemetry with QoS 0 and 1; retain False. (mqtt.retain prints True/False.)

- **In Wireshark:** In Wireshark, click a DNP3 frame and expand **Distributed Network Protocol 3.0**: the Data Link Layer (Source/Destination link addresses + CRC), the Transport, and the Application Layer (Function Code, Internal Indications, Objects).
```bash
# DNP3: compare the IP source with the DNP3 LINK source, and read the control
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5}" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.ctl.trip -e dnp3.ctl.op
```
> **Expected:** the legitimate close (Close/Pulse-On) from the master, and the rogue Trip — note ip.src vs dnp3.src.


## Check yourself

1. **What is the HMI's MQTT password, and which field held it?**
   <details><summary>answer</summary>Plant!ntel2024, in mqtt.passwd — sent in cleartext inside the CONNECT.</details>

2. **In DNP3, what's the difference between `ip.src` and `dnp3.src`?**
   <details><summary>answer</summary>ip.src is the network (IP) source; dnp3.src is the 16-bit DNP3 *link* address inside the data-link header. They can disagree — which is the whole game in Level 4.</details>

3. **Which object carries a breaker command, and which fields tell you trip vs close?**
   <details><summary>answer</summary>The CROB (group 12 var 1). dnp3.ctl.trip = Trip/Close code; dnp3.ctl.op = operation type (e.g., pulse on).</details>

**Level up:** You can extract any field by name and read a DNP3 control down to trip-vs-close, and you understand IP-address vs DNP3-link-address.


---

<a id="level-4"></a>

# Level 4 — Find the attack

*Security analysis — turn fields into findings*

**Difficulty:** Intermediate &nbsp;·&nbsp; **Time:** ~35 min &nbsp;·&nbsp; **Prerequisite:** Level 3. Read the modules' Security & Controls tab alongside this.

**Goal.** Use your field skills to locate the planted anomalies in the teaching captures and name the weakness each one exploits.

## What you'll be able to do

- Find the MQTT anomalies: cleartext creds, anonymous connect, '#' wildcard, unauthorized command publish.
- Find the DNP3 anomalies: spoofed source/link address, the unauthenticated trip, the cold restart.
- Tie each finding to a control (TLS, ACLs, DNP3-SA, segmentation).

## Background

Attacks in these protocols rarely look 'malformed' — they look like *valid messages from the wrong party*. That's why the field skills from Level 3 matter: the anomaly is a legal packet whose fields tell on it.

## Do this

```bash
# MQTT: anonymous CONNECT (no username) the broker accepted
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid
```
> **Expected:** frame 38, client mqtt-explorer-x — no credentials.

```bash
# MQTT: the '#' wildcard subscribe (eavesdrop-all) and the injected command
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.topic=="#" || mqtt.topic=="plant/tank1/command"' -T fields -e frame.number -e mqtt.msgtype -e mqtt.topic
```
> **Expected:** the '#' SUBSCRIBE and the PUBLISH to plant/tank1/command (frame 52).

```bash
# DNP3: the unauthenticated trip and the cold restart, and who sent them
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func==5 || dnp3.al.func==13" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
```
> **Expected:** DIRECT_OPERATE (5) and COLD_RESTART (13) from 10.20.0.66 — with dnp3.src forged to the master's 100.

- **Note:** For each finding, open the matching module (modules/*.html) ▸ **Frame Explorer** and jump to that frame to read the full teaching note and the control that stops it.

## Check yourself

1. **How does the outstation 'know' the trip in frame 27 came from the master?**
   <details><summary>answer</summary>It doesn't — DNP3 has no authentication. The frame's dnp3.src claims 100 (the master) but ip.src is 10.20.0.66. The link address is just a number the attacker wrote in.</details>

2. **The anonymous MQTT client was accepted. Is the later command injection an authentication or authorization failure?**
   <details><summary>answer</summary>Authorization — the broker *authenticated* it (accepted the anonymous identity); it failed to *constrain* what that identity could publish (no topic ACL).</details>

**Level up:** You can locate every planted anomaly by field evidence and state the weakness + control for each.


---

<a id="level-5"></a>

# Level 5 — Catch it automatically

*Detection engineering — from one packet to a rule*

**Difficulty:** Advanced &nbsp;·&nbsp; **Time:** ~40 min &nbsp;·&nbsp; **Prerequisite:** Level 4.

**Goal.** Write detection that survives a real adversary — key on invariants, not on a single spoofable field — and turn packets into logs with Zeek + CISA ICSNPP.

## What you'll be able to do

- Write tshark/display-filter detections for the anomalies.
- Run Zeek + the ICSNPP DNP3 parser and read dnp3_control.log / mqtt_*.log.
- Explain why 'alert on wrong source IP' is naive and what invariant beats it.

## Background

A detection is only as good as its evasion resistance. The obvious DNP3 rule — 'alert if a control's source IP isn't the master' — fails the moment the attacker spoofs the master's IP. The durable rule binds an **invariant**: {DNP3 link address ↔ expected source ↔ known-master set ↔ SELECT-before-OPERATE}. Read the modules' 'Detection under adversarial and operational reality' section.

## Do this

```bash
# a first-cut DNP3 rule: controls not from the master IP
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5,13} && ip.src != 10.20.0.5" -T fields -e frame.number -e ip.src -e dnp3.al.func
```
> **Expected:** catches the rogue trip & restart HERE — but only because the attacker kept its real IP.

```bash
# turn packets into readable logs with Zeek + CISA ICSNPP
docker compose -f lab/docker-compose.yml --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap
cat lab/zeek_reference_output/dnp3/dnp3_control.log | grep -i direct
```
> **Expected:** a DIRECT_OPERATE / Trip / Success line whose source host is 10.20.0.66 — your best single alert.

```bash
# MQTT detections: anonymous connect, and a '#' subscribe
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.msgtype==8 && mqtt.topic=="#"' -T fields -e frame.number
```
> **Expected:** the anonymous CONNECT and the wildcard SUBSCRIBE.

- **Note:** Now break your own rule: in the lab, re-run the DNP3 attack with `--src-addr 100` (spoofing the master's link address) and with a spoofed IP, and watch the naive source-IP rule miss it. That's why Level 6 asks for an invariant detector.

## Check yourself

1. **Why is 'alert when a control's source IP isn't the master' insufficient?**
   <details><summary>answer</summary>The source IP (and the DNP3 link address) are attacker-controlled/spoofable, and real outstations answer to *several* legitimate masters — so it both misses spoofed sources and false-positives on backups/FEPs.</details>

2. **What does Zeek + ICSNPP give you that a raw pcap doesn't?**
   <details><summary>answer</summary>Structured, queryable logs (dnp3_control.log, dnp3_objects.log, mqtt_*.log) you can alert and hunt on at scale — e.g., every control with its operation type, source host, and status.</details>

**Level up:** You can write detections, generate ICSNPP logs, and articulate the invariant-based rule that resists spoofing. You are ready for the Machine Problem.


---

<a id="level-6"></a>

# Level 6 — Machine Problem — ICS Intrusion Analysis

*Capstone: analyze two unseen captures, build a detector, write the incident up*

**Difficulty:** University-level capstone &nbsp;·&nbsp; **Time:** ~120 min &nbsp;·&nbsp; **Prerequisite:** Levels 1–5.

**Goal.** Apply Levels 1–5 to captures you've never seen, using DIFFERENT attacks. Autograded (100 pts) + a written incident report.

## What you'll be able to do

- Triage two unseen captures and prove findings with named fields (Part 1, autograded).
- Implement an invariant-based detector.py (Part 2, autograded).
- Write an incident report with evidence, authN-vs-authZ, and controls (Part 3 + rubric).

## Background

This is a formal, university-style Machine Problem. The handout, the two evidence captures, an answer template, a self-check autograder, and the report rubric are all in the **`mp/`** folder. The attacks are new: a spoofed DNP3 status report (not a control), and an MQTT retained-message harvest + persistent command injection.

## Do this

```bash
cd mp && cat README.md      # the full handout: parts, deliverables, grading
```
> **Expected:** MP: ICS Intrusion Analysis — Parts 1–3 + bonus.

```bash
# analyze the two unseen captures
../lab/open-wireshark.sh captures/dnp3_assessment.pcap
tshark -r captures/mqtt_assessment.pcap -Y mqtt
```
> **Expected:** two captures you have not walked — apply everything from Levels 1–5.

```bash
# fill submission/answers.json, write detector.py and report.md, then self-check:
python3 grade.py
```
> **Expected:** PASS/FAIL per item and a score /100. Iterate to green.


## Check yourself

1. **Where is the handout, and how do you check your work?**
   <details><summary>answer</summary>mp/README.md is the handout; `python3 mp/grade.py` autogrades Part 1 (answers.json) + Part 2 (detector.py) + Part 3 (format), and mp/rubric.md scores the written report.</details>

2. **Why must your detector.py use an invariant instead of printing the frame number?**
   <details><summary>answer</summary>The proctored re-run uses a freshly generated capture with different addresses; only an invariant (link-address↔IP inconsistency; anon-connect↔retained-command) generalizes.</details>

> **Capstone.** The handout, evidence captures, answer template, autograder, and rubric are in the `mp/` folder — start with `mp/README.md`.

**Level up:** Score 90+ on the autograder and meet the report rubric's mastery gates. You've completed the path.


---
