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
| 7 | [The living plant](#level-7) | Advanced | ~60 min |

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

- **Read.** Open the forwarded port **6080** ('noVNC Desktop'). It opens **straight to the desktop — no password prompt** — with Wireshark already capturing on `lo`. (If a VNC prompt ever appears, the password is `vscode`.)

- **Do · Click.** In Wireshark's green display-filter bar, type `mqtt` and press Enter. Watch the telemetry. Then clear it and type `dnp3`.

- **Read.** Short filters like these you just **type** — quickest by far. When you need to **paste** a longer filter or command onto this remote desktop, your normal Ctrl/Cmd+V won't reach it: open noVNC's **Clipboard panel** (clipboard icon on the left edge), paste your text there, then **Ctrl+V** in Wireshark (or **Shift+Insert** in an xterm). A bridge keeps that panel in sync with the desktop automatically. Full guide: `RUNNING_COMMANDS.md`.

**⌨ Type:** `l0`  — runs `tshark -i lo -c 10 -f "tcp port 1883 or tcp port 20000"`

> **Check (expected):** 10 packets summarised — a mix of MQTT (1883) and DNP3 (20000).

**⌨ Type:** `l0b`  — runs `./lab/intrude.sh`

> **Check (expected):** MQTT anonymous connect + command injection, then a DNP3 trip.


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

**⌨ Type:** `l1`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z endpoints,ip`

> **Check (expected):** 10.10.20.10  (61 pkts)  <- the broker (busiest)
10.10.20.30  (22)   <- HMI
10.10.20.7   (22)   <- sensor
10.10.20.66  (17)   <- rogue

**⌨ Type:** `l1b`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z conv,tcp`

> **Check (expected):** three TCP conversations, all to 10.10.20.10:1883 — the broker is the hub.

- **Do · Click.** In Wireshark: **Statistics ▸ Conversations** (TCP tab) and **Statistics ▸ Endpoints** (IPv4). Then **Statistics ▸ Protocol Hierarchy** to see mqtt under tcp.

**⌨ Type:** `l1c`  — runs `tshark -r pcaps/dnp3_substation.pcap -q -z conv,tcp`

> **Check (expected):** the master (10.20.0.5) ↔ outstation (10.20.0.20:20000), plus a second session from 10.20.0.66 — the rogue.


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

**⌨ Type:** `l2`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c`

> **Check (expected):** 3 CONNECT(1), 3 CONNACK(2), 8 PUBLISH(3), 2 PUBACK(4), 2 SUBSCRIBE(8), 2 SUBACK(9), 1 PINGREQ(12), 1 PINGRESP(13), 1 DISCONNECT(14).

**⌨ Type:** `l2b`  — runs `tshark -r pcaps/dnp3_substation.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c`

> **Check (expected):** READ(1)x2, SELECT(3), OPERATE(4), DIRECT_OPERATE(5), COLD_RESTART(13), RESPONSE(129)x6, UNSOL(130), CONFIRM(0).

- **Do · Click.** Apply `mqtt` then `dnp3` in Wireshark and read the **Info** column top-to-bottom — you can follow the whole story without expanding a packet.

- **Read.** Controls are the dangerous ones: MQTT PUBLISH to a command topic, and DNP3 SELECT/OPERATE/DIRECT_OPERATE (function codes 3/4/5). Note how few there are — they're easy to enumerate.


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

**⌨ Type:** `l3`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.clientid -e mqtt.username -e mqtt.passwd`

> **Check (expected):** hmi-scada-01  hmi_operator  Plant!ntel2024   (…and the sensor's creds). Cleartext — no TLS.

**⌨ Type:** `l3b`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==3 -T fields -e frame.number -e mqtt.topic -e mqtt.qos -e mqtt.retain`

> **Check (expected):** plant/tank1/telemetry with QoS 0 and 1; retain False. (mqtt.retain prints True/False.)

- **Do · Click.** In Wireshark, click a DNP3 frame and expand **Distributed Network Protocol 3.0**: the Data Link Layer (Source/Destination link addresses + CRC), the Transport, and the Application Layer (Function Code, Internal Indications, Objects).

**⌨ Type:** `l3c`  — runs `tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5}" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.ctl.trip -e dnp3.ctl.op`

> **Check (expected):** the legitimate close (Close/Pulse-On) from the master, and the rogue Trip — note ip.src vs dnp3.src.


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

**⌨ Type:** `l4`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid`

> **Check (expected):** frame 38, client mqtt-explorer-x — no credentials.

**⌨ Type:** `l4b`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.topic=="#" || mqtt.topic=="plant/tank1/command"' -T fields -e frame.number -e mqtt.msgtype -e mqtt.topic`

> **Check (expected):** the '#' SUBSCRIBE and the PUBLISH to plant/tank1/command (frame 52).

**⌨ Type:** `l4c`  — runs `tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func==5 || dnp3.al.func==13" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func`

> **Check (expected):** DIRECT_OPERATE (5) and COLD_RESTART (13) from 10.20.0.66 — with dnp3.src forged to the master's 100.

- **Read.** For each finding, open the matching module (modules/*.html) ▸ **Frame Explorer** and jump to that frame to read the full teaching note and the control that stops it.


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

**⌨ Type:** `l5`  — runs `tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5,13} && ip.src != 10.20.0.5" -T fields -e frame.number -e ip.src -e dnp3.al.func`

> **Check (expected):** catches the rogue trip & restart HERE — but only because the attacker kept its real IP.

**⌨ Type:** `l5b`  — runs `docker compose -f lab/docker-compose.yml --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap ; cat lab/zeek_reference_output/dnp3/dnp3_control.log | grep -i direct`

> **Check (expected):** a DIRECT_OPERATE / Trip / Success line whose source host is 10.20.0.66 — your best single alert.

**⌨ Type:** `l5c`  — runs `tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number ; tshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.msgtype==8 && mqtt.topic=="#"' -T fields -e frame.number`

> **Check (expected):** the anonymous CONNECT and the wildcard SUBSCRIBE.

- **Read.** Now break your own rule: in the lab, re-run the DNP3 attack with `--src-addr 100` (spoofing the master's link address) and with a spoofed IP, and watch the naive source-IP rule miss it. That's why Level 6 asks for an invariant detector.


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

**⌨ Type:** `l6`  — runs `cd mp && cat README.md      # the full handout: parts, deliverables, grading`

> **Check (expected):** MP: ICS Intrusion Analysis — Parts 1–3 + bonus.

**⌨ Type:** `l6b`  — runs `cd mp ; ../lab/open-wireshark.sh captures/dnp3_assessment.pcap ; tshark -r captures/mqtt_assessment.pcap -Y mqtt`

> **Check (expected):** two captures you have not walked — apply everything from Levels 1–5.

**⌨ Type:** `l6c`  — runs `cd mp ; python3 grade.py`

> **Check (expected):** PASS/FAIL per item and a score /100. Iterate to green.


## Check yourself

1. **Where is the handout, and how do you check your work?**
   <details><summary>answer</summary>mp/README.md is the handout; `python3 mp/grade.py` autogrades Part 1 (answers.json) + Part 2 (detector.py) + Part 3 (format), and mp/rubric.md scores the written report.</details>

2. **Why must your detector.py use an invariant instead of printing the frame number?**
   <details><summary>answer</summary>The proctored re-run uses a freshly generated capture with different addresses; only an invariant (link-address↔IP inconsistency; anon-connect↔retained-command) generalizes.</details>

> **Capstone.** The handout, evidence captures, answer template, autograder, and rubric are in the `mp/` folder — start with `mp/README.md`.

**Level up:** Score 90+ on the autograder and meet the report rubric's mastery gates. You've completed the path.


---

<a id="level-7"></a>

# Level 7 — The living plant

*Beyond the descent — your field skills on the twin's live, multi-zone traffic*

**Difficulty:** Advanced &nbsp;·&nbsp; **Time:** ~60 min &nbsp;·&nbsp; **Prerequisite:** Levels 0–6 (the full descent, including the Machine Problem). Docker + the compose plugin (the Codespace ships them).

**Goal.** Take the exact Level 3–5 field-analysis skills onto the digital twin's LIVE multi-zone traffic: catch a forged-link DNP3 control and an MQTT command injection on the wire, watch them spill the wet-well, then flip to `--hardened` and prove the same attack is refused.

## What you'll be able to do

- Re-run your Level 1–3 skills on the twin's LIVE multi-zone DNP3 + MQTT traffic — not a fixed teaching pcap.
- Fire the forged-link DIRECT_OPERATE and the MQTT command injection from the granted cell foothold, and watch the SSO spill counter climb.
- Flip to `--hardened`, replay the same attack, and prove it is refused while the spill counter stays 0 — the CIE 'even-if' acceptance test.

## Background

Levels 0–6 trained your eye on a clean loopback capture. The **digital twin** is the same protocols on a *living* plant: **OpenPLC** (a Modbus **client**) driving a simulated wet-well (the Modbus **server**), fronted by a DNP3 **outstation** gateway on TCP/20000 that a SCADA **master** polls, and an MQTT **broker** with a telemetry **publisher** and a pump-controller **subscriber** — all across five segmented IEC-62443 zones behind an nftables conduit firewall, with an out-of-band tap so every packet still reaches Wireshark.

Nothing here is a new skill. You already know how to map endpoints (Level 1), classify function codes and control packets (Level 2), read `dnp3.src` against `ip.src` and the MQTT retain/username fields (Level 3), turn those fields into a finding (Level 4), and bind a spoof-resistant invariant (Level 5). Level 7 points those exact skills at real, multi-zone traffic that fights back — and at a physical consequence you can measure: gallons of sanitary-sewer overflow.

## Do this

- **Read.** **Apply your Level 0 skill — 'see it running' — to an entire plant.** Boot the multi-zone digital twin with the adversary foothold staged (the capture plane comes up automatically):

`bash lab/twin/launch-twin.sh --attack`

Doors once it boots: OpenPLC control logic **:8088** · FUXA HMI **:1881** · noVNC Wireshark **:3000**. The objective scoreboard is the plant-sim SSO **spill** counter — Pass = spill stays 0 under full DNP3 + MQTT write access. Follow it with `bash lab/twin/launch-twin.sh --logs`.

- **Do · Click.** **Apply your Level 1 skill — the map before the message — to five zones.** Open Wireshark at **:3000**, load `/caps/conduit_live.pcap` (the whole-zone conduit tap), and run **Statistics ▸ Conversations** (TCP): the SCADA master ↔ outstation on 20000 and the MQTT broker star on 1883, both crossing the `zone-fw` conduit between IEC-62443 zones.

**⌨ Type:** `l7`  — runs `tshark -r lab/twin/captures/conduit_live.pcap -q -z conv,tcp`

> **Check (expected):** the SCADA master↔outstation on 20000 and the broker star on 1883, both crossing zone-fw — plus the foothold 172.30.10.66, an endpoint that fits no legitimate role.

**⌨ Type:** `l7b`  — runs `tshark -r lab/twin/captures/conduit_live.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c ; tshark -r lab/twin/captures/mqtt_live.pcap  -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c`

> **Check (expected):** READ(1)/RESPONSE(129) polling from the SCADA master, plus the injected DIRECT_OPERATE(5); MQTT PUBLISH(3) telemetry plus the rogue CONNECT(1) and its injected PUBLISH.

**⌨ Type:** `l7c`  — runs `# (run from lab/twin/; the launcher pins the compose project 'ics-twin-liftstation') ; cd lab/twin && docker compose -p ics-twin-liftstation -f docker-compose.twin.yml \ ; exec adversary-foothold python master.py --host 172.30.10.12 --attack ; # ...and the MQTT command injection from the insecure cell: ; docker compose -p ics-twin-liftstation -f docker-compose.twin.yml \ ; exec iiot-gw python attacker.py`

> **Check (expected):** adversary-foothold: DIRECT_OPERATE(5) accepted, pumps forced off. attacker.py: CONNECT accepted with NO credentials, command PUBLISHed. The spill scoreboard (launch-twin.sh --logs) starts climbing.

**⌨ Type:** `l7d`  — runs `tshark -r lab/twin/captures/conduit_live.pcap -Y "dnp3.al.func==5" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func ; # and the MQTT anonymous connect the broker accepted: ; tshark -r lab/twin/captures/mqtt_live.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid`

> **Check (expected):** a DIRECT_OPERATE whose dnp3.src claims 100 (the master) but whose ip.src is 172.30.10.66 (the foothold) — the Level 3 link-vs-IP contradiction, now on five-zone traffic — and an anonymous CONNECT from mqtt-explorer-x.

**⌨ Type:** `l7e`  — runs `bash lab/twin/launch-twin.sh --hardened --attack ; cd lab/twin && docker compose -p ics-twin-liftstation -f docker-compose.twin.yml -f docker-compose.hardened.yml \ ; exec adversary-foothold python master.py --host 172.30.10.12 --attack`

> **Check (expected):** the DIRECT_OPERATE is refused (status != Success): SAv5 + the arm-latch reject a lone control and the allow-list drops the forged link. Even if a control is bypassed, the hardwired HH float force-starts the pump at 95% — the spill counter stays 0.

- **Read.** **This is your capstone artifact.** Diff the two runs — vulnerable `spill > 0` vs hardened `spill == 0` under identical write access — and the two `dnp3_control.log` files (add `--tools` for Zeek + CISA ICSNPP). Submit the twin evidence bundle (the conduit pcap + the plant-sim spill log + the Zeek logs) and grade it against **projects/ARTIFACT_RUBRIC.md** — R4 (invariant detection), R5 (the SSO High-Consequence Event), and R6 (proving the backstop holds under full write access).


## Check yourself

1. **On the live conduit capture, a DIRECT_OPERATE trip carries `dnp3.src`=100 (the master) but `ip.src`=172.30.10.66 (the foothold). Which Level 3 tell catches it, and why does the outstation still obey?**
   <details><summary>answer</summary>The link-address-vs-IP-source mismatch — `dnp3.src` (the 16-bit DNP3 link address) disagrees with `ip.src`. DNP3 authenticates neither, so with SAv5 off the outstation obeys any well-formed frame. It is the exact Level 3–4 tell, now on live multi-zone traffic.</details>

2. **You gave the attacker full DNP3 + MQTT write access in `--hardened` mode, yet the SSO spill counter stayed 0. What held it — and what did NOT?**
   <details><summary>answer</summary>An engineered process backstop held it: the hardwired high-high float force-starts the pump at 95%, plus the ST setpoint clamp/interlock — spill stays 0 even if authentication is fully bypassed. What did NOT hold it is trust in the network or the identity; the CIE 'even-if' guarantee is a physical/logic backstop, not an access control.</details>

3. **The same `docker compose exec adversary python master.py --attack` from `attacker_net` is dropped, while the foothold on `cell_net` succeeds. Why?**
   <details><summary>answer</summary>The nftables conduit firewall (`zone-fw`) between IEC-62443 zones blocks the cross-zone path from attacker_net, so the packet never reaches the outstation; the granted foothold sits inside cell_net, past the conduit. Segmentation is the defense-in-depth layer — the attack only lands once the attacker is already inside the zone.</details>

**Level up:** You can carry the Level 1–5 skills onto live, multi-zone twin traffic, force and observe a physical SSO spill, and demonstrate the CIE 'even-if' backstop that holds spill at 0 under full write access. Package the run as your capstone artifact for projects/ARTIFACT_RUBRIC.md.


---
