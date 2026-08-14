# -*- coding: utf-8 -*-
"""Leveled curriculum content (single source of truth) — introductory → university-style MP.

Progression: tooling → endpoints/conversations → message types → inside the packet →
security → detection → capstone Machine Problem. Every command/output was verified
against the shipped pcaps with tshark.
"""

LEVELS = [
    {
        "n": 0, "id": "orientation", "title": "Orientation — see it running",
        "subtitle": "One click, and the lab is already live",
        "difficulty": "Start here", "minutes": 10,
        "goal": "Confirm the environment is up and watch real DNP3 + MQTT packets move.",
        "objectives": [
            "Open the noVNC desktop and confirm Wireshark is capturing on 'lo'.",
            "Recognize that you are watching a live conversation between real endpoints.",
        ],
        "prereq": "None — this is the first level.",
        "background": [
            "This Codespace auto-started everything: an MQTT broker, a DNP3 outstation, a publishing sensor, "
            "a subscriber, a pump-controller, and Wireshark already capturing. You don't set anything up — you observe.",
            "Two protocols are flowing. **MQTT** is publish/subscribe messaging (IoT/IIoT telemetry). **DNP3** is a "
            "SCADA protocol (electric/water utilities). By the end of this path you'll read both down to the byte and "
            "catch an intruder in them.",
        ],
        "steps": [
            {"kind": "note", "text": "Open the forwarded port **6080** ('noVNC Desktop', password `vscode`). Wireshark is already open and capturing."},
            {"kind": "gui", "text": "In Wireshark's green display-filter bar, type `mqtt` and press Enter. Watch the telemetry. Then clear it and type `dnp3`."},
            {"kind": "cmd", "text": "# prefer the terminal? watch it headless:\ntshark -i lo -c 10 -f \"tcp port 1883 or tcp port 20000\"",
             "expect": "10 packets summarised — a mix of MQTT (1883) and DNP3 (20000)."},
            {"kind": "cmd", "text": "# re-run the attacks any time and watch them appear:\n./lab/intrude.sh", "expect": "MQTT anonymous connect + command injection, then a DNP3 trip."},
        ],
        "checkpoints": [
            {"q": "What are the two protocols you see, and what TCP ports identify them?",
             "a": "MQTT on TCP/1883 and DNP3 on TCP/20000.",
             "options": ["HTTP on 80 and HTTPS on 443", "MQTT on TCP/1883 and DNP3 on TCP/20000", "Modbus on 502 and DNP3 on 20000", "MQTT on 8883 and DNP3 on 19999"], "correct": 1},
            {"q": "Did you have to install or start anything?",
             "a": "No — the devcontainer auto-built and auto-started the whole lab."},
        ],
        "levelup": "You can see live `mqtt` and `dnp3` traffic in Wireshark (or tshark). Continue to Level 1.",
        "teaser": "Confirm the lab is live and watch real packets move.",
        "storybeat": "The lab is alive and already breathing. Something in this traffic moves wrong — you just cannot name it yet. First question, before anything else: who are all these hosts, and which one does not belong?",
        "evidence": "Two protocols share one wire — MQTT on TCP/1883 and DNP3 on TCP/20000 — and the whole lab auto-started. Nothing was installed by hand.",
    },

    {
        "n": 1, "id": "endpoints", "title": "Who is talking?",
        "subtitle": "Endpoints & conversations — the map before the message",
        "difficulty": "Introductory", "minutes": 25,
        "goal": "Identify every host, which ports they use, and who connects to whom — without opening a single packet's guts.",
        "objectives": [
            "List the IP endpoints in a capture and rank them by traffic.",
            "Identify TCP conversations and the server port that names the protocol.",
            "Spot the 'hub' (MQTT broker / DNP3 master↔outstation) and any host that looks out of place.",
        ],
        "prereq": "Level 0.",
        "background": [
            "Before you read bytes, understand the **graph**: who are the endpoints and who talks to whom. This is exactly "
            "how a real analyst starts triage. Two protocols, two shapes: MQTT is a **star** (every client talks to one "
            "broker); DNP3 is usually a **master↔outstation** pair. Anything that breaks the expected shape is a lead.",
        ],
        "steps": [
            {"kind": "cmd", "text": "tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z endpoints,ip",
             "expect": "10.10.20.10  (61 pkts)  <- the broker (busiest)\n10.10.20.30  (22)   <- HMI\n10.10.20.7   (22)   <- sensor\n10.10.20.66  (17)   <- rogue"},
            {"kind": "cmd", "text": "tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z conv,tcp",
             "expect": "three TCP conversations, all to 10.10.20.10:1883 — the broker is the hub."},
            {"kind": "gui", "text": "In Wireshark: **Statistics ▸ Conversations** (TCP tab) and **Statistics ▸ Endpoints** (IPv4). Then **Statistics ▸ Protocol Hierarchy** to see mqtt under tcp."},
            {"kind": "cmd", "text": "tshark -r pcaps/dnp3_substation.pcap -q -z conv,tcp",
             "expect": "the master (10.20.0.5) ↔ outstation (10.20.0.20:20000), plus a second session from 10.20.0.66 — the rogue."},
        ],
        "checkpoints": [
            {"q": "In the MQTT capture, which IP is the broker, and how did you know from endpoints alone?",
             "a": "10.10.20.10 — it has the most packets and is the common endpoint of every TCP conversation (the star center)."},
            {"q": "Which port tells you a conversation is MQTT? DNP3?",
             "a": "TCP/1883 = MQTT; TCP/20000 = DNP3 (the server side of each conversation).",
             "options": ["TCP/80 and TCP/443", "TCP/1883 for MQTT and TCP/20000 for DNP3", "TCP/502 and TCP/44818", "UDP/161 and UDP/162"], "correct": 1},
            {"q": "Which host looks out of place in each capture, before you've read any payload?",
             "a": "10.10.20.66 (MQTT) and 10.20.0.66 (DNP3) — extra endpoints that aren't the expected broker/master/outstation."},
        ],
        "levelup": "You can name the endpoints, the protocol ports, the hub, and the odd host out — using only conversation/endpoint statistics.",
        "teaser": "Map the endpoints and conversations before you read a single byte.",
        "storybeat": "You can draw the map now — the broker at the center of its star, the master and its outstation, and two .66 addresses that fit nowhere. But a map tells you who, not what. So what are these hosts actually saying to each other?",
        "evidence": "Two rogue endpoints stand out by shape alone: 10.10.20.66 on the MQTT side and 10.20.0.66 on the DNP3 side — hosts that are neither broker, master, nor outstation.",
    },

    {
        "n": 2, "id": "messages", "title": "What kind of messages?",
        "subtitle": "Message types & the request/response rhythm — the envelope",
        "difficulty": "Introductory", "minutes": 25,
        "goal": "Classify the control packets / function codes and see the protocol's rhythm — still on the surface, not yet inside the fields.",
        "objectives": [
            "Filter to a single protocol and read the Info column.",
            "Count the message types (MQTT control packets; DNP3 function codes).",
            "Tell request from response, and spot the control (write) messages among the reads.",
        ],
        "prereq": "Level 1.",
        "background": [
            "Every protocol has a small vocabulary of message types. MQTT: CONNECT/CONNACK, SUBSCRIBE/SUBACK, "
            "PUBLISH/PUBACK, PINGREQ/PINGRESP, DISCONNECT. DNP3: READ, RESPONSE, UNSOLICITED RESPONSE, SELECT, OPERATE, "
            "DIRECT OPERATE, COLD RESTART, CONFIRM. Learn to count them — anomalies often show up as the *wrong type* in "
            "the wrong place.",
        ],
        "steps": [
            {"kind": "cmd", "text": "tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c",
             "expect": "3 CONNECT(1), 3 CONNACK(2), 8 PUBLISH(3), 2 PUBACK(4), 2 SUBSCRIBE(8), 2 SUBACK(9), 1 PINGREQ(12), 1 PINGRESP(13), 1 DISCONNECT(14)."},
            {"kind": "cmd", "text": "tshark -r pcaps/dnp3_substation.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c",
             "expect": "READ(1)x2, SELECT(3), OPERATE(4), DIRECT_OPERATE(5), COLD_RESTART(13), RESPONSE(129)x6, UNSOL(130), CONFIRM(0)."},
            {"kind": "gui", "text": "Apply `mqtt` then `dnp3` in Wireshark and read the **Info** column top-to-bottom — you can follow the whole story without expanding a packet."},
            {"kind": "note", "text": "Controls are the dangerous ones: MQTT PUBLISH to a command topic, and DNP3 SELECT/OPERATE/DIRECT_OPERATE (function codes 3/4/5). Note how few there are — they're easy to enumerate."},
        ],
        "checkpoints": [
            {"q": "How many PUBLISH vs SUBSCRIBE packets are in the MQTT capture, and why so many more PUBLISH?",
             "a": "8 PUBLISH vs 2 SUBSCRIBE — telemetry is published repeatedly and fanned out by the broker, while a client subscribes once."},
            {"q": "Which DNP3 function codes are *controls*, and how many are there?",
             "a": "SELECT (3), OPERATE (4), DIRECT OPERATE (5) — three control messages. (COLD RESTART 13 is an admin control too.)",
             "options": ["READ (1) and RESPONSE (129)", "SELECT (3), OPERATE (4), and DIRECT_OPERATE (5)", "CONFIRM (0) only", "UNSOLICITED RESPONSE (130) only"], "correct": 1},
            {"q": "Which single DNP3 function code is the outstation talking without being asked?",
             "a": "UNSOLICITED RESPONSE (130) — a report-by-exception event."},
        ],
        "levelup": "You can enumerate message types for both protocols and point to the control messages — the surface is fully mapped.",
        "teaser": "Classify the control messages and feel the request and response rhythm.",
        "storybeat": "You can count the vocabulary — every CONNECT and PUBLISH, every SELECT and OPERATE — and point straight at the control messages. But a message type is only the envelope. What is written inside it? Time to open one up.",
        "evidence": "The dangerous verbs are few and now enumerated: DNP3 SELECT (3), OPERATE (4), and DIRECT_OPERATE (5), plus one UNSOLICITED RESPONSE (130) the outstation sent without being asked.",
    },

    {
        "n": 3, "id": "inside", "title": "Inside the packet",
        "subtitle": "Fields & layers — now we open it up",
        "difficulty": "Intermediate", "minutes": 40,
        "goal": "Read specific fields inside the packets: MQTT credentials/topics/QoS/retain, and DNP3's three layers, addresses, IIN, and control objects.",
        "objectives": [
            "Expand the protocol tree and read named fields; use Apply as Column.",
            "Extract exact field values with `tshark -T fields -e <field>`.",
            "Read a DNP3 CROB control code and distinguish the DNP3 link address from the IP address.",
        ],
        "prereq": "Level 2. This is where 'endpoints' turns into 'internals'.",
        "background": [
            "Now we dive in. In Wireshark, click a frame and expand the protocol tree in the middle pane; **hover a field** "
            "to see its filter name in the status bar, and **right-click ▸ Apply as Column** to pull it up. On the CLI, "
            "`-T fields -e <name>` prints exact values — the analyst's scalpel.",
            "DNP3 is layered: **data link** (0x0564 start, addresses, CRC) → **pseudo-transport** → **application** "
            "(function code, IIN, objects). The Control Relay Output Block (group 12 var 1) is the object that moves a breaker.",
        ],
        "steps": [
            {"kind": "cmd", "text": "# MQTT: read the cleartext login straight off the wire\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.clientid -e mqtt.username -e mqtt.passwd",
             "expect": "hmi-scada-01  hmi_operator  Plant!ntel2024   (…and the sensor's creds). Cleartext — no TLS."},
            {"kind": "cmd", "text": "# MQTT: topic, QoS and the RETAIN flag on each publish\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==3 -T fields -e frame.number -e mqtt.topic -e mqtt.qos -e mqtt.retain",
             "expect": "plant/tank1/telemetry with QoS 0 and 1; retain False. (mqtt.retain prints True/False.)"},
            {"kind": "gui", "text": "In Wireshark, click a DNP3 frame and expand **Distributed Network Protocol 3.0**: the Data Link Layer (Source/Destination link addresses + CRC), the Transport, and the Application Layer (Function Code, Internal Indications, Objects)."},
            {"kind": "cmd", "text": "# DNP3: compare the IP source with the DNP3 LINK source, and read the control\ntshark -r pcaps/dnp3_substation.pcap -Y \"dnp3.al.func in {3,4,5}\" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.ctl.trip -e dnp3.ctl.op",
             "expect": "the legitimate close (Close/Pulse-On) from the master, and the rogue Trip — note ip.src vs dnp3.src.",
             "consequence": "The CROB in this frame is what moves a 13.8 kV breaker — trip vs close is the difference between dark and lit."},
        ],
        "checkpoints": [
            {"q": "What is the HMI's MQTT password, and which field held it?",
             "a": "Plant!ntel2024, in mqtt.passwd — sent in cleartext inside the CONNECT."},
            {"q": "In DNP3, what's the difference between `ip.src` and `dnp3.src`?",
             "a": "ip.src is the network (IP) source; dnp3.src is the 16-bit DNP3 *link* address inside the data-link header. They can disagree — which is the whole game in Level 4.",
             "options": ["They are always identical by design", "ip.src is the IP source; dnp3.src is the 16-bit DNP3 link address — and they can disagree", "dnp3.src is the device MAC address", "ip.src is the TCP source port"], "correct": 1},
            {"q": "Which object carries a breaker command, and which fields tell you trip vs close?",
             "a": "The CROB (group 12 var 1). dnp3.ctl.trip = Trip/Close code; dnp3.ctl.op = operation type (e.g., pulse on)."},
        ],
        "levelup": "You can extract any field by name and read a DNP3 control down to trip-vs-close, and you understand IP-address vs DNP3-link-address.",
        "teaser": "Open the layers and read named fields down to the DNP3 control.",
        "storybeat": "You have read the fields with your own eyes — the cleartext password, the QoS and retain flags, and two source addresses that are supposed to agree and do not. You have seen the tell. Now prove it is an attack: find every planted anomaly and name exactly what each one breaks.",
        "evidence": "The MQTT login rides the wire in cleartext — Plant!ntel2024 in mqtt.passwd — and DNP3 carries two sources, ip.src and dnp3.src, that can be made to disagree.",
    },

    {
        "n": 4, "id": "security", "title": "Find the attack",
        "subtitle": "Security analysis — turn fields into findings",
        "difficulty": "Intermediate", "minutes": 35,
        "goal": "Use your field skills to locate the planted anomalies in the teaching captures and name the weakness each one exploits.",
        "objectives": [
            "Find the MQTT anomalies: cleartext creds, anonymous connect, '#' wildcard, unauthorized command publish.",
            "Find the DNP3 anomalies: spoofed source/link address, the unauthenticated trip, the cold restart.",
            "Tie each finding to a control (TLS, ACLs, DNP3-SA, segmentation).",
        ],
        "prereq": "Level 3. Read the modules' Security & Controls tab alongside this.",
        "background": [
            "Attacks in these protocols rarely look 'malformed' — they look like *valid messages from the wrong party*. "
            "That's why the field skills from Level 3 matter: the anomaly is a legal packet whose fields tell on it.",
        ],
        "steps": [
            {"kind": "cmd", "text": "# MQTT: anonymous CONNECT (no username) the broker accepted\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y \"mqtt.msgtype==1 && !mqtt.username\" -T fields -e frame.number -e mqtt.clientid",
             "expect": "frame 38, client mqtt-explorer-x — no credentials."},
            {"kind": "cmd", "text": "# MQTT: the '#' wildcard subscribe (eavesdrop-all) and the injected command\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.topic==\"#\" || mqtt.topic==\"plant/tank1/command\"' -T fields -e frame.number -e mqtt.msgtype -e mqtt.topic",
             "expect": "the '#' SUBSCRIBE and the PUBLISH to plant/tank1/command (frame 52)."},
            {"kind": "cmd", "text": "# DNP3: the unauthenticated trip and the cold restart, and who sent them\ntshark -r pcaps/dnp3_substation.pcap -Y \"dnp3.al.func==5 || dnp3.al.func==13\" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func",
             "expect": "DIRECT_OPERATE (5) and COLD_RESTART (13) from 10.20.0.66 — with dnp3.src forged to the master's 100.",
             "consequence": "This DIRECT_OPERATE trips a 13.8 kV feeder breaker — lights out downstream, from a host that never authenticated."},
            {"kind": "note", "text": "For each finding, open the matching module (modules/*.html) ▸ **Frame Explorer** and jump to that frame to read the full teaching note and the control that stops it."},
        ],
        "checkpoints": [
            {"q": "How does the outstation 'know' the trip in frame 27 came from the master?",
             "a": "It doesn't — DNP3 has no authentication. The frame's dnp3.src claims 100 (the master) but ip.src is 10.20.0.66. The link address is just a number the attacker wrote in."},
            {"q": "The anonymous MQTT client was accepted. Is the later command injection an authentication or authorization failure?",
             "a": "Authorization — the broker *authenticated* it (accepted the anonymous identity); it failed to *constrain* what that identity could publish (no topic ACL).",
             "options": ["Authentication — the broker rejected the identity", "Authorization — the identity was accepted, then never constrained on what it could publish", "Encryption — the payload was unreadable", "Integrity — the message was corrupted in transit"], "correct": 1},
        ],
        "levelup": "You can locate every planted anomaly by field evidence and state the weakness + control for each.",
        "teaser": "Turn field evidence into named findings and the control that stops each.",
        "storybeat": "Every anomaly is located and named. The trip in frame 27 claims dnp3.src=100 — the master — yet it arrived from 10.20.0.66, the ghost. You can catch it by hand. But you cannot watch the wire all night. Can a rule catch it for you — one a clever attacker cannot slip past?",
        "evidence": "The signature is forged: a DIRECT_OPERATE trip carrying dnp3.src=100 (the master's link address) but ip.src=10.20.0.66. DNP3 authenticates nothing — the link address is only a number the attacker wrote in.",
    },

    {
        "n": 5, "id": "detection", "title": "Catch it automatically",
        "subtitle": "Detection engineering — from one packet to a rule",
        "difficulty": "Advanced", "minutes": 40,
        "goal": "Write detection that survives a real adversary — key on invariants, not on a single spoofable field — and turn packets into logs with Zeek + CISA ICSNPP.",
        "objectives": [
            "Write tshark/display-filter detections for the anomalies.",
            "Run Zeek + the ICSNPP DNP3 parser and read dnp3_control.log / mqtt_*.log.",
            "Explain why 'alert on wrong source IP' is naive and what invariant beats it.",
        ],
        "prereq": "Level 4.",
        "background": [
            "A detection is only as good as its evasion resistance. The obvious DNP3 rule — 'alert if a control's source "
            "IP isn't the master' — fails the moment the attacker spoofs the master's IP. The durable rule binds an "
            "**invariant**: {DNP3 link address ↔ expected source ↔ known-master set ↔ SELECT-before-OPERATE}. Read the "
            "modules' 'Detection under adversarial and operational reality' section.",
        ],
        "steps": [
            {"kind": "cmd", "text": "# a first-cut DNP3 rule: controls not from the master IP\ntshark -r pcaps/dnp3_substation.pcap -Y \"dnp3.al.func in {3,4,5,13} && ip.src != 10.20.0.5\" -T fields -e frame.number -e ip.src -e dnp3.al.func",
             "expect": "catches the rogue trip & restart HERE — but only because the attacker kept its real IP."},
            {"kind": "cmd", "text": "# turn packets into readable logs with Zeek + CISA ICSNPP\ndocker compose -f lab/docker-compose.yml --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap\ncat lab/zeek_reference_output/dnp3/dnp3_control.log | grep -i direct",
             "expect": "a DIRECT_OPERATE / Trip / Success line whose source host is 10.20.0.66 — your best single alert."},
            {"kind": "cmd", "text": "# MQTT detections: anonymous connect, and a '#' subscribe\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y \"mqtt.msgtype==1 && !mqtt.username\" -T fields -e frame.number\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.msgtype==8 && mqtt.topic==\"#\"' -T fields -e frame.number",
             "expect": "the anonymous CONNECT and the wildcard SUBSCRIBE."},
            {"kind": "note", "text": "Now break your own rule: in the lab, re-run the DNP3 attack with `--src-addr 100` (spoofing the master's link address) and with a spoofed IP, and watch the naive source-IP rule miss it. That's why Level 6 asks for an invariant detector."},
        ],
        "checkpoints": [
            {"q": "Why is 'alert when a control's source IP isn't the master' insufficient?",
             "a": "The source IP (and the DNP3 link address) are attacker-controlled/spoofable, and real outstations answer to *several* legitimate masters — so it both misses spoofed sources and false-positives on backups/FEPs.",
             "options": ["It is too slow to compute at line rate", "The source IP and link address are attacker-spoofable, and real outstations answer several legitimate masters", "Zeek cannot parse DNP3 at all", "It only works for MQTT traffic"], "correct": 1},
            {"q": "What does Zeek + ICSNPP give you that a raw pcap doesn't?",
             "a": "Structured, queryable logs (dnp3_control.log, dnp3_objects.log, mqtt_*.log) you can alert and hunt on at scale — e.g., every control with its operation type, source host, and status."},
        ],
        "levelup": "You can write detections, generate ICSNPP logs, and articulate the invariant-based rule that resists spoofing. You are ready for the Machine Problem.",
        "teaser": "Write detection that keys on invariants, not on spoofable fields.",
        "storybeat": "You can write a detection that survives a spoof — bound to the invariant, not the address — and you are holding the exact evidence pattern the ghost leaves behind. One trial remains: two captures you have never seen, attacks you have not walked, and only your judgment to catch them.",
        "evidence": "The durable rule binds an invariant — SELECT-before-OPERATE, and link-address matching source-IP matching a known-master set — because a naive wrong-source-IP alert dies the instant the attacker spoofs the master.",
    },

    {
        "n": 6, "id": "mp", "title": "Machine Problem — ICS Intrusion Analysis",
        "subtitle": "Capstone: analyze two unseen captures, build a detector, write the incident up",
        "difficulty": "University-level capstone", "minutes": 120,
        "goal": "Apply Levels 1–5 to captures you've never seen, using DIFFERENT attacks. Autograded (100 pts) + a written incident report.",
        "objectives": [
            "Triage two unseen captures and prove findings with named fields (Part 1, autograded).",
            "Implement an invariant-based detector.py (Part 2, autograded).",
            "Write an incident report with evidence, authN-vs-authZ, and controls (Part 3 + rubric).",
        ],
        "prereq": "Levels 1–5.",
        "background": [
            "This is a formal, university-style Machine Problem. The handout, the two evidence captures, an answer template, a "
            "self-check autograder, and the report rubric are all in the **`mp/`** folder. The attacks are new: a spoofed "
            "DNP3 status report (not a control), and an MQTT retained-message harvest + persistent command injection.",
        ],
        "steps": [
            {"kind": "cmd", "text": "cd mp && cat README.md      # the full handout: parts, deliverables, grading",
             "expect": "MP: ICS Intrusion Analysis — Parts 1–3 + bonus."},
            {"kind": "cmd", "text": "# analyze the two unseen captures\n../lab/open-wireshark.sh captures/dnp3_assessment.pcap\ntshark -r captures/mqtt_assessment.pcap -Y mqtt",
             "expect": "two captures you have not walked — apply everything from Levels 1–5."},
            {"kind": "cmd", "text": "# fill submission/answers.json, write detector.py and report.md, then self-check:\npython3 grade.py",
             "expect": "PASS/FAIL per item and a score /100. Iterate to green."},
        ],
        "checkpoints": [
            {"q": "Where is the handout, and how do you check your work?",
             "a": "mp/README.md is the handout; `python3 mp/grade.py` autogrades Part 1 (answers.json) + Part 2 (detector.py) + Part 3 (format), and mp/rubric.md scores the written report."},
            {"q": "Why must your detector.py use an invariant instead of printing the frame number?",
             "a": "The proctored re-run uses a freshly generated capture with different addresses; only an invariant (link-address↔IP inconsistency; anon-connect↔retained-command) generalizes."},
        ],
        "levelup": "Score 90+ on the autograder and meet the report rubric's mastery gates. You've completed the path.",
        "teaser": "The capstone: two unseen captures, a detector you build, an incident you write up.",
        "storybeat": "First light. You walked in unable to see the intruder; you leave able to catch one you have never met. The wire keeps no more secrets from you — go find the next one.",
        "evidence": "Mastery: the same pattern — a forged source, cleartext credentials, an invariant broken — generalizes to captures you have never seen.",
        "is_mp": True,
    },
]
