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
