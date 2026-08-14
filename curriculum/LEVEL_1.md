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
