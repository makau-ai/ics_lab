# -*- coding: utf-8 -*-
"""Structured content for the MQTT teaching module (single source of truth)."""

MQTT = {
    "id": "mqtt",
    "protocol": "MQTT",
    "title": "MQTT — Message Queuing Telemetry Transport",
    "subtitle": "Reading an IIoT telemetry conversation, frame by frame",
    "port": "TCP/1883 (plaintext) · TCP/8883 (MQTT over TLS)",
    "spec": "OASIS MQTT Version 3.1.1",
    "pcap": "mqtt_iot_telemetry.pcap",
    "level": "Protocol analysis & defensive recognition — not an offensive tradecraft course. Intermediate (TCP/IP + basic Wireshark; new to IoT/OT)",

    "overview": [
        "MQTT is the lightweight publish/subscribe protocol behind an enormous amount of the Internet of Things and "
        "Industrial IoT (IIoT). Instead of clients talking directly to each other, every device connects to a central "
        "**broker**. Publishers send messages to named **topics**; subscribers ask the broker for topics they care about; "
        "the broker fans each message out to whoever subscribed. A field sensor never needs to know who — if anyone — is "
        "listening.",

        "That decoupling is what makes MQTT scale to millions of devices over flaky, low-bandwidth links. It also concentrates "
        "risk at the broker: whoever can reach it, and whatever the broker is (mis)configured to allow, defines the security "
        "of the whole system. MQTT 3.1.1 itself provides only optional username/password authentication — sent in cleartext "
        "unless you add TLS — and **no authorization model at all**. Topic access control is left entirely to the broker.",

        "You will analyze `mqtt_iot_telemetry.pcap`, a curated 61-frame capture of a small plant telemetry deployment: an "
        "HMI dashboard subscribes, a field sensor publishes tank readings, and the broker fans them out. Then a rogue host "
        "connects anonymously, subscribes to everything, and injects a command. Every frame number and field in this module "
        "was produced and verified with Wireshark/tshark and Zeek's MQTT analyzer."
    ],

    "objectives": [
        "Explain the MQTT publish/subscribe model and the broker's central role, and predict which clients receive a given published message from the subscription table.",
        "From a capture, identify the core control packets (CONNECT, CONNACK, SUBSCRIBE, SUBACK, PUBLISH, PUBACK, PINGREQ/PINGRESP, DISCONNECT) and extract connection details from a CONNECT (client ID, clean session, keep-alive, username/password, Last Will), reading cleartext credentials directly off the wire.",
        "Trace a single reading from publisher through the broker to every subscriber, and explain how QoS and the RETAIN flag change what a newly-connecting client receives, distinguishing a live PUBLISH from a delivered retained message by the RETAIN bit.",
        "[Assessed] Given an unseen capture with several legitimate publishers and a buried abuse, differentiate normal telemetry from a retained-message harvest and from an unauthorized (retained) command injection, justifying each finding by citing the packet type, topic, and RETAIN/return-code fields.",
        "[Assessed] Distinguish an authentication failure from an authorization failure in an MQTT intrusion — determining from CONNECT/CONNACK whether the rogue was accepted, and from the PUBLISH/SUBSCRIBE whether the abuse is a missing read or write ACL — and critique a proposed 'reject #-subscriptions' defense by showing how the attacker still succeeds.",
        "Given the insecure broker, recommend a layered hardening plan (allow_anonymous false, per-topic read/write ACLs bound to identity, TLS on 8883, retained-message and command-topic controls) and predict how the capture changes after each control.",
        "Using Zeek's MQTT analyzer, produce mqtt_connect/publish/subscribe logs and derive detections for anonymous CONNECTs and for '#'/retained-message abuse, naming the log field each alert keys on."
    ],

    "callouts": [
        {"tone":"scope","title":"Scope & threat model — read this first",
         "body":"This module teaches you to **read** MQTT and **recognize** its weaknesses on the wire. It does **not** teach you to attack a plant — it deliberately hands you the one thing a real operator-of-harm must earn first: reachability to the broker (or a position on the client↔broker path).\n\nThe real ICS/IIoT kill chain (MITRE ATT&CK for ICS): Initial Access → pivot into the OT/IIoT network (Lateral Movement) → recon & topic/asset enumeration (Discovery; Network Sniffing T0842) → **the injection you practice here** (Unauthorized Command Message, T0855) → optional impact/persistence (Manipulation of Control T0831).\n\nThe frame-52 command PUBLISH is the **last ~5%**. The enumeration, the L2 adjacency to the broker/client, and the broker access that precede it are the hard 95% — and are out of scope here. See 'What would make this real offense' below."}
    ],

    "industry": {
        "intro":
            "MQTT rarely appears in isolation — it is the connective tissue of modern telemetry, spanning consumer smart "
            "homes up through industrial sensor fleets and cloud IoT platforms. In OT settings it increasingly rides "
            "alongside legacy SCADA as plants add sensors and push data to analytics.",
        "sectors": [
            ["Industrial IoT & smart manufacturing",
             "Sensor-to-cloud telemetry for vibration, temperature, energy, and predictive-maintenance data; MQTT (often via "
             "Sparkplug B) links edge gateways to historians and dashboards."],
            ["Utilities & smart infrastructure",
             "Water/energy telemetry from distributed assets, smart-metering backhaul, and building-management sensor data — "
             "exactly the 'plant/tank1/telemetry' pattern in this capture."],
            ["Connected products & smart home",
             "Thermostats, locks, trackers, and hubs almost universally speak MQTT to a cloud broker; much public MQTT "
             "exposure research comes from this sector."],
            ["Connected vehicles, logistics & healthcare",
             "Fleet/asset location, cold-chain monitoring, and device telemetry where MQTT's low overhead suits cellular links."]
        ],
        "use_cases": [
            "Telemetry ingestion: many sensors PUBLISH readings to per-asset topics; a dashboard SUBSCRIBEs with a wildcard to see them all.",
            "Command & control: a controller PUBLISHes to a command topic a device is subscribed to (the pattern the attacker abuses in frame 52).",
            "Presence & health: the Last Will & Testament lets the broker announce a device 'offline' automatically if it drops.",
            "Store-and-forward: QoS 1/2 and retained messages let intermittently-connected devices exchange data reliably."
        ]
    },

    "anatomy": {
        "intro":
            "Every MQTT packet begins with a 2-byte-minimum fixed header: a control packet type in the high nibble of byte 1, "
            "flags in the low nibble, and a variable-length 'remaining length' field. Most types then carry a variable header "
            "and payload. Wireshark decodes all of this under the 'MQ Telemetry Transport Protocol' tree.",
        "layers": [
            ["Fixed header",
             "Byte 1 high nibble = packet type (CONNECT=1, CONNACK=2, PUBLISH=3, PUBACK=4, SUBSCRIBE=8, SUBACK=9, "
             "PINGREQ=12, PINGRESP=13, DISCONNECT=14). For PUBLISH the low nibble carries DUP, QoS (2 bits), and RETAIN. "
             "Then a 1–4 byte Remaining Length.",
             "type(4b) | flags(4b) | remaining-length(1–4B)"],
            ["CONNECT variable header & payload",
             "Protocol name 'MQTT', level 4 (=3.1.1), a connect-flags byte (username, password, will retain, will QoS, will "
             "flag, clean session), and keep-alive. Payload order: client ID, will topic, will message, username, password.",
             "'MQTT' · level · connect-flags · keep-alive · [client-id, will, user, pass]"],
            ["PUBLISH / SUBSCRIBE",
             "PUBLISH carries a topic name, a packet identifier (only if QoS>0), then the payload bytes. SUBSCRIBE carries a "
             "packet identifier and one or more (topic filter + requested-QoS) pairs; SUBACK returns a granted-QoS code per filter.",
             "topic · [packet-id if QoS>0] · payload"]
        ],
        "funcs": [
            ["1", "CONNECT", "Client → broker: open a session (carries credentials, will, keep-alive)."],
            ["2", "CONNACK", "Broker → client: accept (return code 0) or refuse."],
            ["3", "PUBLISH", "Send a message to a topic (either direction, via the broker)."],
            ["4", "PUBACK", "Acknowledge a QoS-1 PUBLISH."],
            ["8", "SUBSCRIBE", "Client → broker: register interest in topic filter(s)."],
            ["9", "SUBACK", "Broker → client: granted QoS per requested filter."],
            ["12/13", "PINGREQ / PINGRESP", "Keep-alive heartbeat in both directions."],
            ["14", "DISCONNECT", "Client → broker: clean shutdown of the session."]
        ]
    },

    "capture": {
        "scenario":
            "A Mosquitto broker (10.10.20.10:1883) serves a small plant. An HMI dashboard (10.10.20.30) subscribes to "
            "'plant/+/telemetry'; a field sensor (10.10.20.7) connects with a Last Will and publishes tank readings, which "
            "the broker fans out to the HMI. Then a rogue host (10.10.20.66) connects with no credentials, subscribes to '#' "
            "(every topic), receives the leaked telemetry, and publishes a command to 'plant/tank1/command'.",
        "topology": [
            ["MQTT broker", "10.10.20.10:1883", "Mosquitto broker — the hub every client connects to"],
            ["HMI / dashboard", "10.10.20.30", "SCADA/HMI subscriber to plant/+/telemetry"],
            ["Field sensor", "10.10.20.7", "Publishes plant/tank1/telemetry; sets a Last Will & Testament"],
            ["Rogue host", "10.10.20.66", "Connects anonymously, subscribes to #, injects a command"]
        ],
        "stats": "61 frames · 3 TCP streams · TCP/1883 · subscribe + publish fan-out + anonymous eavesdrop/inject"
    },

    "frames": [
        {"n":1,"t":"0.000","src":"10.10.20.30","dst":"10.10.20.10","layer":"TCP","summary":"49512 → 1883 [SYN]",
         "plain":"The HMI opens a TCP connection to the broker on MQTT's default plaintext port 1883.",
         "fields":[["Dst port","1883 (MQTT)"],["Flags","SYN"]],
         "teach":"Port 1883 is unencrypted MQTT. Its secure sibling is 8883 (MQTT over TLS). Seeing 1883 tells you every byte that follows — including passwords — is readable on the wire.",
         "security":{"level":"info","note":"Plaintext port. The same conversation on 8883 would be opaque to a sniffer."},
         "filter":"tcp.port==1883 && tcp.flags.syn==1"},

        {"n":4,"t":"0.002","src":"10.10.20.30","dst":"10.10.20.10","layer":"MQTT","summary":"Connect Command (hmi-scada-01)",
         "plain":"The HMI's CONNECT. It identifies itself, requests a clean session, sets a 60-second keep-alive, and supplies a username and password — all visible in Wireshark.",
         "fields":[["Client ID","hmi-scada-01"],["Clean session","Set"],["Keep-alive","60 s"],["Username","hmi_operator"],["Password","Plant!ntel2024 (cleartext!)"]],
         "teach":"Expand the CONNECT tree in Wireshark and you will read the password in plain ASCII. MQTT credentials are part of the CONNECT payload with no protection of their own.",
         "security":{"level":"critical","note":"Cleartext credential exposure. Anyone on-path harvests hmi_operator / Plant!ntel2024 with no cracking required. TLS (8883) is the fix."},
         "filter":"mqtt.msgtype==1"},

        {"n":6,"t":"0.004","src":"10.10.20.10","dst":"10.10.20.30","layer":"MQTT","summary":"Connect Ack (accepted)",
         "plain":"The broker accepts the connection with return code 0 (Connection Accepted). The HMI now has a live session.",
         "fields":[["Msg type","CONNACK (2)"],["Return code","0 — Connection Accepted"],["Session present","0"]],
         "teach":"A return code of 0 means success; codes 1–5 are refusals (bad protocol level, bad credentials, not authorized, etc.). Watching CONNACK codes tells you whether a broker is enforcing anything.",
         "security":None,"filter":"mqtt.msgtype==2"},

        {"n":8,"t":"0.006","src":"10.10.20.30","dst":"10.10.20.10","layer":"MQTT","summary":"Subscribe Request [plant/+/telemetry]",
         "plain":"The HMI subscribes to 'plant/+/telemetry' at QoS 1. The '+' is a single-level wildcard: it matches plant/tank1/telemetry, plant/tank2/telemetry, and so on — but only one level.",
         "fields":[["Msg type","SUBSCRIBE (8)"],["Packet id","1"],["Topic filter","plant/+/telemetry"],["Requested QoS","1"]],
         "teach":"Wildcards are how one dashboard follows many assets. '+' matches exactly one level; '#' (later) matches everything beneath a point. Scoping subscriptions tightly is both good design and a security control.",
         "security":None,"filter":"mqtt.msgtype==8"},

        {"n":10,"t":"0.007","src":"10.10.20.10","dst":"10.10.20.30","layer":"MQTT","summary":"Subscribe Ack (granted QoS 1)",
         "plain":"The broker grants the subscription at QoS 1 and returns the matching packet identifier.",
         "fields":[["Msg type","SUBACK (9)"],["Packet id","1"],["Granted QoS","1"]],
         "teach":"SUBACK returns a granted-QoS code per requested filter (0/1/2), or 0x80 for failure. A broker that enforced ACLs could refuse here — this one grants everything.",
         "security":None,"filter":"mqtt.msgtype==9"},

        {"n":15,"t":"0.361","src":"10.10.20.7","dst":"10.10.20.10","layer":"MQTT","summary":"Connect Command (field-sensor-07, with Will)",
         "plain":"The field sensor connects. Besides credentials, it registers a Last Will & Testament: if it drops unexpectedly, the broker will publish 'offline' to plant/tank1/status on its behalf.",
         "fields":[["Client ID","field-sensor-07"],["Keep-alive","30 s"],["Username / Password","sensor_svc / s3ns0r-pw (cleartext)"],["Will topic","plant/tank1/status"],["Will payload","offline"]],
         "teach":"The Will is MQTT's dead-man's switch — how a fleet knows a device died without polling it. You can read the will topic and payload right in the CONNECT.",
         "security":{"level":"warn","note":"Second set of cleartext credentials. Also note: a will payload is attacker-readable intelligence about topic structure."},
         "filter":"mqtt.msgtype==1 && mqtt.willtopic"},

        {"n":19,"t":"0.364","src":"10.10.20.7","dst":"10.10.20.10","layer":"MQTT","summary":"Publish [plant/tank1/telemetry] QoS 0",
         "plain":"The sensor publishes a tank reading to plant/tank1/telemetry at QoS 0 (fire-and-forget). The JSON payload — level, temperature, flow — is fully visible.",
         "fields":[["Msg type","PUBLISH (3)"],["Topic","plant/tank1/telemetry"],["QoS","0"],["Payload","{\"level_pct\":72.4,\"temp_c\":21.6,\"flow_lpm\":11.8}"]],
         "teach":"QoS 0 means at-most-once: no PUBACK, minimal overhead — typical for high-rate telemetry. The payload format is entirely up to the application (here, JSON).",
         "security":{"level":"info","note":"Process data in the clear. Over time, captured telemetry reveals plant behavior and setpoints (the reconnaissance value Trend Micro documented at scale)."},
         "filter":"mqtt.msgtype==3 && mqtt.topic==\"plant/tank1/telemetry\""},

        {"n":21,"t":"0.366","src":"10.10.20.10","dst":"10.10.20.30","layer":"MQTT","summary":"Publish → HMI (broker fan-out, QoS 0)",
         "plain":"The broker forwards the sensor's reading to the HMI, which subscribed to a matching filter. The HMI subscribed at QoS 1, but the sensor published at QoS 0 — so the broker delivers at QoS 0, with no packet id and no PUBACK.",
         "fields":[["Msg type","PUBLISH (3)"],["Direction","broker → subscriber"],["QoS","0 (delivered)"],["Topic","plant/tank1/telemetry"]],
         "teach":"This is the pub/sub magic in two frames: the sensor (frame 19) never addressed the HMI — the broker matched the topic to the subscription and delivered it (frame 21). Delivery QoS is the minimum of the publish QoS and the subscription's max QoS, so a broker may downgrade but never upgrade it.",
         "security":None,"filter":"mqtt.msgtype==3 && ip.dst==10.10.20.30"},

        {"n":23,"t":"0.566","src":"10.10.20.7","dst":"10.10.20.10","layer":"MQTT","summary":"Publish [plant/tank1/telemetry] QoS 1 (id=15)",
         "plain":"The next reading is published at QoS 1 (at-least-once). Because QoS>0 it carries a packet identifier (15); the broker acknowledges it with a PUBACK (frame 25) and — since the HMI also subscribed at QoS 1 — fans it out to the HMI at QoS 1 (frame 27).",
         "fields":[["Msg type","PUBLISH (3)"],["Topic","plant/tank1/telemetry"],["QoS","1"],["Packet id","15"],["Payload","{\"level_pct\":73.1,\"temp_c\":21.7,\"flow_lpm\":12.0}"]],
         "teach":"Contrast with frame 19: QoS 1 adds a packet identifier and a guaranteed acknowledgement, at the cost of extra frames. Sensors mix QoS 0 for cheap high-rate telemetry and QoS 1 for readings that must not be lost.",
         "security":None,"filter":"mqtt.msgtype==3 && mqtt.qos==1"},

        {"n":29,"t":"0.570","src":"10.10.20.30","dst":"10.10.20.10","layer":"MQTT","summary":"Publish Ack (id=41)",
         "plain":"The HMI acknowledges the QoS-1 delivery it received from the broker (frame 27) with a PUBACK carrying the same packet identifier, closing the at-least-once loop.",
         "fields":[["Msg type","PUBACK (4)"],["Packet id","41"]],
         "teach":"Match packet ids to pair each QoS-1 PUBLISH with its PUBACK. Note the ids differ per hop (15 for sensor→broker, 41 for broker→HMI): each MQTT link manages its own identifiers.",
         "security":None,"filter":"mqtt.msgtype==4"},

        {"n":31,"t":"0.874","src":"10.10.20.7","dst":"10.10.20.10","layer":"MQTT","summary":"Ping Request (keep-alive)",
         "plain":"With no data to send, the sensor sends a PINGREQ to keep its session alive within the 30-second keep-alive window.",
         "fields":[["Msg type","PINGREQ (12)"],["Payload","none"]],
         "teach":"PINGREQ/PINGRESP is a 2-byte heartbeat. If the broker hears nothing for 1.5× keep-alive, it considers the client dead and fires its Will. Heartbeats are how brokers detect silent drop-offs.",
         "security":None,"filter":"mqtt.msgtype==12 || mqtt.msgtype==13"},

        {"n":38,"t":"1.280","src":"10.10.20.66","dst":"10.10.20.10","layer":"MQTT","summary":"⚠ Connect Command (anonymous)","anomaly":True,
         "plain":"A rogue host connects with client ID 'mqtt-explorer-x' and NO username or password. Whether this succeeds depends entirely on the broker's allow_anonymous setting.",
         "fields":[["Client ID","mqtt-explorer-x"],["Username","(none)"],["Password","(none)"],["Clean session","Set"]],
         "teach":"Compare this CONNECT to frames 4 and 15: the connect flags have no username/password bits set. An anonymous connect is only as safe as the broker's configuration.",
         "security":{"level":"critical","note":"Anonymous access attempt. Mosquitto 2.0+ defaults to allow_anonymous false, but countless internet-exposed brokers set it true — Avast found ~32,000 brokers with no password at all."},
         "filter":"mqtt.msgtype==1 && !mqtt.username"},

        {"n":40,"t":"1.281","src":"10.10.20.10","dst":"10.10.20.66","layer":"MQTT","summary":"⚠ Connect Ack (accepted anonymously)","anomaly":True,
         "plain":"The broker accepts the anonymous client with return code 0. This broker is misconfigured to allow_anonymous true — the rogue host now has a full session.",
         "fields":[["Msg type","CONNACK (2)"],["Return code","0 — Connection Accepted"]],
         "teach":"A return code of 0 to a credential-less CONNECT is the single clearest 'this broker is open' signal you can find in a capture.",
         "security":{"level":"critical","note":"The broker authorized an unauthenticated client. Set allow_anonymous false and require a password_file (or client certificates)."},
         "filter":"mqtt.msgtype==2 && ip.dst==10.10.20.66"},

        {"n":42,"t":"1.283","src":"10.10.20.66","dst":"10.10.20.10","layer":"MQTT","summary":"⚠ Subscribe Request [#] — all topics","anomaly":True,
         "plain":"The rogue host subscribes to '#', the multi-level wildcard that matches every topic on the broker. In one request it asks to receive everything the broker relays.",
         "fields":[["Msg type","SUBSCRIBE (8)"],["Topic filter","# (multi-level wildcard)"],["Requested QoS","0"]],
         "teach":"'#' at the root is the classic MQTT eavesdropping move — and a favorite of exposure researchers, because an open broker will happily stream its entire message flow to whoever asks.",
         "security":{"level":"critical","note":"Full-broker eavesdrop. With no topic ACLs, the broker will grant it. This is exactly how public MQTT scans harvest sensitive data (Lundgren, DEF CON 24)."},
         "filter":"mqtt.msgtype==8 && mqtt.topic==\"#\""},

        {"n":50,"t":"1.441","src":"10.10.20.10","dst":"10.10.20.66","layer":"MQTT","summary":"⚠ Publish → rogue host (data leaked)","anomaly":True,
         "plain":"Because the rogue host subscribed to '#', the broker now forwards the plant's telemetry to it — the attacker passively collects live process data.",
         "fields":[["Msg type","PUBLISH (3)"],["Direction","broker → rogue subscriber"],["Topic","plant/tank1/telemetry"],["Payload","{\"level_pct\":73.6,…}"]],
         "teach":"Trace it: the sensor published (frame 46), and the broker delivered the same message to both the legitimate HMI (frame 48) and the eavesdropper (frame 50). The attacker did nothing but subscribe.",
         "security":{"level":"critical","note":"Confidentiality breach with no exploit — just a subscription. Topic ACLs restricting which clients may read which topics would have blocked this."},
         "filter":"mqtt.msgtype==3 && ip.dst==10.10.20.66"},

        {"n":52,"t":"1.642","src":"10.10.20.66","dst":"10.10.20.10","layer":"MQTT","summary":"⚠ Publish [plant/tank1/command] — injection","anomaly":True,
         "plain":"The rogue host publishes a command to 'plant/tank1/command' — {\"actuator\":\"pump1\",\"cmd\":\"START\",\"valve\":\"open\"}. Any device subscribed to that command topic would act on it.",
         "fields":[["Msg type","PUBLISH (3)"],["Topic","plant/tank1/command"],["Payload","{\"actuator\":\"pump1\",\"cmd\":\"START\",\"valve\":\"open\"}"],["QoS","0"]],
         "teach":"MQTT has no concept of 'who is allowed to publish here.' The broker accepts the write purely because nothing stops it. If an actuator trusts this topic, the attacker just moved physical equipment.",
         "security":{"level":"critical","note":"Unauthorized command injection. Controls: broker ACLs scoping write access per client/topic; authenticate and validate commands at the subscriber; separate telemetry and command brokers/credentials."},
         "filter":"mqtt.msgtype==3 && mqtt.topic==\"plant/tank1/command\""},

        {"n":54,"t":"1.644","src":"10.10.20.66","dst":"10.10.20.10","layer":"MQTT","summary":"⚠ Disconnect","anomaly":True,
         "plain":"The rogue host cleanly disconnects, having harvested credentials-free telemetry and injected a command — a full intrusion in a handful of frames.",
         "fields":[["Msg type","DISCONNECT (14)"],["Payload","none"]],
         "teach":"A clean DISCONNECT suppresses the client's Will. Reviewing this whole session end-to-end (frames 38–54) is a compact case study in what an open broker allows.",
         "security":{"level":"info","note":"The entire rogue session took under half a second and left almost no trace at the application layer — which is why broker-side auth/authorization and network monitoring matter."},
         "filter":"mqtt.msgtype==14"}
    ],

    "security": [
        {"id":"M1","severity":"critical","title":"Cleartext credentials on port 1883",
         "frames":[4,15],
         "risk":"MQTT username/password live in the CONNECT payload with no protection. On plaintext 1883 (frames 4 and 15) anyone on-path reads them directly in Wireshark — here, hmi_operator / Plant!ntel2024 and sensor_svc / s3ns0r-pw.",
         "realworld":"Exposed-broker research (Lucas Lundgren, DEF CON 24, 2016) repeatedly found brokers with weak or sniffable credentials; the protocol offers no credential protection on its own.",
         "attack":"Credential capture / sniffing",
         "control":"Run MQTT over TLS on 8883 so the whole CONNECT — credentials included — is encrypted. Use strong, unique per-client credentials or, better, client certificates. Never expose 1883 beyond a trusted segment."},

        {"id":"M2","severity":"high","title":"No transport encryption — telemetry & topics in the clear",
         "frames":[19,50],
         "risk":"On 1883 every topic name and payload is visible (frames 19, 50). Captured over time, plant telemetry reveals process behavior, setpoints, and topic structure — a reconnaissance goldmine — and messages can be intercepted or tampered with in transit.",
         "realworld":"Trend Micro (2018) observed over 200 million MQTT messages leaking from exposed brokers in a four-month window, including data usable for reconnaissance and lateral movement.",
         "attack":"Interception / passive collection",
         "control":"TLS on 8883 for confidentiality and integrity; segment IoT/OT networks so capture points are limited; avoid putting sensitive data in topic names."},

        {"id":"M3","severity":"critical","title":"Anonymous / unauthenticated access",
         "frames":[38,40],
         "risk":"If the broker allows anonymous connections, a client with no credentials gets a full session (frames 38–40) and can subscribe and publish like any other.",
         "realworld":"Avast (2018) used Shodan to find roughly 49,000 internet-exposed MQTT brokers, of which about 32,000–33,000 had no password protection at all — smart-home dashboards, locks, and location feeds reachable by anyone.",
         "attack":"Unauthorized access",
         "control":"Set allow_anonymous false and require a password_file or client certificates. Firewall the broker so only known clients can reach it; never expose it to the internet unintentionally."},

        {"id":"M4","severity":"high","title":"No authorization — wildcard eavesdropping",
         "frames":[42,50],
         "risk":"MQTT 3.1.1 defines no access control. Absent broker-side ACLs, any client can subscribe to '#' and receive every message the broker relays (frames 42, 50) — instant, silent confidentiality loss.",
         "realworld":"Subscribing to '#' on open brokers is the standard technique in public MQTT exposure studies; it requires no exploit, only a subscription.",
         "attack":"Eavesdropping / data collection",
         "control":"Enforce per-topic ACLs at the broker (Mosquitto acl_file, or EMQX/HiveMQ equivalents): scope each client to only the topics it needs. Brokers enforce ACLs per message topic, so a client receives nothing outside its grant even if it subscribes to '#'. Combine with authentication (control M3) so ACLs bind to identity — that is what stops the anonymous rogue client, at CONNECT, before any subscription."},

        {"id":"M5","severity":"critical","title":"Unauthorized publish / command injection",
         "frames":[52],
         "risk":"With no write authorization, any connected client can publish to a command topic (frame 52). If an actuator or controller trusts that topic, an attacker can drive physical equipment through the broker.",
         "realworld":"Exposure research has shown open brokers permitting publishes to control/command topics, turning data leaks into potential physical impact.",
         "attack":"Command injection via topic write",
         "control":"Broker ACLs granting write only to authorized publishers per topic; validate and authenticate commands at the subscribing device (don't trust topic membership alone); separate telemetry and command paths (distinct brokers/credentials/segments)."}
    ],

    "extras": [
        {"title":"Frame-52 triage — impact is currently notional",
         "body":"As shipped, nothing in the base capture subscribes to `plant/tank1/command` (the HMI takes `plant/+/telemetry`; the sensor's Will is on `.../status`), so the injected command is delivered to no actuator — it proves the broker **accepts** an unauthorized write, not that equipment moved. The Docker lab closes this: a `pump-controller.py` subscriber now acts on `plant/tank1/command`, so you can watch the injected command actually toggle a simulated pump. Absent that subscriber, treat the impact as **demonstrative**."},
        {"title":"What would make this real offense (out of scope in this kit)",
         "body":"A fuller offensive track — deliberately **out of scope** here — would add:\n\n- **Asset/topic enumeration** — reconstruct the topic tree, client-ids, and credentials from a capture or broker probing, instead of being handed the topics.\n- **L2 positioning** — ARP-spoof the client↔broker path; this kit assumes that adjacency already exists.\n- **TCP-session hijack** — take over a legitimate client's established broker session instead of opening a new anonymous one.\n- **Retained-message & $SYS harvest** — pull retained messages and $SYS/# broker metrics for zero-touch recon (exactly the technique in the unseen assessment capture).\n- **Sparkplug B command injection** — forge NCMD/DCMD payloads against a Sparkplug edge node — the real IIoT command path, not a bare topic string.\n- **Client-id takeover** — reconnect with a live client's id to evict it and assume its session/ACL identity."}
    ],

    "lab": {
        "intro":
            "The Docker lab runs a real Mosquitto broker plus paho-mqtt Python publisher/subscriber scripts, so you can "
            "reproduce this whole capture live and then harden it. You will start with the insecure default (anonymous, "
            "1883), watch it in Wireshark, then add authentication, ACLs, and TLS and watch the capture change.\n\n"
            "**How to run these exercises.** Each one is written as **Read** (why), **Do · Type** or **Do · Click** "
            "(exactly one action), and **Check** (what you should see). Terminal commands sit in a code block — copy "
            "them with the **Copy** button or **Ctrl/Cmd+Shift+V** (the paste-backup), never by re-typing. Where a "
            "command already has a lab-runner token you can `lab <token>` instead of copying. The analysis desktop "
            "opens on port **:6080** straight to the desktop with **no password**, and Wireshark is already capturing "
            "on `lo` (if a VNC prompt ever appears, it's `vscode`).",
        "exercises": [
            {"title":"Read a password off the wire",
             "steps":[
                 "**Read.** MQTT carries its username and password inside the CONNECT packet with no protection of "
                 "their own. On plaintext port 1883 that means the credentials sit in the payload in plain ASCII — no "
                 "cracking, no decryption, just reading. This is the most visceral demonstration of why 1883 belongs "
                 "only inside a trusted segment.",
                 "**Do · Click** — In Wireshark, type `mqtt.msgtype==1` in the display-filter bar and press Enter, "
                 "click frame 4, then expand the **MQ Telemetry Transport Protocol** tree in the detail pane down to "
                 "the Username and Password fields.",
                 "**Check —** the Username reads `hmi_operator` and the Password reads `Plant!ntel2024`, both in "
                 "cleartext; if the tree is collapsed, click the ▸ triangle beside 'MQ Telemetry Transport' to expand it.",
                 "**Do · Type** — Read the same credentials straight off the wire:\n\n"
                 "```\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.clientid "
                 "-e mqtt.username -e mqtt.passwd\n```\n\n"
                 "— or just type `l3`.",
                 "**Check —** one row per CONNECT, including `hmi-scada-01  hmi_operator  Plant!ntel2024`; if the "
                 "passwd column is blank, confirm you are reading `mqtt_iot_telemetry.pcap` and not a hardened capture.",
             ],
             "question":"What are the HMI's username and password, and which single control would have prevented you from reading them?",
             "answer":"hmi_operator / Plant!ntel2024, readable in cleartext. Running MQTT over TLS on port 8883 would have encrypted the entire CONNECT, including the credentials."},
            {"title":"Trace one message to two subscribers",
             "steps":[
                 "**Read.** In pub/sub the publisher never addresses a subscriber — it publishes to a topic, and the "
                 "broker fans the message out to everyone whose subscription matches. That is the elegance and the "
                 "risk: once the rogue host holds a `#` subscription, the broker delivers the plant's telemetry to it "
                 "exactly as it delivers to the legitimate HMI, with no extra step from the attacker.",
                 "**Do · Click** — In Wireshark, apply the filter `mqtt.msgtype==3` to show only PUBLISH frames, then "
                 "click the sensor's third reading at frame 46.",
                 "**Check —** frame 46 is a PUBLISH from 10.10.20.7 to the broker on topic `plant/tank1/telemetry`; "
                 "if the frame numbers differ, confirm the filter is `mqtt.msgtype==3` and not `==8`.",
                 "**Do · Click** — Read the two PUBLISH frames the broker sends immediately after — frame 48 and "
                 "frame 50 — and note the destination IP on each.",
                 "**Check —** frame 48 goes to the HMI (10.10.20.30) and frame 50 goes to the rogue host "
                 "(10.10.20.66) — one publish, two deliveries, the second unauthorized; if you see only one delivery, "
                 "clear any leftover `ip.dst` filter.",
             ],
             "question":"Starting at the sensor's publish (frame 46), which frames deliver that same reading, and to whom?",
             "answer":"Frame 46 (sensor→broker) is fanned out to the legitimate HMI in frame 48 and to the rogue eavesdropper in frame 50. One publish, two deliveries — the second is an unauthorized leak."},
            {"title":"Catch the anonymous intruder",
             "steps":[
                 "**Read.** An anonymous CONNECT is one whose connect-flags carry no username or password bit. Whether "
                 "it is a problem depends entirely on the broker: a hardened broker refuses it, an open one hands back "
                 "a return-code-0 CONNACK and a full session. The tell is in the CONNECT itself, before the attacker "
                 "does anything else.",
                 "**Do · Click** — In Wireshark, filter `mqtt.msgtype==1` and compare the connect-flags of frames 4, "
                 "15, and 38 in the detail pane.",
                 "**Check —** frames 4 and 15 have the Username/Password flags set, while frame 38 (`mqtt-explorer-x`) "
                 "has neither — it is the anonymous one; if all three look identical, expand the 'Connect Flags' "
                 "sub-tree to see the individual bits.",
                 "**Do · Type** — Detect the credential-less CONNECT from the terminal:\n\n"
                 "```\ntshark -r pcaps/mqtt_iot_telemetry.pcap -Y \"mqtt.msgtype==1 && !mqtt.username\" -T fields "
                 "-e frame.number -e mqtt.clientid\n```\n\n"
                 "— or just type `l4`.",
                 "**Check —** exactly one row, `38  mqtt-explorer-x`; if you get more rows, confirm you loaded "
                 "`mqtt_iot_telemetry.pcap` (a legitimate client should never be missing its username here).",
             ],
             "question":"Which CONNECT is anonymous, and what does mqtt_connect.log show for it?",
             "answer":"Frame 38 (client mqtt-explorer-x) has no username/password — visible in the CONNECT connect-flags. But do NOT try to catch it by 'empty will fields' in mqtt_connect.log: that log has no username/password column at all, and the legitimate authenticated HMI (hmi-scada-01) also logs empty will fields — so that discriminator both misses and false-positives. Detect anonymous access from the broker's own auth telemetry (Mosquitto's '… as anonymous' / repeated CONNACK rc=5), not Zeek's connect log, which sees only client_id and connect_status, never credentials."},
            {"title":"Harden the broker",
             "steps":[
                 "**Read.** The whole intrusion — anonymous connect, `#` harvest, command injection — collapses if the "
                 "broker stops trusting strangers. Three settings do it: `allow_anonymous false` forces credentials, a "
                 "`password_file` defines who those credentials belong to, and an `acl_file` scopes each identity to "
                 "only the topics it needs. Authentication decides *who*; the ACL decides *what*.",
                 "**Do · Click** — In VS Code, open `lab/mosquitto/mosquitto.conf`, set `allow_anonymous false`, add a "
                 "`password_file` line, and add an `acl_file` scoping the HMI to read `plant/+/telemetry` only.",
                 "**Check —** the three directives are present and the file is saved (VS Code's unsaved-dot on the tab "
                 "clears on save); if the file is read-only, open the folder from the lab workspace root.",
                 "**Do · Type** — Restart the broker so it reloads the new config:\n\n```\nlab reset\n```",
                 "**Check —** the broker comes back up listening on 1883 (the command prints the restart lines with no "
                 "error); if it fails to start, re-open `mosquitto.conf` and check for a typo in the directives.",
                 "**Do · Type** — Replay the intrusion against the hardened broker:\n\n```\n./lab/intrude.sh\n```\n\n"
                 "— or just type `l0b`.",
                 "**Check —** the anonymous CONNECT is now refused with CONNACK return code 5 (Not Authorized), so the "
                 "rogue never subscribes and the leaked-telemetry PUBLISH frames do not appear; if it still connects, "
                 "confirm `allow_anonymous false` was saved and the broker actually restarted (`lab reset` again).",
             ],
             "question":"After hardening, what happens to the anonymous connect, and how does the capture differ?",
             "answer":"The anonymous CONNECT is refused with CONNACK return code 5 (Not Authorized) — verified in the lab — so the rogue host never connects or subscribes, and the leaked-telemetry frames disappear. The ACL is defense-in-depth: Mosquitto enforces it per message topic (a client only receives topics its rule grants) rather than by failing the '#' SUBACK, so scope credentials tightly instead of relying on rejecting the wildcard itself. Adding TLS on 8883 further hides credentials and payloads entirely."}
        ]
    },

    "personas": [
        {"code":"15-1212.00","title":"Information Security Analysts","tag":"SME voice (Bright Outlook)",
         "voice":"I pull the pcap, read the cleartext creds in frame 4, and write the alert for anonymous CONNECTs.",
         "relevance":"O*NET tasks: 'Encrypt data transmissions … to keep out tainted digital transfers' and 'Monitor use of data files and regulate access.' Tool list names Wireshark and IDS/IPS — the analyst who triages this broker."},
        {"code":"15-1299.05","title":"Information Security Engineers","tag":"Builds the defenses (Bright Outlook)",
         "voice":"I stand up the hardened broker: TLS on 8883, password_file, and per-topic ACLs.",
         "relevance":"O*NET tasks: 'Develop or install software, such as firewalls and data encryption programs' and 'Identify security system weaknesses, using penetration tests.' The engineer who implements M1–M5's controls."},
        {"code":"15-1241.00","title":"Computer Network Architects","tag":"Segmentation & packet analysis (Bright Outlook)",
         "voice":"I decide where the broker lives and who can reach 1883/8883 — and I read the packets to prove it.",
         "relevance":"The only occupation of this set whose O*NET tool list names 'Packet analysis software' as a discrete entry; owns the segmentation that keeps a broker off the open internet."},
        {"code":"17-2071.00","title":"Electrical Engineers","tag":"IIoT system design (Bright Outlook)",
         "voice":"As I add sensors to the plant, I choose whether telemetry and commands share a broker — a security decision.",
         "relevance":"O*NET tools include SCADA/PLC/HMI software; the persona integrating MQTT sensors alongside legacy control and deciding the topic/command architecture."},
        {"code":"15-1299.04","title":"Penetration Testers","tag":"Adversary emulation (Bright Outlook)",
         "voice":"I demonstrate the frame 38→52 intrusion in a lab so the org funds ACLs and TLS.",
         "relevance":"O*NET tasks: 'Develop security penetration testing processes (wireless, data networks, telecommunications).'"},
        {"code":"25-9031.00","title":"Instructional Coordinators","tag":"Curriculum author",
         "voice":"I built this module from a verified capture, mapping each objective to a real occupation.",
         "relevance":"O*NET tasks: 'Interview subject-matter experts … to develop instructional content' and keep training 'technologically current.'"}
    ],

    "onet_alignment": {
        "practice": [
            ["Identify MQTT control packets, extract CONNECT details (including reading cleartext credentials), and trace pub/sub fan-out — distinguishing a live PUBLISH from a delivered retained message by the RETAIN flag","15-1212.00","Information Security Analysts — monitor use of data files, regulate access, and analyze traffic to detect intrusions"],
            ["Decide where the broker lives and who may reach 1883/8883, and read the packets to prove the segmentation holds","15-1241.00","Computer Network Architects — design data-communication networks ('packet analysis software' is a named O*NET tool)"],
            ["Stand up the hardened broker: allow_anonymous false, password_file, per-topic read/write ACLs, TLS on 8883, and retained-message/command-topic controls","15-1299.05","Information Security Engineers — develop or install firewalls and data-encryption software; identify weaknesses using penetration tests"],
            ["Safely emulate the anonymous harvest-and-inject intrusion (including the unseen retained-message abuse) to justify the controls","15-1299.04","Penetration Testers — develop security penetration-testing processes across data networks"]
        ],
        "context": [
            ["Electrical Engineers","17-2071.00","Decide whether telemetry and commands share a broker — a design/procurement security decision — and must require the controls the analyst specifies."],
            ["Instructional Coordinators","25-9031.00","Authored this module from the verified capture — the author's own occupation, not a learner skill."],
            ["Plant-floor operators / HMI users","(no single O*NET code)","The people whose process view and equipment the analysis protects; the retained command injection targets their actuators."]
        ]
    },

    "references": [
        ["OASIS — MQTT Version 3.1.1 Standard","http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html"],
        ["Eclipse Mosquitto — broker & mosquitto.conf (allow_anonymous, acl_file, TLS)","https://mosquitto.org/man/mosquitto-conf-5.html"],
        ["Zeek — built-in MQTT analyzer & logs","https://docs.zeek.org/en/lts/scripts/base/protocols/mqtt/index.html"],
        ["Lucas Lundgren & Neal Hindocha — DEF CON 24: 'Light-Weight Protocol! Serious Equipment! Critical Implications!'","https://www.youtube.com/watch?v=o7qDVZr0t2c"],
        ["Avast (M. Hron, 2018) — exposed MQTT in smart homes","https://www.gendigital.com/blog/insights/leadership-perspectives/are-smart-homes-vulnerable-to-hacking"],
        ["Trend Micro (2018) — 'The Fragility of Industrial IoT's Data Backbone'","https://documents.trendmicro.com/assets/white_papers/wp-the-fragility-of-industrial-IoTs-data-backbone.pdf"],
        ["NIST SP 800-82 Rev. 3 — Guide to Operational Technology (OT) Security","https://csrc.nist.gov/pubs/sp/800/82/r3/final"],
        ["OWASP Internet of Things Project","https://owasp.org/www-project-internet-of-things/"],
        ["O*NET — Information Security Analysts 15-1212.00","https://www.onetonline.org/link/summary/15-1212.00"],
        ["O*NET — Information Security Engineers 15-1299.05","https://www.onetonline.org/link/summary/15-1299.05"]
    ]
}
