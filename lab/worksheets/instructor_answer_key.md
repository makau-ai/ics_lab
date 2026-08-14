# ICS/OT Protocol Analysis — Instructor Answer Key

Work these exercises with the two teaching captures open in Wireshark (`dnp3_substation.pcap`, `mqtt_iot_telemetry.pcap`) and the Docker lab running. Each exercise follows the same **Read → Do → Check** rhythm: a short **Read** sets up the *why*, each **Do · Type** / **Do · Click** is one action to perform, and the **Check** tells you what you should see.

> **Environment** — The lab desktop on port **6080** opens **straight to the desktop — no password** — with Wireshark already capturing on `lo`. (If a VNC prompt ever appears, it's `vscode`.) Terminal commands copy with the **Copy** button on each code block, or paste with **Ctrl/Cmd+Shift+V** (the paste-backup).

**Student name / date:** ______________________________


## DNP3 — DNP3

*Capture: `dnp3_substation.pcap`*

### Q1. Find the control lifecycle

> **Read** — DNP3 moves physical equipment with a tiny set of control function codes: a supervised **SELECT (3)** then **OPERATE (4)**, or a one-step **DIRECT OPERATE (5)**. A legitimate control shows the SELECT→OPERATE shape and comes from the master; a lone DIRECT OPERATE, or a control from any other host, is a red flag. Here you isolate every control frame and separate the real pair from the injected trip.

**Do · Click** — In Wireshark, choose **File ▸ Open** and load `dnp3_substation.pcap`.

**Check —** you should see the packet list fill with the 37-frame master↔outstation session; if it stays empty, run `lab reset` and reopen the file.

**Do · Click** — In Wireshark's green display-filter bar, type `dnp3.al.func in {3,4,5}` and press Enter.

**Check —** you should see only the control frames — one SELECT, one OPERATE, and one DIRECT OPERATE; if the list is empty, clear the bar and retype the filter, or run `lab reset`.

**Question.** How many control messages are there, and which one lacks a SELECT — and why does that matter?

**Answer.** Three controls: SELECT (frame 16) and OPERATE (frame 20) from the master, and a DIRECT OPERATE (frame 27) from 10.20.0.66. The DIRECT OPERATE has no SELECT interlock and comes from a non-master IP — it is the injected TRIP that opens the breaker.

### Q2. Spot the impostor by address

> **Read** — In DNP3 the **IP source** and the **DNP3 link source address** are two different identities in the same frame — and nothing forces them to agree. The master is IP 10.20.0.5 / link address 100; the outstation is link address 10. An attacker can forge the link address while its real IP shows through, so exposing both as columns lets you catch the frame where they disagree.

**Do · Click** — In the display-filter bar, type `dnp3` and press Enter.

**Check —** you should see every DNP3 frame in the capture; if not, run `lab reset`.

**Do · Click** — Click a control frame, expand the detail pane, right-click the **ip.src** field ▸ **Apply as Column**, then do the same for the DNP3 link source **dnp3.src**.

**Check —** you should see two new columns, `ip.src` and `dnp3.src`, in the packet list; if a column is missing, right-click its field and re-apply.

**Question.** What is inconsistent about frame 27, and which field did the attacker forge?

**Answer.** Frame 27's IP source is 10.20.0.66 but its DNP3 link source is 100 — the master's address. The attacker forged the link source to impersonate the master. Base DNP3 has no way to reject this.

### Q3. Turn packets into detections with ICSNPP

> **Read** — Reading frames by eye does not scale. Zeek with CISA's ICSNPP DNP3 parser turns the capture into structured, greppable logs — `dnp3_control.log` (every control with its operation and status) and `dnp3_objects.log`. The kit root is mounted at `/kit` inside the Zeek container, so the capture lives at `/kit/pcaps/...`.

**Do · Type** — From `lab/`, run Zeek + CISA ICSNPP over the capture:

```
docker compose --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap
```

**Check —** you should see Zeek write its logs with no error (look for `dnp3_control.log` and `dnp3_objects.log`); if it errors, run `lab reset` and retry.

**Do · Click** — Open `dnp3_control.log` and `dnp3_objects.log` in VS Code (Explorer ▸ the generated Zeek output folder).

**Check —** you should see one row per control, each with a source host and a status; if the files are empty, re-run the Zeek command above.

**Question.** Which single log line is your best alert for the attack, and what field makes it detectable?

**Answer.** The dnp3_control.log line 'DIRECT_OPERATE … Trip … Success' whose source_h is 10.20.0.66. But note that works here only because the attacker kept its real IP while forging the DNP3 link address; a smarter attacker who also spoofs the master's IP (or hijacks its TCP session) defeats a source-IP rule. The durable detection keys on an invariant — a control with no preceding SELECT, from an unexpected session, or off the master's baseline cadence (see 'Detection under adversarial and operational reality').

### Q4. Design the control

> **Read** — Not every fix is available today. DNP3 Secure Authentication (SAv5) is the durable answer, but it needs new outstation firmware. Before that lands, compensating controls — segmentation, an OT-firewall source allow-list on TCP/20000, and a Zeek+ICSNPP sensor — cut the frame-27 risk this week.

**Do · Click** — Open the DNP3 module page (`modules/dnp3_module.html`) ▸ **Security & Controls** and re-read findings **D1** and **D3**.

**Check —** you should see D1 (no authentication on control commands) and D3 (source spoofing / command injection); if the page won't open, use the curriculum hub's module link.

**Question.** Name three compensating controls that reduce the frame-27 risk without changing the outstation firmware.

**Answer.** (1) OT firewall rule allowing TCP/20000 to the outstation only from the master IP; (2) network segmentation / a data diode isolating the control LAN; (3) a Zeek+ICSNPP sensor alarming on controls from non-master sources. DNP3-SA is the durable fix once the device supports it.


## MQTT — MQTT

*Capture: `mqtt_iot_telemetry.pcap`*

### Q5. Read a password off the wire

> **Read** — MQTT authenticates inside the **CONNECT** packet — and on plain 1883 it travels in cleartext. If you can capture the CONNECT you can read the client's username and password with no cryptography at all. Here you pull the HMI's credentials straight off the wire.

**Do · Click** — In Wireshark, choose **File ▸ Open** and load `mqtt_iot_telemetry.pcap`.

**Check —** you should see the packet list fill with the MQTT session; if it stays empty, run `lab reset` and reopen.

**Do · Click** — In the display-filter bar, type `mqtt.msgtype==1` and press Enter to isolate the CONNECT packets.

**Check —** you should see only the CONNECT frames; if the list is empty, retype the filter or run `lab reset`.

**Do · Click** — Click **frame 4**, then in the detail pane expand **MQ Telemetry Transport ▸ Connect Command** and read the User Name and Password fields.

**Check —** you should see the HMI's username and password in cleartext; if the detail pane is blank, click the frame first.

**Question.** What are the HMI's username and password, and which single control would have prevented you from reading them?

**Answer.** hmi_operator / Plant!ntel2024, readable in cleartext. Running MQTT over TLS on port 8883 would have encrypted the entire CONNECT, including the credentials.

### Q6. Trace one message to two subscribers

> **Read** — The broker fans a single PUBLISH out to every subscriber of that topic. When an unauthorized subscriber is present, one sensor reading is delivered twice — once to the legitimate HMI and once to the eavesdropper. Following a single publish through the broker exposes the leak.

**Do · Click** — In the display-filter bar, type `mqtt.msgtype==3` and press Enter to show every PUBLISH.

**Check —** you should see only PUBLISH frames; if empty, retype the filter or run `lab reset`.

**Do · Click** — Select the sensor's publish at **frame 46**, read its topic, then scan the following frames for the same reading leaving the broker.

**Check —** you should see the broker re-deliver that reading to two different destinations; if frame 46 isn't a PUBLISH, re-check the filter.

**Question.** Starting at the sensor's publish (frame 46), which frames deliver that same reading, and to whom?

**Answer.** Frame 46 (sensor→broker) is fanned out to the legitimate HMI in frame 48 and to the rogue eavesdropper in frame 50. One publish, two deliveries — the second is an unauthorized leak.

### Q7. Catch the anonymous intruder

> **Read** — A broker that allows anonymous access will accept a CONNECT with no username or password. The tell is in the CONNECT **connect-flags** — and the broker's own logs, not Zeek's connect log, are where you confirm it, because Zeek never records credentials.

**Do · Click** — In the display-filter bar, type `mqtt.msgtype==1` and press Enter.

**Check —** you should see only the three CONNECT frames (4, 15, 38); if empty, retype the filter.

**Do · Click** — Click frames 4, 15, and 38 in turn and expand **Connect Command ▸ Connect Flags** to compare the Username/Password flags.

**Check —** you should be able to read each frame's Username Flag and Password Flag; if the detail pane is blank, click the frame first.

**Do · Type** — From `lab/`, run Zeek + CISA ICSNPP over the MQTT capture:

```
docker compose --profile tools run --rm zeek run-zeek /kit/pcaps/mqtt_iot_telemetry.pcap
```

**Check —** you should see Zeek write `mqtt_connect.log` (and the other `mqtt_*.log`) with no error; if it fails, run `lab reset` and retry.

**Do · Click** — Open `mqtt_connect.log` in VS Code and read the `client_id` and `connect_status` columns.

**Check —** you should see a row per CONNECT with a client_id but no credential column; if the file is empty, re-run the Zeek command.

**Question.** Which CONNECT is anonymous, and what does mqtt_connect.log show for it?

**Answer.** Frame 38 (client mqtt-explorer-x) has no username/password — visible in the CONNECT connect-flags. But do NOT try to catch it by 'empty will fields' in mqtt_connect.log: that log has no username/password column at all, and the legitimate authenticated HMI (hmi-scada-01) also logs empty will fields — so that discriminator both misses and false-positives. Detect anonymous access from the broker's own auth telemetry (Mosquitto's '… as anonymous' / repeated CONNACK rc=5), not Zeek's connect log, which sees only client_id and connect_status, never credentials.

### Q8. Harden the broker

> **Read** — The fix for anonymous access and topic over-sharing is broker configuration: turn off anonymous logins, require a password file, and scope each client with an ACL. After the broker reloads, the rogue's CONNECT is refused and the leaked-telemetry frames disappear.

**Do · Click** — In VS Code, open the lab's `mosquitto.conf` and set `allow_anonymous false`, add a `password_file`, and add an `acl_file` that scopes the HMI to `read plant/+/telemetry`.

**Check —** you should see the three directives saved in `mosquitto.conf`; if the file won't save, check you opened the copy under `lab/`.

**Do · Type** — Restart the loopback lab so the broker reloads `mosquitto.conf`:

```
lab reset
```

**Check —** you should see the broker (1883) and outstation (20000) come back up; if it hangs, run `lab reset` again.

> **Read** — Now re-run the publisher, the subscriber, and a `#` subscriber (the exact client commands are in `lab/README.md`): the anonymous CONNECT is now refused with CONNACK return code 5 (Not Authorized) and the leaked-telemetry frames are gone.

**Question.** After hardening, what happens to the anonymous connect, and how does the capture differ?

**Answer.** The anonymous CONNECT is refused with CONNACK return code 5 (Not Authorized) — verified in the lab — so the rogue host never connects or subscribes, and the leaked-telemetry frames disappear. The ACL is defense-in-depth: Mosquitto enforces it per message topic (a client only receives topics its rule grants) rather than by failing the '#' SUBACK, so scope credentials tightly instead of relying on rejecting the wildcard itself. Adding TLS on 8883 further hides credentials and payloads entirely.


## Synthesis

> **Read** — These pull the two captures together. There are no new commands to run — reason from the evidence you have already gathered.

### Q9.

**Question.** A classmate reduces both intrusions to one root cause — 'neither protocol authenticates, so the rogue host is trusted.' That is only half right. Using the captures, separate AUTHENTICATION (who are you?) from AUTHORIZATION (are you allowed to do this?). For DNP3 frame 27 and for the MQTT command injection, state (i) whether authentication happened at all, (ii) whether the failure is one of authentication or authorization, and (iii) the exact missing mechanism that would have stopped it. Cite the specific frame(s).

**Answer.** The classmate conflates two different failures. DNP3 (frame 27): there is NO authentication of any kind — the outstation never checks identity; the only 'identity' is a 16-bit link address (here forged to 100, the master's) that any host can write into a frame, so the rogue at 10.20.0.66 simply opens its own session and issues a DIRECT OPERATE (Trip). Authentication failure. Missing mechanism: DNP3 Secure Authentication (SAv5) — a challenge-response MAC on critical function codes — plus source allow-listing. MQTT (frame 52, the PUBLISH to plant/tank1/command — NOT frame 54, which is the rogue's DISCONNECT): authentication DID occur and SUCCEEDED — the rogue authenticated anonymously at CONNECT (frame 38) and the broker accepted it with CONNACK return code 0 (frame 40). The injection is therefore an AUTHORIZATION failure: with no per-topic write ACL, an accepted client may publish to a command topic it should never write. Missing mechanism: a broker write-ACL scoping publish rights per client/topic (and, upstream, allow_anonymous false so the anonymous identity is refused before any topic write). Bottom line: DNP3 fails because identity is never checked; MQTT fails because an accepted identity is never constrained — 'no authentication' describes DNP3, while MQTT's gap is 'no authorization,' and the fixes differ (DNP3-SA vs. broker ACLs).

### Q10.

**Question.** For each protocol, name the standard/control that adds authentication and say whether it also adds confidentiality.

**Answer.** DNP3: Secure Authentication (SAv5 / IEEE 1815-2012) adds authentication + integrity of critical functions but NOT confidentiality (use TLS/VPN for that). MQTT: TLS on 8883 adds confidentiality + protects credentials; authorization still depends on broker-side ACLs, and authentication on broker credentials/certs.

### Q11.

**Question.** You can monitor but not immediately re-engineer these systems. Give one Zeek/ICSNPP-based detection for each capture.

**Answer.** DNP3: alert on any dnp3_control.log control (SELECT/OPERATE/DIRECT_OPERATE) whose source host is not the sanctioned master. MQTT: alert on mqtt_connect.log connects with empty credentials/anonymous, or mqtt_subscribe.log subscriptions to '#'.
