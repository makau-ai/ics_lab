# Starter AI Prompts — Forward-Engineer It, Then Reverse-Engineer It

*A scaffolded ladder for building your own ICS/OT/IoT app and then taking it apart on the wire*

The rest of this kit hands you captures the instructors built and asks you to analyze them. This
ladder flips that: **you** prompt an AI assistant to build a small, deliberately-insecure ICS/OT/IoT
application, run it in the lab to emit real DNP3 / MQTT / Modbus traffic, capture it, and then
**reverse-engineer your own output** with the exact Level 1–5 method — endpoints → message types →
fields → the attack → the detection — before designing the control that bounds the consequence.

You learn the protocol twice: once as the person who wired the trust in, once as the analyst who
finds where it was misplaced. Building the target is what makes the weakness obvious; the reverse
task is where the learning is graded (against [`ARTIFACT_RUBRIC.md`](ARTIFACT_RUBRIC.md)).

The rungs mirror the kit's levels:

| Rung | Level band | Build target | Core lesson |
|---|---|---|---|
| 1 | L1–L2 | A leaky IoT/MQTT tank sensor | Map the conversation from statistics alone |
| 2 | L3–L4 | A spoofed-source DNP3 outstation | Catch the impostor by field evidence (ip.src vs dnp3.src) |
| 3 | L5 | An evadable detector, then a hardened one | Invariant beats signature; precision **and** recall |
| 4 | L6–L7 | The wet-well twin, extended | Full incident + Cyber-Informed-Engineering remediation |
| 5 | Bonus | A Modbus wet-well pump skid | Closed-loop physics + the engineered backstop |
| 6 | Bonus | An MQTT command-topic fleet | Separate observe from control; authZ is the gap |

---

> ## Ethics & scope — read this before you build anything
>
> This ladder is **defensive and analysis-first**, exactly like the rest of the kit. The whole point
> is to *recognize* misplaced trust on the wire, not to develop offensive tradecraft.
>
> - **Build and attack only systems you own in this kit's isolated lab** — the Codespace/devcontainer,
>   the Docker networks, `lab/twin/`, or a VM you control. Every forward prompt below produces a target
>   *you* stand up for *you* to analyze.
> - **Never touch real, production, or third-party OT.** DNP3/MQTT/Modbus move physical equipment;
>   a "harmless" probe against a live lift station, substation, or broker can spill sewage, trip a
>   feeder, or brief an operator with false status. The kit deliberately hands you the last ~5%
>   (the injection) in a sandbox and leaves the "hard 95%" — real access, positioning, enumeration —
>   out of scope.
> - **Keep it plaintext and in-band-observable *by design*.** These are teaching targets: no TLS, no
>   auth, correct standard ports, so Wireshark and Zeek/ICSNPP can parse every byte. That is a lab
>   choice, never a deployment pattern.
> - **The planted weakness is always a *legal message from the wrong party*, never a malformed or
>   memory-corrupting packet.** If a forward prompt tempts you toward a crash/fuzz payload, stop —
>   that is out of scope here (see the DNP3 module's "What would make this real offense").
> - **Label your work.** Ship a ground-truth file with every capture so a grader (and future-you)
>   can tell the planted frame from the noise. Sharing a graded capture is an integrity violation.

---

## How to run a rung

Every rung is the same four-move loop — **Forward** (build) → **Capture** → **Reverse** (analyze) →
**Assemble** (grade). Background is a **Read**; anything you actually run is a **Do · Type** followed
by a **Check** so you know it worked.

> Commands copy with the **Copy** button on each fenced block, or paste them with
> **Ctrl/Cmd+Shift+V** (the paste-backup) if a normal paste is swallowed by the terminal.

> **Read** — Move 1, *Forward.* Paste the rung's **FORWARD PROMPT** into an AI coding assistant. Read
> what it gives you for wire-validity and scope (correct port, plaintext, stdlib/`paho-mqtt`/Mosquitto,
> a one-command run that also captures), then run it in the lab.

> **Read** — Move 2, *Capture.* Sniff **out-of-band** to a `.pcap` (on the lab interface or the twin's
> capture plane) so the sniffer never perturbs the traffic it records.

**Do · Type** — capture your running target to a pcap (swap `<lab-if>` for your lab interface; stop
with Ctrl-C after ~60 s):

```
tcpdump -i <lab-if> -w cap.pcap 'tcp port 1883 or tcp port 20000 or tcp port 502'
```

**Check —** `tcpdump` reports a rising packet count while the target runs; if it stays at `0 packets
captured`, you are on the wrong interface — list them with `tcpdump -D` and retry.

**Do · Type** — confirm the capture parses as a protocol, not just bare TCP:

```
tshark -r cap.pcap -Y 'dnp3 || mqtt || mbtcp'
```

**Check —** you should see DNP3, MQTT, or Modbus/TCP rows; if the result is empty you caught only the
TCP handshake — re-capture while the app is mid-conversation.

> **Read** — Move 3, *Reverse.* Do the rung's **REVERSE TASK** *without reading your own source* —
> analyze the pcap as if it were an unseen incident, then diff your reconstruction against what you
> actually built.

> **Read** — Move 4, *Assemble.* Build the bundle in [§ Definition of done](#definition-of-done) and
> self-score against [`ARTIFACT_RUBRIC.md`](ARTIFACT_RUBRIC.md). The worked exemplar of a Mastery
> bundle is [`../verification/`](../verification/README.md).

Ports are fixed so the curriculum transfers: **MQTT 1883** (plaintext) / **8883** (mTLS) · **DNP3
20000** · **Modbus 502**. Protocol roles are named correctly throughout — DNP3 **master/outstation**,
MQTT **broker/publisher/subscriber**, Modbus **client/server** (the kit deliberately retired
Modbus master/slave for client/server).

Each rung ends with the **ARTIFACT_RUBRIC dimensions** it exercises hardest, so you know what a grader
will weight. The dimension IDs (R1–R8) are defined in [`ARTIFACT_RUBRIC.md`](ARTIFACT_RUBRIC.md).

---

## Rung 1 — L1–L2 · A leaky IoT/MQTT tank sensor

*Forward: stand up a cleartext sensor fleet. Reverse: map the whole conversation without opening a
single payload.*

**FORWARD PROMPT**

> Act as an IoT firmware developer building a **deliberately insecure teaching target for my own
> isolated lab**. Using `paho-mqtt` (or the Python standard library if you prefer no dependency) and a
> local **Mosquitto broker on 1883 in cleartext**, write three small programs:
> 1. a "tank-level" **publisher** that connects with a **hardcoded username/password** and publishes
>    JSON `{"level_pct":…, "temp_c":…, "flow_lpm":…}` to `plant/myrig/telemetry` once per second;
> 2. an **HMI subscriber** on `plant/+/telemetry`;
> 3. a second **subscriber that uses the `#` multi-level wildcard** (a lazy "see everything" client).
>
> Provide a `mosquitto.conf` with `allow_anonymous true` and no ACL, and a **single command** that
> launches the broker + all three clients and runs `tcpdump -i <lab-if> -w sensor.pcap 'tcp port
> 1883'` for ~60 seconds. **Do not add TLS** — this is an intentionally observable target so I can read
> it in Wireshark. Keep everything on 1883 and make the traffic parse cleanly under Zeek's MQTT
> analyzer. It must only touch localhost/the lab bridge.

**REVERSE TASK.** Close your source. From `sensor.pcap` alone, reproduce the Level 1–2 method.

**Do · Type** — rank the endpoints and list the TCP conversations to find the hub:

```
tshark -r sensor.pcap -q -z endpoints,ip
tshark -r sensor.pcap -q -z conv,tcp
```

**Check —** the **broker** is the busiest endpoint and the common endpoint of every conversation (the
star hub), and the **rogue `#` subscriber** stands out — all from statistics, before you read any
payload; if only one endpoint appears, your capture missed the clients — re-run the launch-and-capture
command.

**Do · Type** — enumerate the MQTT control-packet vocabulary:

```
tshark -r sensor.pcap -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c
```

**Check —** you should see the CONNECT / CONNACK / SUBSCRIBE / SUBACK / PUBLISH counts; if the result
is empty the capture didn't parse as MQTT — confirm the broker really is on 1883 in cleartext.

**Do · Type** — read the **cleartext credentials** straight off a CONNECT:

```
tshark -r sensor.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.username -e mqtt.passwd
```

**Check —** the hardcoded username and password print in the clear; name the one control (TLS on 8883)
that would have hidden them — and, precisely, what it would *not* have hidden (an authorized rogue
reading through the broker).

> **Read** — Finally, reconstruct the topology (a star), the roles (**broker / publisher /
> subscriber**), and the topic tree; then **diff that reconstruction against what you actually coded.**
> Note anything you declared but never used.

**Concepts.** Endpoints/conversations, star topology, MQTT control-packet vocabulary, QoS/retain,
cleartext credentials, wildcard subscribe, reconstructing design from statistics.

**Rubric dimensions targeted.** R1 (forward fidelity), R2 (evidence-grounded analysis), R3
(authN-vs-authZ, first exposure), R7 (provenance), R8 (communication).

---

## Rung 2 — L3–L4 · A spoofed-source DNP3 outstation

*Forward: a wire-valid outstation and a rogue that forges the master's link address. Reverse: the
impostor tells on itself in one field.*

**FORWARD PROMPT**

> You are a red-team **tooling author for a defensive lab I own**. Using only the Python standard
> library, write a minimal **DNP3-over-TCP outstation on port 20000** (outstation link address **10**)
> that frames the data link correctly (`0x0564` sync, length, control octet, 16-bit little-endian
> dest/src link addresses, **valid CRC-16/DNP** on the header and each data block), a pseudo-transport
> octet, and an application layer that serves a small wet-well point map — g1 binary inputs, g30 analog
> inputs, a **g12v1 CROB** — and executes **READ, SELECT, OPERATE, DIRECT_OPERATE, and COLD_RESTART**
> with **no origin check**. Add a **master** (link address **100**) that runs an integrity poll and a
> supervised SELECT→OPERATE. Then add a **third host on a different IP** that **forges the master's
> link address (dnp3.src = 100) while keeping its own ip.src** and injects one `DIRECT_OPERATE` (CROB
> Trip). Self-test the CRC routine against the standard vector (`check("123456789") == 0xEA82`). Emit
> everything to `dnp3_lab.pcap`, plaintext and **Zeek/ICSNPP-parseable**. Isolated lab only.

**REVERSE TASK.** Analyze `dnp3_lab.pcap` as an unseen capture.

**Do · Type** — put `ip.src` and `dnp3.src` side by side on every control frame:

```
tshark -r dnp3_lab.pcap -Y "dnp3.al.func in {3,4,5}" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
```

**Check —** exactly one control frame shows `ip.src` and `dnp3.src` **disagreeing** (the injected
`DIRECT_OPERATE` carrying a forged link address) — that is your injection; if every row agrees, the
rogue kept a consistent identity — re-run the forward build with the spoofing host enabled.

> **Read** — State **which field the attacker forged** (the 16-bit DNP3 *link* address) and **why the
> outstation cannot tell**: base DNP3 authenticates neither the IP nor the link address. Classify it as
> an **authentication** failure (CWE-290 spoofed identity / CWE-306 missing auth on control), not an
> authorization one — contrast with Rung 6's MQTT case. Then **recompute the CRCs yourself** in Python
> to prove the frame is byte-valid, not malformed — the weakness is a legal message from the wrong
> party.

**Do · Type** — turn the packets into structured logs with Zeek + the CISA ICSNPP DNP3 parser:

```
zeek -C -r dnp3_lab.pcap icsnpp-dnp3
```

**Check —** a `dnp3_control.log` is written; find the single line that best evidences the unauthorized
control and name the field. If Zeek reports the parser is unknown, install it first with
`zkg install icsnpp-dnp3`.

> **Read** — Note the trap: the source-IP rule fires here **only because the attacker left its real
> IP.** Write the detector as an invariant over `{link address ↔ expected source ↔ known-master set ↔
> SELECT-before-OPERATE}` and show it still fires when you regenerate the capture with different
> IPs / frame order.

**Concepts.** DNP3 3+1 stack, data-link CRC framing, function codes (0x01/03/04/05/0D/81/82),
ip.src vs dnp3.src, source spoofing, authN vs authZ, CWE-290/306, T0855/T0856, ICSNPP logs.

**Rubric dimensions targeted.** R2 (evidence), R3 (authN-vs-authZ), R4 (invariant detection),
R5 (consequence/technique), R1 (forward fidelity).

---

## Rung 3 — L5 · An evadable detector, then a hardened one

*Forward: build a rule that is easy to slip past. Reverse: break it, then rewrite it to key on the
invariant — and measure precision and recall.*

**FORWARD PROMPT**

> Act as a detection engineer working in **my isolated lab**. First, write a naive MQTT detector
> (tshark or Python over a pcap) that alerts **only** when a client SUBSCRIBEs to `#`. Second, write an
> attacker script that **still** harvests data and plants a **persistent (RETAINED) command** to a
> topic containing `command`, but is designed to **slip past that naive rule** — e.g. it subscribes to
> specific topics like `plant/+/telemetry` and `plant/tank1/status` instead of `#`, and connects
> **anonymously** to a `allow_anonymous true` Mosquitto broker on 1883. Generate two captures:
> `benign.pcap` (normal telemetry only) and `evasion.pcap` (normal telemetry **plus** the stealthy
> harvest-and-inject). Keep everything cleartext on 1883 and Zeek-parseable. Lab only.

**REVERSE TASK.** Turn a leaky signature into a durable invariant.

> **Read** — First run *your own* naive "block `#`" rule (the one you built in the FORWARD PROMPT)
> against `evasion.pcap` and confirm it **misses** the injection: the stealthy attacker subscribed to
> specific topics, never to `#`, so the signature never fires.

**Do · Type** — show the durable **authorization invariant** on the wire — an anonymous CONNECT paired
with a RETAINED publish to a `command` topic, independent of the subscription shape:

```
tshark -r evasion.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid
tshark -r evasion.pcap -Y "mqtt.retain==1 && mqtt.topic contains \"command\"" -T fields -e frame.number -e mqtt.topic
```

**Check —** both the anonymous CONNECT and the retained command PUBLISH appear even though no client
ever subscribed to `#`; that pair is exactly what your naive rule missed and what `mp/detector.py`
keys on. Rebuild your detector to fire on this invariant and confirm it now flags `evasion.pcap`.

> **Read** — **Measure precision and recall** against your own labels: the hardened rule must fire on
> the injection **and stay silent on `benign.pcap`** (no false positives). A detector that sprays ALERT
> on every frame is the anti-pattern — perfect recall, useless precision. Then, in two sentences,
> explain why "block `#`" was **signature thinking** (it enumerates one shape of the attack) and yours
> is **invariant thinking** (it keys on the authorization property the attacker cannot avoid while
> still succeeding).

**Concepts.** Signature vs invariant detection, retained messages, evasion resistance, precision/recall
against labeled ground truth, false-positive scoping, Zeek/ICSNPP MQTT logs.

**Rubric dimensions targeted.** R4 (invariant detection — primary), R2 (evidence), R7
(reproducibility), R8 (documented detector).

---

## Rung 4 — L6–L7 · The wet-well twin, extended (full incident + CIE remediation)

*Forward: add a process variable and a new weakness to the living plant. Reverse: run the incident,
then prove an engineered backstop holds even with full write access.*

**FORWARD PROMPT**

> You are a control-systems engineer extending **this kit's wastewater digital twin** (`lab/twin/`),
> which I run in my own isolated Docker lab. Help me:
> 1. Add **one new process variable** to `plant-sim/plant_sim.py` (e.g. wet-well temperature, a second
>    force-main pressure, or a chlorine residual) and integrate it into the physics + the **spill
>    (SSO) scoreboard**;
> 2. Expose it in the **DNP3 point map** the `dnp3-gw` serves (an added g30 analog input, or a g41
>    analog-output setpoint), keeping the Modbus↔DNP3 image consistent;
> 3. Introduce **one new weakness** in `openplc/st/naive_wetwell.st` in the style of the existing
>    holes — an **unclamped writable setpoint** (CWE-693, the Oldsmar move) or an **unconditional
>    remote command** (CWE-306) — so a legal write drives the process unsafe;
> 4. Give me the **exact attack commands from the granted cell foothold only** (`adversary-foothold`
>    on `cell_net`) that exploit it and push the **spill counter above 0**, plus the out-of-band
>    capture command. Keep it plaintext, capture out-of-band, and **inside the isolated lab**.

**REVERSE TASK.** Treat the resulting capture as an unseen incident and close the loop:

- **Triage** with the Level 1–5 method: endpoints → message types → the fields that disagree.
  Name the malicious frame(s) by **frame number + named field + value** (which g41 WRITE exceeded the
  band; which OPERATE had no SELECT; which source was outside the known-master set).
- **Separate authentication from authorization** for each finding, and map the chain to
  **MITRE ATT&CK for ICS** (T0855/T0836/T0831/T0814) and **CWE-1358** members, tagging each claim as a
  *demonstrated protocol weakness* vs an *attributed incident* (analogy vs attribution).
- Write an **`mp/report.md`-style incident report**: BLUF, evidence, authN-vs-authZ, impact tied to
  the **physical consequence (the SSO)**, and the control.
> **Read** — **Design the CIE backstop** that bounds the consequence *even with full DNP3+MQTT write
> access*: clamp the setpoint in `hardened_wetwell.st`, arm the **hardwired high-high float**, and place
> each control on the hierarchy (**eliminate / engineer / administer / add-on**).

**Do · Type** — boot the hardened twin and replay the *same* attack from the granted cell foothold:

```
bash lab/twin/launch-twin.sh --hardened --attack
```

**Check —** the **spill counter stays 0** under identical full write access (`spill == 0` vs the
vulnerable run's `spill > 0`); if it climbs, a control did not arm — confirm `FLOAT_ENABLED=true` and
the clamp is in `hardened_wetwell.st`, then re-launch.

> **Read** — Now **attribute which layer held** (setpoint clamp vs stop-interlock vs the analog float),
> not the toggle bundle. State plainly what SAv5 / the arm-latch do **and do not** cover (e.g. the
> firewall "data-diode" does not stop broker-originated downward delivery; the teaching HMAC gives
> authenticity, not freshness; a raw Modbus/502 path from the cell bypasses the whole DNP3 story).
> Finally, research **TRITON/TRISIS** and argue why a discrete-I/O float no register can write defeats
> an attacker who owns the logic solver.

**Concepts.** PLC Structured Text, Modbus↔DNP3 mapping, physical consequence, ATT&CK-for-ICS, CWE-1358,
Cyber-Informed Engineering "even-if" test, hierarchy of controls, segmentation/data-diode myths,
SAv5 freshness limits, incident reporting, TRITON/TRISIS grounding.

**Rubric dimensions targeted.** All eight — this is the capstone. Weighted hardest on R1 (forward
fidelity of the twin extension), R4 (invariant detection), R5 (consequence/incident grounding),
R6 (honest CIE layering); with R2, R3, R7, R8 throughout.

---

## Rung 5 — Bonus · A Modbus wet-well pump skid (client/server)

*Forward: the twin's beating heart — closed-loop physics over Modbus/TCP. Reverse: reconstruct the
point map and prove the engineered backstop, not the register, is what bounds the spill.*

**FORWARD PROMPT**

> Act as a controls engineer building a Modbus/TCP wet-well skid for **my own lab**, standard library
> only (no `pymodbus`). Build two programs:
> 1. a **Modbus/TCP server** ("plant-sim") on **port 502** that integrates wet-well level from
>    `(inflow − pump_outflow) · dt` in **consistent gallons/tick**, clamps level 0–100%, and counts
>    **overflow gallons** in a spill counter; it exposes **input registers** for level, flow, and a
>    discharge **psi that follows a real downward head–flow pump curve**, **discrete inputs** for the
>    floats, and **coils** for two ~1500 gpm duty/standby pumps and an alarm;
> 2. a **Modbus/TCP client** ("controller") that runs a **deadband loop** (LEAD_START 60%, LAG_START
>    80%, STOP 20%, HLA 90%) with **duty/standby alternation** each pump-down and **dry-run + dead-head
>    interlocks that actually read** the flow/pressure input registers.
>
> Add **no authentication**. Log every Modbus transaction. Use the terms **client** and **server**
> (not master/slave). Provide one command that runs both and captures `skid.pcap` (`tcp port 502`),
> plaintext and parseable as `mbtcp` in Wireshark/Zeek.

**REVERSE TASK.** From `skid.pcap` alone.

**Do · Type** — enumerate the Modbus/TCP function codes the **client** issued against the **server**:

```
tshark -r skid.pcap -Y mbtcp -T fields -e mbtcp.func_code | sort | uniq -c
```

**Check —** you should see the read/write function codes (e.g. Read Coils 1, Read Input Registers 4,
Write Single Coil 5); if nothing prints, the capture didn't parse as `mbtcp` — confirm the server is
on port 502 in cleartext.

> **Read** — From that vocabulary, **reconstruct the full register/coil map** (which register is level
> vs flow vs psi; which coils are P-1 / P-2 / alarm). Infer the **deadband setpoints** from where coils
> toggle, and check whether **lead/lag alternation** is actually happening. Write a one-page "as-found"
> point list and flag any register you declared but the logic never reads.
- Identify the **missing-authentication** weakness (CWE-306); map it to **T0836 Modify Parameter**.
  **Write `LEAD_START > 100%`** over Modbus and prove the well overflows (spill climbs).
- Propose the **engineered control** — a **hardwired high-high float on discrete I/O** that
  force-starts a pump regardless of any coil or holding register — and demonstrate empirically that
  **the float, not the register write, is what bounds the spill** ("even-if"). Argue from the data why
  an add-on cyber control alone would not have satisfied that test.

**Concepts.** Mass-balance modeling, Modbus data model (4 address spaces, client/server), deadband /
duty-standby sequencing, dead-code/unused-I/O detection, CWE-306, T0836, CIE engineered backstop.

**Rubric dimensions targeted.** R1 (physical-model + protocol fidelity — primary), R5 (consequence
grounding), R6 (engineered backstop / honest layering), R2 (evidence), R3 (auth reasoning).

---

## Rung 6 — Bonus · An MQTT command-topic fleet

*Forward: a telemetry-and-command IIoT edge with a physically consequential command path. Reverse:
the broker authenticated the rogue — the gap is authorization.*

**FORWARD PROMPT**

> Build a small IIoT telemetry-and-command system for **my isolated lab** with `paho-mqtt` and a
> **Mosquitto broker on 1883**:
> 1. a **sensor publisher** emitting JSON tank readings to `plant/tank1/telemetry` with a **Last Will
>    & Testament** on `plant/tank1/status`;
> 2. an **HMI subscriber** on `plant/+/telemetry`;
> 3. an **actuator subscriber** ("pump-controller") that **acts on** `plant/tank1/command` (it prints
>    "pump START/STOP" so the command path is *physically consequential*).
>
> Ship **two broker configs**: an **insecure** one (`allow_anonymous true`, no ACL, creds in the
> CONNECT) and a **secure** one (`allow_anonymous false` + a **password_file** + a **per-topic ACL**
> that makes telemetry up-only and forbids `command`/setpoint writes from unauthorized clients, plus an
> optional **8883 mTLS** listener). Then write an attacker that connects **anonymously**, subscribes
> `#`, and publishes a **STOP** to the command topic. Capture `mqtt_fleet.pcap` on 1883, cleartext,
> Zeek-parseable. Lab only.

**REVERSE TASK.** Separate observe from control.

**Do · Type** — pull the rogue's **anonymous CONNECT** the broker accepted:

```
tshark -r mqtt_fleet.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid
```

**Check —** the rogue session's CONNECT appears with **no username**, and its CONNACK carries return
code 0 — proof the broker **authenticated** it anonymously; conclude the injection is an
**authorization** failure (the identity was accepted; the *permission* was never constrained). Avoid
the classic miss "MQTT has no authentication" — it authenticated the rogue anonymously.
- Distinguish a **read-ACL gap** (the `#` eavesdrop, `SUBSCRIBE`/delivery) from a **write-ACL gap**
  (the `command` PUBLISH), with field evidence for each.
- Swap in the **secure** config and **re-capture**: show the anonymous CONNECT now refused
  (**CONNACK rc=5, Not Authorized**) and the leaked-telemetry/command frames gone. Explain precisely
  why **TLS alone would not** have stopped an *authenticated* rogue reading through the broker — the
  fix is **ACLs bound to identity**. Note where your **Zeek sensor goes dark** on 8883 (only
  `ssl.log`/JA3 remain) and argue whether **MQTT 5.0's AUTH packet** closes finding M3 or just moves
  it.

**Concepts.** Pub/sub broker trust model, CONNECT/CONNACK flags, QoS/retain, wildcard subscribe,
broker ACLs vs TLS, authN vs authZ, encryption-blind-spot, M1–M5, T0842/T0855.

**Rubric dimensions targeted.** R2 (evidence), R3 (authN-vs-authZ — primary), R4 (detection/ACL
efficacy), R6 (control efficacy & honest layering), R8 (terminology discipline).

---

<a id="definition-of-done"></a>
## Definition of done — the artifact bundle you submit

One rung is complete when you can hand a grader a self-contained bundle that lets them **reproduce
every number you claim**. This mirrors the kit's own evidence exemplar in
[`../verification/`](../verification/README.md) — precision over adjectives; every claim backed by a
file they can open. Submit a folder containing:

- [ ] **`forward/`** — the app source the AI produced (after your review) **and `RUN.md`**: the exact
      one command that launches the target *and* captures it. It must run headless.
- [ ] **`capture.pcap`** — your primary capture, plus a **`benign.pcap`** control capture for any rung
      graded on precision (Rungs 3 and 6). Include the **`capinfos`** output (packet count, duration,
      encapsulation) and a **`SHA-256SUMS`** manifest of every pcap, so a regenerated or corrupted
      capture fails loudly.
- [ ] **`ground_truth.labels.json`** — the single source of truth: the **malicious frame(s)**, the
      **attacker IP**, the **forged link address** / **anonymous client-id** / **command topic**, the
      **ATT&CK-for-ICS technique**, and the **CWE-1358** member. Your report, your detector, and any
      grader all read from this — so the narrative and the answer key cannot silently disagree.
- [ ] **`report.md`** — **BLUF** first (what happened, per capture), then a predictable order:
      **evidence → authN-vs-authZ → impact → control**. Every claim anchored to a **frame + field +
      value** (e.g. `frame 27, dnp3.src=100 arriving from ip.src=10.20.0.66`), distinguishing
      claimed-vs-real and retained-vs-live. An operator should be able to act on the recommendation
      without a packet-analysis background.
- [ ] **`detector.py`** — a **header comment states the invariant** it keys on and why it generalizes
      beyond these frame numbers. It keys on that invariant, **not** a hard-coded `frame==` or `ip==`.
      It runs headless and prints `ALERT frame=<n> reason=<invariant>`. The report notes its known
      **false-positive / coverage limits**.
- [ ] **`REPRODUCE.md`** — one documented command (with **pinned tool versions** or a container
      digest) that re-runs the forward build, the capture, the detector, and the analysis, and
      reproduces every figure bit-for-bit.
- [ ] **(Rungs 4–5, the process tiers)** the **hardened re-run**: the same full-write-access attack
      with the CIE controls on, the **spill counter at 0**, and one sentence naming **which layer
      held** (clamp vs interlock vs float).

When the bundle is assembled, **self-score against [`ARTIFACT_RUBRIC.md`](ARTIFACT_RUBRIC.md)** and
meet its mastery gates before you submit.
