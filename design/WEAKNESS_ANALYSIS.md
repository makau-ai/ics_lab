# Weakness Analysis — ICS Digital Twin mapped to MITRE CWE View 1358

**Analysts:** Penetration Tester (15-1299.04) with Information Security Engineer (15-1299.05).
**Date:** 2026-08-14 · **Target:** Wastewater lift-station digital twin (DNP3/20000 + MQTT/1883, segmented Purdue/IEC-62443).
**Scope:** the weaknesses that exist *by construction* in the twin and its buildable substrate
(`lab/dnp3/`, `lab/mqtt/`, `lab/mosquitto/`, `lab/docker-compose*.yml`, `lab/zeek/`), mapped to
**CWE View 1358 — Weaknesses in SEI ETF Categories of Security Vulnerabilities in ICS**.

> **Framing.** These are not accidental bugs; they are the *teaching surface*. The base DNP3 and MQTT
> protocols ship with no authentication and no encryption, and this twin faithfully reproduces that so
> students can watch the attack and then watch the engineered controls (segmentation, DNP3 SAv5,
> MQTT mTLS/ACL, and the **hardwired high-high float**) close each gap. Every weakness below is
> intentional, wire-observable, and paired with the control that neutralizes it.

---

## 0. Method and citation discipline (read before the table)

View 1358 is a **graph/teaching view** that aligns CWE entries to the SEI ETF report using MITRE's
**"Nearest IT Neighbor"** recommendations; MITRE warns *"Relationships are likely to change,"* and
several member categories carry a *"cannot be used for mapping"* note. Two consequences for this doc,
carried directly from `research_cwe1358.md §4`:

- **Direct members** of View 1358 that we cite as primary anchors: **CWE-306, CWE-319, CWE-311,
  CWE-290, CWE-349, CWE-284, CWE-807, CWE-693, CWE-1393, CWE-287, CWE-288, CWE-494, CWE-276.**
- **NOT enumerated in View 1358** (so we cite their *in-view analogs* instead, and say so):
  - **CWE-20 Improper Input Validation** → in-view analogs **CWE-349** (Acceptance of Extraneous
    Untrusted Data) and **CWE-807** (Reliance on Untrusted Inputs in a Security Decision); memory-safety
    leaves **CWE-121/125/787** for malformed-frame parsing.
  - **CWE-345 Insufficient Verification of Data Authenticity** → in-view analogs **CWE-290**
    (Authentication Bypass by Spoofing), **CWE-349**, **CWE-494** (Download of Code Without Integrity
    Check).
  - **CWE-654 Reliance on a Single Factor in a Security Decision** (the canonical "single interlock"
    parent) → in-view analogs **CWE-693** (Protection Mechanism Failure, via category **CWE-1370
    Common Mode Frailties**) and **CWE-807**.

Primary category buckets used below: **CWE-1366** Frail Security in Protocols · **CWE-1364** Zone
Boundary Failures · **CWE-1365** Unreliability · **CWE-1368** External Digital Systems · **CWE-1369**
IT/OT Convergence · **CWE-1370** Common Mode Frailties.

---

## 1. Key weakness categories — master mapping table

| # | CWE id + name | View-1358 category | Where it manifests in the twin (file · evidence) | Operational consequence | CyOTE observable (Zeek/ICSNPP field) | ATT&CK-ICS · phase |
|---|---|---|---|---|---|---|
| **1** | **CWE-306 Missing Authentication for Critical Function** | CWE-1366 (also 1364/1365/1368) | `lab/dnp3/outstation.py` L46–58 executes **SELECT/OPERATE/DIRECT_OPERATE (CROB)** and L60–64 **COLD_RESTART** with **no credential check** (L50 comment: *"no authentication — executed on request!"*). MQTT: `lab/mosquitto/mosquitto.insecure.conf` L6 `allow_anonymous true`; `lab/mqtt/pump-controller.py` L18–19 `USER/PW = None` and L35–46 acts on any `plant/tank1/command`. DNP3 base protocol has no SAv5. | Unauthenticated pump-stop / breaker trip / RTU cold-restart → **wet-well overflow (SSO)**; loss of availability. | `dnp3.log` `fc_request ∈ {SELECT, OPERATE, DIRECT_OPERATE, COLD_RESTART}`; `dnp3_control.log` `function_code=DIRECT_OPERATE`, `trip_control_code`; `mqtt_connect.log` `connect_status="Connection Accepted"` w/ empty user (client `mqtt-explorer-x`); `mqtt_publish.log` `topic=plant/tank1/command`. | T0855, T0831, T0816 · Late→Impact |
| **2** | **CWE-319 Cleartext Transmission of Sensitive Information** (+ **CWE-311 Missing Encryption**) | CWE-1366 | DNP3/20000 has no TLS (`lab/dnp3/dnp3lib.py` framing is plaintext + CRC only). MQTT/1883 plaintext; `mosquitto.secure.conf` L15–24 leaves the TLS/8883 listener **commented out**. `lab/mqtt/publisher.py` L14–15 & `subscriber.py` L14–15 send **hardcoded creds in the cleartext CONNECT** (`sensor_svc:s3ns0r-pw`, `hmi_operator:Plant!ntel2024`). | Credential capture, telemetry disclosure, replayable control frames — an eavesdropper reconstructs the whole process. | Existence of parsed `dnp3.log`/`mqtt_*.log` = plaintext on the wire; `conn.log` shows **no TLS** on `:20000`/`:1883`; MQTT CONNECT username/password readable in pcap; `mqtt_publish.log` `payload` shows full JSON. | T0842, T0830 · Early→Middle |
| **3** | **CWE-284 Improper Access Control / No Authorization** | CWE-1369 (IT/OT Convergence) | Insecure broker loads **no ACL** (`acl` file is only wired by `mosquitto.secure.conf`), so `lab/mqtt/attacker.py` L32 **SUBSCRIBE `#`** (all topics) and L56 **PUBLISH to command** both succeed. DNP3 `outstation.py` enforces **no per-source authorization / no link-address allow-list**. The C2 conduit is only **stateful egress filtering** (it permits cell/control→broker on 1883), NOT a data-diode — because the cell MQTT subscriber initiates the session up, the broker fans out downward PUBLISH deliveries back down that established socket, so `plant/tank1/command` down-delivery is **not** blocked (see §2.3). | Full telemetry harvest (loss of confidentiality) + unauthorized actuator command (loss of control). | `mqtt_subscribe.log` `topics` contains `#`; PUBLISH to `command`/`setpoint` from a non-authorized `client_id`; `dnp3.log` two distinct `id.orig_h` mastering one outstation. | T0802, T0831 · Middle |
| **4** | **CWE-290 Authentication Bypass by Spoofing** *(in-view analog for CWE-345 data-authenticity / spoofable link addresses)* | CWE-1366 | `lab/dnp3/dnp3lib.py` L27–34 puts **src/dest link addresses** in every frame but nothing signs them (CRC is integrity-only, **no SAv5/HMAC**). `outstation.py` reads `ctrl, dest, src, user` and **uses `src` only to address the reply — never to authorize**. `lab/dnp3/master.py` L72–76 exposes `--src-addr` to **forge the master's DNP3 link address (100)**; spoofed **UNSOLICITED_RESPONSE (0x82)** is accepted as truth. | Attacker impersonates the trusted master; injected OPERATE frames and forged telemetry are trusted → **loss of view** while the field diverges. | `dnp3.log` control/`UNSOLICITED_RESPONSE` from an **unexpected `id.orig_h`** while claiming the master's link src-addr; **commanded-state ≠ reported-state** mismatch vs. historian baseline. | T0848, T0856, T0829 · Middle→Late |
| **5** | **CWE-349 Acceptance of Extraneous Untrusted Data** + **CWE-807 Reliance on Untrusted Inputs in a Security Decision** *(in-view analogs for CWE-20 input validation)* | CWE-1366 / CWE-1365 | `master.py` L22–48 `decode_response()` is a **hand-rolled object walker with no range/bounds/schema validation** — it `struct.unpack`s attacker-controlled slices and trusts whatever objects arrive. `outstation.py` L48 indexes `objs[5]` off wire bytes. Injected `0x82` unsolicited data is **merged with legitimate poll data**; HMI/historian **trust the reported level PV** the attacker forges low. (Memory-safety leaves **CWE-121/125/787** live for a fuzzed frame.) | Operator makes the *do-nothing* safety decision on spoofed values → SSO goes unperceived; crafted objects can desync/crash the parser. | `dnp3_objects.log` `object_type`/`object_count`/`range_low`–`range_high` inconsistent with the §5 point map; extraneous objects appended to a RESPONSE; reported `level_pct` ≠ physics. | T0856, T0832, T0829 · Middle→Late |
| **6** | **CWE-693 Protection Mechanism Failure** (via CWE-1370) + **CWE-807** *(in-view analogs for "reliance on a single software interlock," parent CWE-654)* | CWE-1370 (Common Mode Frailties) / CWE-1365 | The PLC's **HLA / dead-head / dry-run interlocks + deadband loop** (`DIGITAL_TWIN §1.2`) are **software reachable via DNP3 g41 setpoint WRITE and MQTT `setpoint`/`command`**. Pushing **LEAD_START > 100%** (Oldsmar "modify parameter") neutralizes the *single* software layer that starts pumps. If safety relied on that interlock alone, owning one register defeats it. | A single setpoint/register write disables automated protection; **without an independent layer the well overflows**. | `dnp3_objects.log` **g41 Analog Output** write / MQTT `setpoint` **outside the engineering band**; pumps commanded off while `level_pct` rising; commanded ≠ reported. | T0836, T0826 · Late→Impact |

---

## 2. Narrative — each weakness in detail

### 2.1 CWE-306 — Missing Authentication for a Critical Function *(the headline weakness)*
**Where.** The DNP3 outstation is an open command executor. In `lab/dnp3/outstation.py` the `handle()`
loop dispatches on the application function code and, for `0x03/0x04/0x05` (SELECT / OPERATE /
DIRECT_OPERATE of a Control Relay Output Block) and `0x0D` (COLD_RESTART), it mutates
`breaker_state` and replies success **without any authentication step** — the code even narrates the
gap (`"<<< NOTE: no authentication -- executed on request!"`, L50). There is no DNP3 Secure
Authentication (SAv5), no challenge/response, no allow-list. On the MQTT side the same category
appears twice: the broker runs `allow_anonymous true` (`mosquitto.insecure.conf` L6), and the
`pump-controller.py` actuator subscribes with `USER/PW = None` and executes any JSON on
`plant/tank1/command` (L35–46) — the design's own comment calls it *"exactly the trusting subscriber
that turns a broker authorization gap into equipment movement."*

**Consequence.** This is the direct route to the twin's consequence of concern: an unauthenticated
`OPERATE`/`DIRECT_OPERATE` that stops both pumps, or a `plant/tank1/command {"cmd":"STOP"}`, leaves
inflow arriving with no outflow → wet-well overflow → **Sanitary Sewer Overflow (SSO)**. `COLD_RESTART`
adds an availability attack on the RTU.

**CyOTE observable.** `dnp3.log` `fc_request` in the control/restart set from any source; the richer
`dnp3_control.log` gives `function_code=DIRECT_OPERATE`, `block_type="Control Relay Output Block"`,
`trip_control_code`, and `status_code=Success`. For MQTT, `mqtt_connect.log` shows a
`Connection Accepted` with an empty username (the `mqtt-explorer-x` client) and `mqtt_publish.log`
shows a PUBLISH to `plant/tank1/command`. **ATT&CK-ICS:** T0855 Unauthorized Command Message,
T0831 Manipulation of Control, T0816 Device Restart/Shutdown.

**Control that closes it.** DNP3 SAv5 (aggressive-mode HMAC on control), MQTT `allow_anonymous false`
+ per-client auth (`mosquitto.secure.conf`), and making `pump-controller` read-only per CIE intent.

---

### 2.2 CWE-319 — Cleartext Transmission (with CWE-311 Missing Encryption)
**Where.** Neither protocol carries transport security in the default build. `dnp3lib.py` frames DNP3
in the clear (link CRC is an *integrity* check, not confidentiality or authenticity), and the twin
deliberately keeps everything *"plaintext and Zeek/ICSNPP-parseable"* (`DIGITAL_TWIN §0`). MQTT runs on
`:1883` with the TLS/8883 listener commented out in `mosquitto.secure.conf` (L15–24). Worse, the clients
put **credentials on the wire**: `publisher.py`/`subscriber.py` call `username_pw_set()` with hardcoded
values (`sensor_svc:s3ns0r-pw`, `hmi_operator:Plant!ntel2024`) that ride the cleartext MQTT CONNECT —
the `passwd` file is hashed at rest but the CONNECT packet is not.

**Consequence.** An eavesdropper on the segment (or anyone the flat network exposes) recovers broker
credentials, reads all process telemetry, and captures well-formed control frames to **replay**. This
is the reconnaissance/collection that precedes every later stage.

**CyOTE observable.** The fact that ICSNPP emits `dnp3.log` and `mqtt_*.log` **at all** proves plaintext;
`conn.log` shows the absence of a TLS handshake on `:20000`/`:1883`; the MQTT CONNECT username/password
are literally visible in the pcap; `mqtt_publish.log` `payload` prints the JSON body. **ATT&CK-ICS:**
T0842 Network Sniffing, T0830 Adversary-in-the-Middle. **Control:** DNP3-over-TLS / SAv5, MQTT 8883 mTLS.

---

### 2.3 CWE-284 — Improper Access Control / No Authorization
**Where.** Authentication (who you are) and authorization (what you may do) are distinct; the twin
misses both, but this row is specifically the **missing authorization**. The insecure broker loads no
ACL — the `lab/mosquitto/acl` file is referenced *only* by `mosquitto.secure.conf` — so `attacker.py`
can SUBSCRIBE to the `#` wildcard (harvest every topic, L32) and PUBLISH into a command topic (L56). On
DNP3, the outstation applies no per-source authorization: any TCP peer that completes a frame is served,
and a second "master" from a new IP is accepted alongside the real one. The twin's C2 conduit was
originally described as a one-way "data-diode" (telemetry up, command/setpoint **down denied**); that
description is **incorrect** and is retained as an *assumption-audit* lesson. `zone-fw` performs only
**stateful egress filtering**: it permits the cell/control→broker session on 1883, and because the cell
MQTT **subscriber** (e.g. `pump-controller`) *initiates* that TCP session **up** to the broker, the
`ct state established,related` rule then accepts the broker's downward PUBLISH fan-out — including an
injected `plant/tank1/command` — back down the same established socket. A stateful L3/L4 firewall
cannot make a bidirectional publish/subscribe protocol one-way. **Residual risk:** broker-originated
downward delivery to a cell subscriber is unblocked; the honest control is application-layer (split
telemetry/command brokers, make the command broker unreachable from the cell, or a true unidirectional
gateway). Students should *empirically test* whether downward commands are truly blocked before
trusting the claim — misplaced trust in a control is itself the weakness.

**Consequence.** Loss of confidentiality (a `#` subscriber vacuums the plant) *and* loss of control
(an unauthorized publisher moves an actuator). **CyOTE observable.** `mqtt_subscribe.log` `topics`
containing `#` from a client that never publishes; PUBLISH to `command`/`setpoint` from an
unrecognized `client_id`; `dnp3.log` two distinct `id.orig_h` values mastering outstation 10.
**ATT&CK-ICS:** T0802 Automated Collection, T0831. **Control:** the `acl` file (per-topic least
privilege) + broker auth; DNP3 master-address allow-listing + SAv5.

---

### 2.4 CWE-290 — Authentication Bypass by Spoofing *(spoofable link addresses / data authenticity)*
**Where.** DNP3 identity is a **claim, not a proof**. `dnp3lib.py` writes 16-bit source/destination
*link addresses* into every frame (L27–34), but there is no cryptographic binding — the CRC only detects
bit-errors. `outstation.py` destructures `ctrl, dest, src, user` and then uses `src` purely to address
the reply; it never checks that `src` (or the source IP) is the legitimate master. `master.py` hands the
attacker the forgery primitive directly: `--src-addr` (L72–76) sets the DNP3 link source to **100**, the
master's own address, so the injected frame *is* the master as far as the outstation can tell. Spoofed
**UNSOLICITED_RESPONSE (0x82)** frames reporting a false level/alarm are likewise accepted as truth.
Because CWE-345 (Insufficient Verification of Data Authenticity) is **not** a View-1358 member, CWE-290
is the correct in-view anchor (with CWE-349 and CWE-494 for the related integrity-of-data angles).

**Consequence.** The classic Maroochy rogue-master pattern: the attacker impersonates the control
center to issue trusted commands, and spoofs reporting messages so the HMI shows normal while the field
diverges — **loss of view**. **CyOTE observable.** control or `UNSOLICITED_RESPONSE` in `dnp3.log` from
an **unexpected `id.orig_h`** that nonetheless claims the master's link address; and the tell-tale
**commanded-state ≠ reported-state** divergence measured against the historian baseline. **ATT&CK-ICS:**
T0848 Rogue Master, T0856 Spoof Reporting Message, T0829 Loss of View. **Control:** SAv5 (proves the
sender holds the key, defeating link-address spoofing) + master allow-listing at the conduit.

---

### 2.5 CWE-349 + CWE-807 — Untrusted / Unvalidated Data in a Decision *(input-validation analogs)*
**Where.** The parsers trust the wire. `master.py`'s `decode_response()` (L22–48) is a minimal,
hand-rolled object walker with **no range, bounds, or schema validation**: it advances an index through
attacker-controlled bytes and `struct.unpack`s slices directly (`objs[i+1:i+5]`). `outstation.py`
similarly reaches `objs[5]` off the wire. Nothing rejects **extraneous objects appended to a legitimate
RESPONSE** (CWE-349), and nothing distinguishes a real level reading from a spoofed one — the HMI,
historian, and any operator interlock **make a safety decision on data an attacker controls** (CWE-807).
CWE-20 (Improper Input Validation) is the canonical parent but is not enumerated in View 1358; CWE-349
and CWE-807 are its in-view stand-ins, with memory-safety leaves **CWE-121/125/787** live for a
deliberately malformed frame against the tiny parser.

**Consequence.** The operator's *do-nothing* decision is induced by forged telemetry (the SSO happens
unseen), and a crafted object stream can desync or crash the lightweight stack. **CyOTE observable.**
`dnp3_objects.log` rows whose `object_type`/`object_count`/`range_low`–`range_high` do **not** match the
published point map; unsolicited/extraneous objects; `mqtt_publish.log` `level_pct` that contradicts the
physical model. **ATT&CK-ICS:** T0856 Spoof Reporting, T0832 Manipulation of View, T0829 Loss of View.
**Control:** strict object/range allow-listing at the FEP, cross-checking reported vs. commanded state,
and rejecting extraneous objects.

---

### 2.6 CWE-693 + CWE-807 — Reliance on a Single Software Interlock
**Where.** This is the CIE / defense-in-depth weakness. The PLC's protective logic — high-level alarm,
**dead-head** (low-flow/high-pressure) trip, **dry-run** cutout, and the deadband start/stop loop
(`DIGITAL_TWIN §1.2`) — is **software**, and every input to it is reachable by an attacker who owns
DNP3 or MQTT: a **g41 Analog Output WRITE** (or MQTT `setpoint`) that pushes `LEAD_START` above 100%
means the software loop *never commands the pumps to start*, so the interlock that would have protected
the well is silently defeated by one register write (the Oldsmar "modify parameter" move). If the plant
relied on that single software interlock, one write = one catastrophe. CWE-654 (Reliance on a Single
Factor in a Security Decision) is the conceptual parent but is not in View 1358; the in-view anchors are
**CWE-693 Protection Mechanism Failure** (via **CWE-1370 Common Mode Frailties** — a protection layer
with no independent redundancy) and **CWE-807**.

**Consequence.** Automated protection is neutralized by a legitimate-looking parameter change; with no
independent layer, inflow > outflow drives the level past HLA and the weir → **SSO**. **CyOTE
observable.** `dnp3_objects.log` g41 write / MQTT `setpoint` **outside the engineering band**; pumps
commanded/ inferred off while `level_pct` climbs; commanded ≠ reported. **ATT&CK-ICS:** T0836 Modify
Parameter, T0826 Loss of Availability.

**Control (the twin's whole point).** The **hardwired high-high float LSHH-102** wired to the pump
starter (`DIGITAL_TWIN §1.3`, §7.3) starts the standby pump and raises the horn at 95% **regardless of
the `%QX` coils, DNP3, or MQTT** — an *independent, non-digital* protection layer that turns CWE-693
from catastrophic into bounded. The mechanical weir and motor-protection relay are the second and third
independent layers. This is exactly the CIE **"even-if" acceptance test** (§7.3): run the full attack
with total DNP3+MQTT write access and the well *still* pumps down at the float. The weakness is present
by construction; the analog backstop is why the consequence stays bounded.

---

## 3. Supporting / adjacent View-1358 members (present but secondary)

| CWE id + name | View-1358 category | Where in the twin | Note |
|---|---|---|---|
| **CWE-1364 Zone Boundary Failures** | CWE-1364 | `lab/docker-compose.yml` L122–128 puts attacker, RTU, and broker on **one flat `otlan` 172.28.0.0/24** — no zone boundary. Fixed in `docker-compose.segmented.yml` (2 zones) and fully in the twin (5 zones + `zone-fw` deny-by-default). | The segmentation lesson: the *same payload* succeeds on the flat net and dies at the conduit. |
| **CWE-1393 Use of Default Password** (canonical parent CWE-798 Hard-coded Credentials, not in view) | CWE-1366/1364/1368 | Hardcoded lab creds `s3ns0r-pw`, `Plant!ntel2024` in `publisher.py`/`subscriber.py` and `docker-compose.yml` env. | Well-known/shipped credentials function as defaults; rotate + secrets-manage. |
| **CWE-311 Missing Encryption of Sensitive Data** | CWE-1366 | Same root as CWE-319 — process telemetry and creds published without TLS. | Paired with CWE-319 above. |
| **CWE-276 Incorrect Default Permissions** | CWE-1366 | Default broker = anonymous + world-readable/writable topic tree (no ACL). | Closed by `acl` + `allow_anonymous false`. |
| **CWE-287 Improper Authentication / CWE-288 Auth Bypass via Alternate Path** | CWE-1364/1368 | Engineering path (`eng-ws → openplc` 8080/502) and the DNP3 control path both admit an actor who reaches the port. | Broaden auth beyond network reachability. |
| **CWE-494 Download of Code Without Integrity Check** | CWE-1364 | PLC logic / outstation config pushed over C3 with no signature check (in-view analog for CWE-345 code-authenticity). | Sign + verify logic downloads. |

---

## 4. Weakness → control crosswalk (how the twin closes each gap)

| Weakness (CWE) | Digital-twin control that closes it | Where |
|---|---|---|
| CWE-306 (no auth for control) | DNP3 **SAv5** aggressive-mode HMAC; MQTT `allow_anonymous false` + auth; read-only `pump-controller` | SAv5 lesson · `mosquitto.secure.conf` · CIE #2 |
| CWE-319 / CWE-311 (cleartext) | DNP3-over-TLS / SAv5; MQTT **8883 mTLS** | `mosquitto.secure.conf` L15–24 (uncomment) |
| CWE-284 (no authz) | MQTT **`acl`** least-privilege; DNP3 master allow-list | `lab/mosquitto/acl` · conduit C1 |
| CWE-290 (spoofable identity) | **SAv5** proves key-holding sender; conduit binds the master⇄gw pair only | `DIGITAL_TWIN §4.2` C1 |
| CWE-349 / CWE-807 (untrusted data) | Object/range allow-listing; **commanded-vs-reported** cross-check at the FEP/historian | `DIGITAL_TWIN §5`, §8 |
| CWE-693 / CWE-807 (single software interlock) | **Hardwired HH float LSHH-102** (PLC-independent) + weir + motor-protection relay | `DIGITAL_TWIN §1.3`, §7.3 |
| CWE-1364 (zone boundary) | **IEC 62443-3-2 zones + `zone-fw` deny-by-default** conduit firewall | `docker-compose.segmented.yml` / twin `zone-fw` |

---

## 5. Bottom line

The twin is, by construction, a compact catalog of **CWE-1366 Frail Security in Protocols** with
boundary and common-mode additions. The six key categories — **missing authentication for a critical
function (CWE-306)**, **cleartext transmission (CWE-319/311)**, **improper access control / no
authorization (CWE-284)**, **authentication bypass by spoofing / spoofable link addresses
(CWE-290)**, **acceptance of unvalidated/extraneous data used in a decision (CWE-349/807, the in-view
stand-ins for CWE-20/CWE-345)**, and **reliance on a single software interlock (CWE-693/807, the in-view
stand-ins for CWE-654)** — chain cleanly into the SSO consequence and are each detectable in the
Zeek/ICSNPP logs and closable by the twin's segmentation, SAv5, mTLS/ACL, and, above all, the
**independent hardwired float**. That last control is the thesis of the lab: every digital weakness here
can be *owned*, and the plant must still be safe because a non-digital layer holds.

---

## 6. Provenance / caveats
- CWE IDs, names, category memberships, and the CWE-20/CWE-345/CWE-654 "not-in-view → use analog" notes: `design/research_cwe1358.md` (verified against CWE 4.20, View 1358).
- Perception→detection→attribution model, ATT&CK-for-ICS technique IDs, Maroochy/Industroyer/Havex/Oldsmar case anchors: `design/research_cyote.md`. CyOTE mapped these techniques to IEC-101/104/61850 and OPC — the DNP3/MQTT translation is this kit's engineering layer, not a CyOTE claim.
- Twin topology, point maps, attack chain, CIE backstops: `design/DIGITAL_TWIN_ARCHITECTURE.md`.
- Code evidence and Zeek field names: `lab/dnp3/{outstation,master,dnp3lib}.py`, `lab/mqtt/{publisher,subscriber,pump-controller,attacker}.py`, `lab/mosquitto/{mosquitto.insecure.conf,mosquitto.secure.conf,acl,passwd}`, `lab/docker-compose*.yml`, `lab/zeek/local.zeek`, `lab/zeek_reference_output/`.
- View 1358 is a **teaching taxonomy** (Nearest-IT-Neighbor; "relationships likely to change"; some categories "cannot be used for mapping"). Memberships are cited as an organizing framework, not a conformance certification.
</content>
</invoke>
