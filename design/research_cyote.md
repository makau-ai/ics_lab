# Research: INL CyOTE — Consequence-driven OT Threat Detection

**Author:** Intelligence-analyst researcher (ICS digital-twin Scrum)
**Date:** 2026-08-14
**Purpose:** Ground the training digital twin in a real, government-published OT-detection
methodology. Summarize the CyOTE program, its perception → detection → attribution model, and
extract 3–5 *documented* attack use cases that the DNP3/MQTT twin can recreate as observable
network traffic.

> **Provenance / no-fabrication note.** Everything in the "What CyOTE documents" columns below is
> sourced to a named INL/DOE report with a URL (verified via web fetch during this pass, Aug 2026).
> The **"How to build it in the twin"** blocks are *our engineering translation* of CyOTE's
> documented MITRE ATT&CK for ICS techniques onto this kit's two protocols (DNP3/TCP-20000 and
> MQTT/1883). CyOTE's own case studies are mostly in IEC-101/104, IEC-61850/MMS, OPC-DA, radio
> SCADA, and TeamViewer — **CyOTE did not say "do this in DNP3."** The protocol mapping is the
> kit's design layer and is labelled as such so no reader mistakes it for a CyOTE claim.

---

## 1. What CyOTE is

**CyOTE™ = Cybersecurity for the Operational Technology Environment.** A research program
**sponsored by the U.S. Department of Energy, Office of Cybersecurity, Energy Security, and
Emergency Response (CESER)** and **led by Idaho National Laboratory (INL)**, run with the national
lab complex and energy-sector asset owners.

- **Problem it addresses:** "Energy companies currently have few tools to analyze OT systems for
  malicious activity," and OT networks are increasingly converging with IT. Public OT-attack data
  is scarce, so CyOTE pools intelligence from a documented corpus (27 publicly reported OT
  incidents; a growing ontology of 14,000+ indicators across 4,000+ pages) and shares adversary
  TTPs with operators. (DOE CESER program page; CyOTE Fact Sheet.)
- **Framing:** *consequence-driven* — start from the operational consequence (the "triggering
  event," e.g. a pump overflow or a breaker opening) and work backward through the observable
  precursors an operator could have perceived, so defenders can act **left of impact**.
- **Backbone framework:** everything is mapped to **MITRE ATT&CK for ICS** (technique IDs `T0###`).
  CyOTE's job is to link a perceived anomaly to the ATT&CK-for-ICS technique(s) that could produce
  it, and to a phase of an ongoing campaign.

Sources: [DOE CESER — CyOTE program](https://www.energy.gov/ceser/cybersecurity-operational-technology-environment-cyote) ·
[CyOTE Fact Sheet (PDF)](https://www.energy.gov/sites/default/files/2021-09/CyOTE_Fact_Sheet_508.pdf) ·
[cyote.inl.gov](https://cyote.inl.gov/) ·
[CyOTE Program Document, INL/MIS-24-79011 (OSTI)](https://www.osti.gov/biblio/2428893)

---

## 2. The perception → detection → attribution idea

CyOTE's own words: the methodology is "based on the fundamental concepts of **perception and
comprehension**, applied to a universe of knowns and unknowns that are increasingly disaggregated
into **observables, anomalies, and triggering events**," and it seeks "to **tie anomalies in
operations to a cyberattack**" rather than relying only on commercial IT security tooling
(CyOTE Fact Sheet). This is Endsley-style situational awareness (Level 1 perception → Level 2
comprehension → Level 3 projection) applied to OT. Mapping the task's three-word framing onto
CyOTE's actual vocabulary:

| Task framing | CyOTE concept | What it means operationally | Twin data that carries it |
|---|---|---|---|
| **Perception** | *Perception* of **Observables** | Sense raw signals: network packets, host/auth logs, physical-process sensor values, and human operator observations. An **Observable** is the atomic unit. | DNP3/MQTT packets on the wire; alarm logs; remote-login events; HMI/process point values. |
| **Detection** | *Comprehension* → **Anomaly** → **Triggering event** | Correlate observables into an anomaly (deviation from the OT baseline) and recognize the triggering event (the operational consequence). CyOTE's **OPTIC** tool (Operational Process for Trigger Identification and Comprehension) walks an analyst from a trigger through comprehension across ~65,000 decision paths. | Baseline vs. live diff: unexpected function codes, new talker pairs, command-rate spikes, commanded-vs-reported mismatch. |
| **Attribution** | *Tie the anomaly to a cyberattack* → **BAM** phase inference | Decide whether the anomaly is a **cyberattack vs. a benign fault**, map it to ATT&CK-for-ICS technique(s), and place it in an attack **phase** (Early / Middle / Late / Impact). CyOTE's **Bayesian Attack Model (BAM)** does this probabilistically: ingest STIX-2.1 observables → ACE classifier maps to candidate `T0###` techniques → compute phase probabilities → escalate. | Sequence of anomalies scored against a technique/phase model; JSON/STIX output. |

**Key CyOTE ideas the twin should teach:**
- **Perceivability.** A technique that leaves an observable side effect (a packet, a file write, an
  alarm) is *perceivable*; a stealthy one is not. CyOTE ranks observables by "increased likelihood
  of being perceived" in the window before the triggering event.
- **Precursors / left-of-impact.** In every case study most detectable observables occur *before*
  the consequence (e.g. Colonial: 24 of 45 observables were high-perceivability precursors;
  Industroyer: 348 of 548 precursor observables were assessed more likely to be perceived in the
  300 days before impact). The teaching goal is to catch the campaign in the Early/Middle phase.
- **Anomaly ≠ attack, yet.** Attribution is explicitly a *decision under uncertainty* — BAM exists
  because an operator anomaly (a pump acting up) is not self-evidently malicious.

**CyOTE tool suite** (the concrete artifacts, from the DOE "New CyOTE Tools" article and the
BAM tool page):
- **BAM — Bayesian Attack Model:** explainable-ML engine; observables → ATT&CK-for-ICS TTPs →
  Early/Middle/Late/Impact phase probabilities; STIX-2.1 in, JSON/STIX out. *This is the
  attribution engine.*
- **OPTIC — Operational Process for Trigger Identification and Comprehension:** guided decision
  workflow (~65,000 paths) from a trigger to a response. *This is the detection/comprehension step.*
- **CATCH — Collection and Analysis of Telemetry for CyOTE Heuristics:** structured collect/store/
  analyze/report of OT telemetry. *This is the perception/sensing plumbing.*
- **CyOTE Executive's Dashboard** and **CyOTE Ontology** (data-warehouse of 14,000+ indicators
  from 27 incidents) for reporting and knowledge organization.

Sources: [CyOTE Fact Sheet](https://www.energy.gov/sites/default/files/2021-09/CyOTE_Fact_Sheet_508.pdf) ·
[New CyOTE Tools (DOE CESER)](https://www.energy.gov/ceser/articles/new-cyote-tools-support-better-risk-informed-cybersecurity-decision-making) ·
[BAM tool page](https://cyote.inl.gov/tools/bayesian-attack-model-bam/)

---

## 3. Buildable use cases (documented by CyOTE → recreatable in the twin)

CyOTE publishes a library of **Precursor Analysis Reports / Case Studies** (each an `INL/RPT-##`)
that walk an incident's ATT&CK-for-ICS chain and rank its observables by perceivability. Below are
the five best fits for a **DNP3 + MQTT** teaching twin, ordered by how protocol-native they are.
Use cases #1–#4 are directly recreatable as OT protocol traffic; #5 is the flagship "precursor /
IT-OT boundary" narrative.

Full CyOTE case-study index (all verified live): Colonial Pipeline/DarkSide, EKANS/Honda,
Industroyer, Havex, WannaCry, Norsk Hydro/LockerGoga, Night Dragon, DoppelPaymer/PEMEX,
Maroochy, Oldsmar, Ukraine 2015, Thyssenkrupp, Mumbai 2020, Ryuk/UHS, Conti/HSE-Ireland,
Davis-Besse/SQL-Slammer — all under `https://cyote.inl.gov/content/uploads/24/2025/12/`.

---

### Use case #1 — Maroochy Shire rogue-master / spoofed-command attack (2000)  ★ best DNP3 fit
**CyOTE report:** *Precursor Analysis Report: Insider Attack on the Maroochy Shire* —
[CyOTE-Case-Study_Maroochy.pdf](https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Maroochy.pdf)

**What CyOTE documents.** A disgruntled ex-contractor used a stolen RTU + Motorola radio + config
laptop to join the SCADA radio network as a **rogue master**, impersonate legitimate pumping
stations (Station 14, then Station 1), issue **unauthorized commands**, **spoof reporting/alarm
messages**, and cause a **loss of view** — leading to ~800,000 L of sewage spilled over months.
ATT&CK-for-ICS: **T0848 Rogue Master**, **T0864 Transient Cyber Asset**, **T0860 Wireless
Compromise**, **T0855 Unauthorized Command Message**, **T0856 Spoof Reporting Message**,
**T0831 Manipulation of Control**, **T0815 Denial of View**, **T0829 Loss of View**.
Top perceivable observables: *anomalous radio traffic from an anomalous pumping-station address*
and *commanded-state ≠ reported-state* mismatch (both only became perceivable once logging existed).

**How to build it in the twin (DNP3).**
- Stand up a legitimate master (IP A) polling an outstation, plus a **second, unexpected DNP3
  source (IP B) that also speaks master** to the same outstation (`dnp3.src` / talker pair anomaly).
- IP B issues **Control Relay Output Block (Group 12 Var 1 / g12v1)** via `OPERATE` (app func
  `0x04`) or `DIRECT_OPERATE` (`0x05`) to trip/close a breaker or start/stop a pump it should not
  control → **T0855 / T0831**.
- Inject **spoofed unsolicited responses** (app func `0x82`, `UNSOLICITED_RESPONSE`) reporting a
  *false* binary/analog state so the HMI shows normal while the field is not → **T0856 / T0829**.
- **Detect:** two masters to one outstation; control (`0x03/04/05`) from an IP that never issued
  them before; unsolicited responses from an unexpected source; g12v1 command with no matching
  operator action. Teachable via `dnp3.al.func` and source/pair analysis (kit Levels 3–4).

---

### Use case #2 — Industroyer / CRASHOVERRIDE "brute-force I/O" grid attack (2016)  ★ best SCADA-sweep fit
**CyOTE report:** *Precursor Analysis Report: Industroyer Targeting Ukraine* —
[CyOTE-Case-Study_Industroyer.pdf](https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Industroyer.pdf)

**What CyOTE documents.** Modular malware with protocol payloads for **IEC-101, IEC-104,
IEC-61850/MMS, and OPC-DA** de-energized a Kyiv substation. Chain (300-day timeline): spearphish
→ valid accounts across 100+ hosts → **network enumeration** and **remote system discovery**
(IEC-61850 MMS reads of breaker status; queries for `ctlSelOn/ctlOperOn/Pos/stVal`) → **brute-force
I/O** (IEC-104 module toggling every discovered IOA in range/shift/sequence modes) → **unauthorized
command messages** opening breakers → **denial of control/view** and a **wiper**. ATT&CK-for-ICS:
**T0840 Network Connection Enumeration**, **T0846 Remote System Discovery**, **T0888 Remote System
Information Discovery**, **T0806 Brute Force I/O**, **T0855 Unauthorized Command Message**,
**T0831 Manipulation of Control**, **T0813 Denial of Control**, **T0829 Loss of View**.
Top perceivable observables: broadcast/enumeration sweeps and *IEC-104 range-mode sweeps across
the subnet* generating "significant amounts of network traffic."

**How to build it in the twin (DNP3 analog of the IEC-104 sweep).**
- **Enumeration:** an integrity poll — `READ` (app func `0x01`) of **Class 1/2/3/0** — to discover
  the full point map (→ T0840/T0846/T0888).
- **Brute-force I/O:** iterate `OPERATE` (`0x04`) of **g12v1 CROB** across *every* binary-output
  index in sequence, and/or `DIRECT_OPERATE` writes to **Analog Output Block (Group 41)** across all
  analog points — the DNP3 equivalent of Industroyer's range/sequence IOA toggling (→ T0806/T0855).
- **Detect:** command rate far above the polling baseline; a single source Operating across the
  *entire* index space in a tight time window; reads of all classes immediately preceding the sweep.
  Classic `dnp3.al.func in {3,4,5}` count anomaly (kit Level 4).

---

### Use case #3 — Havex ICS/OPC reconnaissance (2013–2014)  ★ best scan/enumeration fit
**CyOTE report:** *Precursor Analysis Report: Havex Malware in a U.S. [asset]* —
[CyOTE-Case-Study_Havex.pdf](https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Havex.pdf)

**What CyOTE documents.** Trojanized OEM software updates / watering holes delivered Havex, whose
OPC-scanner module enumerated ICS assets by probing **TCP 102 (Siemens/S7), 502 (Modbus),
44818 (Rockwell/EtherNet-IP)** plus 135/DCOM, then harvested OPC **points and tags**. ATT&CK-for-ICS:
**T0846 Remote System Discovery**, **T0888 Remote System Information Discovery**, **T0861 Point &
Tag Identification**, **T0842 Network Sniffing**, **T0802 Automated Collection**, C2 over HTTP.
Top perceivable observables: ARP sweeps and *scanning across ICS ports* from one host;
COM/DCOM/DCE-RPC spikes; transient OPC client/server malfunctions.

**How to build it in the twin (DNP3 + MQTT).**
- **Port sweep:** one scanner host opens TCP connections across the OT range including **20000
  (DNP3)**, 502, 102, 44818, and **1883 (MQTT)** → T0846. (Half-open/`SYN` fan-out from a single src.)
- **DNP3 point/tag ID:** a **Class-0 integrity `READ` (`0x01`)** to dump the full static database =
  the DNP3 form of "point & tag identification" → T0861/T0888.
- **MQTT harvest:** a rogue client sends **SUBSCRIBE to wildcard `#`** to vacuum every telemetry
  topic → T0802 automated collection. (`mqtt.msgtype == SUBSCRIBE`, topic `#`.)
- **Detect:** one source touching many ICS ports; a DNP3 read of *all* objects from a new master;
  an MQTT subscriber to `#` that never publishes. Kit Levels 1–2 (endpoints/ports) → 4 (odd one out).

---

### Use case #4 — Oldsmar water-treatment setpoint manipulation (2021)  ★ best "Modify Parameter" fit
**CyOTE report:** *Remote Access Attack on Oldsmar Water Treatment* —
[CyOTE-Case-Study_Oldsmar.pdf](https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Oldsmar.pdf)

**What CyOTE documents.** An attacker reached an internet-exposed HMI via **TeamViewer** and
changed the **sodium hydroxide setpoint from 100 ppm to 11,100 ppm**. ATT&CK-for-ICS:
**T0822 External Remote Services**, **T0859 Valid Accounts**, **T0883 Internet Accessible Device**,
**T0823 Graphical User Interface**, **T0836 Modify Parameter**, **T0831 Manipulation of Control**.
Top perceivable observables (20 of 21 high-perceivability): *anomalous remote-support software use
(RDP/TeamViewer TCP 5938) from external IP to an internal host*, Windows Event ID 4624 Type-10
logons at 08:00 and 13:30, *anomalous HMI mouse-cursor movement*, and the *out-of-band setpoint
change* itself.

**How to build it in the twin (DNP3 + MQTT).**
- **DNP3:** a **Select-before-Operate** (`SELECT 0x03` then `OPERATE 0x04`) or `DIRECT_OPERATE`
  (`0x05`) writing an **Analog Output Block (Group 41)** to push a process setpoint from a safe
  value to an unsafe one (the NaOH 100→11,100 analog) → T0836/T0831. Pair it with a *remote-login
  event just before* the write to reproduce the perception chain.
- **MQTT variant:** a `PUBLISH` to a command/setpoint topic (e.g. `plant/dosing/naoh/setpoint`)
  carrying an out-of-engineering-range value → T0836.
- **Detect:** analog-output write from an unexpected source/time; value outside the safe band;
  a remote-service session immediately preceding the change; setpoint write with no work-order.
  Excellent for teaching "anomaly → is-this-an-attack?" (BAM-style attribution).

---

### Use case #5 — Colonial Pipeline / DarkSide precursor & IT-OT boundary (2021)  ○ boundary/precursor narrative
**CyOTE report:** *Case Study: DarkSide Ransomware Attack on Colonial Pipeline* —
[CyOTE-Case-Study_Colonial-Pipeline.pdf](https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Colonial-Pipeline.pdf)

**What CyOTE documents.** IT-side ransomware; the pipeline was shut down proactively and **OT
segments were left intact** (segmentation contained it). CyOTE flags 24 of 45 observables as
high-perceivability precursors: **T0822 External Remote Services** (VPN, leaked creds),
**T0859 Valid Accounts** (dormant account from the dark web), **T0869 Standard Application Layer
Protocol** (HTTP POST C2), **T0884 Connection Proxy** (Tor), **T0811 Data from Information
Repositories**, **T0882 Theft of Operational Information** (~100 GB exfil), **T0809 Data
Destruction** (shadow-copy deletion), **T0826 Loss of Availability**.

**How to build it in the twin (IT-OT boundary, less protocol-native).**
- Model the **enterprise/DMZ egress**, not the fieldbus: a **dormant/valid-account login from an
  anomalous time+geo**, then **beaconing outbound HTTP POST to an external C2 IP** and a **large
  exfil surge**, followed by a **boundary shutdown** that severs the historian/MQTT-bridge egress.
- In an MQTT context you can represent the **broker bridge / historian egress** showing the
  anomalous outbound connection and the dormant-account publish, then the segmentation cut.
- **Teaching point (not a protocol exploit):** the *detectable* signal lived on the **IT side**
  as precursors, and **network segmentation is why OT survived** — the core consequence-driven,
  left-of-impact lesson. Use it to contrast "precursor perception" vs. the direct OT attacks above.

---

## 4. Buildability matrix (map to kit protocols & levels)

| # | Use case | Primary ATT&CK-for-ICS | DNP3 build | MQTT build | Kit level |
|---|---|---|---|---|---|
| 1 | Maroochy (rogue master / spoof) | T0848, T0855, T0856, T0829 | 2nd master IP; g12v1 `OPERATE`; spoofed `0x82` unsolicited | (opt.) rogue publisher to control topic | L3–L4 |
| 2 | Industroyer (brute-force I/O) | T0806, T0855, T0840, T0813 | Class-0/1/2/3 `READ` sweep → `OPERATE` across all indices | — | L4 |
| 3 | Havex (recon/enumeration) | T0846, T0861, T0888, T0802 | port scan incl. 20000; Class-0 `READ` dump | SUBSCRIBE `#` wildcard harvest | L1–L2, L4 |
| 4 | Oldsmar (modify setpoint) | T0836, T0822, T0831 | `SELECT`+`OPERATE` Group-41 analog-out write | `PUBLISH` out-of-range setpoint | L3–L4 |
| 5 | Colonial (precursor/boundary) | T0822, T0859, T0869, T0826 | IT-egress model + segmentation cut | broker-bridge egress anomaly | L1, narrative |

**DNP3 reference for the build (matches kit's `dnp3.al.func` teaching):** `0x01` READ · `0x02` WRITE ·
`0x03` SELECT · `0x04` OPERATE · `0x05` DIRECT_OPERATE · `0x06` DIRECT_OPERATE_NR · `0x81` RESPONSE ·
`0x82` UNSOLICITED_RESPONSE. Control objects: **g12v1** Control Relay Output Block (binary control,
breaker/pump); **Group 41** Analog Output Block (setpoints). Classes: **0** static/integrity,
**1/2/3** event data — an "integrity poll" reads Class 1,2,3,0.

---

## 5. Sources (all verified live, Aug 2026)

Program & methodology
- DOE CESER program page — https://www.energy.gov/ceser/cybersecurity-operational-technology-environment-cyote
- CyOTE Fact Sheet (PDF) — https://www.energy.gov/sites/default/files/2021-09/CyOTE_Fact_Sheet_508.pdf
- CyOTE program site — https://cyote.inl.gov/
- New CyOTE Tools (OPTIC/CATCH/BAM/Dashboard/Ontology) — https://www.energy.gov/ceser/articles/new-cyote-tools-support-better-risk-informed-cybersecurity-decision-making
- Bayesian Attack Model (BAM) tool page — https://cyote.inl.gov/tools/bayesian-attack-model-bam/
- CyOTE Program Document, INL/MIS-24-79011 (OSTI) — https://www.osti.gov/biblio/2428893
- INL Software Marketplace — CyOTE — https://inlsoftware.inl.gov/product/cyote

Case studies used
- Maroochy Shire — https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Maroochy.pdf
- Industroyer / CRASHOVERRIDE — https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Industroyer.pdf
- Havex — https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Havex.pdf
- Oldsmar water treatment — https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Oldsmar.pdf
- Colonial Pipeline / DarkSide — https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Colonial-Pipeline.pdf

MITRE ATT&CK for ICS technique references (for exact IDs/definitions)
- T0856 Spoof Reporting Message — https://attack.mitre.org/techniques/T0856/
- T0829 Loss of View — https://attack.mitre.org/techniques/T0829/
- T0832 Manipulation of View — https://attack.mitre.org/techniques/T0832/
- T0830 Adversary-in-the-Middle — https://attack.mitre.org/techniques/T0830/

---

## 6. Recommendation for the twin

Adopt CyOTE's **consequence-driven, left-of-impact** teaching arc explicitly: for each scenario,
show (a) the **triggering event** (the consequence), then have the learner walk backward through
**perceivable precursor observables** in the DNP3/MQTT capture, then **attribute** the anomaly to
ATT&CK-for-ICS technique(s) and an attack **phase** (Early/Middle/Late/Impact) — mirroring
BAM/OPTIC. Ship **Use cases #1–#4** as protocol-native captures (they map cleanly onto
`dnp3.al.func` control/read/unsolicited traffic and MQTT SUBSCRIBE-`#`/PUBLISH-setpoint), and use
**#5 (Colonial)** as the boundary/precursor narrative that motivates segmentation. This gives the
twin a real, citable, government-published detection methodology instead of an ad-hoc one.
