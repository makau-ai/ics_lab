# CWE View 1358 — SEI ETF Categories of Security Vulnerabilities in ICS

**Research note for the ICS digital-twin (DNP3 / MQTT / PLC) lab.**
Compiled 2026-08-14. All CWE IDs/names and memberships below were verified against `cwe.mitre.org` (CWE 4.20 content). Where the task's example CWEs are **not** members of the view, that is stated explicitly rather than fabricated.

---

## 1. What View 1358 is

- **Canonical view:** CWE-1358 — "Weaknesses in SEI ETF Categories of Security Vulnerabilities in ICS"
- **View URL:** https://cwe.mitre.org/data/definitions/1358.html
- **Flat member slice (all weaknesses in one list):** https://cwe.mitre.org/data/slices/1358.html
- **View type:** Graph (a curated organizational view, not a scoring/mapping view).
- **Provenance:** Aligns CWE entries to the **Securing Energy Infrastructure Executive Task Force (SEI ETF)** report *"New Categories of Security Vulnerabilities in ICS"* (v1.0, published **March 2022**). Source PDF: https://secureenergy.inl.gov/content/uploads/27/2024/12/SEI-ETF-NCSV-TPT-Categories-of-Security-Vulnerabilities-ICS-v1_03-09-22.pdf ; DOE program page: https://www.energy.gov/ceser/securing-energy-infrastructure-executive-task-force
- **Method / caveat (important for citing):** The view maps SEI ETF categories to CWEs using **"Nearest IT Neighbor"** recommendations. MITRE explicitly warns *"Relationships are likely to change in future CWE versions."* Several member categories carry a **"cannot be used for mapping"** usage note — they organize/teach, they do not certify a CVE-to-CWE mapping. Treat memberships as a teaching taxonomy, not a fixed conformance list.
- **Target audience (per MITRE):** ICS/OT hardware designers, product vendors, assessment-tool vendors, and academic researchers.

---

## 2. Category structure (full tree)

View 1358 has **3 top-level SEI ETF pillars → 8 subcategories**. Every node is a CWE **Category** (CWE-1359..1371); leaf members are ordinary CWE weaknesses.

```
CWE-1358  View: Weaknesses in SEI ETF Categories of Security Vulnerabilities in ICS
│
├── CWE-1359  ICS Communications
│     ├── CWE-1364  ICS Communications: Zone Boundary Failures
│     ├── CWE-1365  ICS Communications: Unreliability
│     └── CWE-1366  ICS Communications: Frail Security in Protocols   ◄── most relevant to DNP3/MQTT
│
├── CWE-1360  ICS Dependencies (& Architecture)
│     ├── CWE-1367  External Physical Systems
│     └── CWE-1368  External Digital Systems
│
└── CWE-1361  ICS Supply Chain
      ├── CWE-1369  IT/OT Convergence/Expansion
      ├── CWE-1370  Common Mode Frailties
      └── CWE-1371  Poorly Documented or Undocumented Features
```

Category URLs (pattern `https://cwe.mitre.org/data/definitions/<ID>.html`):
1359, 1360, 1361 (pillars); 1364, 1365, 1366, 1367, 1368, 1369, 1370, 1371 (subcategories).

---

## 3. Verified membership of the lab-relevant subcategories

### CWE-1366 — ICS Communications: Frail Security in Protocols  *(the primary bucket for DNP3 & MQTT)*
URL: https://cwe.mitre.org/data/definitions/1366.html
Summary: *"Vulnerabilities arise as a result of mis-implementation or incomplete implementation of security in ICS implementations of communication protocols."*

| CWE | Name |
|-----|------|
| 121 | Stack-based Buffer Overflow |
| 125 | Out-of-bounds Read |
| 268 | Privilege Chaining |
| 269 | Improper Privilege Management |
| 276 | Incorrect Default Permissions |
| **290** | **Authentication Bypass by Spoofing** |
| **306** | **Missing Authentication for Critical Function** |
| **311** | **Missing Encryption of Sensitive Data** |
| 312 | Cleartext Storage of Sensitive Information |
| **319** | **Cleartext Transmission of Sensitive Information** |
| 325 | Missing Cryptographic Step |
| 327 | Use of a Broken or Risky Cryptographic Algorithm |
| 330 | Use of Insufficiently Random Values |
| 336 | Same Seed in PRNG |
| 337 | Predictable Seed in PRNG |
| 341 | Predictable from Observable State |
| **349** | **Acceptance of Extraneous Untrusted Data With Trusted Data** |
| 358 | Improperly Implemented Security Check for Standard |
| 362 | Race Condition (improper synchronization of shared resource) |
| 377 | Insecure Temporary File |
| 384 | Session Fixation |
| 648 | Incorrect Use of Privileged APIs |
| 787 | Out-of-bounds Write |
| 1189 | Improper Isolation of Shared Resources on SoC |
| 1303 | Non-Transparent Sharing of Microarchitectural Resources |
| **1393** | **Use of Default Password** |

### CWE-1364 — ICS Communications: Zone Boundary Failures
URL: https://cwe.mitre.org/data/definitions/1364.html
Summary: traffic crossing network-zone boundaries that were designed for *safety* but are being repurposed for *security*.
Members: 212, 268, 269, **287 (Improper Authentication)**, **288 (Authentication Bypass Using an Alternate Path or Channel)**, **306**, 362, 384, 434, 494 (Download of Code Without Integrity Check), 501 (Trust Boundary Violation), 668, 669, 754, 829, 1189, 1263 (Improper Physical Access Control), 1303, **1393**.

### CWE-1365 — ICS Communications: Unreliability
URL: https://cwe.mitre.org/data/definitions/1365.html
Summary: vulnerabilities from disruptions to the physical layer carrying traffic (e.g., induced electrical noise).
Members: 121, 269, **306**, **349**, 362, **807 (Reliance on Untrusted Inputs in a Security Decision)**, 1247, 1261, 1332, 1351, 1384.

### CWE-1368 — ICS Dependencies (& Architecture): External Digital Systems
URL: https://cwe.mitre.org/data/definitions/1368.html
Members: 15, **287**, **306**, 308 (Single-factor Auth), 312, 440, 470, 603 (Client-Side Authentication), 610, 638 (Not Using Complete Mediation), 1059, 1068, 1104, 1329, 1357, **1393**.

### CWE-1369 — ICS Supply Chain: IT/OT Convergence/Expansion
URL: https://cwe.mitre.org/data/definitions/1369.html
Key members: **CWE-284 (Improper Access Control)**, CWE-636 (Not Failing Securely / "Failing Open"). Carries a "cannot be used for mapping" note.

### CWE-1367 / 1370 / 1371 (less central to a comms lab)
- **1367 External Physical Systems:** 1247, 1338, 1357, 1384.
- **1370 Common Mode Frailties:** 329, 664, 693, 707, 710, 1357.
- **1371 Poorly Documented/Undocumented Features:** 489 (Active Debug Code), 912 (Hidden Functionality), 1059, 1242 (Undocumented Features / "Chicken Bits").

---

## 4. Reconciling the task's example CWEs (verified, no fabrication)

The task listed five example weaknesses. Verification result:

| Task example | CWE | Actually a member of View 1358? | Where / nearest verified analog in the view |
|---|---|---|---|
| Missing authentication for critical function | **CWE-306** | **YES** | Members of CWE-1364, 1365, 1366, 1368 |
| Cleartext transmission | **CWE-319** | **YES** | Member of CWE-1366 (see also CWE-311 Missing Encryption, CWE-312 Cleartext Storage) |
| Improper access control | **CWE-284** | **YES** | Member of CWE-1369 |
| Improper input validation | **CWE-20** | **NO — not present in the view** | Nearest members: **CWE-349** (Acceptance of Extraneous Untrusted Data w/ Trusted), **CWE-807** (Reliance on Untrusted Inputs in a Security Decision), plus memory-safety leaves CWE-121/125/787 for malformed-packet parsing |
| Insufficient verification of data authenticity | **CWE-345** | **NO — not present in the view** | Nearest members: **CWE-290** (Authentication Bypass by Spoofing), **CWE-349**, **CWE-494** (Download of Code Without Integrity Check), CWE-358 (Improperly Implemented Security Check for Standard) |

**Takeaway for the write-up:** cite CWE-306 / 319 / 284 as *direct* View-1358 members; when you need "input validation" or "data-authenticity" framing, cite the **in-view analogs (349, 807, 290, 494)** and note that CWE-20/CWE-345 are their canonical parents but are *not themselves* enumerated in View 1358 (a consequence of the "Nearest IT Neighbor" mapping method).

---

## 5. Lab mapping — concrete, buildable scenarios (DNP3 / MQTT / PLC)

All detections assume the Zeek + **ICSNPP** analyzers already in this kit (`dnp3.log`, `mqtt*.log`, `conn.log`).

### DNP3 (TCP/20000, no auth or crypto in the base protocol)
- **CWE-306 Missing Authentication for Critical Function** — Craft/replay an **unauthenticated DNP3 control**: application-layer function code **0x04 OPERATE** (or 0x03 SELECT then 0x04) carrying a **CROB (Control Relay Output Block, group 12 var 1)** to trip/close a breaker; also 0x0D COLD_RESTART / 0x0E WARM_RESTART. Outstation executes with no credential. *Detect:* Zeek `dnp3.log` `fc_request` = `OPERATE`/`SELECT`/`COLD_RESTART` from a non-master source; alert on any write/operate/restart function code.
- **CWE-319 Cleartext Transmission** — DNP3 app data rides cleartext TCP; objects/points are readable in the PCAP with no TLS. *Detect:* presence of parsed `dnp3.log` at all (protocol visible in plaintext) + `conn.log` showing no TLS on :20000.
- **CWE-290 Authentication Bypass by Spoofing** — Spoof the master's source IP/DNP3 source address to inject OPERATE frames the outstation trusts. *Detect:* same DNP3 command function code from an unexpected `id.orig_h` / DNP3 source addr.
- **CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data** (in-view analog for "input validation") — Inject **unsolicited responses** (function 0x82) or extra objects so the master ingests attacker data alongside legitimate polls.

### MQTT (TCP/1883 plaintext; TCP/8883 TLS)
- **CWE-306 Missing Authentication** — Broker with `allow_anonymous true`: a client issues **CONNECT** with no username/password and **PUBLISH**es to a control topic. *Detect:* ICSNPP MQTT `connect` events with empty username; PUBLISH to control topics from unknown clients.
- **CWE-319 Cleartext Transmission** — On :1883 the **CONNECT** packet carries username/password in cleartext, and all PUBLISH payloads are readable. *Build:* PCAP contrasting :1883 (readable creds/telemetry) vs :8883 (TLS). *Detect:* MQTT parsed on 1883 = plaintext; creds visible.
- **CWE-1393 Use of Default Password** / **CWE-276 Incorrect Default Permissions** — Broker shipped with vendor default creds / world-writable topic tree.
- **CWE-284 Improper Access Control** (via CWE-1369) — No MQTT ACLs: any client may SUBSCRIBE to `#` (all telemetry) and PUBLISH to actuator/command topics. *Detect:* subscription to wildcard `#`, or PUBLISH to command topics by non-authorized client IDs.
- **CWE-311 Missing Encryption of Sensitive Data** — Sensitive process telemetry published without TLS.

### PLC / field device
- **CWE-306 / CWE-287 Improper Authentication** — PLC management/register-write path (e.g., Modbus-style or vendor programming protocol) accepts writes with no credential; write a holding register / download logic unauthenticated.
- **CWE-1393 Use of Default Password / CWE-308 Single-factor Auth** — engineering-workstation → PLC session protected only by a default or single factor.
- **CWE-807 Reliance on Untrusted Inputs in a Security Decision** — HMI/operator trusts PLC-reported state that an attacker can forge (classic "lie to the operator" — Stuxnet/Industroyer pattern), so a safety decision is made on spoofed values.
- **CWE-494 Download of Code Without Integrity Check** (via CWE-1364) — firmware/logic download to the PLC with no signature/integrity verification (in-view analog for CWE-345 data-authenticity).

---

## 6. Suggested minimal citation set for lab docs

Direct View-1358 members to cite for a comms-focused DNP3/MQTT/PLC lab:
**CWE-306, CWE-319, CWE-311, CWE-290, CWE-349, CWE-284, CWE-807, CWE-287, CWE-288, CWE-494, CWE-1393** — all under view **CWE-1358**, primarily via category **CWE-1366** (Frail Security in Protocols) with boundary/dependency additions from **CWE-1364/1365/1368/1369**.
Note in the doc that **CWE-20** and **CWE-345**, though commonly expected, are **not enumerated** in View 1358; their in-view stand-ins are **CWE-349/CWE-807** and **CWE-290/CWE-494** respectively.

---

## Sources
- CWE-1358 view (definition): https://cwe.mitre.org/data/definitions/1358.html
- CWE-1358 view (flat slice of all members): https://cwe.mitre.org/data/slices/1358.html
- CWE-1366 Frail Security in Protocols: https://cwe.mitre.org/data/definitions/1366.html
- CWE-1364 Zone Boundary Failures: https://cwe.mitre.org/data/definitions/1364.html
- CWE-1365 Unreliability: https://cwe.mitre.org/data/definitions/1365.html
- CWE-1367 External Physical Systems: https://cwe.mitre.org/data/definitions/1367.html
- CWE-1368 External Digital Systems: https://cwe.mitre.org/data/definitions/1368.html
- CWE-1369 IT/OT Convergence/Expansion: https://cwe.mitre.org/data/definitions/1369.html
- CWE-1370 Common Mode Frailties: https://cwe.mitre.org/data/definitions/1370.html
- CWE-1371 Poorly Documented/Undocumented Features: https://cwe.mitre.org/data/definitions/1371.html
- SEI ETF "New Categories of Security Vulnerabilities in ICS" (v1.0, Mar 2022): https://secureenergy.inl.gov/content/uploads/27/2024/12/SEI-ETF-NCSV-TPT-Categories-of-Security-Vulnerabilities-ICS-v1_03-09-22.pdf
- DOE Securing Energy Infrastructure Executive Task Force: https://www.energy.gov/ceser/securing-energy-infrastructure-executive-task-force
