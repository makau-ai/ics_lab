# Cyber-Informed Engineering (CIE) — DOE/INL

**Research note for the ICS digital-twin (DNP3 / MQTT / PLC) lab.**
Compiled 2026-08-14. The 12 CIE principles, their guiding questions, the 5 National-Strategy pillars, and the CCE 4-phase methodology below were verified against DOE/CESER and Idaho National Laboratory (INL) primary sources (cited inline). Where an item is my **engineering application** to the lab rather than a direct quote from a CIE source, it is labeled `[APPLICATION]`. Direct quotes are in quotation marks. No principle names, guiding questions, or counts were invented.

---

## 0. TL;DR — what CIE actually is

- **Definition (DOE/CESER):** *"Cyber-Informed Engineering (CIE) is an emerging method to integrate cybersecurity considerations into the conception, design, development, and operation of any physical system."* — https://www.energy.gov/ceser/cyber-informed-engineering
- **Strategy definition:** CIE is *"the inclusion of cybersecurity considerations as a foundational element of engineering risk management for any function aided by digital technology."* — National CIE Strategy (June 2022).
- **The core move:** use *"design decisions and engineering controls to mitigate or even eliminate avenues for cyber-enabled attack, or reduce the consequences when an attack occurs."* — National CIE Strategy. CIE does not ask engineers to become cyber experts; it asks them to *"apply engineering tools and make engineering decisions that improve cybersecurity outcomes"* (CIE Implementation Guide, INL/RPT-23-74072).
- **Why it matters for us:** CIE is the doctrine that says a well-designed **hardwired interlock, mechanical relief valve, or analog backstop is a cybersecurity control** — because a consequence that is physically impossible cannot be caused by any packet on the wire. That is exactly the design lens for a DNP3/MQTT/PLC digital twin.

Two related-but-distinct things share the "consequence" language — keep them straight:
- **CIE** = the 12-principle engineering *philosophy/discipline* (design-time, applies to everyone, every lifecycle phase).
- **CCE** (Consequence-driven Cyber-informed Engineering) = INL's 4-phase *how-to methodology* for the highest-consequence systems; it is the operational way to *find* the consequences and *derive* the engineered mitigations. CIE and CCE are bidirectional: *"Considerations at any phase of any [CIE] principle may be prompted and improved by outcomes from running the CCE process."* (wisdiam.com, CIE vs CCE).

---

## 1. Primary sources (cite these)

| # | Document | ID / Publisher | URL |
|---|----------|----------------|-----|
| S1 | **National Cyber-Informed Engineering Strategy** (congressionally directed) | DOE/CESER, June 2022 | landing: https://www.energy.gov/ceser/articles/us-department-energys-doe-national-cyber-informed-engineering-cie-strategy-document · PDF: https://inl.gov/content/uploads/2023/07/FINAL-DOE-National-CIE-Strategy-June-2022_0.pdf |
| S2 | **CIE Implementation Guide** (the canonical 12-principle, lifecycle-question guide) | INL/RPT-23-74072-Rev000; authors: INL, 1898 & Co, Nexight, UT San Antonio, West Yost, Auburn | OSTI: https://www.osti.gov/biblio/1995796 |
| S3 | **Implementing CIE in Early Systems Engineering Lifecycle Stages** (defines the 2 categories × 6 principles = 12) | INL/CON-23-71008; Eggers, Le Blanc, Anderson, Wright; June 2023 | https://inldigitallibrary.inl.gov/sites/sti/sti/Sort_65018.pdf |
| S4 | **CIE Principles** (slide deck: each principle + guiding question + one-line definition) | INL | https://inldigitallibrary.inl.gov/sites/sti/sti/Sort_132848.pdf |
| S5 | **CIE Workbook** (GDO/GRIP hands-on training; guiding questions verbatim) | INL / CSDET | https://csdet.inl.gov/content/uploads/45/2025/03/GDO-GRIP_CIE-Workbook.pdf |
| S6 | **DOE CIE program page** (definition, consequence-focused framing) | DOE/CESER | https://www.energy.gov/ceser/cyber-informed-engineering |
| S7 | **INL CIE program page + Resource Library** | INL | https://inl.gov/national-security/cie/ · https://inl.gov/cie-resource-library/ |
| S8 | **CCE program page + Concept Paper** (the 4 phases) | INL | https://inl.gov/national-security/cce/ · PDF: https://inl.gov/content/uploads/2023/07/DOE_OSTI_CCEconcept-Paper.pdf |
| S9 | **CIE Engineered Controls Database / Explorer** (catalog of engineered controls) | INL — GitHub `idaholab/CIE_EC_Database`; related report OSTI purl 3006995 | https://github.com/idaholab/CIE_EC_Database · https://www.osti.gov/servlets/purl/3006995 |
| S10 | **"What are engineered controls?"** (practitioner explainer; cites the INL catalog, ~62,000 controls / 7 categories) | S. Fluchs (Medium), Jul 2026 | https://fluchsfriction.medium.com/what-are-engineered-controls-211568916b35 |
| S11 | *Countering Cyber Sabotage: Introducing CCE* (the CCE book, background) | Bochman & Freeman | ref: https://icdt.osu.edu/countering-cyber-sabotage-introducing-consequence-driven-cyber-informed-engineering-cce |

> Provenance caveat: the 12 principles / guiding questions below were cross-checked between S4 (slide deck) and S5 (workbook) and agree verbatim; the 2-category structure is from S3. Guiding questions are quoted from S4/S5. The engineered-controls taxonomy counts (~62,000 controls, 7 categories) are as reported by S10 citing the S9 repository — treat S9 as the source-of-truth to consult before quoting the exact category set in a deliverable.

---

## 2. The National CIE Strategy: five integrated pillars (S1)

These are the **strategy's program pillars** (how DOE drives CIE adoption) — *not* the engineering principles. Do not confuse the two.

1. **Awareness** — "Raise awareness of the CIE approach... among decision makers in the Energy Sector Industrial Base."
2. **Education** — "Develop a pipeline of CIE practitioners through education, training, and certification."
3. **Development** — "Mature CIE approaches... by building a repository of tools, practices, methods."
4. **Current Infrastructure** — "Use a consequence-driven approach to identify and apply CIE principles to the nation's systemically important critical infrastructure already... in service today."
5. **Future Infrastructure** — apply CIE "into the full lifecycle of newly commissioned critical infrastructure systems."
(Source: S1; pillar text mirrored at cyberinformedengineering.com/en/cie-pillars.)

For the lab, pillar 4 (retrofit existing) vs pillar 5 (design new) maps to two teaching tracks: *"how would you bolt CIE onto this legacy DNP3 RTU"* vs *"how would you design the twin so the consequence is impossible from day one."*

---

## 3. The 12 CIE principles — guiding questions + how each DESIGNS OUT cyber risk

Structure per S3 (Table 1): **6 Design & Operational** principles + **6 Organizational** principles. Guiding questions quoted from S4/S5. Each entry gives: the verified guiding question, the "design-out" mechanism, and `[APPLICATION]` buildable specifics for a DNP3/MQTT/PLC twin.

### A. Design & Operational principles

#### 1. Consequence-Focused Design
- **Guiding question (S4/S5):** *"How do I understand what critical functions my system must ensure and the undesired consequences it must prevent?"*
- **Design-out mechanism:** Start from the **worst physical outcome**, not from a list of CVEs. Enumerate the handful of High-Consequence Events (HCEs) the system must never allow, then design so those are unreachable regardless of cyber state. This is the "consequence-focused" core: *"prioritize defense against the worst possible consequences of cyberattacks"* (S6).
- **"Design-basis threat" for cyber:** replace an open-ended threat list with a **consequence-based design basis** — a short, bounded set of "must-never-happen" events becomes the thing the engineering must provably prevent (see §4 on CCE, the method that produces it).
- `[APPLICATION]` For the twin: write a one-page HCE register (e.g., *"pump deadheads against a closed valve"*, *"breaker recloses onto a fault"*, *"tank overfills"*). Tag each DNP3 point / MQTT topic that could contribute. Every later design decision references an HCE ID. Acceptance test: for each HCE, an attacker with full DNP3/MQTT write access still cannot reach it.

#### 2. Engineered Controls
- **Guiding question (S4/S5):** *"How do I select and implement controls to reduce avenues for attack or the damage that could result?"*
- **Design-out mechanism:** Apply the **hierarchy of controls** — prefer *eliminate/substitute* (make the bad state physically impossible) over *engineering controls* (hardwired/analog limits that don't depend on the digital system) over *administrative* controls (procedures) over *add-on cybersecurity* (last). An engineered control is *"a physical change in design or infrastructure that removes... digital devices or physical components from the cyber attack target deck"* (S8, CCE Phase 4). INL publishes a catalog of these — reported as ~62,000 controls across seven categories: *Physical Logic Mechanisms, Redundant Designs, Physical Constraints, Digital Engineered Controls, Passive Physical Dynamics, One-Way Enforcement, Fail-Safe Defaults* (S10 citing S9).
- **Hardwired interlocks / analog backstops (concrete, from S9/S10):** pressure **relief valves**, **rupture discs**, **spring-return (fail-safe) valves**, mechanical **locking/keyed** devices, **data diodes** (one-way enforcement), **thermal fuses / temperature-sensitive links**, **flywheels** (passive inertia). Strategy examples (S1): "replace networked switches with manual controls," "impose physical limits on harmful outputs," "retain hardwired backup capabilities."
- `[APPLICATION]` For the twin, model each as a component the PLC/DNP3 path cannot override:
  - Mechanical **overspeed/overpressure trip** and **relief valve** downstream of any actuator the attacker can command — the consequence caps out at the mechanical setpoint no matter what the setpoint register says.
  - **Hardwired ESD/interlock** in the safety instrumented function (SIF) that de-energizes to trip (fail-safe), wired to discrete I/O, *not* reachable over DNP3/MQTT and not writable by the logic solver's comms stack.
  - **Data diode** on the historian/telemetry egress so the twin can be observed but never commanded from the enterprise/MQTT-broker side.
  - Simulate the interlock in the digital twin as a hard clamp: even if the DNP3 CROB "TRIP/CLOSE" or an MQTT `cmd` payload is injected, the modeled process variable is bounded by the analog backstop.

#### 3. Secure Information Architecture
- **Guiding question (S4/S5):** *"How do I prevent undesired manipulation of important data?"*
- **Design-out mechanism:** Identify data sources, flows, trust boundaries; restrict how data moves so an attacker can't inject/alter the values that drive physical action (S4). Constrain command paths to one authenticated, minimal channel; make everything else read-only.
- `[APPLICATION]` DNP3: enable **Secure Authentication v5 (SAv5)** on control DNP3 (function codes SELECT/OPERATE, CROB, analog output), and enforce direction — outstation accepts commands only from the one authorized master. MQTT: **mTLS**, per-client ACLs so field devices can `publish` telemetry but only the controller can `publish` to command topics; broker denies wildcard subscribe on `cmd/#`. Segregate "measurement" from "command" onto separate topics/associations so a compromised sensor path cannot emit actuation.

#### 4. Design Simplification
- **Guiding question (S4/S5):** *"How do I determine what features of my system are not absolutely necessary to achieve the critical functions?"*
- **Design-out mechanism:** Remove non-essential features, ports, protocols, remote paths — every deleted feature is attack surface that no longer needs defending. "Design out" here literally means *delete*.
- `[APPLICATION]` Disable unused DNP3 function codes and unsolicited responses if not needed; turn off web/FTP/Telnet on RTUs; drop MQTT features you don't use (retained messages on command topics, `$SYS` exposure, anonymous access). One master, one protocol per link. Bill-of-features review each sprint: justify every open port against an HCE-relevant function or remove it.

#### 5. Resilient Layered Defenses (a.k.a. Layered Defenses)
- **Guiding question (S4/S5):** *"How do I create the best compilation of system defenses?"*
- **Design-out mechanism:** Defense-in-depth using the **Swiss-Cheese model** (S4) — no single barrier is trusted; independent layers (digital + engineered + physical + procedural) are stacked so holes don't line up. Crucially, at least one layer should be **non-digital** so a total OT-network compromise still can't align the holes.
- `[APPLICATION]` Layer stack for one HCE: (1) DNP3 SAv5 + MQTT ACL (digital), (2) PLC range/rate limits in logic, (3) independent **safety PLC/SIS** on separate I/O, (4) **hardwired interlock + relief valve** (analog), (5) operator procedure. The analog layer (4) is the backstop that holds *even if* layers 1–3 are fully owned.

#### 6. Active Defense
- **Guiding question (S4/S5):** *"How do I proactively prepare to defend my system from any threat?"*
- **Design-out mechanism:** Build in observability, tripwires, and the ability to detect/respond while operating (S4/S8). Design the system so defenders have vantage and pre-planned moves — including "tripwires" placed by CCE Phase 4.
- `[APPLICATION]` This is where our Zeek/ICSNPP work plugs in: passive DNP3/MQTT monitoring via a SPAN/TAP (never inline on the control path), analytics for illegal function codes, out-of-baseline setpoint writes, new master associations, MQTT clients publishing to `cmd/*`. Place deliberate **honey-points** (a DNP3 point / MQTT topic that should never be written) as tripwires. Monitoring taps read-only via the same data-diode discipline as principle 2.

### B. Organizational principles

#### 7. Interdependency Evaluation
- **Guiding question (S4/S5):** *"How do I understand where my system can impact others or be impacted by others?"*
- **Design-out mechanism:** Map cross-system dependencies and cascading effects (S4) so you don't inherit someone else's compromise (shared power, comms, time, DNS, cloud broker) and don't export yours.
- `[APPLICATION]` Diagram the twin's dependencies: shared MQTT broker/tenant, NTP/PTP time source, upstream SCADA master, cloud connectivity. For each, ask "if this is hostile, what HCE opens?" and add an engineered decoupling (local time fallback, broker-loss safe state, autonomous local control that survives comms loss).

#### 8. Digital Asset Awareness
- **Guiding question (S4/S5):** *"How do I understand where digital assets are used, what functions they are capable of, and our assumptions about how they work?"*
- **Design-out mechanism:** Maintain an inventory of digital assets *and their latent capabilities* — including undocumented/"hidden" functions that expand what an attacker can do. You can't design out what you don't know exists.
- `[APPLICATION]` Inventory every PLC/RTU/gateway with firmware version, enabled DNP3 function codes, MQTT client IDs/ACLs, engineering/maintenance ports, and dormant capabilities (e.g., an RTU that *can* do peer-to-peer DNP3 even if unused). Feed this straight into principle 4 (simplify) and principle 9 (supply chain).

#### 9. Cyber-Secure Supply Chain Controls
- **Guiding question (S4/S5):** *"How do I ensure my providers deliver the security the system needs?"*
- **Design-out mechanism:** Specify security requirements to vendors and verify them (SBOM, signed firmware, secure defaults, disclosed features) so unvetted trust isn't designed *in*.
- `[APPLICATION]` Procurement language: require SBOMs, signed/verifiable firmware, DNP3 SAv5 and MQTT-TLS support, no hardcoded creds, disclosure of all remote-access/undocumented features (ties to principle 12 of CWE work: "Poorly Documented/Undocumented Features"). Verify on the twin before field deployment.

#### 10. Planned Resilience (Planned Resiliency, with no assumed security)
- **Guiding question (S4/S5):** *"How do I turn 'what ifs' into 'even ifs'?"*
- **Design-out mechanism:** **Assume compromise.** Define degraded modes and alternate operating states so the mission survives "even if" the digital system is owned (S4). This is the doctrinal home of the analog backstop: design so that *even if* every controller is malicious, the plant stays in a safe envelope.
- `[APPLICATION]` For each HCE define an "even-if" statement and its engineered guarantee: *"Even if the DNP3 master is fully compromised, the pump cannot deadhead, because a mechanical relief valve + independent low-flow trip exist."* Design a manual/local **fallback control** and a defined **safe state on comms loss** (fail-closed/last-safe). Test by red-teaming the twin with full protocol write access and confirming the HCE still can't occur.

#### 11. Engineering Information Control
- **Guiding question (S4/S5):** *"How do I manage knowledge about my system? How do I keep it out of the wrong hands?"*
- **Design-out mechanism:** Protect the design knowledge (P&IDs, network diagrams, logic, setpoints, point lists) that an adversary needs to plan a consequence-based attack — starving CCE-style targeting of its inputs.
- `[APPLICATION]` Classify and access-control the twin's artifacts: DNP3 point maps, MQTT topic trees, PLC logic, SIS setpoints, network diagrams. Don't ship real point lists in training exports; scrub before publishing lab material. Least-privilege on the repo holding engineering info.

#### 12. Organizational Culture (Cybersecurity Culture)
- **Guiding question (S4/S5):** *"How do I ensure that everyone's behavior and decisions align with our security goals?"*
- **Design-out mechanism:** Make CIE a habit across engineering, ops, procurement — so consequence-thinking and engineered controls are default, not bolt-on.
- `[APPLICATION]` Bake the 12 guiding questions into our Scrum: a "CIE gate" in each sprint's Definition of Done (which HCE does this touch? what engineered/analog backstop bounds it?). Reference the CIE Implementation Guide (S2) lifecycle questions at design review.

---

## 4. The "design-basis threat for cyber" — CCE 4-phase methodology (S8)

Nuclear/physical security engineers design to a formal **Design Basis Threat**. CIE's cyber analog is **consequence-based**, not threat-enumerated, and the method that produces it is **CCE** — *"a methodology to identify high-consequence physical events achievable through cyber means... and develop mitigations and protections."* The four phases (S8 concept paper):

1. **Consequence Prioritization** — define the most critical functions and the highest-consequence events to protect (the "must-never-happen" set → the consequence-based design basis).
2. **System-of-Systems Breakdown** — identify the critical systems, digital devices, components, and key information exchanges that could produce those consequences.
3. **Consequence-based Targeting** — take the **adversary's perspective**: quantify *how* to achieve the specific impact, mapping the attack path against the **ICS Cyber Kill Chain**. *(This is the true "design-basis threat" step — it defines the concrete cyber-physical attack the engineering must defeat.)*
4. **Mitigations and Protections** — produce engineering design changes, mitigations, protections, and **tripwires**, favoring *"a physical change in design or infrastructure that removes... digital devices or physical components from the cyber attack target deck."*

**How to use it on the twin `[APPLICATION]`:** run a mini-CCE per HCE — (1) name the consequence, (2) trace the DNP3/MQTT/PLC path that could cause it, (3) play attacker and write the exact malicious sequence (injected CROB, forged analog-output write, MQTT command spoof), (4) insert the engineered backstop (interlock/relief/rate-limit/data-diode) that makes step 3 physically ineffective, plus a Zeek tripwire that catches the attempt. The pass criterion mirrors principle 10: the scripted attack executes fully and the HCE still cannot occur.

---

## 5. One-line crosswalk: task themes → CIE anchors

| Task theme | Primary CIE principle(s) | Source anchor |
|---|---|---|
| Consequence-focused | #1 Consequence-Focused Design; CCE Phase 1 | S4, S6, S8 |
| Engineered controls | #2 Engineered Controls (hierarchy of controls); CCE Phase 4 | S4, S8, S9/S10 |
| "Design-basis threat" for cyber | CCE Phase 3 Consequence-based Targeting; #10 "even ifs" | S8, S4 |
| Hardwired interlocks / analog backstops | #2 Engineered Controls + #5 Layered + #10 Planned Resilience | S1 (examples), S9/S10 (catalog) |

---

## 6. Gaps / verify-before-quoting
- Exact **category names and count** of the INL Engineered Controls catalog (§3 #2) are from S10 citing S9; the repo's own `Data/README` should be opened to quote the canonical taxonomy (a raw-file fetch 404'd on the guessed path — check the default branch/`Data/` path in S9 before publishing the seven category names as authoritative).
- S1 gives *hypothetical* engineering examples ("manual controls," "physical limits," "isolate safety sensors," "hardwired backup"); they are illustrative in the strategy, quoted as such here.
- Some content was retrieved via summarizing fetches of PDFs (S1, S3, S4, S5, S8); guiding questions were corroborated across two independent INL sources (S4 and S5) and agree. For a citable deliverable, pull the guiding questions from the CIE Implementation Guide (S2) as the single authoritative reference.
