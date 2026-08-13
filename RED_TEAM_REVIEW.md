# Adversarial Review — ICS/OT Protocol Lab Kit (DNP3 & MQTT)

*Five O\*NET-grounded reviewers were each asked to attack the shipped kit from their professional
vantage — not to be fair, but to find what's toy-level, unrealistic, misleading, or wrong. Each read
the actual module text, lab code, pcaps, and Zeek logs. This document synthesizes their findings,
separates genuine defects from scope-expansion and defensible tradeoffs, and proposes a fix order.*

## The panel

| O\*NET | Persona | Lens | One-line verdict |
|---|---|---|---|
| 15-1299.04 | Penetration Testers | Offense realism | "Drills the trivial last 5% of an engagement and hand-waves the 95% that's hard." |
| 15-1212.00 | Information Security Analysts | Detection realism | "Two headline detections are demonstrably broken against the kit's own logs." |
| 51-8012.00 | Power Distributors & Dispatchers | OT reality / safety | "Teaches a control-room fantasy dressed up as Aurora; a trip is not godmode." |
| 25-9031.00 | Instructional Coordinators | Pedagogy / assessment | "Measures reading compliance, not learning; the exam is the practice with answers attached." |
| 15-1241.00 | Computer Network Architects | Architecture | "Instantiates the exact anti-pattern it should warn against; segmentation is cited, never built." |

## Bottom line up front

The kit's **protocol decoding is accurate and honestly instrumented** — every reviewer confirmed the
wire data, function codes, CRCs, QoS, and ICSNPP/Zeek parse check out. The attack surface it exposes
is real and the blue-team instinct (compensating controls, monitoring) is right.

But the reviewers agree the kit **over-promises on three fronts it doesn't deliver**: it frames a
pre-opened socket injection as "OT attack skills," it teaches a **detection that fails on its own live
lab traffic**, and it **builds the flat, unsegmented network that is itself the vulnerability** while
naming segmentation only in prose. Layered on top are a handful of **outright factual/consistency
errors** introduced in the content (frame count, an authN/authZ conflation, an inflated Aurora
analogy, a mis-scoped NERC CIP claim). None of this makes it useless — it makes it a strong
*protocol-literacy + intro-security* kit mislabeled in places as something more advanced.

---

## Most damaging cross-cutting findings (ranked)

### 1. The headline DNP3 detection is naive — and the live lab disproves it. *(SOC: BLOCKER · Pentest: MAJOR)*
The kit teaches "alert on any control whose source host isn't the sanctioned master" (Exercise 3, D3,
`dnp3_control.log`). Three problems, all confirmed against the files:
- `source_h` is the **IP**. The attacker forged only the DNP3 **link address** (kept real IP 10.20.0.66 and MAC); the forged field appears in **no** ICSNPP log. A smarter attacker who also assumes the master's IP (free from the L2 position the scenario already grants, or by hijacking the master's still-open TCP session) produces `source_h = 10.20.0.5` and the alert emits nothing.
- The **live** lab attack (`master.py --attack`) runs from the **master's own container/IP**, so a student who captures the live lab sees the trip originate from the legitimate master address — the signature they were just taught **fails on the exact traffic the kit generates**.
- It's base-rate naive: real outstations are legitimately controlled by primary **and** backup control centers, multiple front-end processors, DMS/OMS, and engineering laptops during maintenance — all non-primary IPs.

**Fix:** key on an invariant the attacker can't trivially satisfy — {link-address ↔ expected source ↔ known-master **set** ↔ SELECT-before-OPERATE}; alarm on OPERATE-without-SELECT, new sessions to :20000, or off-baseline function codes/timing. Add a separate `dnp3-attacker` service on its own IP (mirror the MQTT pattern) so live traffic matches the pcap, and note the link address must be added to the Zeek log to key on it at all.

### 2. The lab builds the OT anti-pattern and never lets students fix it. *(Architect: 2× BLOCKER · Dispatcher: MAJOR · Pentest: BLOCKER)*
Every service — broker, HMI, outstation, **both** attackers, and the Zeek monitor — sits on one Docker
bridge (`otlan`, 172.28.0.0/24) / one flat /24. Segmentation (IEC 62443 zones-and-conduits, NIST
SP 800-82r3) is *the* foundational OT control, and the lab models its inverse. The attacker's L2
adjacency to the RTU is the failure that should be **the lesson** — instead it's the unspoken premise.
There is a full broker harden-and-retest loop but **no segmentation harden-and-retest loop**.

**Fix:** split into ≥2 networks with a firewall/gateway container between an OT cell and a site/DMZ
zone; add a "move the attacker outside the conduit and watch the DIRECT_OPERATE trip and the anonymous
PUBLISH die at the firewall" exercise. Reorder every controls block to lead with segmentation/allow-
listing, with DNP3-SA/TLS as the durable upgrade (today D1/D3 lead with the SA re-flash you usually
*can't* ship and demote the firewall you can deploy this week).

### 3. Inflated / inaccurate incident framing. *(Dispatcher: BLOCKER + MAJOR · Instructional/Pentest corroborate)*
- **Aurora.** Frame 27's note calls a single feeder **trip** "the protocol equivalent of… the 2007 Aurora test." Wrong physics: Aurora is an **out-of-synchronism re-CLOSE** of a rotating generator (slip-torque destroys the machine), defended by sync-check (25) relays — not anything a lone trip touches. A feeder open destroys nothing; it's the fail-safe, reversible direction.
- **NERC CIP.** The DNP3 industry section says distribution traffic "falls under NERC CIP regulation." NERC CIP scopes the **Bulk Electric System** (broadly transmission ≥100 kV + certain generation); ordinary **distribution feeders are generally excluded** (state-PUC regulated, narrow UFLS/RAS exceptions). The kit then implies these same outstations are routinely internet-exposed — the two claims can't anchor the same asset.
- **Ukraine 2015 / Industroyer** are used correctly elsewhere, but the "protocol equivalent of the 2015 breaker-manipulation" line on frame 27 overreaches (2015 was stolen-credential HMI operation; Industroyer used IEC-104/61850/OPC, not DNP3).

**Fix:** strike the two "protocol equivalent" claims; if Aurora is taught, teach it accurately as an out-of-sync **close** problem; correct the CIP scope and cleanly separate "small/municipal/water DNP3 that does appear on Shodan" from "CIP-regulated transmission behind an electronic security perimeter."

### 4. Consequence model backwards; SELECT-before-OPERATE mis-taught as security. *(Dispatcher: MAJOR ×2)*
The module lavishes drama on the **trip** (open) — but from the control room, open is the fail-safe,
self-announcing, reversible direction. The genuinely dangerous act is an unsupervised **CLOSE** (onto a
grounded line/crew, into a fault, out-of-sync), which real substations gate with hot-line/clearance
tags, sync-check (25), reclose-blocking, and a **local/remote (43) switch** that removes the breaker
from SCADA during maintenance — none mentioned. Separately, SBO is a **safety/robustness** mechanism,
not authentication; D3's "consider disabling DIRECT OPERATE" stops zero attackers (they send
SELECT+OPERATE — two frames instead of one).

**Fix:** add an "OPEN ≠ CLOSE in consequence" note plus the engineering safeguards; label SBO
explicitly "safety, not security"; delete or footnote the disable-DIRECT-OPERATE mitigation.

### 5. Assessment is invalid: the exam is the practice with the answers attached. *(Instructional: BLOCKER ×2)*
Worksheet Q1–Q8 are **verbatim** the module's lab exercises, whose answers are one `<details>` click
(HTML) or printed inline (MD). Objectives are entirely low-Bloom's ("Identify / Read / Interpret /
Explain / Run"); the higher-order skill the kit claims to teach ("author the detection," "emulate
command injection") is **never assessed**. No rubrics, no mastery threshold, compound questions two
graders would score differently.

**Fix:** ship a separate **unseen** assessment capture (different addresses, a different injected
technique — e.g., a spoofed UNSOLICITED_RESPONSE or a wrong-source SELECT/OPERATE) with an analytic
rubric and a stated mastery bar; keep the current captures as guided practice. Rewrite objectives with
measurable higher-order verbs and matching tasks.

### 6. authN vs. authZ conflation in the answer key (plus a stale frame number). *(Instructional: MAJOR)*
Worksheet Q9's model answer says DNP3 and MQTT "share one root weakness … neither protocol
authenticates the peer." That's wrong for MQTT: the rogue host **was accepted at CONNECT** (anonymous
authentication *succeeded*, frame 40); the command injection is an **authorization** failure (no write
ACL) — which the module's own M3 vs. M5 correctly separate. The same answer cites "MQTT frame 54"; after
the QoS renumber the command is **frame 52** (the worksheet synthesis text wasn't updated).

**Fix:** reframe Q9 to distinguish identity (authN) from permission (authZ) and make it a misconception
probe; correct 54 → 52.

### 7. Frame-count inconsistency undercuts the "every frame verified" promise. *(Instructional + Architect: MINOR, but corrosive)*
The MQTT module text says a **"63-frame"** capture; the README, the landing page, and the shipped
`mqtt_iot_telemetry.pcap` are **61** (the QoS-correctness rework dropped two frames and the module
prose wasn't updated). Worksheet answers depend on exact numbers, so this isn't cosmetic.

**Fix:** correct to 61 everywhere.

### 8. The offense is the trivial last 5%; claimed capabilities aren't shipped. *(Pentest: BLOCKER + MAJOR ×3)*
The student is handed L2 adjacency, the addresses (hardcoded `OUTSTN_ADDR`/`MASTER_ADDR`), and an
outstation that obeys any peer — the entire hard part (initial access, pivot to the OT segment, recon,
address enumeration, persistence, exfil) is gone. There is no SBO **state** to bypass (OPERATE without
SELECT already executes), no DNP3-SA challenge/downgrade, and **no actual fuzzing** despite D5's
Project-Robus claim. `attacker.py` is a linear demo missing real MQTT tradecraft: retained-message
harvest, `$SYS/broker/#` enumeration, **Sparkplug B** `DCMD` injection (the dominant IIoT encoding),
and client-id-takeover DoS. Frame 52's "injection" also publishes into the void — nothing subscribes to
the command topic, so impact is notional.

**Fix (honesty now, depth later):** add explicit "the CROB is the last 5%; here's the kill chain that
precedes it" framing immediately; then, as a roadmap, add enumeration / L2-positioning / SBO-state /
SA-downgrade / fuzz exercises and a real MQTT enumeration tool with a subscriber that acts on commands.

### 9. The recommended encryption blinds the recommended sensor — never acknowledged. *(SOC: MAJOR · Architect: MINOR)*
The kit's headline fixes (DNP3 over TLS/VPN; MQTT on 8883) make ICSNPP/Zeek go **dark** — Zeek emits no
`mqtt_*.log` on 8883, and a DNP3 TLS tunnel is opaque to ICSNPP. The TLS exercise frames "payloads now
unreadable" purely as a win. Precision the kit also misses: **DNP3-SA (a MAC) does *not* blind ICSNPP**
— only transport encryption does. Monitoring **tap/SPAN placement** is never taught (the sniffers are
host-based on the asset itself).

**Fix:** add a beat — "once transport is encrypted, detection moves to broker auth logs, RTU syslog, and
flow/JA3 metadata" — and distinguish SA (visible on the wire) from TLS (opaque). State the tap point per
scenario.

### 10. Accessibility: the flagship interactive is unusable by keyboard/AT, and severity is color-only. *(Instructional: MAJOR ×2 — WCAG/508)*
Frame-Explorer rows are click-only `<div>`s (no `tabindex`/`role`/Enter handler); the detail pane is
`innerHTML` with no `aria-live`, so keyboard and screen-reader users can't navigate or hear selection
changes. NOTE/CAUTION/CRITICAL are conveyed **only** by dot color (WCAG 1.4.1). (Anomaly rows are fine —
they carry a ⚠ glyph and an "ANOMALY" text badge; extend that pattern.)

**Fix:** real `<button>`/`role="option"` rows in a `role="listbox"` with roving `tabindex`, `aria-live`
on the detail pane, visible arrow-key hint, and a short text token per severity so the dot is redundant.

### 11. Smaller but real *(Dispatcher/SOC/Architect: MINOR–MAJOR)*
Toy point list (4 binary/3 analog/1 counter) called "the substation's entire state" — real feeders carry
hundreds–thousands of points; **frequency** is rarely a per-feeder analog; a **1000 ms** CROB pulse is
long for a coil. Captures are noise-free, so "spot the impostor" is trivial — ship a high-volume,
multi-master **haystack** pcap with the injection buried. `mqtt_publish.log` logs full payloads for every
message — a process-data firehose at scale. Mutual-TLS/client certs and broker-per-zone are *recommended*
(M1/M3/M5) but **not built**. The O\*NET mapping is partly decorative — a **dispatcher never decodes DNP3
bytes** (the module's own persona quote admits it), so "Interpret CROB controls → 51-8012.00" is a loose
trace; keep the packet/detection occupations (15-1212, 15-1299.04, 15-1241) as "skill you practice," and
re-scope the operator/repairer to "context."

---

## Honest triage — what I'd actually change

**A. Fix now (factual/consistency errors in a shipped artifact; ~quick).**
Frame count 63 → 61 everywhere · Q9 authN/authZ reframe + frame 54 → 52 · NERC-CIP distribution scope ·
Aurora "protocol equivalent" correction · SBO "safety not security" + drop the disable-DIRECT-OPERATE
mitigation · add the "detection can be spoofed / TLS blinds the sensor" caveats · add a separate
`dnp3-attacker` container IP so the live lab stops contradicting the taught detection.

**B. High-value enhancements, on-scope (moderate effort).**
A short "detection under adversarial + operational reality" unit (invariant-based, multi-master,
encryption-blinds-sensor, tap placement) · a **segmentation** lab network + harden-and-retest exercise ·
an "OT reality check" box (OPEN≠CLOSE, safeguards, collapsed-topology disclaimer) · accessibility fixes ·
an **unseen** assessment capture + rubric + mastery bar · a noisy haystack pcap.

**C. Scope expansion (a bigger/next course, not defects).**
Full kill-chain tradecraft, DNP3-SA simulation + downgrade/replay, real fuzzing lab, Sparkplug B,
mutual-TLS + cert-lifecycle depth, broker-per-zone. Reasonable roadmap; label the current kit honestly
as protocol-literacy + intro OT security rather than an offensive OT course.

**D. Defensible tradeoffs (keep, but label).**
Curated, noise-free captures are fine as the *first* rung for intermediate learners — clean-first, then
a haystack. The collapsed single-segment topology is acceptable **only if explicitly labeled as
collapsed-for-teaching**, which every reviewer demanded and the kit currently omits.

## What all five agreed is genuinely good
1. **The wire data is correct and tool-verified** — valid DNP3 CRCs, coherent SELECT→OPERATE lifecycle, correct IIN semantics (0x8000 restart, 0x0200 Class-1), correct MQTT QoS/Will/pub-sub fan-out, clean ICSNPP/Zeek parse. As protocol-literacy material it's solid.
2. **The blue-team instinct is right** — cleartext-recon framing, the authenticity-vs-confidentiality distinction, correctly-applied MITRE ATT&CK for ICS IDs (T0855/T0856/T0814/T0842), and centering compensating controls for the "can't re-flash" defender.
3. **The MQTT insecure→secure harden-and-retest loop is model pedagogy** — a real, verifiable state change (CONNACK flips to rc=5). It's the template the DNP3 side and the missing segmentation exercise should copy.
