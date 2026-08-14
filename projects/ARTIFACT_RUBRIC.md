# Artifact Rubric — Forward→Reverse ICS/OT/IoT Projects (and the Twin Capstone)

Applied to the **artifact bundle** a student submits from [`STARTER_AI_PROMPTS.md`](STARTER_AI_PROMPTS.md)
— `forward/` app + `capture.pcap` (+ a benign control capture) + `ground_truth.labels.json` +
`report.md` + `detector.py` + `REPRODUCE.md` — and equally to the wet-well twin capstone. It grades
whether the student can **build a wire-valid target, take it apart on the evidence, and bound the
consequence honestly.**

**Persona-validated.** Each dimension is backed by named O*NET personas who authored and reviewed the
kit: **15-1212.00** Information Security Analyst · **17-2071.00** Electrical Engineer · **15-2051.00**
Data Scientist · **25-9031.00** Instructional Coordinator · **33-3021.06** Intelligence Analyst ·
**27-3042.00** Technical Writer. The persona codes on each row name the reviewers whose
`rubric_criteria` converged into it. The **worked exemplar of a Mastery-level bundle** is
[`../verification/`](../verification/README.md) — its §1–§3 (reproducible verification pass,
frame-level pcap decode, live-lab evidence) map onto R1–R7 below.

**Scoring.** Score each dimension **0–3**, multiply by its weight, sum, and divide by 3 for a weighted
percent (all-3s = 100%). Weights sum to 100%. Bands and mastery gates are below the table.

| Criterion | 0 — Not shown | 1 — Emerging | 2 — Proficient | 3 — Mastery |
|---|---|---|---|---|
| **R1 · Forward-engineering fidelity** — wire-valid traffic & sound physics *(12% · 25-9031.00, 17-2071.00)* | App doesn't run, emits only raw TCP no dissector recognizes, **or** the "weakness" is a malformed/crashing packet rather than a legal message | Runs but traffic is partly invalid — bad CRC/framing, wrong port, or Zeek/ICSNPP won't parse it; any physics is dimensionally wrong or unbounded | Wire-valid traffic on the correct port that Wireshark parses; minor gaps (a declared-but-unused I/O point, an off unit, or an illusory per-point control) | Wire-valid, **Zeek/ICSNPP-parseable** traffic on the correct port (MQTT 1883/8883 · DNP3 20000 · Modbus 502); planted weakness is a **legal message from the wrong party**; any physics is a dimensionally-correct bounded mass balance with consistent sizing; declared I/O is used and each control index maps to a **distinct physical effect** |
| **R2 · Evidence-grounded packet/log analysis** — frame + field citation *(18% · 15-1212.00, 25-9031.00, 27-3042.00)* | Claims asserted with no frame/field evidence, or the named malicious frame is wrong | Surface reading; cites frames but not the deciding field, or misreads a key field (link-vs-IP, RETAIN, a value) | Correct malicious frame(s) and main actors cited by frame + field; one minor omission | **Every** claim anchored to the specific **frame, field, and value** (and Zeek log line) that proves it; distinguishes **IP source from DNP3 link source**, a live PUBLISH from a **retained** delivery by the RETAIN bit, and claimed-vs-real — naming the field that decides each |
| **R3 · Authentication vs authorization reasoning** *(12% · 25-9031.00, 15-1212.00)* | No/wrong evidence, or conflates the two ("the protocol has no authentication") | Conflates authN and authZ, or classifies from a single field | Two correct fields; classification mostly right for each capture | **≥3 independent fields**; cleanly separates "who are you" from "are you allowed" **for each capture** — e.g. the broker *authenticated* the anonymous client (CONNECT + CONNACK rc=0) so the injection is an **authorization** failure, while the DNP3 forged-link control is an **authentication** failure |
| **R4 · Detection realism** — invariant not signature; precision AND recall *(18% · 15-1212.00, 15-2051.00, 25-9031.00)* | No detector, a hard-coded `frame==`/`ip==`, or a spray-everything rule that "passes" by alerting on all frames | Keys on a single spoofable field (source IP) or one attack shape (block `#`); no false-positive test | Invariant-based and fires on the attack, but not measured against a benign control, or false-positives on legitimate secondary masters / normal telemetry | Keys on a **spoof-resistant invariant** (link-address-from-two-IPs; anon-connect + retained-write-to-command-topic; OPERATE-without-SELECT); **precision AND recall** measured against labeled ground truth incl. a **benign capture it stays silent on**; survives an address/frame re-run; accounts for base rate and where the sensor goes **dark under encryption** |
| **R5 · Physical & consequence grounding** — HCE + scoped real incident *(12% · 17-2071.00, 33-3021.06, 15-2051.00, 15-1212.00)* | No tie to physical consequence, or a wrong/over-claimed analogy (calls a feeder trip "Aurora") | Names a consequence or an incident loosely; wrong ATT&CK technique or mis-scoped incident | Ties the finding to the physical HCE and a real incident with a mostly-correct technique ID; minor over-claim | Ties the technical finding to the physical **High-Consequence Event** (SSO / breaker operation) **and** a correctly-scoped real incident (Maroochy · Oldsmar · Aliquippa · FrostyGoop · TRITON); correct **ATT&CK-for-ICS** ID; honest **analogy-vs-attribution**; findings prioritized by contribution to the HCE, not CVSS reflex |
| **R6 · Control efficacy & honest CIE layering** *(14% · 15-1212.00, 17-2071.00, 25-9031.00, 33-3021.06)* | No workable control, or one the capture shows would fail (e.g. TLS against an authenticated rogue) | Generic control, not tied to the evasion or false-positives; no statement of coverage limits | Reasonable control that closes the demonstrated gap; incomplete on what it does **not** cover, or hierarchy placement fuzzy | Places each control on the hierarchy (**eliminate / engineer / administer / add-on**) and states precisely what it does **and does not** stop (SELECT arm-latch is operational not identity; the firewall "data-diode" doesn't stop broker-originated downward delivery; the teaching HMAC gives authenticity not freshness); at the process tier, **proves the engineered backstop holds under full write access**, attributing spill==0 to the specific layer (clamp vs interlock vs **float**) |
| **R7 · Reproducibility & provenance** *(8% · 15-2051.00, 33-3021.06, 27-3042.00)* | Orphan/unexplained pcap; no origin, no checksum; numbers not reproducible | Documented origin but no manifest/lockfile; a grader cannot re-derive the figures | Documented origin + SHA-256 + `capinfos`; re-runnable with minor manual steps or unpinned tools | Every capture has a **documented origin** (self-generated command line or cited dataset), a **SHA-256 manifest** + `capinfos`, a **machine-readable ground-truth** label file, and **one documented command** (pinned tool versions / container digest) reproduces every figure bit-for-bit |
| **R8 · Communication & inclusive-accurate terminology** *(6% · 27-3042.00, 25-9031.00, 33-3021.06)* | Unstructured; jargon unexplained; wrong protocol role names; not headlessly reproducible (GUI screenshots only) | Some structure; inconsistent terminology or an ableist/imprecise metaphor; analyst-only, no operator handoff | **BLUF** + predictable section order; terminology mostly correct; filters a reader could re-run; minor lapses | BLUF-first and findable in <10s; translates protocol detail into an **operator decision** (analyst→operator handoff); filters/frames **re-runnable headlessly**; color/graphics carry text equivalents; correct roles (DNP3 **master/outstation** · MQTT **broker/publisher/subscriber** · Modbus **client/server**), authN vs authZ kept distinct, **inclusive-accurate** language (allow-list/deny-list, on-path, "loss of view"); states **confidence** and analogy-vs-attribution |

**Mastery gates (must be met for an overall Mastery band):** phrased by invariant first; the frame
numbers are parenthetical and **variant-specific — verify each against your own `ground_truth.labels.json`.**

1. **Identifies the malicious message as a legal frame from an unauthorized party** — for DNP3, the
   control frame whose link address is sourced from an IP **outside the known-master set** (the
   forged-link DIRECT_OPERATE/spoofed UNSOLICITED — *frame 27 in the `dnp3_substation` teaching
   capture; frame 26 in the MP self-check; verify against your key*), **not** the genuine event (e.g.
   the real unsolicited, frame 12 in the teaching capture).
2. **Classifies the MQTT injection as an authorization failure** — the broker **authenticated** the
   anonymous client (accepting CONNECT + CONNACK rc=0), so identity was granted; only permission was
   unconstrained (*the accepting CONNECT/CONNACK pair in your capture — frames 38/40 teaching, 39/41
   MP; cite yours*). Never "MQTT has no authentication."
3. **The detector keys on a spoof-resistant invariant, not a hard-coded frame/IP** — it fires on the
   attack (**recall**) **and** stays silent on a benign control capture (**precision**), and still
   fires when the capture is regenerated with different addresses/frame order.
4. **At the process/twin tier, the engineered backstop is proven under full write access** — the same
   attack re-run hardened leaves the **spill counter at 0**, and the report attributes **which
   independent layer held** (setpoint clamp vs stop-interlock vs the hardwired float), not the toggle
   bundle. *(Gate 4 applies to Rungs 4–5 and the twin capstone; waive for the flat-pcap rungs 1–3, 6.)*

**Bands:** **Mastery** ≥ 85% weighted **+ all applicable gates** · **Proficient** 70–84% ·
**Developing** 50–69% · **Not yet** < 50%.

**Common misses:** calling the genuine event the attack (R2 = 0); "MQTT has no authentication" (R3
miss — it authenticated the rogue anonymously; the gap is ACLs); proposing **TLS as the harvest fix**
(R6 partial only — TLS stops an on-path sniffer, not an *authenticated* rogue reading through the
broker); a source-IP detector (R4 miss — fails the moment the attacker spoofs the master's IP and
false-positives on backup masters/FEPs); attributing `spill==0` to the toggle bundle instead of the
one layer that held (R6 miss); a spray-everything detector scoring full marks (R4 = 0 — the
anti-pattern); calling a feeder trip "Aurora" or a demonstrated protocol weakness an "attributed
incident" (R5 over-claim).
