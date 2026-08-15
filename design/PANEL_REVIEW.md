# O*NET Persona Panel Review — Digital Twin + Learning Application

**Method.** Six O\*NET personas independently reviewed the kit (each grounded in the actual
repo — code, captures, curriculum, design docs), then their findings were synthesized and
turned into deliverables. Personas: **Information Security Analyst (15-1212.00)**, **Electrical
Engineer — Control Systems (17-2071.00)**, **Data Scientist (15-2051.00)**, **Instructional
Coordinator (25-9031.00)**, **Intelligence Analyst (33-3021.06)**, **Technical Writer
(27-3042.00)**.

**Bottom line.** The panel judged this "an unusually strong ICS teaching kit" — the
attack→harden loop is grounded in real code, the verification is byte-level honest (63/63 CRCs
recomputed), and the module prose is careful about scope. The gaps are the gaps of a kit that
has outgrown its origin: it began as *"some documented DNP3 & MQTT sample pcaps"* and became a
seven-level course plus a digital twin, and a few connective pieces and honesty caveats had not
caught up. This review records those gaps and what was built in response.

---

## What this review already produced

The maintainer's four asks were answered as concrete artifacts, each drawn from the panel's
own contributions:

| Ask | Deliverable | Backed by |
|---|---|---|
| Real-world connections to investigate | `projects/REAL_WORLD_CONNECTIONS.md` — a **web-verified** incident→source→ATT&CK→task index | Intelligence Analyst (+ all) |
| Starter AI prompts (forward→reverse) | `projects/STARTER_AI_PROMPTS.md` — a scaffolded forward-engineer-then-reverse ladder | Instructional Coordinator (+ all) |
| A grading rubric | `projects/ARTIFACT_RUBRIC.md` — 8 weighted dimensions, mastery gates, persona-validated | all six |
| Generated pcaps/artifacts as formal verification | `verification/` — a live-captured pcap + tshark evidence + the 21/21 reproducible pass | Data Scientist (+ InfoSec) |
| *(north-star, surfaced by the panel)* | `pcaps/README.md` — the sample-capture manifest the co-instructor actually needed | Technical Writer |

An accuracy fix was also applied: the twin launcher's `--attack` copy was corrected (it brings
up the adversary foothold; the injection is then run from it — it does not auto-fire).

---

## Prioritized gaps

### P0 — structural (mostly now addressed)

1. **No forward→reverse-engineer loop existed anywhere** *(Instructional, Data Scientist).* The
   kit only asked students to analyze instructor-built captures. **Addressed** by
   `projects/STARTER_AI_PROMPTS.md`, which makes "build it, then take it apart" the connective
   tissue between the pcaps and the twin.
2. **The digital twin has no on-ramp from the seven levels — the richest artifact is orphaned**
   *(Instructional).* A student finishing Level 6 has no scaffolded path into `lab/twin/`.
   **Partially addressed** (the project track + front-door now route into it); the standing
   recommendation is a formal **"Level 7 — the living plant"** bridge level that reuses the
   exact Level 3–5 field-analysis skills on the twin's live traffic.
3. **Invariant-based detection is taught in prose but never shipped as runnable code**
   *(InfoSec, Data Scientist).* Both modules describe the durable detection (bind link-address ↔
   expected session ↔ known-master set ↔ SELECT-before-OPERATE) but ship nothing a student can
   run and then evade. **Recommended build (P1):** a small Zeek/tshark/Suricata **detection
   pack** plus a red-team evasion exercise (the `STARTER_AI_PROMPTS` L5 rung rehearses this).
4. **`pcaps/` — the exact artifact the co-instructor asked for — had no manifest**, and the
   unseen graded captures sat unlabeled beside the teaching captures *(Technical Writer).*
   **Addressed** by `pcaps/README.md`.

### P1 — honesty & assessment integrity

5. **A few claims over-reach and should be corrected honestly** *(InfoSec, Data Scientist,
   Technical Writer).* Turn each into an "assumption-audit" lesson rather than a silent fix:
   - The C2 conduit is called a **data-diode but does not actually block downward MQTT
     commands** — teach it as stateful egress filtering with an explicit residual risk.
   - The **SAv5 stand-in has no freshness/anti-replay** (no monotonic CSQ/nonce in the HMAC
     input), which contradicts the documented anti-replay control.
   - **"Formal Verification"** is stronger than what runs (a reproducible *test record*, not
     model/property checking) — either rename or add one genuine property-based check.
   - **Industroyer does not speak DNP3** (it targets IEC-101/104/61850/OPC DA) — the real-world
     doc now states this precisely; ensure module prose never implies otherwise.
6. **The Machine-Problem answer key and detector ship inside the student handout folder**
   *(Instructional).* Split proctored materials into an instructor-only path; ship students a
   real stub (docstring + TODO, no working invariants).
7. **The self-check autograder is gameable and answer-leaking** *(Data Scientist,
   Instructional).* A spray-everything detector can score full marks; scoring ignores precision
   vs. recall and gives no partial credit or actionable feedback. Score precision **and** recall
   against a ground-truth label file; on FAIL emit a hint pointing at the field/filter to re-run.
8. **The net-new twin has zero automated verification and its central safety invariant is never
   proven headlessly** *(Data Scientist, Electrical).* Add a headless test: run `plant_sim`
   under adversarial pump forcing, assert **spill > 0 insecure** and **spill == 0 hardened**, and
   attribute *why* spill stayed 0 (clamp-rejected / interlock-veto / float-trip counters) so a
   green result cannot mask a bring-up failure.
9. **Real-world grounding needed the modern water-sector and the safety-layer anchor**
   *(Intelligence).* TRITON/TRISIS (the defining safety-instrumented-system attack) and the
   2023–24 water intrusions were missing. **Addressed** in `REAL_WORLD_CONNECTIONS.md`
   (TRITON = ATT&CK **S1009 / Campaign C0030**; CISA **AA23-335A** CyberAv3ngers, **AA24-038A**
   Volt Typhoon, Dragos **FrostyGoop**).

### P2 — control-fidelity & polish (twin backlog + docs)

10. **Twin control-logic fidelity** *(Electrical Engineer).* A rich, specific backlog: the
    dead-head/dry-run interlock is advertised but FIT-104/PIT-105 are wired and never read;
    `REMOTE_CMD (%MW12)` is a sticky mode with no auto-revert (one command pins the loop out of
    auto forever); duty/standby alternation is documented but P-1 is always lead; the hardened
    clamp's 85% upper bound exceeds `LAG_START` 80% (lag can start before lead); two hardened
    controls (W1 rising-well interlock, #10 comms-loss safe state) are dead code; `PIT-105` does
    not follow a centrifugal H-Q curve; DNP3 per-pump CROB index is collapsed to run-lead/stop-all;
    the OpenPLC `%MW/%IX/%QX` register map is unverified on real bring-up.
11. **Verification/reproducibility hardening** *(Data Scientist).* Assert *exact* frame counts
    (the current count check is effectively dead); ship a machine-readable `*.labels.json`
    ground-truth per capture; add a `to_flows(pcap)` feature-extraction lab step; publish a
    pinned toolchain lockfile + container digest; have `launch-twin.sh` drop a signed evidence
    bundle (pcap + spill log + Zeek logs) on teardown.
12. **Docs & onboarding** *(Technical Writer, Instructional).* Add a "just the pcaps" 90-second
    onramp and an `INSTRUCTORS.md` (how to grade without the shipped key); reconcile `build/` vs
    `source/` naming in the README; fix the worksheet's Zeek invocation to match the lab; publish
    the implicit objective/skill map; state MP/twin time-on-task honestly; foreground the headless
    `tshark` path as a co-equal (not fallback) track so the experience is not GUI/color-bound.

---

## Persona highlights

- **Information Security Analyst** — the attack→harden loop is real code, not slideware; the
  strongest single ask is to *ship the detections you teach* and then have students evade them.
- **Electrical Engineer** — the wet-well integrator is dimensionally correct and internally
  consistent with the attack narrative; the fidelity gaps are in the interlocks and mode logic,
  not the physics.
- **Data Scientist** — the byte-level CRC recomputation (with a self-test) is genuinely rigorous;
  the weakness is that too much verification lives in prose tables rather than assertions, and the
  twin is unverified.
- **Instructional Coordinator** — a textbook reverse-engineering progression; the missing half is
  the *forward* direction and a bridge from Level 6 into the twin.
- **Intelligence Analyst** — the real-world claims are careful and well-caveated; add TRITON and
  the modern water cases, and teach analogy-vs-attribution explicitly (Oldsmar is the example).
- **Technical Writer** — mature, well-written; keep the co-instructor's original 30-second use
  case (open a documented sample pcap) reachable in one step.

---

## Provenance

Full per-persona findings (with severities, evidence, and every proposed link/prompt/criterion)
are retained as JSON alongside this review. Real-world citations in
`projects/REAL_WORLD_CONNECTIONS.md` were individually web-verified; corrections made during that
pass include **Triton = S1009** (not the retired S0013, which now maps to PlugX), the **Havex
alert = ICS-ALERT-14-176-02A**, and a corrected Dragos FrostyGoop URL.
