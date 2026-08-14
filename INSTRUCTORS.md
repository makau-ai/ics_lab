# Co-Instructor Onboarding

Everything a co-instructor needs to **run and grade** this kit — especially the Machine Problem (MP)
— without leaking the shipped answer key. It gathers into one place what is otherwise implicit across
`mp/README.md`, `mp/instructor/PROCTORING.md`, `mp/grade.py`, and `build/README.md`.

Protocol roles are used precisely throughout: DNP3 **master/outstation**; MQTT
**broker/publisher/subscriber**; Modbus **client/server**.

> **Working tree vs. shipped kit.** You edit everything under **`build/`**; the assembled kit mirrors
> those same scripts to **`source/`**. So `build/verify_all.py` here and `source/verify_all.py` in a
> shipped kit are the same file — commands below show `build/`; substitute `source/` on a packaged kit.

---

## 1. The two graded pieces, and where the rubrics fit

There are **two distinct graded workflows**. Do not confuse them.

| Piece | What the student submits | How it is graded |
|---|---|---|
| **Machine Problem** (`mp/`, Level 6) | `submission/answers.json` (Part 1) · `detector.py` (Part 2) · `report.md` (Part 3) | **`mp/grade.py`** autogrades Part 1 (exact-match, 60 pts) and Part 2 (precision **and** recall vs. ground-truth labels, 30 pts); you hand-grade `report.md` with **`mp/rubric.md`** (12 pts). |
| **Forward→reverse project / twin capstone** (`projects/`, `lab/twin/`) | an artifact **bundle**: `forward/` app + `capture.pcap` (+ a benign control capture) + `ground_truth.labels.json` + `report.md` + `detector.py` + `REPRODUCE.md` | you hand-grade the whole bundle with **`projects/ARTIFACT_RUBRIC.md`** (8 weighted dimensions, mastery gates, bands). |

**How the rubrics relate.** `mp/rubric.md` is the *narrow* report rubric for the MP's single incident
write-up (Identify / Interpret / Justify / Recommend-control + a Communicate axis). `ARTIFACT_RUBRIC.md`
is the *superset* — it grades a student's own built-and-broken artifact across forward-engineering
fidelity, evidence, authN-vs-authZ, detection realism, physical/consequence grounding, control
efficacy, reproducibility, and communication. The two share language on purpose (the same
authN-vs-authZ gate, the same "invariant not signature" detection standard), so a student who masters
the MP report is already writing to the artifact rubric. The **worked exemplar** of a Mastery-level
bundle is **`verification/`** — its evidence maps onto the artifact rubric's R1–R7.

---

## 2. Grading the MP without leaking the shipped key

The public repo ships a **self-check** build on purpose: `mp/grade.py` loads its key and ground-truth
labels from **`mp/instructor/`**, so a self-paced learner can score their own work. **That means the
answers are readable in the repo** — a student can open `mp/instructor/answer_key.json` or print
`ALERT frame=26` and pass the self-check without an invariant-based detector. For a **graded,
proctored** run you must do two things: remove the leaked answers from the students' reach, **and**
change the capture so last year's answers and hard-coded detectors do not transfer. Both are achieved
by building an **address-shifted hidden variant**. Full procedure: **`mp/instructor/PROCTORING.md`**.

**Why address-shifting, not just hiding the key.** Part 1 is exact-match and Part 2 is scored on
precision/recall against `*.labels.json`. A detector that hard-codes `frame=26` or
`ip.src==10.30.0.66` earns full marks on the shipped capture. Shift the addresses and frame layout and
only a genuinely **invariant-based** detector survives — a DNP3 link address that appears from more
than one source IP is impersonation; an MQTT client that connected anonymously and then PUBLISHed a
**retained** message to a command topic is a persistent unauthorized command. That is exactly the
skill being assessed.

**Build the variant (summary — see `PROCTORING.md` for every value):**

```bash
# 1. Edit the generator: change network identities and planted values.
#    build/build_assessment.py — attacker IP, outstation IP, master link addresses,
#    the forged link, false breaker state, MQTT rogue IP, leaked username, hi_setpoint;
#    reorder/pad frames so absolute frame numbers move.
cd build && python3 build_assessment.py            # rebuilds the two assessment pcaps

# 2. Sanity-check the new captures with tshark (roles used precisely):
tshark -r ../pcaps/dnp3_assessment.pcap -Y dnp3 \
       -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
tshark -r ../pcaps/mqtt_assessment.pcap -Y mqtt \
       -T fields -e frame.number -e ip.src -e mqtt.msgtype -e mqtt.username -e mqtt.topic -e mqtt.retain

# 3. Copy mp/instructor/ to a path OUTSIDE the student hand-out and update it to match:
#    answer_key.json (every Part-1 value) and the two *.labels.json (malicious_frames,
#    attacker_ip, forged_link, ttp) — recompute malicious_frames from the tshark dump above.
cp -r ../mp/instructor ~/mp_hidden

# 4. Strip the hand-out: delete mp/instructor/ (and the mp/solution/ compat symlinks)
#    from the student copy. What remains is a real stub — detector.py with a docstring +
#    TODO and no working invariants, a blank submission/answers.json, README/rubric/report.

# 5. Grade against the hidden key (grade.py reads $MP_KEY_DIR, else mp/instructor/):
MP_KEY_DIR=~/mp_hidden python3 ../mp/grade.py path/to/student/submission/answers.json
```

**Self-check ≠ certification.** A PASS on the shipped self-check does **not** prove a detector is
invariant-based — only a run against a **shifted** hidden capture does. Tell students this, and grade
the real thing against the variant.

**Grading `report.md`.** Score it with `mp/rubric.md`. Two mastery gates apply, but **the parenthetical
frame numbers in `mp/rubric.md` are variant-specific** — they name the shipped self-check capture
(DNP3 spoofed UNSOLICITED = frame 26; MQTT CONNECT/CONNACK = frames 39/41). When you grade an
address-shifted variant, **verify the gates against your own hidden `*.labels.json`**, not the printed
frame numbers. The gates themselves are invariant: (1) names the spoofed message as the malicious
frame, not the genuine unsolicited event; (2) classifies the MQTT injection as an **authorization**
failure (the broker authenticated the anonymous client — CONNECT accepted, CONNACK rc 0 — so identity
was granted; only permission was unconstrained). Never accept "MQTT has no authentication."

---

## 3. Run & verify commands

```bash
# Self-check a student's MP submission (shipped key):
cd mp && python3 grade.py submission/answers.json

# Grade a proctored variant against a hidden key/labels directory:
MP_KEY_DIR=~/mp_hidden python3 mp/grade.py path/to/student/answers.json

# Rebuild the student worksheet + instructor answer key:
cd build && python3 build_worksheets.py

# Rebuild the two assessment captures after editing the generator:
cd build && python3 build_assessment.py

# Full reproducible verification pass (byte-level CRCs, curriculum commands, MP anchors):
cd build && python3 verify_all.py
#   Expected: 18/18 checks, 63/63 DNP3 CRCs. Section E asserts a BLANK student copy
#   scores 10/100 (Part-3 format only) and the reference solution scores 100/100 —
#   re-run these two anchors after building any variant before you proctor.

# Run the shipped invariant detectors (and see them evaded):
cd lab/detect && ./run_selftest.sh     # see lab/detect/README.md + RED_TEAM_EVASION.md
```

---

## 4. Honest time-on-task

Plan the syllabus against real numbers, not the happy path.

| Unit | Realistic time-on-task | What drives it |
|---|---|---|
| Levels 0–5 (the guided path) | ~2.5–3 h total (10 / 25 / 25 / 40 / 35 / 40 min) | Reading + hands-on tshark/Wireshark per level; see the objective/skill map in `README.md`. |
| **Machine Problem — Parts 1–2** (autograded) | **~120 min** for a prepared student | Triaging two unseen captures field-by-field and writing an invariant-based `detector.py`; iterating against the precision/recall grader adds time. |
| **Machine Problem — Part 3** (report) | **+30–45 min** | Writing the incident report to the `mp/rubric.md` gates. |
| Instructor: build + verify an address-shifted variant | **~30–60 min, one-time per offering** | Editing `build_assessment.py`, recomputing the hidden key + labels, re-running the two `verify_all.py` anchors. |
| Forward→reverse project (a `projects/` rung) | ~2–4 h per rung | Build the app, capture, analyze, write the detector + `REPRODUCE.md` (graded on `ARTIFACT_RUBRIC.md`). |
| **Twin capstone** (`lab/twin/`) | **~1.5–3 h**, and note the **one-time manual seed** | The twin will **spill on first boot until you complete the UI-driven OpenPLC seed** (`lab/twin/README.md` §7 — Slave Devices → the values in `openplc/slave_devices.seed`). Budget that seed *before* the "keep spill at 0" acceptance run; the front door's "spill stays 0" promise only holds after it. |

---

## 5. Files you will touch (and the ones you must not hand out)

| Path | Role |
|---|---|
| `mp/grade.py` | Autograder. Reads the key from `$MP_KEY_DIR` else `mp/instructor/`. Do not edit; point it, don't patch it. |
| `mp/instructor/` | **INSTRUCTOR-ONLY, answer-leaking.** Strip from any proctored hand-out; copy + edit for the hidden variant. |
| `mp/rubric.md` | Report rubric (hand-graded). Frame numbers are variant-specific — verify against your labels. |
| `mp/instructor/PROCTORING.md` | The authoritative variant-build procedure. |
| `build/build_assessment.py` | The assessment-capture generator you edit to shift addresses. |
| `build/verify_all.py` | The reproducible pass + the two MP anchor scores. |
| `projects/ARTIFACT_RUBRIC.md` | The superset rubric for built-and-broken artifact bundles / the twin. |
| `verification/` | The Mastery-level worked exemplar you can show students. |
