# Proctoring the MP: building an address-shifted hidden variant

The public repo ships a **self-check** build: `grade.py` loads its key and ground-truth labels from
`mp/instructor/`, so anyone who reads the repo can see the answers. That is intentional for
self-paced learning. For a **graded, proctored** run you must (1) remove the leaked answers from the
students' reach and (2) change the capture so a student cannot copy last year's answers or a
hard-coded detector. Do both by generating an *address-shifted* variant.

## Why address-shifting (not just hiding the key)

The Part-2 detector is graded on **precision and recall** against `*.labels.json`, and Part-1 is
exact-match. A detector that hard-codes `frame=26` or `ip.src==10.30.0.66` earns full marks on the
shipped capture. Shift the addresses/frame layout and only an **invariant-based** detector
(link-address↔IP inconsistency; anonymous-CONNECT↔retained-command correlation) survives — which is
exactly the skill being assessed.

## Steps

1. **Edit the generator.** In `build/build_assessment.py` change the network identities and the
   planted values — e.g. attacker IP `10.30.0.66 → 10.30.7.42`, outstation `10.30.0.20 → 10.30.7.9`,
   master links `100/101 → 200/201`, the forged link, the false breaker state / frequency, the MQTT
   rogue IP, service username, and `hi_setpoint`. Reorder or pad frames so absolute frame numbers move.
2. **Rebuild** the two captures: `cd build && python3 build_assessment.py`. Confirm with tshark:
   ```bash
   tshark -r <new_dnp3>.pcap -Y dnp3 -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
   tshark -r <new_mqtt>.pcap -Y mqtt -T fields -e frame.number -e ip.src -e mqtt.msgtype \
                                      -e mqtt.username -e mqtt.topic -e mqtt.retain
   ```
3. **Regenerate the hidden key + labels** to match the new capture. Copy this directory to a location
   OUTSIDE the student hand-out, e.g. `~/mp_hidden/`, and update:
   - `answer_key.json` — every Part-1 value.
   - `dnp3_assessment.labels.json` / `mqtt_assessment.labels.json` — `malicious_frames`,
     `attacker_ip`, `forged_link`, `ttp` (recompute `malicious_frames` from the tshark dump above).
4. **Strip the student hand-out.** Delete `mp/instructor/` (and the `mp/solution/` compat symlinks)
   from the copy you give students. What remains at the student path is a real stub:
   `detector.py` (docstring + TODO, no working invariants), a blank `submission/answers.json`, the
   handout `README.md`, `rubric.md`, and `report.md`.
5. **Grade against the hidden key.** Point `grade.py` at the hidden directory:
   ```bash
   MP_KEY_DIR=~/mp_hidden python3 grade.py path/to/student/answers.json
   ```
   `grade.py` reads `answer_key.json` and `*.labels.json` from `$MP_KEY_DIR` when set, otherwise from
   `mp/instructor/`. Precision/recall is computed against the hidden labels, so a spray-everything
   detector fails and a hard-coded-frame detector fails on the shifted capture.

## Anchor scores to preserve when you build a variant

`build/verify_all.py` Section E expects a **blank** student copy to score **10/100** (Part-3 format
only) and the **reference** solution to score **100/100**. After building a variant, re-point the
reference `answers.solution.json` + reference `detector.py` and re-run `python3 grade.py` with the
hidden key to confirm those two anchors still hold before you proctor.
