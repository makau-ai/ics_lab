# `mp/instructor/` — INSTRUCTOR-ONLY (proctored materials)

**Do not distribute the contents of this directory to students.** Everything here is answer-leaking.
It is kept in the public teaching repo *only* so the self-paced autograder (`../grade.py`) can
self-check learner work and so `build/verify_all.py` can prove the anchor scores. For a real graded
exam, strip this directory and build an address-shifted hidden variant (see `PROCTORING.md`).

| File | What it is | Leaks |
|---|---|---|
| `answer_key.json` | Part-1 exact-match key that `grade.py` loads (was previously hard-coded inside `grade.py`) | all Part-1 answers |
| `answers.solution.json` | reference student answers (scores 60/60 on Part 1) | all Part-1 answers |
| `detector.py` | **reference** Part-2 detector (invariant-based; scores 30/30) | Part-2 solution |
| `dnp3_assessment.labels.json` | ground truth for the DNP3 precision/recall grader (`malicious_frames`, `attacker_ip`, `forged_link`, `ttp`) | the malicious frame |
| `mqtt_assessment.labels.json` | ground truth for the MQTT precision/recall grader | the malicious frames |
| `SOLUTION.md` | full worked solution + instructor notes | everything |
| `PROCTORING.md` | how to build an address-shifted hidden variant for a real graded run | — |

## Backward compatibility

`grade.py` loads the key from `answer_key.json` and the detector ground truth from the two
`*.labels.json` files in this directory. If this directory is **absent** (i.e. it was stripped for a
proctored hand-out and no hidden variant was wired up), `grade.py` degrades to **self-check mode**:
it still validates submission format, runs the student detector, checks the `ALERT frame=<n>` output
shape, and prints actionable hints — but it cannot score Part-1 correctness or Part-2 precision/recall
without a key. Point `grade.py` at a hidden key/labels directory via the `MP_KEY_DIR` environment
variable to grade a proctored variant (see `PROCTORING.md`).

The legacy `../solution/` directory is now just two backward-compat **symlinks**
(`answers.solution.json`, `detector.py`) into this directory, retained so `build/verify_all.py`
Section E and the `cp solution/… ` snippet in `FORMAL_VERIFICATION.md` keep resolving unchanged.
