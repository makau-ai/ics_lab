# Written Incident Report — Grading Rubric (12 pts)

Applied to `report.md`. This complements the 100-point autograder (which scores the exact answers and
the detector); the report measures whether the student can *reason about and communicate* the incident.

| Criterion | 0 — Not shown | 1 — Emerging | 2 — Proficient | 3 — Mastery |
|---|---|---|---|---|
| **Identify** | Misnames the attack or the malicious frame | Vague; wrong or partial frames/actors | Correct malicious frame + main actors, minor omission | Exact malicious frame(s) and every key actor by number/field/address, no misclassification |
| **Interpret** | Misreads the protocol behavior | Surface reading; misreads a key field (link-vs-IP, RETAIN, a value) | Mostly correct; one minor error | Correctly reads the fields and states real-vs-claimed / retained-vs-live accurately |
| **Justify (authN vs authZ)** | Assertion, no/wrong evidence | Conflates authentication and authorization | Two correct fields; classification mostly right | ≥3 independent fields; cleanly separates authentication from authorization for **each** capture |
| **Recommend-control** | No workable control, or one the capture shows would fail | Generic control, not tied to the evasion or false-positives | Reasonable control, incomplete coverage | Control actually closes the gap **and** states what it does/doesn't cover; scoped to avoid false positives (e.g., a master **set**, per-topic ACL) |

**Mastery gates (must be met for a report score ≥ 10/12):**
1. Names the DNP3 **spoofed UNSOLICITED RESPONSE** (frame 26) as the malicious frame — not the genuine
   unsolicited event (frame 12).
2. Classifies the MQTT injection as an **authorization** failure (the rogue *was* authenticated
   anonymously — CONNECT frame 39, CONNACK 0 frame 41 — so identity was accepted; permission was not
   constrained).

**Bands:** Mastery 10–12 (+ gates) · Proficient 7–9 · Developing 4–6 · Not yet ≤ 3.
Common misses: calling frame 12 the attack (Identify=0); "MQTT has no authentication" (Justify miss —
it authenticated the rogue anonymously); proposing TLS as the harvest fix (partial only — TLS stops an
on-path sniffer, not an *authenticated* rogue reading through the broker; the gap is ACLs).
