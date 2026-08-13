# Instructor Solution & Notes (do NOT distribute to students)

> Delete this `solution/` directory before handing the MP out for a graded (proctored) run, and
> replace `grade.py` with a hidden-key version pointed at a freshly generated capture. For self-paced
> learning, leaving `grade.py`'s key in place is fine — it lets students self-check.

## Answer key
See `answers.solution.json` (this scores 60/60 on Part 1). Summary:

**DNP3 (`dnp3_assessment.pcap`)** — a spoofed **UNSOLICITED RESPONSE** (MITRE ATT&CK for ICS **T0856**,
Spoof Reporting Message).
- Malicious frame **26**: `ip.src 10.30.0.66`, but `dnp3.src` (link) **10** — the outstation's address,
  forged. The real outstation is **10.30.0.20** (link 10), which sends the genuine unsolicited event in
  frame **12** and all the responses.
- Two **legitimate masters**: link **100** (10.30.0.5, polls + controls) and link **101** (10.30.0.6,
  read-only) — so a naïve "only IP 10.30.0.5 is allowed" rule is wrong.
- The spoof reports the breaker **open** (g2v1 binary change, point 0 = 0) and **58.50 Hz** (g32v2 analog
  change, point 2 = 5850) — both **false**; the polls show breaker closed / 60.00 Hz. It carries **no
  control function code**, so a "watch the controls" detector never fires.

**MQTT (`mqtt_assessment.pcap`)** — a retained-message **harvest + persistent command injection**;
an **authorization** failure (the rogue authenticated fine).
- Anonymous **CONNECT** frame **39** (`mqtt-recon`, no username), **accepted** with CONNACK return code
  **0** in frame **41** (`allow_anonymous true`).
- Retained messages delivered to the rogue right after SUBACK: frames **47** (`plant/line1/config`),
  **49** (`plant/line1/command`), **51** (`plant/site/info`) — all `mqtt.retain == True`. Leaked:
  `hi_setpoint 80`, firmware `1.4.2`, service username **`svc_ingest`**, gateway `edge-gw-3`.
- Injection frame **57**: PUBLISH to `plant/line1/command`, **RETAIN = 1**, payload
  `{"actuator":"pump1","cmd":"START","valve":"open"}` — persists and re-delivers to the pump controller
  on its next connect (long after the attacker disconnects, frame 59).

## Part 2 detector
`solution/detector.py` implements the invariants and prints:
```
ALERT frame=26 ... (DNP3 link 10 from unexpected source 10.30.0.66)
ALERT frame=39 ... (MQTT anonymous CONNECT)
ALERT frame=57 ... (MQTT retained PUBLISH to command topic from anonymous client)
```
It generalizes to instructor variants (different addresses) because it keys on link-address↔IP
inconsistency and anon-connect↔retained-command correlation, not literals.

## Regenerating a fresh capture for a proctored run
Edit `source/build_assessment.py` (change the addresses/values), rebuild
(`python3 build_assessment.py`), update the key in a hidden `grade.py`, and re-verify with tshark.
