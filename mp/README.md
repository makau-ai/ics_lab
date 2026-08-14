# MP: ICS Intrusion Analysis (DNP3 & MQTT)

*Network-Security Machine Problem — capstone (Level 6). Weight: instructor-set.
Due: instructor-set (to the minute, with time zone). This is a **solo** assignment.*

> *"You can't defend. You can't prevent. The only thing you can do is detect and respond."*
> — Bruce Schneier

## 1. Overview

A small electric/utility operator has pulled two packet captures off segments where something
looks wrong. Your job is the analyst's job: **triage the captures, prove what happened with
evidence from specific fields, build a detector that catches it, and write the incident up.**

These captures are **new** — you have not walked them in the lessons, and each uses a *different*
technique than the guided demos. Everything you need you learned in Levels 1–5 (endpoints →
message types → packet internals → security → detection). Reading an answer off a prior exercise
will not work here.

- `captures/dnp3_assessment.pcap` — a substation monitored by more than one legitimate master; one
  frame is a lie.
- `captures/mqtt_assessment.pcap` — a plant broker; a rogue client abuses a broker feature to harvest
  secrets and plant a persistent command.

## 2. Learning objectives

By completing this MP you will be able to: (a) differentiate legitimate from spoofed/unauthorized
protocol messages using named packet fields as evidence; (b) implement a deterministic,
invariant-based detector rather than a signature that hard-codes addresses; (c) distinguish an
**authentication** failure from an **authorization** failure; and (d) communicate an incident and a
remediation in writing.

## 3. Ethics & authorization

Analyze **only** the provided lab captures and the isolated lab you were given. The techniques here
are for defense. Running these attacks against systems you are not explicitly authorized to test is
prohibited by law and by your institution's policy, and may result in fines, expulsion, and criminal
charges. When in doubt, don't.

## 4. Environment & setup

Do this MP inside the kit's Codespace (or any box with `tshark`, `wireshark`, and `python3`):

```bash
cd mp
python3 grade.py          # runs the autograder against your work (self-check as you go)
```

Open a capture in Wireshark with `../lab/open-wireshark.sh captures/dnp3_assessment.pcap`, or analyze
headlessly with `tshark -r captures/dnp3_assessment.pcap -Y dnp3`.

## 5. Provided files

| File | Purpose | Modify? |
|---|---|---|
| `captures/*.pcap` | the two evidence captures | do not modify |
| `answers.template.json` | the Part-1 answer schema | copy → `submission/answers.json`, then fill |
| `submission/answers.json` | **your** Part-1 answers | **yes — you fill this** |
| `detector.py` | **your** Part-2 detector (a stub is provided) | **yes — you implement this** |
| `report.md` | **your** Part-3 incident report (a template is provided) | **yes — you write this** |
| `grade.py` | the autograder (self-check; ships with the key for learning) | do not modify |
| `rubric.md` | how the written report is scored | reference |

## 6. The problem

### Part 1 — Manual triage (60 pts, autograded)

Open each capture and answer, in `submission/answers.json`, using field evidence (not guesses).
Every value is exactly checkable. Fields:

**`part1_dnp3`**
- `malicious_frame` — the one frame that is an attack (integer).
- `attacker_ip` — the IP source of that frame.
- `forged_link_source` — the DNP3 **link** source address the attacker wrote into it (integer).
- `genuine_unsolicited_frame` — the frame number of the *legitimate* unsolicited response (for contrast).
- `real_outstation_ip` — the true outstation's IP.
- `master_link_addresses` — the DNP3 link addresses of **all** legitimate masters (array of integers).
- `false_breaker_state` — the breaker state the attack *claims* (`"open"` or `"closed"`).
- `attack_technique_ttp` — the MITRE ATT&CK for ICS technique ID (e.g., `"T0xxx"`).

**`part1_mqtt`**
- `anonymous_connect_frame` — the rogue's CONNECT with no credentials.
- `connack_return_code` — the broker's CONNACK return code to that CONNECT (integer).
- `injection_frame` — the frame that plants a persistent command.
- `injection_retain_flag` — the RETAIN flag value on that PUBLISH (`1` or `0`).
- `leaked_service_username` — a service account username the rogue harvested.
- `leaked_hi_setpoint` — a numeric setpoint the rogue harvested.
- `failure_class` — is the injection an `"authentication"` or an `"authorization"` failure?

> Hints you learned earlier: `tshark -r <pcap> -Y dnp3 -T fields -e frame.number -e ip.src -e dnp3.src`;
> compare `ip.src` against `dnp3.src`. For MQTT, `mqtt.retain` prints `True`/`False`. Retained messages
> are delivered right after a subscribe.

### Part 2 — Build a detector (30 pts, autograded)

Implement `detector.py` so that `python3 detector.py <capture.pcap>` prints one line per malicious
frame, in the form:

```
ALERT frame=<n> reason=<short reason>
```

The autograder runs your detector on **both** captures and checks that you flag the malicious frame in
each (DNP3 and MQTT — 15 pts each). **Detect by invariant, not by hard-coding** frame numbers or IPs:
a DNP3 link address that appears from more than one source IP is impersonation; an MQTT client that
connected with no username and then published a **retained** message to a command topic is a
persistent unauthorized command. A detector that only works by printing `frame=26` literally earns no
credit on the hidden re-run (instructor variant with different addresses).

### Part 3 — Incident report (10 pts format, + rubric)

Write `report.md`: for each capture, a short incident write-up — what happened, the evidence (named
fields/frames), whether it was an authentication or authorization failure, the likely impact, and the
**control** that would have stopped it (map to DNP3-SA/segmentation or broker ACLs/auth). The
autograder gives 10 pts for a present, valid submission; the **content** is scored on `rubric.md`
(Identify / Interpret / Justify / Recommend-control).

### Bonus (optional) — Recover & remediate

(1) Decode the harvested MQTT payloads from hex to recover every leaked value. (2) Propose and, in the
lab, **implement** one concrete control per protocol (a Mosquitto `acl_file` entry; a firewall/allow-list
or DNP3-SA note), then show — with a fresh capture or the segmented lab — that the attack no longer
succeeds. Document it in `report.md` under "Remediation."

## 7. Testing / autograder

```bash
cd mp && python3 grade.py
```

It prints PASS/FAIL per item and a score out of 100 (Part 1 = 60, Part 2 = 30, Part 3 format = 10).
Iterate until green. `grade.py` ships with the answer key so you can self-check while learning; a
proctored version uses a hidden key and a different capture.

## 8. What to submit

`submission/answers.json`, `detector.py`, and `report.md` (plus any remediation artifacts for the bonus).

## 9. Grading

| Component | Pts |
|---|---|
| Part 1 — manual triage (15 exact-match items × 4) | 60 |
| Part 2 — detector flags the DNP3 attack | 15 |
| Part 2 — detector flags the MQTT attack | 15 |
| Part 3 — valid `answers.json` + `report.md` present | 10 |
| **Autograded total** | **100** |
| Written report content (see `rubric.md`, 12 pts) | instructor-weighted |

## 10. Academic integrity

This MP is **solo**. You may discuss concepts and tools, but sharing or viewing another student's
`answers.json`, `detector.py`, or report text — or posting the captures/solutions publicly — is an
integrity violation. Do not share the handout or captures with a public LLM service.

## 11. Late policy

Instructor-set (e.g., a fixed per-hour penalty (for example 2%/hour) or a small number of grace
hours). State it on your course page.
