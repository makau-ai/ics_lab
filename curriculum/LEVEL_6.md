# Level 6 — Machine Problem — ICS Intrusion Analysis

*Capstone: analyze two unseen captures, build a detector, write the incident up*

**Difficulty:** University-level capstone &nbsp;·&nbsp; **Time:** ~120 min &nbsp;·&nbsp; **Prerequisite:** Levels 1–5.

**Goal.** Apply Levels 1–5 to captures you've never seen, using DIFFERENT attacks. Autograded (100 pts) + a written incident report.

## What you'll be able to do

- Triage two unseen captures and prove findings with named fields (Part 1, autograded).
- Implement an invariant-based detector.py (Part 2, autograded).
- Write an incident report with evidence, authN-vs-authZ, and controls (Part 3 + rubric).

## Background

This is a formal, university-style Machine Problem. The handout, the two evidence captures, an answer template, a self-check autograder, and the report rubric are all in the **`mp/`** folder. The attacks are new: a spoofed DNP3 status report (not a control), and an MQTT retained-message harvest + persistent command injection.

## Do this

**⌨ Type:** `l6`  — runs `cd mp && cat README.md      # the full handout: parts, deliverables, grading`

> **Check (expected):** MP: ICS Intrusion Analysis — Parts 1–3 + bonus.

**⌨ Type:** `l6b`  — runs `../lab/open-wireshark.sh captures/dnp3_assessment.pcap ; tshark -r captures/mqtt_assessment.pcap -Y mqtt`

> **Check (expected):** two captures you have not walked — apply everything from Levels 1–5.

**⌨ Type:** `l6c`  — runs `python3 grade.py`

> **Check (expected):** PASS/FAIL per item and a score /100. Iterate to green.


## Check yourself

1. **Where is the handout, and how do you check your work?**
   <details><summary>answer</summary>mp/README.md is the handout; `python3 mp/grade.py` autogrades Part 1 (answers.json) + Part 2 (detector.py) + Part 3 (format), and mp/rubric.md scores the written report.</details>

2. **Why must your detector.py use an invariant instead of printing the frame number?**
   <details><summary>answer</summary>The proctored re-run uses a freshly generated capture with different addresses; only an invariant (link-address↔IP inconsistency; anon-connect↔retained-command) generalizes.</details>

> **Capstone.** The handout, evidence captures, answer template, autograder, and rubric are in the `mp/` folder — start with `mp/README.md`.

**Level up:** Score 90+ on the autograder and meet the report rubric's mastery gates. You've completed the path.
