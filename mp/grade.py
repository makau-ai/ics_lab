#!/usr/bin/env python3
"""
grade.py — autograder for MP: ICS Intrusion Analysis (100 points).

Run from the mp/ directory:

    python3 grade.py                       # grades ./submission/answers.json + ./detector.py + ./report.md
    python3 grade.py path/to/answers.json  # grade a specific answers file

Grades three parts:
  Part 1  (60) — manual triage: exact-match answers in answers.json
  Part 2  (30) — your detector.py flags the malicious frame in each capture
  Part 3  (10) — submission format: valid answers.json + report.md present

This grader ships with the answer key so you can self-check as you work.
Instructors distributing this as a *graded* assessment should remove or replace
grade.py with a hidden-key version and delete the solution/ directory.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.join(HERE, "captures")

# ---------------- answer key ----------------
KEY = {
    "part1_dnp3": {
        "malicious_frame": 26,
        "attacker_ip": "10.30.0.66",
        "forged_link_source": 10,
        "genuine_unsolicited_frame": 12,
        "real_outstation_ip": "10.30.0.20",
        "master_link_addresses": [100, 101],   # set-compared
        "false_breaker_state": "open",
        "attack_technique_ttp": "T0856",
    },
    "part1_mqtt": {
        "anonymous_connect_frame": 39,
        "connack_return_code": 0,
        "injection_frame": 57,
        "injection_retain_flag": 1,             # 1/true accepted
        "leaked_service_username": "svc_ingest",
        "leaked_hi_setpoint": 80,
        "failure_class": "authorization",
    },
}
PART1_POINTS = 4  # per item (8 dnp3 + 7 mqtt = 15 items * 4 = 60)
DETECTOR_TARGETS = {                            # detector must ALERT these frames
    "dnp3_assessment.pcap": 26,
    "mqtt_assessment.pcap": 57,
}


def norm(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, str):
        return v.strip().lower()
    return v


def match(key_val, ans):
    if isinstance(key_val, list):
        try:
            return set(int(x) for x in ans) == set(key_val)
        except Exception:
            return False
    if key_val in (0, 1) and isinstance(ans, bool):
        return int(ans) == key_val
    if isinstance(key_val, int):
        try:
            return int(ans) == key_val
        except Exception:
            return False
    return norm(ans) == norm(key_val)


def grade_part1(ans):
    got, total, lines = 0, 0, []
    for section in ("part1_dnp3", "part1_mqtt"):
        for field, kv in KEY[section].items():
            total += PART1_POINTS
            a = ans.get(section, {}).get(field, None)
            ok = a is not None and match(kv, a)
            got += PART1_POINTS if ok else 0
            lines.append(f"  [{'PASS' if ok else 'FAIL'}] {section}.{field:26} "
                         f"expected={kv!r:24} got={a!r}")
    return got, total, lines


def run_detector(pcap, target):
    det = os.path.join(HERE, "detector.py")
    if not os.path.exists(det):
        return 0, f"  [FAIL] detector.py not found (write it for Part 2)"
    p = os.path.join(CAP, pcap)
    try:
        out = subprocess.run([sys.executable, det, p], capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return 0, f"  [FAIL] detector.py crashed on {pcap}: {e}"
    hit = any(f"frame={target}" in ln.replace(" ", "") or f"frame= {target}" in ln
              or f"frame={target} " in (ln + " ") for ln in out.splitlines())
    # be lenient: accept the target frame number appearing after 'frame='
    hit = any(("frame=" in ln and str(target) in ln.split("frame=", 1)[1].split()[0]) for ln in out.splitlines())
    return (15 if hit else 0), f"  [{'PASS' if hit else 'FAIL'}] detector.py flags frame {target} in {pcap}"


def main():
    apath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "submission", "answers.json")
    print("=" * 68)
    print("  MP: ICS Intrusion Analysis — autograder")
    print("=" * 68)
    fmt = 0
    # Part 3a: valid answers.json (5)
    ans = {}
    try:
        with open(apath) as f:
            ans = json.load(f)
        fmt += 5
        print(f"\nPart 3 — submission format")
        print(f"  [PASS] answers.json parses ({apath})")
    except Exception as e:
        print(f"\nPart 3 — submission format")
        print(f"  [FAIL] answers.json missing/invalid: {e}")
    # Part 3b: report present (5)
    report = os.path.join(HERE, "report.md")
    if os.path.exists(report) and os.path.getsize(report) > 0:
        fmt += 5
        print(f"  [PASS] report.md present")
    else:
        print(f"  [FAIL] report.md missing or empty (write your incident report)")

    print("\nPart 1 — manual triage (answers.json)")
    p1, p1max, lines = grade_part1(ans)
    for ln in lines:
        print(ln)

    print("\nPart 2 — detector.py")
    p2 = 0
    for pcap, target in DETECTOR_TARGETS.items():
        pts, msg = run_detector(pcap, target)
        p2 += pts
        print(msg)

    total = p1 + p2 + fmt
    print("\n" + "-" * 68)
    print(f"  Part 1 (triage):   {p1:3d} / {p1max}")
    print(f"  Part 2 (detector): {p2:3d} / 30")
    print(f"  Part 3 (format):   {fmt:3d} / 10")
    print(f"  TOTAL:             {total:3d} / 100")
    band = "Mastery" if total >= 90 else "Proficient" if total >= 75 else "Developing" if total >= 60 else "Not yet"
    print(f"  BAND:              {band}")
    print("-" * 68)
    print("Note: the written report.md is scored separately by the rubric in rubric.md.")


if __name__ == "__main__":
    main()
