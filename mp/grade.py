#!/usr/bin/env python3
"""
grade.py — autograder for MP: ICS Intrusion Analysis (100 points).

Run from the mp/ directory:

    python3 grade.py                       # grades ./submission/answers.json + ./detector.py + ./report.md
    python3 grade.py path/to/answers.json  # grade a specific answers file

Grades three parts:
  Part 1  (60) — manual triage: exact-match answers in answers.json
  Part 2  (30) — your detector.py, scored on PRECISION AND RECALL against a
                 ground-truth label set (15 pts per capture, F1-weighted). A
                 detector that flags the malicious frame(s) *and only those*
                 earns full marks; a spray-everything detector that flags every
                 frame is penalised on precision and scores near zero.
  Part 3  (10) — submission format: valid answers.json + report.md present

ANSWER KEY & GROUND TRUTH ARE NOT IN THIS FILE. The Part-1 key is loaded from
instructor/answer_key.json and the Part-2 detector ground truth from
instructor/<capture>.labels.json. Set MP_KEY_DIR to grade against a hidden,
address-shifted proctored variant (see mp/instructor/PROCTORING.md). If neither
is present, grade.py runs in self-check mode: it validates format, runs your
detector, checks the ALERT output shape and prints hints, but cannot score
Part-1 correctness or Part-2 precision/recall without a key.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.join(HERE, "captures")
# Answer key + ground-truth labels live in an instructor-only directory so they
# are not shipped inline in this student-visible grader. MP_KEY_DIR overrides it
# for a hidden proctored variant.
KEY_DIR = os.environ.get("MP_KEY_DIR") or os.path.join(HERE, "instructor")

PART1_POINTS = 4          # per item (8 dnp3 + 7 mqtt = 15 items * 4 = 60)
PART2_PER_CAPTURE = 15    # per capture, F1-weighted on precision & recall
LABEL_FILES = {           # capture -> ground-truth label file (in KEY_DIR)
    "dnp3_assessment.pcap": "dnp3_assessment.labels.json",
    "mqtt_assessment.pcap": "mqtt_assessment.labels.json",
}

# Actionable hints emitted on a FAILED Part-1 item: point the student at the
# exact field/filter to re-run rather than just "expected X, got Y".
PART1_HINTS = {
    "part1_dnp3": {
        "malicious_frame":
            "tshark -r captures/dnp3_assessment.pcap -Y dnp3 -T fields -e frame.number "
            "-e ip.src -e dnp3.src -e dnp3.al.func  — find the frame whose dnp3.src (link) "
            "is claimed by an ip.src that no other frame with that link uses.",
        "attacker_ip":
            "ip.src of the malicious frame (compare ip.src vs dnp3.src): "
            "-Y dnp3 -T fields -e frame.number -e ip.src -e dnp3.src",
        "forged_link_source":
            "the dnp3.src (data-link source) written into the malicious frame: "
            "-Y dnp3 -T fields -e frame.number -e dnp3.src",
        "genuine_unsolicited_frame":
            "the LEGITIMATE unsolicited response, for contrast (from the real outstation IP): "
            "-Y 'dnp3.al.func==130' -T fields -e frame.number -e ip.src -e dnp3.src",
        "real_outstation_ip":
            "the ip.src that legitimately owns that link address on every other frame: "
            "-Y dnp3 -T fields -e ip.src -e dnp3.src",
        "master_link_addresses":
            "ALL legitimate master link addresses (there is more than one — a set): "
            "-Y dnp3 -T fields -e dnp3.src -e dnp3.dst  (masters poll; note both).",
        "false_breaker_state":
            "the breaker state the spoof CLAIMS vs. what the polls show "
            "(g2 binary change, point 0): open or closed?",
        "attack_technique_ttp":
            "MITRE ATT&CK for ICS technique ID for spoofing a reporting/unsolicited message "
            "(format T0xxx).",
    },
    "part1_mqtt": {
        "anonymous_connect_frame":
            "the rogue CONNECT with no credentials: "
            "-Y 'mqtt.msgtype==1' -T fields -e frame.number -e ip.src -e mqtt.username "
            "(the one with an EMPTY mqtt.username).",
        "connack_return_code":
            "the broker's CONNACK return code to that CONNECT: "
            "-Y 'mqtt.msgtype==2' -T fields -e frame.number -e mqtt.conack.val",
        "injection_frame":
            "the frame that PLANTS a persistent command (retained PUBLISH to a command topic): "
            "-Y 'mqtt.msgtype==3 && mqtt.retain==1' -T fields -e frame.number -e ip.src "
            "-e mqtt.topic",
        "injection_retain_flag":
            "the mqtt.retain flag on that PUBLISH (prints True/False; answer 1 or 0).",
        "leaked_service_username":
            "a service account username in a retained payload delivered to the rogue: "
            "-Y 'mqtt.msgtype==3 && mqtt.retain==1' -T fields -e mqtt.msg  (decode hex).",
        "leaked_hi_setpoint":
            "the numeric high setpoint harvested from a retained config payload "
            "(decode mqtt.msg from hex).",
        "failure_class":
            "authentication or authorization? The rogue WAS accepted (CONNACK 0), so identity "
            "was granted — the failure is that its permissions were not constrained.",
    },
}


# ---------------- key / label loading ----------------
def load_key():
    """Return (key_dict_or_None, source_str)."""
    path = os.path.join(KEY_DIR, "answer_key.json")
    try:
        with open(path) as f:
            k = json.load(f)
        k.pop("_comment", None)
        for sect in k.values():
            if isinstance(sect, dict):
                sect.pop("_comment", None)
        return k, path
    except Exception:
        return None, path


def load_labels(pcap):
    """Return (label_dict_or_None, source_str)."""
    fn = LABEL_FILES.get(pcap)
    if not fn:
        return None, None
    path = os.path.join(KEY_DIR, fn)
    try:
        with open(path) as f:
            return json.load(f), path
    except Exception:
        return None, path


# ---------------- Part 1: exact-match triage ----------------
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


def grade_part1(ans, key):
    got, total, lines = 0, 0, []
    for section in ("part1_dnp3", "part1_mqtt"):
        for field, kv in key[section].items():
            total += PART1_POINTS
            a = ans.get(section, {}).get(field, None)
            ok = a is not None and match(kv, a)
            got += PART1_POINTS if ok else 0
            lines.append(f"  [{'PASS' if ok else 'FAIL'}] {section}.{field:26} "
                         f"expected={kv!r:24} got={a!r}")
            if not ok:
                hint = PART1_HINTS.get(section, {}).get(field)
                if hint:
                    lines.append(f"         hint: {hint}")
    return got, total, lines


# ---------------- Part 2: detector precision & recall ----------------
def parse_alert_frames(out):
    """Extract the set of frame numbers a detector flagged from its stdout.

    Accepts `frame=<n>`, `frame= <n>`, `frame:<n>` with optional whitespace.
    """
    frames = set()
    for m in re.finditer(r"frame\s*[=:]\s*(\d+)", out):
        frames.add(int(m.group(1)))
    return frames


def run_detector_capture(pcap, label):
    """Run the student detector on one capture and score it on precision/recall
    against the ground-truth malicious_frames. Returns (points, list_of_lines)."""
    det = os.path.join(HERE, "detector.py")
    lines = []
    if not os.path.exists(det):
        return 0, [f"  [FAIL] detector.py not found (write it for Part 2)"]
    p = os.path.join(CAP, pcap)
    try:
        proc = subprocess.run([sys.executable, det, p],
                              capture_output=True, text=True, timeout=60)
        out = proc.stdout
    except Exception as e:
        return 0, [f"  [FAIL] detector.py crashed on {pcap}: {e}"]

    flagged = parse_alert_frames(out)

    if label is None:
        # self-check mode: no ground truth. Report shape only, no score.
        shape_ok = bool(flagged)
        lines.append(f"  [{'INFO' if shape_ok else 'FAIL'}] {pcap}: detector emitted "
                     f"{len(flagged)} ALERT frame(s) {sorted(flagged) or '{}'} "
                     f"(no label file — correctness not scored in self-check mode)")
        if not shape_ok:
            lines.append("         hint: print one line per detection as "
                         "`ALERT frame=<n> reason=<...>` — the grader reads the frame= number.")
        return 0, lines

    truth = set(int(x) for x in label.get("malicious_frames", []))
    tp = flagged & truth
    fp = flagged - truth
    fn = truth - flagged
    recall = len(tp) / len(truth) if truth else 0.0
    precision = len(tp) / len(flagged) if flagged else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    pts = round(PART2_PER_CAPTURE * f1)

    status = "PASS" if (fn == set() and fp == set()) else ("PART" if tp else "FAIL")
    lines.append(f"  [{status}] {pcap}: precision={precision:.2f} recall={recall:.2f} "
                 f"F1={f1:.2f} -> {pts}/{PART2_PER_CAPTURE}  "
                 f"(flagged {sorted(flagged) or '{}'}, truth {sorted(truth)})")
    if fn:
        lines.append(f"         hint: MISSED malicious frame(s) {sorted(fn)} — your invariant is "
                     f"too narrow. Re-run: {label.get('_rerun', _rerun_hint(label))}")
    if fp:
        lines.append(f"         hint: FALSE POSITIVE on {sorted(fp)} — you flagged benign frames; "
                     f"tighten the invariant (do not alert on every frame / every message).")
    return pts, lines


def _rerun_hint(label):
    proto = (label.get("protocol") or "").lower()
    if proto == "dnp3":
        return ("tshark -r <pcap> -Y dnp3 -T fields -e frame.number -e ip.src -e dnp3.src "
                "— a link address (dnp3.src) seen from more than one ip.src is impersonation.")
    if proto == "mqtt":
        return ("tshark -r <pcap> -Y mqtt -T fields -e frame.number -e ip.src -e mqtt.msgtype "
                "-e mqtt.username -e mqtt.topic -e mqtt.retain — anon CONNECT then RETAINED "
                "PUBLISH to a command topic from the same client.")
    return "compare the malicious frame's fields against the legitimate ones."


def grade_part2(labels_by_cap):
    got, lines = 0, []
    for pcap in LABEL_FILES:
        pts, ls = run_detector_capture(pcap, labels_by_cap.get(pcap))
        got += pts
        lines.extend(ls)
    return got, lines


def main():
    apath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "submission", "answers.json")
    print("=" * 68)
    print("  MP: ICS Intrusion Analysis — autograder")
    print("=" * 68)

    key, key_src = load_key()
    labels_by_cap = {}
    for pcap in LABEL_FILES:
        lab, _ = load_labels(pcap)
        labels_by_cap[pcap] = lab
    self_check = key is None
    if self_check:
        print(f"\n[self-check mode] no answer key at {key_src} — format/hints only "
              f"(set MP_KEY_DIR or restore mp/instructor/ to score correctness).")

    # Part 3a: valid answers.json (5)
    fmt = 0
    ans = {}
    print(f"\nPart 3 — submission format")
    try:
        with open(apath) as f:
            ans = json.load(f)
        fmt += 5
        print(f"  [PASS] answers.json parses ({apath})")
    except Exception as e:
        print(f"  [FAIL] answers.json missing/invalid: {e}")
        print(f"         hint: copy answers.template.json -> submission/answers.json and fill it.")
    # Part 3b: report present (5)
    report = os.path.join(HERE, "report.md")
    if os.path.exists(report) and os.path.getsize(report) > 0:
        fmt += 5
        print(f"  [PASS] report.md present")
    else:
        print(f"  [FAIL] report.md missing or empty (write your incident report)")

    print("\nPart 1 — manual triage (answers.json)")
    if key is None:
        p1, p1max = 0, 60
        print("  [SKIP] answer key not present — Part 1 not scored (self-check mode).")
    else:
        p1, p1max, lines = grade_part1(ans, key)
        for ln in lines:
            print(ln)

    print("\nPart 2 — detector.py (precision & recall vs. ground-truth labels)")
    p2, p2lines = grade_part2(labels_by_cap)
    for ln in p2lines:
        print(ln)

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
