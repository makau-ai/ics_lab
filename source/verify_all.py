# -*- coding: utf-8 -*-
"""verify_all.py — reproducible formal-verification pass over the whole kit.

Checks, all programmatically:
  A. Frame counts of every shipped capture.
  B. DNP3 data-link CRC-16/DNP over every DNP3 frame (header CRC + each data-block CRC).
  C. Documented frames (content_dnp3 / content_mqtt) exist in their pcap.
  D. Curriculum command outputs (content_levels) match the embedded 'expect' values.
  E. The MP autograder: 100/100 against the solution, 10/100 against the blank student copy.

Run:  cd build && python3 verify_all.py
Exit code 0 == everything passed.
"""
import json
import os
import re
import shutil
import subprocess
import sys

from scapy.all import rdpcap, Raw, TCP

# Resolve paths relative to this script so it runs from build/ (dev) or source/ (shipped kit).
HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)          # kit root = parent of build/ or source/
PCAPS = os.path.join(KIT, "pcaps")
MP = os.path.join(KIT, "mp")

sys.path.insert(0, HERE)             # content_dnp3/content_mqtt sit next to this script
from content_dnp3 import DNP3
from content_mqtt import MQTT

results = []      # (section, name, ok, detail)


def check(section, name, ok, detail=""):
    results.append((section, name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))


def tsh(pcap, args):
    out = subprocess.run(["tshark", "-r", pcap] + args, capture_output=True, text=True)
    return out.stdout


# ----------------------------------------------------------- CRC-16/DNP (0x3D65)
def crc_dnp(data: bytes) -> int:
    """DNP3 data-link CRC: reflected, poly 0x3D65, init 0, xorout 0xFFFF.
    Verifies as check(b'123456789') == 0xEA82."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC   # reflected 0x3D65
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def dnp3_crc_audit(pcap_path):
    """Return (frames, crcs_checked, crcs_ok). Recomputes header + block CRCs."""
    pkts = rdpcap(pcap_path)
    frames = crcs = ok = 0
    for p in pkts:
        if Raw not in p:
            continue
        pl = bytes(p[Raw].load)
        if len(pl) < 10 or pl[0] != 0x05 or pl[1] != 0x64:
            continue
        frames += 1
        # header: 8 bytes + 2-byte CRC (little-endian)
        hdr, hdr_crc = pl[0:8], int.from_bytes(pl[8:10], "little")
        crcs += 1
        if crc_dnp(hdr) == hdr_crc:
            ok += 1
        # user data blocks: LEN counts ctrl+addr(5) + user data
        length = pl[2]
        udl = max(0, length - 5)
        idx = 10
        remaining = udl
        while remaining > 0 and idx + 2 <= len(pl):
            blk = min(16, remaining)
            if idx + blk + 2 > len(pl):
                break
            data = pl[idx:idx + blk]
            blk_crc = int.from_bytes(pl[idx + blk:idx + blk + 2], "little")
            crcs += 1
            if crc_dnp(data) == blk_crc:
                ok += 1
            idx += blk + 2
            remaining -= blk
    return frames, crcs, ok


# ============================================================ A. frame counts
print("\nA. Capture frame counts (EXACT — a regenerated/corrupted capture fails loudly)")
# Ground truth verified by reading the pcaps with scapy (2026-08-14). These are HARD
# assertions: n must equal the expected value, not merely be > 0. The previous CAPS
# dict was dead code (never referenced) and stale (33 vs the actual 37), so Section A
# only ever enforced n>0 — see review_3 (Data Scientist) / PANEL_REVIEW P2 item 11.
EXPECTED_FRAMES = {
    "dnp3_substation.pcap": 37,
    "mqtt_iot_telemetry.pcap": 61,
    "dnp3_assessment.pcap": 30,
    "mqtt_assessment.pcap": 66,
}
counts = {}
for rel, want in EXPECTED_FRAMES.items():
    path = os.path.join(PCAPS, rel)
    n = len(rdpcap(path))
    counts[rel] = n
    check("A", f"{rel} == {want} frames (exact)", n == want,
          f"{n} frames" if n == want else f"got {n}, expected {want}")

# self-test the CRC routine on the standard check vector
check("A", "CRC-16/DNP self-test check('123456789')==0xEA82",
      crc_dnp(b"123456789") == 0xEA82, hex(crc_dnp(b"123456789")))

# ============================================================ B. DNP3 CRCs
print("\nB. DNP3 data-link CRC audit (recomputed over raw bytes)")
crc_total = crc_ok = 0
for rel in ["dnp3_substation.pcap", "dnp3_assessment.pcap"]:
    fr, c, o = dnp3_crc_audit(os.path.join(PCAPS, rel))
    crc_total += c
    crc_ok += o
    check("B", f"{rel}: {o}/{c} CRCs valid across {fr} DNP3 frames", o == c and c > 0,
          f"{o}/{c}")
check("B", f"ALL DNP3 CRCs valid ({crc_ok}/{crc_total})", crc_ok == crc_total and crc_total > 0,
      f"{crc_ok}/{crc_total}")


# property-based assertion (not a fixed-value one): over random subsets of the DNP3 frames,
# EVERY recomputed data-link CRC (header + each data block) must equal the CRC stored on the
# wire. This is a genuine invariant check — "∀ frame f in capture: recompute(f)==stored(f)" —
# exercised against random samples rather than asserting a single literal total.
import random


def dnp3_crc_property(pcap_path, trials=250, seed=1815):
    rnd = random.Random(seed)
    frames = []
    for p in rdpcap(pcap_path):
        if Raw not in p:
            continue
        pl = bytes(p[Raw].load)
        if len(pl) >= 10 and pl[0] == 0x05 and pl[1] == 0x64:
            frames.append(pl)
    if not frames:
        return False, 0
    checked = 0
    for _ in range(trials):
        pl = rnd.choice(frames)
        # header CRC
        if crc_dnp(pl[0:8]) != int.from_bytes(pl[8:10], "little"):
            return False, checked
        checked += 1
        # every data-block CRC in the sampled frame
        udl = max(0, pl[2] - 5)
        idx, remaining = 10, udl
        while remaining > 0 and idx + 2 <= len(pl):
            blk = min(16, remaining)
            if idx + blk + 2 > len(pl):
                break
            if crc_dnp(pl[idx:idx + blk]) != int.from_bytes(pl[idx + blk:idx + blk + 2], "little"):
                return False, checked
            checked += 1
            idx += blk + 2
            remaining -= blk
    return True, checked


prop_ok = True
prop_checked = 0
for rel in ["dnp3_substation.pcap", "dnp3_assessment.pcap"]:
    ok, nch = dnp3_crc_property(os.path.join(PCAPS, rel))
    prop_ok = prop_ok and ok
    prop_checked += nch
check("B", f"PROPERTY: ∀ random DNP3 frame, recomputed CRC == stored CRC ({prop_checked} samples)",
      prop_ok, f"{prop_checked} CRC recomputations, 0 mismatches" if prop_ok else "MISMATCH found")

# ============================================================ C. documented frames exist
print("\nC. Documented frames exist in their capture")
for mod in (DNP3, MQTT):
    path = os.path.join(PCAPS, mod["pcap"])
    total = len(rdpcap(path))
    doc = [f["n"] for f in mod["frames"]]
    bad = [n for n in doc if n < 1 or n > total]
    check("C", f'{mod["id"]}: {len(doc)} documented frames within 1..{total}', not bad,
          f'out-of-range={bad}' if bad else f'{len(doc)} frames ok')

# machine-readable ground-truth label files parse, carry the required schema, and every
# labelled malicious frame is a real frame in its capture (bridge from pcap -> detector).
LABEL_SCHEMA = ("capture", "protocol", "malicious_frames", "attacker_ip",
                "forged_link", "ttp", "benign_frames_summary")
for rel, labelname in [("dnp3_substation.pcap", "dnp3_substation.labels.json"),
                       ("mqtt_iot_telemetry.pcap", "mqtt_iot_telemetry.labels.json")]:
    lp = os.path.join(PCAPS, labelname)
    total = len(rdpcap(os.path.join(PCAPS, rel)))
    try:
        lab = json.load(open(lp))
        mf = lab["malicious_frames"]
        schema_ok = all(k in lab for k in LABEL_SCHEMA)
        in_range = bool(mf) and all(isinstance(n, int) and 1 <= n <= total for n in mf)
        check("C", f"{labelname}: schema ok, {len(mf)} malicious frames within 1..{total}",
              schema_ok and in_range,
              "ok" if schema_ok and in_range else f"schema_ok={schema_ok} frames={mf}")
    except Exception as e:  # noqa: BLE001
        check("C", f"{labelname}: parses & validates", False, f"{type(e).__name__}: {e}")

# ============================================================ D. curriculum outputs
print("\nD. Curriculum commands reproduce their documented 'expect' values")

# D1 MQTT endpoints: broker 10.10.20.10 busiest at 61
ep = tsh(os.path.join(PCAPS, "mqtt_iot_telemetry.pcap"), ["-q", "-z", "endpoints,ip"])
check("D", "MQTT broker 10.10.20.10 present & 61 pkts",
      "10.10.20.10" in ep and re.search(r"10\.10\.20\.10\s+61", ep) is not None)

# D2 MQTT msgtype histogram
mt = tsh(os.path.join(PCAPS, "mqtt_iot_telemetry.pcap"),
         ["-Y", "mqtt", "-T", "fields", "-e", "mqtt.msgtype"])
from collections import Counter
mc = Counter(x for x in mt.split() if x)
exp_mqtt = {"1": 3, "2": 3, "3": 8, "4": 2, "8": 2, "9": 2, "12": 1, "13": 1, "14": 1}
check("D", "MQTT msgtype counts (3/3/8/2/2/2/1/1/1)", all(mc.get(k) == v for k, v in exp_mqtt.items()),
      dict(mc))

# D3 DNP3 func histogram
df = tsh(os.path.join(PCAPS, "dnp3_substation.pcap"),
         ["-Y", "dnp3", "-T", "fields", "-e", "dnp3.al.func"])
dc = Counter(x for x in df.split() if x)
exp_dnp = {"0": 1, "1": 2, "3": 1, "4": 1, "5": 1, "13": 1, "129": 6, "130": 1}
check("D", "DNP3 func counts (READx2,SEL,OP,DOP,CR,RESPx6,UNSOL,CONF)",
      all(dc.get(k) == v for k, v in exp_dnp.items()), dict(dc))

# D4 Level-3 comma-syntax filter works and returns frames 16,20,27
l3 = tsh(os.path.join(PCAPS, "dnp3_substation.pcap"),
         ["-Y", "dnp3.al.func in {3,4,5}", "-T", "fields", "-e", "frame.number",
          "-e", "ip.src", "-e", "dnp3.src"])
l3f = [ln.split("\t")[0] for ln in l3.strip().splitlines() if ln.strip()]
check("D", "L3 filter 'in {3,4,5}' → frames 16,20,27", l3f == ["16", "20", "27"], l3f)

# D5 Level-4 anonymous MQTT connect is frame 38, mqtt-explorer-x
an = tsh(os.path.join(PCAPS, "mqtt_iot_telemetry.pcap"),
         ["-Y", "mqtt.msgtype==1 && !mqtt.username", "-T", "fields",
          "-e", "frame.number", "-e", "mqtt.clientid"])
check("D", "L4 anonymous CONNECT → frame 38 (mqtt-explorer-x)",
      an.strip().startswith("38") and "mqtt-explorer-x" in an, an.strip())

# D6 Level-4 DNP3 rogue trip+restart from 10.20.0.66
rg = tsh(os.path.join(PCAPS, "dnp3_substation.pcap"),
         ["-Y", "dnp3.al.func==5 || dnp3.al.func==13", "-T", "fields",
          "-e", "frame.number", "-e", "ip.src", "-e", "dnp3.src"])
rows = [ln.split("\t") for ln in rg.strip().splitlines() if ln.strip()]
check("D", "L4 rogue DOP+COLD_RESTART from 10.20.0.66 (link forged 100)",
      len(rows) == 2 and all(r[1] == "10.20.0.66" and r[2] == "100" for r in rows), rg.strip().replace("\n", " | "))

# ============================================================ E. autograder
print("\nE. MP autograder")
subm = os.path.join(MP, "submission", "answers.json")
det = os.path.join(MP, "detector.py")
sol_ans = os.path.join(MP, "solution", "answers.solution.json")
sol_det = os.path.join(MP, "solution", "detector.py")

# back up shipped student files
bak_ans = subm + ".bak"
bak_det = det + ".bak"
shutil.copy(subm, bak_ans)
shutil.copy(det, bak_det)
try:
    # blank student copy → expect 10
    out_blank = subprocess.run(["python3", "grade.py"], cwd=MP, capture_output=True, text=True).stdout
    m_blank = re.search(r"TOTAL:\s+(\d+)\s*/\s*100", out_blank)
    check("E", "blank student copy scores 10/100 (Part-3 format only)",
          bool(m_blank) and m_blank.group(1) == "10", m_blank.group(0) if m_blank else "no score")

    # solution copy → expect 100
    shutil.copy(sol_ans, subm)
    shutil.copy(sol_det, det)
    out_sol = subprocess.run(["python3", "grade.py"], cwd=MP, capture_output=True, text=True).stdout
    m_sol = re.search(r"TOTAL:\s+(\d+)\s*/\s*100", out_sol)
    check("E", "solution scores 100/100 (Mastery)",
          bool(m_sol) and m_sol.group(1) == "100", m_sol.group(0) if m_sol else "no score")
finally:
    # restore shipped student files no matter what
    shutil.move(bak_ans, subm)
    shutil.move(bak_det, det)

# ============================================================ summary
print("\n" + "=" * 60)
passed = sum(1 for *_, ok, _ in [(r[0], r[1], r[2], r[3]) for r in results] if ok)
total = len(results)
by_sec = {}
for sec, name, ok, _ in results:
    d = by_sec.setdefault(sec, [0, 0])
    d[1] += 1
    if ok:
        d[0] += 1
for sec in sorted(by_sec):
    p, t = by_sec[sec]
    print(f"  Section {sec}: {p}/{t}")
print(f"  TOTAL: {passed}/{total} checks passed")
print("=" * 60)
# emit machine-readable line for the doc
print("VERIFY_JSON " + json.dumps({
    "passed": passed, "total": total,
    "crc_ok": crc_ok, "crc_total": crc_total,
    "counts": counts,
    "by_section": {k: by_sec[k] for k in by_sec},
}))
sys.exit(0 if passed == total else 1)
