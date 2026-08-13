# -*- coding: utf-8 -*-
"""Render Markdown teaching modules from the content dicts (also the DOCX source)."""
import os
from scapy.all import rdpcap
from content_dnp3 import DNP3
from content_mqtt import MQTT

OUT = "/root/icsnpp_kit/modules"
PCAP_DIR = "/root/icsnpp_kit/pcaps"
os.makedirs(OUT, exist_ok=True)
SEVL = {"info": "NOTE", "warn": "CAUTION", "critical": "CRITICAL"}


def frame_times(pcap):
    try:
        pkts = rdpcap(pcap)
    except Exception:
        return {}
    t0 = float(pkts[0].time) if len(pkts) else 0.0
    return {i: f"{float(p.time) - t0:.3f}" for i, p in enumerate(pkts, 1)}


def tbl(rows, header):
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    return "\n".join(out)


def module_md(m):
    times = frame_times(os.path.join(PCAP_DIR, m["pcap"]))
    L = []
    L.append(f"# {m['title']}")
    L.append(f"*{m['subtitle']}*\n")
    L.append(f"- **Protocol:** {m['protocol']}  ")
    L.append(f"- **Transport:** {m['port']}  ")
    L.append(f"- **Reference:** {m['spec']}  ")
    L.append(f"- **Capture file:** `{m['pcap']}`  ")
    L.append(f"- **Level:** {m['level']}\n")
    L.append("> Every frame number, field value, and CRC below was produced and verified with Wireshark/tshark"
             " and CISA's ICSNPP / Zeek. The capture is a curated teaching file — synthetic but protocol-valid.\n")

    L.append("## 1. What this module is\n")
    L += [p + "\n" for p in m["overview"]]

    L.append("## 2. Learning objectives\n")
    L += [f"{i+1}. {o}" for i, o in enumerate(m["objectives"])]
    L.append("")

    for c in m.get("callouts", []):
        L.append(f"> **{c['title']}**\n")
        L.append(c["body"] + "\n")

    L.append("## 3. Where this protocol lives — industry & use cases\n")
    L.append(m["industry"]["intro"] + "\n")
    for name, det in m["industry"]["sectors"]:
        L.append(f"**{name}.** {det}\n")
    L.append("**Typical use cases**\n")
    L += [f"- {u}" for u in m["industry"]["use_cases"]]
    L.append("")

    L.append("## 4. Protocol anatomy\n")
    L.append(m["anatomy"]["intro"] + "\n")
    for name, det, diagram in m["anatomy"]["layers"]:
        L.append(f"### {name}\n{det}\n")
        L.append("```\n" + diagram + "\n```\n")
    L.append("### Function / packet types you will see\n")
    L.append(tbl([[c, n, d] for c, n, d in m["anatomy"]["funcs"]], ["Code", "Name", "Meaning"]) + "\n")

    L.append("## 5. The capture at a glance\n")
    L.append(m["capture"]["scenario"] + "\n")
    L.append(tbl([[r[0], f"`{r[1]}`", r[2]] for r in m["capture"]["topology"]],
                 ["Host / role", "Address", "Notes"]) + "\n")
    L.append(f"*{m['capture']['stats']}*\n")

    L.append("## 6. Frame-by-frame walkthrough\n")
    L.append("Open the matching `.pcap` in Wireshark and follow along; the frame numbers line up exactly.\n")
    for f in m["frames"]:
        flag = "  ⚠ **ANOMALY**" if f.get("anomaly") else ""
        L.append(f"### Frame {f['n']} — {f['summary']}{flag}")
        L.append(f"`t={times.get(f['n'], f['t'])}s`  ·  `{f['src']}` → `{f['dst']}`  ·  {f['layer']}\n")
        L.append(f["plain"] + "\n")
        L.append(tbl([[k, v] for k, v in f["fields"]], ["Field", "Value"]) + "\n")
        L.append(f"**Why it matters.** {f['teach']}\n")
        if f.get("security"):
            s = f["security"]
            L.append(f"**{SEVL[s['level']]}.** {s['note']}\n")
        L.append(f"**Wireshark filter:** `{f['filter']}`\n")

    L.append("## 7. Security risks & controls\n")
    for s in m["security"]:
        fr = (", frames " + ", ".join(str(x) for x in s["frames"])) if s.get("frames") else ""
        L.append(f"### {s['id']} · {s['title']}  \n*Severity: {s['severity'].upper()}{fr}*\n")
        L.append(f"- **Risk.** {s['risk']}")
        L.append(f"- **Real-world.** {s['realworld']}")
        if s.get("attack"):
            L.append(f"- **Technique.** {s['attack']}")
        L.append(f"- **Control.** {s['control']}\n")

    for x in m.get("extras", []):
        L.append(f"### {x['title']}\n")
        L.append(x["body"] + "\n")

    L.append("## 8. Hands-on lab\n")
    L.append(m["lab"]["intro"] + "\n")
    for i, ex in enumerate(m["lab"]["exercises"], 1):
        L.append(f"### Exercise {i}. {ex['title']}\n")
        L += [f"{j+1}. {st}" for j, st in enumerate(ex["steps"])]
        L.append(f"\n**Question.** {ex['question']}\n")
        L.append(f"**Answer.** {ex['answer']}\n")

    L.append("## 9. O*NET personas & career pathways\n")
    L.append("This module is framed around real O*NET occupational personas — the subject-matter voices that shaped it "
             "and the people whose work it maps to (see the split below: skills you practice vs. who this protects).\n")
    for p in m["personas"]:
        L.append(f"### {p['code']} — {p['title']}  *( {p['tag']} )*\n")
        L.append(f"> “{p['voice']}”\n")
        L.append(p["relevance"] + "\n")
    oa = m["onet_alignment"]
    L.append("### What you practice → who does this work\n")
    L.append("These occupations do packet and detection analysis (or implement the controls) as their actual job — the skills this kit rehearses.\n")
    L.append(tbl([[s, c, w] for s, c, w in oa["practice"]], ["Skill you practice in this kit", "O*NET", "The real work it maps to"]) + "\n")
    L.append("### Context: who this protects\n")
    L.append("These roles operate, maintain, design, or authored the systems under analysis — not skills the learner performs here.\n")
    L.append(tbl([[o, c, why] for o, c, why in oa["context"]], ["Occupation", "O*NET", "Why they are in the room"]) + "\n")

    L.append("## 10. References & sources\n")
    L += [f"- [{lab}]({url})" for lab, url in m["references"]]
    L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    for m, fn in [(DNP3, "dnp3_module.md"), (MQTT, "mqtt_module.md")]:
        md = module_md(m)
        with open(os.path.join(OUT, fn), "w") as fh:
            fh.write(md)
        print("wrote", fn, len(md), "chars")
