# -*- coding: utf-8 -*-
"""Generate a consolidated student worksheet and instructor answer key."""
import os
from content_dnp3 import DNP3
from content_mqtt import MQTT

OUT = "/root/icsnpp_kit/lab/worksheets"
os.makedirs(OUT, exist_ok=True)

INTRO = (
    "# ICS/OT Protocol Analysis — {kind}\n\n"
    "Work these exercises with the two teaching captures open in Wireshark "
    "(`dnp3_substation.pcap`, `mqtt_iot_telemetry.pcap`) and the Docker lab running. "
    "Each exercise lists the steps, then the question to answer.{note}\n\n"
    "**Student name / date:** ______________________________\n"
)


def render(modules, answers):
    kind = "Instructor Answer Key" if answers else "Student Worksheet"
    note = "" if answers else "  Record your answers in the space after each question."
    L = [INTRO.format(kind=kind, note=note)]
    qn = 1
    for m in modules:
        L.append(f"\n## {m['protocol']} — {m['title'].split('—')[0].strip()}\n")
        L.append(f"*Capture: `{m['pcap']}`*\n")
        for ex in m["lab"]["exercises"]:
            L.append(f"### Q{qn}. {ex['title']}\n")
            L += [f"{j+1}. {st}" for j, st in enumerate(ex["steps"])]
            L.append(f"\n**Question.** {ex['question']}\n")
            if answers:
                L.append(f"**Answer.** {ex['answer']}\n")
            else:
                L.append("_Answer:_\n\n> \n\n> \n")
            qn += 1
    # a few synthesis questions
    L.append("\n## Synthesis\n")
    syn = [
        ("A classmate reduces both intrusions to one root cause — 'neither protocol authenticates, so the rogue host is trusted.' That is only half right. Using the captures, separate AUTHENTICATION (who are you?) from AUTHORIZATION (are you allowed to do this?). For DNP3 frame 27 and for the MQTT command injection, state (i) whether authentication happened at all, (ii) whether the failure is one of authentication or authorization, and (iii) the exact missing mechanism that would have stopped it. Cite the specific frame(s).",
         "The classmate conflates two different failures. DNP3 (frame 27): there is NO authentication of any kind — the outstation never checks identity; the only 'identity' is a 16-bit link address (here forged to 100, the master's) that any host can write into a frame, so the rogue at 10.20.0.66 simply opens its own session and issues a DIRECT OPERATE (Trip). Authentication failure. Missing mechanism: DNP3 Secure Authentication (SAv5) — a challenge-response MAC on critical function codes — plus source allow-listing. MQTT (frame 52, the PUBLISH to plant/tank1/command — NOT frame 54, which is the rogue's DISCONNECT): authentication DID occur and SUCCEEDED — the rogue authenticated anonymously at CONNECT (frame 38) and the broker accepted it with CONNACK return code 0 (frame 40). The injection is therefore an AUTHORIZATION failure: with no per-topic write ACL, an accepted client may publish to a command topic it should never write. Missing mechanism: a broker write-ACL scoping publish rights per client/topic (and, upstream, allow_anonymous false so the anonymous identity is refused before any topic write). Bottom line: DNP3 fails because identity is never checked; MQTT fails because an accepted identity is never constrained — 'no authentication' describes DNP3, while MQTT's gap is 'no authorization,' and the fixes differ (DNP3-SA vs. broker ACLs)."),
        ("For each protocol, name the standard/control that adds authentication and say whether it also adds confidentiality.",
         "DNP3: Secure Authentication (SAv5 / IEEE 1815-2012) adds authentication + integrity of critical functions but NOT confidentiality (use TLS/VPN for that). MQTT: TLS on 8883 adds confidentiality + protects credentials; authorization still depends on broker-side ACLs, and authentication on broker credentials/certs."),
        ("You can monitor but not immediately re-engineer these systems. Give one Zeek/ICSNPP-based detection for each capture.",
         "DNP3: alert on any dnp3_control.log control (SELECT/OPERATE/DIRECT_OPERATE) whose source host is not the sanctioned master. MQTT: alert on mqtt_connect.log connects with empty credentials/anonymous, or mqtt_subscribe.log subscriptions to '#'."),
    ]
    for q, a in syn:
        L.append(f"### Q{qn}.\n{q}\n")
        if answers:
            L.append(f"**Answer.** {a}\n")
        else:
            L.append("_Answer:_\n\n> \n\n> \n")
        qn += 1
    return "\n".join(L)


if __name__ == "__main__":
    for answers, fn in [(False, "student_worksheet.md"), (True, "instructor_answer_key.md")]:
        md = render([DNP3, MQTT], answers)
        with open(os.path.join(OUT, fn), "w") as fh:
            fh.write(md)
        print("wrote", fn, len(md), "chars")
