# -*- coding: utf-8 -*-
"""Generate a consolidated student worksheet and instructor answer key.

The worksheet steps use the same **Read / Do / Check** model as the curriculum
(see build/content_levels.py and build/build_curriculum.py's step_html, and the
lab runner lab/lab):

  * Read  — background/why, a bolded ``**Read.**`` / ``> **Read** —`` lead-in with
            no action in it.
  * Do    — exactly one action. ``**Do · Type**`` shows a terminal command in a
            fenced code block; ``**Do · Click**`` gives the exact GUI path.
  * Check — the expected result ("you should see …; if not, run ``lab reset``").

Read and Do are never blended, each Do has exactly one action, and every Do is
followed by a Check. The ``lab`` runner's short tokens (``lN``) cover the
*curriculum* only, so these docs lean on the Copy button / Ctrl+Cmd+Shift+V
paste-backup (reminded once, in the intro) rather than inventing tokens.
"""
import os
from content_dnp3 import DNP3
from content_mqtt import MQTT

OUT = "/root/icsnpp_kit/lab/worksheets"
os.makedirs(OUT, exist_ok=True)


# The lab does not expose a bare `zeek` binary at `/pcaps/...`. The kit root is
# mounted at `/kit` inside the Zeek container and Zeek+ICSNPP runs through the
# `zeek` compose service and its `run-zeek` wrapper (see lab/README.md "Analyze
# with Zeek + CISA ICSNPP" and lab/zeek/run-zeek.sh). The exercise steps in
# content_dnp3.py / content_mqtt.py are authored with the wrong `zeek -C -r
# /pcaps/...` invocation; we derive the real command from each module's own pcap
# so the generated worksheets match how the lab actually runs.
def zeek_cmd_for(pcap):
    """The real Zeek + CISA ICSNPP invocation for a capture, run from ``lab/``."""
    return "docker compose --profile tools run --rm zeek run-zeek /kit/pcaps/%s" % pcap


INTRO = (
    "# ICS/OT Protocol Analysis — {kind}\n\n"
    "Work these exercises with the two teaching captures open in Wireshark "
    "(`dnp3_substation.pcap`, `mqtt_iot_telemetry.pcap`) and the Docker lab running. "
    "Each exercise follows the same **Read → Do → Check** rhythm: a short **Read** sets up "
    "the *why*, each **Do · Type** / **Do · Click** is one action to perform, and the "
    "**Check** tells you what you should see.{note}\n\n"
    "> **Environment** — The lab desktop on port **6080** opens **straight to the desktop — "
    "no password** — with Wireshark already capturing on `lo`. (If a VNC prompt ever appears, "
    "it's `vscode`.) Terminal commands copy with the **Copy** button on each code block, or "
    "paste with **Ctrl/Cmd+Shift+V** (the paste-backup).\n\n"
    "**Student name / date:** ______________________________\n"
)


# ---------------------------------------------------------------- Read/Do/Check content
# Authored Read lead-ins + Do/Check steps per exercise, keyed by (protocol, title).
# question/answer are still pulled live from the content modules so the instructor
# key stays exact; only the *step framing* is reformatted here. A `type` step whose
# command is Zeek carries {"zeek": True} and is filled from the module's own pcap.
BLOCKS = {
    ("DNP3", "Find the control lifecycle"): {
        "read":
            "DNP3 moves physical equipment with a tiny set of control function codes: a supervised "
            "**SELECT (3)** then **OPERATE (4)**, or a one-step **DIRECT OPERATE (5)**. A legitimate "
            "control shows the SELECT→OPERATE shape and comes from the master; a lone DIRECT OPERATE, "
            "or a control from any other host, is a red flag. Here you isolate every control frame and "
            "separate the real pair from the injected trip.",
        "dos": [
            {"kind": "click",
             "text": "In Wireshark, choose **File ▸ Open** and load `dnp3_substation.pcap`.",
             "check": "you should see the packet list fill with the 37-frame master↔outstation session; "
                      "if it stays empty, run `lab reset` and reopen the file."},
            {"kind": "click",
             "text": "In Wireshark's green display-filter bar, type `dnp3.al.func in {3,4,5}` and press Enter.",
             "check": "you should see only the control frames — one SELECT, one OPERATE, and one "
                      "DIRECT OPERATE; if the list is empty, clear the bar and retype the filter, or run `lab reset`."},
        ],
    },
    ("DNP3", "Spot the impostor by address"): {
        "read":
            "In DNP3 the **IP source** and the **DNP3 link source address** are two different identities "
            "in the same frame — and nothing forces them to agree. The master is IP 10.20.0.5 / link "
            "address 100; the outstation is link address 10. An attacker can forge the link address while "
            "its real IP shows through, so exposing both as columns lets you catch the frame where they disagree.",
        "dos": [
            {"kind": "click",
             "text": "In the display-filter bar, type `dnp3` and press Enter.",
             "check": "you should see every DNP3 frame in the capture; if not, run `lab reset`."},
            {"kind": "click",
             "text": "Click a control frame, expand the detail pane, right-click the **ip.src** field ▸ "
                     "**Apply as Column**, then do the same for the DNP3 link source **dnp3.src**.",
             "check": "you should see two new columns, `ip.src` and `dnp3.src`, in the packet list; "
                      "if a column is missing, right-click its field and re-apply."},
        ],
    },
    ("DNP3", "Turn packets into detections with ICSNPP"): {
        "read":
            "Reading frames by eye does not scale. Zeek with CISA's ICSNPP DNP3 parser turns the capture "
            "into structured, greppable logs — `dnp3_control.log` (every control with its operation and "
            "status) and `dnp3_objects.log`. The kit root is mounted at `/kit` inside the Zeek container, "
            "so the capture lives at `/kit/pcaps/...`.",
        "dos": [
            {"kind": "type", "zeek": True,
             "text": "From `lab/`, run Zeek + CISA ICSNPP over the capture:",
             "check": "you should see Zeek write its logs with no error (look for `dnp3_control.log` and "
                      "`dnp3_objects.log`); if it errors, run `lab reset` and retry."},
            {"kind": "click",
             "text": "Open `dnp3_control.log` and `dnp3_objects.log` in VS Code (Explorer ▸ the generated "
                     "Zeek output folder).",
             "check": "you should see one row per control, each with a source host and a status; "
                      "if the files are empty, re-run the Zeek command above."},
        ],
    },
    ("DNP3", "Design the control"): {
        "read":
            "Not every fix is available today. DNP3 Secure Authentication (SAv5) is the durable answer, but "
            "it needs new outstation firmware. Before that lands, compensating controls — segmentation, an "
            "OT-firewall source allow-list on TCP/20000, and a Zeek+ICSNPP sensor — cut the frame-27 risk "
            "this week.",
        "dos": [
            {"kind": "click",
             "text": "Open the DNP3 module page (`modules/dnp3_module.html`) ▸ **Security & Controls** and "
                     "re-read findings **D1** and **D3**.",
             "check": "you should see D1 (no authentication on control commands) and D3 (source spoofing / "
                      "command injection); if the page won't open, use the curriculum hub's module link."},
        ],
    },

    ("MQTT", "Read a password off the wire"): {
        "read":
            "MQTT authenticates inside the **CONNECT** packet — and on plain 1883 it travels in cleartext. "
            "If you can capture the CONNECT you can read the client's username and password with no "
            "cryptography at all. Here you pull the HMI's credentials straight off the wire.",
        "dos": [
            {"kind": "click",
             "text": "In Wireshark, choose **File ▸ Open** and load `mqtt_iot_telemetry.pcap`.",
             "check": "you should see the packet list fill with the MQTT session; if it stays empty, run "
                      "`lab reset` and reopen."},
            {"kind": "click",
             "text": "In the display-filter bar, type `mqtt.msgtype==1` and press Enter to isolate the CONNECT packets.",
             "check": "you should see only the CONNECT frames; if the list is empty, retype the filter or run `lab reset`."},
            {"kind": "click",
             "text": "Click **frame 4**, then in the detail pane expand **MQ Telemetry Transport ▸ Connect Command** "
                     "and read the User Name and Password fields.",
             "check": "you should see the HMI's username and password in cleartext; if the detail pane is blank, "
                      "click the frame first."},
        ],
    },
    ("MQTT", "Trace one message to two subscribers"): {
        "read":
            "The broker fans a single PUBLISH out to every subscriber of that topic. When an unauthorized "
            "subscriber is present, one sensor reading is delivered twice — once to the legitimate HMI and "
            "once to the eavesdropper. Following a single publish through the broker exposes the leak.",
        "dos": [
            {"kind": "click",
             "text": "In the display-filter bar, type `mqtt.msgtype==3` and press Enter to show every PUBLISH.",
             "check": "you should see only PUBLISH frames; if empty, retype the filter or run `lab reset`."},
            {"kind": "click",
             "text": "Select the sensor's publish at **frame 46**, read its topic, then scan the following "
                     "frames for the same reading leaving the broker.",
             "check": "you should see the broker re-deliver that reading to two different destinations; "
                      "if frame 46 isn't a PUBLISH, re-check the filter."},
        ],
    },
    ("MQTT", "Catch the anonymous intruder"): {
        "read":
            "A broker that allows anonymous access will accept a CONNECT with no username or password. The "
            "tell is in the CONNECT **connect-flags** — and the broker's own logs, not Zeek's connect log, "
            "are where you confirm it, because Zeek never records credentials.",
        "dos": [
            {"kind": "click",
             "text": "In the display-filter bar, type `mqtt.msgtype==1` and press Enter.",
             "check": "you should see only the three CONNECT frames (4, 15, 38); if empty, retype the filter."},
            {"kind": "click",
             "text": "Click frames 4, 15, and 38 in turn and expand **Connect Command ▸ Connect Flags** to "
                     "compare the Username/Password flags.",
             "check": "you should be able to read each frame's Username Flag and Password Flag; if the detail "
                      "pane is blank, click the frame first."},
            {"kind": "type", "zeek": True,
             "text": "From `lab/`, run Zeek + CISA ICSNPP over the MQTT capture:",
             "check": "you should see Zeek write `mqtt_connect.log` (and the other `mqtt_*.log`) with no error; "
                      "if it fails, run `lab reset` and retry."},
            {"kind": "click",
             "text": "Open `mqtt_connect.log` in VS Code and read the `client_id` and `connect_status` columns.",
             "check": "you should see a row per CONNECT with a client_id but no credential column; "
                      "if the file is empty, re-run the Zeek command."},
        ],
    },
    ("MQTT", "Harden the broker"): {
        "read":
            "The fix for anonymous access and topic over-sharing is broker configuration: turn off anonymous "
            "logins, require a password file, and scope each client with an ACL. After the broker reloads, "
            "the rogue's CONNECT is refused and the leaked-telemetry frames disappear.",
        "dos": [
            {"kind": "click",
             "text": "In VS Code, open the lab's `mosquitto.conf` and set `allow_anonymous false`, add a "
                     "`password_file`, and add an `acl_file` that scopes the HMI to `read plant/+/telemetry`.",
             "check": "you should see the three directives saved in `mosquitto.conf`; if the file won't save, "
                      "check you opened the copy under `lab/`."},
            {"kind": "type", "cmd": "lab reset",
             "text": "Restart the loopback lab so the broker reloads `mosquitto.conf`:",
             "check": "you should see the broker (1883) and outstation (20000) come back up; if it hangs, "
                      "run `lab reset` again."},
            {"kind": "readnote",
             "text": "Now re-run the publisher, the subscriber, and a `#` subscriber (the exact client "
                     "commands are in `lab/README.md`): the anonymous CONNECT is now refused with CONNACK "
                     "return code 5 (Not Authorized) and the leaked-telemetry frames are gone."},
        ],
    },
}


def render_do(do, m):
    """Render one Do block (+ its Check) as Markdown."""
    kind = do["kind"]
    if kind == "readnote":
        return "> **Read** — " + do["text"]
    if kind == "type":
        cmd = zeek_cmd_for(m["pcap"]) if do.get("zeek") else do["cmd"]
        return ("**Do · Type** — " + do["text"] + "\n\n"
                "```\n" + cmd + "\n```\n\n"
                "**Check —** " + do["check"])
    # click
    return "**Do · Click** — " + do["text"] + "\n\n**Check —** " + do["check"]


def render_exercise(m, ex, qn, answers):
    protocol = m["protocol"]
    L = ["### Q%d. %s\n" % (qn, ex["title"])]
    blk = BLOCKS.get((protocol, ex["title"]))
    if blk:
        L.append("> **Read** — " + blk["read"] + "\n")
        for do in blk["dos"]:
            L.append(render_do(do, m) + "\n")
    else:
        # Fallback: keep the raw steps working even if an exercise is added/renamed.
        L.append("> **Read** — Work through the steps below, then answer the question.\n")
        for st in ex["steps"]:
            L.append("**Do · Click** — " + st + "\n\n"
                     "**Check —** you should see the capture respond to the step above; "
                     "if not, run `lab reset` and retry.\n")
    L.append("**Question.** " + ex["question"] + "\n")
    if answers:
        L.append("**Answer.** " + ex["answer"] + "\n")
    else:
        L.append("_Answer:_\n\n> \n\n> \n")
    return "\n".join(L)


def render(modules, answers):
    kind = "Instructor Answer Key" if answers else "Student Worksheet"
    note = "" if answers else "  Record your answers in the space after each question."
    L = [INTRO.format(kind=kind, note=note)]
    qn = 1
    for m in modules:
        L.append("\n## %s — %s\n" % (m["protocol"], m["title"].split("—")[0].strip()))
        L.append("*Capture: `%s`*\n" % m["pcap"])
        for ex in m["lab"]["exercises"]:
            L.append(render_exercise(m, ex, qn, answers))
            qn += 1

    # a few synthesis questions
    L.append("\n## Synthesis\n")
    L.append("> **Read** — These pull the two captures together. There are no new commands to run — "
             "reason from the evidence you have already gathered.\n")
    syn = [
        ("A classmate reduces both intrusions to one root cause — 'neither protocol authenticates, so the rogue host is trusted.' That is only half right. Using the captures, separate AUTHENTICATION (who are you?) from AUTHORIZATION (are you allowed to do this?). For DNP3 frame 27 and for the MQTT command injection, state (i) whether authentication happened at all, (ii) whether the failure is one of authentication or authorization, and (iii) the exact missing mechanism that would have stopped it. Cite the specific frame(s).",
         "The classmate conflates two different failures. DNP3 (frame 27): there is NO authentication of any kind — the outstation never checks identity; the only 'identity' is a 16-bit link address (here forged to 100, the master's) that any host can write into a frame, so the rogue at 10.20.0.66 simply opens its own session and issues a DIRECT OPERATE (Trip). Authentication failure. Missing mechanism: DNP3 Secure Authentication (SAv5) — a challenge-response MAC on critical function codes — plus source allow-listing. MQTT (frame 52, the PUBLISH to plant/tank1/command — NOT frame 54, which is the rogue's DISCONNECT): authentication DID occur and SUCCEEDED — the rogue authenticated anonymously at CONNECT (frame 38) and the broker accepted it with CONNACK return code 0 (frame 40). The injection is therefore an AUTHORIZATION failure: with no per-topic write ACL, an accepted client may publish to a command topic it should never write. Missing mechanism: a broker write-ACL scoping publish rights per client/topic (and, upstream, allow_anonymous false so the anonymous identity is refused before any topic write). Bottom line: DNP3 fails because identity is never checked; MQTT fails because an accepted identity is never constrained — 'no authentication' describes DNP3, while MQTT's gap is 'no authorization,' and the fixes differ (DNP3-SA vs. broker ACLs)."),
        ("For each protocol, name the standard/control that adds authentication and say whether it also adds confidentiality.",
         "DNP3: Secure Authentication (SAv5 / IEEE 1815-2012) adds authentication + integrity of critical functions but NOT confidentiality (use TLS/VPN for that). MQTT: TLS on 8883 adds confidentiality + protects credentials; authorization still depends on broker-side ACLs, and authentication on broker credentials/certs."),
        ("You can monitor but not immediately re-engineer these systems. Give one Zeek/ICSNPP-based detection for each capture.",
         "DNP3: alert on any dnp3_control.log control (SELECT/OPERATE/DIRECT_OPERATE) whose source host is not the sanctioned master. MQTT: alert on mqtt_connect.log connects with empty credentials/anonymous, or mqtt_subscribe.log subscriptions to '#'."),
    ]
    for q, a in syn:
        L.append("### Q%d.\n\n**Question.** %s\n" % (qn, q))
        if answers:
            L.append("**Answer.** %s\n" % a)
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
