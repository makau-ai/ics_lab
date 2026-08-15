# ICS/OT Protocol Analysis Lab Kit — DNP3 & MQTT

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/YOUR-ORG/YOUR-REPO?quickstart=1)

> **One click to start.** Push this kit to a GitHub repo, then replace `YOUR-ORG/YOUR-REPO` in the
> badge above (and in this line) with your repo's slug. Clicking the badge builds the Codespace and
> **auto-opens the interactive Learning Path** (7 levels, Level 0 → the Machine Problem) on port
> **8080** — nothing to install. No repo yet? On any repo of this kit just press **`.`** then
> **Create codespace on main**.

A self-contained teaching kit for learning two of the most important operational-technology
protocols by reading real packet captures: **DNP3** (the SCADA protocol of the North American
electric and water sectors) and **MQTT** (the publish/subscribe backbone of the Industrial IoT).

Each protocol gets its own module built around a curated, Wireshark-ready `.pcap` file. Students
walk the capture frame by frame, see how the protocol actually works on the wire, spot deliberately
planted security anomalies, tie each one to a publicly documented real-world incident and a defensive
control, and then reproduce and harden the whole thing in a runnable Docker lab.

Everything was produced and verified with **tshark/Wireshark** and **CISA's ICSNPP** Zeek parsers —
every frame number, field value, and DNP3 CRC in the documentation matches the shipped captures.

## Just the pcaps (90 seconds)

New here, or just want the original thing — *documented DNP3 & MQTT sample captures to open and
read*? You do not need Docker, the Codespace, or the 7-level path for that.

1. Open a documented teaching capture in Wireshark, or point `tshark` at it:
   ```bash
   wireshark pcaps/dnp3_substation.pcap          # or: pcaps/mqtt_iot_telemetry.pcap
   tshark -r pcaps/dnp3_substation.pcap -q -z conv,tcp     # who is talking, on what ports
   ```
2. Read **[`pcaps/README.md`](pcaps/README.md)** — a one-line-per-file manifest (what each capture is,
   frame count, TCP port, role addresses, TEACHING vs GRADED-UNSEEN vs REAL) with a copy-paste
   30-second tshark tour that walks you straight to the planted anomaly in each file.

That is the whole original use case in one step: open a clean, documented sample pcap and see the
protocol on the wire. Everything below (modules, lab, curriculum, twin) builds outward from these
same files.

> **Revision 5** adds a one-click **Guided Tour** (`curriculum/tour.html`) — a narrated, full-screen
> walk through all eight sections with the real commands and real output, an animated real-world scene
> per step, and the O*NET role behind it. It speaks aloud in **10 languages** (English, Spanish, French,
> German, Portuguese, Mandarin, Japanese, Arabic — full RTL, Hindi, Russian) with synchronized closed
> captions, keyboard/screen-reader access, and reduced-motion support.
>
> **Revision 4** makes the optional **digital twin** run end-to-end from a single command — OpenPLC
> self-seeds and self-starts, the ST control loop runs the pumps (`spill = 0`), and DNP3 + MQTT cross the
> five IEC-62443 conduits — validated live from a clean volume in a fresh Codespace
> (`FORMAL_VERIFICATION.md` Part 5). It builds on **Revision 3's** **one-click, 7-level Learning Path**
> (`curriculum/`, auto-opens in the Codespace) that ends in a **university-style Machine Problem** (`mp/`),
> a verified list of **government & university** capture sources (`EXTERNAL_CAPTURES.md`), and a reproducible
> **formal-verification** record (`FORMAL_VERIFICATION.md` + `build/verify_all.py`: 21/21 checks, 63/63 DNP3
> CRCs); and on **Revision 2's** five-persona red-team review (see `RED_TEAM_REVIEW.md` and `CHANGELOG.md`): an unseen
> graded assessment with a rubric, a segmented-network lab, honest scope framing, more realistic
> detections, and keyboard/screen-reader accessibility fixes.

## Who it's for

Intermediate students who are comfortable with TCP/IP and basic Wireshark but new to industrial
protocols. The material is constructed through real **O\*NET occupational personas** — the
subject-matter voices that author it (Information Security Analysts 15-1212.00, Information Security
Engineers 15-1299.05, Penetration Testers 15-1299.04) and the OT careers students are training toward
(Power Distributors & Dispatchers 51-8012.00, Substation & Relay Repairers 49-2095.00, Electrical
Engineers 17-2071.00), with each learning objective mapped to O\*NET tasks and skills.

## ▶ Run it in GitHub Codespaces (zero install — everything auto-starts)

This repo includes a **`.devcontainer/`** that auto-builds and **auto-starts the entire lab** in the
cloud, with a browser-visible **Wireshark GUI over noVNC**. A student does nothing but open it and watch.

1. Click the **Open in GitHub Codespaces** badge above (or, on the repo, press **`.`** → **Create
   codespace on main**).
2. Wait for the one-time build. On start it automatically brings up the MQTT broker, the DNP3 outstation,
   a continuously-publishing sensor, an HMI subscriber, a pump-controller, and **Wireshark — already
   capturing on `lo`**. A short attack demo fires on its own.
3. The **Learning Path** opens on its own on port **`8080`** — this is your front door. Work the
   **7 levels in order** (Level 0 Orientation → Level 6, a university-style Machine Problem); the page tracks
   your progress. When Level 0 asks, open port **`6080`** ("noVNC Desktop") — it opens **straight to the
   desktop, no password**, with Wireshark already capturing. New to the terminal? See [`RUNNING_COMMANDS.md`](RUNNING_COMMANDS.md).
4. Re-run the attacks with **`./lab/intrude.sh`**; the multi-container + IEC 62443 segmentation labs also
   run here via docker-in-docker.

Full walkthrough and troubleshooting: **`.devcontainer/README.md`**. The whole path is also in
**`CURRICULUM.md`** (Markdown) if you prefer reading it in the editor.

## Start here (local)

1. Open **`index.html`** in a browser and click **Start the Learning Path**, or open
   **`curriculum/index.html`** directly for the 7-level path (Level 0 → Machine Problem). Prefer
   Markdown? See **`CURRICULUM.md`**. For reference material, go straight to a module:
   - `modules/dnp3_module.html` — interactive DNP3 module (clickable frame explorer)
   - `modules/mqtt_module.html` — interactive MQTT module
2. Open the matching capture in Wireshark alongside it:
   - `pcaps/dnp3_substation.pcap`
   - `pcaps/mqtt_iot_telemetry.pcap`
3. Work the **Frame Explorer**, then the **Security & Controls** and **Hands-On Lab** tabs.
4. Stand up the lab: `cd lab && docker compose up --build` (see `lab/README.md`).

Prefer print or an LMS? Every module also ships as **PDF**, **Word (.docx)**, and **Markdown**.

## What's inside

> **`build/` vs `source/`.** The working tree edits everything under **`build/`** (the content
> modules and builder scripts); when the kit is assembled for release those same scripts are
> **mirrored to `source/`** in the shipped copy — so `build/verify_all.py` in this repo and
> `source/verify_all.py` in a shipped kit are the same file. Edit `build/`; read `source/` only in a
> packaged kit.

| Path | Contents |
|---|---|
| `.devcontainer/` | **GitHub Codespaces** build: Dockerfile + noVNC desktop (Wireshark GUI) + docker-in-docker + auto-served Learning Path. See `.devcontainer/README.md`. |
| `curriculum/` | The **interactive Learning Path** — `index.html` (7 levels, progress-tracked, plus an advanced Level 7 digital twin) + `LEVEL_0..7.md`. The Codespace front door. |
| `CURRICULUM.md` | The whole leveled path as a single Markdown walkthrough. |
| `mp/` | The **Machine Problem** (Level 6): handout, two evidence captures, answer template, self-check autograder (`grade.py`), rubric, and instructor solution. |
| `pcaps/` | Two teaching captures **plus two unseen assessment captures** (`dnp3_assessment.pcap`, `mqtt_assessment.pcap`) and one real government-origin trace — all indexed in **`pcaps/README.md`** (the sample-capture manifest; start here for "just the pcaps"). |
| `modules/` | DNP3 & MQTT modules in **HTML** (interactive), **PDF**, **DOCX**, and **MD**. |
| `projects/` | The **forward→reverse** project track: `STARTER_AI_PROMPTS.md` (build a wire-valid app, then take it apart), `REAL_WORLD_CONNECTIONS.md` (web-verified incident→source→ATT&CK index), `ARTIFACT_RUBRIC.md` (persona-validated bundle rubric). See `projects/README.md`. |
| `verification/` | **Platform-generated evidence** that the captures and lab behave as documented — the reproducible `verify_all` pass, per-pcap tshark decodes, and a live-lab capture. A worked exemplar of a Mastery-level artifact bundle. See `verification/README.md`. |
| `lab/detect/` | **Runnable invariant detectors** (Python + `tshark`) for the durable detections the modules describe in prose — plus a red-team evasion exercise (`RED_TEAM_EVASION.md`). Ship the detections you teach, then evade them. |
| `EXTERNAL_CAPTURES.md` | Verified **government & university** DNP3/MQTT capture sources (CISA, UOWM, Genoa, Abertay) with provenance & licensing. |
| `FORMAL_VERIFICATION.md` | The reproducible verification record (21/21 checks, 63/63 DNP3 CRCs, autograder) + `build/verify_all.py`. |
| `lab/` | Docker Compose lab (flat + `docker-compose.segmented.yml`): Mosquitto broker, Python DNP3 outstation/master, MQTT pub/sub + attacker + pump-controller, tcpdump capture, and Zeek + CISA ICSNPP. Plus `run-local.sh` / `open-wireshark.sh` for the Codespaces GUI path. See `lab/README.md`. |
| `lab/worksheets/` | Student worksheet + instructor answer key (MD / DOCX / PDF). |
| `lab/zeek_reference_output/` | Real `dnp3_*.log` and `mqtt_*.log` produced from the captures. |
| `build/` | The content modules and scripts that build the whole kit from one content source, so instructors can extend it (mirrored to `source/` in a shipped kit — see the note above). |
| `INSTRUCTORS.md` | **Co-instructor onboarding** — how to grade the Machine Problem without leaking the shipped key (build the address-shifted hidden variant), how the rubrics fit together, the run/verify commands, and honest time-on-task. |

## Each module covers

Overview & learning objectives · industry and use cases · protocol anatomy (layers, function/packet
types) · a frame-by-frame walkthrough tied to exact frame numbers · security risks & controls (each
mapped to a real incident, a MITRE ATT&CK for ICS technique, and a control such as DNP3 Secure
Authentication, TLS, ACLs, or segmentation) · a hands-on lab with exercises and answer keys · O\*NET
personas and career pathways · full references.

## The objective/skill map (what each level makes you able to do)

The 7-level path is a single reverse-engineering progression — surface to fields to attack to
detection. Each level has one **observable** objective: something you can demonstrably *do* at the
end, not just read about. Times are honest per-level estimates (from `curriculum/`).

| Level | Observable objective — you can… | Approx. time |
|---|---|---|
| **0 · Orientation** | See live `dnp3` and `mqtt` traffic move in Wireshark/tshark and confirm the environment is up. | ~10 min |
| **1 · Who is talking?** | Name every host, its ports, the hub, and the odd host out — from conversation/endpoint statistics alone, without opening a packet. | ~25 min |
| **2 · What kind of messages?** | Enumerate the message types / DNP3 function codes for both protocols and point to the control messages — the surface fully mapped. | ~25 min |
| **3 · Inside the packet** | Extract any field by name; read a DNP3 control down to trip-vs-close; distinguish an **IP source** from a **DNP3 link address**; read MQTT credentials/topic/QoS/retain. | ~40 min |
| **4 · Find the attack** | Locate every planted anomaly by field evidence and state the weakness **and** a control for each. | ~35 min |
| **5 · Catch it automatically** | Write an **invariant-based** detection that resists spoofing, and turn packets into `dnp3_*`/`mqtt_*` logs with Zeek + CISA ICSNPP. | ~40 min |
| **6 · Machine Problem** | Apply Levels 1–5 to **unseen** captures using *different* attacks: score 90+ on the autograder (100 pts) and meet the incident-report mastery gates. | ~120 min |

Beyond the path: the **`projects/`** forward→reverse track and the **`lab/twin/`** wet-well digital
twin reuse these same Level 3–5 field-analysis skills on traffic and physics you build yourself.

## The captures at a glance

**DNP3 (`dnp3_substation.pcap`, 37 frames, TCP/20000).** A control-center master polls a substation
outstation, reads binary/analog telemetry, receives an unsolicited event, and performs a supervised
SELECT→OPERATE breaker close — then a rogue host injects an **unauthenticated DIRECT_OPERATE trip**
and a **cold restart**, which the outstation obeys because base DNP3 has no authentication.

**MQTT (`mqtt_iot_telemetry.pcap`, 61 frames, TCP/1883).** A sensor publishes tank telemetry (QoS 0
and QoS 1) that the broker fans out to an HMI dashboard — then a rogue host connects **anonymously**,
subscribes to **`#`** to eavesdrop everything, and **publishes an unauthorized command**.

## A note on accuracy and ethics

The captures are **curated teaching files — synthetic but fully protocol-valid** (they parse cleanly in
Wireshark, pass DNP3 CRC validation, and are recognized by the CISA ICSNPP/Zeek parsers). The planted
"attacker" traffic and the intentionally insecure broker are for isolated lab use only; the real-world
incidents referenced are cited to their public sources. Nothing here is weaponized — the goal is to
teach defenders to recognize and mitigate these weaknesses.

## Credits & primary sources

Built on public standards and research: the **DNP Users Group** DNP3 Primer and **IEEE 1815-2012**;
the **OASIS MQTT 3.1.1** specification; **CISA/INL ICSNPP** (`icsnpp-dnp3`) and the **Zeek** MQTT
analyzer; **O\*NET Online**; **NIST SP 800-82r3**; **MITRE ATT&CK for ICS**; and the CISA ICS
advisories and vendor/academic research cited in each module's References section.
