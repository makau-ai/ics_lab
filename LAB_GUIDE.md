# 🧪 Student Lab Guide — DNP3 & MQTT (everything is already running)

Welcome. This Codespace **auto-started the whole lab** for you. You don't have to install or launch
anything — just watch, filter, and poke.

> **New here? Take the Learning Path instead.** For a structured, level-by-level route from your
> first packet to a university-style Machine Problem, open the **Learning Path** on port **8080** (it
> auto-opens), or `curriculum/index.html` / `CURRICULUM.md`. This guide is the quick "poke around"
> companion — the Learning Path is the course.

> **How this guide is laid out.** Every task is split into **Read** (why it matters — no action),
> **Do · Type** (a command to run) or **Do · Click** (a GUI action with the exact menu path), and a
> **Check** (what you should see). Copy any command with its **Copy** button, or with
> **Ctrl/Cmd+Shift+V** (the paste-backup). A handful of commands also have a short Learning-Path
> token — where one exists, you can just type it in the `lab` runner instead of copying.

## 0. See the live traffic (30 seconds)

> **Read** — This Codespace auto-started everything: an MQTT **broker** and a DNP3 substation
> **outstation**, a sensor **publishing** telemetry every 2 s, an HMI **subscriber**, and a
> pump-controller. Wireshark is already open and capturing on `lo`. A one-time attack demo fires
> ~15 s after start, and a DNP3 poll repeats every ~25 s. You don't set anything up — you observe.
> The `:6080` noVNC desktop opens straight to the desktop with **no password prompt** (if a VNC
> prompt ever appears, it's `vscode`).

**Do · Click** — Open the forwarded port `6080`: the **Ports** tab ▸ the `6080` row ▸ the
**Open in Browser** (globe) icon. A "Simple Browser" tab may already be open for it.

**Check —** you should see the Linux desktop with **Wireshark already running** and packets scrolling
in a live capture on `lo`; if not, reopen the `6080` port from the **Ports** tab.

**Do · Click** — In Wireshark's green display-filter bar, type `mqtt` and press Enter; then clear it,
type `dnp3`, and press Enter.

**Check —** you should see MQTT telemetry rows fill the packet list (then DNP3 rows on the second
filter); if not, confirm the capture is running on `lo` and run `lab reset`.

> **Read** — Short filters like `mqtt` / `dnp3` you just **type**. To **paste** a longer filter or
> command onto this remote desktop, your normal Ctrl/Cmd+V won't reach it — go through noVNC's
> **Clipboard panel**: click the clipboard icon on the noVNC window's **left edge**, paste your text
> into that box, then **Ctrl+V** in Wireshark (or **Shift+Insert** in an `xterm`). A bridge keeps that
> panel in sync with the desktop for you. Most work needs no pasting at all — commands run from the
> **VS Code terminal** with the `lab` runner. Details: `RUNNING_COMMANDS.md`.

**Do · Type** — Re-run the attack demo any time from a terminal (or just type `l0b`):

```bash
./lab/intrude.sh
```

**Check —** you should see the MQTT anonymous connect + command injection and a DNP3 trip appear in
the capture; if not, run `lab reset` and re-run.

---

## 1. MQTT — read secrets and watch an intrusion

### a. Cleartext credentials

> **Read** — MQTT is publish/subscribe messaging: a **broker** relays between **publishers** and
> **subscribers**. A CONNECT packet carries the client's credentials, and without TLS they cross the
> wire in plain text — which is why MQTT belongs on TLS (port 8883).

**Do · Click** — In the display-filter bar, type `mqtt.msgtype == 1` (CONNECT) and press Enter.

**Check —** you should see only CONNECT packets in the list; if not, clear the filter and retype it.

**Do · Click** — Click one CONNECT packet, then in the middle (packet-details) pane expand
**MQ Telemetry Transport ▸ Connect Command**.

**Check —** you should see the **Username** and **Password** fields in cleartext; if not, run
`lab reset`.

### b. The telemetry fan-out

> **Read** — Telemetry flows as PUBLISH messages: the sensor **publishes** readings and the broker
> fans them out to every **subscriber** (here, the HMI).

**Do · Click** — In the display-filter bar, type `mqtt.msgtype == 3` (PUBLISH) and press Enter.

**Check —** you should see the sensor's readings and the broker forwarding them to the HMI; if not,
run `lab reset`.

### c. Run the intrusion

> **Read** — The attack demo connects a rogue client **anonymously**, subscribes to `#` (every
> topic), and publishes to a command topic — and the pump-controller acts on that injected command.
> The rogue was *accepted* by the broker: is the command injection an **authentication** or an
> **authorization** failure? (Answer in the MQTT module, Security & Controls.)

**Do · Type** — Fire the intrusion from a terminal (or just type `l0b`):

```bash
./lab/intrude.sh
```

**Check —** you should see the **pump-controller** print that it acted on the injected command — real
impact; if not, run `lab reset` and re-run.

**Do · Click** — In the display-filter bar, type `mqtt` and press Enter.

**Check —** you should see an anonymous **CONNECT** (no username) that the broker accepts with CONNACK
return code 0, a **SUBSCRIBE** to `#`, and a **PUBLISH** to `plant/tank1/command`; if not, run
`lab reset`.

---

## 2. DNP3 — spot the impostor

### a. Normal control

> **Read** — In DNP3 a **master** polls an **outstation**. A legitimate control is supervised: the
> master issues an integrity poll (**Read**), the outstation sends a **Response**, then a **Select** →
> **Operate** pair closes the breaker.

**Do · Click** — In the display-filter bar, type `dnp3` and press Enter.

**Check —** you should see the master's integrity **Read**, the outstation's **Response**, and a
supervised **Select** → **Operate** breaker close; if not, run `lab reset`.

### b. The injection

> **Read** — DNP3 has no authentication, so an attacker can forge its identity. The malicious frame's
> **IP source is not the master**, yet its **DNP3 link address claims to be the master (100)** — a
> forged identity base DNP3 can't reject.

**Do · Type** — Re-run the attack (or just type `l0b`):

```bash
./lab/intrude.sh
```

**Check —** you should see a new **Direct Operate** that **trips** the breaker appear in the capture;
if not, run `lab reset`.

**Do · Click** — Right-click the `ip.src` field in the details pane and choose **Apply as Column**,
then do the same for the `dnp3.src` field.

**Check —** you should see, on the malicious **Direct Operate** frame, an `ip.src` that is **not** the
master while `dnp3.src` = **100**; if not, run `lab reset`.

> **Read** — Spoofing the link address *as well* shows why a "wrong source IP" alert alone isn't
> enough — the durable rule keys on an invariant, not on one spoofable field.

**Do · Type** — Also spoof the DNP3 link address, then re-read the frame:

```bash
./lab/intrude.sh
python3 lab/dnp3/master.py --host 127.0.0.1 --src-addr 100 --attack
```

**Check —** you should see the spoofed control now carry the master's link address, so a
source-IP-only rule would miss it; if not, run `lab reset`.

---

## 3. Go deeper — the interactive modules

> **Read** — The interactive modules go deeper still: a **Frame Explorer** walks the reference
> captures frame by frame, plus **Security & Controls** and **O\*NET & Careers** tabs.

**Do · Click** — In VS Code's Explorer, right-click **`modules/dnp3_module.html`** (or
**`modules/mqtt_module.html`**) and choose **Open with Live Preview** (or **Open Preview**).

**Check —** you should see the module open with its **Frame Explorer**, **Security & Controls**, and
**O\*NET & Careers** tabs; if not, reopen it from the Explorer.

---

## 4. Graded assessment (unseen captures)

> **Read** — The graded assessment uses two *unseen* captures with *different* attacks than the demo
> (a spoofed DNP3 status report; an MQTT retained-message harvest + persistent command). You answer
> the worksheet `lab/worksheets/unseen_assessment.md`; the instructor key + rubric live in
> `lab/worksheets/unseen_assessment_key.md`.

**Do · Type** — Open an unseen capture in Wireshark:

```bash
./lab/open-wireshark.sh pcaps/dnp3_assessment.pcap
```

**Check —** you should see the assessment capture load in Wireshark, ready to filter; if not, confirm
the path and that the desktop on `:6080` is open.

---

## 5. Advanced — segmentation lab (multi-container)

> **Read** — The segmentation lab shows how zoning stops the attack at the boundary: the same DNP3
> attack is **blocked** from the DMZ but **succeeds** from the OT cell. Full details and the
> harden-and-retest exercises are in **`lab/README.md`**.

**Do · Type** — Bring up the segmented lab:

```bash
docker compose -f lab/docker-compose.segmented.yml up -d --build
```

**Check —** you should see the containers build and start; if not, re-run the command and check the
Docker output.

**Do · Type** — Run the attack from the DMZ:

```bash
docker compose -f lab/docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-dmz
```

**Check —** you should see the attack **blocked** at the zone boundary (the outstation is never
reached); if not, confirm the segmented stack is still up.

**Do · Type** — Run the attack from inside the OT cell:

```bash
docker compose -f lab/docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-otcell
```

**Check —** you should see the attack **succeed** from inside the cell — segmentation is the layer
that made the difference; if not, confirm the segmented stack is still up.

---

### Wireshark cheat-sheet

| Goal | Filter |
|---|---|
| All MQTT | `mqtt` |
| MQTT connects / creds | `mqtt.msgtype == 1` |
| MQTT publishes | `mqtt.msgtype == 3` |
| Anonymous MQTT connect | `mqtt.msgtype == 1 && !mqtt.username` |
| All DNP3 | `dnp3` |
| DNP3 controls only | `dnp3.al.func in {3,4,5}` |
| DNP3 unsolicited responses | `dnp3.al.func == 130` |

Reset the running services: `./lab/run-local.sh down` then `bash .devcontainer/autostart.sh`.
