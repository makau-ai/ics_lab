# 🧪 Student Lab Guide — DNP3 & MQTT (everything is already running)

Welcome. This Codespace **auto-started the whole lab** for you. You don't have to install or launch
anything — just watch, filter, and poke.

> **New here? Take the Learning Path instead.** For a structured, level-by-level route from your
> first packet to a university-style Machine Problem, open the **Learning Path** on port **8080** (it
> auto-opens), or `curriculum/index.html` / `CURRICULUM.md`. This guide is the quick "poke around"
> companion — the Learning Path is the course.

## 0. See the live traffic (30 seconds)

1. Open the forwarded port **`6080`** — a **noVNC Desktop** (a "Simple Browser" tab may already be open;
   otherwise use the **Ports** tab). Password: **`vscode`**.
2. **Wireshark is already open and capturing on `lo`.** You should see packets scrolling.
3. In Wireshark's display-filter bar, type **`mqtt`** and press Enter. Then try **`dnp3`**.

What's running for you: an MQTT broker + a DNP3 substation outstation, a sensor publishing telemetry
every 2 s, an HMI subscriber, and a pump-controller. A one-time **attack demo** fires ~15 s after start,
and a DNP3 poll repeats every ~25 s. Re-run the attacks any time with **`./lab/intrude.sh`**.

---

## 1. MQTT — read secrets and watch an intrusion

**a. Cleartext credentials.** Filter `mqtt.msgtype == 1` (CONNECT). Click a CONNECT, expand
*MQ Telemetry Transport* in the middle pane, and read the **Username** and **Password** in plain text.
→ That's why MQTT belongs on TLS (port 8883). 

**b. The telemetry fan-out.** Filter `mqtt.msgtype == 3` (PUBLISH). See the sensor's readings and the
broker forwarding them to the HMI.

**c. Run the intrusion.** In a terminal: `./lab/intrude.sh`. Now filter `mqtt` and find:
- an anonymous **CONNECT** (no username) that the broker **accepts** (CONNACK return code 0),
- a **SUBSCRIBE** to `#` (every topic), and
- a **PUBLISH** to `plant/tank1/command`.
Watch the terminal: the **pump-controller** prints that it acted on the injected command — real impact.

> Question: the rogue was *accepted* by the broker. Is the command injection an **authentication** or an
> **authorization** failure? (Answer in the MQTT module, Security & Controls.)

---

## 2. DNP3 — spot the impostor

**a. Normal control.** Filter `dnp3`. Find the master's integrity poll (**Read**), the outstation's
**Response**, and a supervised **Select** → **Operate** breaker close.

**b. The injection.** Run `./lab/intrude.sh` again and find the **Direct Operate** that **trips** the
breaker. Add columns for `ip.src` and `dnp3.src` (right-click a field → *Apply as Column*): the malicious
frame's **IP source is not the master**, yet its **DNP3 link address claims to be the master (100)** — a
forged identity base DNP3 can't reject.

> Try `./lab/intrude.sh` then `python3 lab/dnp3/master.py --host 127.0.0.1 --src-addr 100 --attack` to also
> spoof the link address — and see why a "wrong source IP" alert alone isn't enough.

---

## 3. Go deeper — the interactive modules

Open **`modules/dnp3_module.html`** and **`modules/mqtt_module.html`** (right-click → *Open with Live
Preview* or *Open Preview*). Use the **Frame Explorer** tab to walk the reference captures frame by frame,
then the **Security & Controls** and **O\*NET & Careers** tabs.

---

## 4. Graded assessment (unseen captures)

Open these in Wireshark (`./lab/open-wireshark.sh pcaps/dnp3_assessment.pcap`) and answer
**`lab/worksheets/unseen_assessment.md`** — they use *different* attacks than the demo (a spoofed DNP3
status report; an MQTT retained-message harvest + persistent command). Instructor key + rubric:
`lab/worksheets/unseen_assessment_key.md`.

---

## 5. Advanced — segmentation lab (multi-container)

See how zoning stops the attack at the boundary:

```bash
docker compose -f lab/docker-compose.segmented.yml up -d --build
docker compose -f lab/docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-dmz   # blocked
docker compose -f lab/docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-otcell # succeeds
```

Full details and the harden-and-retest exercises are in **`lab/README.md`**.

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
