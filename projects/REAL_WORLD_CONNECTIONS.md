# Real-World Connections — A Verified Investigation Index

*Mapping each level of the DNP3 + MQTT + wastewater-twin kit to a real incident, a primary source, a MITRE ATT&CK for ICS technique, and a hands-on investigation task.*

---

## How to use this document

You have spent the seven levels of this kit reading two protocols down to the byte and
watching an attacker move a simulated pump. This index is the bridge from *that capture on
your screen* to *the real world it stands in for*. Every row below is an invitation to leave
the lab for twenty minutes, read a primary source with your own eyes, and then come back and
map what the source describes onto a frame, a Zeek log line, or the spill counter you already
know.

Each entry follows the same shape:

> **Kit topic / level → Incident (year) → What actually happened (carefully caveated) →
> Primary source (a URL that was verified to resolve) → ATT&CK for ICS technique →
> `Investigate:` a concrete task that ties the source back to the lab.**

**Work it as an analyst, not a tourist.** Do not just click the link and skim. For each
incident, decide *which of the kit's findings it grounds* (a D-finding in
`modules/dnp3_module.md §7`, an M-finding in `modules/mqtt_module.md §7`, or a W-weakness in
`design/WEAKNESS_ANALYSIS.md`), *which ATT&CK technique the kit reproduces and which it
cannot*, and *what the kit's packet-only sensor would and would not have seen*. The best
learners finish each entry able to say one true sentence about the limits of the analogy.

**Every URL in this file was checked to resolve at the time of writing (2026-08-14).** Where a
source was confirmed by search-engine index and multiple corroborating outlets but an
automated fetch was blocked by the host's anti-bot rules, that is noted. Nothing here is a
guessed or fabricated link. If a link rots, the *title + identifier* given in each row is
enough to re-find the authoritative copy.

---

## A learner's note on analogy vs. attribution — read this first

The single most important habit an OT intelligence analyst practices is separating three very
different kinds of claim:

| Claim type | What it means | Confidence you can lend it |
|---|---|---|
| **Demonstrated protocol weakness** | Someone showed the protocol *can* be abused (the kit's frame-27 DNP3 injection, frame-52 MQTT command) | High — you watched it on the wire |
| **Exposure census** | A scan found many devices *reachable* and misconfigured (Avast's 32,000 open brokers) | High for "it exists," zero for "it was attacked" |
| **Attributed incident** | A named actor *did* a specific thing to a specific victim (CyberAv3ngers at Aliquippa) | Only as strong as the investigation behind it — and investigations get revised |

The kit's modules are deliberately disciplined about this: the DNP3 module's frame-27 note
*refuses* to call the injection an "Aurora attack" or a "Ukraine attack," because Aurora
(2007) destroyed a generator by an out-of-sync **re-close**, and Ukraine 2015 was
hands-on-keyboard operation of the utility's own HMIs with **stolen credentials** — neither
was a DNP3 command-injection. Keep that discipline. When you write your Machine-Problem
report, *classify your real-world evidence as analogy or attribution and state your
confidence*.

### The cautionary tale: Oldsmar (2021)

In February 2021 the water treatment plant in Oldsmar, Florida became the most-cited water-OT
"hack" in the world. The reported story: a remote intruder reached the HMI (over TeamViewer)
and pushed the sodium-hydroxide (lye) dosing setpoint from 100 ppm to 11,100 ppm before an
operator watching the screen dragged it back. CISA, the FBI and EPA issued a joint advisory.
It was, for two years, *the* example everyone used — including, at first, this kit.

**Then the attribution fell apart.** By 2023, Pinellas County officials and the former Oldsmar
city manager stated publicly that there was likely **no external intrusion at all** — that the
setpoint excursion was most plausibly **operator error**, an authorized employee "banging on
his keyboard." The FBI, per that reporting, "was not able to confirm that this incident was
initiated by a targeted cyber intrusion."

The teaching point is *not* "Oldsmar was fake." It is that **OT attribution is hard, initial
reports are often wrong, and a plausible cyber story and a plausible human-error story can
produce the identical setpoint change on the wire.** A packet capture that shows
`LEAD_START` jumping to 150% cannot, by itself, tell you whether a foreign actor or a tired
operator's mouse did it — the most decisive evidence (remote-access session logs, Windows
Type-10 logons) lives *off the wire*, exactly where the kit's sniffer cannot see. Treat
Oldsmar as a **reported incident whose attribution was later disputed**, and let it make you
humble about every other row in this table.

- Primary (original, reported): **CISA AA21-042A, "Compromise of U.S. Water Treatment
  Facility"** — <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-042a>
- The revision (read both): CyberScoop, *"Did someone really hack into the Oldsmar, Florida,
  water treatment plant? New details suggest maybe not."* —
  <https://cyberscoop.com/water-oldsmar-incident-cyberattack/> — and Tampa Bay Times,
  *"Cyberattack on Oldsmar's water supply never happened, official says"* —
  <https://www.tampabay.com/news/pinellas/2023/04/11/oldsmar-cyberattack-water-supply-poisoning-fbi-update/>
- OT-analyst framing (precursor observables, most of them off-wire): INL CyOTE case study,
  *Remote Access Attack on Oldsmar Water Treatment Facility 2021* —
  <https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Oldsmar.pdf>

**`Investigate` —** reproduce the Oldsmar-style setpoint excursion in the twin, then reason about what
the wire can and cannot tell you.

> Commands copy with the **Copy** button on each fenced block, or paste them with
> **Ctrl/Cmd+Shift+V** (the paste-backup) if the terminal swallows a normal paste.

**Do · Type** — run the Oldsmar-style move: push `LEAD_START` above 100% so the pumps never start:

```
master.py --host 172.30.10.12 --setpoint-lead 150
```

**Check —** the twin's `dnp3_objects.log` records a g41 analog-output WRITE carrying the out-of-band
`150` setpoint; if no g41 line appears, the write never reached the outstation — confirm the twin is up
and re-run.

> **Read** — Now write two incident narratives from that *same* `dnp3_objects.log` g41-write line: one
> blaming an external actor, one blaming operator error. List the evidence that would distinguish them,
> and note which of that evidence your packet sensor **cannot** produce. That gap is the whole lesson.

---

## The kit's arc, grounded

A one-screen index first; detailed entries follow.

| Kit level / topic | Real incident (year) | Primary source (verified) | ATT&CK for ICS |
|---|---|---|---|
| **L1–L2** Recon / endpoint & topic enumeration | Havex / Dragonfly (2013–14) | INL CyOTE Havex case study | T0842 Network Sniffing |
| **L3–L4** Rogue master / spoofed source (DNP3) | Maroochy Shire sewage spill (2000) | MITRE (Abrams & Weiss) + CyOTE | T0848 Rogue Master · T0856 Spoof Reporting |
| **L3–L4** Unauthorized command, loss of control | Ukraine grid attack (2015) | E-ISAC / SANS Defense Use Case | T0855 Unauthorized Command · T0814 DoS |
| **L3–L4** Protocol-family command malware | Industroyer / CRASHOVERRIDE (2016), Industroyer2 (2022) | MITRE ATT&CK S0604 + CyOTE | T0855 · T0814 (*not DNP3 — IEC-101/104/61850/OPC*) |
| **L4** Setpoint / "modify parameter" | Oldsmar (2021, *disputed*) | CISA AA21-042A + CyberScoop/Tampa Bay | T0836 Modify Parameter |
| **L5** Detection & the DNP3 implementation attack surface | Project Robus DNP3 fuzzing (2013–16) | CISA ICSA-13-291-01B | T0814 Denial of Service |
| **L5** Detection engineering at scale | ICSNPP parser + UOWM/MQTTset datasets | cisagov/icsnpp-dnp3, Zenodo, MDPI | (detection tooling) |
| **Twin / CIE** Attack on the safety layer | TRITON / TRISIS (2017) | MITRE S1009 + Campaign C0030 | (safety-system attack) |
| **Twin** Modbus actuation bus | FrostyGoop (2024) | Dragos | T0855 (Modbus/502) |
| **Twin** Exposed water PLCs, default creds | Aliquippa / CyberAv3ngers (2023) | CISA AA23-335A | T0855 · exposed-device access |
| **Twin** State-actor pre-positioning ("the hard 95%") | Volt Typhoon (2024) | CISA AA24-038A | Discovery / Lateral Movement |
| **Twin** IT→OT pivot on a water utility | "Kemuri Water Company" (2016) | Verizon DBD via SecurityWeek | T0836 Modify Parameter |
| **Standards** DNP3 authentication | IEEE 1815-2012 SAv5 | standards.ieee.org | (durable control) |
| **Standards** MQTT auth/authz | OASIS MQTT 3.1.1 / 5.0 | docs.oasis-open.org | (durable control) |
| **Standards** OT segmentation | NIST SP 800-82r3 · IEC 62443-3-2 | csrc.nist.gov · IEC | (zones & conduits) |
| **Standards** Consequence-based engineering | DOE/INL CIE + CyOTE | energy.gov/ceser | (the twin's thesis) |

---

## Levels 1–2 — Recon & enumeration

*You mapped endpoints, the broker/master hub, and the odd host out, then counted message
types — all before opening a payload. That is exactly the work a real ICS recon campaign
automates.*

### Havex / Dragonfly (2013–2014) — the reconnaissance the kit hands you for free

**What actually happened.** The Dragonfly (Energetic Bear) espionage campaign spread the Havex
remote-access trojan into ICS environments, notably by trojanizing legitimate ICS-vendor
software installers (a supply-chain / watering-hole approach). Havex's most-cited module was an
**OPC scanner** that enumerated ICS/SCADA assets on the LAN — building an inventory of what was
present. It was, as far as public reporting shows, an *espionage and enumeration* operation:
map the plant, exfiltrate, pre-position. Read it as the "hard 95%" — the Discovery and
enumeration that must happen *before* anyone reaches your frame-27 injection.

- **Primary source (verified):** INL CyOTE case study, *Havex Malware in a U.S. Manufacturing
  Facility 2014* — <https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Havex.pdf>
  (14 techniques, 48 observables, mapped to ATT&CK for ICS). Corroborating government alert:
  CISA/ICS-CERT *ICS Focused Malware (Update A)*, **ICS-ALERT-14-176-02A** —
  <https://www.cisa.gov/news-events/ics-alerts/ics-alert-14-176-02a>.
- **ATT&CK for ICS:** T0842 Network Sniffing (and Discovery-tactic asset enumeration). See the
  matrix at <https://attack.mitre.org/matrices/ics/>.

**`Investigate` —** re-run the Level 1 recon by hand, then map it back to Havex's automated enumeration.

**Do · Type** — rank endpoints and list conversations on the MQTT teaching capture (these are the
curriculum's own steps — or just type `l1` then `l1b`):

```
tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z endpoints,ip
tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z conv,tcp
```

**Check —** you should see the **broker** `10.10.20.10` as the busy star hub plus the rogue endpoint;
if the capture is missing, run `lab reset`.

**Do · Type** — do the same on the DNP3 capture (the conversations view is curriculum step `l1c`):

```
tshark -r pcaps/dnp3_substation.pcap -q -z endpoints,ip
tshark -r pcaps/dnp3_substation.pcap -q -z conv,tcp
```

**Check —** you should see the **master ↔ outstation** pair on TCP/20000 plus the rogue `.66`; if not,
run `lab reset`.

> **Read** — You just did by hand what Havex's OPC scanner automated. Now read the CyOTE Havex report
> and list *which* of Havex's enumeration observables map to a DNP3 Class-0 integrity READ ("point &
> tag identification") and a `SUBSCRIBE #` (automated collection) — and which of Havex's steps
> (trojanized installer, C2 beaconing) leave **no trace** in a protocol capture at all.

---

## Levels 3–4 — Spoofed source & command injection

*You cross-checked `ip.src` against `dnp3.src`, found the one control frame where they
disagree, and named the weakness. These are the incidents that make that skill matter.*

### Maroochy Shire (2000) — the twin's design-basis event

**What actually happened.** Between February and April 2000, Vitek Boden — a contractor
rejected for a job with the Maroochy Shire (Queensland, Australia) council — used **radio
equipment and stolen SCADA gear** to issue commands to sewage pumping stations as a *rogue
master*, ultimately spilling on the order of **800,000 litres (~211,000 gallons)** of raw
sewage into parks, a river, and a hotel's grounds. It is the canonical case of an attacker who
**impersonated the control system's identity** — because that identity was a claim, not a
proof — and it is *frame-for-frame the wet-well Sanitary Sewer Overflow (SSO)* this kit's twin
reproduces. **Caveat on the analogy:** Maroochy was an insider over **radio**, not an IP/DNP3
injection; the twin deliberately collapses that radio topology to a flat subnet so the abuse is
visible on the wire.

- **Primary source (verified):** Marshall Abrams & Joe Weiss (MITRE / NIST), *Malicious Control
  System Cyber Security Attack Case Study — Maroochy Water Services, Australia* —
  <https://www.mitre.org/sites/default/files/pdf/08_1145.pdf>. OT-analyst walk-through: INL
  CyOTE, *Insider Attack on the Maroochy Shire Sewerage Control System in 2000* —
  <https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Maroochy.pdf>.
- **ATT&CK for ICS:** T0848 Rogue Master (<https://attack.mitre.org/techniques/T0848/>) and
  T0856 Spoof Reporting Message (<https://attack.mitre.org/techniques/T0856/>); the physical
  end-state is T0831 Manipulation of Control.

**`Investigate` —** compare the kit's forged DNP3 trip to Maroochy's rogue master, then reproduce the
Maroochy consequence in the twin.

> **Read** — Frame 27 of `dnp3_substation.pcap` is the rogue **DIRECT OPERATE** whose `dnp3.src` is
> forged to the master's `100` while `ip.src` stays `10.20.0.66`. It defeats the same thing Maroochy's
> stolen-identity rogue master did — *identity that is a claim, not a proof.*

**Do · Click** — see it in the packet: in the noVNC desktop's Wireshark, choose **File ▸ Open** and
load `pcaps/dnp3_substation.pcap`, then type `dnp3.al.func==5` in the green display-filter bar and
press Enter. (The :6080 desktop opens with **no password** and Wireshark is already capturing; if a
VNC prompt ever appears, it's `vscode`.)

**Check —** the filtered frame is the DIRECT OPERATE showing DNP3 link source `100` (the master)
arriving from IP source `10.20.0.66` (the rogue) — the two-sources contradiction; if the file won't
open, confirm you launched the loopback lab (`lab reset`).

**Do · Type** — now reproduce the physical consequence in the twin — stop both pumps as a rogue master:

```
master.py --host 172.30.10.12 --attack
```

**Check —** the `spill` counter climbs above 0 — your Maroochy SSO; watch it live with
`docker compose logs -f plant-sim`, and if it stays at 0 the command never landed, so confirm the twin
is up and re-run.

> **Read** — Which ATT&CK technique does the kit reproduce (T0848 / T0856) and which one (T0860
> Wireless Compromise) can it **not**, and why?

### Ukraine grid attack (2015) — why stolen credentials beat frame injection

**What actually happened.** On 23 December 2015, attackers caused outages at three Ukrainian
electricity distribution companies, cutting power to ~225,000 customers. Crucially, the breaker
operations were **hands-on-keyboard use of the utilities' own HMIs with stolen credentials** —
the attackers logged in and operated the real control system — supplemented by KillDisk
wiping, a telephone denial-of-service, and **bricking of serial-to-Ethernet converters** to
prolong the outage and blind operators. This was **not** a DNP3 (or any) protocol-injection
exploit. It is the kit's honest counter-example: sometimes *operating the real HMI is easier
than forging a frame.*

- **Primary source (verified):** E-ISAC & SANS, *Analysis of the Cyber Attack on the Ukrainian
  Power Grid* (Defense Use Case, 18 March 2016) —
  <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2016/05/20081514/E-ISAC_SANS_Ukraine_DUC_5.pdf>.
- **ATT&CK for ICS:** T0855 Unauthorized Command Message
  (<https://attack.mitre.org/techniques/T0855/>) via valid access; T0814 Denial of Service
  (<https://attack.mitre.org/techniques/T0814/>) for the converter-bricking / loss of control.

> `Investigate:` The kit's frame-27 attacker forged a link address; the Ukraine 2015 attackers
> stole a password and used the genuine HMI. Argue, in two sentences, why the second is often
> the *lower-effort* path — and map the attackers' serial-to-Ethernet-converter bricking to the
> kit's **COLD RESTART** (frame 31, `dnp3.al.func==13`) availability lesson. Which of these
> would your Zeek/ICSNPP sensor detect, and which happens entirely at a login prompt the sensor
> never sees?

### Industroyer / CRASHOVERRIDE (2016) & Industroyer2 (2022) — right idea, wrong protocol

**What actually happened.** Industroyer (a.k.a. CRASHOVERRIDE) was purpose-built grid malware
used against a Kyiv transmission substation in December 2016. It carried interchangeable
protocol modules for **IEC 60870-5-101, IEC 60870-5-104, IEC 61850, and OPC DA** — and it
tripped breakers by, among other things, sweeping every discovered Information Object Address in
IEC-104 "range mode." **It did not use DNP3.** A variant, Industroyer2, was deployed against a
Ukrainian energy provider in 2022. The reason this belongs in the kit is *methodological, not
protocol-level*: the **detection invariant** (a command rate far above the polling baseline; a
sweep across every control index) transfers to DNP3 even though the wire format does not.

- **Primary source (verified):** MITRE ATT&CK for ICS, **Software S0604 (Industroyer)** —
  <https://attack.mitre.org/software/S0604/> (confirms the IEC-101/104/61850/OPC DA modules,
  Dec 2016 Ukraine). OT-analyst walk-through: INL CyOTE, *Industroyer Targeting Ukraine* —
  <https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Industroyer.pdf> (and the
  companion *Industroyer2 and Wiper* study,
  <https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Industroyer2.pdf>).
- **ATT&CK for ICS:** T0855 Unauthorized Command Message; T0814 Denial of Service.

> `Investigate:` Build the DNP3 analog of Industroyer's IEC-104 range-mode sweep: an
> **OPERATE (0x04)** across every `g12v1` CROB index. You cannot copy Industroyer's protocol,
> but you *can* copy its signature. Write a detection that fires on "control-command rate far
> above the established poll baseline" and argue why it survives even though DNP3 ≠ IEC-104.
> This is the honesty the kit models: reproduce the *technique*, not the false claim that
> Ukraine was a DNP3 attack.

---

## Level 5 — Detection, and where the sensor goes dark

*You learned that "alert on wrong source IP" is signature-thinking that a spoofed IP defeats,
and that once traffic is encrypted your ICSNPP sensor goes blind. Two real-world anchors.*

### Project Robus (2013–2016) — the DNP3 *implementation* attack surface

**What actually happened.** Independent researchers Adam Crain and Chris Sistrunk fuzzed DNP3
stacks across many vendors and found dozens of implementation flaws — malformed frames that
could crash or hang a master or outstation. This is a different class of bug from the kit's
*design* gaps (no authentication): it is **improper input validation** in the parser itself,
and it is exactly the risk in the twin's deliberately tiny hand-rolled stdlib parser
(`dnp3lib.py`, flagged CWE-121/125/787 in `WEAKNESS_ANALYSIS §2.5`).

- **Primary source (verified):** CISA/ICS-CERT umbrella advisory **ICSA-13-291-01B, "DNP3
  Implementation Vulnerability (Update B)"** —
  <https://www.cisa.gov/news-events/ics-advisories/icsa-13-291-01b>. (This is the umbrella entry
  for the ~30 vendor advisories the Robus effort produced.)
- **ATT&CK for ICS:** T0814 Denial of Service (against the monitoring/control path itself).

> `Investigate:` The kit's D5 finding cites Robus but ships *no* fuzzer. Craft one malformed
> DNP3 frame against the twin's `master.py`/`dnp3lib.py` decode path and observe whether it
> desyncs or crashes the parser — then articulate the difference between a **design** gap
> (frame 27 is a *legal* frame from the wrong party) and an **implementation** gap (a crafted
> *illegal* frame the parser mishandles). Different weakness, different fix, different ATT&CK
> phase.

### Detection engineering at scale — from your 60-packet pcap to labeled datasets

**Why this is here.** The kit's captures are clean, single-conversation teaching files with no
noise, so nothing in the graded path measures your detector's **false-positive rate**. Real
detection engineering lives on noisy, labeled, base-rate-realistic data — and the same ICSNPP
parser the kit uses in the lab is the bridge.

- **Primary tooling (verified):** CISA ICSNPP DNP3 Zeek parser — <https://github.com/cisagov/icsnpp-dnp3>
  (produces `dnp3.log`, `dnp3_control.log`, `dnp3_objects.log`).
- **DNP3 attack dataset (verified):** UOWM *DNP3 Intrusion Detection Dataset*, 9 attack
  scenarios with pcaps + flow-feature CSVs (Radoglou-Grammatikis et al.), Zenodo record
  7348493 — <https://zenodo.org/records/7348493>.
- **MQTT attack dataset (verified):** *MQTTset* (Vaccari et al., *Sensors* 2020, 20(22):6578),
  labeled legitimate + attack MQTT traffic — <https://www.mdpi.com/1424-8220/20/22/6578>.

> `Investigate:` Take your Level-5 MQTT rule (anonymous CONNECT → retained PUBLISH to a
> command topic) and your DNP3 invariant (one link address seen from >1 source IP), and run
> them against MQTTset / the UOWM DNP3 set. Measure precision and recall on data with a real
> base rate. A detector that scored perfectly on a 60-packet clean pcap will teach you what
> "1/1000 false positives on real traffic" actually costs a SOC.

### The encryption blind spot (no incident — a structural lesson)

When you close the confidentiality gap (DNP3-over-TLS, MQTT on 8883), your ICSNPP/Zeek sensor
goes **dark**: Zeek emits only `ssl.log` on 8883, and DNP3-in-TLS is opaque to the parser.
Detection must move to broker auth logs, endpoint syslog, and flow/JA3 metadata. Note the
precise boundary the DNP3 module draws: **DNP3 Secure Authentication (SAv5) is a MAC —
authenticity/integrity only — so it does *not* take the sensor dark; only transport encryption
does.** (See the standards section below for the SAv5 primary source.)

**`Investigate` —** take the sensor dark on purpose, then reason about where detection has to move.

**Do · Type** — generate the certificates for the twin's optional 8883 mTLS listener:

```
bash mosquitto/gen-certs.sh
```

**Check —** the CA and server cert/key files appear under `mosquitto/`; if the script errors, confirm
you are running it from the twin directory and that `openssl` is installed.

> **Read** — Enable the `listener 8883` block, **re-capture**, and confirm `mqtt_*.log` stops parsing
> while only `ssl.log` appears — your MQTT visibility just went dark. Now re-home your anonymous-CONNECT
> detection onto the broker's own auth telemetry. Where, exactly, did your visibility move — and what
> did it cost you?

---

## The digital twin & Cyber-Informed Engineering (CIE)

*The twin's pass condition — `spill == 0` under full DNP3+MQTT write access — is a CIE "even-if"
acceptance test: even if every digital layer is owned, an independent hardwired float must hold.
These incidents are why that thesis exists.*

### TRITON / TRISIS (2017) — the one time an adversary attacked the safety layer

**What actually happened.** Between roughly June and August 2017, the actor tracked as
TEMP.Veles deployed the **TRITON** framework (a.k.a. TRISIS / HatMan) against a petrochemical
facility's **Triconex Safety Instrumented System (SIS)** — the last-line protection layer whose
entire job is to bring the process to a safe state. The malware was built to interact with and
reprogram the SIS controllers; a flaw in the attack instead **tripped the Triconex into a safe
shutdown**, halting the plant for over a week and exposing the operation. It is, to date, the
**only** publicly known malware to deliberately target a safety system — which makes it the
real-world proof behind this kit's entire CIE argument. **The crucial nuance for the twin:**
TRITON attacked a *software-configured* SIS reachable over the network. The kit's backstop is a
**hardwired high-high float on discrete I/O that no register, coil, DNP3 frame, or MQTT message
can rewrite** — which is precisely *why* it survives a TRITON-class attacker that a
software-only SIS did not.

- **Primary source (verified):** MITRE ATT&CK for ICS, **Software S1009 (Triton)** —
  <https://attack.mitre.org/software/S1009/> ("an attack framework built to interact with
  Triconex Safety Instrumented System (SIS) controllers"), and **Campaign C0030, "Triton Safety
  Instrumented System Attack"** — <https://attack.mitre.org/campaigns/C0030/> (TEMP.Veles,
  Triconex, ~June–August 2017, >1-week shutdown).
  *(Note for accuracy: some references cite the old ATT&CK-for-ICS wiki ID "S0013" for Triton —
  that ID is now **PlugX** in current ATT&CK; use **S1009**.)*

> `Investigate:` This is the twin's capstone Socratic test. Own every digital layer — stop both
> pumps, spoof the level low, push `LEAD_START` out of band over both DNP3 and MQTT — and show
> that `spill` stays `0` **only** because the hardwired float force-starts the pump at 95%
> (`FLOAT_ENABLED=true`). Then read the TRITON sources and write the argument: *why is a
> discrete-I/O float that no comms path can write safer than a software-configured SIS that
> TRITON reprogrammed?* That sentence is the thesis of the entire kit.

### FrostyGoop (2024) — the Modbus actuation bus is the real path

**What actually happened.** FrostyGoop is ICS malware that **directly interacts with field
devices using Modbus TCP over port 502**. Dragos assesses it was likely used in a 2024 attack on
a district heating company in Ukraine (widely reported as Lviv), sending Modbus commands to ENCO
controllers that caused inaccurate readings and left customers without heat for nearly two days;
Dragos counts it as the ninth known ICS-specific malware. Its importance to the twin is direct:
it validates that the **unmonitored Modbus bus is the realistic actuation path**, not only the
SAv5-protected DNP3 gateway — a granted cell foothold can write coils/registers on `:502` and
bypass the entire DNP3 hardening story.

- **Primary source (verified):** Dragos, *How to Protect Against FrostyGoop: ICS Malware
  Targeting Operational Technology* —
  <https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology>.
- **ATT&CK for ICS:** T0855 Unauthorized Command Message
  (<https://attack.mitre.org/techniques/T0855/>), over Modbus rather than DNP3; physical result
  T0831 Manipulation of Control.

> `Investigate:` The InfoSec-analyst review of this kit flagged that the twin's Modbus bus has
> **zero detection coverage**. From the granted cell foothold, write raw Modbus (`modbus_tcp.py`
> client) directly to the pump coils `%QX100.0/.1` and the setpoint register `%MW10`, bypassing
> the DNP3-SAv5 gateway entirely, and confirm from the physics which control actually bounds the
> spill — the SAv5 gateway (it doesn't) or the hardwired float (it does). FrostyGoop is why
> "Modbus client/server" belongs in your threat model next to "DNP3 master/outstation."

### Aliquippa / CyberAv3ngers (2023) — a 2000-era weakness causing 2024 headlines

**What actually happened.** In November 2023, an IRGC-affiliated persona calling itself
**CyberAv3ngers** compromised internet-exposed **Unitronics** programmable logic controllers at
U.S. water and wastewater utilities — most famously the **Municipal Water Authority of Aliquippa,
Pennsylvania**, whose booster-station HMI was defaced. Per CISA, the actors reached at least 75
devices (at least 34 in the U.S. Water/Wastewater sector), exploiting **internet reachability and
default or absent credentials**. This is the modern, attributed, headline version of the kit's
own findings: `allow_anonymous true` (M3/CWE-306), the no-auth outstation, and internet-reachable
control ports.

- **Primary source (verified):** CISA joint advisory **AA23-335A, "IRGC-Affiliated Cyber Actors
  Exploit PLCs in Multiple Sectors, Including US Water and Wastewater Systems Facilities"** —
  <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a>.
- **ATT&CK for ICS:** access via exposed device + default credentials → T0855 Unauthorized
  Command Message.

> `Investigate:` Map one 2023 Aliquippa fact to one specific lab finding. The Unitronics PLCs
> were reachable from the internet with default/no credentials; the twin's insecure broker sets
> `allow_anonymous true` and the base DNP3 outstation authenticates nothing. Argue, in your
> report, *why a weakness the Maroochy case demonstrated in 2000 was still causing incidents in
> 2023* — and which single control (segmentation? auth? both?) most cheaply breaks the chain.

### Volt Typhoon (2024) — the "hard 95%" as a live state-actor reality

**What actually happened.** CISA and partners attributed to **Volt Typhoon** — a PRC
state-sponsored actor — a campaign of **living-off-the-land pre-positioning** inside U.S.
critical-infrastructure networks, including the water/wastewater sector, maintaining access for as
long as years to enable potential future disruption. There is no "frame 27" here: this is the
Initial Access, Lateral Movement, and OT-adjacent positioning that the kit explicitly scopes out
as the hard 95% *before* any injection. **Caveat:** this is pre-positioning/espionage, not a
demonstrated destructive OT actuation.

- **Primary source (verified):** CISA joint advisory **AA24-038A, "PRC State-Sponsored Actors
  Compromise and Maintain Persistent Access to U.S. Critical Infrastructure"** —
  <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a>.
- **ATT&CK for ICS / Enterprise:** Discovery and Lateral Movement tactics (living-off-the-land);
  T0842 Network Sniffing where OT telemetry is observed.

> `Investigate:` Everything the kit hands you for free — L2 adjacency to the RTU/broker, a
> position on the wire — is what Volt Typhoon spent months earning. Read AA24-038A's water-utility
> case study and list the pre-injection steps (initial access, credential access, lateral
> movement) that would have to precede frame 27 in a real intrusion, and note that **none of them
> appear in a DNP3/MQTT protocol capture.** That absence is why the kit is honest about scoping
> the "last 5%."

### Kemuri Water Company (2016) — the IT→OT pivot the segmentation lesson is built for

**What actually happened.** In Verizon's 2016 *Data Breach Digest*, an anonymized water utility
("**Kemuri Water Company**") was breached when attackers moved from an internet-facing payment
web application to an aging **AS/400** that happened to *also* run valve- and flow-control
applications tied to PLCs. They altered chemical-dosing settings (and stole ~2.5 million payment
records); the utility's alarms let staff catch and reverse the changes. Verizon assessed the
attackers had little ICS knowledge — more expertise could have done far worse. It is a cleaner
model of the kit's **IT/OT-convergence** weakness (CWE-1369) than Maroochy: a flat trust
boundary between business IT and OT. **Caveat:** "Kemuri" is Verizon's pseudonym; specifics come
from Verizon's narrative rather than a named public investigation.

- **Primary source (verified, accessible report):** SecurityWeek, *Attackers Alter Water
  Treatment Systems in Utility Hack: Report* (covering the Verizon Data Breach Digest, March
  2016) — <https://www.securityweek.com/attackers-alter-water-treatment-systems-utility-hack-report/>.
  Origin: Verizon RISK Team, *Data Breach Digest* (2016) —
  <https://www.verizon.com/business/resources/reports/data-breach-digest/>.
- **ATT&CK for ICS:** T0836 Modify Parameter (<https://attack.mitre.org/techniques/T0836/>).

> `Investigate:` The twin's C2 conduit claims telemetry-up / command-down is a "data diode."
> Kemuri is the exact IT→OT pivot that a real zone boundary is supposed to stop. Map Kemuri's
> path (internet payment app → AS/400 → PLC) onto the twin's zones (`ent_net` → ... → `cell_net`)
> and identify *which conduit rule* in `zone-fw/conduits.nft` would have to hold — then test the
> InfoSec reviewer's finding that a stateful firewall does **not** actually make a pub/sub path
> one-way. Misplaced trust in a control is itself the lesson.

---

## Standards — the durable fixes the kit prescribes

*The kit's hardening isn't invented; it implements published standards. Read the primaries and
judge what the twin's teaching stand-ins model and what they omit.*

### IEEE 1815-2012 — DNP3 with Secure Authentication (SAv5)

The durable fix for DNP3 findings D1/D3: SAv5 puts a challenge-response **MAC on critical
function codes**, proving a control came from a key-holding master and was not altered — closing
the "identity is just a link address" gap without requiring encryption. The twin ships a
**truncated-HMAC aggressive-mode approximation**, and this kit's own reviewers note it lacks a
sequence number / nonce, so it provides authenticity/integrity but **not** anti-replay.

- **Primary source (verified):** IEEE Std 1815-2012, *IEEE Standard for Electric Power Systems
  Communications — Distributed Network Protocol (DNP3)* — <https://standards.ieee.org/ieee/1815/5414/>.

> `Investigate:` Read how SAv5 aggressive mode carries a monotonic Challenge Sequence Number,
> then examine the twin's `dnp3lib.py sav5_tag` (a static HMAC with no CSQ/nonce). Capture a
> hardened SELECT+OPERATE pair and replay it verbatim. Does it pass? Write the one-line
> correction to `CIE_HARDENING.md W2`: the teaching HMAC gives *authenticity*, not *freshness*.

### OASIS MQTT 3.1.1 (and 5.0) — auth exists, authorization is the broker's job

MQTT 3.1.1 offers only optional cleartext username/password and **no authorization model** — every
M-finding in the kit flows from that. MQTT 5.0 adds an **AUTH packet / enhanced authentication**,
but per-topic ACLs bound to identity still do the actual authorization.

- **Primary source (verified):** OASIS, *MQTT Version 3.1.1* (OASIS Standard, 2014) —
  <http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html>.

> `Investigate:` Recall Level 4: the anonymous rogue was *authenticated* (CONNACK rc=0) but not
> *authorization-constrained*. Argue whether MQTT 5.0's AUTH packet closes finding M3 (anonymous
> access) or merely **moves** it — and prove from the hardened broker's `acl` that authorization,
> not authentication, is what actually stops the `plant/tank1/command` injection.

### NIST SP 800-82r3 & IEC 62443-3-2 — zones, conduits, and control ordering

These ground the twin's five-zone / conduit-firewall design and the DNP3 module's
compensating-control ordering (segmentation/allow-listing *first*, then SAv5/TLS, because you
can't re-flash the RTU tomorrow).

- **Primary sources (verified):** NIST SP 800-82 Rev. 3, *Guide to Operational Technology (OT)
  Security* (Sept 2023) — <https://csrc.nist.gov/pubs/sp/800/82/r3/final>. IEC 62443-3-2:2020,
  *Security for industrial automation and control systems — Part 3-2: Security risk assessment
  for system design* (the zones-and-conduits standard; formal text is paywalled at the IEC/ANSI
  webstore — title and scope confirmed, but there is no free canonical fulltext URL).
- **ATT&CK relevance:** the whole point is to make Discovery and Lateral Movement expensive.

> `Investigate:` From the granted cell foothold, show the *same* payload that dies at the
> `zone-fw` conduit when launched from `attacker_net` succeeds intra-zone — the segmentation
> lesson straight from IEC 62443-3-2. Then map the twin's C1–C4 conduits to 62443 zones and to
> NIST 800-82r3's monitoring guidance, and name the control that would have stopped Kemuri's
> IT→OT pivot.

### DOE / INL Cyber-Informed Engineering — the twin's whole thesis

CIE is the doctrine behind "even if every digital layer is owned, a hardwired float keeps spill
at 0." It is a real, government-published framework, not a lab conceit.

- **Primary source (verified):** DOE CESER, *Cyber-Informed Engineering* (and the National CIE
  Strategy) — <https://www.energy.gov/ceser/cyber-informed-engineering>.

> `Investigate:` Trace the twin's `spill == 0 under full write access` acceptance test to CIE's
> "even-if" idea, and place each of the twin's controls on the hierarchy — eliminate / engineered
> / administrative / add-on. Which is the SELECT arm-latch? Which is the hardwired float? Only one
> of them holds when the network is fully owned.

---

## Capstone task — build your own ATT&CK Navigator layer

You now have every technique the kit touches, each tied to a real incident. Assemble them into a
visual you can defend.

**Do · Click** — open the **MITRE ATT&CK Navigator** (hosted:
<https://mitre-attack.github.io/attack-navigator/>; source:
<https://github.com/mitre-attack/attack-navigator>). On the landing page choose **Create New Layer ▸
ICS** to start a fresh ICS-domain matrix.

**Check —** you should see the ICS technique matrix (tactic columns like *Initial Access*, *Impair
Process Control*, *Inhibit Response Function*), not the Enterprise one; if it looks wrong, delete the
layer tab and pick **ICS** again under Create New Layer.

> **Read** — Now build the evidence layer:
>
> 1. **Highlight the kit's own chain** (frame-27 / frame-52 and the twin attack): T0842 Network
>    Sniffing → T0848 Rogue Master → T0855 Unauthorized Command Message → T0856 Spoof Reporting
>    Message → T0836 Modify Parameter → T0831 Manipulation of Control → T0814 Denial of Service.
>    (Confirm each against the ICS matrix: <https://attack.mitre.org/matrices/ics/>.)
> 2. **Make a second layer for a real campaign** — Maroochy, or Ukraine 2015 — and **diff** it against
>    the kit's layer. The gap you see (initial access, lateral movement, wireless compromise,
>    credential theft — the "hard 95%") is exactly what the kit scopes out. Write two sentences on what
>    your lab captures and what it does not.
> 3. **Tag each highlighted technique with its incident + primary URL from this document** as the cell
>    comment, so your layer is self-documenting evidence.

The habit you are building — *technique ↔ incident ↔ primary source ↔ observable* — is the daily
tradecraft of an OT intelligence analyst.

---

## Where to go next — real pathways

- **INL CyOTE (Cybersecurity for the OT Environment)** — the government methodology this kit's
  detection arc borrows (perception → comprehension → attribution). Start from the consequence
  (the SSO), enumerate perceivable precursors left-of-impact, and decide "anomaly vs. attack"
  under uncertainty. Program home: <https://cyote.inl.gov/> · DOE CESER page:
  <https://www.energy.gov/ceser/cybersecurity-operational-technology-environment-cyote> · the
  case-study library used throughout this document lives under
  `https://cyote.inl.gov/content/uploads/…` (Maroochy, Oldsmar, Havex, Industroyer/2, Colonial
  Pipeline, Thyssenkrupp).
- **DOE Operational Technology (OT) Defender Fellowship** — a DOE/INL program for OT defenders in
  U.S. energy critical infrastructure; the professional continuation of the role this kit
  rehearses. <https://www.energy.gov/ceser/ot-defender-fellowship> (INL: <https://otdefender.inl.gov/>).
- **MITRE ATT&CK for ICS** — the technique backbone; read the technique pages behind every ID you
  used and trace them to their real reported campaigns. <https://attack.mitre.org/matrices/ics/>

---

## Source-verification ledger (for the maintainer)

Every citation above was checked on 2026-08-14. Confidence notes:

- **Verified by direct fetch (HTTP 200, content confirmed):** MITRE S0604 (Industroyer), MITRE
  S1009 (Triton), MITRE Campaign C0030; CISA AA23-335A (CyberAv3ngers), CISA AA24-038A (Volt
  Typhoon); Dragos FrostyGoop blog; INL CyOTE Maroochy, Oldsmar, and Havex case-study PDFs;
  MITRE/Abrams-Weiss Maroochy PDF; E-ISAC/SANS Ukraine DUC PDF; NIST SP 800-82r3; IEEE
  1815-2012; OASIS MQTT 3.1.1; Trend Micro MQTT report; Avast/Gen Digital MQTT-exposure post;
  SecurityWeek Kemuri report; DOE CESER CIE page and CyOTE page; CISA ICSNPP DNP3 repo; Zenodo
  UOWM DNP3 dataset; MDPI MQTTset; CyberScoop and Tampa Bay Times Oldsmar-dispute articles; IEC
  62443-3-2:2020 title (via ANSI/IEC preview).
- **Verified via search-engine index + multiple corroborating outlets (automated fetch was blocked
  by the host's anti-bot 403, not a bad link):** CISA **AA21-042A** ("Compromise of U.S. Water
  Treatment Facility") and CISA **ICSA-13-291-01B** ("DNP3 Implementation Vulnerability (Update
  B)"). Both exact titles + IDs + canonical `cisa.gov` URLs confirmed; safe to publish. The CyOTE
  Industroyer / Industroyer2 PDFs were likewise confirmed by index (real INL report numbers) plus
  the sibling PDFs fetched cleanly.
- **Corrections applied to the personas' proposed links:**
  - **Triton is MITRE ATT&CK ID S1009, not S0013** (the Intelligence Analyst review cited the
    retired wiki ID; current ATT&CK maps S0013 to *PlugX*). Added Campaign **C0030** as the
    primary campaign object.
  - **Havex CISA alert is ICS-ALERT-14-176-02A**, not "ICS-ALERT-14-176-A" as the review had it.
  - **FrostyGoop Dragos URL** in the review (`/blog/frostygoop-malware-analysis/`) 404s; the live
    Dragos page is `/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology`.
  - **Oldsmar** is presented as a *reported* incident with later-disputed attribution (per the
    maintainer's instruction), paired with the CyberScoop + Tampa Bay Times revisions — not as a
    confirmed hack.
- **Cited by designation only (no free canonical fulltext URL):** IEC 62443-3-2:2020 (paywalled at
  the IEC/ANSI webstore; title and scope verified). Verizon *Data Breach Digest* "Kemuri" is
  anonymized and lives behind a report portal, so the accessible **SecurityWeek** write-up is
  cited as the readable source of record.
- **⚠ Could NOT get a clean fetch (rate-limited), so NOT used as a load-bearing citation:** ESET
  *welivesecurity* Industroyer2 article (`/2022/04/12/industroyer2-industroyer-reloaded/`) returned
  HTTP 429 on repeated attempts. It is the kit's own existing reference and is structurally valid,
  but Industroyer is anchored here on the cleanly-fetched **MITRE S0604** and **CyOTE** primaries
  instead. Maintainer may re-confirm the ESET link at leisure.
- **Deliberately *not* given a load-bearing citation:** the 2007 INL **Aurora** generator test is
  mentioned only inside the analogy/attribution caveat (as the DNP3 module already frames it),
  because clean primary sourcing for Aurora is thin and it is frequently mis-cited; it is used as
  a *counter-example to over-claiming*, not as an attributed grounding.
