# CIE Hardening — Designing OUT the Twin's Weaknesses with Engineered Controls

**Authors:** Electrical/Control Engineer (17-2071.00), Cyber-Informed Engineering practitioner,
paired with Information Security Engineer (15-1299.05).
**Date:** 2026-08-14 · **Target:** wastewater lift-station digital twin (DNP3/20000 + MQTT/1883,
5-zone IEC-62443 segmentation).
**Reads with:** `design/research_cie.md` (the 12 CIE principles + hierarchy of controls),
`design/WEAKNESS_ANALYSIS.md` (the six key CWE-1358 weaknesses), `design/DIGITAL_TWIN_ARCHITECTURE.md`
(the twin, its point maps, the attack chain, the analog backstops).

---

## 0. Thesis — design out, don't bolt on

`WEAKNESS_ANALYSIS.md` proves the twin is a compact catalog of protocol-frailty weaknesses. The reflex
of an IT-security review is to wrap each one in an add-on control — a firewall, a password, TLS. CIE
inverts the order. The controlling doctrine (`research_cie.md` #2) is the **hierarchy of controls**:

```
   eliminate / substitute   →   make the bad physical state impossible          (best)
   engineered controls      →   hardwired / analog / deterministic-logic limits
   administrative           →   procedures, training
   add-on cybersecurity     →   SAv5, mTLS, ACLs, IDS                            (last, not first)
```

The engineering move is: **make the High-Consequence Event physically unreachable, then add the cyber
layers so an attacker cannot even get close enough to test the backstop.** A consequence that a
mechanical float makes impossible cannot be caused by any packet on the wire — so the float is the
cybersecurity control, and SAv5 is the second layer, not the first.

This document takes **each key weakness** and gives three things the task demands:

1. **The CIE principle(s) applied** — from the verified 12 (`research_cie.md §3`).
2. **The engineered control** — led by the control/electrical engineer `[ENG]` (hardwired interlocks,
   independent trips, deterministic PLC logic, physical clamps, one-way flow), complemented by the
   infosec engineer `[SEC]` (SAv5, mTLS, ACL, allow-lists, segmentation). The `[ENG]` layer is the one
   that must hold when the `[SEC]` layer is fully owned.
3. **How the twin demonstrates BOTH variants** — the vulnerable "before" that already exists in
   `lab/`, and the hardened "after," so students watch the same attack succeed then fail.

Provenance tags carried from the sibling docs: `[NOW]` = the variant exists in the current `lab/`
substrate today; `[BUILD]` = net-new hardened variant this design specifies for the twin
(`docker-compose.twin.yml` / OpenPLC ST program / `dnp3-gw`), consistent with `DIGITAL_TWIN §9`
("design approved for build"). Nothing here is weaponized; attacks are described only at the
protocol-observable level already present in the kit.

---

## 1. Consequence-based prioritization — the frame for every control below

> **CIE #1 Consequence-Focused Design** · guiding question (`research_cie.md`): *"How do I understand
> what critical functions my system must ensure and the undesired consequences it must prevent?"* ·
> CCE Phase 1 (Consequence Prioritization).

Before a single control is chosen, name the consequence. For this twin there is exactly one
High-Consequence Event, and it is the design basis every control traces to:

**HCE-1 — Wet-well overflow → Sanitary Sewer Overflow (SSO):** inflow continues to arrive, pumped
outflow stops or never starts, wet-well level rises past the weir, raw sewage is released (EPA
point-source violation). This is the Maroochy Shire (2000) consequence, reproduced frame-for-frame in
the twin (`DIGITAL_TWIN §1`, `§7`).

The **consequence-based design basis** (the cyber analog of a nuclear Design-Basis Threat,
`research_cie.md §4`) is therefore a single testable assertion:

> **DB-1: Even with full DNP3 + MQTT write access, an attacker cannot cause an unbounded SSO.**

Every weakness in `WEAKNESS_ANALYSIS.md` is important **only to the degree it contributes to HCE-1**.
That is what lets the control engineer prioritize: the weakness that most directly reaches HCE-1
(CWE-693, the single software interlock) gets the strongest, most independent control (a hardwired
float); a weakness that only enables reconnaissance (CWE-319 cleartext) gets a proportionate one. The
**twin's SSO spill counter** (`plant-sim`, `DIGITAL_TWIN §1.3`: `if level>=100%: spill += …`) is the
objective before/after scoreboard for every exercise: **spill == 0 under full write access = the
control passed.**

---

## 2. The six key weaknesses, designed out

### W1 — CWE-306 Missing Authentication for a Critical Function *(the headline weakness)*

**Where it lives (before).** `lab/dnp3/outstation.py` L46–58 executes SELECT / OPERATE /
DIRECT_OPERATE (CROB) and L60–64 COLD_RESTART with no credential check — L50 literally narrates
*"no authentication -- executed on request!"*. On MQTT, `lab/mosquitto/mosquitto.insecure.conf` L6
`allow_anonymous true`, and `lab/mqtt/pump-controller.py` L35–46 acts on any JSON arriving on
`plant/tank1/command`.

**CIE principles applied.** #2 Engineered Controls · #5 Resilient Layered Defenses · #10 Planned
Resilience · anchored to #1 (this is the shortest path to HCE-1).

**Engineered control.**

- `[ENG]` **Deterministic PLC logic that refuses unsafe / out-of-sequence commands.** Enforce
  **SELECT-before-OPERATE in the ladder/ST, as a state machine, not a courtesy.** The `dnp3-gw` /
  PLC keeps a per-point *arm latch*: an OPERATE (0x04) is honored **only** if a matching SELECT (0x03)
  for the *same index* arrived on the *same association* within a short arm-timeout (e.g., 2 s), after
  which the latch clears. **DIRECT_OPERATE (0x05) and DIRECT_OPERATE_NR (0x06) are rejected outright for
  consequential points** (pump stop, setpoint) — the single-packet fire-and-forget injection that
  `master.py --attack` relies on no longer has a code path. *(INL engineered-controls category: Physical
  Logic Mechanism / Digital Engineered Control.)*
- `[ENG]` **Command-permissive interlock (refuse the unsafe command by logic).** A pump-STOP is
  accepted only when stopping is physically safe: `permit_stop := (level < LEAD_START) AND
  (level_falling OR both_pumps_healthy)`. **The PLC will not de-energize the pumps into a rising
  high-well condition regardless of who issued the command.** This is the core CIE idea — the
  actuator's own logic vetoes a command whose *consequence* is HCE-1, independent of authentication.
- `[ENG]` **Independent hardwired backstop that no packet can override.** LSHH-102 high-high float,
  wired in series with the standby-pump starter (`DIGITAL_TWIN §1.3`), force-starts the pump + horn at
  95% **regardless of `%QX` coils, DNP3, or MQTT.** Even if authentication is 100% bypassed, HCE-1 is
  bounded. *(Category: Physical Logic Mechanism / Fail-Safe Default.)*
- `[ENG]` **Design out the MQTT command path entirely (simplification, CIE #4).** In the hardened
  build the `pump-controller` actuator is **removed / made read-only** and the `plant/tank1/command`
  topic carries no authority — MQTT is observe-only (this is the C2 data-diode intent, `DIGITAL_TWIN
  §4.2`). A path that does not exist needs no authentication.
- `[SEC]` **DNP3 Secure Authentication v5**, aggressive-mode HMAC on the control function codes
  (SELECT/OPERATE/DIRECT_OPERATE, g41 write, COLD_RESTART): the outstation executes a control only if
  the frame carries a valid HMAC over the pre-shared/session key. `[SEC]` **MQTT** `allow_anonymous
  false` + `password_file` (`mosquitto.secure.conf` L8–9).

> **Honest scoping.** Logic-enforced SELECT-before-OPERATE is an *operational* control: a determined
> attacker who holds the session can still send SELECT then OPERATE. Its job is to kill the trivial
> single-packet injection and to *force a stateful, authenticable exchange* — which is exactly where
> SAv5 (`[SEC]`) then proves key-possession, and where the interlock + float (`[ENG]`) bound the
> consequence even if both are defeated. The three layers are the Swiss-cheese stack (CIE #5); no one
> of them is claimed to be sufficient alone.

**Twin demonstrates both.**

- **Before** `[NOW]`: `python master.py --host dnp3-gw --attack` → outstation prints the "executed on
  request" line, `breaker/pump` trips; against `plant-sim`, level climbs and **spill increments**.
  `attacker.py` publishes the command, `pump-controller` obeys. Zeek: `dnp3_control.log`
  `function_code=DIRECT_OPERATE, status_code=Success`; `mqtt_publish.log topic=plant/tank1/command`.
- **After** `[BUILD]`: run `dnp3-gw` with `--enforce-select` (arm-latch + DIRECT_OPERATE refused) and
  the hardened ST loop with the stop-interlock; swap `mosquitto.secure.conf`. Same `--attack` →
  DIRECT_OPERATE is rejected (Zeek shows OPERATE with **no state change / status ≠ Success**), the
  SAv5-less frame is dropped, the STOP-while-rising is vetoed by logic, and if every digital layer is
  disabled the **float starts the pump at 95% → spill stays 0**. Students diff the two `dnp3_control.log`
  files and the two spill counters.

---

### W2 — CWE-319 / CWE-311 Cleartext Transmission / Missing Encryption

**Where it lives (before).** DNP3/20000 is framed in the clear (`lab/dnp3/dnp3lib.py` — link CRC is
integrity only, never confidentiality/authenticity). MQTT/1883 is plaintext with the 8883 TLS listener
commented out (`mosquitto.secure.conf` L15–24). `lab/mqtt/publisher.py` L14–15 ships hardcoded creds
(`sensor_svc:s3ns0r-pw`) that ride the cleartext CONNECT.

**CIE principles applied.** #3 Secure Information Architecture · #2 Engineered Controls · #4 Design
Simplification · #11 Engineering Information Control.

**Engineered control.** Encryption is a genuine `[SEC]` control here — but the CIE engineering
contribution is to ensure that *capturing cleartext yields no reusable authority*, so the plaintext
teaching mode stays safe by design:

- `[ENG]` **Anti-replay by construction.** A captured control frame must be inert on re-injection.
  SAv5's challenge/response carries a monotonic **Challenge Sequence Number (CSQ)**; combined with the
  **SELECT arm-timeout latch (W1)**, a sniffed OPERATE is useless without a fresh, matching, authentic
  SELECT. This is an engineered property (freshness), not just an encrypted pipe — it holds even if the
  pipe is deliberately left plaintext for ICSNPP visibility.
- `[ENG]` **Confine the cleartext to a monitored zone (CIE #5).** Plaintext DNP3 exists *only* on
  `cell_net`; the zones-and-conduits boundary (`zone-fw`, W3) means an eavesdropper needs a cell
  foothold before there is anything to sniff. Cleartext is not a global exposure, it is a
  zone-local one behind a monitored conduit.
- `[ENG]` **One-way telemetry egress (data-diode intent) on C2.** The historian/enterprise side reads
  values but the segment is engineered so those captured values cannot be turned into a downward command
  (`DIGITAL_TWIN §4.2` C2 "command/setpoint down is denied by design"). *(Category: One-Way
  Enforcement.)*
- `[SEC]` **DNP3-over-TLS / SAv5** and **MQTT 8883 mTLS** (uncomment the `mosquitto.secure.conf`
  8883 listener + certs). `[SEC]` stop shipping hardcoded creds — secrets management + rotation (this is
  also CWE-1393/798, §3 below).

**Twin demonstrates both.**

- **Before** `[NOW]`: Wireshark on `:1883`/`:20000` shows the CONNECT username/password, full JSON
  payloads, and well-formed control frames in clear; the very fact ICSNPP emits `mqtt_*.log` / `dnp3.log`
  proves plaintext (`conn.log` shows no TLS).
- **After** `[BUILD]`: swap `mosquitto.secure.conf` with the 8883 mTLS listener enabled → `conn.log`
  shows a TLS handshake, `mqtt_*.log` stops parsing (encrypted), creds no longer in pcap. Then **replay a
  captured OPERATE** → rejected by the SAv5 CSQ / expired SELECT latch, demonstrating that the
  *engineered* freshness control — not only the encryption — is what defeats replay.

---

### W3 — CWE-284 Improper Access Control / No Authorization *(+ CWE-1364 zone boundary)*

**Where it lives (before).** The insecure broker loads no ACL, so `lab/mqtt/attacker.py` L32
SUBSCRIBEs `#` (all topics) and L56 PUBLISHes to a command topic, both accepted. DNP3 `outstation.py`
applies no per-source authorization — a second "master" from a new IP is served alongside the real one.
`lab/docker-compose.yml` puts everything on one flat `otlan/24` (CWE-1364).

**CIE principles applied.** #3 Secure Information Architecture · #5 Resilient Layered Defenses · #4
Design Simplification · #6 Active Defense.

**Engineered control.** Authorization enforced by **structure**, not by hoping the app checks:

- `[ENG/SEC] ` **Zones-and-conduits segmentation, deny-by-default (IEC 62443-3-2).** `zone-fw`
  (nftables, `DIGITAL_TWIN §4.2`) routes all inter-zone traffic and permits only the named conduits:
  **C1** `scada-master ⇄ dnp3-gw` on tcp/20000 **only**; **C2** telemetry up; **C3** `eng-ws → openplc`.
  The adversary in the DMZ/enterprise has **no conduit into `cell_net`** — the DNP3/MQTT packet is
  dropped at `zone-fw` before the app ever sees it. Authorization is a property of the network topology.
- `[ENG]` **Data-diode / one-way concept on C2.** Telemetry flows up; **command and setpoint *down*
  from the cloud/broker are denied at the conduit** — so even a fully authenticated broker client cannot
  push actuation into the cell. The one-way rule is the engineered control; the ACL is the backup.
  *(Category: One-Way Enforcement.)*
- `[ENG/SEC]` **DNP3 master allow-list** at the conduit (bind the one master IP ⇄ outstation pair) and
  a **DNP3 link-address allow-list** in the outstation — a second source address is dropped, not
  answered.
- `[ENG]` **Active-Defense tripwire (CIE #6).** The `zone-fw` `CONDUIT-DROP` log line fires the instant
  an adversary probes `cell_net:20000` from a zone with no conduit — the "attack dies at the conduit,"
  now instrumented as a detection event fed to Zeek.
- `[SEC]` **MQTT `acl` file** (`lab/mosquitto/acl`): least privilege per identity — `hmi_operator`
  may only `read plant/+/telemetry`, `sensor_svc` may only `write` its own telemetry/status, **no rule
  grants `#`**, so full-broker eavesdropping is impossible even with valid creds.

**Twin demonstrates both.**

- **Before** `[NOW]`: on the flat `docker-compose.yml`, `attacker.py` `#`-subscribe + command publish
  succeed; two DNP3 masters are accepted. Zeek: `mqtt_subscribe.log topics` contains `#`;
  `dnp3.log` two distinct `id.orig_h` mastering outstation 10.
- **After** `[NOW→BUILD]`: `docker-compose.segmented.yml` already shows the attack **die at the
  conduit** — the DMZ attacker (`dnp3-attacker-dmz`) is dropped by inter-network isolation while the
  cell-adjacent one succeeds (the segmentation lesson today). The twin `[BUILD]` upgrades this to
  explicit `zone-fw` nftables with the `CONDUIT-DROP` tripwire and the C2 one-way rule, and swaps in
  `mosquitto.secure.conf` + `acl` so that **even from a granted cell foothold** the `#` subscribe and the
  command publish are refused by the ACL. Students see: same `attacker.py`, three outcomes — dropped at
  the conduit (structure), refused by the ACL (authorization), inert on C2 (one-way).

---

### W4 — CWE-290 Authentication Bypass by Spoofing *(spoofable DNP3 link addresses / data authenticity)*

**Where it lives (before).** `lab/dnp3/dnp3lib.py` L27–34 writes 16-bit src/dest link addresses into
every frame but nothing signs them (CRC is integrity only). `outstation.py` uses `src` only to address
the reply, never to authorize. `lab/dnp3/master.py` L72–76 exposes `--src-addr` to **forge the master's
link address (100)**; spoofed UNSOLICITED_RESPONSE (0x82) is accepted as truth → the Maroochy
rogue-master / loss-of-view pattern.

**CIE principles applied.** #3 Secure Information Architecture · #2 Engineered Controls · #6 Active
Defense · #10 Planned Resilience.

**Engineered control.**

- `[SEC]` **DNP3 Secure Authentication v5 — the definitive design-out of link-address spoofing.**
  SAv5 binds identity to *key-possession*: a forged OPERATE that merely claims `src=100` is rejected
  without the HMAC, and a spoofed 0x82 unsolicited without aggressive-mode auth is dropped. `--src-addr`
  becomes a dead primitive.
- `[ENG]` **The safety decision never trusts the network-reported value.** This is the control
  engineer's key move: the PLC's protective logic reads the **local LT-101 transmitter and the hardwired
  LSHH-102 float**, not the DNP3/MQTT-reported level. A spoofed "level = LOW / HLA = clear" telemetry
  stream cannot induce the do-nothing decision *at the control layer*, because the loop that starts the
  pumps and the float that force-starts them are wired to the physical instrument, not to the wire. Loss
  of *view* at the HMI is possible; loss of *control* is engineered out.
- `[ENG]` **Commanded-vs-reported cross-check (Active Defense, CIE #6).** The historian/PLC
  continuously compares reported PV against commanded pump state and the physics model; a reported level
  that diverges from `(inflow − pumped-outflow)` — e.g., "LOW" while pumps are commanded off and inflow
  is present — is flagged as a spoof tripwire and the logic falls back to the local sensor + float.
- `[ENG/SEC]` **Master allow-list at the conduit** binds the `scada-master ⇄ dnp3-gw` pair, so a rogue
  master from a new IP is dropped even before SAv5 evaluates.

**Twin demonstrates both.**

- **Before** `[NOW]`: `python master.py --host dnp3-gw --src-addr 100 --attack` from a rogue container
  is trusted as the master; a spoofed 0x82 stream makes the HMI read normal while the field diverges.
  Zeek: control / `0x82` from an unexpected `id.orig_h` claiming `src=100`; **commanded-state ≠
  reported-state** vs the historian baseline.
- **After** `[BUILD]`: with SAv5 enabled the forged frame is rejected (Zeek shows an **auth failure /
  no state change**); the conduit allow-list drops the rogue IP; and — critically — with the ST loop
  reading the *local* sensor + float, running the spoofed-telemetry attack still leaves the well pumping
  down (**spill = 0**), while the commanded-vs-reported monitor lights the tripwire. Students see that
  spoofing can blind the *view* but cannot move the *plant*.

---

### W5 — CWE-349 / CWE-807 Acceptance of Extraneous / Unvalidated Data in a Decision

**Where it lives (before).** `lab/dnp3/master.py` L22–48 `decode_response()` is a hand-rolled object
walker with no range/bounds/schema validation — it `struct.unpack`s attacker-controlled slices and
trusts whatever objects arrive; `outstation.py` L48 indexes `objs[5]` straight off the wire. Extraneous
objects appended to a RESPONSE are merged; the HMI/historian trust a forged level PV. Memory-safety
leaves CWE-121/125/787 live for a fuzzed frame against the tiny parser.

**CIE principles applied.** #3 Secure Information Architecture · #2 Engineered Controls · #4 Design
Simplification · #6 Active Defense.

**Engineered control.**

- `[ENG]` **Object / range allow-listing at the gateway (the RTU only speaks its own point map).**
  `dnp3-gw` accepts **only** the exact `DIGITAL_TWIN §5` point map — g1 idx 0–3, g30 idx 0–2, g12v1 idx
  0–1, g41 idx 0–1, with the expected qualifiers. Any group/variation/index/qualifier outside the map,
  or any **extraneous object appended to a RESPONSE**, is dropped and logged. Deterministic input
  validation by allow-list — the engineer's positive model of "what this device can legally say."
  *(Category: Physical/Digital Logic Mechanism.)*
- `[ENG]` **Engineering-unit range clamps + quality flags in PLC logic.** A level PV outside 0–100 %,
  a flow/psi outside its transmitter span, or a setpoint outside its band is **rejected/clamped and its
  quality bit set BAD** before it can drive any decision; the loop then uses last-good-value or the local
  sensor. CWE-807 is designed out because the safety decision consumes only range-checked,
  quality-flagged, cross-checked values — never a raw wire slice.
- `[ENG]` **Design simplification (CIE #4).** Disable unused DNP3 function codes and unsolicited
  responses if not needed — a smaller grammar is less to validate and less to fuzz.
- `[SEC]` **A bounded, schema-checked parser** at the FEP (reject short/oversized objects, validate
  counts against ranges) closes the CWE-121/125/787 memory-safety leaves; **SAv5** adds authenticity so
  the values are known-source as well as in-range.

**Twin demonstrates both.**

- **Before** `[NOW]`: feed a crafted frame with extraneous / out-of-map objects, or an out-of-range
  level, through `master.py` / into `outstation.py` — it is parsed and merged, and a deliberately
  malformed frame can desync the naive walker. Zeek `dnp3_objects.log` shows `object_type` / range
  inconsistent with the published point map.
- **After** `[BUILD]`: the `dnp3-gw` allow-list rejects the out-of-map object (Zeek logs the rejected
  object vs the point map), the ST clamp marks the out-of-range PV quality-BAD and the loop falls back to
  the local sensor + float (**spill = 0**), and the bounded parser rejects the fuzzed frame cleanly
  instead of crashing. Run the naive vs hardened parser on the same malformed pcap for the contrast.

---

### W6 — CWE-693 / CWE-807 Reliance on a Single Software Interlock *(the thesis of the lab)*

**Where it lives (before).** The PLC's protective logic — HLA, dead-head, dry-run, deadband loop
(`DIGITAL_TWIN §1.2`) — is **software**, and every input is reachable by a **g41 Analog Output WRITE**
(or MQTT `setpoint`): push `LEAD_START` above 100 % and the loop never commands a start, silently
defeating the one layer that would have protected the well. This is the Oldsmar "modify parameter" move
(`WEAKNESS_ANALYSIS §2.6`). One register write = one catastrophe **if safety relies on that single
software layer.**

**CIE principles applied.** #2 Engineered Controls · #5 Resilient Layered Defenses (Swiss-cheese) · #10
Planned Resilience (the "even-if" test) · #1 Consequence-Focused.

**Engineered control — independent, non-digital layers that turn CWE-693 from catastrophic to bounded.**

- `[ENG]` **Hardwired high-high float LSHH-102, wired in series with the standby-pump starter.** At
  95 % it energizes the pump + horn **regardless of `%QX` coils, DNP3 g41, or MQTT** (`DIGITAL_TWIN §1.3`,
  §7.3). No packet overrides a dry contact in the starter circuit. This is the single most important
  control in the entire kit — the eliminate/substitute-tier layer. *(Category: Physical Logic Mechanism /
  Fail-Safe Default.)*
- `[ENG]` **Setpoint range clamp in the ladder — the writable register is bounded by logic the write
  cannot change.** `LEAD_START` is hard-limited in ST to a safe engineering band (e.g., 40–85 %); a g41
  write of 150 % is clamped to 85 %. The "modify parameter" move cannot push the start point out of
  reach because the bound lives in code, not in the register. *(Category: Physical Constraint / Digital
  Engineered Control.)*
- `[ENG]` **Independent trip + passive release layers.** Motor-protection relay (49/50) + VFD
  low-flow trip cap dead-head/dry-run at a setpoint no register overrides; the **mechanical overflow
  weir → equalization basin** bounds the release path as the last resort (`DIGITAL_TWIN §7.3`). Three
  independent layers (float, relay, weir), at least one non-digital — Swiss-cheese with a slice no cyber
  attack can align. *(Categories: Redundant Design, Passive Physical Dynamics.)*
- `[ENG]` **Comms-loss safe state (fail-operational, CIE #10).** On loss of master/broker the PLC
  holds last-safe setpoints and keeps pumping locally — an explicit "even-if" guarantee.
- `[SEC]` **g41 write behind SAv5 + the conduit; MQTT `setpoint`-down denied on C2** (data diode) so
  the register cannot be written from the cloud at all.

**Twin demonstrates both — this is the CIE "even-if" acceptance test (DB-1, `DIGITAL_TWIN §7.3`).**

- **Before** `[NOW→BUILD]`: run the full `§7.1` chain with full write access — `--attack` writes
  `LEAD_START > 100 %` (or MQTT `setpoint`), pumps never start, level climbs past HLA and the weir →
  **spill increments (SSO)**, and step-1 spoofing masks the HMI. Toggle `FLOAT_ENABLED=false` in
  `plant-sim` to show the unbounded consequence with the backstop removed.
- **After** `[BUILD]`: the ST clamp refuses > 85 % (Zeek shows the g41 write **outside the engineering
  band** as a tripwire, but `plant-sim` shows the setpoint clamped); and even if a student *deletes the
  clamp*, with `FLOAT_ENABLED=true` the **hardwired float force-starts the pump at 95 % → spill stays
  0**. The pass criterion is exact: **run the entire attack chain with full DNP3 + MQTT write access and
  the well still pumps down at the float.** The weakness is present by construction; the analog layer is
  why HCE-1 stays bounded.

---

## 3. Supporting weaknesses — designed out

| CWE | Where (before) | CIE principle | Engineered control (after) | Twin before/after |
|---|---|---|---|---|
| **CWE-1364 Zone Boundary Failures** | `docker-compose.yml` flat `otlan/24` | #5 Layered Defenses | `[ENG]` `zone-fw` deny-by-default zones+conduits (W3) | flat vs `docker-compose.segmented.yml` `[NOW]` → `zone-fw` twin `[BUILD]` |
| **CWE-1393 / CWE-798 Default / Hard-coded Credentials** | `publisher.py` L14–15 `sensor_svc:s3ns0r-pw`, `subscriber.py`, compose env | #9 Supply Chain · #11 Eng. Info Control | `[SEC]` per-client secrets, rotation, no creds in image; `[SEC]` procurement bans hardcoded creds | hardcoded `[NOW]` → env/secret-injected + rotated `[BUILD]` |
| **CWE-276 Incorrect Default Permissions** | insecure broker = anonymous + world topic tree | #3 Secure Info Arch. | `[SEC]` `mosquitto.secure.conf` + `acl` least privilege | `insecure.conf` vs `secure.conf`+`acl` `[NOW]` |
| **CWE-287 / CWE-288 Improper Auth / Auth Bypass via Alternate Path** | eng path (`eng-ws→openplc` 8080/502) + DNP3 control path admit anyone who reaches the port | #3 · #5 | `[ENG]` auth beyond network reachability: C3 conduit binds `eng-ws→openplc` only; `[SEC]` SAv5 on control; signed logic (below) | flat reachability `[NOW]` → C3 conduit + SAv5 `[BUILD]` |
| **CWE-494 Download of Code Without Integrity Check** | PLC logic / outstation config pushed over C3 unsigned | #2 Engineered Controls · #9 Supply Chain | `[SEC]` sign + verify ST/logic downloads on the twin before field; `[ENG]` load-enable keyswitch models a hardware run/program interlock | unsigned push `[NOW]` → verified/keyswitched load `[BUILD]` |

---

## 4. Master crosswalk — weakness → CIE principle → engineered control → cyber complement → twin variant

| # | Weakness (CWE) | CIE principle(s) | `[ENG]` engineered control (leads) | `[SEC]` cyber complement | Before / After in the twin |
|---|---|---|---|---|---|
| W1 | 306 Missing Auth for Critical Fn | #2,#5,#10,#1 | SELECT-before-OPERATE arm-latch in logic; refuse DIRECT_OPERATE; stop-while-rising interlock; **hardwired float**; drop MQTT command path | DNP3 **SAv5** HMAC; MQTT `allow_anonymous false`+passwd | `outstation.py`/`pump-controller.py` obey `[NOW]` → `--enforce-select`+ST interlock+`secure.conf` `[BUILD]`; spill 0 |
| W2 | 319/311 Cleartext / No Encryption | #3,#2,#4,#11 | anti-replay by SAv5 CSQ + SELECT arm-timeout; confine cleartext to `cell_net`; one-way C2 egress | DNP3-over-TLS/SAv5; **MQTT 8883 mTLS**; kill hardcoded creds | plaintext parse `[NOW]` → 8883 mTLS + replay-rejected `[BUILD]` |
| W3 | 284 No Authorization (+1364) | #3,#5,#4,#6 | **zones-and-conduits deny-by-default**; **data-diode C2**; DNP3 master/link allow-list; CONDUIT-DROP tripwire | MQTT **`acl`** least privilege; broker auth | flat `[NOW]` → `segmented.yml` `[NOW]` → `zone-fw`+`acl` `[BUILD]` |
| W4 | 290 Spoofing (link addr / authenticity) | #3,#2,#6,#10 | safety decision reads **local sensor + float**, never the wire; commanded-vs-reported tripwire; master allow-list | DNP3 **SAv5** (key-possession) | `--src-addr 100 --attack` trusted `[NOW]` → SAv5 rejects + plant unmoved `[BUILD]` |
| W5 | 349/807 Extraneous / unvalidated data | #3,#2,#4,#6 | **object/range allow-list at gateway**; EU range clamps + quality flags; disable unused FCs | bounded schema-checked parser; SAv5 authenticity | naive walker merges `[NOW]` → allow-list rejects + clamp `[BUILD]` |
| W6 | 693/807 Single software interlock | #2,#5,#10,#1 | **hardwired HH float**; **setpoint clamp in ladder**; motor-protection + weir; comms-loss safe state | g41 behind SAv5+conduit; setpoint-down denied on C2 | `--attack` LEAD_START>100%→SSO `[NOW/BUILD]` → clamp+float→spill 0 `[BUILD]` |

---

## 5. Hierarchy-of-controls placement (why this is engineering, not IT bolt-on)

| Hierarchy tier (`research_cie.md §3 #2`) | Controls in this design | Holds when the network is fully owned? |
|---|---|---|
| **Eliminate / Substitute** | remove MQTT command path; hardwired float makes overflow physically self-correcting | **Yes** |
| **Engineered (hardwired / analog / deterministic logic)** | float, setpoint clamp, stop-interlock, SELECT arm-latch, object allow-list, motor-protection relay, weir, one-way C2, local-sensor safety decision | **Yes** (non-digital + logic that the write can't reach) |
| **Administrative** | procurement bans on hardcoded creds/undisclosed features; CIE gate in Definition of Done | partial |
| **Add-on cybersecurity (last)** | DNP3 SAv5, MQTT mTLS/ACL, zone-fw allow-lists, bounded parser, Zeek/ICSNPP tripwires | No — assumes it *will* be bypassed |

The design deliberately loads the top two tiers. Every add-on cyber control is there to keep the
attacker far from the backstop and to *detect* the attempt — but **DB-1 is satisfied by the engineered
tiers alone**, which is the CIE thesis and the twin's acceptance test.

---

## 6. How the twin ships both variants (build mechanics)

The before/after contrast is not a slide — it is a runnable toggle, so students execute the identical
attack against each:

1. **MQTT broker** `[NOW]` — swap `mosquitto.insecure.conf` ↔ `mosquitto.secure.conf` (+`acl`, +8883
   mTLS). Re-run `attacker.py`; watch CONNECT/`#`/publish flip from accepted to refused.
2. **Segmentation** `[NOW→BUILD]` — `docker-compose.yml` (flat) → `docker-compose.segmented.yml`
   (2-zone conduit, already shows "attack dies at the conduit") → `docker-compose.twin.yml` with the
   explicit `zone-fw` nftables + `CONDUIT-DROP` tripwire and the one-way C2 rule.
3. **DNP3 gateway** `[BUILD]` — an `--enforce-select` / `--allowlist` / `--sav5` hardened mode on
   `dnp3-gw` vs the current obey-on-request `outstation.py`. Same `master.py --attack` / `--src-addr`
   scripts run against both.
4. **PLC logic** `[BUILD]` — two OpenPLC ST programs: the naive loop (`DIGITAL_TWIN §1.2`) vs the
   hardened loop (SELECT arm-latch, stop-interlock, setpoint clamp, EU range/quality checks, local-sensor
   safety decision, comms-loss safe state).
5. **Physical backstop** `[BUILD]` — a `FLOAT_ENABLED` (and `WEIR_ENABLED`) toggle in `plant-sim` so
   students watch HCE-1 occur with the hardwired float removed and stay bounded with it wired in — the
   most important single before/after in the kit.

**Objective scoreboard for every exercise:** the `plant-sim` **spill counter** and the Zeek
`dnp3_control.log` / `dnp3_objects.log` / `mqtt_*.log`. **Pass = spill 0 under full DNP3+MQTT write
access** (DB-1) — the same "even-if" acceptance test in `DIGITAL_TWIN §7.3`, now attached to each
weakness's hardened variant.

---

## 7. Provenance / caveats

- CIE principles, guiding questions, hierarchy of controls, engineered-controls categories, the
  "even-if" test — `design/research_cie.md` (verified against DOE/CESER + INL primary sources).
- Weakness inventory, CWE-1358 mappings, file:line evidence, ATT&CK-for-ICS — `design/WEAKNESS_ANALYSIS.md`
  and the substrate it cites (`lab/dnp3/*.py`, `lab/mqtt/*.py`, `lab/mosquitto/*`, `lab/docker-compose*.yml`).
- Twin topology, point maps, conduits, attack chain, analog backstops, spill counter — `design/DIGITAL_TWIN_ARCHITECTURE.md`.
- `[NOW]` controls (`mosquitto.secure.conf`, `acl`, `docker-compose.segmented.yml`) exist in `lab/`
  today; `[BUILD]` controls (SAv5, `zone-fw` nftables, hardened `dnp3-gw` modes, hardened OpenPLC ST
  program, `plant-sim` `FLOAT_ENABLED` toggle) are net-new for the twin build (`DIGITAL_TWIN §9`).
- **Scoping honesty:** logic-enforced SELECT-before-OPERATE and object allow-listing raise the bar and
  kill single-packet injection but are not identity authentication; SAv5 supplies that, and the
  hardwired/analog layers bound the consequence when both are defeated. No single control is claimed
  sufficient alone — that layering is the point (CIE #5). DNP3-over-TLS/SAv5 and MQTT mTLS reduce
  ICSNPP visibility, so the twin keeps a plaintext mode for the parsing curriculum and hardened modes for
  the contrast — a documented teaching trade-off, not a security recommendation for production.
