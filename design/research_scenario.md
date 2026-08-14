# Research: The ICS Scenario for the Digital Twin — Water Sector Lift Station (DNP3 + MQTT)

**Author:** Researcher (Electrical Engineers 17-2071.00 lens), ICS digital-twin Scrum
**Date:** 2026-08-14
**Purpose:** Propose **ONE** realistic, well-scoped ICS scenario for the DNP3/MQTT twin, grounded in
a real sector and a CyOTE-style *consequence of concern*, and buildable in the kit's existing
containers. Describe the physical process, field devices, the PLC control loop, the DNP3 + MQTT
data flows, and the consequence an attacker would target.

> **Provenance / no-fabrication note.** Sector facts (DNP3 in water/wastewater, lift-station control
> loop, field devices, pump-failure physics, the SSO consequence, ICSNPP log outputs, Sparkplug B)
> are each cited to a named external source, verified via web fetch during this pass (Aug 2026). The
> CyOTE case anchors (Maroochy, Oldsmar) reuse the already-verified `design/research_cyote.md`. Point
> indices, tag names, and setpoint numbers are *engineering choices for the twin* (labeled
> `[TWIN]`) — realistic and internally consistent, but not quoted from any one plant. Nothing here is
> weaponized; attacker steps are described at the protocol-observable level for a defensive lab.

---

## 0. The scenario in one paragraph

**A remote municipal wastewater LIFT STATION (a "pump + wet-well tank" station).** A below-grade
**wet well** collects sewage by gravity; a PLC runs closed-loop **level control** over two
duty/standby submersible pumps that push flow into a pressurized **force main**. The station's
**RTU/PLC is a DNP3 outstation** that reports to the utility's **central SCADA master** over
DNP3/TCP-20000 (report-by-exception + unsolicited events), and an **IIoT gateway publishes the same
telemetry to a cloud condition-monitoring platform over MQTT/1883** (`plant/tank1/#`, plain-JSON
default; Sparkplug B as a realism upgrade). The **consequence of concern** is a **wet-well overflow →
sanitary sewer overflow (SSO)**, a raw-sewage release — reached by an attacker who **manipulates pump
control and/or spoofs level telemetry** so the pumps stay off (or run dry / dead-head) while the HMI
shows "normal." This is the **Maroochy Shire** consequence, recreatable frame-for-frame in the kit's
existing DNP3 + MQTT containers. A **potable booster-station variant** (same twin, relabeled to an
elevated storage tank) yields the alternative consequences of **tank overflow, loss of pressure, and
pump dead-head / water hammer**.

**Why this one (scoping rationale).**
- **It unifies both kit protocols into ONE physical process.** Today the kit ships a DNP3 substation
  *and* an unrelated MQTT tank. A lift station legitimately carries **both**: DNP3 to the utility
  SCADA (the regulated real-time control path) and MQTT to a vendor/utility cloud (the IIoT
  condition-monitoring path). That is exactly how modern water utilities run remote stations.
- **It has a genuine closed PLC control loop** (wet-well level → duty/standby pump start/stop with a
  deadband) — cleaner than a distribution feeder, which is protection (recloser/relay), not a loop.
- **It has a strong, regulated, CyOTE-anchored consequence** (SSO; EPA point-source violation) with
  two documented water case studies to teach against (**Maroochy 2000**, **Oldsmar 2021**).
- **It re-skins, not rebuilds, the existing lab** — `plant/tank1/*`, `pump-controller.py`, the DNP3
  outstation's CROB/analog handling, Zeek+ICSNPP, and the capture sidecars all already exist.

---

## 1. Physical process (the plant)

A wastewater collection network moves sewage downhill by gravity, but terrain forces periodic
**re-lifts**: a **lift (pumping) station** collects inflow in a **wet well** and pumps it up/onward
into a **force main** to the next gravity reach or the treatment works.

- **Wet well ("the tank"):** a sealed below-grade concrete chamber, ~3.0 m usable depth `[TWIN]`.
  Inflow is uncontrolled (diurnal + storm-driven); outflow is the pumps. If inflow > pumping for long
  enough, the well fills to the top and **overflows** — the consequence of concern.
- **Duty/standby submersible pumps (2×):** e.g., ~50 hp, ~1,500 gpm each `[TWIN]`; normally one runs
  ("lead/duty"), the second ("lag/standby") assists on high inflow or covers a duty failure. They
  discharge through check valves + isolation valves into a common **force main** (pressurized pipe).
- **Force main:** carries flow under pressure; a **check valve** at each pump prevents backflow and
  is a first line against **water hammer** on pump stop.
- **Overflow / relief path:** a permitted **emergency overflow weir** to an equalization basin is the
  engineered last resort; if it too is exceeded, sewage escapes to ground/waterway (an **SSO**).

The wastewater lift-station process and its two-setpoint pump control are described by DwyerOmega and
AutomationDirect (see §8). The **SSO** consequence — "sanitary sewers will release raw sewage,"
caused among other things by "power failures and equipment malfunctions," able to "back-up into homes"
and "contaminate our waters" — is defined by **US EPA**, which estimates **23,000–75,000 SSOs/year**
in the U.S.

---

## 2. Field devices (the instrument & electrical list) `[TWIN tags]`

An Electrical Engineer (17-2071.00) specifying this station's controls would schedule roughly:

| Tag | Device | Type / signal | Role in the loop |
|---|---|---|---|
| **LT-101** | Wet-well **level transmitter** | Submersible **hydrostatic/piezoresistive**, 4–20 mA, 0–3 m | Primary process variable (the level the PLC controls). DwyerOmega Series **PBLT2/SBLT2** are exactly this class of device. |
| **LSHH-102** | **High-high float switch** | Direct-wired dry contact | **Hardwired backstop** — see §6. Independent of the PLC. |
| **LSL-103** | **Low-level float switch** | Direct-wired dry contact | Dry-run / pump-off cutout, independent of LT-101. |
| **FIT-104** | Force-main **flow meter** | Magnetic flow, 4–20 mA | Confirms pumps are actually moving flow (dead-head / dry-run detection). |
| **PIT-105** | Discharge **pressure transmitter** | 4–20 mA | High pressure ⇒ closed valve / dead-head; low ⇒ loss of prime. |
| **P-1 / P-2** | Submersible **pump motors** | 3-phase, via **VFD or soft-starter** | The actuators the PLC starts/stops. |
| **49/50 (MPR)** | **Motor-protection relay** | thermal overload, phase-loss, underload | Trips a pump on electrical fault; underload ≈ dry-run. |
| **ATS + genset** | Automatic transfer switch + standby generator | discrete status to PLC | Power resilience; a power loss is a top SSO cause (EPA). |
| **RTU/PLC** | Station controller | **DNP3 outstation, TCP/20000**; runs the loop | The brain — §3, §4. |
| **GW** | **IIoT gateway** | **MQTT client, TCP/1883** | Publishes telemetry to cloud — §5. (May be the PLC itself.) |

Class I Div 1 (explosive gas) applies inside a sewage wet well, so the level transmitter and floats
are **intrinsically safe** — an authentic electrical-design detail, not load-bearing for the twin.

---

## 3. The control loop the PLC runs (autonomous, local)

Textbook **wet-well level control** with a **deadband** (DwyerOmega: a *"programmable level
differential enables accurate on/off control to reduce excessive pump cycling"*), **duty/standby
alternation**, a **high-level alarm**, and **dry-run / dead-head protection**. Setpoints `[TWIN]`
(as % of 3.0 m usable):

```
INPUTS:  LT-101 level%  ;  FIT-104 flow_gpm  ;  PIT-105 psi  ;  LSHH-102, LSL-103 floats
OUTPUTS: P-1, P-2 start/stop (+ VFD speed, optional)

Setpoints:  LAG_START=80%   LEAD_START=60%   STOP=20%   LOWCUT=10%   HLA=90%   HHLL(float)=95%

scan (every 500 ms):
  level = LT-101
  if level >= LEAD_START:   start(lead_pump)                 # begin pumping down
  if level >= LAG_START:    start(lag_pump)                  # both pumps on heavy inflow
  if level <= STOP:         stop(all_pumps); alternate_lead()  # equalize wear each cycle
  if level <= LOWCUT or LSL-103==WET==False: inhibit_start   # DRY-RUN protection
  if a_pump_running and flow_gpm < MIN_FLOW and psi > HI_PSI: # DEAD-HEAD protection
        trip_that_pump; raise_alarm                          # closed valve / blockage
  if level >= HLA:          set HIGH_LEVEL_ALARM (DNP3 BI, MQTT alarm)
  # comms-loss safe behavior: keep running THIS loop locally on last-known setpoints
  #   (fail-operational locally); never depend on the master/broker to pump the well down.
```

Key properties the twin should teach: the loop is **autonomous** (the station pumps the well down even
with SCADA/broker unreachable), the **deadband** (LEAD_START 60% vs STOP 20%) prevents short-cycling,
**alternation** equalizes pump wear, and **dry-run/dead-head interlocks** protect the pumps. The
central SCADA master normally only **supervises and adjusts setpoints** — it does not pump the well.

---

## 4. DNP3 data flow (station RTU ⇄ utility SCADA master)

**Why DNP3 here:** water/wastewater utilities run DNP3 from remote stations to a central master
because of **report-by-exception**, **unsolicited (device-initiated) event reporting**, and
**time-stamped data with per-point quality flags** (online/offline, local-forced, restart,
out-of-range) — Automation World, "DNP3 for Water/Wastewater SCADA Systems." One outstation can
report to **multiple masters**.

**Roles:** `dnp3-outstation` = the lift-station RTU/PLC (**outstation addr 10**, TCP/20000);
`dnp3-master` = the utility central SCADA. Media in the field is typically licensed radio, cellular,
or fiber; in the twin it is the `otlan` bridge network.

**Point map `[TWIN]` — remap the kit's canned outstation values to water semantics** (same DNP3
machinery already in `lab/dnp3/outstation.py`, new labels):

| DNP3 object | Idx | Point | Notes |
|---|---|---|---|
| **g1 Binary Input** (status) | 0 | P-1 run | duty pump running |
| | 1 | P-2 run | standby pump running |
| | 2 | **High-level alarm (HLA)** | the key "view" bit an attacker spoofs |
| | 3 | Pump fault / E-stop | |
| **g30 Analog Input** (measure) | 0 | **Wet-well level %** (LT-101) | the primary PV; spoof target |
| | 1 | Force-main flow gpm (FIT-104) | |
| | 2 | Motor current / discharge psi | |
| **g12v1 CROB** (Control Relay Output Block) | 0 | **P-1 start/stop** | binary control — TRIP/CLOSE = stop/start |
| | 1 | **P-2 start/stop** | |
| **g41 Analog Output** (setpoint) | 0 | **LEAD_START setpoint** | the "Modify Parameter" (Oldsmar) target |
| | 1 | STOP setpoint | |

**Normal traffic (already in the kit):** master **integrity poll** — `READ` (app func **0x01**) of
**Class 1,2,3,0**; outstation **RESPONSE 0x81** with g1/g30 data; **unsolicited RESPONSE 0x82** on a
new HLA event (report-by-exception). Supervised control uses **SELECT 0x03 → OPERATE 0x04** (or
**DIRECT_OPERATE 0x05**) of a **g12v1 CROB**; setpoint changes write **g41**. Availability abuse uses
**COLD_RESTART 0x0D** (the outstation already handles this). Function/object references match
`design/research_cyote.md` and `lab/dnp3/dnp3lib.py`.

**What Zeek+ICSNPP shows (verified, cisagov/icsnpp-dnp3):** `dnp3.log` plus **`dnp3_control.log`**
(fields `block_type` = Control_Relay_Output_Block, `function_code` = SELECT/OPERATE/RESPONSE,
`index_number`, **`trip_control_code`** = Nul/Close/**Trip**, `operation_type` = Latch_On/Latch_Off/
Pulse_On…, `status_code`) and **`dnp3_objects.log`** (`function_code`, `object_type`, `range_low/high`)
— exactly the logs already in `lab/zeek_reference_output/dnp3/`.

---

## 5. MQTT data flow (IIoT gateway → cloud condition-monitoring)

**Why MQTT here (real pattern):** utilities increasingly bolt an **IIoT gateway/cloud** onto remote
stations for pump condition monitoring, energy, and remote visibility (ControlByWeb, ThingsLog,
Neteon, NFM Consulting). It rides **alongside** DNP3, not replacing it — DNP3 stays the control path,
MQTT is the observe/analytics path. Broker = `eclipse-mosquitto:2` on **TCP/1883** (already in the
kit).

**Topic tree `[TWIN]` — reuse the kit's `plant/tank1/*` exactly** (`publisher.py`,
`pump-controller.py`, `subscriber.py` already speak these):

| Topic | Dir | QoS | Payload (JSON) |
|---|---|---|---|
| `plant/tank1/telemetry` | GW → cloud | 0/1 | `{"level_pct":42,"flow_gpm":1490,"p1":"RUN","p2":"STOP","psi":31}` |
| `plant/tank1/status` | GW → cloud | 1, retained | pump/alarm/health |
| `plant/tank1/setpoint` | cloud → GW | 1 | `{"lead_start":60,"stop":20}` — the **Oldsmar** analog |
| `plant/tank1/command` | cloud → GW | 1 | `{"actuator":"pump1","cmd":"STOP"}` — the actuator `pump-controller.py` **already obeys** |

**Default = plain JSON** (fully human-readable; Zeek's MQTT analyzer emits `mqtt_publish.log` /
`mqtt_subscribe.log` / `mqtt_connect.log`, as in `lab/zeek_reference_output/mqtt/`). **Realism upgrade
= Sparkplug B** (Eclipse **Sparkplug 3.0.0**): topic namespace `spBv1.0/<group>/NBIRTH|DBIRTH|NDATA|
DDATA|NDEATH/<edge_node>/<device>` with **birth/death** state semantics. **Accuracy caveat (teaching
point, not a bug):** Sparkplug payloads are **Google-Protobuf-encoded**, so Zeek's MQTT analyzer parses
the **MQTT envelope + topic string** (you *see* `spBv1.0/.../NDATA/...`) but **does not decode the
protobuf body** — keep the twin on **JSON by default** for full wire-readability, and use Sparkplug as
an optional "what real IIoT looks like" mode.

---

## 6. The consequence of concern (CyOTE-style) + the attack that reaches it

**Consequence of concern (the "triggering event"):** **wet-well OVERFLOW → Sanitary Sewer Overflow
(SSO)** — an uncontrolled release of **raw sewage** (EPA point-source violation; public-health and
environmental harm). This is the **Maroochy Shire (2000)** consequence: a rogue master on a sewage
SCADA network issued unauthorized commands and **spoofed pumping-station telemetry**, spilling
**~800,000 L of sewage** over ~3 months (CyOTE case study, `research_cyote.md`).

**The attack, at the wire-observable level (buildable now):**
1. **Loss of view / spoof reporting** — attacker floods **spoofed DNP3 `0x82` unsolicited responses**
   reporting **level = LOW** and **HLA = clear**, and **publishes spoofed `plant/tank1/telemetry`**
   with `level_pct` low → the HMI shows "normal." *(ATT&CK for ICS: **T0856 Spoof Reporting Message**,
   **T0829 Loss of View**.)*
2. **Manipulation of control** — attacker sends **CROB OPERATE/DIRECT_OPERATE (0x04/0x05)** to **stop
   both pumps** (and/or **MQTT `plant/tank1/command` `{"cmd":"STOP"}`**, which `pump-controller.py`
   already executes). *(**T0855 Unauthorized Command Message**, **T0831 Manipulation of Control**.)*
3. **Modify parameter (Oldsmar variant)** — instead of stopping pumps, **write g41 / publish
   `plant/tank1/setpoint`** to push **LEAD_START above 100%** so the pumps *never* start, or push
   **STOP below 0%** so a running pump **dry-runs / dead-heads**. *(**T0836 Modify Parameter**.)*
4. **Result:** inflow keeps arriving, pumps stay off, level rises past HLA and the overflow weir →
   **SSO**. The operator perceives nothing because step 1 masked the view. *(**T0826 Loss of
   Availability** of the collection system; safety/enviro impact.)*
   Optional availability escalation: **DNP3 `0x0D COLD_RESTART`** of the RTU (kit outstation already
   simulates this).

**Alternative consequence (potable booster variant, same twin relabeled):** commanding a pump ON
against a closed discharge, or setpoints that starve suction, causes **dead-heading** — "the water
temperature will…rise because of the friction…," seals "shatter, crack, score," and overpressure can
even cause failure (Hayes Pump); **dry-running** adds cavitation; abrupt pump/valve changes cause
**water hammer**. Storage-tank overfill is the direct **overflow** analog.

**Perception → detection → attribution table (CyOTE, for the twin):**

| Observable (DNP3/MQTT) | Anomaly | ATT&CK-for-ICS | Phase |
|---|---|---|---|
| Second DNP3 source to outstation 10; control from an IP that never controlled before | Rogue master / wrong source | T0848, T0855 | Middle |
| `0x82` unsolicited from unexpected src; reported level ≠ commanded/expected | Spoofed view | T0856, T0829 | Middle→Late |
| CROB `Trip`/stop on both pumps with no work order; command-rate spike | Manip. of control | T0831, T0806 | Late |
| g41 / `plant/tank1/setpoint` write outside engineering band | Modify parameter | T0836 | Late |
| MQTT client publishing to `command`/`setpoint`, or SUBSCRIBE `#` | Rogue publisher/harvest | T0831, T0802 | Middle |
| `0x0D` cold restart | Availability | T0816 | Impact |

---

## 7. Engineered / analog backstops (CIE — so the HCE is bounded regardless of packets)

Per `design/research_cie.md` (principles #2 Engineered Controls, #5 Layered, #10 Planned Resilience),
the twin should teach that a **non-digital layer** holds *even if* DNP3+MQTT are fully owned:
- **Hardwired high-high float (LSHH-102) wired directly to the pump starter** — starts the standby
  pump (and local horn) at 95% **independent of the PLC/DNP3/MQTT**. Spoofing the network cannot
  suppress it. *(This is the single most important backstop against the §6 attack.)*
- **Mechanical overflow weir to a permitted equalization basin** — bounds the release path.
- **Motor-protection relay underload + VFD dry-run/low-flow trip** — caps dead-head/dry-run damage at
  a setpoint no register can override.
- **Check valves** on each pump — mitigate water hammer.
- **Data-diode / read-only egress** on the MQTT/historian path — observe the station, never command it
  from the cloud side; **DNP3 Secure Authentication (SAv5)** on control functions; **MQTT mTLS + ACLs**
  so field devices publish telemetry only and `command`/`setpoint` topics reject wildcard/foreign
  publishers. (Ties directly to the kit's `mosquitto.secure.conf` / `acl` and the SAv5 lesson.)

Acceptance test (CIE #10 "even-if"): run the §6 attack with full DNP3+MQTT write access — the well
**still** pumps down at the high-high float and cannot cause an unbounded SSO.

---

## 8. Buildability — maps 1:1 onto existing containers (re-skin, don't rebuild)

Everything below already exists in `lab/docker-compose.yml`; the scenario is a **relabel + a control
loop**, not new infrastructure:

| Twin element | Existing service / file | Change needed |
|---|---|---|
| Broker | `broker` (eclipse-mosquitto:2, 1883/8883) | none |
| Wet-well level/flow sensor | `mqtt-publisher` → `publisher.py` | relabel fields to `level_pct/flow_gpm/p1/p2` |
| **PLC control loop + actuator** | `pump-controller` → `pump-controller.py` | add the §3 level loop; honor `setpoint` |
| HMI dashboard | `mqtt-subscriber` → `subscriber.py` | none |
| Telemetry/command spoofer | `mqtt-attacker` → `attacker.py` (profile `attack`) | add spoofed-low-level publish |
| Lift-station RTU (DNP3) | `dnp3-outstation` → `outstation.py` | remap BINARY/ANALOG to §4 points; add g41 setpoints |
| Central SCADA master | `dnp3-master` (profile `tools`) | none |
| Rogue master (own IP) | `dnp3-attacker` (profile `attack`) | none — "wrong source" detection already fires |
| Passive analyzer | `zeek` + ICSNPP (profile `tools`) | none — emits `dnp3_control.log`, `dnp3_objects.log`, `mqtt_*` |
| Capture sidecars | `sniff-dnp3`, `sniff-mqtt` (profile `capture`) | none |
| Segmentation lab | `docker-compose.segmented.yml` | none — reuse for the IEC-62443 zone story |

Container topology stays: everything on `otlan` (172.28.0.0/24). One coherent lift station now spans
**DNP3/20000** (control path) and **MQTT/1883** (IIoT path), and a single planted attack produces the
SSO consequence on both wires — captured, parsed by ICSNPP, and detectable at kit Levels 3–4.

---

## 9. Sources (verified live, Aug 2026)

DNP3 in water/wastewater SCADA
- Automation World — *DNP3 for Water/Wastewater SCADA Systems* — https://www.automationworld.com/process/water-wastewater/article/13306838/dnp3-for-water-wastewater-scada-systems
- DNP3 (protocol overview) — https://en.wikipedia.org/wiki/DNP3

Lift-station process, control loop & field devices
- DwyerOmega — *Pump Controllers and Level Transmitters Automate Wastewater Lift Stations* — https://www.dwyeromega.com/en-us/resources/pump-controller-with-level-transmitter-control-pumps-in-wastewater-lift-stations
- DwyerOmega — *Lift Station Level Sensing* — https://www.dwyeromega.com/en-us/resources/lift-station-level-sensing
- AutomationDirect (Library) — *PLCs Give Wastewater Pumping Stations a Lift* — https://library.automationdirect.com/plcs-give-wastewater-pumping-stations-a-lift-issue-19-2011/
- NFM Consulting — *Lift Station Automation 101: Controls, Alarms, and Remote Monitoring* — https://www.nfmconsulting.com/knowledge/lift-station-automation-controls-remote-monitoring/

MQTT / IIoT cloud path & Sparkplug B
- Eclipse — *Sparkplug 3.0.0 Specification* (PDF) — https://sparkplug.eclipse.org/specification/version/3.0/documents/sparkplug-specification-3.0.0.pdf ; spec hub — https://sparkplug.eclipse.org/specification/
- ControlByWeb — *Water/Wastewater Remote Measurement* — https://controlbyweb.com/industries/water-wastewater/
- Neteon — *IoT Gateway for Wastewater Treatment Remote Monitoring* — https://www.neteon.net/neteon-blogs/iot-gateway-for-wastewater-treatment-remote-monitoring
- NFM Consulting — *Ignition MQTT and Sparkplug B Integration* — https://nfmconsulting.com/knowledge/ignition-mqtt-sparkplug-b-integration/

Consequence of concern
- US EPA — *Sanitary Sewer Overflows (SSOs)* — https://www.epa.gov/npdes/sanitary-sewer-overflows-ssos
- Hayes Pump — *How to Protect Centrifugal Pumps From Deadheading* — https://blog.hayespump.com/blog/centrifugal-pump-deadheading
- Water Online — *Protecting Pumps From Dead-Head Conditions* — https://www.wateronline.com/doc/protecting-pumps-from-dead-head-conditions-0001
- CyOTE case studies (Maroochy, Oldsmar) — via `design/research_cyote.md`:
  https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Maroochy.pdf ·
  https://cyote.inl.gov/content/uploads/24/2025/12/CyOTE-Case-Study_Oldsmar.pdf

Analysis tooling (what the twin observes)
- CISA ICSNPP — https://github.com/cisagov/ICSNPP · https://www.cisa.gov/resources-tools/services/ics-network-protocol-parsers
- CISA icsnpp-dnp3 (log files & fields) — https://github.com/cisagov/icsnpp-dnp3

Internal design anchors
- `design/research_cyote.md` (CyOTE methodology + case studies) · `design/research_cie.md` (CIE/CCE
  engineered controls) · `lab/dnp3/outstation.py`, `lab/mqtt/pump-controller.py`,
  `lab/docker-compose.yml`, `lab/zeek_reference_output/` (the buildable substrate).
</content>
</invoke>
