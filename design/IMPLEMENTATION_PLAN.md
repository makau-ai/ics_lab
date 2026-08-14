# Implementation Plan — Wastewater Lift-Station Digital Twin (build spec)

**Author:** Software Developer / DevOps (O*NET 15-1252.00).
**Date:** 2026-08-14 · **Sprint:** 2 (digital-twin build-out).
**Status:** PLAN ONLY — nothing in here is implemented yet. This is the buildable spec a
developer executes to realize `design/DIGITAL_TWIN_ARCHITECTURE.md` (the twin) hardened per
`design/CIE_HARDENING.md` (the controls).

**Reads with / implements:** `DIGITAL_TWIN_ARCHITECTURE.md` (topology §2, containers §3, zones/conduits
§4, flows §5, capture §6, attack §7), `CIE_HARDENING.md` (the six weaknesses + the before/after toggle
mechanics §6), `research_arch.md` (verified upstream images/ports). Reuses the existing substrate:
`lab/dnp3/*.py`, `lab/mqtt/*.py`, `lab/mosquitto/*`, `lab/zeek/*`, `.devcontainer/` (noVNC on 6080).

> **Grounding rule for the build.** Re-skin, don't rebuild. Every kit-built service starts as a copy of
> an existing `lab/` script remapped to the water point map; only `plant-sim`, `zone-fw`, and the OpenPLC
> ST programs are genuinely net-new code. Upstream images are pinned to the `research_arch.md`-verified
> tags. Nothing is weaponized; attacker steps stay at the protocol-observable level already in the kit.

---

## 0. Deliverables this plan defines (maps to the task)

| # | Task item | Section |
|---|---|---|
| 1 | Compose service list + images | §2, §3 |
| 2 | Segmented `networks:` blocks + who attaches where | §4 |
| 3 | Volumes | §5 |
| 4 | OpenPLC process logic (ST/ladder outline) | §6 |
| 5 | How the capture container mirrors/sees traffic | §7 |
| 6 | Vulnerable-vs-hardened toggle | §8 |
| 7 | Phased build order (what to build first) | §9 |

---

## 1. File & directory layout to create

Everything lands under `lab/` next to the two existing compose files (which stay **untouched**).

```
lab/
  docker-compose.twin.yml          # NEW — base twin = the VULNERABLE variant (§3,§4)
  docker-compose.hardened.yml      # NEW — override that flips ALL controls on at once (§8)
  plant-sim/                       # NEW — wet-well physics, Modbus slave
    Dockerfile  requirements.txt  plant_sim.py  config.py
  zone-fw/                         # NEW — nftables router-firewall (the conduit)
    Dockerfile  conduits.nft  entrypoint.sh
  openplc/                         # NEW — OpenPLC build + seeded config + ST programs
    Dockerfile                     # FROM thiagoralves/OpenPLC_v3
    st/naive_wetwell.st            # §6 naive loop
    st/hardened_wetwell.st         # §6 hardened loop
    slave_devices.seed             # plant-sim as remote-I/O (Modbus master config)
    load-program.sh                # seeds st_files + selects program via OpenPLC API
  dnp3/                            # EXTEND existing — add gateway + Modbus source + g41/unsol
    outstation.py -> reused by dnp3-gw (remapped);  master.py -> reused by scada-master
    dnp3lib.py    -> add obj_analog_outputs()/g41, unsolicited helper, arm-latch/allow-list
    gateway.py    (NEW entrypoint wrapping outstation.py logic + Modbus client to OpenPLC)
  mqtt/                            # EXTEND existing — iiot-gw + historian feeder
    publisher.py -> reused by iiot-gw (water fields, reads OpenPLC Modbus)
    subscriber.py -> reused by hmi-less historian feeder
    pump-controller.py, attacker.py -> reused as-is
  mosquitto/                       # REUSE as-is — insecure.conf | secure.conf | acl | passwd
    certs/                         # NEW — server/ca certs for the 8883 mTLS toggle
  zeek/                            # REUSE as-is (icsnpp-dnp3 + built-in MQTT)
  captures/                        # existing shared pcap volume (.gitkeep already present)
  nftables/ -> folded into zone-fw/
```

**Compose strategy (the DevOps backbone of the toggle, §8).** `docker-compose.twin.yml` is the base and
boots the **vulnerable** twin. `docker-compose.hardened.yml` is a thin override applied with
`-f docker-compose.twin.yml -f docker-compose.hardened.yml` that swaps the broker conf, sets the
`dnp3-gw`/PLC/`plant-sim` hardening env, and drops the MQTT command path — flipping every control at once
for the "watch the same attack fail" demo. Profiles gate optional depth (below).

**Profiles** (same pattern as today's `attack|tools|capture`):
`twin-full` = historian + eng-ws + jump-host + edgeshark; `attack` = adversary (+ granted cell foothold);
`capture` = the sniff sidecars + noVNC wireshark; `tools` = zeek. Default `up` = core twin
(plant-sim, openplc, dnp3-gw, iiot-gw, pump-controller, mqtt-broker, scada-master, hmi, zone-fw).

---

## 2. Container inventory — images & build contexts

Ports are container-internal unless a host publish is noted. IPs are the static plan from §4.2.

| # | Service | Image (pin) | Build ctx | Zone / IP | Ports | Reuse origin |
|---|---|---|---|---|---|---|
| 1 | `plant-sim` | `python:3.11-slim` | `./plant-sim` | cell 172.30.10.10 | 502(mb-slave) | NEW (mirrors `lab/mqtt` Dockerfile) |
| 2 | `openplc` | build `thiagoralves/OpenPLC_v3` | `./openplc` | cell 172.30.10.11 | 8080 web, 502 mb-server | upstream OpenPLC_v3 |
| 3 | `dnp3-gw` | `python:3.11-slim` | `./dnp3` | cell 172.30.10.12 | 20000 | `lab/dnp3/outstation.py` remapped + Modbus client |
| 4 | `iiot-gw` | `python:3.11-slim` | `./mqtt` | cell 172.30.10.13 | — | `lab/mqtt/publisher.py` remapped |
| 5 | `pump-controller` | `python:3.11-slim` | `./mqtt` | cell 172.30.10.14 | — | `lab/mqtt/pump-controller.py` as-is |
| 6 | `mqtt-broker` | `eclipse-mosquitto:2` | — | dmz 172.30.30.30 | 1883, 8883 (host-pub 1883) | `lab/mosquitto/` as-is |
| 7 | `scada-master` | `python:3.11-slim` | `./dnp3` | control 172.30.20.20 | — | `lab/dnp3/master.py` extended (poll-loop) |
| 8 | `hmi` | `frangoteam/fuxa` | — | control 172.30.20.21 | 1881 (host-pub) | upstream FUXA |
| 9 | `historian` | python `./mqtt` (default) / `influxdb:1.8` (`twin-full`) | `./mqtt` | control 172.30.20.22 | (8086 if influx) | `lab/mqtt/subscriber.py` extended |
| 10 | `eng-ws` | `nicolaka/netshoot` (or KasmVNC) | — | control 172.30.20.23 | — | NEW (thin) |
| 11 | `zone-fw` | build `debian:stable-slim` + nftables | `./zone-fw` | **all zones** .1 | — | NEW |
| 12 | `jump-host` | `nicolaka/netshoot` | — | ent 172.30.40.40 | — | mirrors segmented `historian` |
| 13 | `adversary` | `kalilinux/kali-rolling` or `netshoot` | `./dnp3`+`./mqtt` scripts | attacker 172.30.66.66 (+cell foothold) | — | `master.py --attack`, `attacker.py` |
| 14 | `zeek` | build `zeek/zeek:lts` + `icsnpp-dnp3` | `./zeek` | dmz / capture | — | `lab/zeek/` as-is |
| 15 | `sniff-dnp3` | `nicolaka/netshoot` | — | netns:`dnp3-gw` | — | as-is |
| 16 | `sniff-mqtt` | `nicolaka/netshoot` | — | netns:`mqtt-broker` | — | as-is |
| 17 | `sniff-conduit` | `nicolaka/netshoot` | — | netns:`zone-fw` | — | NEW (SPAN-like) |
| 18 | `wireshark` | `lscr.io/linuxserver/wireshark` | — | netns:`zone-fw` / `./captures` | 3000, 3001 (host-pub) | + kit noVNC 6080 |
| 19 | `edgeshark` | `ghcr.io/siemens/edgeshark` | — | dmz + host netns | 5001 (host-pub) | upstream |

**Key build decision — OpenPLC's own DNP3 is disabled; `dnp3-gw` provides DNP3.** OpenPLC v3 can serve
DNP3 itself, but that path is opendnp3 (opaque on the wire). To preserve the kit's **readable,
ICSNPP-parseable** DNP3 teaching contract, OpenPLC runs **Modbus-server (502) + Modbus-master (remote
I/O) only**; the readable `dnp3-gw` (kit `dnp3lib.py`) polls OpenPLC over Modbus and fronts DNP3/20000.
OpenPLC's EtherNet/IP and DNP3 servers are toggled OFF in Settings/seed.

**OpenPLC privilege:** run with `cap_add: [NET_ADMIN]` (sufficient for the soft-PLC; avoid `--privileged`
unless the image's hardware layer complains — flagged in §10).

---

## 3. The compose service stanzas (target shape)

Illustrative — the developer authors these into `docker-compose.twin.yml`. `x-*` anchors DRY the repeats.

```yaml
name: ics-twin-liftstation

x-cap-net: &capnet { cap_add: [NET_ADMIN, NET_RAW] }
x-route-fix: &routefix          # see §4.3 — force default route through zone-fw
  restart: on-failure
  depends_on: { zone-fw: { condition: service_started } }

services:
  # ---------- L0/L1 PROCESS CELL ----------
  plant-sim:
    build: ./plant-sim
    environment:
      FLOAT_ENABLED: "false"      # VULNERABLE default; hardened.yml sets true
      WEIR_ENABLED:  "true"
      MOTOR_PROT_ENABLED: "true"
      DIURNAL: "1"  STORM_AT: "600"
    networks: { cell_net: { ipv4_address: 172.30.10.10 } }

  openplc:
    build: ./openplc
    <<: *capnet
    environment: { PLC_PROGRAM: "naive_wetwell.st" }   # hardened.yml -> hardened_wetwell.st
    volumes:
      - openplc_st:/opt/openplc/webserver/st_files      # persistent programs + openplc.db
      - ./openplc/st:/seed/st:ro
      - ./openplc/slave_devices.seed:/seed/slave_devices.seed:ro
    ports: ["8080:8080"]
    networks: { cell_net: { ipv4_address: 172.30.10.11 } }
    depends_on: [plant-sim]

  dnp3-gw:
    build: ./dnp3
    command: python gateway.py --modbus-host openplc --listen 0.0.0.0:20000 --outstn-addr 10
    environment: { HARDEN: "0" }   # hardened.yml -> 1 (arm-latch, no DIRECT_OPERATE, allow-list, sav5)
    networks: { cell_net: { ipv4_address: 172.30.10.12 } }
    depends_on: [openplc]

  iiot-gw:
    build: ./mqtt
    command: python publisher.py            # remapped: reads OpenPLC Modbus, water fields
    environment: { BROKER: 172.30.30.30, PORT: "1883", MQTT_USER: sensor_svc, MQTT_PASS: s3ns0r-pw,
                   MODBUS_HOST: openplc }
    networks: { cell_net: { ipv4_address: 172.30.10.13 } }

  pump-controller:
    build: ./mqtt
    command: python pump-controller.py
    environment: { BROKER: 172.30.30.30, PORT: "1883" }
    networks: { cell_net: { ipv4_address: 172.30.10.14 } }
    # hardened.yml: deploy.replicas 0  (command path removed = CIE #4 "design out")

  # ---------- L3 CONTROL CENTER ----------
  scada-master:
    build: ./dnp3
    command: python master.py --host 172.30.10.12 --poll-loop 5   # integrity poll every 5s
    networks: { control_net: { ipv4_address: 172.30.20.20 } }

  hmi:
    image: frangoteam/fuxa
    volumes: [ fuxa_appdata:/usr/src/app/FUXA/server/_appdata ]
    ports: ["1881:1881"]
    networks: { control_net: { ipv4_address: 172.30.20.21 } }

  historian:
    build: ./mqtt
    command: python subscriber.py --historian   # subscribes plant/tank1/#, logs + commanded-vs-reported
    environment: { BROKER: 172.30.30.30, PORT: "1883", MQTT_USER: hmi_operator, MQTT_PASS: Plant!ntel2024 }
    networks: { control_net: { ipv4_address: 172.30.20.22 } }

  eng-ws:
    image: nicolaka/netshoot
    command: sleep infinity
    profiles: ["twin-full"]
    networks: { control_net: { ipv4_address: 172.30.20.23 } }

  # ---------- L3.5 OT-DMZ ----------
  mqtt-broker:
    image: eclipse-mosquitto:2
    volumes:
      - ./mosquitto/mosquitto.insecure.conf:/mosquitto/config/mosquitto.conf:ro   # <-- toggle surface
      - ./mosquitto/passwd:/mosquitto/config/passwd:ro
      - ./mosquitto/acl:/mosquitto/config/acl:ro
      - ./mosquitto/certs:/mosquitto/config/certs:ro
    ports: ["1883:1883"]
    networks: { dmz_net: { ipv4_address: 172.30.30.30 } }

  # ---------- CONDUIT FIREWALL / ROUTER ----------
  zone-fw:
    build: ./zone-fw
    <<: *capnet
    sysctls: { net.ipv4.ip_forward: "1" }
    volumes: [ ./zone-fw/conduits.nft:/etc/nftables/conduits.nft:ro ]
    networks:
      cell_net:     { ipv4_address: 172.30.10.1 }
      control_net:  { ipv4_address: 172.30.20.1 }
      dmz_net:      { ipv4_address: 172.30.30.1 }
      ent_net:      { ipv4_address: 172.30.40.1 }
      attacker_net: { ipv4_address: 172.30.66.1 }

  # ---------- ENTERPRISE / RED TEAM (profiles) ----------
  jump-host:
    image: nicolaka/netshoot
    command: sleep infinity
    profiles: ["twin-full"]
    networks: { ent_net: { ipv4_address: 172.30.40.40 } }

  adversary:
    build: ./dnp3
    command: sleep infinity          # student drives master.py --attack / attacker.py by hand
    profiles: ["attack"]
    networks: { attacker_net: { ipv4_address: 172.30.66.66 } }

  adversary-foothold:                 # the SCENARIO-GRANTED cell foothold (mirrors segmented.yml)
    build: ./dnp3
    command: sleep infinity
    profiles: ["attack"]
    networks: { cell_net: { ipv4_address: 172.30.10.66 } }

  # ---------- ANALYSIS + CAPTURE (profiles) ----------
  zeek:      { build: ./zeek, volumes: ["..:/kit","./captures:/caps"], command: sleep infinity, profiles: ["tools"], networks: [dmz_net] }
  sniff-dnp3:    { image: nicolaka/netshoot, network_mode: "service:dnp3-gw",     <<: *capnet, command: tcpdump -i any -U -w /caps/dnp3_live.pcap "tcp port 20000",        volumes: ["./captures:/caps"], profiles: ["capture"] }
  sniff-mqtt:    { image: nicolaka/netshoot, network_mode: "service:mqtt-broker", <<: *capnet, command: tcpdump -i any -U -w /caps/mqtt_live.pcap "tcp port 1883 or tcp port 8883", volumes: ["./captures:/caps"], profiles: ["capture"] }
  sniff-conduit: { image: nicolaka/netshoot, network_mode: "service:zone-fw",     <<: *capnet, command: tcpdump -i any -U -w /caps/conduit_live.pcap "tcp port 20000 or tcp port 1883 or tcp port 8883", volumes: ["./captures:/caps"], profiles: ["capture"] }
  wireshark:     { image: lscr.io/linuxserver/wireshark, <<: *capnet, ports: ["3000:3000","3001:3001"], volumes: ["./captures:/captures"], profiles: ["capture"] }
  edgeshark:     { image: ghcr.io/siemens/edgeshark, ports: ["5001:5001"], profiles: ["twin-full"] }  # + host netns per upstream compose
```

---

## 4. Segmented networks (task item 2)

### 4.1 Zones — one Docker bridge per zone (mirrors `DIGITAL_TWIN §4.1`)

```yaml
networks:
  cell_net:     { driver: bridge, ipam: { config: [ { subnet: 172.30.10.0/24 } ] } }   # L0-L1 process cell
  control_net:  { driver: bridge, ipam: { config: [ { subnet: 172.30.20.0/24 } ] } }   # L3 control center
  dmz_net:      { driver: bridge, ipam: { config: [ { subnet: 172.30.30.0/24 } ] } }   # L3.5 OT-DMZ
  ent_net:      { driver: bridge, ipam: { config: [ { subnet: 172.30.40.0/24 } ] } }   # L4 enterprise
  attacker_net: { driver: bridge, ipam: { config: [ { subnet: 172.30.66.0/24 } ] } }   # red team
volumes:
  openplc_st: {}
  fuxa_appdata: {}
  influx_data: {}     # only when historian=influxdb (twin-full)
```

### 4.2 Who attaches where + static IPs

| Zone / bridge | Members (service : IP) |
|---|---|
| `cell_net` 172.30.10.0/24 | plant-sim .10 · openplc .11 · dnp3-gw .12 · iiot-gw .13 · pump-controller .14 · adversary-foothold .66 · zone-fw .1 |
| `control_net` 172.30.20.0/24 | scada-master .20 · hmi .21 · historian .22 · eng-ws .23 · zone-fw .1 |
| `dmz_net` 172.30.30.0/24 | mqtt-broker .30 · zeek .31 · edgeshark .32 · zone-fw .1 |
| `ent_net` 172.30.40.0/24 | jump-host .40 · zone-fw .1 |
| `attacker_net` 172.30.66.0/24 | adversary .66 · zone-fw .1 |
| capture/OOB (no L3 addr) | sniff-* (netns of their target) · wireshark (netns zone-fw or `./captures`) |

`zone-fw` holds **`.1` in every zone** = the default gateway each zone routes through. The sniffers own
no zone IP; they borrow their target's netns (`network_mode: service:*`), so the capture plane is
out-of-band by construction (CIE #6).

### 4.3 The crux DevOps detail — forcing all cross-zone traffic through `zone-fw`

Docker gives each bridge a host-side gateway and **drops inter-bridge forwarding** (DOCKER-ISOLATION), so
two containers on different bridges cannot talk *unless a multi-homed container routes them*. `zone-fw` is
that router, but containers won't use it until their **default route points at `zone-fw`'s in-zone `.1`**
instead of Docker's default gateway. Mechanism to implement:

- **`zone-fw`:** `entrypoint.sh` sets `sysctl net.ipv4.ip_forward=1` and `nft -f /etc/nftables/conduits.nft`,
  then `sleep infinity`.
- **Every other conduit participant:** a one-shot **netns route-injector** — a `nicolaka/netshoot` sidecar
  per service with `network_mode: "service:<svc>"`, `cap_add:[NET_ADMIN]`, `command: ip route replace
  default via 172.30.<zone>.1`. It edits the shared netns route table then exits, and works uniformly for
  **upstream images too** (mosquitto/FUXA/OpenPLC) without modifying them. Kit-built python services can
  instead bake the `ip route replace` into their entrypoint (cheaper; no extra container).
- **Why this is safe w.r.t. Docker isolation:** cross-zone packets never hit the host FORWARD chain —
  cell→`zone-fw`(cell leg) and `zone-fw`(control leg)→target are each **intra-bridge L2** deliveries; the
  routing/filtering happens *inside* `zone-fw`'s netns. This is the OTForge/GRFICS router pattern.
- **Fallback if a host's Docker/iptables fights the injector:** dual-home the ~7 conduit endpoints
  directly (the `docker-compose.segmented.yml` pattern) and keep `zone-fw` for the DMZ/enterprise/attacker
  boundaries only. Documented as a known-good degrade path (§10).

### 4.4 Conduits — the nftables ruleset (`zone-fw/conduits.nft`)

Author exactly the `DIGITAL_TWIN §4.2` ruleset (deny-by-default forward chain; conduits = allow rules),
pinned to the §4.2 IPs: **C1** control⇄cell tcp/20000 (bind `172.30.20.20 ⇄ 172.30.10.12` to tighten to
the master/gw pair); **C2** cell/control → `172.30.30.30` tcp/{1883,8883} **up only**; **C3** control →
`172.30.10.11` tcp/{8080,502}; **C4** ent → dmz tcp/{1883,5001}; everything else
`log prefix "CONDUIT-DROP " drop` (the Active-Defense tripwire feeding Zeek/Suricata). No conduit exists
from `attacker_net` → the adversary is dropped at the boundary until the scenario grants the cell foothold.

---

## 5. Volumes (task item 3)

| Volume / mount | Type | Mounted by | Purpose |
|---|---|---|---|
| `./captures:/caps` | bind | sniff-*, zeek | shared rolling pcaps (sniffers write, zeek/wireshark read) |
| `./captures:/captures` | bind | wireshark | noVNC Wireshark opens the live pcaps |
| `openplc_st` | named | openplc | persist `st_files/` + `openplc.db` (programs + slave-device config) |
| `./openplc/st:/seed/st:ro` | bind | openplc | ship both ST programs into the image for `load-program.sh` |
| `./mosquitto/*.conf,passwd,acl` | bind (ro) | mqtt-broker | **the broker toggle surface** (insecure↔secure) |
| `./mosquitto/certs:/…/certs:ro` | bind (ro) | mqtt-broker | 8883 mTLS certs (hardened) |
| `./zone-fw/conduits.nft:/etc/nftables/conduits.nft:ro` | bind (ro) | zone-fw | the conduit ruleset |
| `fuxa_appdata` | named | hmi | FUXA project/dashboard persistence (`research_arch §2`) |
| `influx_data` | named | historian (influx) | time-series store when `twin-full` uses influxdb:1.8 |
| `..:/kit` | bind | zeek | whole-kit mount so `/kit/pcaps` + `lab/zeek/local.zeek` resolve (as today) |

---

## 6. OpenPLC process logic to author (task item 4)

**Scenario chosen:** wet-well level control (the `DIGITAL_TWIN §1.2` loop). Language: **Structured Text**
(OpenPLC's primary; MatIEC compiles ST→C). Two programs authored so the toggle (§8) swaps them.

### 6.1 I/O wiring — how the PLC sees the plant

OpenPLC runs **two Modbus roles at once**: (a) **Modbus master / "Slave Devices" remote-I/O** polling
`plant-sim` (mapped to the `DIGITAL_TWIN §1.3` addresses), and (b) **Modbus TCP server on 502** exposing
the same `%I/%Q/%MW` image to `dnp3-gw`, `iiot-gw`, and `hmi`. Configure via `slave_devices.seed`
(`plant-sim` at 172.30.10.10:502) loaded by `load-program.sh` (seeds the DB / `mbconfig`, enables the
Modbus master, selects `PLC_PROGRAM`, disables the DNP3 + ENIP servers). Point map = `DIGITAL_TWIN §1.3`:

```
%IW100 LT-101 level(0-10000)  %IW101 FIT-104 flow  %IW102 PIT-105 psi
%IX100.0 LSHH-102 float       %IX100.1 LSL-103 low
%QX100.0 P-1  %QX100.1 P-2  %QX100.2 HLA
%MW10 LEAD_START (writable)   %MW11 STOP (writable)
```

### 6.2 `naive_wetwell.st` — the vulnerable loop (500 ms scan)

```
level := INT_TO_REAL(%IW100) / 100.0;                 (* 0..100 % *)
IF level >= LEAD_START THEN start(lead_pump); END_IF;  (* LEAD_START from %MW10, unclamped *)
IF level >= LAG_START  THEN start(lag_pump);  END_IF;  (* LAG_START = 80 % *)
IF level <= STOP       THEN stop_all(); alternate_lead(); END_IF;
IF (level <= LOWCUT) OR (%IX100.1 = FALSE) THEN inhibit_start := TRUE; END_IF;   (* dry-run *)
IF pump_running AND (flow < MIN_FLOW) AND (psi > HI_PSI) THEN trip(); alarm(); END_IF; (* dead-head *)
IF level >= HLA THEN %QX100.2 := TRUE; END_IF;         (* HLA -> DNP3 BI + MQTT alarm *)
(* comms-loss: hold last setpoints, keep pumping locally = fail-operational *)
```

The vulnerability is CWE-693: `LEAD_START` (`%MW10`) is writable via DNP3 g41 / MQTT setpoint with **no
clamp**, so pushing it > 100 % means the loop never starts a pump (Oldsmar "modify parameter").

### 6.3 `hardened_wetwell.st` — same loop + the CIE `[ENG]` controls

Adds, per `CIE_HARDENING` W1/W5/W6 (all in-ladder, so a register write cannot reach past them):

- **Setpoint clamp (W6):** `LEAD_START := LIMIT(40.0, %MW10/100.0, 85.0);` — a g41 write of 150 % is
  clamped to 85 %; the bound lives in code, not the register.
- **Stop-permissive interlock (W1):** `permit_stop := (level < LEAD_START) AND (level_falling OR
  both_pumps_healthy);` — the PLC refuses to de-energize pumps into a rising well regardless of who
  commanded it.
- **EU range + quality (W5):** clamp `level/flow/psi` to transmitter span; on out-of-range set
  `PV_QUALITY := BAD` and fall back to last-good / local sensor before any decision (kills CWE-807).
- **Local-sensor safety decision (W4):** protective logic reads `%IW100`/`%IX100.0` (the wired
  transmitter + float), **never** a DNP3/MQTT-reported value — spoofed telemetry can blind the view but
  cannot move the plant.
- **Comms-loss safe state (W6/CIE #10):** explicit last-safe-setpoint hold on master/broker loss.

> **The hardwired float is NOT in the PLC.** LSHH-102 at 95 % is modeled in **`plant-sim`** as a path
> honored regardless of `%QX` coils (§7 of the twin doc) — the analog backstop that holds even if the ST
> is deleted. The ST setpoint clamp is the *digital* layer; the float is the *engineered* layer beneath it.

---

## 7. plant-sim + protocol services — code to author

### 7.1 `plant-sim/plant_sim.py` (NEW)

`python:3.11-slim` + `pymodbus` **Modbus TCP slave (server)** on 502 that OpenPLC polls. Per 500 ms tick,
integrate the `DIGITAL_TWIN §1.3` model: `Q_in = diurnal(t)+storm(t)`, `Q_out = (P1+P2)*1500*eff`,
`level += (Q_in-Q_out)*dt/AREA` clamped 0..100 %; derive FIT-104/PIT-105; drive float discretes; and the
**SSO spill counter** `if level>=100: spill += (Q_in-Q_out)*dt`. Reads coils (`%QX`) from OpenPLC's writes,
writes input regs/discretes back. Env toggles: `FLOAT_ENABLED` (force-start standby + horn at 95 %
independent of coils), `WEIR_ENABLED` (bounded release path), `MOTOR_PROT_ENABLED` (underload/low-flow
trip). Log `level`, `spill`, pump state each tick; expose `spill` as the objective scoreboard (stdout +
optional `plant/tank1/status`).

### 7.2 `dnp3/gateway.py` (NEW wrapper) + `dnp3lib.py` (extend)

`gateway.py` = `outstation.py`'s server loop, but the canned `BINARY`/`ANALOG` are replaced by a **Modbus
client** polling OpenPLC:502 → live water values mapped to the `DIGITAL_TWIN §5` DNP3 point map (g1 idx
0–3, g30 idx 0–2, g12v1 idx 0–1, g41 idx 0–1). CROB OPERATE writes OpenPLC coils; g41 WRITE writes
`%MW10/%MW11`; new HLA emits **UNSOLICITED 0x82**. `dnp3lib.py` net-new helpers: `obj_analog_outputs()`
(g41), an unsolicited-response builder (`appctl(uns=1)` already exists), and the `HARDEN=1` primitives —
per-point **SELECT arm-latch** (OPERATE 0x04 honored only within 2 s of a matching SELECT 0x03 on the same
association; **reject DIRECT_OPERATE 0x05/0x06** for consequential points), **object/range allow-list**
(drop out-of-map group/var/index), **DNP3 link-address allow-list**, and the **SAv5 aggressive-mode HMAC**
check on control FCs. `HARDEN=0` = today's obey-on-request behavior.

### 7.3 `scada-master` = `master.py` extended · `iiot-gw`/`historian` = `mqtt/*` remapped

- `master.py`: add `--poll-loop N` (continuous integrity poll), unsolicited receive, SELECT→OPERATE pump
  CROB, g41 setpoint WRITE. `--attack`/`--src-addr` already present for the red-team drills.
- `iiot-gw` (`publisher.py`): read OpenPLC:502 (Modbus client) instead of `random`; publish
  `plant/tank1/telemetry|status` with `{level_pct,flow_gpm,p1,p2,psi}`.
- `historian` (`subscriber.py --historian`): subscribe `plant/tank1/#`, persist, and compute the
  **commanded-vs-reported** cross-check (CIE #6 spoof tripwire) against the physics baseline.
- `pump-controller.py`, `attacker.py`, `mosquitto/*`, `zeek/*`, `sniff-*` = **as-is**.

---

## 8. How the capture container mirrors / sees traffic (task item 5)

Docker bridges have **no SPAN/mirror**, so the twin uses three complementary, out-of-band methods
(`DIGITAL_TWIN §6`, `research_arch §5`), all writing Zeek-ready pcaps to `./captures`:

- **Method A — per-host netns tap (precise, the kit's proven method).** `sniff-dnp3` shares `dnp3-gw`'s
  netns and captures `tcp port 20000`; `sniff-mqtt` shares `mqtt-broker`'s netns for `1883/8883`. Exactly
  that host's traffic; survives restarts.
- **Method B — conduit / whole-zone tap (SPAN-like).** Because **all inter-zone traffic crosses
  `zone-fw`**, `sniff-conduit` shares `zone-fw`'s netns and sees **every cross-conduit packet at once** —
  the digital SPAN at the OT/DMZ boundary and the natural Zeek/Suricata sensor feed. (Host-side
  `tcpdump -i br-xxxx` on a zone's bridge, found via `docker network inspect`, is the same view from the
  host.)
- **Method C — Edgeshark live click-to-Wireshark.** `edgeshark` on 5001 + the `cshargextcap` extcap
  plugin streams any container interface straight into desktop Wireshark — "show me `dnp3-gw` right now,"
  no file.

**How the student SEES packets:** (1) the standalone `lscr.io/linuxserver/wireshark` noVNC GUI on
3000/3001, mounting `./captures` (**File ▸ Open** the auto-reloading `*_live.pcap`) or `network_mode:
service:zone-fw` for live **Capture ▸ eth0**; and (2) the existing kit noVNC desktop on **6080** driven by
`lab/open-wireshark.sh`, repointed from `lo` to the real inter-container pcaps.

**Filters (unchanged, so the curriculum transfers):** capture `tcp port 20000 or tcp port 1883 or tcp
port 8883`; display `dnp3 || mqtt`, then `dnp3.al.func`, `dnp3.al.ctrl.code`, `mqtt.msgtype`, `mqtt.topic`.
**Detection feed:** Method-A/B pcaps → `zeek` + ICSNPP → `dnp3*.log`/`mqtt*.log` (`local.zeek` already
`@load icsnpp-dnp3`). **Discipline:** every tap is passive/out-of-band — never inline on a control path.

---

## 9. Vulnerable-vs-hardened toggle (task item 6)

Two layers so students can flip **everything at once** or **one control at a time**, plus the segmentation
scenario progression. Objective scoreboard for every variant = `plant-sim` **spill counter** +
Zeek `dnp3_control.log`/`dnp3_objects.log`/`mqtt_*.log`. **Pass = spill 0 under full DNP3+MQTT write
access (DB-1).**

### 9.1 Coarse — one command flips all controls

```bash
# VULNERABLE twin (base):
docker compose -f docker-compose.twin.yml --profile attack up -d
# HARDENED twin (override):
docker compose -f docker-compose.twin.yml -f docker-compose.hardened.yml --profile attack up -d
```

`docker-compose.hardened.yml` overrides: broker conf `insecure→secure.conf` (+`acl`, +8883 mTLS mount) ·
`dnp3-gw HARDEN=1` · `openplc PLC_PROGRAM=hardened_wetwell.st` · `plant-sim FLOAT_ENABLED=true` ·
`pump-controller replicas 0` (MQTT command path designed out). Same `adversary` scripts run against both.

### 9.2 Fine — per-control env, to teach each weakness alone (`CIE_HARDENING` W1–W6)

| Control | Toggle | Vulnerable → Hardened |
|---|---|---|
| MQTT broker (W1/W3) | swap `mosquitto.insecure.conf` ↔ `secure.conf`(+acl+8883) | anonymous/`#` → auth+ACL+mTLS |
| DNP3 gateway (W1/W4/W5) | `dnp3-gw` env `HARDEN=0/1` | obey-on-request → arm-latch + no DIRECT_OPERATE + allow-list + SAv5 |
| PLC logic (W6) | `openplc` env `PLC_PROGRAM=naive/hardened` | unclamped setpoint → clamp + interlock + local-sensor decision |
| Physical backstop (W6) | `plant-sim` env `FLOAT_ENABLED` (+`WEIR_ENABLED`) | float off → hardwired float at 95 % |
| Segmentation (W3/CWE-1364) | scenario progression (below) | flat → segmented → `zone-fw` conduits |

### 9.3 Segmentation progression (already partly `[NOW]`)

`docker-compose.yml` (flat `otlan`) → `docker-compose.segmented.yml` (2-zone, "attack dies at the
conduit") → `docker-compose.twin.yml` (explicit `zone-fw` nftables + `CONDUIT-DROP` tripwire + one-way C2).
The `--profile attack` `adversary` (attacker_net, dropped at conduit) vs `adversary-foothold` (cell_net,
succeeds) reproduces the segmentation lesson against the live process.

---

## 10. Phased build order (task item 7 — the headline)

Each phase is independently demoable and has an acceptance gate; later phases don't start until the gate
passes. Order chosen so the **physical loop is real before any network/attack work**, matching
`DIGITAL_TWIN §9` bring-up.

**Phase 0 — Scaffolding (½ day).** Create the §1 tree; `docker-compose.twin.yml` skeleton with the 5
networks (§4.1) and named volumes; pin every upstream image tag/digest; add profiles. *Gate:* `docker
compose config` validates; empty services build.

**Phase 1 — Physics + PLC core loop (the heart).** Build `plant-sim` (Modbus slave + integrator + spill)
and `openplc` (seed `slave_devices.seed`, load `naive_wetwell.st`, enable Modbus master + 502 server,
disable DNP3/ENIP). Run cell-only, flat, no firewall. *Gate:* level oscillates within the deadband, pumps
cycle, `spill==0` under normal diurnal inflow; a storm pulse drives level up and the loop pumps it down.

**Phase 2 — DNP3 conduit (F2).** `dnp3-gw` (remap + Modbus client + g41/unsolicited) and `scada-master`
(poll-loop + SELECT→OPERATE + g41), still flat. *Gate:* integrity poll returns live water points;
SELECT→OPERATE toggles a pump in `plant-sim`; a forced HLA emits UNSOLICITED 0x82; ICSNPP parses
`dnp3.log`/`dnp3_control.log`/`dnp3_objects.log`.

**Phase 3 — MQTT telemetry (F3/F4).** `mqtt-broker` (insecure), `iiot-gw` (water fields from OpenPLC),
`pump-controller`, `historian`, and `hmi` (FUXA project reading OpenPLC Modbus + broker MQTT). *Gate:*
telemetry visible in FUXA; `plant/tank1/command STOP` moves the pump; `mqtt_*.log` parses.

**Phase 4 — Segmentation (§4).** Build `zone-fw` (nftables + ip_forward), author `conduits.nft`, split
services into the 5 zones with static IPs, wire the **route-injectors** (§4.3). *Gate:* C1–C4 flows pass;
`CONDUIT-DROP` logs when the DMZ/enterprise probes `cell_net:20000`; cross-zone still works for sanctioned
pairs only. (Fallback to dual-homing if the injector fights a host — §10 risks.)

**Phase 5 — Capture & visibility (§7).** Add `sniff-dnp3/mqtt/conduit`, `zeek`, `wireshark` noVNC,
`edgeshark`. *Gate:* live inter-container pcaps in `./captures` feed ICSNPP to the same logs; student opens
them in noVNC (3000/6080) and Edgeshark click-capture streams `dnp3-gw`.

**Phase 6 — Adversary + attack chain (§7.1), VULNERABLE.** `--profile attack`; run the ordered chain from
`adversary-foothold`: spoofed 0x82/telemetry → CROB/`command` STOP both pumps → g41/`setpoint` LEAD_START
> 100 %. *Gate:* full chain drives `spill > 0` (SSO reproduced), HMI still shows "normal" (loss of view);
`adversary` on attacker_net is dropped at the conduit.

**Phase 7 — Hardened variant + toggles (§9), the CIE acceptance test.** Author `docker-compose.hardened.yml`,
`hardened_wetwell.st`, `dnp3-gw HARDEN=1`, `secure.conf`+`acl`+8883 certs, `FLOAT_ENABLED=true`. Re-run the
**identical** Phase-6 attack hardened. *Gate (DB-1):* `spill == 0` under full DNP3+MQTT write access — the
float starts the pump at 95 % even with every digital layer owned; `dnp3_control.log` shows OPERATE with no
state change / auth failure; students diff the two spill counters and log sets.

**Phase 8 — Polish & CI.** FUXA dashboard, historian commanded-vs-reported tripwire, `twin-full` extras
(influx/eng-ws/jump-host/edgeshark), README + `LAB_GUIDE` updates, and a **CI smoke test** (`compose up`,
assert live pcaps + `spill==0` hardened / `spill>0` vulnerable, `compose down`). *Gate:* one-command bring-up
green in CI and in the devcontainer.

**Bring-up ordering (`depends_on`, per `DIGITAL_TWIN §9`):** `plant-sim` → `openplc` → `dnp3-gw`,`iiot-gw`
→ `mqtt-broker`,`zone-fw` → `scada-master`,`hmi`,`historian` → capture plane → (on demand) `eng-ws`,
`jump-host`,`adversary`. Add container `healthcheck`s (Modbus 502 reachable, broker 1883 reachable, DNP3
20000 accepting) so `depends_on: condition: service_healthy` gates each layer.

---

## 11. Risks / decisions / open questions (senior judgment)

- **Route-injection is the single fiddly bit.** Primary = netns route-injector sidecars; fallback =
  dual-home conduit endpoints (the proven `segmented.yml` pattern). Validate on the target Docker host in
  Phase 4 before building the rest of the segmentation on it.
- **OpenPLC privilege:** try `cap_add:[NET_ADMIN]` first; escalate to `--privileged` only if the image's
  hardware layer refuses. Persist `st_files`/`openplc.db` in the named volume so the seeded program +
  slave-device config survive restarts.
- **SAv5 fidelity:** the kit's readable `dnp3lib` implements SAv5 as an **aggressive-mode HMAC check** for
  teaching, not a full opendnp3 SA stack — documented as a teaching approximation (consistent with
  `CIE_HARDENING §7` scoping honesty), and DNP3-over-TLS/mTLS reduces ICSNPP visibility, so the plaintext
  mode stays default for the parsing curriculum.
- **Historian:** default to the lightweight python historian (no extra creds, laptop-friendly); influxdb:1.8
  only under `twin-full`.
- **Sparkplug-B:** keep plain-JSON MQTT default (fully wire-readable); Sparkplug is an optional realism
  mode with the documented "protobuf body opaque" caveat.
- **Image pinning:** pin `frangoteam/fuxa`, `eclipse-mosquitto:2`, `ghcr.io/siemens/edgeshark`,
  `lscr.io/linuxserver/wireshark`, `zeek/zeek:lts`, `nicolaka/netshoot`, `kalilinux/kali-rolling` to
  digests in Phase 0 for reproducibility.

## 12. Definition of Done

1. `docker compose -f docker-compose.twin.yml up -d` brings the core twin up on the 5 segmented zones with
   the closed loop running (`plant-sim` ↔ `openplc` Modbus, autonomous).
2. Real inter-container DNP3/20000 + MQTT/1883 cross the conduits (never loopback) and ICSNPP produces
   `dnp3*.log`/`mqtt*.log`; students see packets in noVNC Wireshark and Edgeshark.
3. `zone-fw` enforces deny-by-default; the adversary is dropped at the conduit and logged (`CONDUIT-DROP`)
   until granted the cell foothold.
4. The vulnerable variant reproduces the SSO (`spill > 0`); the hardened variant passes DB-1
   (`spill == 0` under full DNP3+MQTT write access) via the in-ladder clamp/interlock + the `plant-sim`
   hardwired float — the CIE "even-if" acceptance test.
5. The toggle works both coarse (`hardened.yml`) and fine (per-service env), and the flat→segmented→twin
   progression is runnable.
```
