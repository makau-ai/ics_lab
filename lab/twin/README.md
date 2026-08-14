# Wastewater Lift-Station Digital Twin

A multi-container ICS **digital twin** that replaces the loopback demo: a real
closed-loop control process (OpenPLC controlling a simulated wet-well over
Modbus), fronted by a **DNP3 outstation gateway** on TCP/20000 and an **MQTT**
telemetry path on TCP/1883, across **5 segmented IEC-62443 zones** with an
**nftables conduit firewall** (`zone-fw`), plus an **out-of-band capture plane**
so students still SEE every packet. Ships a one-command **vulnerable ↔ hardened**
toggle for the CIE "even-if" acceptance test.

Built per `design/IMPLEMENTATION_PLAN.md` + `DIGITAL_TWIN_ARCHITECTURE.md` +
`CIE_HARDENING.md`. Re-skins the existing `lab/` substrate (dnp3/mqtt/mosquitto/
zeek); only `plant-sim`, `zone-fw`, the OpenPLC ST programs, and the Modbus
plumbing are net-new.

---

## 1. Boot it

Run from `lab/twin/`. Requires Docker + the compose plugin.

```bash
# VULNERABLE twin (the base). Core services only:
docker compose -f docker-compose.twin.yml up -d --build

# add the packet-capture plane (sniffers + noVNC Wireshark):
docker compose -f docker-compose.twin.yml --profile capture up -d

# add Zeek+ICSNPP, the red team, or the enterprise/HMI depth:
docker compose -f docker-compose.twin.yml --profile tools --profile attack --profile twin-full up -d
```

Profiles: `capture` (sniff-* + wireshark) · `tools` (zeek) · `attack` (adversary
+ granted cell foothold) · `twin-full` (historian-influx + eng-ws + jump-host +
edgeshark). Default `up` = the core twin (plant-sim, openplc, dnp3-gw, iiot-gw,
pump-controller, mqtt-broker, scada-master, hmi, historian, zone-fw + route-injectors).

**Objective scoreboard:** `docker compose logs -f plant-sim` — watch `level` and
the **`spill`** counter (gallons of Sanitary Sewer Overflow). **Pass = spill 0
under full DNP3+MQTT write access.**

---

## 2. The vulnerable ↔ hardened toggle

### Coarse — flip ALL CIE controls at once

```bash
# HARDENED twin: the SAME base + the thin override
docker compose -f docker-compose.twin.yml -f docker-compose.hardened.yml up -d --build
```

The override (`docker-compose.hardened.yml`) changes exactly five things:

| Service | Vulnerable (base) | Hardened (override) | Weakness |
|---|---|---|---|
| `plant-sim` | `FLOAT_ENABLED=false` | `FLOAT_ENABLED=true` (hardwired HH float @95%) | W6 |
| `openplc` | `naive_wetwell.st` | `hardened_wetwell.st` (clamp + interlock + local decision) | W1/W5/W6 |
| `dnp3-gw` | `HARDEN=0 SAV5=0` | `HARDEN=1 SAV5=1` (arm-latch, no DIRECT_OPERATE, allow-list, SAv5) | W1/W4/W5 |
| `mqtt-broker` | `mosquitto.insecure.conf` | `mosquitto.secure.conf` + `acl` (+ optional 8883 mTLS) | W1/W3 |
| `pump-controller` | running | `replicas: 0` (MQTT command path designed OUT) | CIE #4 |

### Fine — teach one weakness at a time

Set the same env by hand instead of the whole override, e.g. only the PLC logic:
`docker compose -f docker-compose.twin.yml run -e PLC_PROGRAM=hardened_wetwell.st openplc`,
or only the gateway: `... -e HARDEN=1 dnp3-gw`, or only the broker: swap the
`mosquitto.conf` mount. See `CIE_HARDENING.md` §6 for the per-control matrix.

### Optional 8883 mTLS (W2 deeper layer)

```bash
./mosquitto/gen-certs.sh                       # writes certs/{ca,server}.{crt,key}
# then uncomment the "listener 8883" block in mosquitto/mosquitto.secure.conf
```

---

## 3. Run the attack, watch it fail hardened

Bring up with `--profile attack`, then drive the chain from the **granted cell
foothold** (`adversary-foothold`, on `cell_net`). The same commands from
`adversary` (on `attacker_net`) are **dropped at the conduit** — the segmentation
lesson.

```bash
# 1. manipulation of control: stop both pumps (unauthenticated DIRECT_OPERATE)
docker compose exec adversary-foothold python master.py --host 172.30.10.12 --attack

# 2. modify parameter (Oldsmar): push LEAD_START above 100% so pumps never start
docker compose exec adversary-foothold python master.py --host 172.30.10.12 --setpoint-lead 150

# 3. MQTT command injection (from the cell, insecure broker)
docker compose exec iiot-gw python attacker.py         # uses BROKER=172.30.30.30
```

- **Vulnerable:** pumps stop / never start, `plant-sim` `spill` climbs > 0 (SSO
  reproduced), the HMI still reads "normal."
- **Hardened:** DIRECT_OPERATE is rejected (`status ≠ Success`), the g41 write is
  clamped to 85% in the ladder, and even if every digital layer is owned the
  **hardwired float force-starts the pump at 95% → spill stays 0** (DB-1).
- **From `attacker_net`:** `docker compose exec adversary python master.py --host
  172.30.10.12 --attack` → the packet is dropped at `zone-fw` and logged
  (`CONDUIT-DROP` in `dmesg` on the host).

Legit supervised control (for contrast): `docker compose exec scada-master python
master.py --host 172.30.10.12 --stop-pump 0 --sav5` (SELECT→OPERATE, HMAC-tagged).

---

## 4. See the packets (DNP3/MQTT between containers, never loopback)

All traffic is plaintext and Zeek/ICSNPP-parseable. Capture is **out-of-band**.

- **noVNC Wireshark** (`--profile capture`): open `http://localhost:3000` (or
  3001 https). **File ▸ Open** the auto-reloading pcaps in `/captures`:
  `dnp3_live.pcap`, `mqtt_live.pcap`, `conduit_live.pcap`.
- Three taps write those pcaps, each sharing a target's netns (out-of-band):
  `sniff-dnp3` (at the RTU), `sniff-mqtt` (at the broker), `sniff-conduit` (the
  SPAN-like whole-zone tap at `zone-fw` — every cross-conduit packet at once).
- **Edgeshark** (`--profile twin-full`): `http://localhost:5001`, click any
  container interface → live-stream into desktop Wireshark (`cshargextcap`).
- **Kit noVNC desktop (port 6080):** point `lab/open-wireshark.sh` at the real
  pcaps in `lab/twin/captures/` instead of `lo`.

Filters (unchanged, so the curriculum transfers):
- capture: `tcp port 20000 or tcp port 1883 or tcp port 8883`
- display: `dnp3 || mqtt`, then `dnp3.al.func`, `dnp3.al.ctrl.code`,
  `mqtt.msgtype`, `mqtt.topic`.

Detection: pipe the pcaps to Zeek (`--profile tools`):
`docker compose exec zeek run-zeek /caps/conduit_live.pcap` → `dnp3.log`,
`dnp3_control.log`, `dnp3_objects.log`, `mqtt_*.log`.

---

## 5. Zones, IPs, conduits

| Zone / bridge | Subnet | Members (`.IP`) |
|---|---|---|
| `cell_net` L0-L1 | 172.30.10.0/24 | plant-sim .10 · openplc .11 · dnp3-gw .12 · iiot-gw .13 · pump-controller .14 · foothold .66 · zone-fw .1 |
| `control_net` L3 | 172.30.20.0/24 | scada-master .20 · hmi .21 · historian .22 · eng-ws .23 · influx .24 · zone-fw .1 |
| `dmz_net` L3.5 | 172.30.30.0/24 | mqtt-broker .30 · zeek .31 · edgeshark .32 · wireshark .33 · zone-fw .1 |
| `ent_net` L4 | 172.30.40.0/24 | jump-host .40 · zone-fw .1 |
| `attacker_net` | 172.30.66.0/24 | adversary .66 · adversary-mqtt .67 · zone-fw .1 |

`zone-fw` holds `.1` in every zone and is the default route for every container,
so all cross-zone traffic is forced through its nftables `forward` chain
(`zone-fw/conduits.nft`, deny-by-default). Sanctioned conduits: **C1** DNP3/20000
(scada-master⇄dnp3-gw only) · **C2** MQTT/1883 up-only (cell/control→broker;
command/setpoint down denied = data-diode) · **C3** eng 8080/502 (control→openplc)
· **C4** ent→DMZ 1883/5001. Everything else → `CONDUIT-DROP` log + drop. The
attacker zone has **no conduit**.

**Route forcing:** kit-built Python services set their default route via
`entrypoint.sh` (`ZONE_GW` env); the three upstream images (openplc, broker, hmi)
get a `route-*` netns sidecar. All degrade to a no-op if `NET_ADMIN` is absent.

---

## 6. Process + point maps

Wet-well level control (deadband, duty/standby, HLA, dry-run/dead-head interlocks),
`plant-sim` integrating inflow − pump outflow with a **spill** (SSO) counter and
the analog backstops (hardwired float, weir, motor protection).

**Modbus image (plant-sim server ↔ OpenPLC client):** `%IW100` level (0–10000) ·
`%IW101` flow · `%IW102` psi · `%IX100.0` LSHH float · `%IX100.1` LSL · `%QX100.0/.1`
P-1/P-2 · `%QX100.2` HLA · `%MW10` LEAD_START · `%MW11` STOP · `%MW12` REMOTE_CMD.

**DNP3 point map (dnp3-gw serves):** g1 idx 0–3 (P1,P2,HLA,fault) · g30 idx 0–2
(level,flow,psi) · g12v1 idx 0–1 (pump CROB) · g41 idx 0–1 (LEAD_START,STOP setpoints).

---

## 7. Live bring-up caveats (verify in the Codespace)

1. **OpenPLC seeding is the one manual step.** Headless ST load is UI-driven and
   version-specific. On first boot: web UI at `http://localhost:8088` (default `openplc`/`openplc`)
   → **Slave Devices** add `wetwell-plant-sim` (values in `openplc/slave_devices.seed`)
   → **Programs** upload+compile the selected `st/*.st` → **Settings** enable Modbus,
   disable the DNP3 + EtherNet/IP servers. `openplc/load-program.sh` automates this
   best-effort; verify it took.
2. **OpenPLC Modbus register map.** `dnp3-gw`/`iiot-gw` default to `PLC_MAP=sim`
   (plant-sim's raw addresses, which also match OpenPLC's **input** registers).
   OpenPLC maps `%IX100.0`/`%QX100.0` to Modbus **bit offset 800** — once confirmed
   live, set `PLC_MAP=openplc`. Guaranteed-working fallback for the reads:
   `MODBUS_HOST=plant-sim` (read the authoritative sim image directly).
3. **Route-injection is the fiddly bit.** If a host's Docker/iptables fights the
   netns route sidecars, fall back to dual-homing the conduit endpoints (the
   `docker-compose.segmented.yml` pattern) and keep `zone-fw` for the DMZ/enterprise
   boundaries (IMPLEMENTATION_PLAN §4.3 / §10).
4. **CONDUIT-DROP logs** land in the host kernel ring buffer (`dmesg | grep
   CONDUIT-DROP`), not container stdout.
5. **Pinning:** images use the tags the plan names; pin to digests for full
   reproducibility before field use (IMPLEMENTATION_PLAN §11).

---

## 8. Deliberate deviations from the plan

- **Modbus is pure standard library** (`modbus_tcp.py`), not `pymodbus` — same
  philosophy as the kit's stdlib `dnp3lib.py`. Removes a version-drift dependency,
  keeps the wire real and Wireshark-parseable (`mbtcp`), and needs zero pip installs.
- **SAv5** is a truncated HMAC-SHA256 aggressive-mode approximation (teaching
  stand-in for the full opendnp3 SA stack), per `CIE_HARDENING.md` §7 scoping honesty.
- **Supervised control** writes a PLC command register (`%MW12`) the ST honors,
  rather than a raw coil the recomputing loop would overwrite — realistic SCADA
  remote-command semantics.
