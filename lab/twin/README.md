# Wastewater Lift-Station Digital Twin

A multi-container ICS **digital twin** that replaces the loopback demo: a real
closed-loop control process (OpenPLC — a Modbus **client** — controlling a
simulated wet-well, the Modbus **server**), fronted by a **DNP3 outstation
gateway** on TCP/20000 that a SCADA **master** polls, and an **MQTT** telemetry
path on TCP/1883 with a **publisher** and a pump-controller **subscriber**,
across **5 segmented IEC-62443 zones** with an **nftables conduit firewall**
(`zone-fw`), plus an **out-of-band capture plane** so students still SEE every
packet. Ships a one-command **vulnerable ↔ hardened** toggle for the CIE
"even-if" acceptance test.

Built per `design/IMPLEMENTATION_PLAN.md` + `DIGITAL_TWIN_ARCHITECTURE.md` +
`CIE_HARDENING.md`. Re-skins the existing `lab/` substrate (dnp3/mqtt/mosquitto/
zeek); only `plant-sim`, `zone-fw`, the OpenPLC ST programs, and the Modbus
plumbing are net-new.

> **Read — how to run the commands below.** Every fenced command has a **Copy**
> button; click it, then paste into your terminal. If Copy ever misbehaves, the
> keyboard paste-backup is **Ctrl/Cmd+Shift+V**. The twin's commands are plain
> `docker compose` and `bash lab/twin/launch-twin.sh` — there is **no** short
> `lab` token for them (those tokens cover the leveled curriculum only). Run every
> command in this guide from `lab/twin/`.

---

## 1. Boot it

> **Read.** The twin is a fleet of containers, not a single process. You bring it
> up in layers: the core control loop first, then the out-of-band capture plane,
> then optional depth (Zeek, the red team, the enterprise/HMI tier). Requires
> Docker + the compose plugin.

**Do · Type.** Boot the VULNERABLE twin — core services only:

```bash
docker compose -f docker-compose.twin.yml up -d --build
```

**Check —** you should see the core containers come up (plant-sim, openplc,
dnp3-gw, iiot-gw, pump-controller, mqtt-broker, scada-master, hmi, historian,
zone-fw + route-injectors). If a build fails or a container is missing, re-run the
command; to start clean, `docker compose -f docker-compose.twin.yml down` then
bring it up again.

**Do · Type.** Add the packet-capture plane (sniffers + noVNC Wireshark):

```bash
docker compose -f docker-compose.twin.yml --profile capture up -d
```

**Check —** you should see the `sniff-*` taps and the `wireshark` container
running. If they don't appear, re-run the command with the `--profile capture`
flag present.

**Do · Type.** Add Zeek+ICSNPP, the red team, and the enterprise/HMI depth:

```bash
docker compose -f docker-compose.twin.yml --profile tools --profile attack --profile twin-full up -d
```

**Check —** you should see the `zeek`, `adversary`, `adversary-foothold`, and the
`twin-full` containers (historian-influx, eng-ws, jump-host, edgeshark) join the
running set (`docker compose ps`).

> **Read.** Profiles: `capture` (sniff-* + wireshark) · `tools` (zeek) · `attack`
> (adversary + granted cell foothold) · `twin-full` (historian-influx + eng-ws +
> jump-host + edgeshark). Default `up` = the core twin (plant-sim, openplc,
> dnp3-gw, iiot-gw, pump-controller, mqtt-broker, scada-master, hmi, historian,
> zone-fw + route-injectors).

**Do · Type.** Open the objective scoreboard — the **`spill`** counter (gallons of
Sanitary Sewer Overflow):

```bash
docker compose logs -f plant-sim
```

**Check —** you should see `level` and `spill` fields update. **Pass = `spill`
stays 0 under full DNP3+MQTT write access.** If the log is empty, confirm
`plant-sim` is up in `docker compose ps`.

---

## 2. The vulnerable ↔ hardened toggle

### Coarse — flip ALL CIE controls at once

> **Read.** One thin override file turns every CIE control on at once, so you can
> replay the identical attack against a hardened plant.

**Do · Type.** Boot the HARDENED twin — the SAME base + the thin override:

```bash
docker compose -f docker-compose.twin.yml -f docker-compose.hardened.yml up -d --build
```

**Check —** you should see the same container set rebuild with the hardened
settings applied; confirm with `docker compose ps`. If the override was ignored,
make sure both `-f` flags are present, in order.

> **Read.** The override (`docker-compose.hardened.yml`) changes exactly five
> things:

| Service | Vulnerable (base) | Hardened (override) | Weakness |
|---|---|---|---|
| `plant-sim` | `FLOAT_ENABLED=false` | `FLOAT_ENABLED=true` (hardwired HH float @95%) | W6 |
| `openplc` | `naive_wetwell.st` | `hardened_wetwell.st` (clamp + interlock + local decision) | W1/W5/W6 |
| `dnp3-gw` | `HARDEN=0 SAV5=0` | `HARDEN=1 SAV5=1` (arm-latch, no DIRECT_OPERATE, allow-list, SAv5) | W1/W4/W5 |
| `mqtt-broker` | `mosquitto.insecure.conf` | `mosquitto.secure.conf` + `acl` (+ optional 8883 mTLS) | W1/W3 |
| `pump-controller` | running | `replicas: 0` (MQTT command path designed OUT) | CIE #4 |

### Fine — teach one weakness at a time

> **Read.** Instead of the whole override, set the same env by hand to isolate a
> single control. The full per-control matrix is in `CIE_HARDENING.md` §6.

**Do · Type.** Harden only the PLC logic (leave everything else vulnerable):

```bash
docker compose -f docker-compose.twin.yml run -e PLC_PROGRAM=hardened_wetwell.st openplc
```

**Check —** you should see OpenPLC restart running `hardened_wetwell.st`. The same
pattern isolates the gateway (`... -e HARDEN=1 dnp3-gw`) or the broker (swap the
`mosquitto.conf` mount) — see `CIE_HARDENING.md` §6.

### Optional 8883 mTLS (W2 deeper layer)

> **Read.** For the deeper TLS layer you generate a CA + server certificate, then
> enable the encrypted 8883 listener.

**Do · Type.** Generate the certs:

```bash
./mosquitto/gen-certs.sh
```

**Check —** you should see `certs/{ca,server}.{crt,key}` written under
`mosquitto/`. If the script errors, confirm you are in `lab/twin/` and that
`openssl` is on `PATH`.

**Do · Click.** Open `mosquitto/mosquitto.secure.conf` in your editor and
uncomment the `listener 8883` block.

**Check —** the `listener 8883` lines should no longer be commented; restart the
broker to pick up the change.

---

## 3. Run the attack, watch it fail hardened

> **Read.** Bring the twin up with `--profile attack`, then drive the chain from
> the **granted cell foothold** (`adversary-foothold`, on `cell_net`). The same
> commands from `adversary` (on `attacker_net`) are **dropped at the conduit** —
> that is the segmentation lesson, exercised at the end of this section. Protocol
> roles stay precise: DNP3 **master/outstation**, MQTT **broker/publisher/subscriber**.

**Do · Type.** 1 — manipulation of control: stop both pumps with an
unauthenticated DNP3 `DIRECT_OPERATE`:

```bash
docker compose exec adversary-foothold python master.py --host 172.30.10.12 --attack
```

**Check —** *Vulnerable:* both pumps stop, `plant-sim` `spill` climbs > 0 (the SSO
is reproduced) while the HMI still reads "normal." *Hardened:* the
`DIRECT_OPERATE` is rejected (`status ≠ Success`) and `spill` stays 0. If nothing
changes, confirm you booted with `--profile attack`.

**Do · Type.** 2 — modify parameter (the Oldsmar move): push `LEAD_START` above
100% so the pumps never start:

```bash
docker compose exec adversary-foothold python master.py --host 172.30.10.12 --setpoint-lead 150
```

**Check —** *Vulnerable:* the pumps never start and `spill` climbs. *Hardened:*
the g41 setpoint write is clamped to 78% in the ladder (strictly below the 80%
lag-start), so the pumps still run and `spill` stays 0.

**Do · Type.** 3 — MQTT command injection from the cell, against the insecure
broker:

```bash
docker compose exec iiot-gw python attacker.py
```

**Check —** *Vulnerable:* the broker accepts a `CONNECT` with NO credentials and
the injected command `PUBLISH` lands. *Hardened:* the anonymous `CONNECT` is
refused by the ACL and the command path is designed out (`pump-controller`
`replicas: 0`). (`attacker.py` uses `BROKER=172.30.30.30`.)

**Do · Type.** 4 — prove segmentation: fire the identical attack from
`attacker_net` (no conduit) and watch it never reach the outstation:

```bash
docker compose exec adversary python master.py --host 172.30.10.12 --attack
```

**Check —** the packet is dropped at `zone-fw`; you should see a `CONDUIT-DROP`
line in the host kernel ring buffer (`dmesg | grep CONDUIT-DROP`), and `spill`
stays 0 because the control never arrived.

> **Read — the CIE "even-if" guarantee.** Under `--hardened`, even if every digital
> layer is owned: a replayed SAv5 control is refused for a stale CSQ, and the
> hardwired float force-starts the pump at 95% → **`spill` stays 0** (DB-1). Same
> attacker, same full write access, opposite outcome — held by an engineered
> backstop, not by trusting the network.

**Do · Type.** Legit supervised control, for contrast (a proper SELECT→OPERATE,
HMAC-tagged):

```bash
docker compose exec scada-master python master.py --host 172.30.10.12 --stop-pump 0 --sav5
```

**Check —** you should see the control accepted (`status = Success`) through the
two-phase SELECT→OPERATE handshake — the legitimate path the injected
`DIRECT_OPERATE` skips.

---

## 4. See the packets (DNP3/MQTT between containers, never loopback)

> **Read.** All traffic is plaintext and Zeek/ICSNPP-parseable, and capture is
> **out-of-band** — three taps each share a target's netns and write auto-reloading
> pcaps to `/captures`: `sniff-dnp3` (at the RTU), `sniff-mqtt` (at the broker),
> and `sniff-conduit` (the SPAN-like whole-zone tap at `zone-fw`, every
> cross-conduit packet at once). The noVNC desktops open **straight to the desktop
> with NO password**, and Wireshark is already up (if a VNC prompt ever appears,
> it's `vscode`).

**Do · Click.** Open the noVNC Wireshark (from `--profile capture`) at
`http://localhost:3000` (or `3001` for https), then **File ▸ Open** and choose
`/captures/conduit_live.pcap` (or `dnp3_live.pcap` / `mqtt_live.pcap`).

**Check —** you should see live, reloading DNP3/MQTT frames in the packet list. If
the file list is empty, confirm the `--profile capture` taps are running
(`docker compose ps`).

**Do · Click.** In that Wireshark, type `dnp3 || mqtt` in the green display-filter
bar and press Enter; then drill with `dnp3.al.func`, `dnp3.al.ctrl.code`,
`mqtt.msgtype`, or `mqtt.topic`.

**Check —** the packet list should narrow to DNP3/MQTT only. These filters are
unchanged from the teaching pcaps, so the curriculum transfers directly.

> **Read — other capture doors.** **Edgeshark** (`--profile twin-full`):
> `http://localhost:5001`, click any container interface → live-stream into desktop
> Wireshark (`cshargextcap`). **Kit noVNC desktop (port 6080):** opens straight to
> the desktop with no password (if a VNC prompt ever appears, it's `vscode`); point
> `lab/open-wireshark.sh` at the real pcaps in `lab/twin/captures/` instead of `lo`.
> Capture filter for a live tap: `tcp port 20000 or tcp port 1883 or tcp port 8883`.

**Do · Type.** Turn the pcaps into readable logs with Zeek + CISA ICSNPP
(`--profile tools`):

```bash
docker compose exec zeek run-zeek /caps/conduit_live.pcap
```

**Check —** you should see `dnp3.log`, `dnp3_control.log`, `dnp3_objects.log`, and
`mqtt_*.log` written. If `run-zeek` is not found, confirm you booted with
`--profile tools`.

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
(scada-master⇄dnp3-gw only) · **C2** MQTT/1883 cell/control→broker (**stateful
egress filtering**, not a data-diode — see below) · **C3** eng 8080/502
(control→openplc) · **C4** ent→DMZ 1883/5001. Everything else → `CONDUIT-DROP`
log + drop. The attacker zone has **no conduit**.

> **Assumption-audit — C2 is NOT a data-diode (residual risk).** Earlier drafts
> called C2 a one-way "data-diode" that blocks downward MQTT commands. That claim
> is false and is kept here as a deliberate teaching trap. The MQTT subscriber on
> the cell (e.g. `pump-controller`) *initiates* the TCP session **up** to the
> broker; because `conduits.nft` accepts `ct state established,related`, the broker
> can then fan out **any** PUBLISH — including an injected `plant/tank1/command` —
> back **down** that same established socket, and the stateful firewall accepts it.
> A stateful L3/L4 firewall cannot make a bidirectional pub/sub protocol one-way.
> **Residual risk:** broker-originated downward delivery to a cell subscriber is
> unblocked. **Exercise:** empirically test the claim (inject a command from the
> DMZ/broker side and watch it reach the cell subscriber), then design the real
> control — split telemetry and command brokers, make the command broker
> unreachable from the cell, or use a true unidirectional gateway. "Diode by
> firewall rule" is a common and false OT assumption; auditing it is the lesson.

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
  It **now enforces freshness/anti-replay**: a monotonic 32-bit Challenge Sequence
  Number (CSQ) is folded into the HMAC input and the gateway rejects any control
  whose CSQ is not strictly greater than the last accepted CSQ for that association,
  so a captured hardened SELECT+OPERATE pair replays verbatim and is refused
  (`dnp3/gateway.py`; proven headlessly by `test_sav5.py`).
- **Supervised control** writes a PLC command register (`%MW12`) the ST honors,
  rather than a raw coil the recomputing loop would overwrite — realistic SCADA
  remote-command semantics.
