# Research: Reference Architectures for a Multi-Container ICS Digital Twin

**Author:** Computer Systems Engineer/Architect researcher (O*NET 15-1299.08), ICS digital-twin Scrum
**Date:** 2026-08-14
**Purpose:** Survey buildable reference architectures for a **multi-container ICS digital twin** —
OpenPLC soft-PLC(s), Docker Compose with **segmented networks** that model the Purdue/ISA-95 levels
and IEC 62443 zones-and-conduits, DNP3 + MQTT carried across those segments, and how to keep
**packet visibility** for a Zeek/ICSNPP + Wireshark workflow. Every image, port, and command below is
sourced to a named upstream (GitHub/Docker Hub/vendor docs) verified by web fetch, Aug 2026.

> **Provenance / no-fabrication note.** Claims in the "verified" columns are quoted from the cited
> upstream. Two ports could **not** be confirmed from an OpenPLC doc line during this pass — DNP3/tcp
> **20000** and EtherNet/IP/tcp **44818** — so they are cited as the *protocols' IANA-registered
> standard ports* (which is what OpenPLC's servers use, and 20000 is what this kit already uses),
> **not** as a quoted OpenPLC config line. Any place I extrapolate to *this kit's* design is labelled
> "kit design," not an upstream claim.

---

## 0. TL;DR — the recommended target architecture

A four-service control core (**OpenPLC** runtime + **FUXA** HMI + **eclipse-mosquitto** broker +
**python DNP3** master/outstation) placed across **Purdue-aligned Docker bridge networks**, with an
out-of-band **capture plane** (a netns-sharing tcpdump sidecar *plus* Siemens **Edgeshark** for live
Wireshark), feeding **Zeek + CISA ICSNPP**. Two field-proven open-source projects already assemble
almost exactly this and are the best blueprints to copy:

- **OTForge** — `OpenPLC + FUXA + Kali + Suricata + Zeek + InfluxDB + Grafana` over **6 Purdue-aligned
  bridge nets** with an **IEC 62443-3-2 nftables zone firewall**. MIT. This is the closest match to
  the task. <https://github.com/iburres/otforge>
- **GRFICSv3** — fully containerized `OpenPLC + HMI + 3D process sim + engineering WS + Kali/Caldera +
  router-firewall + optional Wazuh`, with process/enterprise zones. GPL-3.0.
  <https://github.com/Fortiphyd/GRFICSv3>

---

## 1. Soft-PLC layer — OpenPLC (ladder/ST, Modbus/DNP3)

**Primary image — OpenPLC Runtime v3** (`thiagoralves/OpenPLC_v3`, the de-facto standard soft-PLC).
Build/run from the repo Dockerfile (verified on DeepWiki's Docker-setup page):

```bash
docker build -t openplc:latest .
docker run -it --rm --privileged -p 8080:8080 openplc:latest   # web UI at http://localhost:8080
```

- **Logic:** IEC 61131-3, primarily **Structured Text (ST)**; the bundled **MatIEC** compiler converts
  ST to C. Ladder Diagram and the other 61131-3 languages are authored in the OpenPLC Editor and
  uploaded as `.st`. Programs live in the persistent `st_files/` directory. (DeepWiki, verified.)
- **Protocols the runtime speaks:** **Modbus TCP/RTU, DNP3, EtherNet/IP, Snap7 (S7), EtherCAT.**
  (DeepWiki OpenPLC pages, verified.)
- **Ports:**
  - Web UI **8080/tcp** — *verified* (DeepWiki; netPI container README).
  - **Modbus TCP server 502/tcp** — *verified* (netPI OpenPLC container README: "By default OpenPLC
    supports Modbus TCP server functionality using the default port `502`").
  - **DNP3 outstation 20000/tcp** — protocol's IANA-registered port (`dnp`); this is the port OpenPLC's
    DNP3 server uses and the port this kit already uses. *Not* quoted from an OpenPLC doc line.
  - **EtherNet/IP 44818/tcp** — protocol's IANA-registered port. Same caveat.
  - Each protocol server is toggled in the OpenPLC web UI under Settings (DeepWiki).
- **Newer option:** **OpenPLC Runtime v4** — `Autonomy-Logic/openplc-runtime` (pairs with OpenPLC
  Editor v4). Worth tracking, but v3 has the most community lab tooling today.
- **Run privileged/`--cap-add`:** OpenPLC wants `--privileged` (or at least `NET_ADMIN`) for its
  hardware/driver layer; for a pure soft-PLC twin `NET_ADMIN` is usually enough.

Sources: [OpenPLC_v3 repo](https://github.com/thiagoralves/OpenPLC_v3) ·
[DeepWiki: Docker setup](https://deepwiki.com/thiagoralves/OpenPLC_v3/2.4-docker-setup) ·
[DeepWiki: Programming OpenPLC](https://deepwiki.com/thiagoralves/OpenPLC_v3/7-programming-openplc) ·
[netPI OpenPLC container](https://github.com/HilscherAutomation/netPI-openplc/blob/master/README.md) ·
[OpenPLC Runtime v4](https://github.com/Autonomy-Logic/openplc-runtime)

> **Kit design note.** This kit today uses a *hand-rolled* readable DNP3 (`lab/dnp3/`, `dnp3lib.py`)
> rather than OpenPLC. Adding an OpenPLC container gives real ladder/ST logic and a real Modbus/DNP3
> stack for a higher-fidelity twin, while the hand-rolled stack stays as the "readable teaching" path.

---

## 2. HMI / SCADA layer

Three open, containerizable choices, best-first for a modern twin:

| HMI | Image / source | Web port | Protocols (verified) | Notes |
|---|---|---|---|---|
| **FUXA** | `frangoteam/fuxa` ([Docker Hub](https://hub.docker.com/r/frangoteam/fuxa), [repo](https://github.com/frangoteam/FUXA)) | **1881** | Modbus RTU/TCP, **MQTT**, OPC-UA, BACnet IP, Siemens S7, EtherNet/IP (AB), ODBC | Modern web SCADA/HMI; speaks **both** Modbus (to OpenPLC) and MQTT (to mosquitto) — ideal bridge for this kit's two protocols. |
| **Scada-LTS** | `scadalts/scadalts` ([Docker Hub](https://hub.docker.com/r/scadalts/scadalts/)) | 8080 (Tomcat) | Modbus, DNP3, MQTT, SNMP, OPC | Maintained successor to **ScadaBR**; Tomcat + MySQL stack. |
| **ScadaBR** | `bitelxux/scadabr` ([Docker Hub](https://hub.docker.com/r/bitelxux/scadabr)) | 8080 | Modbus, DNP3, MQTT | The classic ScadaBR the task named; community Docker image. Pairs with OpenPLC over Modbus (OpenPLC forum: "OpenPLC with ScadaBR and DNP3"). |

```bash
docker run -d -p 1881:1881 \
  -v fuxa_appdata:/usr/src/app/FUXA/server/_appdata \
  frangoteam/fuxa:latest                              # FUXA HMI, verified
```

Sources: [FUXA repo](https://github.com/frangoteam/FUXA) ·
[FUXA on Docker Hub](https://hub.docker.com/r/frangoteam/fuxa) ·
[Scada-LTS on Docker](https://github.com/SCADA-LTS/Scada-LTS/wiki/Run-ScadaLTS-on-docker---instruction) ·
[bitelxux/scadabr](https://hub.docker.com/r/bitelxux/scadabr)

---

## 3. Messaging + DNP3 layers

- **MQTT broker — `eclipse-mosquitto:2`** (already used by this kit, `lab/mosquitto/`). Auth + ACL +
  TLS(8883) configs are the security-teaching surface. Official image.
- **DNP3 in Python:**
  - **`dnp3-python`** (VOLTTRON) — `pip install dnp3-python`, ships a `dnp3demo` master/outstation.
    A pybind wrapper over **opendnp3**. Best "real stack" option. <https://github.com/VOLTTRON/dnp3-python>
  - **`opendnp3`** (C++ reference stack) — *archived/EOL*; fine for a lab, not production.
    <https://github.com/dnp3/opendnp3>
  - This kit's own minimal DNP3 (`lab/dnp3/`) stays as the readable teaching implementation; swap in
    `dnp3-python` for a fuller outstation. (OTForge uses OpenDNP3 for the same role.)

---

## 4. Segmentation — Purdue/ISA-95 levels → IEC 62443 zones & conduits in Compose

**The pattern:** one **user-defined Docker bridge network per zone**; a **dual-homed** container per
**conduit**; Docker's native inter-network isolation stands in for a VLAN / zone firewall. This kit
already does the minimal 2-zone version (`ot_cell` L1/L2 + `site_dmz` L3/L3.5, FEP as the only
conduit). The reference architectures scale it to the full Purdue stack.

**OTForge's 6-network layout (verified, copy this):**

| Purdue level | Docker network | Subnet | Contents |
|---|---|---|---|
| L0–L2 (process/OT) | `ot-net` | 10.200.10.0/24 | PLCs, RTUs, IEDs, sensors, actuators |
| L3 (control center) | `control-net` | 10.200.20.0/24 | HMI, historian, workstations |
| L3.5 (plant DMZ) | `plant-dmz-net` | 10.200.30.0/24 | firewall, IDS/IPS, router |
| L4 (enterprise) | `enterprise-net` | 10.200.40.0/24 | domain controller, servers |
| L5 (internet DMZ) | `internet-dmz-net` | 10.200.50.0/24 | email, web |
| — (red team) | `attacker-net` | 10.200.60.0/24 | Kali |

- **Zones & conduits enforcement:** OTForge adds an **IEC 62443-3-2 "zone-aware firewall rule editor
  with nftables enforcement"** so inter-zone flow is deny-by-default — the *conduit* becomes an
  explicit allow-rule, not just Docker's default isolation. This is the standards-faithful upgrade
  over relying on bridge isolation alone.
- **Where the sensor goes:** because all inter-zone traffic must cross the firewall/router container
  (OTForge, GRFICSv3), that container is the natural **conduit tap** for Zeek/Suricata — the digital
  equivalent of a SPAN at the OT/DMZ boundary.

**Authoritative references for the model itself:**
- **NIST SP 800-82 Rev.3**, *Guide to OT Security* — the canonical US-gov reference for OT
  segmentation, zones/conduits, and defense-in-depth.
  <https://csrc.nist.gov/pubs/sp/800/82/r3/final>
- **IEC 62443-3-2** (risk assessment → **zones and conduits**) and **IEC 62443-3-3** (system security
  requirements). Peer-reviewed treatment: MDPI, *Security Aspects of Zones and Conduits in IEC 62443*.
  <https://www.mdpi.com/2624-800X/6/2/52>
- **SANS**, *The Purdue Model — Introduction to ICS Security Pt.2*.
  <https://www.sans.org/blog/introduction-to-ics-security-part-2>

Sources: [OTForge](https://github.com/iburres/otforge) ·
[NIST SP 800-82r3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) ·
[IEC 62443 zones/conduits (MDPI)](https://www.mdpi.com/2624-800X/6/2/52) ·
[SANS Purdue Model](https://www.sans.org/blog/introduction-to-ics-security-part-2)

---

## 5. Packet visibility across the segments (the crux)

Docker bridges have **no native SPAN/mirror**, so choose from these verified techniques (a real twin
uses 2–3 together):

1. **Netns-sharing tcpdump sidecar (per-host tap) — this kit's current method.** A sniffer container
   joins the target's network namespace and captures to a shared pcap volume:
   ```yaml
   sniff-dnp3:
     image: nicolaka/netshoot
     network_mode: "service:openplc"        # share the PLC's netns
     cap_add: [NET_ADMIN, NET_RAW]
     command: tcpdump -i any -U -w /caps/dnp3_live.pcap "tcp port 20000"
     volumes: ["./captures:/caps"]
   ```
   Precise (sees exactly that host's traffic), survives restarts, writes a Zeek-ready pcap.
2. **Host-side bridge capture (whole-zone tap).** Every user-defined network has a Linux bridge
   (`docker network inspect <net>` → find `br-xxxxxxxx`); `sudo tcpdump -i br-xxxxxxxx` sees **all**
   containers on that zone at once — the closest thing to mirroring an entire segment.
3. **Siemens Edgeshark + `cshargextcap` (live Wireshark from any container).** MIT-licensed
   containerized service + a Wireshark **extcap** plugin; web UI on **5001**, click any container
   interface to start a live capture. Deploy one-liner (verified):
   ```bash
   wget -q --no-cache -O - \
     https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose-localhost.yaml \
     | DOCKER_DEFAULT_PLATFORM= docker compose -f - up
   ```
   Plugin: <https://github.com/siemens/cshargextcap/releases>. Needs Linux kernel ≥4.11 (≥5.6 rec.).
4. **containerlab-style SSH pipe to a desktop Wireshark** (verified pattern):
   ```bash
   ssh $HOST "ip netns exec <node> tcpdump -U -nni <if> -w -" | wireshark -k -i -
   ```
5. **Wireshark GUI in the browser (noVNC/KasmVNC).** `lscr.io/linuxserver/wireshark` — web GUI on
   **3000/http, 3001/https**, `--cap-add=NET_ADMIN`, `--net=host` to see host/bridge traffic
   (verified). This kit already ships a noVNC Wireshark in `.devcontainer/` on port **6080** for
   Codespaces — the LinuxServer image is the standalone-container equivalent.
   ```bash
   docker run -d --name=wireshark --net=host --cap-add=NET_ADMIN \
     -p 3000:3000 -p 3001:3001 lscr.io/linuxserver/wireshark:latest
   ```
6. **True SPAN via Open vSwitch (highest fidelity).** Replace a zone's bridge with an OVS container and
   configure a **mirror port** to a dedicated IDS interface — a real switch SPAN for a Zeek/Suricata
   sensor. Heavier to wire; use when the lesson *is* mirroring.

**Feed it to detection:** pcaps from (1)/(2) → **Zeek + CISA ICSNPP** (`icsnpp-dnp3`, built-in MQTT
analyzer) → `dnp3*.log` / `mqtt*.log` (this kit's `lab/zeek/`). OTForge/GRFICS wire **Suricata (ET ICS
rules)** and **Wazuh** on the same tap for the IDS/SIEM half.

Sources: [Edgeshark](https://github.com/siemens/edgeshark) · [Edgeshark site](https://edgeshark.siemens.io/) ·
[cshargextcap](https://github.com/siemens/cshargextcap) ·
[containerlab: Wireshark](https://containerlab.dev/manual/wireshark/) ·
[LinuxServer Wireshark](https://docs.linuxserver.io/images/docker-wireshark/)

---

## 6. Full reference architectures to copy (verified)

- **OTForge** (`iburres/otforge`, **MIT**) — the strongest single blueprint for this task:
  OpenPLC + FUXA + Kali(KasmVNC) + **Suricata (ET ICS rules)** + **Zeek** + InfluxDB 1.8 + Grafana +
  Loki/Promtail, over the 6 Purdue nets in §4, with the **nftables IEC 62443-3-2 zone firewall**.
  Uses authentic protocol stacks (**pymodbus, OpenDNP3, node-opcua, bacpypes, cpppo, libiec61850**)
  and captures "genuine packets, not application-layer simulations." <https://github.com/iburres/otforge>
- **GRFICSv3** (`Fortiphyd/GRFICSv3`, **GPL-3.0**) — fully containerized: **OpenPLC** + HMI + web **3D
  chemical-plant process sim** + engineering workstation + **Kali + MITRE Caldera** + router/firewall +
  optional **Wazuh** SIEM; process/enterprise zones with controllable flow. (v2 was VirtualBox VMs;
  v3 moved to Docker.) <https://github.com/Fortiphyd/GRFICSv3>
- **DHALSIM** (`Critical-Infrastructure-Systems-Lab/DHALSIM`, **MIT**; SUTD CISL / TU Delft / CISPA /
  iTrust) — water-distribution **digital twin**: WNTR/**EPANET** physics + **Mininet + MiniCPS** PLC/
  SCADA emulation over **Modbus TCP**, and it **emits network captures of the PLCs/SCADA**. Note it
  uses **Mininet (network namespaces), not Docker Compose** — the best cite for *physics-coupled*
  twin fidelity and for pcap generation, contrasting with the Compose-native OTForge/GRFICS.
  <https://github.com/Critical-Infrastructure-Systems-Lab/DHALSIM>

---

## 7. Concrete image/tooling shortlist (all verified this pass)

| Role | Image / package | Key port(s) | Source |
|---|---|---|---|
| Soft-PLC (ladder/ST, Modbus/DNP3) | build `thiagoralves/OpenPLC_v3`; v4 `Autonomy-Logic/openplc-runtime` | 8080 web, 502 Modbus, (20000 DNP3, 44818 ENIP = std ports) | [repo](https://github.com/thiagoralves/OpenPLC_v3) |
| HMI/SCADA (modern) | `frangoteam/fuxa` | 1881 | [Docker Hub](https://hub.docker.com/r/frangoteam/fuxa) |
| HMI/SCADA (ScadaBR lineage) | `scadalts/scadalts`, `bitelxux/scadabr` | 8080 | [Scada-LTS](https://hub.docker.com/r/scadalts/scadalts/) |
| MQTT broker | `eclipse-mosquitto:2` | 1883 / 8883 | Docker Official |
| DNP3 (Python, full) | `dnp3-python` (pip; wraps opendnp3) | 20000 | [repo](https://github.com/VOLTTRON/dnp3-python) |
| Net toolbox / sniffer sidecar | `nicolaka/netshoot` | — | Docker Hub |
| Live container Wireshark | `siemens/edgeshark` + `cshargextcap` | 5001 | [repo](https://github.com/siemens/edgeshark) |
| Wireshark web GUI (noVNC) | `lscr.io/linuxserver/wireshark` | 3000/3001 | [docs](https://docs.linuxserver.io/images/docker-wireshark/) |
| Network sensor | Zeek + CISA **ICSNPP** (`icsnpp-dnp3`) | — | this kit `lab/zeek/` |
| IDS / SIEM (optional) | Suricata (ET ICS rules), Wazuh | — | OTForge / GRFICSv3 |

---

## 8. How this maps onto THIS kit (kit design)

- **Keep** the 2-zone `docker-compose.segmented.yml` (`ot_cell` / `site_dmz`, FEP-as-conduit) as the
  minimal teaching case; **extend** toward OTForge's 6-net Purdue layout for a full-fidelity twin.
- **Add** an **OpenPLC** container on `ot_cell` (Modbus 502 + DNP3 20000) driven by a small ST program,
  and point **FUXA** (in `site_dmz`, port 1881) at it over Modbus and at `mosquitto` over MQTT — one
  HMI spanning both of the kit's protocols.
- **Upgrade segmentation enforcement** from bare Docker isolation to an **nftables zone firewall**
  container (OTForge pattern) so the *conduit* is an explicit allow-rule = IEC 62443-3-2 faithful.
- **Packet plane:** keep the netns tcpdump sidecars (§5.1), **add Edgeshark** (§5.3) for click-to-
  Wireshark, and keep the noVNC Wireshark (already on 6080) — LinuxServer's image is the drop-in.
- **Detection:** existing Zeek+ICSNPP stays the analysis core; optionally add Suricata ET-ICS at the
  conduit tap for the IDS half.

---

### Source index (all fetched/verified Aug 2026)
OpenPLC: [v3 repo](https://github.com/thiagoralves/OpenPLC_v3) ·
[Docker setup](https://deepwiki.com/thiagoralves/OpenPLC_v3/2.4-docker-setup) ·
[programming](https://deepwiki.com/thiagoralves/OpenPLC_v3/7-programming-openplc) ·
[netPI](https://github.com/HilscherAutomation/netPI-openplc/blob/master/README.md) ·
[v4](https://github.com/Autonomy-Logic/openplc-runtime) ·
HMI: [FUXA](https://github.com/frangoteam/FUXA) ·
[Scada-LTS](https://github.com/SCADA-LTS/Scada-LTS/wiki/Run-ScadaLTS-on-docker---instruction) ·
[ScadaBR](https://hub.docker.com/r/bitelxux/scadabr) ·
DNP3: [dnp3-python](https://github.com/VOLTTRON/dnp3-python) · [opendnp3](https://github.com/dnp3/opendnp3) ·
Reference archs: [OTForge](https://github.com/iburres/otforge) ·
[GRFICSv3](https://github.com/Fortiphyd/GRFICSv3) ·
[DHALSIM](https://github.com/Critical-Infrastructure-Systems-Lab/DHALSIM) ·
Segmentation: [NIST SP 800-82r3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) ·
[IEC 62443 zones/conduits](https://www.mdpi.com/2624-800X/6/2/52) ·
[SANS Purdue](https://www.sans.org/blog/introduction-to-ics-security-part-2) ·
Capture: [Edgeshark](https://github.com/siemens/edgeshark) ·
[cshargextcap](https://github.com/siemens/cshargextcap) ·
[containerlab Wireshark](https://containerlab.dev/manual/wireshark/) ·
[LinuxServer Wireshark](https://docs.linuxserver.io/images/docker-wireshark/)
