# ICS/OT Protocol Analysis Lab

A self-contained Docker lab for the DNP3 and MQTT modules. You get a live MQTT
broker with a sensor and dashboard, a DNP3 outstation and master, packet
capture, and Zeek + CISA's ICSNPP parsers to turn traffic into readable logs.

> **Safety.** Everything runs on an isolated Docker bridge network. The
> "attacker" scripts and the insecure broker are for this lab only — never point
> them at systems you do not own.

> **No local install? Use GitHub Codespaces.** The repo's `.devcontainer/` gives you a
> browser-visible **Wireshark GUI over noVNC**. Open the Codespace, open port **6080**
> (no password — it opens straight to the desktop), then `./lab/run-local.sh up` → `./lab/open-wireshark.sh` → capture
> on interface `lo`. Details: `.devcontainer/README.md`.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose version`) — **already provided in the Codespaces devcontainer.**
- Wireshark (to open the provided `.pcap` files and any you capture) — **provided in Codespaces; open with `./open-wireshark.sh`.**
- The kit's `pcaps/` folder must sit next to this `lab/` folder (the Zeek
  service mounts the kit root at `/kit`).

## Fastest path (localhost, best for the Codespaces GUI)

```bash
./run-local.sh up        # MQTT broker (1883) + DNP3 outstation (20000) as localhost processes
./open-wireshark.sh      # Wireshark on the noVNC desktop — capture on 'lo'
./run-local.sh dnp3      # poll + supervised close + rogue trip
./run-local.sh mqtt      # publish/subscribe + anonymous eavesdrop + command injection
./run-local.sh down
```

## Quick start

```bash
cd lab
docker compose up --build          # starts the insecure broker, sensor, HMI, and DNP3 outstation
```

You will see the sensor publishing and the HMI receiving telemetry. Leave it
running and open a second terminal for the exercises below.

### What's running

| Service | Role | Address on the lab network |
|---|---|---|
| `broker` | Mosquitto MQTT broker (insecure by default) | `broker:1883`, published to `localhost:1883` |
| `mqtt-publisher` | Field sensor `field-sensor-07` | — |
| `mqtt-subscriber` | HMI dashboard `hmi-scada-01` | — |
| `dnp3-outstation` | Substation RTU (DNP3 addr 10) | `dnp3-outstation:20000` |
| `mqtt-attacker` | Rogue MQTT host (profile `attack`) | — |
| `dnp3-master` | DNP3 master (profile `tools`) | — |
| `zeek` | Zeek + ICSNPP analysis box (profile `tools`) | — |
| `sniff-mqtt` / `sniff-dnp3` | tcpdump capture (profile `capture`) | — |

## MQTT exercises

**1 — Watch the insecure broker.** With the stack up, capture live traffic:

```bash
docker compose --profile capture up sniff-mqtt      # writes lab/captures/mqtt_live.pcap
```

Open `captures/mqtt_live.pcap` in Wireshark. Apply `mqtt` and confirm you can
read the sensor's username/password in the CONNECT (control **M1**).

**2 — Run the intrusion.** In another terminal:

```bash
docker compose --profile attack run --rm mqtt-attacker
```

The attacker connects with no credentials, subscribes to `#`, prints the
telemetry it eavesdrops, and publishes an unauthorized command — the frame
38→52 story from the module, live. Watch `docker compose logs -f pump-controller`:
the injected command actually reaches the simulated actuator and toggles its
state, so you see the *impact*, not just an accepted publish.

**3 — Harden the broker.** Edit `docker-compose.yml` and change the broker's
config mount from `mosquitto.insecure.conf` to `mosquitto.secure.conf`, then:

```bash
docker compose up -d broker            # reload with auth + ACLs
docker compose --profile attack run --rm mqtt-attacker
```

Now the anonymous CONNECT is refused with return code 5 (Not Authorized) and the
intrusion fails. The ACL additionally scopes each authenticated client to its
own topics. Add TLS on 8883 (see "TLS" below) to also hide credentials and
payloads (controls **M1–M4**).

## DNP3 exercises

**1 — Poll and control.** With `dnp3-outstation` running:

```bash
docker compose --profile tools run --rm dnp3-master python master.py --host dnp3-outstation
docker compose --profile tools run --rm dnp3-master python master.py --host dnp3-outstation --close
```

The master prints the outstation's binary/analog telemetry and performs a
supervised SELECT→OPERATE breaker close. Watch the outstation's log:
`docker compose logs -f dnp3-outstation`.

**2 — Inject an unauthenticated trip (from a non-master host).**

```bash
docker compose --profile attack run --rm dnp3-attacker
```

The `dnp3-attacker` service runs the injection from its **own container IP** — a
non-master source — so your live capture matches the provided pcap *and* the
"alarm on controls from a non-master source" detection actually fires. The
outstation obeys a DIRECT_OPERATE **TRIP** with no SELECT and no authentication
and logs it loudly (the frame 27 story). For the availability attack (frame 31):
`docker compose --profile tools run --rm dnp3-master python master.py --host dnp3-outstation --restart`.

Detection caveat (see the module's *Detection under adversarial and operational
reality*): this fires only because the attacker kept a distinct IP. A smarter
attacker spoofs the master's IP or hijacks its TCP session — add `--src-addr 100`
to also forge the master's DNP3 link address and see why a single-source-IP rule
is not enough.

**3 — Capture it.**

```bash
docker compose --profile capture up sniff-dnp3      # writes lab/captures/dnp3_live.pcap
```

Open in Wireshark and compare your live capture to the provided
`dnp3_substation.pcap`.

## Segmentation — build a zone boundary and watch the attack die at the conduit

The default lab is one flat network so the protocol lessons are easy to see — but
a flat OT network is itself the vulnerability. `docker-compose.segmented.yml`
splits the lab into two IEC 62443 zones (`ot_cell` 172.28.10.0/24 and `site_dmz`
172.28.20.0/24) isolated by Docker's inter-network isolation, with the DNP3
master (front-end processor) as the **only** device bridging them — the
sanctioned conduit.

```bash
docker compose -f docker-compose.segmented.yml up -d --build
```

**Fire the DMZ attacker (blocked):**

```bash
docker compose -f docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-dmz
```

It is handed the RTU's exact address (172.28.10.10) yet hangs and fails
(`Errno 110`) — it has no leg in `ot_cell`, so Docker drops the SYN between
bridges. Prove it from the DMZ jump box:
`docker compose -f docker-compose.segmented.yml exec historian nc -zv -w3 172.28.10.10 20000` (fails).

**Fire the OT-cell attacker (succeeds):**

```bash
docker compose -f docker-compose.segmented.yml --profile attack run --rm dnp3-attacker-otcell
```

Same payload, but L2-adjacent to the RTU — the outstation executes the trip. The
lesson: **L2 adjacency to the RTU is the vulnerability; segmentation removes the
adjacency, so the attack dies at the conduit, not at the RTU.** The same contrast
works for MQTT (`mqtt-attacker-dmz` blocked vs `mqtt-attacker-otcell` succeeds
against the cell broker). Reset with
`docker compose -f docker-compose.segmented.yml --profile "*" down`.

### Order your controls: segmentation first

Lead with the controls you can deploy without re-flashing a device: **zones &
conduits** (an OT firewall that lets only the sanctioned FEP reach the RTU on
tcp/20000), then **monitoring** at the conduit tap, then **DNP3-SA / TLS** as the
durable cryptographic upgrade — which needs capable firmware on both ends and a
longer change window. Segmentation is the compensating control that buys the time
to get there.

### Two things detection can't do for free

- **Encryption takes the sensor dark.** Once you tunnel DNP3 over TLS/VPN or move MQTT
  to 8883, the Zeek/ICSNPP network sensor goes dark (no `mqtt_*.log` on 8883; a
  DNP3-in-TLS tunnel is opaque). Detection then lives in broker auth logs,
  RTU/endpoint syslog, and flow/JA3 metadata. Note DNP3-SA (a MAC) does **not**
  take ICSNPP dark — only transport encryption does.
- **Tap placement matters.** The sensor only sees what its tap sees. Put it on a
  SPAN/mirror at the OT/DMZ conduit the master crosses. An attacker injecting into
  the *local* RTU never crosses a control-center SPAN, and serial-tail DNP3 is
  invisible to any network sensor.

## Analyze with Zeek + CISA ICSNPP

```bash
docker compose --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap
docker compose --profile tools run --rm zeek run-zeek /kit/pcaps/mqtt_iot_telemetry.pcap
```

This produces `dnp3.log`, `dnp3_control.log`, `dnp3_objects.log` (DNP3, via the
CISA `icsnpp-dnp3` extension) and `mqtt_connect.log`, `mqtt_publish.log`,
`mqtt_subscribe.log` (MQTT, Zeek's built-in analyzer). Pre-generated copies of
these logs from the provided captures are in `zeek_reference_output/`.

Key detection: in `dnp3_control.log`, any `DIRECT_OPERATE` / `Trip` whose source
host is **not** the sanctioned master is your alert for the injection.

## Replaying the provided captures (tcpreplay)

To feed the provided pcaps to a sensor/IDS instead of generating live traffic:

```bash
sudo tcpreplay -i eth0 ../pcaps/dnp3_substation.pcap
```

Note: `tcpreplay` injects the captured frames verbatim at Layer 2 — the source
MAC/IP won't match your lab hosts, so real devices won't respond. It is for
feeding monitoring tools, not for driving a two-way exchange. Use
`tcpreplay-edit --enet-dmac=… --pnat=…` to rewrite addresses to your topology.

## TLS (optional, controls M1/M2)

```bash
# from lab/mosquitto/ — generate a demo CA + server cert
mkdir -p certs && cd certs
openssl req -new -x509 -days 365 -nodes -keyout ca.key -out ca.crt -subj "/CN=lab-ca"
openssl req -new -nodes -keyout server.key -out server.csr -subj "/CN=broker"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt
```

Uncomment the `listener 8883` block in `mosquitto.secure.conf`, restart the
broker, and connect a client with `--cafile ca.crt -p 8883`. Capture on 8883 and
confirm the credentials and payloads are now unreadable.

## Going further

- **Fuller DNP3 stack:** the lab's `outstation.py`/`master.py` are deliberately
  small and readable. For a production-grade stack, try
  [`dnp3-python`](https://github.com/VOLTTRON/dnp3-python) (`pip install dnp3-python`,
  then `dnp3demo`) or [opendnp3](https://github.com/dnp3/opendnp3) (note: opendnp3
  is archived/EOL — fine for a lab, not for production).
- **Reset the lab:** `docker compose --profile "*" down -v`

## Files

```
lab/
├── docker-compose.yml
├── mosquitto/   mosquitto.insecure.conf · mosquitto.secure.conf · passwd · acl
├── mqtt/        publisher.py · subscriber.py · attacker.py · Dockerfile
├── dnp3/        outstation.py · master.py · dnp3lib.py · Dockerfile
├── zeek/        Dockerfile · local.zeek · run-zeek.sh
├── captures/    (your live captures land here)
└── zeek_reference_output/   pre-generated dnp3_*.log and mqtt_*.log
```
