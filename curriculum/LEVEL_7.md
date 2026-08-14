# Level 7 — The living plant

*Beyond the descent — your field skills on the twin's live, multi-zone traffic*

**Difficulty:** Advanced &nbsp;·&nbsp; **Time:** ~60 min &nbsp;·&nbsp; **Prerequisite:** Levels 0–6 (the full descent, including the Machine Problem). Docker + the compose plugin (the Codespace ships them).

**Goal.** Take the exact Level 3–5 field-analysis skills onto the digital twin's LIVE multi-zone traffic: catch a forged-link DNP3 control and an MQTT command injection on the wire, watch them spill the wet-well, then flip to `--hardened` and prove the same attack is refused.

## What you'll be able to do

- Re-run your Level 1–3 skills on the twin's LIVE multi-zone DNP3 + MQTT traffic — not a fixed teaching pcap.
- Fire the forged-link DIRECT_OPERATE and the MQTT command injection from the granted cell foothold, and watch the SSO spill counter climb.
- Flip to `--hardened`, replay the same attack, and prove it is refused while the spill counter stays 0 — the CIE 'even-if' acceptance test.

## Background

Levels 0–6 trained your eye on a clean loopback capture. The **digital twin** is the same protocols on a *living* plant: **OpenPLC** (a Modbus **client**) driving a simulated wet-well (the Modbus **server**), fronted by a DNP3 **outstation** gateway on TCP/20000 that a SCADA **master** polls, and an MQTT **broker** with a telemetry **publisher** and a pump-controller **subscriber** — all across five segmented IEC-62443 zones behind an nftables conduit firewall, with an out-of-band tap so every packet still reaches Wireshark.

Nothing here is a new skill. You already know how to map endpoints (Level 1), classify function codes and control packets (Level 2), read `dnp3.src` against `ip.src` and the MQTT retain/username fields (Level 3), turn those fields into a finding (Level 4), and bind a spoof-resistant invariant (Level 5). Level 7 points those exact skills at real, multi-zone traffic that fights back — and at a physical consequence you can measure: gallons of sanitary-sewer overflow.

## Do this

- **Note:** **Apply your Level 0 skill — 'see it running' — to an entire plant.** Boot the multi-zone digital twin with the adversary foothold staged (the capture plane comes up automatically):

`bash lab/twin/launch-twin.sh --attack`

Doors once it boots: OpenPLC control logic **:8088** · FUXA HMI **:1881** · noVNC Wireshark **:3000**. The objective scoreboard is the plant-sim SSO **spill** counter — Pass = spill stays 0 under full DNP3 + MQTT write access. Follow it with `bash lab/twin/launch-twin.sh --logs`.
- **In Wireshark:** **Apply your Level 1 skill — the map before the message — to five zones.** Open Wireshark at **:3000**, load `/caps/conduit_live.pcap` (the whole-zone conduit tap), and run **Statistics ▸ Conversations** (TCP): the SCADA master ↔ outstation on 20000 and the MQTT broker star on 1883, both crossing the `zone-fw` conduit between IEC-62443 zones.
```bash
# Level 1, headless: who is talking across the conduit right now?
tshark -r lab/twin/captures/conduit_live.pcap -q -z conv,tcp
```
> **Expected:** the SCADA master↔outstation on 20000 and the broker star on 1883, both crossing zone-fw — plus the foothold 172.30.10.66, an endpoint that fits no legitimate role.

```bash
# Level 2, live: classify the vocabulary on real multi-zone traffic
tshark -r lab/twin/captures/conduit_live.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c
tshark -r lab/twin/captures/mqtt_live.pcap  -Y mqtt -T fields -e mqtt.msgtype | sort | uniq -c
```
> **Expected:** READ(1)/RESPONSE(129) polling from the SCADA master, plus the injected DIRECT_OPERATE(5); MQTT PUBLISH(3) telemetry plus the rogue CONNECT(1) and its injected PUBLISH.

```bash
# Level 4, live: turn access into a finding — fire the attack from the granted cell foothold.
# (run from lab/twin/; the launcher pins the compose project 'ics-twin-liftstation')
cd lab/twin && docker compose -p ics-twin-liftstation -f docker-compose.twin.yml \
  exec adversary-foothold python master.py --host 172.30.10.12 --attack
# ...and the MQTT command injection from the insecure cell:
docker compose -p ics-twin-liftstation -f docker-compose.twin.yml \
  exec iiot-gw python attacker.py
```
> **Expected:** adversary-foothold: DIRECT_OPERATE(5) accepted, pumps forced off. attacker.py: CONNECT accepted with NO credentials, command PUBLISHed. The spill scoreboard (launch-twin.sh --logs) starts climbing.

```bash
# Level 3, live: read the deciding field on the conduit tap — the SAME tell as the teaching capture.
tshark -r lab/twin/captures/conduit_live.pcap -Y "dnp3.al.func==5" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.al.func
# and the MQTT anonymous connect the broker accepted:
tshark -r lab/twin/captures/mqtt_live.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number -e mqtt.clientid
```
> **Expected:** a DIRECT_OPERATE whose dnp3.src claims 100 (the master) but whose ip.src is 172.30.10.66 (the foothold) — the Level 3 link-vs-IP contradiction, now on five-zone traffic — and an anonymous CONNECT from mqtt-explorer-x.

```bash
# Level 5, live: key on the invariant, watch it hold. Flip every CIE control on and replay the SAME attack.
bash lab/twin/launch-twin.sh --hardened --attack
cd lab/twin && docker compose -p ics-twin-liftstation -f docker-compose.twin.yml -f docker-compose.hardened.yml \
  exec adversary-foothold python master.py --host 172.30.10.12 --attack
```
> **Expected:** the DIRECT_OPERATE is refused (status != Success): SAv5 + the arm-latch reject a lone control and the allow-list drops the forged link. Even if a control is bypassed, the hardwired HH float force-starts the pump at 95% — the spill counter stays 0.

- **Note:** **This is your capstone artifact.** Diff the two runs — vulnerable `spill > 0` vs hardened `spill == 0` under identical write access — and the two `dnp3_control.log` files (add `--tools` for Zeek + CISA ICSNPP). Submit the twin evidence bundle (the conduit pcap + the plant-sim spill log + the Zeek logs) and grade it against **projects/ARTIFACT_RUBRIC.md** — R4 (invariant detection), R5 (the SSO High-Consequence Event), and R6 (proving the backstop holds under full write access).

## Check yourself

1. **On the live conduit capture, a DIRECT_OPERATE trip carries `dnp3.src`=100 (the master) but `ip.src`=172.30.10.66 (the foothold). Which Level 3 tell catches it, and why does the outstation still obey?**
   <details><summary>answer</summary>The link-address-vs-IP-source mismatch — `dnp3.src` (the 16-bit DNP3 link address) disagrees with `ip.src`. DNP3 authenticates neither, so with SAv5 off the outstation obeys any well-formed frame. It is the exact Level 3–4 tell, now on live multi-zone traffic.</details>

2. **You gave the attacker full DNP3 + MQTT write access in `--hardened` mode, yet the SSO spill counter stayed 0. What held it — and what did NOT?**
   <details><summary>answer</summary>An engineered process backstop held it: the hardwired high-high float force-starts the pump at 95%, plus the ST setpoint clamp/interlock — spill stays 0 even if authentication is fully bypassed. What did NOT hold it is trust in the network or the identity; the CIE 'even-if' guarantee is a physical/logic backstop, not an access control.</details>

3. **The same `docker compose exec adversary python master.py --attack` from `attacker_net` is dropped, while the foothold on `cell_net` succeeds. Why?**
   <details><summary>answer</summary>The nftables conduit firewall (`zone-fw`) between IEC-62443 zones blocks the cross-zone path from attacker_net, so the packet never reaches the outstation; the granted foothold sits inside cell_net, past the conduit. Segmentation is the defense-in-depth layer — the attack only lands once the attacker is already inside the zone.</details>

**Level up:** You can carry the Level 1–5 skills onto live, multi-zone twin traffic, force and observe a physical SSO spill, and demonstrate the CIE 'even-if' backstop that holds spill at 0 under full write access. Package the run as your capstone artifact for projects/ARTIFACT_RUBRIC.md.
