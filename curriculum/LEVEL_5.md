# Level 5 — Catch it automatically

*Detection engineering — from one packet to a rule*

**Difficulty:** Advanced &nbsp;·&nbsp; **Time:** ~40 min &nbsp;·&nbsp; **Prerequisite:** Level 4.

**Goal.** Write detection that survives a real adversary — key on invariants, not on a single spoofable field — and turn packets into logs with Zeek + CISA ICSNPP.

## What you'll be able to do

- Write tshark/display-filter detections for the anomalies.
- Run Zeek + the ICSNPP DNP3 parser and read dnp3_control.log / mqtt_*.log.
- Explain why 'alert on wrong source IP' is naive and what invariant beats it.

## Background

A detection is only as good as its evasion resistance. The obvious DNP3 rule — 'alert if a control's source IP isn't the master' — fails the moment the attacker spoofs the master's IP. The durable rule binds an **invariant**: {DNP3 link address ↔ expected source ↔ known-master set ↔ SELECT-before-OPERATE}. Read the modules' 'Detection under adversarial and operational reality' section.

## Do this

```bash
# a first-cut DNP3 rule: controls not from the master IP
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5,13} && ip.src != 10.20.0.5" -T fields -e frame.number -e ip.src -e dnp3.al.func
```
> **Expected:** catches the rogue trip & restart HERE — but only because the attacker kept its real IP.

```bash
# turn packets into readable logs with Zeek + CISA ICSNPP
docker compose -f lab/docker-compose.yml --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap
cat lab/zeek_reference_output/dnp3/dnp3_control.log | grep -i direct
```
> **Expected:** a DIRECT_OPERATE / Trip / Success line whose source host is 10.20.0.66 — your best single alert.

```bash
# MQTT detections: anonymous connect, and a '#' subscribe
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y "mqtt.msgtype==1 && !mqtt.username" -T fields -e frame.number
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y 'mqtt.msgtype==8 && mqtt.topic=="#"' -T fields -e frame.number
```
> **Expected:** the anonymous CONNECT and the wildcard SUBSCRIBE.

- **Note:** Now break your own rule: in the lab, re-run the DNP3 attack with `--src-addr 100` (spoofing the master's link address) and with a spoofed IP, and watch the naive source-IP rule miss it. That's why Level 6 asks for an invariant detector.

## Check yourself

1. **Why is 'alert when a control's source IP isn't the master' insufficient?**
   <details><summary>answer</summary>The source IP (and the DNP3 link address) are attacker-controlled/spoofable, and real outstations answer to *several* legitimate masters — so it both misses spoofed sources and false-positives on backups/FEPs.</details>

2. **What does Zeek + ICSNPP give you that a raw pcap doesn't?**
   <details><summary>answer</summary>Structured, queryable logs (dnp3_control.log, dnp3_objects.log, mqtt_*.log) you can alert and hunt on at scale — e.g., every control with its operation type, source host, and status.</details>

**Level up:** You can write detections, generate ICSNPP logs, and articulate the invariant-based rule that resists spoofing. You are ready for the Machine Problem.
