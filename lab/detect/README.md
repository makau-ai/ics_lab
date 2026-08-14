# `lab/detect/` — runnable invariant detectors

The DNP3 and MQTT modules describe *durable, invariant-based detection* in prose
("Detection under adversarial and operational reality") but the kit shipped no
code a student could run — and then evade. This directory closes that gap
(PANEL_REVIEW P0 item 3; `review_1.json`, `review_3.json`).

Each detector is small, dependency-light (Python stdlib + the `tshark` binary),
and **keyed on a protocol invariant, not a hard-coded frame number** — so it
reads any capture, not just the shipped teaching pcaps. Every detector:

- takes a **pcap path** as its argument,
- prints the **offending frames + WHY** (the invariant each frame violated),
- exits **`0` = clean**, **`1` = alert**, **`2` = usage/environment error**
  (so they compose in shell pipelines and CI).

> Protocol terms are used precisely: DNP3 **master/outstation**;
> MQTT **broker/publisher/subscriber**.

---

## The detectors

| Script | Invariant it enforces | Fires on the teaching pcap |
|---|---|---|
| `dnp3_link_spoof.py` | Each DNP3 **link address (`dnp3.src`) is sourced from exactly one `ip.src`.** A link address seen from two IPs = a spoofed/rogue master. | `dnp3_substation.pcap` frames **27, 31** — link `100` (the master's) arrives from `10.20.0.66` |
| `dnp3_select_operate.py` | Supervised control is a handshake: every **OPERATE (fc 4) has a SELECT (fc 3)** on the same session within an arm window; **DIRECT_OPERATE (fc 5/6) has no SELECT phase** and is off-baseline. | frame **27** — forged-link `DIRECT_OPERATE` with no SELECT |
| `dnp3_rogue_master.py` | (1) Control-class requests come **only from a known-master allow-set**; (2) requests stay within the **baseline function codes** `{CONFIRM, READ, SELECT, OPERATE}`. | frame **27** (rogue source + off-baseline `DIRECT_OPERATE`) and frame **31** (off-baseline `COLD_RESTART`) |
| `mqtt_abuse.py` | (A) every **CONNECT authenticates** (User Name flag set); (B) **SUBSCRIBE is scoped** — no `#`; (C) **command PUBLISH only from a controller** allow-set. | `mqtt_iot_telemetry.pcap` frame **38** (anonymous CONNECT), **42** (`#` SUBSCRIBE), **52** (PUBLISH to `plant/tank1/command` from a non-controller) |

`naive_ip_rule.py` is a deliberately brittle "control must come from the master
IP" rule, shipped so students can watch it get evaded — see
**`RED_TEAM_EVASION.md`**.

Why the map to attack frames survives real-world adversaries and where each rule
*breaks* is the whole lesson; read `RED_TEAM_EVASION.md` next.

---

## How to run

```bash
cd lab/detect

# DNP3 — against the shipped substation capture (flags the forged-link attack)
python3 dnp3_link_spoof.py     ../../pcaps/dnp3_substation.pcap
python3 dnp3_select_operate.py ../../pcaps/dnp3_substation.pcap
python3 dnp3_rogue_master.py   ../../pcaps/dnp3_substation.pcap

# MQTT — against the shipped IoT telemetry capture
python3 mqtt_abuse.py          ../../pcaps/mqtt_iot_telemetry.pcap

# Prove no false positive on a benign-only slice (both exit 0, silent)
python3 dnp3_rogue_master.py   samples/dnp3_benign.pcap
python3 mqtt_abuse.py          samples/mqtt_benign.pcap
```

Exit code drives automation:

```bash
python3 mqtt_abuse.py capture.pcap && echo "clean" || echo "ALERT"
```

### Tuning to your asset inventory

Durable OT detection binds alerts to an asset inventory (NIST SP 800-82r3,
IEC 62443). Every allow-set is a CLI flag with a documented default:

```bash
# multiple legitimate masters (primary + backup FEP)
python3 dnp3_rogue_master.py cap.pcap --masters 10.20.0.5,10.20.0.6

# widen/narrow the SELECT arm window (seconds)
python3 dnp3_select_operate.py cap.pcap --window 5

# name the controllers allowed to publish commands, and your command-topic regex
python3 mqtt_abuse.py cap.pcap --controllers 10.10.20.20 --command-re 'command|/cmd|setpoint'
```

---

## Self-test

```bash
./run_selftest.sh
```

asserts, for all four detectors: **alert on the attack capture**, **clean on the
benign slice**, and the **evasion outcome** (naive rule misses, grammar/off-baseline
invariants survive). It regenerates the evasion fixture via `make_evasion_pcap.py`
if absent.

## Files

```
detect_common.py         shared tshark helper + DNP3/MQTT constants (stdlib only)
dnp3_link_spoof.py       link-address <-> source-IP binding
dnp3_select_operate.py   SELECT-before-OPERATE / DIRECT_OPERATE grammar
dnp3_rogue_master.py     master allow-set + off-baseline function codes
mqtt_abuse.py            anonymous CONNECT + '#' SUBSCRIBE + command PUBLISH
naive_ip_rule.py         intentionally brittle source-IP rule (for the exercise)
make_evasion_pcap.py     builds samples/dnp3_master_ip_spoof.pcap (scapy; run once)
run_selftest.sh          asserts every expected verdict above
samples/                 dnp3_benign.pcap, mqtt_benign.pcap, dnp3_master_ip_spoof.pcap
RED_TEAM_EVASION.md      the "detection under adversarial reality" exercise
```

### Dependencies

- `tshark` (Wireshark CLI) on `PATH` — the detectors' only external dependency.
- Python 3 stdlib — no pip installs for the detectors.
- `scapy` **only** for `make_evasion_pcap.py` (already pinned in the kit at 2.7.0);
  the shipped `samples/dnp3_master_ip_spoof.pcap` means you don't need it to run
  the exercise.
