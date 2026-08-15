# Formal Verification Record

*Everything in this kit that can be checked mechanically, checked — and re-checkable by you.*

> **What "verification" means here — read this first.** This is a **reproducible verification /
> test record**, not formal methods. Every check is a *concrete, re-runnable assertion* —
> byte-level CRC **recomputation** over the raw frames, exact frame counts, tshark histograms
> compared to literal expected values, and a re-run of the Machine-Problem autograder. That is
> reproducible, assertion-based integration testing. It is **not** model checking or symbolic
> property proving: there is no state-space exploration and no theorem. We use the phrase "formal
> verification" in its plain sense — *mechanically checked and reproducible* — and are explicit
> about the boundary. One genuine **property-based** assertion is now included (Section A/B: for
> random subsets of DNP3 frames, *every* recomputed CRC must equal the stored CRC — a `∀`
> invariant, not a fixed total). The digital twin's Cyber-Informed-Engineering "even-if" backstop
> (**spill == 0 under full DNP3+MQTT write access**) is proven **by execution** in
> `lab/twin/test_twin.py` and validated live in a fresh Codespace (Part 5); a randomized-attack
> generator over that same invariant is the remaining step to a `∀` proof — see *Where a real
> property check would add value* below.

This document records the verification pass over the ICS/OT Protocol Analysis Lab Kit: what was
tested, the tools and versions used, the evidence, and the two content refinements applied as a
result. The headline: a single reproducible suite (`build/verify_all.py`) runs a set of
**independent, re-runnable checks that all pass** — including **exact** frame-count assertions, a
byte-level recomputation of **every DNP3 CRC (63/63)**, a `∀`-frame CRC property check, ground-truth
label-file validation, and a full run of the Machine-Problem autograder. The toolchain is pinned in
`requirements-lock.txt` beside the verifier.

## Method & tooling

| Tool | Version | Role |
|---|---|---|
| TShark / Wireshark | **4.2.2** | Field extraction & filters (the exact filter dialect students use) |
| Scapy | **2.7.0** | Reads raw frame bytes for the CRC audit and frame counts |
| Python | **3.11** | Verification harness + autograder |
| Zeek + CISA ICSNPP | 8.2.x (in the Codespace) | Shipped as reference logs (`lab/zeek_reference_output/`); parser runs in the lab, not in this pass |

Everything below re-runs with one command:

```bash
cd build && python3 verify_all.py      # exit 0 == all checks pass
```

---

## Part 1 — Automated suite (21/21 passed)

*(The suite grew from 18 to 21 checks this pass: exact frame-count assertions replaced the dead
`n>0` count check, a `∀`-frame CRC property check was added, and the two `.labels.json` ground-truth
files are now schema-validated. The original 18 remain and still pass.)*

### A. Capture integrity — frame counts (EXACT assertions)

These counts are now **hard-asserted**: the verifier fails loudly if any capture has been
regenerated or corrupted (`n == expected`, not merely `n > 0`). The earlier build carried a dead,
stale count dict (33 vs the actual 37) that was never referenced — fixed this pass per the Data
Scientist review.

| Capture | Frames (asserted ==) | Purpose |
|---|---|---|
| `pcaps/dnp3_substation.pcap` | **37** | DNP3 teaching capture (14 DNP3 app frames) |
| `pcaps/mqtt_iot_telemetry.pcap` | **61** | MQTT teaching capture |
| `pcaps/dnp3_assessment.pcap` (= `mp/captures/`) | **30** | MP DNP3 evidence (unseen) |
| `pcaps/mqtt_assessment.pcap` (= `mp/captures/`) | **66** | MP MQTT evidence (unseen) |

The CRC routine is self-tested against the standard vector: `crc_dnp(b"123456789") == 0xEA82` — **pass**.
A **property-based** check then samples random DNP3 frames and requires *every* recomputed
header/block CRC to equal the stored value (`∀`, not a literal total).

Machine-readable ground truth ships beside the captures: `pcaps/dnp3_substation.labels.json` and
`pcaps/mqtt_iot_telemetry.labels.json` (`{malicious_frames, attacker_ip, forged_link, ttp,
benign_frames_summary}`). The verifier validates that each label file parses, carries the required
schema, and references only real frames — the bridge from a pcap to a detector. The
`build/pcap_features.py` helper (`to_frames` / `to_flows`) emits those same per-frame features on
demand.

### B. DNP3 data-link CRC audit — 63/63 valid

Every DNP3 frame's data-link CRC was **recomputed from the raw bytes** (reflected CRC-16/DNP,
poly `0x3D65` / reflected `0xA6BC`, init `0x0000`, xor-out `0xFFFF`) — the header CRC and each
16-byte data-block CRC — and compared to the bytes on the wire:

| Capture | DNP3 frames | CRCs recomputed | Valid |
|---|---|---|---|
| `dnp3_substation.pcap` | 14 | 38 | **38/38** |
| `dnp3_assessment.pcap` | 9 | 25 | **25/25** |
| **Total** | 23 | **63** | **63/63** |

This proves the captures are not just "protocol-shaped" — they are byte-accurate DNP3 that a
compliant stack (and Wireshark's dissector) accepts without a single CRC error.

### C. Documentation ↔ capture consistency

Every frame annotated in the interactive modules resolves to a real frame in its capture:
`dnp3` module — 15 documented frames, all within 1..37; `mqtt` module — 17 documented frames, all
within 1..61. **No dangling frame references.**

### D. Curriculum commands reproduce their stated output

Each load-bearing command embedded in the leveled curriculum (`curriculum/`, from
`content_levels.py`) was executed and its output asserted against the "Expected" text shown to the
student:

| Level | Command (abbrev.) | Asserted result |
|---|---|---|
| 1 | `-z endpoints,ip` (MQTT) | broker `10.10.20.10` present, **61** pkts (busiest) |
| 2 | `mqtt.msgtype` histogram | **3/3/8/2/2/2/1/1/1** (CONNECT…DISCONNECT) |
| 2 | `dnp3.al.func` histogram | READ×2, SEL, OP, DOP, COLD_RESTART, RESP×6, UNSOL, CONFIRM |
| 3 | `dnp3.al.func in {3,4,5}` | frames **16, 20, 27** (master Close ×2, rogue Trip) |
| 4 | `mqtt.msgtype==1 && !mqtt.username` | frame **38**, client `mqtt-explorer-x` |
| 4 | `dnp3.al.func==5 \|\| ==13` | both from `10.20.0.66`, link forged to `100` |

All six **pass**. (The `in {3,4,5}` case is the reason for the fix in Part 4.)

### E. Machine-Problem autograder

| Scenario | Score | Meaning |
|---|---|---|
| Shipped **blank** student copy (`submission/answers.json` empty, stub `detector.py`) | **10 / 100** | Only Part-3 "valid submission present" — correct baseline for a fresh start |
| **Solution** copy (`solution/answers.solution.json` + `solution/detector.py`) | **100 / 100** (Mastery) | The answer key and reference detector fully satisfy Parts 1–3 |

The harness backs up and restores the shipped student files, so running verification leaves the
handout in its correct blank state (confirmed: the stub with its `TODO` is what ships).

---

## Part 2 — Factual claims reviewed against primary sources

Protocol and framework facts asserted across the modules, worksheets, and MP were reviewed against
the governing specifications and public taxonomies. Key load-bearing claims:

| Claim | Basis | Status |
|---|---|---|
| DNP3 uses TCP/20000; MQTT uses TCP/1883 (8883 for TLS) | IEEE 1815-2012; OASIS MQTT 3.1.1; IANA | ✔ |
| DNP3 function codes: READ 0x01, SELECT 0x03, OPERATE 0x04, DIRECT_OPERATE 0x05, COLD_RESTART 0x0D, RESPONSE 0x81, UNSOLICITED 0x82, CONFIRM 0x00 | IEEE 1815-2012 §; corroborated by tshark `dnp3.al.func` | ✔ (matches capture histogram) |
| DNP3 CRC = CRC-16/DNP, poly `0x3D65`, check `0xEA82` | IEEE 1815-2012; recomputed 63/63 | ✔ (Part 1B) |
| CROB is group 12 var 1; Trip/Close code distinguishes trip vs close | IEEE 1815-2012; tshark `dnp3.ctl.trip` (1=Close on master frames 16/20, 2=Trip on rogue frame 27) | ✔ |
| MQTT control packets 1–14 (CONNECT…DISCONNECT); QoS = min(pub,sub); RETAIN persists last msg | OASIS MQTT 3.1.1 §; tshark `mqtt.msgtype`, `mqtt.retain` | ✔ |
| MQTT injection in the MP is an **authorization** failure (rogue authenticated anonymously, then acted beyond permission) | OASIS MQTT 3.1.1 auth model; capture: anon CONNECT accepted (CONNACK 0), then retained publish to a command topic | ✔ (also gated in `mp/rubric.md`) |
| MP DNP3 attack = **T0856 Spoof Reporting Message**; teaching DNP3 trip = **T0855 Unauthorized Command Message** | MITRE ATT&CK for ICS (confirmed T0855/T0856/T0814/T0842/T0831 names) | ✔ |
| O*NET personas resolve to real SOC codes (e.g., **15-1212.00 = Information Security Analysts**) | O*NET-SOC taxonomy (15-1212.00 confirmed via onetonline.org) | ✔ |
| CISA ICSNPP DNP3 parser is BSD-3-Clause; example trace `testing/traces/dnp3_example.pcap` | github.com/cisagov/icsnpp-dnp3 | ✔ |

**Two refinements applied during verification** (documented in `CHANGELOG.md`):

1. **DNP3 layering language** — the module now frames DNP3 as the **"3+1" Enhanced Performance
   Architecture** (data link + pseudo-transport + application, riding on the TCP/IP stack) rather
   than implying a clean 3-layer OSI mapping. This is the accurate way to describe IEEE 1815.
2. **Real-world case counts** — the "D5 real-world" tie-in now states the industrial-intrusion
   figure as an **approximate, time-qualified range** ("early 2014 … ~30+ ultimately") rather than
   a single hard number, matching how the public reporting actually characterized it.

---

## Part 3 — External capture sources verified

The government/university/community capture sources in `EXTERNAL_CAPTURES.md` were each checked to
exist, with real URLs, publishing institution, and license/terms. Highlights:

- **CISA** `icsnpp-dnp3` — BSD-3-Clause, `testing/traces/dnp3_example.pcap` (the only clearly
  open, government-origin DNP3 capture found).
- **UOWM** DNP3 Intrusion Detection Dataset (Radoglou-Grammatikis et al.; EU H2020) — Zenodo
  record `7348493`.
- **University of Genoa / CNR-IEIIT** MQTTset (MDPI *Sensors* 2020) — Kaggle `cnrieiit/mqttset`.
- **Abertay + Strathclyde** MQTT-IoT-IDS2020 — IEEE DataPort, DOI `10.21227/bhxy-ep04`.

Three honesty corrections were baked in: **no government MQTT pcap** could be verified; the
**Wireshark wiki has DNP3 but no MQTT** sample; and **automayt/ICS-pcap has no license** (linked,
not rebundled). See `EXTERNAL_CAPTURES.md` for the full table and citation guidance.

---

## Part 4 — Defect found and fixed this pass

| Where | Problem | Fix |
|---|---|---|
| `content_levels.py` (Levels 3 & 5) | Filter used space-separated set membership `dnp3.al.func in {3 4 5}`. **Wireshark/TShark 4.2 rejects it** (`"4" was unexpected in this context`) — a student on the Ubuntu-24.04 Codespace image would hit a syntax error. | Changed to comma form `in {3,4,5}` / `in {3,4,5,13}`, then re-verified both produce the documented frames (16/20/27 and 27/31). |

No other discrepancies were found between the documentation and the captures.

---

## Part 5 — Digital twin: live bring-up validated in a fresh Codespace

The multi-container digital twin was brought up from a **clean volume** in a fresh GitHub
Codespace (`makau-ai/ics_lab @ 0e814fd`) with a single command and **no manual OpenPLC UI
steps**, then evidenced end-to-end. Full transcript:
`verification/evidence/30_twin_codespace_smoke.txt`. Highlights:

- **Self-seeding OpenPLC.** The `openplc` container runs the `auto-seed.sh` entrypoint, which
  adds the `wetwell-plant-sim` Modbus/TCP slave device, writes `mbconfig.cfg`
  (`Num_Devices = 1`), sets `Start_run_mode=true` with the Modbus server on 502 (DNP3 and
  EtherNet/IP off), compiles the selected ST, and hands off to OpenPLC's own launcher — which
  auto-starts the runtime. `active_program = naive_wetwell.st` (not blank), and the Modbus
  server answers on **502-OPEN** (the old first-boot "Connection refused" is gone).
- **The ST compiles in the real toolchain.** matiec / `iec2c` runs to completion and the glue
  map is exactly `__IW100/101/102`, `__IX100_0/1`, `__QX100_0/1/2`, `__MW10/11/12` — the same
  located addresses the seed's `mbconfig.cfg` targets.
- **The control loop is live.** `plant-sim` shows OpenPLC commanding pump P2 (`Qout=1350`) with
  the well bounded at ~45 % and **`spill = 0.0 gal`** — a closed Modbus loop, not a static image.
- **Cross-zone conduits pass on first boot.** The out-of-band taps captured `conduit_live.pcap`
  (DNP3 + MQTT), `dnp3_live.pcap`, and `mqtt_live.pcap`, confirming the
  `bridge-nf-call-iptables=0` conduit fix (commit `1fb3813`); the deny-by-default
  `CONDUIT-DROP` tripwire still fires on non-conduit flows.

This complements the headless proof: `lab/twin/test_twin.py` drives the plant model with the
adversarial setpoint/command writes and asserts `spill > 0` (naive: 5528 gal) vs `spill == 0`
(hardened), with every defense layer attributed — so the CIE "even-if" invariant is proven
**by execution**, not prose.

---

## Where a real property check would add value

This pass is honest about its boundary (see the callout at the top). The checks are reproducible
assertions plus one `∀`-frame CRC property; they are **not** model checking. Three places a genuine
property-based or model-checked proof would materially strengthen the kit, in priority order:

1. **The twin's CIE "even-if" safety invariant.** `lab/twin/plant-sim/plant_sim.py` models
   hardwired-float / weir / motor-protection backstops whose whole purpose is to guarantee
   `spill == 0` **even under full DNP3 + MQTT write access**. That is a true safety property.
   `lab/twin/test_twin.py` now *proves it by execution* — driving the sim with the adversarial
   `%MW10`/`%MW12` writes and asserting `spill > 0` in vulnerable mode (5528 gal) and `spill == 0`
   in hardened mode, with clamp/interlock/float layers attributed (see Part 5). A Hypothesis-style
   randomized-attack generator over the same invariant would harden it from a fixed scenario to a `∀`.
2. **The detector invariants.** The MP detector keys on invariants — *a DNP3 link source address
   sourced from more than one IP*, and *anonymous-CONNECT + write to a `command` topic*. These are
   stated as properties in the `.labels.json` ground truth and are ideal targets for
   Hypothesis-style property testing (generate address permutations; assert the invariant holds and
   a naïve source-IP / block-`#` rule does not).
3. **Application-layer parse acceptance.** The CRC audit proves data-link validity; it does **not**
   prove CISA's ICSNPP DNP3 dissector accepts the synthetic application objects (CROB group 12
   var 1, etc.). A `zeek -Cr` pass asserting expected `dnp3.log` fields would close that gap.

The property check added this pass (random-subset CRC `∀`) is a first, small step in this
direction; items 1–3 are tracked for the twin verification bundle.

---

## Part 6 — How to reproduce

```bash
# 1. the automated suite (frame counts, 63/63 CRCs, curriculum commands, autograder)
cd build && python3 verify_all.py

# 2. spot-check any curriculum command yourself
tshark -r pcaps/mqtt_iot_telemetry.pcap -q -z endpoints,ip
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5}" \
       -T fields -e frame.number -e ip.src -e dnp3.src

# 3. the MP autograder against the solution
cd mp && cp solution/answers.solution.json submission/answers.json \
      && cp solution/detector.py detector.py && python3 grade.py   # 100/100
#   (then restore the blanks, or just `git checkout` them)

# 4. the digital twin — headless invariant + live bring-up (live needs Docker)
python3 lab/twin/test_twin.py         # naive spills 5528 gal, hardened holds spill at 0
docker compose -p ics-twin-liftstation -f lab/twin/docker-compose.twin.yml down -v
bash lab/twin/launch-twin.sh          # OpenPLC self-seeds + self-starts; pumps run, spill=0
#   (evidence transcript: verification/evidence/30_twin_codespace_smoke.txt)
```

*Verification harness: `build/verify_all.py`. Last run: 21/21 checks passed, 63/63 DNP3 CRCs valid.
Toolchain pinned in `requirements-lock.txt`.*
