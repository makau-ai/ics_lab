# External Captures — Government & University Sources (verified)

This kit ships its own **synthetic, protocol-valid teaching captures**
(`pcaps/dnp3_substation.pcap`, `pcaps/mqtt_iot_telemetry.pcap`, and the two MP assessment
captures). Those are the right place to *learn*, because every frame is annotated and every
value is checkable against the modules and the autograder.

This document is for going **beyond** the teaching set: publicly available, well-documented
DNP3 and MQTT captures published by **governments and universities** that you can download and
analyze with the exact same skills (Levels 1–5). Each entry below was verified to exist and is
listed with its real URL, the institution that published it, its license/terms, and what it
contains. **Read the license column before you redistribute anything** — some of these are
free to *use* but not to *rebundle*.

> Provenance honesty: we could not find a **government-published MQTT** capture. The government
> DNP3 source is CISA's parser test trace. MQTT real-world captures come from universities and
> the security community. Where a "trap" exists (a source people commonly assume has a file it
> doesn't), it is called out explicitly.

---

## 1. Government

| Source | Publisher | URL | License | Contains |
|---|---|---|---|---|
| **ICSNPP DNP3 — `dnp3_example.pcap`** | **CISA** (Cybersecurity & Infrastructure Security Agency) | `https://github.com/cisagov/icsnpp-dnp3` (trace at `tests/traces/dnp3_example.pcap`) | **BSD-3-Clause** | A small DNP3 test trace shipped to exercise CISA's Zeek DNP3 parser. Clean master/outstation DNP3 on TCP/20000. This is the same parser the kit uses in Level 5. |

Why it matters: it is the one **government-origin** DNP3 capture with a clear open license, and it
pairs directly with the ICSNPP parser you run in Level 5. Run it through the kit's Zeek profile:

```bash
# clone CISA's parser + trace, then parse with the kit's Zeek tooling
git clone https://github.com/cisagov/icsnpp-dnp3
zeek -Cr icsnpp-dnp3/tests/traces/dnp3_example.pcap icsnpp-dnp3
tshark -r icsnpp-dnp3/tests/traces/dnp3_example.pcap -q -z conv,tcp   # Level 1 skills on real gov data
```

There is **no CISA/US-Gov MQTT pcap** we could verify. If you find one cited as "government,"
check whether it is actually a university or vendor capture mirrored on a government page.

---

## 2. Universities

| Source | Institution | URL | License / terms | Contains |
|---|---|---|---|---|
| **DNP3 Intrusion Detection Dataset** | **University of Western Macedonia (UOWM)** — Radoglou-Grammatikis, Kelli, Lagkas, Argyriou, Sarigiannidis (EU H2020 *ELECTRON* / *SDN-microSENSE*) | Zenodo: `https://zenodo.org/records/7348493` · IEEE DataPort DOI `10.21227/s7h0-b081` | Research/academic use; **cite the DOI**. Check the record's stated license before redistribution. | Per-entity **DNP3 pcaps** + CSV flow features for **nine** DNP3 attack scenarios (recon, enumeration, spoofing, DoS, replay, etc.), captured May 2020. Excellent "find-the-attack" practice at Level 4. |
| **MQTTset** | **University of Genoa / CNR-IEIIT** (Vaccari et al.), *MDPI Sensors* 2020, 20(22):6578 | Kaggle: `https://www.kaggle.com/datasets/cnrieiit/mqttset` · Paper: `https://www.mdpi.com/1424-8220/20/22/6578` | Kaggle terms + **cite the paper**. | Real **MQTT** broker traffic (legit IoT telemetry) plus labeled attacks: flood, brute-force, malformed, DoS, slow-DoS. The best university MQTT set for Levels 2–4. |
| **MQTT-IoT-IDS2020** | **Abertay University** (Hindy, Bayne) & **University of Strathclyde** (Tachtatzis, Atkinson, Bellekens) | IEEE DataPort: `https://ieee-dataport.org/open-access/mqtt-iot-ids2020-mqtt-internet-things-intrusion-detection-dataset` · DOI `10.21227/bhxy-ep04` | **Open Access**; free IEEE DataPort account to download; **cite the DOI**. | Raw **MQTT pcaps** (~1.35 GB) + packet/uni-flow/bi-flow CSVs across 5 scenarios: normal, aggressive scan, UDP scan, Sparta SSH brute-force, MQTT brute-force. |

---

## 3. Community aggregators & mirrors (use, but mind the terms)

| Source | Maintainer | URL | License / terms | Contains |
|---|---|---|---|---|
| **Wireshark Sample Captures** | Wireshark Foundation (community wiki) | `https://wiki.wireshark.org/SampleCaptures` | Per-file provenance; freely downloadable | **DNP3 only** — three files: `dnp3_read.pcap`, `dnp3_select_operate.pcap`, `dnp3_write.pcap`. ⚠️ **Trap:** there is **no MQTT sample** on this wiki — don't cite `mqtt.pcap` from here. |
| **Netresec — Public PCAP files** | Netresec AB | `https://www.netresec.com/?page=PcapFiles` | Aggregator index; each dataset has its own terms | Curated master list of public captures, including SCADA/ICS entries (4SICS, DigitalBond S4x CTF, automayt). |
| **4SICS / Geek Lounge ICS lab** | Netresec (traffic from the 4SICS village, now CS3Sthlm) | `https://www.netresec.com/?page=PCAP4SICS` | Free download; **attribute CS3Sthlm** if reused in training | Three large live-ICS-lab captures; protocols include **DNP3 (20000)**, Modbus/TCP (502), S7comm (102), plus IT protocols. Great for realistic Level-1 triage. |
| **automayt/ICS-pcap** | automayt (J. Smith) | `https://github.com/automayt/ICS-pcap` | ⚠️ **No license file** — treat as *view-only*; do **not** rebundle into the kit | Protocol-indexed ICS/SCADA pcap collection with a top-level `DNP3/` folder. Fine to study from the source; not clearly licensed for redistribution. |

---

## How to practice with any of these

Everything you learned in Levels 1–5 applies unchanged to a downloaded capture — just point the
tools at the new file:

```bash
# Level 1 — who is talking, and on what ports?
tshark -r <downloaded>.pcap -q -z endpoints,ip
tshark -r <downloaded>.pcap -q -z conv,tcp

# Level 2 — what message types? (DNP3 shown; use mqtt.msgtype for MQTT)
tshark -r <downloaded>.pcap -Y dnp3 -T fields -e dnp3.al.func | sort | uniq -c

# Level 3–4 — open it up / find the odd one out
tshark -r <downloaded>.pcap -Y "dnp3.al.func in {3,4,5}" -T fields -e frame.number -e ip.src -e dnp3.src

# Replay a capture into the live lab to see it in Wireshark on the noVNC desktop
sudo tcpreplay -i lo <downloaded>.pcap
```

Note that real-world captures are **large and noisy** — that is the point. The kit's synthetic
captures teach you the vocabulary on a clean 30–60-packet conversation; these datasets are where
you prove you can do it at scale, on data no one annotated for you (exactly what Level 6, the
Machine Problem, is rehearsing).

## Citation & licensing reminder

If you use a university dataset in coursework or a paper, **cite it** (DOI or the paper) as the
authors ask. For redistribution inside a shared kit, only the BSD-3-licensed
BSD-3-licensed **CISA** trace are unambiguously safe to rebundle with attribution; the others are
free to *download and analyze* but should be **linked, not copied**, unless their record states
otherwise. This kit therefore links to them rather than shipping their files.

---

*All URLs and attributions in this file were verified via web search/fetch during the kit's
formal-verification pass (see `FORMAL_VERIFICATION.md`). Institutions and DOIs are quoted from the
datasets' own landing pages.*
