# Real, approved-source captures — attribution & use

This folder holds packet captures obtained from **approved, authoritative sources** (as opposed to the
kit's own synthetic teaching captures in `pcaps/`). Each is used here under its stated license, with the
required attribution below. Use them to practice the Level 1–5 skills on data no one annotated for you.

## Bundled here

### `dnp3_cisa_example.pcap` — DNP3 (real, government source)
- **Source / authority:** **CISA** (US Cybersecurity & Infrastructure Security Agency) — the ICSNPP
  project, `cisagov/icsnpp-dnp3`, `testing/traces/dnp3_example.pcap`.
- **License:** **BSD‑3‑Clause** (© Battelle Energy Alliance, LLC / Idaho National Laboratory). See
  `DNP3_CISA_LICENSE.txt` in this folder. Redistribution is permitted with the copyright notice retained.
- **Contents:** 834 frames of real DNP3 on TCP/20000 between a master (10.10.20.5) and an outstation
  (10.10.20.8) — Class‑0 reads, responses, and SELECT/OPERATE control pairs.
- **Try it:** `tshark -r pcaps/real/dnp3_cisa_example.pcap -q -z conv,tcp` then
  `tshark -r pcaps/real/dnp3_cisa_example.pcap -Y dnp3 -T fields -e frame.number -e dnp3.al.func | sort | uniq -c`

## Fetched on demand (approved source, obtained by the student)

### MQTT — CICIoMT2024 (real, approved institutional source)
There is **no US‑government‑published MQTT capture** (CISA has no MQTT parser; NIST/NCCoE released none).
The highest‑authority approved source with confirmed MQTT pcaps is:
- **Source / authority:** **Canadian Institute for Cybersecurity (CIC), University of New Brunswick** —
  the **CICIoMT2024** dataset (same institutional lineage as the widely‑used CICIDS/CICIoT sets).
- **Dataset page:** https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
- **Download portal:** http://cicresearch.ca/IOTDataset/CICIoMT2024/ (Wi‑Fi/MQTT split → benign +
  MQTT‑attack `.pcap` files: Connect Flood, Publish Flood, Malformed Data). Open download, no account.
- **License / terms (quoted):** *"With any of our datasets, you may redistribute, republish, and mirror
  our datasets in any form. However, any use or redistribution of the data must include a citation to the
  dataset and the research paper listed."*
- **Required citation:** S. Dadkhah, E. C. P. Neto, R. Ferreira, R. C. Molokwu, S. Sadeghi, A. A.
  Ghorbani, *"CICIoMT2024: A benchmark dataset for multi‑protocol security assessment in IoMT,"*
  Internet of Things, 2024.
- **Fetch it:** run `./lab/fetch_real_captures.sh` (downloads into `pcaps/real/`), or download manually
  from the portal above. The kit does not pre‑bundle it (the dataset archives are multi‑GB).

*Verification of these sources and their licenses is recorded in `FORMAL_VERIFICATION.md` /
`EXTERNAL_CAPTURES.md`.*
