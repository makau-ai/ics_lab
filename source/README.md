# Source scripts (instructors)

Build the whole kit from one content source. Requires `python3`, `scapy`, `tshark`, `pandoc`,
`libreoffice` (docx→pdf), and a headless Chromium (for screenshots, optional).

**Content (single source of truth)**
- `content_dnp3.py`, `content_mqtt.py` — module text, frames, security findings, personas, O*NET.
- `content_levels.py` — the 7-level **Learning Path** (Level 0 → the Machine Problem).

**Capture builders**
- `build_dnp3.py`, `build_mqtt.py` — the two teaching captures.
- `build_assessment.py` — the two unseen MP assessment captures.
- `pcap_util.py` — deterministic Ethernet/IP/TCP frame helper (stable timestamps, clean CRCs).

**Renderers**
- `build_html.py` — interactive HTML modules + `modules/index.html`.
- `build_markdown.py` — Markdown modules.
- `build_worksheets.py` — student/instructor worksheets.
- `build_curriculum.py` — the Learning Path: `curriculum/index.html` (progress-tracked) +
  `curriculum/LEVEL_n.md` + `CURRICULUM.md`.

**Verification**
- `verify_all.py` — reproducible pass: frame counts, **every DNP3 CRC recomputed**, curriculum
  commands re-run against their expected output, documentation↔capture consistency, and the MP
  autograder. Runs from here or from the shipped `source/`. See `../FORMAL_VERIFICATION.md`.

Typical rebuild:

```bash
python3 build_dnp3.py && python3 build_mqtt.py && python3 build_assessment.py
python3 build_html.py && python3 build_markdown.py && python3 build_worksheets.py
python3 build_curriculum.py
python3 verify_all.py          # expect: 21/21 checks passed
# secondary formats:
pandoc ../modules/dnp3_module.md -o ../modules/dnp3_module.docx
soffice --headless --convert-to pdf --outdir ../modules ../modules/dnp3_module.docx
```
