# Inclusive-Language Review

**Scope:** the ICSNPP teaching kit under `/root/icsnpp_kit` — Markdown docs, `build/content_*.py` and other builders, `modules/` text, `curriculum/`, `lab/` scripts, worksheets, and `design/` notes.
**Reviewer role:** Technical Writer (O\*NET 27-3042.00), DEI / inclusive-language pass.
**Date:** 2026-08-14.

## How to read this

The kit is **already in good shape**. Its authors used `on-path` and `Adversary-in-the-Middle` instead of "man-in-the-middle," and `allow-list` / `deny-list` almost everywhere. This review catches the **stragglers**, and — importantly for an ICS course — separates *genuinely biased non-technical wording* (change it) from *accurate protocol role names* (keep them, so students can carry the vocabulary to real DNP3/Modbus tools and specifications).

The **source of truth** for `modules/*.md`, `modules/*.html`, `*.docx`, `*.pdf`, and the rendered `curriculum/` pages is the Python content in `build/` (`content_dnp3.py`, `content_mqtt.py`, `content_levels.py`). Edit those and re-run the builders; do not hand-patch generated artifacts.

---

## Findings table

Legend — **Keep/Change:** `CHANGE` = replace; `KEEP` = accurate technical term, leave as-is (with a note); `KEEP*` = accessibility/pedagogy term that is inclusive by intent.

| # | Term | Concern | Inclusive / accurate replacement | Where it appears | Keep or change |
|---|------|---------|----------------------------------|------------------|----------------|
| 1 | **whitelisting** | "white = allowed / black = blocked" encodes a racial value judgment; also inconsistent with the rest of the kit, which already says *allow-list*. | **allow-listing** (noun: *allow-list*) | `design/WEAKNESS_ANALYSIS.md:163` ("object/range whitelisting at the FEP"); `:217` ("Object/range whitelisting") | **CHANGE** |
| 2 | **Modbus master / slave** | *slave* invokes chattel slavery. Unlike DNP3, the **Modbus Organization officially retired master/slave for client/server in 2020**, so *client/server* is the current, correct Modbus term — this is a technical update, not just a style fix. | **Modbus client / server** (Modbus *master* -> *client*, Modbus *slave* -> *server*) | `design/DIGITAL_TWIN_ARCHITECTURE.md:98` (I/O "as a Modbus/TCP slave; OpenPLC is the Modbus master"), `:158` (diagram label "Modbus slave"), `:229` ("Modbus slave to the PLC"), `:327` ("Modbus slave") | **CHANGE** |
| 2b | OpenPLC **"slave devices"** feature | Same word, but here it is the literal name of an OpenPLC v3 configuration feature. | Keep the exact string **in quotes** as a product-feature citation; add "(OpenPLC's term for remote-I/O client mappings)". | `design/DIGITAL_TWIN_ARCHITECTURE.md:99` | **KEEP** (quoted product term) |
| 3 | **blind** (metaphor: "operators are blind", "you blind your network sensor", "does not blind ICSNPP", "spoofing can blind the view") | Ableist metaphor equating blindness with ignorance / incapacity. The kit already has a better domain-native phrase — **"loss of view"** — used at `content_dnp3.py:254`. | **lose visibility / loss of view / go dark / cannot see / deny visibility** | `build/content_dnp3.py:217` (->`modules/dnp3_module.md:335`, "operators are blind"), `:253` ("blinding operators to the site"), `:269` (section title "When you encrypt, you blind your network sensor" ->`dnp3_module.md:410`); `CHANGELOG.md:75`; `RED_TEAM_REVIEW.md:123`; `lab/README.md:185`; `design/CIE_HARDENING.md:270` | **CHANGE** (recommended) |
| 4 | Generic **"his"** for a hypothetical attacker | Generic-masculine pronoun excludes; *its* is also more precise (the attacker is referenced as a host/actor). | **its** (or *their*) | `build/content_dnp3.py:211` (->`dnp3_module.md:321`, "kept his real IP"); `dnp3_module.md:402` ("left his real IP"); `build/content_levels.py:227` (->`CURRICULUM.md:322`, `curriculum/LEVEL_5.md:25`); `lab/worksheets/instructor_answer_key.md:38` | **CHANGE** |
| 5 | **DNP3 master / outstation** | *Sounds* like master/slave, but is the **standard IEEE 1815 (DNP3) role pair** — DNP3 pairs *master* with *outstation*, never *slave*. Renaming breaks protocol accuracy and students' transfer to real tools/specs. | **Keep.** Add a one-line glossary note: "*master* and *outstation* are the DNP3 (IEEE 1815) role names, retained for technical accuracy." | Pervasive: `build/content_dnp3.py`, `modules/dnp3_module.*`, `lab/dnp3/master.py` + `outstation.py`, `curriculum/*`, `design/*` | **KEEP** (protocol term) |
| 6 | **MQTT** and its roles | Protocol name; MQTT's role vocabulary is **broker / publisher / subscriber / client** — no master/slave, nothing biased. | **Keep.** | `modules/mqtt_module.*`, `build/content_mqtt.py`, `lab/mqtt/*` | **KEEP** (protocol term) |
| 7 | **"mastering outstation N"** | DNP3 verb sense (a master polls/controls an outstation). Borderline; protocol-consistent. | Keep, or optionally reword to **"polling/controlling outstation 10"**. | `design/WEAKNESS_ANALYSIS.md:120`; `design/CIE_HARDENING.md:219` | **KEEP** (low priority) |
| 8 | **Mastery / mastery gate / mastery band** | Assessment context, not ownership — this is established **mastery-based / competency grading** vocabulary (Bloom, CBE). | **Keep.** | `mp/rubric.md`, `lab/worksheets/unseen_assessment*.md`, `curriculum/LEVEL_6.md`, `FORMAL_VERIFICATION.md` | **KEEP*** (pedagogy term) |
| 9 | **kill chain / kill** | "Cyber Kill Chain" (Lockheed Martin) and MITRE ATT&CK are proper-noun industry standards; `kill` in scripts is the POSIX signal command. | **Keep.** (Informal "kill hardcoded creds", `CIE_HARDENING.md:383`, may be softened to *remove* — optional.) | `modules/*_module.md:34`, `RED_TEAM_REVIEW.md`, `lab/run-local.sh` (`kill` PIDs), `design/research_cie.md:138` | **KEEP** (standard term) |
| 10 | **native** ("Docker's native isolation", "protocol-native") | Built-in / inherent software sense, not the identity sense; not flagged by major style guides. | **Keep.** | `lab/docker-compose.segmented.yml:6`, `design/research_arch.md`, `design/DIGITAL_TWIN_ARCHITECTURE.md:268` | **KEEP** |
| 11 | **rogue** (rogue client / master) | Standard security term (rogue AP / rogue device); not a bias term. | **Keep.** | `mp/*`, `LAB_GUIDE.md:39`, `CURRICULUM.md`, `design/*` | **KEEP** |
| 12 | **colour-blind safe** | Not a slur — it *describes an accessibility property* (the difficulty glyphs are legible for colour-blind users). Inclusive by intent. | **Keep** (do not "fix" this one). | `build/build_curriculum.py:43` | **KEEP*** (accessibility) |
| 13 | **abort / hang** ("abort the control", "crash or hang") | Standard computing verbs; not bias terms. | **Keep.** | `build/content_dnp3.py:185`, `:260`; `lab/README.md:152` | **KEEP** |

### Already compliant (no action — called out as done right)

- **man-in-the-middle -> on-path / Adversary-in-the-Middle.** No literal "man-in-the-middle" or "MITM" exists in the kit; it already uses `on-path` and MITRE **T0830 Adversary-in-the-Middle** (`design/WEAKNESS_ANALYSIS.md:103`, `mp/rubric.md:23`, `modules/*_module.md`, `build/content_*.py`).
- **whitelist/blacklist -> allow-list / deny-list** everywhere except the two stragglers in row 1 (`lab/mqtt`, `design/CIE_HARDENING.md`, `design/WEAKNESS_ANALYSIS.md`, `modules/dnp3_module.md`, `build/content_dnp3.py` all already say allow-list; `CIE_HARDENING.md:384` uses deny-by-default / deny-list).
- **sanity check, dummy, grandfathered, deaf-to, segregate, tribe, first-class citizen** — **none present** in the kit.

---

## Policy note

1. **Accuracy beats euphemism for protocol roles.** In an ICS/OT course the priority is that students can move to real tools and standards. **DNP3 "master/outstation" (IEEE 1815) and MQTT "broker/publisher/subscriber" stay** — they are the specification's own role names and contain no biased pairing (DNP3 never uses "slave"). Where a role name only *looks* charged, add a one-line note explaining it is the protocol term, rather than renaming it.
2. **Modbus is the exception that proves the rule.** Modbus *master/slave* is genuinely dated: the **Modbus Organization itself moved to *client/server* in 2020**. So changing it is both the inclusive *and* the technically-current choice. Keep an OpenPLC product-feature name ("slave devices") only as a quoted citation.
3. **Replace genuinely non-technical biased terms** with the industry-standard inclusive equivalents already adopted by NIST, IETF, Linux, and the security community: `whitelist -> allow-list`, `blacklist -> deny-list`, `man-in-the-middle -> on-path / adversary-in-the-middle`, `sanity check -> coherence/consistency check`. The kit already follows this; finish the last two `whitelisting` instances (row 1) for consistency.
4. **Prefer the kit's own domain phrasing over ableist metaphor.** For "blind," reuse the kit's existing **"loss of view / loss of control"** wording (already at `content_dnp3.py:254`) — it is clearer to OT operators *and* inclusive. Treat this as a recommended, not blocking, change.
5. **Use pronoun-neutral wording for hypothetical actors** ("the attacker … *its* real IP"). This also reads more precisely, since the attacker is referenced as a host.
6. **Edit source, not artifacts.** Apply changes in `build/content_*.py` (and the `design/`, `lab/`, root `*.md` sources), then re-run the builders so `modules/`, `curriculum/`, `.html`, `.docx`, and `.pdf` regenerate consistently.
7. **Don't over-correct.** Accessibility and pedagogy terms used *for inclusion* — "colour-blind safe," "mastery" — stay. Standard proper nouns ("Cyber Kill Chain," MITRE technique names) stay.

**Net effort:** small. 2 `whitelisting` -> `allow-listing`; ~5 Modbus `master/slave` -> `client/server` (1 quoted feature name kept); ~6 metaphorical `blind` -> `loss of view` (recommended); ~4 generic `his` -> `its`. Everything else is already inclusive or is an accurate technical term to keep.
