# Revision 4 — Digital twin: one-command bring-up, validated live

Revision 4 makes the optional **digital twin** (the multi-container Wastewater Lift Station) run
end-to-end from a single command, and validates it live from a clean volume in a fresh GitHub
Codespace. The core Learning Path, modules, lab, and Machine Problem are unchanged; this revision
is entirely about the twin and the Codespace experience.

**OpenPLC self-seeds and self-starts — no manual UI step.** The soft-PLC used to need a five-step
manual bring-up in its web UI (add the slave device, upload + compile the ST, enable Modbus, Start
PLC). A new container entrypoint (`lab/twin/openplc/auto-seed.sh` + `seed-openplc.py`) now does all
of it on boot: it adds the `wetwell-plant-sim` Modbus/TCP slave device, rebuilds `mbconfig.cfg` from
the database (OpenPLC only regenerates that file from its UI handlers, never at boot — so a bare DB
insert would leave the Modbus master polling nothing), sets `Start_run_mode=true`, enables the
Modbus server, leaves DNP3 + EtherNet/IP off, compiles the selected program, and hands off to
OpenPLC's own launcher, which auto-starts the runtime. The old best-effort `load-program.sh` curl
stub is removed.

**The ST control programs now compile.** `naive_wetwell.st` and `hardened_wetwell.st` mixed
`AT %…`-located I/O and plain working variables in a single `VAR` block, which OpenPLC's `iec2c`
(matiec) rejects — both programs failed to compile, so the auto-seed would have fallen back to the
blank program. Each now splits the declarations into separate located and working `VAR` blocks and
compiles cleanly (verified with a locally-built `iec2c` and live in the Codespace). Pure
declaration reorg; the control logic — and `test_twin.py`'s spill proof — is unchanged.

**Cross-zone conduits actually pass.** On Docker 27+ (nftables + `br_netfilter`), bridged frames
were run through the host isolation chains, which dropped the forwarded cross-zone packets, so every
conduit timed out. `launch-twin.sh` now sets `net.bridge.bridge-nf-call-iptables=0` on bring-up so
bridged frames bypass host isolation; `zone-fw` still enforces the deny-by-default conduits in its
own namespace, so the security model is unchanged (the `CONDUIT-DROP` tripwire still fires on
non-conduit flows).

**OpenPLC builds from source; zones get explicit gateways.** OpenPLC v3 is not published to Docker
Hub, so `openplc/Dockerfile` clones and compiles the runtime from canonical source (a slow first
build; Docker layer-caches it afterward). Each of the five zone networks got an explicit `.254`
gateway so `zone-fw` can own `.1` without colliding with Docker's auto-assigned gateway.

**Copy-paste into the noVNC Wireshark desktop.** An `autocutsel` + `xclip` clipboard bridge in the
devcontainer lets commands paste cleanly between the browser and the in-Codespace Wireshark desktop.

**Validated live.** From a clean volume in a fresh Codespace, one command brings the whole twin up:
OpenPLC self-seeds, compiles and runs the ST, drives pump P2 (`Qout=1350`) and holds the well at
`spill = 0`, and DNP3 + MQTT cross the conduits (captured out-of-band). Transcript:
`verification/evidence/30_twin_codespace_smoke.txt`; see `FORMAL_VERIFICATION.md` Part 5.

---

# Revision 3 — One-click leveled curriculum + formal verification

This revision turns the kit into a **guided, one-click course** and adds a reproducible verification
record. Nothing from Revision 2 was removed; the modules, lab, and MP are unchanged in substance.

**A structured Learning Path (Levels 0–6).** New `curriculum/` hub (`index.html`) and `CURRICULUM.md`
render seven ordered levels — Orientation → Endpoints → Message types → Inside the packet → Find the
attack → Detection → **a university-style Machine Problem** — built to the exact progression requested:
start with tshark/Wireshark and the protocol endpoints, then dive inside the packets. The HTML hub
tracks progress (per-level "Done", saved in the browser), copies every command with one click, and
reveals checkpoint answers on demand. Rendered by `build/build_curriculum.py` from a single source
(`build/content_levels.py`).

**One click to start.** An **Open in GitHub Codespaces** badge (README) plus a served front door: the
devcontainer now runs a static server (`python3 -m http.server 8080`) and auto-opens the Learning
Path on port **8080** the moment the Codespace starts. `index.html` leads with a "Start the Learning
Path" hero; `welcome.sh`, `LAB_GUIDE.md`, and the README all route students to the path first. The
noVNC Wireshark desktop (6080) is one click away when Level 0 calls for it.

**The Machine Problem (Level 6).** The existing `mp/` capstone is now the explicit end of the path —
handout, two unseen evidence captures, answer template, self-check **autograder** (`grade.py`), rubric,
and instructor solution. Verified: solution scores **100/100**, blank student copy scores the correct
**10/100** baseline.

**External capture sources — government & universities.** New `EXTERNAL_CAPTURES.md` documents verified,
well-provenanced DNP3/MQTT captures beyond the teaching set: **CISA** icsnpp-dnp3 (BSD-3), **UOWM** DNP3
IDS dataset (Zenodo), **University of Genoa/CNR** MQTTset, **Abertay/Strathclyde** MQTT-IoT-IDS2020, and
each with URL, institution, and license.
Three honesty notes baked in: no government MQTT pcap exists; the Wireshark wiki has DNP3 but no MQTT;
automayt/ICS-pcap is unlicensed (linked, not rebundled).

**Formal verification.** New `FORMAL_VERIFICATION.md` + `build/verify_all.py` run **18 automated checks,
all passing**: frame counts, a byte-level recomputation of **every DNP3 CRC (63/63 valid)**, every
curriculum command reproduced against its stated output, documentation↔capture consistency, and the MP
autograder. Protocol facts were re-checked against IEEE 1815, OASIS MQTT 3.1.1, MITRE ATT&CK for ICS
(T0855/T0856 confirmed), and O\*NET (15-1212.00 confirmed).

**Bug fixed.** The DNP3 "controls" display filter used space-separated set membership
(`dnp3.al.func in {3 4 5}`), which **TShark/Wireshark 4.2 on the Ubuntu-24.04 Codespace image rejects**
as a syntax error. Corrected to the comma form `in {3,4,5}` everywhere it appears (curriculum source,
module content, lab guide, worksheets) and re-verified.

---

# Revision 2 — Red-team fixes, applied through the O\*NET personas

The five O\*NET personas that adversarially reviewed the kit each **authored the corrections in their own
domain**. This is what changed, grouped by the persona who owned it. Every documented frame was re-verified
against the pcaps (0 mismatches); the two new assessment captures are CRC/parse-clean; the interactive HTML
has zero JS errors and was keyboard/AT-tested; both Docker compose files pass `docker compose config`.

## Power Distributors & Dispatchers — 51-8012.00 (OT reality)

- **Struck the inflated incident analogies** on frame 27 and finding D1: the 2007 Aurora test was an
  out-of-synchronism **re-CLOSE** of a generator (defended by sync-check relays), **not** a feeder trip;
  Ukraine 2015 was stolen-credential HMI operation; Industroyer used IEC-101/104, IEC 61850, and OPC — not DNP3.
- **Corrected the NERC CIP scope**: CIP covers Bulk Electric System cyber systems (broadly transmission ≥100 kV
  + certain generation); ordinary distribution feeders like this one generally are **not** in scope.
- **Added an "OT reality check" callout**: the collapsed lab topology vs. real serial/dedicated-WAN-behind-a-gateway;
  a peer host on the RTU subnet is *already* a segmentation failure; and OPEN ≠ CLOSE in consequence (trip is
  fail-safe/reversible; the dangerous act is an unsupervised close, gated by hot-line tags, sync-check (25), and
  the local/remote (43) switch).
- **Reframed SELECT-before-OPERATE as safety, not security**, and removed the false-comfort "disable DIRECT
  OPERATE" mitigation from D3.
- **Physical-plausibility caveats**: the 7-point response is a tiny teaching slice (real RTUs carry hundreds–
  thousands); per-feeder "frequency" is atypical; a 1000 ms CROB pulse is long for a coil.

## Information Security Analysts — 15-1212.00 (detection realism)

- **Replaced the naive "alert on non-master source IP"** with a new *Detection under adversarial and operational
  reality* section: key on the invariant {link address ↔ expected source/session ↔ known-master **set** ↔
  SELECT-before-OPERATE}; noted the forged link address isn't in ICSNPP logs by default, and that a smarter
  attacker who spoofs the master IP defeats a source-IP rule.
- **Added "encryption takes your sensor dark"**: TLS/8883 makes the Zeek/ICSNPP sensor go dark; DNP3-SA is a MAC and
  does **not** take it dark — only transport encryption does. Plus tap/SPAN-placement guidance.
- **Fixed the broken MQTT anonymous-connect detection**: the "empty will fields" discriminator both misses and
  false-positives (the authenticated HMI also has empty will fields); detect from broker auth telemetry instead.

## Computer Network Architects — 15-1241.00 (architecture)

- **New segmented lab** (`lab/docker-compose.segmented.yml`): IEC 62443 OT-cell and DMZ zones, a dual-homed FEP
  as the only conduit, broker-per-zone, and DMZ-vs-OT-cell attacker placements — with a "**segment it and watch
  the attack die at the conduit**" exercise mirroring the MQTT harden-and-retest loop.
- **Fixed the self-contradicting detection**: a dedicated `dnp3-attacker` service now injects from its **own IP**,
  so the live capture matches the pcap and the wrong-source alert actually fires; `master.py --src-addr` lets
  students also spoof the master's DNP3 link address to see why source-IP alone is insufficient.
- **Reordered controls to lead with segmentation** (deployable without re-flashing), with DNP3-SA/TLS as the
  durable upgrade; added a topology disclaimer.

## Instructional Coordinators — 25-9031.00 (pedagogy & assessment)

- **New UNSEEN graded assessment** — students analyze captures they have **not** walked, using *different*
  techniques than the lessons: `pcaps/dnp3_assessment.pcap` (a spoofed UNSOLICITED RESPONSE feeding false
  status, amid two legitimate masters) and `pcaps/mqtt_assessment.pcap` (retained-message harvest + a retained
  command injection). Ships with 7 analysis/evaluation questions, a 4-criterion analytic rubric, and mastery
  gates (`lab/worksheets/unseen_assessment.md` + `..._key.md`).
- **Rewrote the learning objectives** to reach Analyze/Evaluate, with two `[Assessed]` higher-order objectives
  per module that the unseen assessment measures.
- **Fixed the authN-vs-authZ conflation** in synthesis Q9 (and the stale frame 54 → 52): DNP3 frame 27 has *no
  authentication*; the MQTT rogue *was* authenticated anonymously, so frame 52 is an *authorization* failure.
- **Split the O\*NET alignment** into "skills you practice here" (15-1212.00, 15-1299.04, 15-1241.00 [+15-1299.05
  for MQTT]) vs. "context: who this protects" (51-8012.00, 49-2095.00, 17-2071.00, 25-9031.00).
- **Accessibility**: the Frame Explorer is now keyboard- and screen-reader-operable (listbox/option roles,
  roving tabindex, Home/End, Enter/Space, `aria-live` detail pane, visible keyboard hint), and severity is
  conveyed by a **text token** (OK/NOTE/CAUTION/CRIT) as well as color (WCAG 1.4.1). Contrast fixes: warn amber
  `#d97706 → #b45309`, muted `#64748b → #475569`.

## Penetration Testers — 15-1299.04 (honest scope)

- **Added a "Scope & threat model" callout** to both modules and an honest level label: this teaches *reading*
  and *recognizing* these protocols; the CROB / command PUBLISH is the last ~5%, and the kill chain that
  precedes it (initial access, OT pivot, enumeration, L2/session control) is out of scope.
- **"What would make this real offense" roadmap** appendix (address/topic enumeration, L2 positioning, TCP-session
  hijack, SBO/DNP3-SA attacks, real fuzzing; MQTT retained/$SYS harvest, Sparkplug B, client-id takeover).
- **Made frame-52 impact real**: a `pump-controller.py` actuator subscribes to the command topic and acts on the
  injected command, so the lab shows physical consequence, not just an accepted publish.

## Consistency

- MQTT capture frame count corrected **63 → 61** everywhere (module text, stats).

---

*See `RED_TEAM_REVIEW.md` for the original adversarial findings this revision addresses.*
