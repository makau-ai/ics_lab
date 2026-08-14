# Red-Team Evasion — detection under adversarial reality

> Mirrors the modules' *"Detection under adversarial and operational reality"*
> section. You will build a rule, watch an attacker who reads your rule defeat
> it, and then move to an invariant that survives. The lesson is not "here is the
> right rule" — it is **which layer of the signal the attacker can cheaply forge,
> and which he cannot.**

> **Read — how to run the commands below.** Every fenced command has a **Copy**
> button; click it, then paste into your terminal (keyboard paste-backup:
> **Ctrl/Cmd+Shift+V**). These detectors are plain `python3 <script>.py <pcap>`,
> not part of the leveled curriculum, so there is no short `lab` token for them.
> Everything here runs against captures already in `samples/` — no lab bring-up
> needed. Run each command from `lab/detect/`.

---

## The target

> **Read.** `../../pcaps/dnp3_substation.pcap` — a DNP3 **master** (`10.20.0.5`,
> link address `100`) polling an **outstation** (`10.20.0.20`, link `10`). At frame
> 27 a rogue host (`10.20.0.66`) injects a **`DIRECT_OPERATE`** using the master's
> link address `100`, then a **`COLD_RESTART`** at frame 31. That is the attack you
> must detect.

---

## Round 1 — the naive rule (and why it feels fine)

> **Read.** The obvious SOC rule: *"DNP3 control is legitimate as long as it comes
> from the master's IP."* That is `naive_ip_rule.py`. The module warns this rule
> "survives this capture only by luck." Here is the luck running out.

**Do · Type.** Run the naive rule against the original attack capture:

```bash
python3 naive_ip_rule.py ../../pcaps/dnp3_substation.pcap
```

**Check —** it **fires**. You should see:

```
[NAIVE ALERT] frame=27 func=DIRECT_OPERATE from ip.src=10.20.0.66 (!= master 10.20.0.5)
RESULT: ALERT -- 1 frame(s) violated the invariant.
```

Case closed — on *this* capture.

---

## Round 2 — the attacker reads your rule and spoofs the master's IP

> **Read.** Your rule keys on **source IP**, a field the attacker controls. If he
> can inject onto the segment at all, he can put the master's IP in the header. We
> ship that variant pre-built as `samples/dnp3_master_ip_spoof.pcap`: the same
> attack, except every frame the rogue host sent now carries `ip.src = 10.20.0.5`
> (the master's own IP). The injected control still lives in its **own TCP session**
> (source port 40666) — a blind/offset injection, not part of the master's real
> polling session on port 52100. (Rebuild it any time with
> `python3 make_evasion_pcap.py`.)

**Do · Type.** Run the same naive rule against the IP-spoof variant:

```bash
python3 naive_ip_rule.py samples/dnp3_master_ip_spoof.pcap
```

**Check —** it **MISSES**. You should see the attack go invisible:

```
(no control seen from a non-master IP -- naive rule is satisfied)
RESULT: clean -- invariant held, no alert.
```

Nothing about the malicious `DIRECT_OPERATE` / `COLD_RESTART` changed — only a
header field the attacker was always free to set.

---

## Round 3 — even the "one IP per link address" invariant is not enough

> **Read.** Your first instinct after being burned by source IP is the link↔IP
> binding (`dnp3_link_spoof.py`): *a link address must come from exactly one IP.* On
> the **original** capture it nails the attack (link `100` from two IPs). But a
> serious attacker spoofs **both** the IP and the link address — which is exactly
> what the evasion fixture does.

**Do · Type.** Run the link↔IP binding detector against the IP-spoof variant:

```bash
python3 dnp3_link_spoof.py samples/dnp3_master_ip_spoof.pcap
```

**Check —** it **MISSES** too:

```
RESULT: clean -- invariant held, no alert.
```

Link `100` now appears from only one IP (`10.20.0.5`), so the binding looks
consistent. **A signal built entirely from forgeable identity fields is
forgeable** — an on-path adversary owns every addressing field, IP *and* DNP3 link
address.

---

## Round 4 — the invariant that survives: protocol grammar, not identity

> **Read.** What the attacker *cannot* cheaply forge is the **conversation that must
> have happened before a control fires**. DNP3 supervised control is `SELECT` →
> `OPERATE` on the same session within an arm window. An injected control either
> uses `DIRECT_OPERATE` (no SELECT phase exists) or lands as an `OPERATE` with no
> arming `SELECT` in its session. `dnp3_select_operate.py` keys on that.

**Do · Type.** Run the SELECT→OPERATE grammar detector against the IP-spoof
variant:

```bash
python3 dnp3_select_operate.py samples/dnp3_master_ip_spoof.pcap
```

**Check —** it **SURVIVES** and alerts:

```
[CONTROL WITHOUT SELECT] frame=27 func=DIRECT_OPERATE(5)
    WHY frame=27: DIRECT_OPERATE fires the point with NO SELECT handshake
    (ip.src=10.20.0.5, link 100->10). Off-baseline for a SELECT/OPERATE plant.
RESULT: ALERT -- 1 frame(s) violated the invariant.
```

> **Read.** The companion invariant — **off-baseline function code** — survives for
> the same reason. `COLD_RESTART` is not something a steady-state poller emits, no
> matter what IP or link address it claims.

**Do · Type.** Run the off-baseline / rogue-master detector against the IP-spoof
variant:

```bash
python3 dnp3_rogue_master.py samples/dnp3_master_ip_spoof.pcap
```

**Check —** it **SURVIVES** and alerts on both frames:

```
[OFF-BASELINE FUNCTION] frame=27 func=DIRECT_OPERATE(5)  ...
[OFF-BASELINE FUNCTION] frame=31 func=COLD_RESTART(13)   ...
RESULT: ALERT -- 2 frame(s) violated the invariant.
```

Both key on **what the attacker asked**, not **who he claimed to be**.

---

## Scoreboard

| Rule | keys on | original attack | master-IP-spoof variant |
|---|---|---|---|
| `naive_ip_rule.py` | source IP | catches | **MISS** |
| `dnp3_link_spoof.py` | link ↔ IP binding | catches | **MISS** (IP+link both spoofed) |
| `dnp3_rogue_master.py` (off-baseline func) | *what* was requested | catches | **survives** |
| `dnp3_select_operate.py` | protocol grammar (SELECT→OPERATE) | catches | **survives** |

**Do · Type.** Assert exactly this table in one shot:

```bash
./run_selftest.sh
```

**Check —** every assertion passes (naive/link rules MISS the spoof variant, the
grammar/off-baseline rules ALERT on it). If a verdict flips, the evasion fixture may
be stale — rebuild it with `python3 make_evasion_pcap.py` and re-run.

---

## Honest caveats — do not over-claim the invariant

The grammar invariant is durable, not magic. Push further and you find its edges,
which is where the graded write-up should go:

- **Replay of a real `SELECT`+`OPERATE` pair.** If the attacker captures and
  replays a *legitimate* supervised pair verbatim, a SELECT *does* precede the
  OPERATE in-window and this rule stays quiet. Defeating that needs freshness
  (a monotonic sequence / nonce), which the teaching SAv5 stand-in does **not**
  provide (see `review_1.json` gap 3). The grammar rule bounds injection, not
  replay.
- **`DIRECT_OPERATE` in a plant that legitimately uses it.** Then invariant is
  "OPERATE-without-in-window-SELECT," and `--window` must match the real
  arm-timeout, or you generate false positives during slow links.
- **Multi-master reality.** Real outstations answer a *set* of masters (primary
  + backup FEP, DMS/OMS, commissioning laptops). The allow-set (`--masters`) is
  an asset-inventory input, and it needs maintenance-window suppression to avoid
  alarming on legitimate commissioning traffic.
- **When you encrypt, the sensor goes dark.** Move DNP3 under TLS (or MQTT to
  8883) and tshark can no longer read `dnp3.al.func` — the grammar invariant
  loses its inputs and detection must pivot to endpoint / broker-auth telemetry.

## Your task (assessed)

1. Reproduce the four runs above and record each verdict.
2. Explain, in one paragraph, **why** IP and link address are cheap to forge but
   the SELECT→OPERATE grammar is not, for an on-path DNP3 adversary.
3. Build a **replayed SELECT+OPERATE** evasion (hint: splice a real frame-16/20
   pair into a new session) and show it defeats `dnp3_select_operate.py`. Then
   propose the control that would catch it (freshness), and name precisely what
   in this kit does **not** implement it.
4. For MQTT, repeat the pattern: show that "flag the literal `#`" is brittle
   (an attacker subscribes to a broad but non-`#` filter), and argue why the
   **command-PUBLISH-from-non-controller** invariant in `mqtt_abuse.py` is the
   durable one.
