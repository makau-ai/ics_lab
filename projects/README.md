# Projects — Forward-Engineer, then Reverse-Engineer

The seven levels and the two modules train the analyst's eye on captures the instructors built.
This track flips the direction: **you build a small ICS/OT/IoT system, run it to emit real
traffic, capture it, and then take your own creation apart on the wire** — and finally design the
control that bounds the consequence. It is the bridge from the loopback teaching lab to the living
digital twin, and it is where the skills become yours.

## What's here

- **[`STARTER_AI_PROMPTS.md`](STARTER_AI_PROMPTS.md)** — a scaffolded ladder of *forward* prompts
  (paste into an AI assistant to build a wire-valid DNP3 / MQTT / Modbus app) each paired with a
  *reverse* task (capture it, analyze it with the Level 1–5 method, find the misplaced trust,
  prove a Cyber-Informed-Engineering control holds). Rungs run L1–L2 → L6–L7 plus the twin.
- **[`REAL_WORLD_CONNECTIONS.md`](REAL_WORLD_CONNECTIONS.md)** — a web-verified investigation index:
  each kit topic mapped to a real incident, a primary source, a MITRE ATT&CK for ICS technique, and
  a concrete "go read this, then map it back to a frame you saw" task. Includes an explicit lesson
  on *analogy vs. attribution* (why the 2021 Oldsmar "hack" is taught as a caution, not a fact).
- **[`ARTIFACT_RUBRIC.md`](ARTIFACT_RUBRIC.md)** — the persona-validated rubric that grades the
  artifact bundle you submit (pcap + labeled ground truth + analysis + detector + reproduction
  recipe). Eight weighted dimensions, mastery gates, and bands, in the same shape as
  `../mp/rubric.md`.

## The loop

```
   investigate a real incident          build a small insecure app            take it apart on the wire
   (REAL_WORLD_CONNECTIONS.md)   ──▶     (STARTER_AI_PROMPTS.md, forward) ──▶  (reverse task: endpoints →
            │                                                                  messages → fields → attack →
            │                                                                  detection → CIE control)
            └──────────────────────────  graded against ARTIFACT_RUBRIC.md  ◀──────────────────────────┘
```

## Definition of done

> **Read** — A complete submission mirrors the worked exemplar in
> **[`../verification/`](../verification/README.md)**: a captured `pcap` (plus a benign control
> capture), a `ground_truth.labels.json`, a `report.md` that opens with a BLUF and cites frames +
> fields, a `detector.py` that keys on an **invariant** (not a hard-coded frame number), and a
> one-command `REPRODUCE.md`. For the twin capstone, add the `spill == 0 under full write access`
> acceptance run, hardened vs. vulnerable.

Before you submit, prove the capture at the heart of the bundle actually holds the traffic you claim.

> Commands copy with the **Copy** button on the fenced block, or paste them with
> **Ctrl/Cmd+Shift+V** (the paste-backup) if the terminal swallows a normal paste.

**Do · Type** — confirm your primary capture parses as a real protocol, not just bare TCP:

```
tshark -r capture.pcap -Y 'dnp3 || mqtt || mbtcp'
```

**Check —** you should see DNP3, MQTT, or Modbus/TCP rows, not an empty result; if it comes back empty
your bundle would ship a capture a grader cannot read — re-capture the target while it is mid-conversation
before assembling the rest of the bundle.

> Scope & ethics: build and attack only the systems you create in this kit's lab. Never point any
> of this at production OT or a system you don't own. The whole kit is analysis-first and defensive
> — the point of building the weakness is to learn to see it.
