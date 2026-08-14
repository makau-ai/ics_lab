# Level 0 — Orientation — see it running

*One click, and the lab is already live*

**Difficulty:** Start here &nbsp;·&nbsp; **Time:** ~10 min &nbsp;·&nbsp; **Prerequisite:** None — this is the first level.

**Goal.** Confirm the environment is up and watch real DNP3 + MQTT packets move.

## What you'll be able to do

- Open the noVNC desktop and confirm Wireshark is capturing on 'lo'.
- Recognize that you are watching a live conversation between real endpoints.

## Background

This Codespace auto-started everything: an MQTT broker, a DNP3 outstation, a publishing sensor, a subscriber, a pump-controller, and Wireshark already capturing. You don't set anything up — you observe.

Two protocols are flowing. **MQTT** is publish/subscribe messaging (IoT/IIoT telemetry). **DNP3** is a SCADA protocol (electric/water utilities). By the end of this path you'll read both down to the byte and catch an intruder in them.

## Do this

- **Read.** Open the forwarded port **6080** ('noVNC Desktop'). It opens **straight to the desktop — no password prompt** — with Wireshark already capturing on `lo`. (If a VNC prompt ever appears, the password is `vscode`.)

- **Do · Click.** In Wireshark's green display-filter bar, type `mqtt` and press Enter. Watch the telemetry. Then clear it and type `dnp3`.

**⌨ Type:** `l0`  — runs `tshark -i lo -c 10 -f "tcp port 1883 or tcp port 20000"`

> **Check (expected):** 10 packets summarised — a mix of MQTT (1883) and DNP3 (20000).

**⌨ Type:** `l0b`  — runs `./lab/intrude.sh`

> **Check (expected):** MQTT anonymous connect + command injection, then a DNP3 trip.


## Check yourself

1. **What are the two protocols you see, and what TCP ports identify them?**
   <details><summary>answer</summary>MQTT on TCP/1883 and DNP3 on TCP/20000.</details>

2. **Did you have to install or start anything?**
   <details><summary>answer</summary>No — the devcontainer auto-built and auto-started the whole lab.</details>

**Level up:** You can see live `mqtt` and `dnp3` traffic in Wireshark (or tshark). Continue to Level 1.
