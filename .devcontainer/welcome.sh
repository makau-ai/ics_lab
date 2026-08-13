#!/usr/bin/env bash
# Printed when you attach to the Codespace (devcontainer postAttachCommand).
cat <<'EOF'

════════════════════════════════════════════════════════════════════════════
  ICS/OT PROTOCOL LAB  —  everything is AUTO-RUNNING.  Nothing to install.

  ▶  START HERE:  the LEARNING PATH opens on port  8080  ("Learning Path — START HERE")
      Seven levels, in order: watch live traffic → name the endpoints → read the
      messages → open the packets → find the attack → detection → the Machine Problem.
      Your progress is tracked as you go. If the tab didn't open, click port 8080 in
      the PORTS panel (or open  http://localhost:8080/ ).

  👀  SEE IT LIVE:  open the forwarded port  6080  ("noVNC Desktop"), password  vscode
      Wireshark is already there, capturing on 'lo' — live DNP3 (20000) + MQTT (1883).
      Level 0 walks you through this. Filters:  dnp3   |   mqtt

  ⚙️  RUNNING FOR YOU:  MQTT broker + DNP3 outstation, a continuously publishing
      sensor, an HMI subscriber, and a pump-controller actuator.
      A startup demo fires the attacks once; DNP3 polling repeats every ~25s.

  ▶️  DO THINGS:
      ./lab/intrude.sh        re-run the MQTT + DNP3 attacks (watch them in Wireshark)
      ./lab/run-local.sh status | down       inspect / stop the services
      curriculum/index.html   the interactive Learning Path (served on :8080)
      CURRICULUM.md           the same path in Markdown (opening for you now)
      mp/README.md            the capstone Machine Problem (Level 6)
      modules/*.html          the DNP3 & MQTT frame-explorer reference modules

  🧩  ADVANCED (multi-container + IEC 62443 zones, via docker-in-docker):
      docker compose -f lab/docker-compose.segmented.yml up -d --build
════════════════════════════════════════════════════════════════════════════
EOF

# Best-effort: open the guided path (Markdown renders in VS Code) when a client attaches.
command -v code >/dev/null 2>&1 && code CURRICULUM.md LAB_GUIDE.md >/dev/null 2>&1 || true
