#!/usr/bin/env bash
# =============================================================================
# launch-twin.sh — opt-in launcher for the Wastewater Lift-Station DIGITAL TWIN.
#
# The default one-click lab (.devcontainer/autostart.sh) is the lightweight
# loopback teaching demo. This script switches the Codespace over to the
# multi-container digital twin: real DNP3 + MQTT across five IEC-62443 zones,
# OpenPLC control logic, an nftables conduit firewall, and an out-of-band capture
# plane so every packet still shows up in Wireshark. Vulnerable by default; add
# --hardened to design the weaknesses out and watch the same attack get refused.
#
#   bash lab/twin/launch-twin.sh              # boot vulnerable twin + capture plane
#   bash lab/twin/launch-twin.sh --hardened   # boot with the CIE hardened override
#   bash lab/twin/launch-twin.sh --attack     # also start the adversary foothold
#   bash lab/twin/launch-twin.sh --tools      # also start Zeek + ICSNPP
#   bash lab/twin/launch-twin.sh --status     # container state + spill scoreboard
#   bash lab/twin/launch-twin.sh --logs       # follow the plant-sim spill scoreboard
#   bash lab/twin/launch-twin.sh --down       # stop the twin
#   bash lab/twin/launch-twin.sh --restore    # stop the twin, bring the loopback lab back
#
# Flags combine, e.g.:  bash lab/twin/launch-twin.sh --hardened --attack
# =============================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"          # .../lab/twin
ROOT="$(cd "$HERE/../.." && pwd)"              # kit root
cd "$HERE" || { echo "cannot cd to $HERE"; exit 1; }

# --- pick a compose command (docker-in-docker ships v2; fall back to v1) ------
if docker compose version >/dev/null 2>&1; then   DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else
  echo "ERROR: Docker Compose not found."
  echo "In a Codespace it ships via the docker-in-docker feature — check with 'docker version'."
  exit 1
fi
PROJECT="-p ics-twin-liftstation"              # pin the project so up/down/status always match
BASE="-f docker-compose.twin.yml"
HARDEN=""
PROFILES="--profile capture"
MODE="VULNERABLE"
STFILE="naive_wetwell.st"
DO="up"

for a in "$@"; do
  case "$a" in
    --hardened|-H) HARDEN="-f docker-compose.hardened.yml"; MODE="HARDENED"; STFILE="hardened_wetwell.st" ;;
    --attack)      PROFILES="$PROFILES --profile attack" ;;
    --tools)       PROFILES="$PROFILES --profile tools" ;;
    --full)        PROFILES="$PROFILES --profile tools --profile twin-full" ;;
    --status|status) DO="status" ;;
    --logs|logs)   DO="logs" ;;
    --down|down)   DO="down" ;;
    --restore)     DO="restore" ;;
    -h|--help)     DO="help" ;;
    *) echo "unknown option: $a  (try --help)"; exit 2 ;;
  esac
done

free_loopback_lab(){
  # the loopback demo binds 1883 + 20000 and floods 'lo'; free them so the twin's
  # own broker + DNP3 gateway can bind. The :8080 Learning Path server is LEFT UP.
  pkill -f "mosquitto -c $ROOT/lab/mosquitto" 2>/dev/null || true
  pkill -f "dnp3/outstation.py"       2>/dev/null || true
  pkill -f "mqtt/publisher.py"        2>/dev/null || true
  pkill -f "mqtt/subscriber.py"       2>/dev/null || true
  pkill -f "mqtt/pump-controller.py"  2>/dev/null || true
  pkill -f "heartbeat.sh"             2>/dev/null || true
}

banner(){
cat <<EOF

════════════════════════════════════════════════════════════════════════════
  DIGITAL TWIN — Wastewater Lift Station        [ $MODE ]
  Real DNP3 (20000) + MQTT (1883) across 5 IEC-62443 zones · OpenPLC control
  logic · nftables conduit firewall · out-of-band packet capture.

  DOORS  (click these in the PORTS panel, or open the URL):
    • OpenPLC — control logic ..... http://localhost:8088   (login  openplc / openplc)
    • FUXA HMI — operator view ..... http://localhost:1881
    • Wireshark — live packets ..... http://localhost:3000   ← watch DNP3/MQTT cross conduits
    • First Light Learning Path .... http://localhost:8080   (still running — unchanged)

  SCOREBOARD  (the objective):
    bash lab/twin/launch-twin.sh --logs      # watch 'level' and 'spill' (SSO gallons)
    PASS = spill stays 0 under full DNP3 + MQTT write access.

  OpenPLC self-seeds — NO manual UI step. On boot auto-seed.sh adds the plant-sim
  slave device, enables the Modbus server, compiles ${STFILE}, and starts the
  runtime. First boot compiles the ST (~30–60 s), so give the pumps ~a minute
  before judging the well. Watch/override it at http://localhost:8088 (openplc /
  openplc) if you like — Slave Devices, Programs, and Settings come pre-filled.

  NEXT:
    bash lab/twin/launch-twin.sh --attack     # adversary foothold — run the injection, watch spill climb
    bash lab/twin/launch-twin.sh --hardened   # rebuild with CIE controls, re-run the SAME attack → refused
    bash lab/twin/launch-twin.sh --restore    # back to the loopback teaching lab (:8080 path)
════════════════════════════════════════════════════════════════════════════
EOF
}

case "$DO" in
  help)
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  up)
    echo "[twin] mode: $MODE   profiles: $PROFILES"
    echo "[twin] freeing loopback-lab ports (1883/20000)…"
    free_loopback_lab
    # zone-fw is a container that ROUTES between five Docker bridges. On Docker 27+
    # (nftables), br_netfilter (bridge-nf-call-iptables=1) runs bridged frames through
    # the host isolation chains, which DROP the forwarded cross-zone packets (they carry
    # a foreign source IP onto the destination bridge) -- so every conduit times out.
    # Turning it off lets bridged frames bypass host isolation; zone-fw's OWN nftables
    # (routed traffic, in its namespace) still enforces the deny-by-default conduits, so
    # the deny-by-default security model is unchanged (verified: allowed conduit passes,
    # non-conduit still hits the CONDUIT-DROP tripwire).
    echo "[twin] enabling inter-zone conduit forwarding (bridge-nf-call-iptables=0)…"
    sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1 \
      || echo "[twin]   NOTE: could not set bridge-nf-call-iptables=0 — cross-zone conduits may not pass (needs root)."
    echo "[twin] running: $DC $PROJECT $BASE $HARDEN $PROFILES up -d --build"
    # shellcheck disable=SC2086
    $DC $PROJECT $BASE $HARDEN $PROFILES up -d --build
    rc=$?
    if [ $rc -ne 0 ]; then
      echo "[twin] compose up returned $rc — see the error above. Common cause: first build is slow; re-run to resume."
      exit $rc
    fi
    banner
    ;;
  status)
    # shellcheck disable=SC2086
    $DC $PROJECT $BASE ps
    echo
    echo "── spill scoreboard (last line of plant-sim) ─────────────────────────────"
    # shellcheck disable=SC2086
    $DC $PROJECT $BASE logs --tail 3 plant-sim 2>/dev/null || echo "  (plant-sim not running yet)"
    ;;
  logs)
    # shellcheck disable=SC2086
    exec $DC $PROJECT $BASE logs -f plant-sim
    ;;
  down)
    echo "[twin] stopping the digital twin (containers for project ics-twin-liftstation)…"
    # shellcheck disable=SC2086
    $DC $PROJECT $BASE down
    echo "[twin] down. Named volumes (OpenPLC program + FUXA project) are kept."
    ;;
  restore)
    echo "[twin] stopping the digital twin…"
    # shellcheck disable=SC2086
    $DC $PROJECT $BASE down
    echo "[twin] restarting the loopback teaching lab…"
    bash "$ROOT/.devcontainer/autostart.sh" || true
    echo "[twin] loopback lab back up — First Light Learning Path on :8080, Wireshark on the :6080 desktop."
    ;;
esac
