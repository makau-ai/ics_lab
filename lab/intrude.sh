#!/usr/bin/env bash
# Re-run the intrusions on demand (services are already up from auto-start).
# Watch them live in Wireshark on 'lo' (filters: mqtt  or  dnp3).
LAB="$(cd "$(dirname "$0")" && pwd)"
echo "[intrude] MQTT: anonymous connect -> '#' eavesdrop -> command injection (watch the pump-controller react)"
BROKER=localhost python3 "$LAB/mqtt/attacker.py"
echo
echo "[intrude] DNP3: unauthenticated DIRECT_OPERATE trip from a non-master host"
python3 "$LAB/dnp3/master.py" --host 127.0.0.1 --attack
echo
echo "Tip: to also spoof the master's DNP3 link address, add --src-addr 100"
