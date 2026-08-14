#!/usr/bin/env bash
# ============================================================================
#  load-program.sh -- seed + select the wet-well ST program in OpenPLC v3.
#
#  Usage (inside the openplc container):
#     /seed/load-program.sh [naive|hardened]
#  Defaults to $PLC_PROGRAM (compose sets naive_wetwell.st / hardened_wetwell.st).
#
#  Best-effort automation of OpenPLC's web flow. OpenPLC's headless program-load
#  is notoriously UI-driven and version-specific, so every step degrades to a
#  printed manual instruction rather than failing hard. Verify interactively on
#  first boot (see README "OpenPLC bring-up caveat").
# ============================================================================
set -u

SEL="${1:-${PLC_PROGRAM:-naive_wetwell.st}}"
case "$SEL" in
  naive|naive_wetwell|naive_wetwell.st)       ST="naive_wetwell.st" ;;
  hardened|hardened_wetwell|hardened_wetwell.st) ST="hardened_wetwell.st" ;;
  *) ST="$SEL" ;;
esac

ST_DIR="${ST_DIR:-/opt/openplc/webserver/st_files}"
WEB="${OPENPLC_WEB:-http://127.0.0.1:8080}"
USER="${OPENPLC_USER:-openplc}"
PASS="${OPENPLC_PASS:-openplc}"
SRC="/seed/st/$ST"

echo "[load-program] selecting $ST"
if [ ! -f "$SRC" ]; then
  echo "[load-program] ERROR: $SRC not found in image (/seed/st)"; exit 1
fi

mkdir -p "$ST_DIR" 2>/dev/null
if cp "$SRC" "$ST_DIR/$ST" 2>/dev/null; then
  echo "[load-program] copied $ST -> $ST_DIR"
else
  echo "[load-program] WARN: could not copy into $ST_DIR (is the openplc_st volume mounted?)"
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[load-program] curl not present; finish in the web UI:"
  echo "   1) Programs -> Upload $ST   2) Compile   3) Start PLC"
  exit 0
fi

JAR="$(mktemp)"
echo "[load-program] logging in to $WEB as $USER"
curl -s -c "$JAR" "$WEB/login" >/dev/null 2>&1
curl -s -c "$JAR" -b "$JAR" -d "username=$USER&password=$PASS" "$WEB/login" >/dev/null 2>&1 \
  || echo "[load-program] WARN: login POST failed (endpoint differs?); use the web UI"

echo "[load-program] requesting compile of $ST"
curl -s -b "$JAR" "$WEB/compile-program?file=$ST" >/dev/null 2>&1 \
  && echo "[load-program] compile requested" \
  || echo "[load-program] WARN: /compile-program differs on this OpenPLC build; compile in the UI"

echo "[load-program] starting the PLC runtime"
curl -s -b "$JAR" "$WEB/start_plc" >/dev/null 2>&1 || true
rm -f "$JAR"

cat <<EOF
[load-program] done (best-effort).
  Verify in the OpenPLC web UI ($WEB):
    * Slave Devices  -> add 'wetwell-plant-sim' from /seed/slave_devices.seed
    * Programs       -> $ST is compiled and RUNNING
    * Settings       -> Modbus ENABLED; DNP3 + EtherNet/IP servers DISABLED
                        (dnp3-gw serves the readable DNP3 on 20000, not OpenPLC)
EOF
