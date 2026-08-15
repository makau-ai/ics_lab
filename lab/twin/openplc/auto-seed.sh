#!/bin/bash
# =============================================================================
#  auto-seed.sh — OpenPLC container entrypoint for the wet-well twin.
#
#  Wraps OpenPLC's own start_openplc.sh so the soft-PLC comes up already
#  configured and RUNNING — no manual clicks in the :8088 web UI. On every boot
#  it (idempotently):
#     1) ensures the persistent state files exist (mirrors start_openplc.sh),
#     2) copies the twin's ST programs into the persistent st_files dir,
#     3) seeds the DB + regenerates mbconfig.cfg  (seed-openplc.py):
#          - adds the plant-sim Modbus/TCP slave device,
#          - registers the ST programs,
#          - Start_run_mode=true, Modbus server on 502, DNP3 + EtherNet/IP off,
#     4) compiles the SELECTED ST ($PLC_PROGRAM) into ./core/openplc if that
#        program is not already the compiled/active one,
#     5) hands off to the stock start_openplc.sh, which — because
#        Start_run_mode=true — auto-starts the runtime and configures the
#        Modbus/DNP3/EtherNet-IP servers from the DB.
#
#  The naive<->hardened switch is just $PLC_PROGRAM (compose sets it): a
#  different program than the one currently active triggers a recompile here.
#
#  Everything degrades to a log line rather than failing hard: if a step can't
#  complete, the web UI still comes up at :8088 so you can finish by hand
#  (see README "OpenPLC bring-up"). First boot compiles the ST (~30-60 s).
# =============================================================================
set -u

WORKDIR=/workdir
WEB="$WORKDIR/webserver"
PERSIST=/docker_persistent
WANT="${PLC_PROGRAM:-naive_wetwell.st}"

# pick an interpreter (OpenPLC installs a venv; fall back to system python3) ---
if [ -x "$WORKDIR/.venv/bin/python3" ]; then PY="$WORKDIR/.venv/bin/python3"
else PY="$(command -v python3 || echo python3)"; fi

echo "[auto-seed] OpenPLC twin bring-up — selected program: $WANT"

# 1) make sure the persistent files exist (same as stock start_openplc.sh) -----
if [ -d "$PERSIST" ]; then
  mkdir -p "$PERSIST/st_files"
  cp -n "$WEB/dnp3_default.cfg"       "$PERSIST/dnp3.cfg"          2>/dev/null || true
  cp -n "$WEB/openplc_default.db"     "$PERSIST/openplc.db"        2>/dev/null || true
  cp -n "$WEB/active_program_default" "$PERSIST/active_program"    2>/dev/null || true
  cp -n "$WEB"/st_files_default/*     "$PERSIST/st_files/"         2>/dev/null || true
  cp -n /dev/null "$PERSIST/persistent.file"                       2>/dev/null || true
  cp -n /dev/null "$PERSIST/mbconfig.cfg"                          2>/dev/null || true
fi

# 2) ship the twin's ST programs into the persistent st_files dir --------------
if [ -d /seed/st ]; then
  cp -f /seed/st/*.st "$PERSIST/st_files/" 2>/dev/null \
    && echo "[auto-seed] copied twin ST programs into $PERSIST/st_files" \
    || echo "[auto-seed] WARN: could not copy /seed/st/*.st (continuing)"
fi

# 3) seed the DB + regenerate mbconfig.cfg -------------------------------------
if [ -f "$WORKDIR/seed-openplc.py" ]; then
  OPENPLC_DB="$PERSIST/openplc.db" OPENPLC_MBCONFIG="$WEB/mbconfig.cfg" \
    "$PY" "$WORKDIR/seed-openplc.py" || echo "[auto-seed] WARN: seed step reported an error (continuing)"
else
  echo "[auto-seed] WARN: seed-openplc.py not found; finish device/Modbus setup in the UI"
fi

# 4) compile the selected ST if it isn't already the active/compiled one -------
ACTIVE=""
[ -f "$PERSIST/active_program" ] && ACTIVE="$(tr -d '\r\n' < "$PERSIST/active_program")"
if [ ! -f "$WEB/core/openplc" ] || [ "$ACTIVE" != "$WANT" ]; then
  if [ -f "$WEB/st_files/$WANT" ]; then
    echo "[auto-seed] compiling $WANT (active was: '${ACTIVE:-none}')…"
    ( cd "$WEB" && ./scripts/compile_program.sh "$WANT" ) 2>&1 | sed 's/^/[compile] /'
  else
    echo "[auto-seed] WARN: $WEB/st_files/$WANT missing — cannot compile; UI upload needed"
  fi
else
  echo "[auto-seed] $WANT already compiled + active — skipping recompile"
fi

# 5) hand off to the stock launcher (auto-starts the runtime at Start_run_mode) -
echo "[auto-seed] handing off to start_openplc.sh — runtime will auto-start"
exec "$WORKDIR/start_openplc.sh" "$@"
