#!/usr/bin/env python3
"""
plant_sim.py -- the wet-well lift-station physics, as a Modbus/TCP server.

This is the ONE genuinely net-new process container. It integrates the tank
model from DIGITAL_TWIN_ARCHITECTURE.md 1.3 every 500 ms and exposes the I/O as
a Modbus server that OpenPLC (the Modbus client / "slave devices" remote I/O)
polls. OpenPLC runs the control logic; this file is only the plant.

  Q_in   = diurnal(t) + storm(t)                     # uncontrolled inflow, gpm
  Q_out  = (P1_run + P2_run) * PUMP_GPM * eff         # pumped outflow, gpm
  level += (Q_in - Q_out - Q_weir) * dt / VOL         # integrate, clamp 0..100 %
  if level >= 100 %:  spill += overflow               # <- the SSO scoreboard

Engineered backstops modeled here (NOT in the PLC) so they hold even if the ST
program is deleted or every register is owned -- the CIE "even-if" layer:
  FLOAT_ENABLED       LSHH-102 force-starts the standby pump + horn at 95 %
  WEIR_ENABLED        emergency weir bounds the release rate past the lip
  MOTOR_PROT_ENABLED  underload/dry-run trip caps damage

Pure standard library (no pymodbus): see modbus_tcp.py. Env toggles let the
hardened override (docker-compose.hardened.yml) flip the analog backstops on.
"""
import math
import os
import threading
import time

import config as C
from modbus_tcp import Datastore, ModbusServer


def _envbool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


FLOAT_ENABLED = _envbool("FLOAT_ENABLED", False)       # vulnerable default: float OFF
WEIR_ENABLED = _envbool("WEIR_ENABLED", True)
MOTOR_PROT_ENABLED = _envbool("MOTOR_PROT_ENABLED", True)
DIURNAL = _envbool("DIURNAL", True)
STORM_AT = float(os.environ.get("STORM_AT", "600"))    # sim seconds; <0 disables
MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "502"))


def inflow(t, diurnal=None, storm_at=None):
    """Uncontrolled sewage inflow at sim-time t (seconds), gpm."""
    if diurnal is None:
        diurnal = DIURNAL
    if storm_at is None:
        storm_at = STORM_AT
    q = C.Q_IN_BASE
    if diurnal:
        q += C.Q_IN_DIURNAL_AMP * math.sin(2.0 * math.pi * t / C.DIURNAL_PERIOD_S)
    if storm_at >= 0 and storm_at <= t < storm_at + C.STORM_DURATION_S:
        q += C.STORM_GPM
    return max(0.0, q)


def pump_psi(q_out, n_run, deadhead):
    """PIT-105 discharge pressure on a DOWNWARD centrifugal H-Q curve.

    Head is highest near shutoff and falls as flow rises (floored at the force-
    main static/friction head); a dead-head (closed valve / dry) sits above
    shutoff; with every pump off only the static column remains.
    """
    if deadhead:
        return C.SHUTOFF_HEAD + C.DEADHEAD_MARGIN
    if n_run <= 0:
        return C.PSI_IDLE
    return max(C.STATIC_HEAD, C.SHUTOFF_HEAD - C.PSI_PER_GPM * q_out)


def step(level, spill, sim_t, p1_cmd, p2_cmd,
         float_enabled=None, weir_enabled=None, motor_prot_enabled=None,
         diurnal=None, storm_at=None):
    """One 500 ms wet-well physics tick.

    Pure function of its arguments (no globals mutated, no I/O) so the headless
    test can drive the SAME integrator the live server runs. Returns the new
    (level, spill) plus the derived transmitter signals FIT-104 / PIT-105 and the
    float/dry-run discretes. The engineered backstops (float / weir / motor
    protection) are parameters, matching the CIE "even-if" layer in the sim.
    """
    if float_enabled is None:
        float_enabled = FLOAT_ENABLED
    if weir_enabled is None:
        weir_enabled = WEIR_ENABLED
    if motor_prot_enabled is None:
        motor_prot_enabled = MOTOR_PROT_ENABLED

    # --- motor protection: refuse to run a pump dry (underload trip) ---
    dry = level <= C.LOWCUT
    p1_run = bool(p1_cmd) and not (motor_prot_enabled and dry)
    p2_run = bool(p2_cmd) and not (motor_prot_enabled and dry)
    n_cmd = int(p1_run) + int(p2_run)

    # --- HARDWIRED high-high float (LSHH-102): the CIE analog backstop ---
    horn = False
    n_run = n_cmd
    if float_enabled and level >= C.FLOAT_TRIP_PCT:
        n_run = max(n_cmd, 1)   # force the standby pump on, coils be damned
        horn = True

    # --- hydraulics ---
    q_in = inflow(sim_t, diurnal=diurnal, storm_at=storm_at)
    q_out = n_run * C.PUMP_GPM * C.PUMP_EFF
    q_weir = C.WEIR_RELEASE_GPM if (weir_enabled and level >= C.WEIR_PCT) else 0.0

    dgal = (q_in - q_out - q_weir) * C.TICK_S / 60.0
    cur_gal = level / 100.0 * C.WETWELL_GALLONS_FULL + dgal
    spill_delta = 0.0
    if cur_gal > C.WETWELL_GALLONS_FULL:            # overflow -> SSO
        spill_delta = cur_gal - C.WETWELL_GALLONS_FULL
        cur_gal = C.WETWELL_GALLONS_FULL
    elif cur_gal < 0.0:
        cur_gal = 0.0
    new_level = cur_gal / C.WETWELL_GALLONS_FULL * 100.0

    # --- derived transmitter signals ---
    flow = q_out                                    # FIT-104 sees real moved flow
    # dead-head: a pump is commanded but no flow moved -> pressure spikes
    deadhead = (bool(p1_cmd) or bool(p2_cmd)) and q_out < C.MIN_FLOW_GPM
    psi = pump_psi(q_out, n_run, deadhead)

    return {
        "level": new_level, "spill": spill + spill_delta, "spill_delta": spill_delta,
        "flow": flow, "psi": psi, "q_in": q_in, "q_out": q_out,
        "p1_run": p1_run, "p2_run": p2_run, "n_run": n_run,
        "deadhead": deadhead, "horn": horn,
        "lshh": new_level >= C.FLOAT_TRIP_PCT, "lsl": new_level > C.LOWCUT,
    }


def main():
    store = Datastore()
    # seed setpoint mirrors so the image is complete from tick 0
    store.set_holding(C.HR_LEAD_START, int(C.LEAD_START * 100))
    store.set_holding(C.HR_STOP, int(C.STOP * 100))

    server = ModbusServer(store, host="0.0.0.0", port=MODBUS_PORT)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"[plant-sim] wet-well online | FLOAT={FLOAT_ENABLED} WEIR={WEIR_ENABLED} "
          f"MOTOR_PROT={MOTOR_PROT_ENABLED} storm@{STORM_AT}s", flush=True)

    level = 45.0          # % of span, mid-well start
    spill = 0.0           # gallons of Sanitary Sewer Overflow (the objective)
    sim_t = 0.0
    tick = 0

    while True:
        # --- what the PLC has commanded (coils it wrote over Modbus) ---
        p1_cmd = store.get_coil(C.CO_P1)
        p2_cmd = store.get_coil(C.CO_P2)

        # --- one physics tick (the same integrator the headless test drives) ---
        r = step(level, spill, sim_t, p1_cmd, p2_cmd,
                 float_enabled=FLOAT_ENABLED, weir_enabled=WEIR_ENABLED,
                 motor_prot_enabled=MOTOR_PROT_ENABLED)
        level = r["level"]
        spill = r["spill"]

        # --- publish the server image back for OpenPLC to read ---
        store.set_input_register(C.IR_LEVEL, int(round(level * 100)))   # 0..10000
        store.set_input_register(C.IR_FLOW, int(round(r["flow"])))
        store.set_input_register(C.IR_PSI, int(round(r["psi"])))
        store.set_discrete_input(C.DI_LSHH, r["lshh"])
        store.set_discrete_input(C.DI_LSL, r["lsl"])

        if tick % 2 == 0:   # ~1 Hz scoreboard line
            flags = []
            if r["horn"]:
                flags.append("FLOAT-HORN")
            if r["deadhead"]:
                flags.append("DEAD-HEAD")
            if level >= 100.0:
                flags.append("*** SPILLING ***")
            print(f"[plant-sim] t={sim_t:6.1f}s level={level:5.1f}% "
                  f"Qin={r['q_in']:5.0f} Qout={r['q_out']:5.0f} "
                  f"P1={int(r['p1_run'])} P2={int(r['p2_run'])} "
                  f"psi={r['psi']:4.0f} spill={spill:7.1f}gal {' '.join(flags)}", flush=True)

        tick += 1
        sim_t += C.TICK_S
        time.sleep(C.TICK_S)


if __name__ == "__main__":
    main()
