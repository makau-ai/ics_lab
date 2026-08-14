#!/usr/bin/env python3
"""
test_twin.py -- headless safety-invariant test for the wet-well digital twin.

Pure standard library, no Docker, no network, no pymodbus. It imports the ACTUAL
wet-well physics (plant_sim.step + config) and drives it through a faithful
Python re-implementation of the naive vs hardened CONTROL DECISIONS
(deadband + setpoint clamp + stop-permissive interlock + the hardwired float),
then runs the twin's adversarial scenario:

    the attacker owns the writable control surface and
      (a) writes LEAD_START (%MW10 / DNP3 g41) ABOVE 100 %  -- the Oldsmar move, and
      (b) forces both pumps OFF (%MW12 STOP ALL, and -- in the "even-if" run --
          the pump coils themselves, i.e. full digital write access).

Central safety invariant, asserted headlessly (design PANEL_REVIEW P2 #10, gap #8):

    naive / insecure  -> spill_gallons  > 0    (SSO: the unclamped setpoint +
                                                 unconditional stop win)
    hardened          -> spill_gallons == 0    (clamp + interlock + analog float
                                                 keep the well bounded)

It prints the attribution counters (clamp_rejected / interlock_veto / float_trip)
so a green result cannot mask a bring-up failure, and exits non-zero on any
failed assertion.

Run:  python3 lab/twin/test_twin.py
"""
import os
import sys

# import the real plant model (plant_sim + config live in ./plant-sim)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "plant-sim"))
import config as C          # noqa: E402
import plant_sim as P       # noqa: E402

# --- setpoints / thresholds mirrored from the ST programs (kept in sync w/ config) ---
LAG_START = C.LAG_START            # 80 %
LOWCUT = C.LOWCUT                  # 10 %
FLOAT_SP = C.FLOAT_TRIP_PCT        # 95 % in-ladder high-high (mirrors the float)
SP_MIN = C.SP_MIN                  # 40 %  hardened clamp floor
SP_MAX = C.SP_MAX                  # 78 %  hardened clamp ceiling (strictly < LAG_START)
STOP_MIN, STOP_MAX = 10.0, 35.0    # hardened STOP-setpoint clamp band (hardened_wetwell.st)


# ===========================================================================
#  Control-decision re-implementations (mirror the two OpenPLC ST programs)
# ===========================================================================
class NaiveController:
    """naive_wetwell.st: deadband + lead/lag alternation, UNCLAMPED %MW10,
    UNCONDITIONAL %MW12 (CWE-693 + CWE-306)."""

    def __init__(self):
        self.p1 = False
        self.p2 = False
        self.lead_is_p1 = True
        self.prev_all_stop = False

    def decide(self, level, lsl, lead_start_raw, stop_raw, remote_cmd):
        lead_start = lead_start_raw / 100.0          # <-- NO CLAMP (the hole)
        stop_sp = stop_raw / 100.0

        # duty/standby alternation on the all-stop rising edge
        all_stopped = (not self.p1) and (not self.p2)
        if all_stopped and not self.prev_all_stop:
            self.lead_is_p1 = not self.lead_is_p1
        self.prev_all_stop = all_stopped

        lead_on, lag_on = (self.p1, self.p2) if self.lead_is_p1 else (self.p2, self.p1)
        if level >= lead_start:
            lead_on = True
        if level >= LAG_START:
            lag_on = True
        if level <= stop_sp:
            lead_on = lag_on = False
        if self.lead_is_p1:
            self.p1, self.p2 = lead_on, lag_on
        else:
            self.p1, self.p2 = lag_on, lead_on

        # momentary per-pump command -- obeyed with NO interlock (CWE-306)
        if remote_cmd == C.REMOTE_START_P1:
            self.p1 = True
        elif remote_cmd == C.REMOTE_START_P2:
            self.p2 = True
        elif remote_cmd == C.REMOTE_STOP_P1:
            self.p1 = False
        elif remote_cmd == C.REMOTE_STOP_P2:
            self.p2 = False
        elif remote_cmd == C.REMOTE_STOP_ALL:
            self.p1 = self.p2 = False

        # dry-run inhibit
        if level <= LOWCUT or not lsl:
            self.p1 = self.p2 = False
        return self.p1, self.p2


class HardenedController:
    """hardened_wetwell.st: in-ladder setpoint CLAMP (W6), stop-permissive
    interlock (W1), and the independent in-ladder high-high (W6). Counts why a
    hostile write was neutralised."""

    def __init__(self):
        self.p1 = False
        self.p2 = False
        self.lead_is_p1 = True
        self.prev_all_stop = False
        self.prev_level = 45.0
        self.both_pumps_healthy = True   # driven by the 49/50 fault in the ST
        self.clamp_rejected = 0
        self.interlock_veto = 0

    def decide(self, level, lsl, lshh, lead_start_raw, stop_raw, remote_cmd):
        raw = lead_start_raw / 100.0
        lead_start = min(max(raw, SP_MIN), SP_MAX)         # W6 clamp
        if raw > SP_MAX or raw < SP_MIN:
            self.clamp_rejected += 1                       # the clamp bound a hostile write
        stop_sp = min(max(stop_raw / 100.0, STOP_MIN), STOP_MAX)
        level_falling = level < self.prev_level

        all_stopped = (not self.p1) and (not self.p2)
        if all_stopped and not self.prev_all_stop:
            self.lead_is_p1 = not self.lead_is_p1
        self.prev_all_stop = all_stopped

        lead_on, lag_on = (self.p1, self.p2) if self.lead_is_p1 else (self.p2, self.p1)
        if level >= lead_start:
            lead_on = True
        if level >= LAG_START:
            lag_on = True
        if level <= stop_sp:
            lead_on = lag_on = False
        if self.lead_is_p1:
            self.p1, self.p2 = lead_on, lag_on
        else:
            self.p1, self.p2 = lag_on, lead_on

        # W1 stop-permissive: a STOP is honored only when stopping is safe
        permit_stop = (level < lead_start) and (level_falling or self.both_pumps_healthy)
        if remote_cmd == C.REMOTE_START_P1:
            self.p1 = True
        elif remote_cmd == C.REMOTE_START_P2:
            self.p2 = True
        elif remote_cmd == C.REMOTE_STOP_P1:
            if permit_stop:
                self.p1 = False
            else:
                self.interlock_veto += 1
        elif remote_cmd == C.REMOTE_STOP_P2:
            if permit_stop:
                self.p2 = False
            else:
                self.interlock_veto += 1
        elif remote_cmd == C.REMOTE_STOP_ALL:
            if permit_stop:
                self.p1 = self.p2 = False
            else:
                self.interlock_veto += 1

        # dry-run inhibit
        if level <= LOWCUT or not lsl:
            self.p1 = self.p2 = False

        # W6 independent in-ladder high-high -- force the LEAD pump on
        if lshh or level >= FLOAT_SP:
            if self.lead_is_p1:
                self.p1 = True
            else:
                self.p2 = True

        self.prev_level = level
        return self.p1, self.p2


# ===========================================================================
#  Scenario driver
# ===========================================================================
def run_scenario(controller, *, float_enabled, weir_enabled=True, motor_prot_enabled=True,
                 attack_setpoint_raw, attack_remote_cmd, force_coils_off=False,
                 ticks=800, storm_at=0.0):
    """Drive a controller against the wet-well physics under an attacker who holds
    the writable control surface. Returns (spill_gallons, peak_level, float_trip)."""
    level, spill, sim_t = 45.0, 0.0, 0.0
    # seeded transmitter feedback (what the PLC reads at tick 0)
    lsl, lshh = True, False
    peak = level
    float_trip = 0

    for _ in range(ticks):
        # --- controller decides on the live PV + the attacker's register writes ---
        if isinstance(controller, HardenedController):
            p1_cmd, p2_cmd = controller.decide(
                level, lsl, lshh, attack_setpoint_raw, int(C.STOP * 100), attack_remote_cmd)
        else:
            p1_cmd, p2_cmd = controller.decide(
                level, lsl, attack_setpoint_raw, int(C.STOP * 100), attack_remote_cmd)

        # --- "even-if" full write access: attacker also owns the output coils ---
        if force_coils_off:
            p1_cmd = p2_cmd = False

        # --- one tick of the REAL plant physics ---
        r = P.step(level, spill, sim_t, p1_cmd, p2_cmd,
                   float_enabled=float_enabled, weir_enabled=weir_enabled,
                   motor_prot_enabled=motor_prot_enabled, diurnal=False, storm_at=storm_at)
        level, spill = r["level"], r["spill"]
        lsl, lshh = r["lsl"], r["lshh"]
        if r["horn"]:
            float_trip += 1
        peak = max(peak, level)
        sim_t += C.TICK_S

    return spill, peak, float_trip


# ===========================================================================
#  Test harness
# ===========================================================================
def main():
    # sustained wet-weather surge so the scenario is deterministic (no diurnal term,
    # storm held on for the whole run) -- this is the attacker striking during a storm.
    C.STORM_DURATION_S = 10 ** 9

    ATTACK_SETPOINT = 15000        # %MW10 write = 150.00 % (> 100 %, unclamped in naive)
    STOP_ALL = C.REMOTE_STOP_ALL   # %MW12 = 5

    failures = []

    def check(name, cond, detail):
        status = "PASS" if cond else "FAIL"
        print(f"  [{status}] {name}: {detail}")
        if not cond:
            failures.append(name)

    print("=" * 74)
    print("Wet-well twin -- headless safety-invariant test (spill under attack)")
    print("Attack: LEAD_START(%MW10)=150.0%  +  STOP ALL(%MW12=5) every scan")
    print("=" * 74)

    # ---- NAIVE / insecure: no clamp, no interlock, float OFF (vulnerable default) ----
    naive_spill, naive_peak, naive_float = run_scenario(
        NaiveController(), float_enabled=False,
        attack_setpoint_raw=ATTACK_SETPOINT, attack_remote_cmd=STOP_ALL)
    print("\nNAIVE (insecure)   float=OFF  clamp=none  interlock=none")
    print(f"  peak_level = {naive_peak:6.2f}%   spill_gallons = {naive_spill:10.1f}")
    check("naive_spills", naive_spill > 0,
          f"spill_gallons = {naive_spill:.1f} (> 0 expected: SSO occurs)")

    # ---- HARDENED run 1: clamp + interlock hold with the analog float enabled ----
    hard_ctl = HardenedController()
    h1_spill, h1_peak, h1_float = run_scenario(
        hard_ctl, float_enabled=True,
        attack_setpoint_raw=ATTACK_SETPOINT, attack_remote_cmd=STOP_ALL)

    # ---- HARDENED run 2 ("even-if"): attacker owns the coils too; only the
    #      hardwired plant-sim float can save it (design rubric: independent layer) ----
    hard_ctl2 = HardenedController()
    h2_spill, h2_peak, h2_float = run_scenario(
        hard_ctl2, float_enabled=True, force_coils_off=True,
        attack_setpoint_raw=ATTACK_SETPOINT, attack_remote_cmd=STOP_ALL)

    clamp_rejected = hard_ctl.clamp_rejected + hard_ctl2.clamp_rejected
    interlock_veto = hard_ctl.interlock_veto + hard_ctl2.interlock_veto
    float_trip = h1_float + h2_float
    hard_spill = h1_spill + h2_spill

    print("\nHARDENED           float=ON   clamp=[40,78]%  interlock=stop-permissive")
    print(f"  run1 (PLC intact)      peak_level = {h1_peak:6.2f}%   spill = {h1_spill:8.1f}")
    print(f"  run2 (coils owned too) peak_level = {h2_peak:6.2f}%   spill = {h2_spill:8.1f}")
    check("hardened_no_spill", hard_spill == 0,
          f"spill_gallons = {hard_spill:.1f} (== 0 expected: well stays bounded)")

    print("\nAttribution counters (why the hardened well never spilled):")
    print(f"  clamp_rejected = {clamp_rejected:5d}   (hostile %MW10 setpoint writes clamped to <= 78%)")
    print(f"  interlock_veto = {interlock_veto:5d}   (unsafe %MW12 STOP commands refused by W1)")
    print(f"  float_trip     = {float_trip:5d}   (hardwired LSHH-102 float force-starts the pump)")

    # the counters must show the defenses actually did work (not a silent no-op)
    check("clamp_active", clamp_rejected > 0, f"clamp_rejected = {clamp_rejected} (> 0)")
    check("interlock_active", interlock_veto > 0, f"interlock_veto = {interlock_veto} (> 0)")
    check("float_active", float_trip > 0, f"float_trip = {float_trip} (> 0)")

    print("\n" + "=" * 74)
    if failures:
        print(f"RESULT: FAIL ({len(failures)} failed): {', '.join(failures)}")
        print("=" * 74)
        return 1
    print("RESULT: PASS -- naive spills, hardened holds spill at 0, all layers attributed")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
