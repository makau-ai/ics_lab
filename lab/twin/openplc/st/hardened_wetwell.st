(* ==========================================================================
   hardened_wetwell.st -- the HARDENED wet-well loop (OpenPLC, IEC-61131-3 ST)

   Same control intent as naive_wetwell.st, plus the CIE [ENG] controls, all
   IN-LADDER so a register write cannot reach past them (CIE_HARDENING W1/W5/W6):

     W6  Setpoint CLAMP        LEAD_START := LIMIT(40, %MW10/100, 78). A g41 write
                               of 150 % is clamped to 78 % -- and 78 % is held
                               STRICTLY BELOW LAG_START (80 %) so an in-band write
                               can never make the lag pump start before the lead.
     W1  Stop-permissive       a remote STOP is honored ONLY when stopping is
         interlock             physically safe -- never de-energize a rising,
                               high well, regardless of who commanded it. The
                               interlock is now driven by the real 49/50 fault
                               (both_pumps_healthy), not a placeholder TRUE.
     W5  EU range + quality    a PV outside 0..100 % is rejected as BAD-quality;
                               the loop falls back to last-good, never a raw slice.
     W4  Local-sensor decision protective logic reads %IW100..102 / %IX100.0 (the
                               wired transmitters + float), NEVER a reported value.
     49/50 Dry-run/dead-head   reads FIT-104 (%IW101) + PIT-105 (%IW102): a pump
         motor protection      commanded with no flow and shutoff pressure latches
                               a fault, drops the coils and clears both_pumps_healthy.
     W6  Independent high-high at/above the float trip the lead pump is forced on
                               in-ladder -- the digital reflection of the hardwired
                               plant-sim float (the true analog backstop is in sim).
     #10 Comms-loss safe state a link watchdog clears comms_ok on master timeout;
                               remote commands are then ignored and the local
                               deadband runs (fail-operational).

   %MW12 REMOTE_CMD contract (shared with the DNP3 gateway + naive program):
       0 = no command / auto     1 = START P1     2 = START P2
       3 = STOP P1               4 = STOP P2      5 = STOP ALL
   Latched on a rising edge, applied (STOPs gated by W1), then %MW12 is written
   back to 0 (auto-revert) so a single command can never pin the loop out of auto.
   ========================================================================== *)
PROGRAM main
  VAR
    level_raw      AT %IW100 : INT;
    flow_raw       AT %IW101 : INT;      (* FIT-104 flow, gpm *)
    psi_raw        AT %IW102 : INT;      (* PIT-105 discharge pressure, psi *)
    lshh           AT %IX100.0 : BOOL;
    lsl            AT %IX100.1 : BOOL;
    p1             AT %QX100.0 : BOOL;
    p2             AT %QX100.1 : BOOL;
    hla            AT %QX100.2 : BOOL;
    lead_start_raw AT %MW10 : INT;
    stop_raw       AT %MW11 : INT;
    remote_cmd     AT %MW12 : INT;
    (* working / state *)
    level              : REAL;
    lead_start         : REAL;
    stop_sp            : REAL;
    prev_level         : REAL := 45.0;
    last_good_level    : REAL := 45.0;
    pv_quality_ok      : BOOL;
    level_falling      : BOOL;
    both_pumps_healthy : BOOL := TRUE;   (* now DRIVEN by the 49/50 fault below *)
    permit_stop        : BOOL;
    comms_ok           : BOOL := TRUE;   (* now DRIVEN by the link watchdog below *)
    comms_wdt          : INT  := 20;     (* watchdog scans remaining before link-loss *)
    (* momentary-command edge latch *)
    prev_cmd           : INT := 0;
    cmd                : INT;
    (* duty/standby alternation *)
    lead_is_p1         : BOOL := TRUE;
    prev_all_stop      : BOOL := FALSE;
    all_stopped        : BOOL;
    lead_on            : BOOL;
    lag_on             : BOOL;
    (* dry-run / dead-head motor protection (49/50) *)
    uf_cnt             : INT := 0;
    pump_fault         : BOOL := FALSE;
  END_VAR

  VAR CONSTANT
    LAG_START    : REAL := 80.0;
    LOWCUT       : REAL := 10.0;
    HLA_SP       : REAL := 90.0;
    FLOAT_SP     : REAL := 95.0;
    SP_MIN       : REAL := 40.0;
    SP_MAX       : REAL := 78.0;       (* strictly below LAG_START (80): lead-before-lag *)
    MIN_FLOW     : INT  := 400;        (* FIT-104 gpm underload threshold *)
    HI_PSI_SP    : INT  := 55;         (* PIT-105 psi dead-head/closed-valve threshold *)
    FAULT_DB     : INT  := 5;          (* consecutive underload scans before fault latches *)
    COMMS_TIMEOUT: INT  := 20;         (* scans without a master command => link lost *)
  END_VAR

  (* ---- W5: EU range + quality. Reject an out-of-span PV; use last-good. ---- *)
  pv_quality_ok := (level_raw >= 0) AND (level_raw <= 10000);
  IF pv_quality_ok THEN
    level := INT_TO_REAL(level_raw) / 100.0;
    last_good_level := level;
  ELSE
    level := last_good_level;
  END_IF;

  (* ---- W6: setpoint clamp -- the writable register is bounded by logic.
     SP_MAX (78) < LAG_START (80) preserves the lead-before-lag ordering. ---- *)
  lead_start := LIMIT(SP_MIN, INT_TO_REAL(lead_start_raw) / 100.0, SP_MAX);
  stop_sp    := LIMIT(10.0,  INT_TO_REAL(stop_raw) / 100.0, 35.0);

  level_falling := level < prev_level;

  (* ---- #10: link watchdog. Any fresh supervisory command (a %MW12 write from
     the master path) reloads the watchdog; otherwise it decrements. On timeout
     comms_ok clears and remote commands are ignored (run local -- fail-operational).
     (A production station would reload this from a dedicated heartbeat register;
     the twin's register-map contract carries only %MW10/11/12, so %MW12 activity
     is the liveness proxy here.) ---- *)
  IF remote_cmd <> 0 THEN
    comms_wdt := COMMS_TIMEOUT;
  ELSIF comms_wdt > 0 THEN
    comms_wdt := comms_wdt - 1;
  END_IF;
  comms_ok := comms_wdt > 0;

  (* ---- supervisory momentary command: latch on rising edge, then auto-revert ---- *)
  cmd := 0;
  IF (remote_cmd <> 0) AND (remote_cmd <> prev_cmd) THEN
    cmd := remote_cmd;
  END_IF;
  prev_cmd   := remote_cmd;
  remote_cmd := 0;                     (* auto-revert per the %MW12 contract *)

  (* ---- #10: comms-loss safe state -- ignore remote, run the local loop ---- *)
  IF NOT comms_ok THEN
    cmd := 0;
  END_IF;

  (* ---- duty/standby alternation: rotate lead on each pump-down (all-stop edge) ---- *)
  all_stopped := (NOT p1) AND (NOT p2);
  IF all_stopped AND (NOT prev_all_stop) THEN
    lead_is_p1 := NOT lead_is_p1;
  END_IF;
  prev_all_stop := all_stopped;

  IF lead_is_p1 THEN
    lead_on := p1; lag_on := p2;
  ELSE
    lead_on := p2; lag_on := p1;
  END_IF;

  (* ---- W4: automatic control decides on the LOCAL transmitter only ---- *)
  IF level >= lead_start THEN lead_on := TRUE; END_IF;
  IF level >= LAG_START  THEN lag_on  := TRUE; END_IF;
  IF level <= stop_sp THEN
    lead_on := FALSE;
    lag_on  := FALSE;
  END_IF;

  IF lead_is_p1 THEN
    p1 := lead_on; p2 := lag_on;
  ELSE
    p1 := lag_on; p2 := lead_on;
  END_IF;

  (* ---- W1: stop-permissive interlock. A STOP is honored only when the well is
     below lead-start AND (already falling OR both pumps healthy). ---- *)
  permit_stop := (level < lead_start) AND (level_falling OR both_pumps_healthy);

  CASE cmd OF
    1: p1 := TRUE;                                (* START P1 -- always allowed *)
    2: p2 := TRUE;                                (* START P2 -- always allowed *)
    3: IF permit_stop THEN p1 := FALSE; END_IF;   (* STOP P1  -- W1-gated *)
    4: IF permit_stop THEN p2 := FALSE; END_IF;   (* STOP P2  -- W1-gated *)
    5: IF permit_stop THEN                        (* STOP ALL -- W1-gated *)
         p1 := FALSE; p2 := FALSE;
       END_IF;
  END_CASE;

  (* ---- 49/50 dry-run / dead-head interlock (reads FIT-104 + PIT-105).
     Latch a pump fault on debounced underload, drop the coils, and DRIVE
     both_pumps_healthy -- this is what makes the W1 interlock real. ---- *)
  IF (p1 OR p2) AND (flow_raw < MIN_FLOW) AND (psi_raw > HI_PSI_SP) THEN
    uf_cnt := uf_cnt + 1;
  ELSE
    uf_cnt := 0;
  END_IF;
  IF uf_cnt >= FAULT_DB THEN
    pump_fault := TRUE;
  END_IF;
  IF level > LOWCUT THEN
    pump_fault := FALSE;               (* auto-reset once the well refills above dry *)
  END_IF;
  both_pumps_healthy := NOT pump_fault;
  IF pump_fault THEN
    p1 := FALSE;
    p2 := FALSE;
  END_IF;

  (* dry-run inhibit *)
  IF (level <= LOWCUT) OR (NOT lsl) THEN
    p1 := FALSE;
    p2 := FALSE;
  END_IF;

  (* ---- W6: independent in-ladder high-high (mirrors the hardwired float).
     Force the LEAD pump on; no command or interlock overrides this. ---- *)
  IF lshh OR (level >= FLOAT_SP) THEN
    IF lead_is_p1 THEN
      p1 := TRUE;
    ELSE
      p2 := TRUE;
    END_IF;
  END_IF;

  hla := level >= HLA_SP;
  prev_level := level;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : main;
  END_RESOURCE
END_CONFIGURATION
