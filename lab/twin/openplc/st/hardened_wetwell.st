(* ==========================================================================
   hardened_wetwell.st -- the HARDENED wet-well loop (OpenPLC, IEC-61131-3 ST)

   Same control intent as naive_wetwell.st, plus the CIE [ENG] controls, all
   IN-LADDER so a register write cannot reach past them (CIE_HARDENING W1/W5/W6):

     W6  Setpoint CLAMP        LEAD_START := LIMIT(40, %MW10/100, 85). A g41 write
                               of 150 % is clamped to 85 % -- the bound lives in
                               code, not the register.
     W1  Stop-permissive       a remote STOP is honored ONLY when stopping is
         interlock             physically safe -- never de-energize a rising,
                               high well, regardless of who commanded it.
     W5  EU range + quality    a PV outside 0..100 % is rejected as BAD-quality;
                               the loop falls back to last-good, never a raw slice.
     W4  Local-sensor decision protective logic reads %IW100 / %IX100.0 (the wired
                               transmitter + float), NEVER a DNP3/MQTT-reported value.
     W6  Independent high-high at/above the float trip the lead pump is forced on
                               in-ladder -- the digital reflection of the hardwired
                               plant-sim float (the true analog backstop is in the sim).
     #10 Comms-loss safe state on master/link loss, ignore remote and run local
                               deadband control (fail-operational).
   ========================================================================== *)
PROGRAM main
  VAR
    level_raw      AT %IW100 : INT;
    flow_raw       AT %IW101 : INT;
    psi_raw        AT %IW102 : INT;
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
    both_pumps_healthy : BOOL := TRUE;   (* placeholder for the 49/50 motor-protection input *)
    permit_stop        : BOOL;
    comms_ok           : BOOL := TRUE;   (* a link watchdog would clear this on master timeout *)
  END_VAR

  VAR CONSTANT
    LAG_START : REAL := 80.0;
    LOWCUT    : REAL := 10.0;
    HLA_SP    : REAL := 90.0;
    FLOAT_SP  : REAL := 95.0;
    SP_MIN    : REAL := 40.0;
    SP_MAX    : REAL := 85.0;
  END_VAR

  (* ---- W5: EU range + quality. Reject an out-of-span PV; use last-good. ---- *)
  pv_quality_ok := (level_raw >= 0) AND (level_raw <= 10000);
  IF pv_quality_ok THEN
    level := INT_TO_REAL(level_raw) / 100.0;
    last_good_level := level;
  ELSE
    level := last_good_level;
  END_IF;

  (* ---- W6: setpoint clamp -- the writable register is bounded by logic ---- *)
  lead_start := LIMIT(SP_MIN, INT_TO_REAL(lead_start_raw) / 100.0, SP_MAX);
  stop_sp    := LIMIT(10.0,  INT_TO_REAL(stop_raw) / 100.0, 35.0);

  level_falling := level < prev_level;

  (* ---- #10: comms-loss safe state -- ignore remote, run local loop ---- *)
  IF NOT comms_ok THEN
    remote_cmd := 0;
  END_IF;

  (* ---- W1: stop-permissive interlock. Stop only when the well is low. ---- *)
  permit_stop := (level < lead_start) AND (level_falling OR both_pumps_healthy);

  IF (remote_cmd = 2) AND permit_stop THEN
    p1 := FALSE;
    p2 := FALSE;
  ELSIF remote_cmd = 1 THEN
    p1 := TRUE;
  ELSE
    (* ---- W4: automatic control decides on the LOCAL transmitter only ---- *)
    IF level >= lead_start THEN p1 := TRUE; END_IF;
    IF level >= LAG_START  THEN p2 := TRUE; END_IF;
    IF level <= stop_sp THEN
      p1 := FALSE;
      p2 := FALSE;
    END_IF;
  END_IF;

  (* dry-run inhibit *)
  IF (level <= LOWCUT) OR (NOT lsl) THEN
    p1 := FALSE;
    p2 := FALSE;
  END_IF;

  (* ---- W6: independent in-ladder high-high (mirrors the hardwired float) ---- *)
  IF lshh OR (level >= FLOAT_SP) THEN
    p1 := TRUE;                        (* force lead pump on; no command overrides this *)
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
