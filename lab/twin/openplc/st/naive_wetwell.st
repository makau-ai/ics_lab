(* ==========================================================================
   naive_wetwell.st -- the VULNERABLE wet-well level loop (OpenPLC, IEC-61131-3 ST)

   Textbook duty/standby level control with a deadband, lead/lag alternation, a
   dry-run/dead-head motor-protection trip and a high-level alarm (DIGITAL_TWIN
   1.2). It is CORRECT for normal operation and deliberately UNSAFE under attack:

     * CWE-693 (the headline): LEAD_START comes from %MW10 (DNP3 g41 / MQTT
       setpoint) with NO CLAMP. Push it above 100 % and the loop never commands
       a pump start -- the Oldsmar "modify parameter" move, and the whole well
       overflows in silence.
     * CWE-306 (manipulation of control): the supervisory REMOTE_CMD (%MW12) is
       obeyed UNCONDITIONALLY -- a remote STOP de-energizes a pump even into a
       rising, nearly-full well. No interlock vetoes an unsafe command.

   %MW12 REMOTE_CMD contract (shared with the DNP3 gateway + hardened program):
       0 = no command / auto     1 = START P1     2 = START P2
       3 = STOP P1               4 = STOP P2      5 = STOP ALL
   The command is latched on a rising edge, applied, then %MW12 is written back
   to 0 (auto-revert) so a single command can never pin the loop out of auto.

   The engineered backstop (LSHH-102 hardwired float) is NOT in this program --
   it lives in plant-sim, independent of every coil here. That is the point.
   ========================================================================== *)
PROGRAM main
  VAR
    (* ---- process inputs (wired transmitters, read from plant-sim) ---- *)
    level_raw      AT %IW100 : INT;      (* LT-101 level, 0..10000 = 0..100.00 % *)
    flow_raw       AT %IW101 : INT;      (* FIT-104 flow, gpm *)
    psi_raw        AT %IW102 : INT;      (* PIT-105 discharge pressure, psi *)
    lshh           AT %IX100.0 : BOOL;   (* LSHH-102 high-high float (informational here) *)
    lsl            AT %IX100.1 : BOOL;   (* LSL-103 low float: TRUE = wet / not dry *)
    (* ---- outputs (pump/alarm coils, written to plant-sim) ---- *)
    p1             AT %QX100.0 : BOOL;    (* P-1 start *)
    p2             AT %QX100.1 : BOOL;    (* P-2 start *)
    hla            AT %QX100.2 : BOOL;    (* high-level alarm lamp -> DNP3 BI + MQTT *)
    (* ---- writable setpoints / command surface (DNP3 g41 / MQTT) ---- *)
    lead_start_raw AT %MW10 : INT;       (* LEAD_START setpoint *100 (UNCLAMPED) *)
    stop_raw       AT %MW11 : INT;       (* STOP setpoint *100 *)
    remote_cmd     AT %MW12 : INT;       (* momentary per-pump command (see contract) *)
  END_VAR
  (* matiec requires AT%-located variables and plain working variables in
     SEPARATE VAR blocks — keep the located I/O above, the workers below. *)
  VAR
    (* ---- working reals ---- *)
    level          : REAL;
    lead_start     : REAL;
    stop_sp        : REAL;
    (* ---- momentary-command edge latch ---- *)
    prev_cmd       : INT := 0;
    cmd            : INT;
    (* ---- duty/standby alternation ---- *)
    lead_is_p1     : BOOL := TRUE;
    prev_all_stop  : BOOL := FALSE;
    all_stopped    : BOOL;
    lead_on        : BOOL;
    lag_on         : BOOL;
    (* ---- dry-run / dead-head motor protection (49/50) ---- *)
    uf_cnt         : INT := 0;
    pump_fault     : BOOL := FALSE;
  END_VAR

  (* fixed setpoints (% of span) and protection thresholds *)
  VAR CONSTANT
    LAG_START : REAL := 80.0;
    LOWCUT    : REAL := 10.0;
    HLA_SP    : REAL := 90.0;
    MIN_FLOW  : INT  := 400;     (* FIT-104 gpm: below this w/ a pump ON = underload *)
    HI_PSI_SP : INT  := 55;      (* PIT-105 psi: above this = closed-valve / dead-head *)
    FAULT_DB  : INT  := 5;       (* consecutive underload scans before the fault latches *)
  END_VAR

  (* engineering units *)
  level      := INT_TO_REAL(level_raw) / 100.0;
  lead_start := INT_TO_REAL(lead_start_raw) / 100.0;   (* <-- NO CLAMP: the CWE-693 hole *)
  stop_sp    := INT_TO_REAL(stop_raw) / 100.0;

  (* ---- supervisory momentary command: latch on rising edge, then auto-revert ---- *)
  cmd := 0;
  IF (remote_cmd <> 0) AND (remote_cmd <> prev_cmd) THEN
    cmd := remote_cmd;               (* fresh command this scan *)
  END_IF;
  prev_cmd   := remote_cmd;
  remote_cmd := 0;                   (* auto-revert per the %MW12 contract *)

  (* ---- duty/standby alternation: rotate lead on each pump-down (all-stop edge) ---- *)
  all_stopped := (NOT p1) AND (NOT p2);
  IF all_stopped AND (NOT prev_all_stop) THEN
    lead_is_p1 := NOT lead_is_p1;    (* equalize wear: swap lead each pump-down cycle *)
  END_IF;
  prev_all_stop := all_stopped;

  (* map physical coils -> lead/lag roles (preserves deadband latching across scans) *)
  IF lead_is_p1 THEN
    lead_on := p1; lag_on := p2;
  ELSE
    lead_on := p2; lag_on := p1;
  END_IF;

  (* ---- automatic deadband level control (roles latch across scans) ---- *)
  IF level >= lead_start THEN lead_on := TRUE; END_IF;
  IF level >= LAG_START  THEN lag_on  := TRUE; END_IF;
  IF level <= stop_sp THEN
    lead_on := FALSE;
    lag_on  := FALSE;
  END_IF;

  (* map lead/lag roles back to the physical coils *)
  IF lead_is_p1 THEN
    p1 := lead_on; p2 := lag_on;
  ELSE
    p1 := lag_on; p2 := lead_on;
  END_IF;

  (* ---- supervisory momentary command -- obeyed with NO interlock (CWE-306) ---- *)
  CASE cmd OF
    1: p1 := TRUE;                   (* START P1 *)
    2: p2 := TRUE;                   (* START P2 *)
    3: p1 := FALSE;                  (* STOP P1 *)
    4: p2 := FALSE;                  (* STOP P2 *)
    5: p1 := FALSE; p2 := FALSE;     (* STOP ALL -- kills both, no safety veto *)
  END_CASE;

  (* ---- dry-run / dead-head interlock: reads FIT-104 (%IW101) + PIT-105 (%IW102) ---- *)
  IF (p1 OR p2) AND (flow_raw < MIN_FLOW) AND (psi_raw > HI_PSI_SP) THEN
    uf_cnt := uf_cnt + 1;
  ELSE
    uf_cnt := 0;
  END_IF;
  IF uf_cnt >= FAULT_DB THEN
    pump_fault := TRUE;              (* latch the underload/dead-head fault *)
  END_IF;
  IF level > LOWCUT THEN
    pump_fault := FALSE;             (* auto-reset once the well refills above dry *)
  END_IF;
  IF pump_fault THEN
    p1 := FALSE;
    p2 := FALSE;                     (* protect the motor: no flow => no run *)
  END_IF;

  (* dry-run inhibit: never run a pump into an empty well *)
  IF (level <= LOWCUT) OR (NOT lsl) THEN
    p1 := FALSE;
    p2 := FALSE;
  END_IF;

  (* high-level alarm *)
  hla := level >= HLA_SP;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : main;
  END_RESOURCE
END_CONFIGURATION
