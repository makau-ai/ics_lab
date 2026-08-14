(* ==========================================================================
   naive_wetwell.st -- the VULNERABLE wet-well level loop (OpenPLC, IEC-61131-3 ST)

   Textbook duty/standby level control with a deadband, dry-run inhibit and a
   high-level alarm (DIGITAL_TWIN 1.2). It is CORRECT for normal operation and
   deliberately UNSAFE under attack:

     * CWE-693 (the headline): LEAD_START comes from %MW10 (DNP3 g41 / MQTT
       setpoint) with NO CLAMP. Push it above 100 % and the loop never commands
       a pump start -- the Oldsmar "modify parameter" move, and the whole well
       overflows in silence.
     * CWE-306 (manipulation of control): a supervisory REMOTE_CMD (%MW12) is
       obeyed UNCONDITIONALLY -- a remote STOP de-energizes both pumps even into
       a rising, nearly-full well. No interlock vetoes an unsafe command.

   The engineered backstop (LSHH-102 hardwired float) is NOT in this program --
   it lives in plant-sim, independent of every coil here. That is the point.
   ========================================================================== *)
PROGRAM main
  VAR
    (* ---- process inputs (wired transmitters, read from plant-sim) ---- *)
    level_raw      AT %IW100 : INT;      (* LT-101 level, 0..10000 = 0..100.00 % *)
    flow_raw       AT %IW101 : INT;      (* FIT-104 flow, gpm *)
    psi_raw        AT %IW102 : INT;      (* PIT-105 pressure, psi *)
    lshh           AT %IX100.0 : BOOL;   (* LSHH-102 high-high float (informational here) *)
    lsl            AT %IX100.1 : BOOL;   (* LSL-103 low float: TRUE = wet / not dry *)
    (* ---- outputs (pump/alarm coils, written to plant-sim) ---- *)
    p1             AT %QX100.0 : BOOL;    (* P-1 start *)
    p2             AT %QX100.1 : BOOL;    (* P-2 start *)
    hla            AT %QX100.2 : BOOL;    (* high-level alarm lamp -> DNP3 BI + MQTT *)
    (* ---- writable setpoints / command surface (DNP3 g41 / MQTT) ---- *)
    lead_start_raw AT %MW10 : INT;       (* LEAD_START setpoint *100 (UNCLAMPED) *)
    stop_raw       AT %MW11 : INT;       (* STOP setpoint *100 *)
    remote_cmd     AT %MW12 : INT;       (* 0=auto, 1=remote-run lead, 2=remote-stop-all *)
    (* ---- working reals ---- *)
    level          : REAL;
    lead_start     : REAL;
    stop_sp        : REAL;
  END_VAR

  (* fixed setpoints (% of span) *)
  VAR CONSTANT
    LAG_START : REAL := 80.0;
    LOWCUT    : REAL := 10.0;
    HLA_SP    : REAL := 90.0;
  END_VAR

  (* engineering units *)
  level      := INT_TO_REAL(level_raw) / 100.0;
  lead_start := INT_TO_REAL(lead_start_raw) / 100.0;   (* <-- NO CLAMP: the CWE-693 hole *)
  stop_sp    := INT_TO_REAL(stop_raw) / 100.0;

  (* supervisory remote command -- obeyed with no interlock (CWE-306) *)
  IF remote_cmd = 2 THEN
    p1 := FALSE;
    p2 := FALSE;                       (* remote STOP: kills both pumps, no safety veto *)
  ELSIF remote_cmd = 1 THEN
    p1 := TRUE;                        (* remote RUN lead pump *)
  ELSE
    (* automatic deadband level control (values latch across scans) *)
    IF level >= lead_start THEN p1 := TRUE; END_IF;
    IF level >= LAG_START  THEN p2 := TRUE; END_IF;
    IF level <= stop_sp THEN
      p1 := FALSE;
      p2 := FALSE;
    END_IF;
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
