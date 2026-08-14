"""
config.py -- wet-well plant model constants + the Modbus point map.

Mirrors DIGITAL_TWIN_ARCHITECTURE.md 1.3 (the L0-L1 image) exactly. All the
numbers a student would tune live here so plant_sim.py stays about the physics.
"""

# ---- Modbus address map (plant-sim is the SERVER; OpenPLC is the client) ----
# Input registers (read-only words, sim -> PLC)
IR_LEVEL = 100     # %IW100  LT-101 wet-well level, 0..10000 = 0..100.00 %
IR_FLOW = 101      # %IW101  FIT-104 force-main flow, gpm
IR_PSI = 102       # %IW102  PIT-105 discharge pressure, psi
# Discrete inputs (read-only bits, sim -> PLC)
DI_LSHH = 0        # %IX100.0  LSHH-102 high-high float (HARDWIRED backstop path)
DI_LSL = 1         # %IX100.1  LSL-103 low float (dry-run cutout; TRUE = wet/ok)
# Coils (read/write bits, PLC -> sim)
CO_P1 = 0          # %QX100.0  P-1 start command
CO_P2 = 1          # %QX100.1  P-2 start command
CO_HLA = 2         # %QX100.2  High-Level-Alarm lamp (DNP3 BI + MQTT alarm feed)
# Holding registers (read/write words) -- setpoints live in the PLC, mirrored here
HR_LEAD_START = 10  # %MW10  LEAD_START setpoint (DNP3 g41 / MQTT target)
HR_STOP = 11        # %MW11  STOP setpoint
HR_REMOTE_CMD = 12  # %MW12  supervisory momentary command (per-pump, auto-reverts to 0)

# ---- %MW12 REMOTE_CMD contract (shared by hardened/naive ST + DNP3 gateway) ----
#   0 = no command / auto      1 = START P1     2 = START P2
#   3 = STOP P1                4 = STOP P2      5 = STOP ALL
# The ST latches the code on a rising edge, applies it, then writes %MW12 back to
# 0 (auto-revert) so a single command can never pin the loop out of automatic.
REMOTE_NONE, REMOTE_START_P1, REMOTE_START_P2 = 0, 1, 2
REMOTE_STOP_P1, REMOTE_STOP_P2, REMOTE_STOP_ALL = 3, 4, 5

# ---- simulation timing ----
TICK_S = 0.5                    # 500 ms scan, matches the ST loop

# ---- wet-well geometry / hydraulics ----
WETWELL_GALLONS_FULL = 4000.0   # usable volume that equals 100 % (3.0 m span)
PUMP_GPM = 1500.0               # each ~50 hp submersible, ~1500 gpm
PUMP_EFF = 0.90                 # volumetric/pumping efficiency

# ---- inflow model: diurnal base + optional storm pulse ----
Q_IN_BASE = 250.0               # dry-weather average inflow, gpm
Q_IN_DIURNAL_AMP = 150.0        # +/- swing over the "day"
DIURNAL_PERIOD_S = 240.0        # compressed municipal day so the demo is watchable
STORM_GPM = 2500.0              # wet-weather surge (exceeds a single pump)
STORM_DURATION_S = 180.0        # how long the surge lasts once it starts

# ---- level control setpoints (% of span) -- authoritative copy is the ST loop ----
LAG_START = 80.0
LEAD_START = 60.0
STOP = 20.0
LOWCUT = 10.0                   # dry-run inhibit below here
HLA = 90.0                      # high-level alarm
FLOAT_TRIP_PCT = 95.0          # LSHH-102 hardwired high-high float
WEIR_PCT = 98.0                # emergency overflow weir lip

# ---- hardened setpoint clamp band (authoritative copy is hardened_wetwell.st) ----
# SP_MAX is held STRICTLY BELOW LAG_START so an in-band setpoint write can never
# reorder the sequence (lead must always start before lag). 85 % > 80 % was the
# inversion the electrical review flagged; 78 % restores lead-before-lag.
SP_MIN = 40.0
SP_MAX = 78.0

# ---- protection thresholds ----
MIN_FLOW_GPM = 400.0           # below this with a pump commanded = dead-head/underload
FAULT_DEBOUNCE = 5             # consecutive scans of underload before a pump-fault latches
HI_PSI = 55.0                  # above this = closed valve / dead-head (trip threshold)

# ---- PIT-105 discharge-pressure model: DOWNWARD centrifugal H-Q curve ----
# A real submersible sewage pump rides a head-flow curve whose head is HIGHEST
# near shutoff (~zero flow) and FALLS as flow rises, bounded below by the static +
# friction head of the force main. psi = SHUTOFF_HEAD - PSI_PER_GPM*q_out, floored
# at STATIC_HEAD; a dead-head (closed valve / dry) sits above shutoff.
SHUTOFF_HEAD = 62.0            # psi at ~zero flow (top of the H-Q curve)
STATIC_HEAD = 18.0            # force-main static + friction head (curve floor)
DEADHEAD_MARGIN = 4.0        # extra psi past shutoff when a pump dead-heads
PSI_IDLE = 8.0               # discharge pressure with all pumps off (static column)
PSI_PER_GPM = 0.0150          # DOWNWARD slope: head falls this much per gpm of flow

# ---- weir bounded-release model ----
WEIR_RELEASE_GPM = 1800.0      # equalization-basin relief once over the weir lip
