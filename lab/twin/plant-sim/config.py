"""
config.py -- wet-well plant model constants + the Modbus point map.

Mirrors DIGITAL_TWIN_ARCHITECTURE.md 1.3 (the L0-L1 image) exactly. All the
numbers a student would tune live here so plant_sim.py stays about the physics.
"""

# ---- Modbus address map (plant-sim is the SLAVE; OpenPLC is the master) ----
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

# ---- protection thresholds ----
MIN_FLOW_GPM = 400.0           # below this with a pump commanded = dead-head/underload
HI_PSI = 55.0                  # above this = closed valve / dead-head
PSI_BASE = 8.0                 # static discharge head when idle
PSI_PER_GPM = 0.0150           # psi rise per gpm of real flow

# ---- weir bounded-release model ----
WEIR_RELEASE_GPM = 1800.0      # equalization-basin relief once over the weir lip
