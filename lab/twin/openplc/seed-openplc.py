#!/usr/bin/env python3
# =============================================================================
#  seed-openplc.py — headlessly seed OpenPLC v3 so the wet-well twin comes up
#  RUNNING, with no manual clicks in the web UI.
#
#  OpenPLC v3 is driven almost entirely from its Flask UI: adding a slave device,
#  enabling the Modbus server, and pressing "Start PLC" all mutate the SQLite DB
#  (webserver/openplc.db) AND, for the slave device, rewrite webserver/mbconfig.cfg
#  (the file the runtime's Modbus MASTER actually reads). Crucially, OpenPLC only
#  regenerates mbconfig.cfg from inside those UI handlers — never at boot — so a
#  bare DB INSERT is not enough: the runtime would start and poll *nothing*.
#
#  This script reproduces exactly what those UI actions do, idempotently:
#    1) INSERT the 'wetwell-plant-sim' Modbus/TCP slave device (if absent).
#    2) Ensure a Programs row exists for each seed ST (boot does
#       `SELECT * FROM Programs WHERE File=?` on the active program and needs a row).
#    3) Settings: Start_run_mode='true' (auto-run at boot), Enip_port='disabled'
#       (leave EtherNet/IP off). Modbus server (Modbus_port='502') and DNP3
#       ('disabled') already match what we want and are asserted for safety.
#    4) Regenerate mbconfig.cfg from the DB — byte-for-byte the same format
#       webserver.py:generate_mbconfig() emits — so the Modbus master polls the sim.
#
#  Register map (must match the ST's located addresses — see slave_devices.seed):
#    DI 0..1  -> %IX100.0 (LSHH-102), %IX100.1 (LSL-103)
#    IR 100..102 -> %IW100 (level), %IW101 (flow), %IW102 (psi)
#    coil 0..2 -> %QX100.0 (P-1), %QX100.1 (P-2), %QX100.2 (HLA)
#  OpenPLC maps the FIRST slave device starting at offset 100, which is why the
#  ST uses %..100. This is the only device, so the offsets line up exactly.
#
#  Idempotent: safe to run on every boot. Re-running only re-asserts settings and
#  rewrites mbconfig.cfg; it never duplicates the device or the Programs rows.
# =============================================================================
import os
import sys
import time
import sqlite3

DB      = os.environ.get("OPENPLC_DB", "/docker_persistent/openplc.db")
MBCONF  = os.environ.get("OPENPLC_MBCONFIG", "/workdir/webserver/mbconfig.cfg")
ST_LIST = ["naive_wetwell.st", "hardened_wetwell.st"]

# --- the plant-sim slave device, as OpenPLC's "Add Modbus Device" would store it ---
DEVICE = dict(
    dev_name="wetwell-plant-sim",
    dev_type="TCP",              # 'Generic Modbus TCP Device'
    slave_id=1,
    com_port="", baud_rate=115200, parity="None", data_bits=8, stop_bits=1,  # RTU-only, ignored for TCP
    ip_address="172.30.10.10", ip_port=502,
    di_start=0,  di_size=2,      # discrete inputs  -> %IX100.0, %IX100.1
    coil_start=0, coil_size=3,   # coils            -> %QX100.0..2
    ir_start=100, ir_size=3,     # input registers  -> %IW100..102
    hr_read_start=0, hr_read_size=0,
    hr_write_start=0, hr_write_size=0,
    pause=0,
)


def seed(conn):
    cur = conn.cursor()

    # 1) slave device (idempotent by unique dev_name) ------------------------
    cur.execute("SELECT COUNT(*) FROM Slave_dev WHERE dev_name=?", (DEVICE["dev_name"],))
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO Slave_dev (dev_name, dev_type, slave_id, com_port, baud_rate, "
            "parity, data_bits, stop_bits, ip_address, ip_port, di_start, di_size, "
            "coil_start, coil_size, ir_start, ir_size, hr_read_start, hr_read_size, "
            "hr_write_start, hr_write_size, pause) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (DEVICE["dev_name"], DEVICE["dev_type"], DEVICE["slave_id"], DEVICE["com_port"],
             DEVICE["baud_rate"], DEVICE["parity"], DEVICE["data_bits"], DEVICE["stop_bits"],
             DEVICE["ip_address"], DEVICE["ip_port"], DEVICE["di_start"], DEVICE["di_size"],
             DEVICE["coil_start"], DEVICE["coil_size"], DEVICE["ir_start"], DEVICE["ir_size"],
             DEVICE["hr_read_start"], DEVICE["hr_read_size"], DEVICE["hr_write_start"],
             DEVICE["hr_write_size"], DEVICE["pause"]),
        )
        print("[seed] added slave device wetwell-plant-sim (172.30.10.10:502)")
    else:
        print("[seed] slave device wetwell-plant-sim already present")

    # 2) Programs rows for each seed ST (boot selects the active one by File) --
    now = int(time.time())
    for st in ST_LIST:
        cur.execute("SELECT COUNT(*) FROM Programs WHERE File=?", (st,))
        if cur.fetchone()[0] == 0:
            name = st.replace(".st", "")
            cur.execute(
                "INSERT INTO Programs (Name, Description, File, Date_upload) VALUES (?,?,?,?)",
                (name, "Wet-well lift-station control logic (twin auto-seed)", st, now),
            )
            print(f"[seed] registered program {st}")

    # 3) Settings ------------------------------------------------------------
    #    Start_run_mode=true  -> run_http() auto-starts the runtime at boot.
    #    Enip_port=disabled   -> leave EtherNet/IP off (DNP3 already disabled;
    #                            the readable DNP3 outstation is dnp3-gw, not OpenPLC).
    #    Modbus_port=502      -> the Modbus SERVER the SCADA/dnp3-gw read.
    for key, val in (("Start_run_mode", "true"),
                     ("Enip_port", "disabled"),
                     ("Dnp3_port", "disabled"),
                     ("Modbus_port", "502")):
        cur.execute("UPDATE Settings SET Value=? WHERE Key=?", (val, key))
        if cur.rowcount == 0:  # key absent in an older DB — insert it
            cur.execute("INSERT INTO Settings (Key, Value) VALUES (?,?)", (key, val))
    print("[seed] settings: Start_run_mode=true, Modbus=502, DNP3=off, EtherNet/IP=off")

    conn.commit()


def generate_mbconfig(conn):
    """Rebuild mbconfig.cfg from the DB — identical format to
    webserver.py:generate_mbconfig() so the runtime's Modbus master reads it."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM Slave_dev")
    num_devices = int(cur.fetchone()[0])
    mb = 'Num_Devices = "' + str(num_devices) + '"'

    cur.execute("SELECT * FROM Settings")
    settings = {r[0]: r[1] for r in cur.fetchall()}
    mb += '\nPolling_Period = "' + str(settings.get("Slave_polling", "100")) + '"'
    mb += '\nTimeout = "' + str(settings.get("Slave_timeout", "1000")) + '"'

    cur.execute("SELECT * FROM Slave_dev")
    rows = cur.fetchall()
    # Slave_dev columns: 0 dev_id,1 dev_name,2 dev_type,3 slave_id,4 com_port,
    # 5 baud,6 parity,7 data_bits,8 stop_bits,9 ip,10 ip_port,11 di_start,12 di_size,
    # 13 coil_start,14 coil_size,15 ir_start,16 ir_size,17 hr_read_start,18 hr_read_size,
    # 19 hr_write_start,20 hr_write_size,21 pause
    for i, row in enumerate(rows):
        mb += "\n# ------------\n#   DEVICE " + str(i) + "\n# ------------\n"
        mb += 'device%d.name = "%s"\n' % (i, row[1])
        mb += 'device%d.slave_id = "%s"\n' % (i, row[3])
        if str(row[2]) in ("ESP32", "ESP8266", "TCP"):
            mb += 'device%d.protocol = "TCP"\n' % i
            mb += 'device%d.address = "%s"\n' % (i, row[9])
        else:
            mb += 'device%d.protocol = "RTU"\n' % i
            mb += 'device%d.address = "%s"\n' % (i, row[4])
        mb += 'device%d.IP_Port = "%s"\n' % (i, row[10])
        mb += 'device%d.RTU_Baud_Rate = "%s"\n' % (i, row[5])
        mb += 'device%d.RTU_Parity = "%s"\n' % (i, row[6])
        mb += 'device%d.RTU_Data_Bits = "%s"\n' % (i, row[7])
        mb += 'device%d.RTU_Stop_Bits = "%s"\n' % (i, row[8])
        mb += 'device%d.RTU_TX_Pause = "%s"\n\n' % (i, row[21])
        mb += 'device%d.Discrete_Inputs_Start = "%s"\n' % (i, row[11])
        mb += 'device%d.Discrete_Inputs_Size = "%s"\n' % (i, row[12])
        mb += 'device%d.Coils_Start = "%s"\n' % (i, row[13])
        mb += 'device%d.Coils_Size = "%s"\n' % (i, row[14])
        mb += 'device%d.Input_Registers_Start = "%s"\n' % (i, row[15])
        mb += 'device%d.Input_Registers_Size = "%s"\n' % (i, row[16])
        mb += 'device%d.Holding_Registers_Read_Start = "%s"\n' % (i, row[17])
        mb += 'device%d.Holding_Registers_Read_Size = "%s"\n' % (i, row[18])
        mb += 'device%d.Holding_Registers_Start = "%s"\n' % (i, row[19])
        mb += 'device%d.Holding_Registers_Size = "%s"\n' % (i, row[20])

    with open(MBCONF, "w") as f:
        f.write(mb)
    print(f"[seed] wrote {MBCONF} (Num_Devices={num_devices})")


def main():
    if not os.path.exists(DB):
        print(f"[seed] ERROR: DB not found at {DB} — is the openplc_persistent volume mounted?",
              file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB)
    try:
        seed(conn)
        generate_mbconfig(conn)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
