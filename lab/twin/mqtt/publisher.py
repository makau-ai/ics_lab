#!/usr/bin/env python3
"""publisher.py -- iiot-gw: the IIoT/MQTT edge gateway (TWIN edition).

Re-skin of the lab field-sensor publisher. Instead of random numbers it reads
the LIVE wet-well image from OpenPLC over Modbus and PUBLISHes it to the broker
in the OT-DMZ, riding alongside the DNP3 path:

  plant/tank1/telemetry  {"level_pct":42.0,"flow_gpm":1490,"p1":"RUN","p2":"STOP","psi":31}
  plant/tank1/status     retained pump/alarm/health summary

Env: BROKER, PORT, MQTT_USER, MQTT_PASS, MODBUS_HOST (default openplc), MODBUS_PORT.
"""
import json
import os
import time

import paho.mqtt.client as mqtt

from modbus_tcp import ModbusClient

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
USER = os.environ.get("MQTT_USER", "sensor_svc")
PW = os.environ.get("MQTT_PASS", "s3ns0r-pw")
MODBUS_HOST = os.environ.get("MODBUS_HOST", "openplc")
MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "502"))

# Modbus addresses -- PLC_MAP="sim" (default) reads plant-sim's raw map (and
# OpenPLC's input registers); "openplc" shifts the bit map by 800 (%QX100.0).
PLC_MAP = os.environ.get("PLC_MAP", "sim")
_BITBASE = 800 if PLC_MAP == "openplc" else 0
MB_IR_LEVEL, MB_IR_FLOW, MB_IR_PSI = 100, 101, 102
MB_CO_P1, MB_CO_P2, MB_CO_HLA = _BITBASE + 0, _BITBASE + 1, _BITBASE + 2


def make_client(cid):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def read_plant(cli_holder):
    """Return the current plant image from OpenPLC Modbus, or None on failure."""
    cli = cli_holder.get("c")
    try:
        if cli is None:
            cli = ModbusClient(MODBUS_HOST, MODBUS_PORT, timeout=2.0)
            cli.connect()
            cli_holder["c"] = cli
        ir = cli.read_input_registers(MB_IR_LEVEL, 3)
        co = cli.read_coils(MB_CO_P1, 3)
        return {
            "level_pct": round(ir[0] / 100.0, 1),
            "flow_gpm": ir[1],
            "psi": ir[2],
            "p1": "RUN" if co[0] else "STOP",
            "p2": "RUN" if co[1] else "STOP",
            "hla": bool(co[2]),
        }
    except (OSError, IOError, ConnectionError) as e:
        cli_holder["c"] = None
        print(f"[iiot-gw] modbus read from {MODBUS_HOST}:{MODBUS_PORT} failed ({e})", flush=True)
        return None


def main():
    c = make_client("iiot-gw-01")
    if USER:
        c.username_pw_set(USER, PW)
    c.will_set("plant/tank1/status", json.dumps({"health": "offline"}), qos=1, retain=True)
    c.connect(BROKER, PORT, keepalive=30)
    c.loop_start()
    print(f"[iiot-gw] connected to {BROKER}:{PORT}; sourcing modbus://{MODBUS_HOST}:{MODBUS_PORT}", flush=True)
    holder = {"c": None}
    try:
        while True:
            plant = read_plant(holder)
            if plant is not None:
                telem = json.dumps({"level_pct": plant["level_pct"], "flow_gpm": plant["flow_gpm"],
                                    "p1": plant["p1"], "p2": plant["p2"], "psi": plant["psi"]})
                c.publish("plant/tank1/telemetry", telem, qos=0)
                status = json.dumps({"health": "online", "hla": plant["hla"],
                                     "pumps": [plant["p1"], plant["p2"]]})
                c.publish("plant/tank1/status", status, qos=1, retain=True)
                print(f"[iiot-gw] -> plant/tank1/telemetry {telem}", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        c.loop_stop()
        c.disconnect()


if __name__ == "__main__":
    main()
