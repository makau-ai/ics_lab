#!/usr/bin/env python3
"""subscriber.py -- historian / HMI feed (TWIN edition).

Base mode mirrors the lab HMI subscriber. With --historian it becomes the
control-center historian: subscribes plant/tank1/#, logs every message, and runs
the CIE #6 commanded-vs-reported cross-check -- a spoof tripwire that compares
the reported telemetry stream against the wet-well physics baseline.

  Physics sanity: with BOTH pumps reported STOP, level must be non-decreasing
  (inflow only). A reported level that FALLS while pumps are off is physically
  impossible -> flag as a probable spoofed-telemetry attack (W4 / CWE-807).

Env: BROKER, PORT, MQTT_USER, MQTT_PASS, TOPIC (default plant/tank1/#).
"""
import argparse
import json
import os

import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
USER = os.environ.get("MQTT_USER", "hmi_operator")
PW = os.environ.get("MQTT_PASS", "Plant!ntel2024")
TOPIC = os.environ.get("TOPIC", "plant/tank1/#")

_last = {"level": None, "pumps_off": None}


def make_client(cid):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def on_connect(c, u, flags, rc, *a):
    print(f"[historian] connected rc={rc}; subscribing to {TOPIC}", flush=True)
    c.subscribe(TOPIC, qos=1)


def _cross_check(payload):
    """Commanded-vs-reported spoof tripwire (returns a warning string or None)."""
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if "level_pct" not in data:
        return None
    level = data.get("level_pct")
    pumps_off = data.get("p1", "STOP") == "STOP" and data.get("p2", "STOP") == "STOP"
    warn = None
    if _last["level"] is not None and pumps_off and _last["pumps_off"]:
        if level is not None and level < _last["level"] - 0.5:
            warn = (f"SPOOF TRIPWIRE: reported level fell {_last['level']}->{level}% "
                    f"with BOTH pumps STOP (physically impossible; inflow only) — "
                    f"likely spoofed telemetry (W4/CWE-807)")
    _last["level"] = level
    _last["pumps_off"] = pumps_off
    return warn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--historian", action="store_true",
                    help="enable persistence log + commanded-vs-reported cross-check")
    args = ap.parse_args()

    def on_message(c, u, msg):
        text = msg.payload.decode(errors="replace")
        print(f"[historian] {msg.topic}  {text}", flush=True)
        if args.historian:
            warn = _cross_check(text)
            if warn:
                print(f"[historian] *** {warn}", flush=True)

    c = make_client("historian-01")
    if USER:
        c.username_pw_set(USER, PW)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(BROKER, PORT, keepalive=60)
    c.loop_forever()


if __name__ == "__main__":
    main()
