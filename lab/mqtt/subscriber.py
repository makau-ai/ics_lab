#!/usr/bin/env python3
"""subscriber.py -- the HMI dashboard that subscribes to plant telemetry.

Mirrors 'hmi-scada-01': authenticates and subscribes to plant/+/telemetry
(single-level wildcard), printing each reading the broker delivers.

Env: BROKER, PORT, MQTT_USER, MQTT_PASS, TOPIC (default plant/+/telemetry).
"""
import os
import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
USER = os.environ.get("MQTT_USER", "hmi_operator")
PW = os.environ.get("MQTT_PASS", "Plant!ntel2024")
TOPIC = os.environ.get("TOPIC", "plant/+/telemetry")


def make_client(cid):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def on_connect(c, u, flags, rc, *a):
    print(f"[subscriber] connected rc={rc}; subscribing to {TOPIC}", flush=True)
    c.subscribe(TOPIC, qos=1)


def on_message(c, u, msg):
    print(f"[subscriber] {msg.topic}  {msg.payload.decode(errors='replace')}", flush=True)


def main():
    c = make_client("hmi-scada-01")
    if USER:
        c.username_pw_set(USER, PW)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(BROKER, PORT, keepalive=60)
    c.loop_forever()


if __name__ == "__main__":
    main()
