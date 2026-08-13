#!/usr/bin/env python3
"""
pump-controller.py -- a simulated actuator that ACTS on plant/tank1/command.

Makes the MQTT command-injection impact concrete (the frame-52 triage note):
it subscribes to the command topic and changes a simulated pump/valve state on
receipt, printing the physical consequence an unauthorized publish would cause.
Lab use only — this is exactly the trusting subscriber that turns a broker
authorization gap into equipment movement.

Env: BROKER, PORT, MQTT_USER, MQTT_PASS.
"""
import os, json
import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
USER = os.environ.get("MQTT_USER") or None
PW = os.environ.get("MQTT_PASS") or None
state = {"pump1": "STOP", "valve": "closed"}


def make(cid):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def on_connect(c, u, flags, rc, *a):
    print(f"[pump-controller] connected rc={rc}; subscribing plant/tank1/command", flush=True)
    c.subscribe("plant/tank1/command", qos=1)


def on_message(c, u, msg):
    try:
        cmd = json.loads(msg.payload.decode())
    except Exception:
        cmd = {"raw": msg.payload.decode(errors="replace")}
    act = cmd.get("actuator", "pump1")
    if cmd.get("cmd"):
        state[act] = cmd["cmd"]
    if cmd.get("valve"):
        state["valve"] = cmd["valve"]
    print(f"[pump-controller] *** COMMAND on {msg.topic}: {cmd} -> state now {state} "
          f"— this is the physical impact an unauthorized publish would cause", flush=True)


def main():
    c = make("pump-controller-1")
    if USER:
        c.username_pw_set(USER, PW)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(BROKER, PORT, keepalive=60)
    c.loop_forever()


if __name__ == "__main__":
    main()
