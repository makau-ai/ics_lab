#!/usr/bin/env python3
"""publisher.py -- a field sensor that publishes tank telemetry (paho-mqtt).

Mirrors 'field-sensor-07' from the capture: authenticates, sets a Last Will,
and publishes JSON readings to plant/tank1/telemetry every 2 seconds.

Env: BROKER (default localhost), PORT (1883), MQTT_USER, MQTT_PASS.
"""
import os, time, json, random
import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER", "localhost")
PORT = int(os.environ.get("PORT", "1883"))
USER = os.environ.get("MQTT_USER", "sensor_svc")
PW = os.environ.get("MQTT_PASS", "s3ns0r-pw")


def make_client(cid):
    # works on both paho-mqtt 1.x and 2.x
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=cid, clean_session=True)


def main():
    c = make_client("field-sensor-07")
    if USER:
        c.username_pw_set(USER, PW)
    c.will_set("plant/tank1/status", "offline", qos=1, retain=False)
    c.connect(BROKER, PORT, keepalive=30)
    c.loop_start()
    print(f"[publisher] connected to {BROKER}:{PORT} as field-sensor-07", flush=True)
    level = 72.0
    try:
        while True:
            level = round(min(95.0, max(5.0, level + random.uniform(-0.6, 0.9))), 1)
            payload = json.dumps({"level_pct": level,
                                  "temp_c": round(21 + random.uniform(-0.3, 0.5), 1),
                                  "flow_lpm": round(11 + random.uniform(-0.5, 0.8), 1)})
            c.publish("plant/tank1/telemetry", payload, qos=0)
            print(f"[publisher] -> plant/tank1/telemetry {payload}", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        c.loop_stop()
        c.disconnect()


if __name__ == "__main__":
    main()
