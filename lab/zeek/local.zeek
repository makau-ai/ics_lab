# Load CISA's ICSNPP DNP3 extension (adds dnp3_control.log + dnp3_objects.log).
@load icsnpp-dnp3
# MQTT is analyzed by Zeek's built-in base/protocols/mqtt (loaded by default on
# Zeek 7.0 LTS+). On older Zeek, add:  @load policy/protocols/mqtt
