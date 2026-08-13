# Level 3 — Inside the packet

*Fields & layers — now we open it up*

**Difficulty:** Intermediate &nbsp;·&nbsp; **Time:** ~40 min &nbsp;·&nbsp; **Prerequisite:** Level 2. This is where 'endpoints' turns into 'internals'.

**Goal.** Read specific fields inside the packets: MQTT credentials/topics/QoS/retain, and DNP3's three layers, addresses, IIN, and control objects.

## What you'll be able to do

- Expand the protocol tree and read named fields; use Apply as Column.
- Extract exact field values with `tshark -T fields -e <field>`.
- Read a DNP3 CROB control code and distinguish the DNP3 link address from the IP address.

## Background

Now we dive in. In Wireshark, click a frame and expand the protocol tree in the middle pane; **hover a field** to see its filter name in the status bar, and **right-click ▸ Apply as Column** to pull it up. On the CLI, `-T fields -e <name>` prints exact values — the analyst's scalpel.

DNP3 is layered: **data link** (0x0564 start, addresses, CRC) → **pseudo-transport** → **application** (function code, IIN, objects). The Control Relay Output Block (group 12 var 1) is the object that moves a breaker.

## Do this

```bash
# MQTT: read the cleartext login straight off the wire
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==1 -T fields -e mqtt.clientid -e mqtt.username -e mqtt.passwd
```
> **Expected:** hmi-scada-01  hmi_operator  Plant!ntel2024   (…and the sensor's creds). Cleartext — no TLS.

```bash
# MQTT: topic, QoS and the RETAIN flag on each publish
tshark -r pcaps/mqtt_iot_telemetry.pcap -Y mqtt.msgtype==3 -T fields -e frame.number -e mqtt.topic -e mqtt.qos -e mqtt.retain
```
> **Expected:** plant/tank1/telemetry with QoS 0 and 1; retain False. (mqtt.retain prints True/False.)

- **In Wireshark:** In Wireshark, click a DNP3 frame and expand **Distributed Network Protocol 3.0**: the Data Link Layer (Source/Destination link addresses + CRC), the Transport, and the Application Layer (Function Code, Internal Indications, Objects).
```bash
# DNP3: compare the IP source with the DNP3 LINK source, and read the control
tshark -r pcaps/dnp3_substation.pcap -Y "dnp3.al.func in {3,4,5}" -T fields -e frame.number -e ip.src -e dnp3.src -e dnp3.ctl.trip -e dnp3.ctl.op
```
> **Expected:** the legitimate close (Close/Pulse-On) from the master, and the rogue Trip — note ip.src vs dnp3.src.


## Check yourself

1. **What is the HMI's MQTT password, and which field held it?**
   <details><summary>answer</summary>Plant!ntel2024, in mqtt.passwd — sent in cleartext inside the CONNECT.</details>

2. **In DNP3, what's the difference between `ip.src` and `dnp3.src`?**
   <details><summary>answer</summary>ip.src is the network (IP) source; dnp3.src is the 16-bit DNP3 *link* address inside the data-link header. They can disagree — which is the whole game in Level 4.</details>

3. **Which object carries a breaker command, and which fields tell you trip vs close?**
   <details><summary>answer</summary>The CROB (group 12 var 1). dnp3.ctl.trip = Trip/Close code; dnp3.ctl.op = operation type (e.g., pulse on).</details>

**Level up:** You can extract any field by name and read a DNP3 control down to trip-vs-close, and you understand IP-address vs DNP3-link-address.
