# Capture plane — seeing REAL inter-container traffic

Docker bridges have no SPAN/mirror, so the twin captures **out-of-band** three
ways (all defined in `../docker-compose.twin.yml`, gated by `--profile capture`
/ `--profile twin-full`). Every tap is passive — never inline on a control path
(CIE #6).

| Service | How it taps | Writes / serves | Filter |
|---|---|---|---|
| `sniff-dnp3` | shares `dnp3-gw` netns (`network_mode: service:dnp3-gw`) | `captures/dnp3_live.pcap` | `tcp port 20000` |
| `sniff-mqtt` | shares `mqtt-broker` netns | `captures/mqtt_live.pcap` | `tcp port 1883 or 8883` |
| `sniff-conduit` | shares `zone-fw` netns (SPAN-like, all zones) | `captures/conduit_live.pcap` | `20000 or 1883 or 8883` |
| `wireshark` | noVNC GUI, mounts `captures/` | `http://localhost:3000` (3001 https) | open the `*_live.pcap` |
| `edgeshark` | live click-to-Wireshark | `http://localhost:5001` | any container interface |
| `zeek` | parses the pcaps (`--profile tools`) | `dnp3*.log` / `mqtt_*.log` (ICSNPP) | — |

## Use it

```bash
docker compose -f ../docker-compose.twin.yml --profile capture up -d
# browser -> http://localhost:3000  (noVNC Wireshark)
#   File > Open > /captures/conduit_live.pcap   (auto-reloads as packets arrive)
#   display filter:  dnp3 || mqtt
```

The pcaps land in `../captures/` (bind-mounted to `/caps` in the sniffers and
`/captures` in Wireshark). They are the same Zeek-ready pcaps the kit's Levels
0→6 curriculum already uses — now real container-to-container DNP3/MQTT across
the conduits, not loopback.

**Live capture alternative:** run Wireshark with `network_mode: service:zone-fw`
to watch **Capture ▸ eth0** on the conduit live (trade-off: it can't also publish
the noVNC ports, so use Edgeshark for click-to-live instead).

**Edgeshark note:** full discovery needs the upstream Siemens deployment (host
PID/netns + the `ghcr.io/siemens/edgeshark` + discovery containers). The compose
service here exposes the UI on 5001; add the host-netns bits from Edgeshark's
`docker-compose-localhost.yaml` when running live.
