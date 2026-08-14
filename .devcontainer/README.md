# Running the lab in GitHub Codespaces (with a Wireshark GUI over noVNC)

This `.devcontainer/` makes the whole kit run in the cloud with a **browser-visible desktop** — no
local install. It builds a workstation image (Wireshark GUI, tshark, tcpdump, tcpreplay, Mosquitto,
Python/paho) and adds two devcontainer features:

- **`desktop-lite`** — a lightweight Fluxbox desktop streamed to your browser via **noVNC on port 6080**.
- **`docker-in-docker`** — so the multi-container `docker compose` labs run inside the Codespace.

## Open it

1. Push this folder to a GitHub repository (the repo root must contain this `.devcontainer/` directory).
2. On the repo: **Code ▸ Codespaces ▸ Create codespace on main**. First build takes a few minutes.
3. When it opens, go to the **Ports** tab and open **6080 “noVNC Desktop (Wireshark)”** in your browser.
   It opens **straight to the desktop — no password prompt** (if one ever appears, it's `vscode`). A Fluxbox
   desktop with Wireshark appears.

> Tip: a 4-core machine type is comfortable if you also run the `docker compose` labs; the localhost
> lab below is fine on 2-core.

## See it live in Wireshark (the simple path)

In the VS Code terminal (or an `xterm` on the noVNC desktop):

```bash
./lab/run-local.sh up          # start the MQTT broker (1883) + DNP3 outstation (20000) on localhost
./lab/open-wireshark.sh        # Wireshark opens on the noVNC desktop (port 6080)
#   in Wireshark: Capture ▸ double-click  lo   ·   display filter:  dnp3   or   mqtt
./lab/run-local.sh dnp3        # poll + supervised close + rogue trip  -> watch it on 'lo'
./lab/run-local.sh mqtt        # publish/subscribe + anonymous eavesdrop + command injection
./lab/run-local.sh down
```

You can also just open the shipped captures: `./lab/open-wireshark.sh pcaps/dnp3_substation.pcap`.

## Multi-container / segmentation lab (Docker-in-Docker)

```bash
docker compose -f lab/docker-compose.yml up --build                    # flat lab
docker compose -f lab/docker-compose.segmented.yml up -d --build       # IEC 62443 zones + conduit
docker compose -f lab/docker-compose.yml --profile capture up sniff-dnp3   # writes lab/captures/dnp3_live.pcap
./lab/open-wireshark.sh lab/captures/dnp3_live.pcap
```

Container-to-container traffic is captured by the `sniff-*` tcpdump services into `lab/captures/`; open
those `.pcap` files in the Wireshark GUI. (Sniffing the internal Docker bridges directly from the
workstation isn't reliable, so the lab captures at the source instead.)

## Zeek + CISA ICSNPP

```bash
docker compose -f lab/docker-compose.yml --profile tools run --rm zeek run-zeek /kit/pcaps/dnp3_substation.pcap
```

Pre-generated reference logs are in `lab/zeek_reference_output/` if you'd rather not build the Zeek image.

## Troubleshooting

- **Port 6080 didn't open / blank screen:** open it from the **Ports** tab, then refresh. Give the desktop
  a few seconds after the Codespace starts. It connects with no password prompt (if one ever appears, it's `vscode`).
- **Copy/paste into the noVNC desktop doesn't work:** the desktop is a remote framebuffer, so a plain
  Ctrl/Cmd+V from your machine doesn't reach it. A clipboard bridge (`autocutsel`) is started for you, so the
  path is: click noVNC's **Clipboard** panel (the clipboard icon on the left edge), paste your text into that
  box, then **Ctrl+V** in Wireshark (or **Shift+Insert** / middle-click in an xterm). Verify the bridge with
  `DISPLAY=:1 xclip -selection clipboard -o`. Usually you don't need this at all — run commands with the `lab`
  runner (`l1`, `l2`, …) in the VS Code terminal and type short filters (`dnp3`, `mqtt`) straight into
  Wireshark. Full guide: `RUNNING_COMMANDS.md`.
- **Wireshark shows no interfaces / can't capture:** the image runs `setcap` on `dumpcap` and adds you to
  the `wireshark` group so non-root capture works; if a shell was opened before that finished, run
  `newgrp wireshark` or reopen the terminal. Headless alternative: `tshark -i lo -f "tcp port 20000"`.
- **`docker compose` says daemon not running:** the docker-in-docker feature starts it a moment after the
  Codespace boots; wait, then retry. Verify with `docker info`.
- **Wireshark opened but I don't see it:** it renders on the noVNC desktop (port 6080), not in VS Code.
  It is launched on `DISPLAY=:1`, which is what noVNC shows.
