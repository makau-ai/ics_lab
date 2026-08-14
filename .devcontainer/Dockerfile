# Workstation image for the ICS/OT Protocol Lab.
# Bakes in the full toolchain so the lab runs in GitHub Codespaces with a
# browser-visible Wireshark GUI (via the desktop-lite / noVNC devcontainer feature).
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive

# Preseed Wireshark so non-root users may capture, then install the lab toolchain.
# autocutsel + xclip: the clipboard bridge for the noVNC desktop. desktop-lite ships
# TigerVNC + noVNC but NO selection bridge, so a filter/command copied in the browser
# can't be pasted into Wireshark/xterm. autocutsel keeps the noVNC clipboard in sync
# with BOTH X selections; xclip is the tool students/instructors use to verify it.
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      wireshark tshark tcpdump tcpreplay \
      mosquitto mosquitto-clients \
      python3 python3-pip python3-venv \
      libcap2-bin iproute2 iputils-ping netcat-openbsd \
      xterm x11-utils autocutsel xclip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Let the non-root 'vscode' user capture packets without sudo.
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/dumpcap 2>/dev/null || true \
 && groupadd -f wireshark \
 && usermod -aG wireshark vscode 2>/dev/null || true

# Python client library for the MQTT lab scripts.
RUN pip3 install --no-cache-dir --break-system-packages paho-mqtt

# Do not let the packaged mosquitto auto-start on :1883 — we launch it on demand.
RUN systemctl disable mosquitto 2>/dev/null || true

# A convenient default DISPLAY for GUI apps launched from a plain shell
# (the desktop-lite feature serves this X display over noVNC on port 6080).
ENV DISPLAY=:1
