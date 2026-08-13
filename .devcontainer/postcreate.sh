#!/usr/bin/env bash
# Runs once after the container is created.
set -e

# Make all lab + devcontainer scripts executable.
chmod +x lab/*.sh lab/zeek/*.sh .devcontainer/*.sh 2>/dev/null || true
find lab -name '*.py' -exec chmod +x {} \; 2>/dev/null || true

# Place for live captures.
mkdir -p lab/captures

# Best-effort: add Wireshark + a terminal to the Fluxbox right-click menu
# (desktop-lite uses Fluxbox). Harmless if the menu layout differs.
if [ -f "$HOME/.fluxbox/menu" ] && ! grep -q "Wireshark" "$HOME/.fluxbox/menu"; then
  sed -i '2i \      [exec] (Wireshark) {wireshark}\n      [exec] (Terminal) {xterm}' "$HOME/.fluxbox/menu" 2>/dev/null || true
fi

echo "postCreate complete — scripts executable, lab/captures/ ready."
