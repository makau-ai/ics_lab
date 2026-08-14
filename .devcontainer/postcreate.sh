#!/usr/bin/env bash
# Runs once after the container is created.
set -e

# Make all lab + devcontainer scripts executable (lab/lab has no extension, so it is
# named explicitly alongside the *.sh glob).
chmod +x lab/*.sh lab/lab lab/zeek/*.sh .devcontainer/*.sh 2>/dev/null || true
find lab -name '*.py' -exec chmod +x {} \; 2>/dev/null || true

# Place for live captures.
mkdir -p lab/captures

# --- lab command runner (Read / Do / Check) ---------------------------------------
# The step files (lab/steps/) + manifests (commands.tsv, aliases.sh) are committed, so
# nothing needs generating at postcreate. As a fallback (e.g. a partial checkout), if
# lab/steps is missing/empty regenerate it from content_levels via build_lab.py.
if [ ! -d lab/steps ] || [ -z "$(ls -A lab/steps 2>/dev/null)" ]; then
  echo "lab/steps missing — regenerating with build/build_lab.py ..."
  python3 build/build_lab.py || true
fi

# Wire the runner into the shell so BOTH the VS Code terminal and the noVNC xterm get
# `lab` on PATH and the short `l1`-style aliases. Idempotent — guarded by grep so it is
# never appended twice.
BASHRC="$HOME/.bashrc"
touch "$BASHRC" 2>/dev/null || true
if ! grep -q "ics_lab/lab/aliases.sh" "$BASHRC" 2>/dev/null; then
  {
    echo ""
    echo "# ICS lab command runner (Read/Do/Check) — added by .devcontainer/postcreate.sh"
    echo 'export PATH="$PATH:/workspaces/ics_lab/lab"'
    echo '[ -f /workspaces/ics_lab/lab/aliases.sh ] && . /workspaces/ics_lab/lab/aliases.sh'
  } >> "$BASHRC"
  echo "Wired lab runner into $BASHRC (PATH + aliases)."
fi

# Best-effort: add Wireshark + a terminal to the Fluxbox right-click menu
# (desktop-lite uses Fluxbox). Harmless if the menu layout differs.
if [ -f "$HOME/.fluxbox/menu" ] && ! grep -q "Wireshark" "$HOME/.fluxbox/menu"; then
  sed -i '2i \      [exec] (Wireshark) {wireshark}\n      [exec] (Terminal) {xterm}' "$HOME/.fluxbox/menu" 2>/dev/null || true
fi

echo "postCreate complete — scripts executable, lab/captures/ ready, lab runner wired (type 'lab list')."
