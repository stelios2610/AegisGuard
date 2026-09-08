#!/usr/bin/env bash
# Idempotent development environment bootstrap for FGUARD UTC / PhishScan.
# Installs system libraries needed by the PyQt6 desktop app, the PhishScan
# tkinter GUI, and the FastAPI web console, then creates a project virtualenv.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── System packages ──────────────────────────────────────────────────────────
# - python3-tk        : tkinter, used by the PhishScan desktop GUI
# - libgl1/libegl1/*  : Qt (PyQt6) platform + xcb plugin runtime libraries
# - iptables          : firewall backend used by the web console (degrades
#                       gracefully when the kernel netfilter table is not writable)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    python3-venv python3-dev python3-tk \
    libgl1 libegl1 libxkbcommon-x11-0 libxcb-cursor0 \
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libdbus-1-3 \
    fonts-dejavu iptables
fi

# ── Python virtualenv ────────────────────────────────────────────────────────
if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "Environment ready. Activate with: source .venv/bin/activate"
