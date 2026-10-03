#!/usr/bin/env bash
# Osprey — One-Command Plug-and-Play Launcher for Linux & macOS

set -e

echo "====================================================================="
echo " [Osprey] Supply Chain Attack Path Control Plane (v2.0)"
echo " One-Command Plug-and-Play Launcher"
echo "====================================================================="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3.10+ is required but was not found in your PATH."
    exit 1
fi

echo "[*] Launching Osprey interactive control plane..."
python3 cli.py ui
