#!/usr/bin/env bash
# Security Monitor -- Quick Launch (Linux / macOS)
# Run with: sudo ./run_app.sh   (sudo required for raw packet capture)

set -e
cd "$(dirname "$0")"

# Activate virtual environment if present
if [[ -d ".venv" ]]; then
    source .venv/bin/activate
else
    echo "[WARN] No .venv found. Running with system Python."
    echo "  Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.11+ first."
    exit 1
fi

# On Linux, Scapy needs root for raw sockets
if [[ "$(uname)" == "Linux" && "$EUID" -ne 0 ]]; then
    echo "[WARN] Not running as root -- packet-based detectors (DDoS, ARP, DNS, BruteForce)"
    echo "       require elevated privileges. Re-run with: sudo $0"
    echo ""
fi

python3 desktop_app.py "$@"
