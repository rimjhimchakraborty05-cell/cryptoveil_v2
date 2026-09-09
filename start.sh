#!/usr/bin/env bash
# ======================================================================
# CryptoVeil v2 — Linux / macOS Automated Launcher
# ======================================================================

set -e

echo "======================================================================"
echo "         CryptoVeil v2 — Automated Setup and Runner"
echo "======================================================================"
echo ""

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    echo "Please install Python 3.10+ using your package manager (e.g. apt, brew, dnf)."
    exit 1
fi

# 2. Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

# 3. Activate
source .venv/bin/activate

# 4. Install Dependencies
echo "[*] Checking and installing dependencies from requirements.txt..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# 5. Open Browser (Linux/macOS)
echo "[*] Opening Dashboard in browser..."
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:8765/dashboard/" &
elif command -v open &> /dev/null; then
    open "http://localhost:8765/dashboard/" &
fi

# 6. Start Agent
echo "[*] Starting CryptoVeil Server on 0.0.0.0:8765..."
echo "======================================================================"
python3 run.py
