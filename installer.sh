#!/bin/bash
echo "[+] Creating virtualenv..."
python3 -m venv venv || { echo "Failed to create venv"; exit 1; }
echo "[+] Activating venv..."
source venv/bin/activate || { echo "Failed to activate venv"; exit 1; }
echo "[+] Installing dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
echo "[+] Environment ready."
echo
echo "To run:"
echo "source venv/bin/activate && python3 uivo.py -h"
echo
