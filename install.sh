#!/bin/bash
set -e
echo "[*] Installation JATHNIEL-WEB-CRAWLER-PRO v6.0 (Adaptive AI)"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo ""
echo "[+] OK"
echo "    source venv/bin/activate"
echo "    python jathniel_crawler_v6.py"