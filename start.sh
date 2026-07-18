#!/usr/bin/env bash
# SecureOps Auto-Launcher

echo "[*] Initiating SecureOps Boot Sequence..."

# Check if the virtual environment folder exists
if [ ! -d "venv" ]; then
    echo "[!] No virtual environment found. Provisioning 'venv'..."
    python3 -m venv venv
    echo "[+] Virtual environment created."
fi

# Activate the virtual environment
echo "[*] Activating isolation environment..."
source venv/bin/activate

# Install or upgrade dependencies quietly
echo "[*] Verifying system dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Launch the Streamlit application
echo "[+] Dependencies verified. Launching SecureOps Engine..."
streamlit run app.py
