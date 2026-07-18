@echo off
echo [*] Initiating SecureOps Boot Sequence...

IF NOT EXIST "venv\" (
    echo [!] No virtual environment found. Provisioning 'venv'...
    python -m venv venv
    echo [+] Virtual environment created.
)

echo [*] Activating isolation environment...
call venv\Scripts\activate.bat

echo [*] Verifying system dependencies...
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q

echo [+] Dependencies verified. Launching SecureOps Engine...
streamlit run app.py
