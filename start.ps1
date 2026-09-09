# ======================================================================
# CryptoVeil v2 — PowerShell Automated Launcher
# ======================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         CryptoVeil v2 — Automated Setup and Runner" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[ERROR] Python was not found in PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ and check 'Add Python to PATH'." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# 2. Virtual environment setup
if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
}

# 3. Activate venv
$venvScript = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venvScript) {
    & $venvScript
}

# 4. Install requirements
Write-Host "[*] Checking and installing dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# 5. Open browser
Write-Host "[*] Opening Dashboard at http://localhost:8765/dashboard/..." -ForegroundColor Green
Start-Process "http://localhost:8765/dashboard/"

# 6. Run
Write-Host "[*] Starting CryptoVeil on 0.0.0.0:8765..." -ForegroundColor Cyan
python run.py
