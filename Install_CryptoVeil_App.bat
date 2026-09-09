@echo off
setlocal enabledelayedexpansion

title CryptoVeil — Security Operations Desktop Application Installer

echo ======================================================================
echo          CryptoVeil v2 — Native Desktop Application Setup
echo ======================================================================
echo.

:: 1. Verify Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in PATH!
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [*] Python detected:
python --version

:: 2. Create/Check Virtual Environment
if not exist ".venv" (
    echo.
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
)

:: 3. Activate Virtual Environment
call .venv\Scripts\activate.bat

:: 4. Install / Update Dependencies
echo.
echo [*] Installing and verifying required desktop dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Retrying dependency installation in verbose mode...
    pip install -r requirements.txt
)

:: 5. Create Desktop and Start Menu Shortcuts
echo.
echo [*] Creating Windows Desktop and Start Menu shortcuts...
python setup_desktop_shortcuts.py

echo.
echo ======================================================================
echo  [✓] CryptoVeil Desktop App installed successfully!
echo  [*] Launching Native Desktop Window...
echo ======================================================================
echo.

python desktop_app.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] CryptoVeil encountered an issue while running.
    pause
)
