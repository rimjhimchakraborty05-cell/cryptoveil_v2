@echo off
setlocal enabledelayedexpansion

title CryptoVeil v2 — Security Operations Desktop Application

echo ======================================================================
echo          CryptoVeil v2 — Security Operations Desktop App
echo ======================================================================
echo.

:: 1. Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in PATH!
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

:: 2. Check/Create Virtual Environment
if not exist ".venv" (
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

:: 4. Install Dependencies
echo [*] Checking required dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Retrying dependency installation...
    pip install -r requirements.txt
)

:: 5. Create Desktop and Start Menu Shortcuts
python setup_desktop_shortcuts.py >nul 2>nul


:: 6. Launch CryptoVeil Native Desktop App
echo.
echo [*] Launching CryptoVeil Desktop Window...
echo ======================================================================
python desktop_app.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] CryptoVeil encountered an issue.
    pause
)

