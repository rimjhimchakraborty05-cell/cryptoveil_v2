@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
.venv\Scripts\python.exe scripts\prepare_environment.py
if errorlevel 1 goto failed
.venv\Scripts\python.exe desktop_app.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo CryptoVeil could not start. Review the error above. Python 3.11+ is required.
pause
exit /b 1
