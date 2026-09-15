@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
.venv\Scripts\python.exe scripts\prepare_environment.py
if errorlevel 1 goto failed
.venv\Scripts\python.exe setup_desktop_shortcuts.py
if errorlevel 1 goto failed
call start.bat
exit /b %errorlevel%
:failed
echo Installation failed. Review the error above.
pause
exit /b 1
