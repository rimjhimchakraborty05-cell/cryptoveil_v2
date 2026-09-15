@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
.venv\Scripts\python.exe -m pip install -r requirements.txt "pyinstaller>=6,<7"
if errorlevel 1 goto failed
.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean CryptoVeil.spec
if errorlevel 1 goto failed
echo Build complete: dist\CryptoVeil\CryptoVeil.exe
echo Distribute the entire dist\CryptoVeil folder. The target needs Microsoft Edge WebView2 Runtime.
exit /b 0
:failed
echo The Windows build failed. Review the error above.
pause
exit /b 1
