@echo off
setlocal enabledelayedexpansion

title Build Standalone CryptoVeil Desktop Executable (.EXE)

echo ======================================================================
echo          CryptoVeil v2 — Standalone Executable Builder
echo ======================================================================
echo.

:: 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH!
    pause
    exit /b 1
)

:: 2. Activate Venv if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

:: 3. Install PyInstaller
echo [*] Ensuring PyInstaller and dependencies are installed...
pip install pyinstaller -r requirements.txt --quiet

:: 4. Build Standalone Executable
echo.
echo [*] Building CryptoVeil Desktop Application binary (.exe)...
pyinstaller --noconfirm --onedir --windowed ^
  --name "CryptoVeil" ^
  --add-data "dashboard;dashboard" ^
  --add-data "extension;extension" ^
  --add-data "process_rules.json;." ^
  --hidden-import "uvicorn" ^
  --hidden-import "uvicorn.logging" ^
  --hidden-import "uvicorn.loops" ^
  --hidden-import "uvicorn.loops.auto" ^
  --hidden-import "uvicorn.loops.asyncio" ^
  --hidden-import "uvicorn.protocols" ^
  --hidden-import "uvicorn.protocols.http" ^
  --hidden-import "uvicorn.protocols.http.auto" ^
  --hidden-import "uvicorn.protocols.http.h11_impl" ^
  --hidden-import "uvicorn.protocols.websockets" ^
  --hidden-import "uvicorn.protocols.websockets.auto" ^
  --hidden-import "uvicorn.protocols.websockets.wsproto_impl" ^
  --hidden-import "uvicorn.protocols.websockets.websockets_impl" ^
  --hidden-import "fastapi" ^
  --hidden-import "starlette" ^
  --hidden-import "webview" ^
  --hidden-import "webview.platforms" ^
  --hidden-import "webview.platforms.winforms" ^
  --hidden-import "webview.platforms.edgechromium" ^
  --hidden-import "agent" ^
  --hidden-import "agent.server.main" ^
  --hidden-import "agent.server.routes" ^
  --hidden-import "agent.server.ws_manager" ^
  --hidden-import "agent.sensors.browser_profiles" ^
  --hidden-import "agent.bus.events" ^
  --hidden-import "agent.bus.event_bus" ^
  --hidden-import "agent.engines.mitre_engine" ^
  --hidden-import "agent.engines.network_engine" ^
  --hidden-import "agent.forensics.audit_logger" ^
  --hidden-import "agent.forensics.merkle_tree" ^
  --hidden-import "agent.forensics.off_host_store" ^
  --hidden-import "agent.reports.scheduler" ^
  --hidden-import "agent.reports.store" ^
  --hidden-import "agent.sensors.clipboard_watcher" ^
  --hidden-import "agent.sensors.entropy_watcher" ^
  --hidden-import "agent.sensors.process_watcher" ^
  desktop_app.py

if %errorlevel% equ 0 (
    echo [*] Copying static assets next to executable for seamless standalone loading...
    xcopy /E /I /Y "dashboard" "dist\CryptoVeil\dashboard" >nul 2>nul
    xcopy /E /I /Y "extension" "dist\CryptoVeil\extension" >nul 2>nul
    copy /Y "process_rules.json" "dist\CryptoVeil\process_rules.json" >nul 2>nul
    echo.
    echo ======================================================================
    echo  [✓] Build Complete! Standalone app located in: dist\CryptoVeil\
    echo  [*] You can run dist\CryptoVeil\CryptoVeil.exe directly on any PC!
    echo ======================================================================
) else (
    echo.
    echo [ERROR] Build failed! Check PyInstaller output above.
)
