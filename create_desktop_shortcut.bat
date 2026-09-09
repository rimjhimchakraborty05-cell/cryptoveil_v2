@echo off
setlocal

echo ======================================================================
echo          Creating CryptoVeil Desktop Application Shortcut
echo ======================================================================
echo.

python setup_desktop_shortcuts.py

if %errorlevel% neq 0 (
    echo [!] Falling back to PowerShell shortcut generator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$ws = New-Object -ComObject WScript.Shell; " ^
      "$desktop = [Environment]::GetFolderPath('Desktop'); " ^
      "$shortcutPath = Join-Path $desktop 'CryptoVeil.lnk'; " ^
      "$shortcut = $ws.CreateShortcut($shortcutPath); " ^
      "$shortcut.TargetPath = 'wscript.exe'; " ^
      "$shortcut.Arguments = '\"%~dp0Launch_CryptoVeil.vbs\"'; " ^
      "$shortcut.WorkingDirectory = '%~dp0'; " ^
      "$shortcut.IconLocation = '%~dp0cryptoveil.ico,0'; " ^
      "$shortcut.Description = 'CryptoVeil v2 — Real-Time Security Operations Desktop Application'; " ^
      "$shortcut.Save(); " ^
      "Write-Host '[✓] Shortcut created on Desktop: ' $shortcutPath -ForegroundColor Green"
)

echo.
echo [✓] Desktop application shortcut created with modern icon!
echo.
