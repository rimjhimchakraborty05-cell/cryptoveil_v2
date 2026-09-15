"""Create Windows shortcuts without interpolating filesystem paths into code."""

import os
import subprocess
from pathlib import Path


def create_shortcuts():
    if os.name != "nt":
        raise SystemExit("Desktop shortcut installation is available on Windows")
    environment = os.environ.copy()
    environment["CV_SHORTCUT_ROOT"] = str(Path(__file__).resolve().parent)
    script = """
$ErrorActionPreference = 'Stop'
$root = $env:CV_SHORTCUT_ROOT
$ws = New-Object -ComObject WScript.Shell
foreach ($folder in @('Desktop', 'Programs')) {
    $target = Join-Path ([Environment]::GetFolderPath($folder)) 'CryptoVeil.lnk'
    $shortcut = $ws.CreateShortcut($target)
    $shortcut.TargetPath = 'wscript.exe'
    $shortcut.Arguments = '"' + (Join-Path $root 'Launch_CryptoVeil.vbs') + '"'
    $shortcut.WorkingDirectory = $root
    $shortcut.IconLocation = (Join-Path $root 'cryptoveil.ico') + ',0'
    $shortcut.Description = 'CryptoVeil - Security and Evidence'
    $shortcut.Save()
}
"""
    subprocess.run(["powershell", "-NoProfile", "-Command", script], env=environment, check=True)
    print("CryptoVeil shortcuts created.")


if __name__ == "__main__":
    create_shortcuts()
