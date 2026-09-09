import os
import sys
import subprocess

def create_shortcuts():
    target_dir = os.path.abspath(os.path.dirname(__file__))
    ico_path = os.path.join(target_dir, "cryptoveil.ico")
    vbs_launcher = os.path.join(target_dir, "Launch_CryptoVeil.vbs")
    py_app = os.path.join(target_dir, "desktop_app.py")

    ps_script = f"""
    $ws = New-Object -ComObject WScript.Shell
    $desktop = [Environment]::GetFolderPath('Desktop')
    $programs = [Environment]::GetFolderPath('Programs')

    $targets = @(
        (Join-Path $desktop 'CryptoVeil.lnk'),
        (Join-Path $programs 'CryptoVeil.lnk')
    )

    foreach ($scPath in $targets) {{
        $sc = $ws.CreateShortcut($scPath)
        $sc.TargetPath = "wscript.exe"
        $sc.Arguments = '"{vbs_launcher}"'
        $sc.WorkingDirectory = "{target_dir}"
        $sc.IconLocation = "{ico_path},0"
        $sc.Description = "CryptoVeil v2 - Real-Time Security Operations Desktop Application"
        $sc.Save()
        Write-Host "[OK] Created shortcut at: $scPath"
    }}
    """

    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    print("[OK] CryptoVeil Desktop Application shortcuts configured with native icon.")

if __name__ == "__main__":
    create_shortcuts()
