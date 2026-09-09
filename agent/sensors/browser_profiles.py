"""
browser_profiles.py — Multi-browser profile and email account discovery engine.

Scans installed browsers (Google Chrome, Microsoft Edge, Brave, Opera, Chromium)
on Windows, macOS, and Linux to discover user profiles, logged-in email accounts
(Google Accounts, Microsoft Accounts), profile display names, and executable paths.
Provides helpers for 1-click launching with the CryptoVeil extension attached.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional


def _get_browser_roots() -> dict[str, list[Path]]:
    """Returns candidate user data directories for various browsers by OS."""
    system = platform.system()
    roots: dict[str, list[Path]] = {
        "Google Chrome": [],
        "Microsoft Edge": [],
        "Brave": [],
        "Opera": [],
        "Chromium": [],
        "Vivaldi": [],
    }

    if system == "Windows":
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))
        app_data = Path(os.environ.get("APPDATA", ""))

        if local_app.exists():
            roots["Google Chrome"].append(local_app / "Google" / "Chrome" / "User Data")
            roots["Microsoft Edge"].append(local_app / "Microsoft" / "Edge" / "User Data")
            roots["Brave"].append(local_app / "BraveSoftware" / "Brave-Browser" / "User Data")
            roots["Chromium"].append(local_app / "Chromium" / "User Data")
            roots["Vivaldi"].append(local_app / "Vivaldi" / "User Data")
        if app_data.exists():
            roots["Opera"].append(app_data / "Opera Software" / "Opera Stable")
            roots["Opera"].append(app_data / "Opera Software" / "Opera GX Stable")

    elif system == "Darwin":  # macOS
        home = Path.home()
        app_sup = home / "Library" / "Application Support"
        roots["Google Chrome"].append(app_sup / "Google" / "Chrome")
        roots["Microsoft Edge"].append(app_sup / "Microsoft Edge")
        roots["Brave"].append(app_sup / "BraveSoftware" / "Brave-Browser")
        roots["Chromium"].append(app_sup / "Chromium")
        roots["Opera"].append(app_sup / "com.operasoftware.Opera")

    else:  # Linux / Unix
        home = Path.home()
        config = home / ".config"
        roots["Google Chrome"].append(config / "google-chrome")
        roots["Google Chrome"].append(config / "chromium")
        roots["Microsoft Edge"].append(config / "microsoft-edge")
        roots["Brave"].append(config / "BraveSoftware" / "Brave-Browser")
        roots["Opera"].append(config / "opera")

    return roots


def _find_browser_executable(browser_name: str) -> Optional[str]:
    """Finds the absolute path to the browser's executable binary."""
    system = platform.system()

    if system == "Windows":
        prog_files = Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
        prog_files_x86 = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"))
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))

        candidates: dict[str, list[Path]] = {
            "Google Chrome": [
                prog_files / "Google" / "Chrome" / "Application" / "chrome.exe",
                prog_files_x86 / "Google" / "Chrome" / "Application" / "chrome.exe",
                local_app / "Google" / "Chrome" / "Application" / "chrome.exe",
            ],
            "Microsoft Edge": [
                prog_files_x86 / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                prog_files / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                local_app / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            ],
            "Brave": [
                prog_files / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
                prog_files_x86 / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
                local_app / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
            ],
            "Opera": [
                local_app / "Programs" / "Opera" / "opera.exe",
                local_app / "Programs" / "Opera GX" / "opera.exe",
                prog_files / "Opera" / "launcher.exe",
            ],
        }

        for path in candidates.get(browser_name, []):
            if path.exists():
                return str(path)

    # Fallback to PATH search
    bin_names = {
        "Google Chrome": ["chrome", "google-chrome", "google-chrome-stable"],
        "Microsoft Edge": ["msedge", "microsoft-edge"],
        "Brave": ["brave", "brave-browser"],
        "Opera": ["opera"],
        "Chromium": ["chromium", "chromium-browser"],
    }
    for name in bin_names.get(browser_name, []):
        found = shutil.which(name)
        if found:
            return found

    return None


class BrowserProfileScanner:
    """Discovers installed browsers and their profiles & email IDs."""

    @staticmethod
    def get_all_profiles() -> list[dict[str, Any]]:
        """
        Scans host system for all installed browsers and user profiles.
        Returns a list of profile dicts with email IDs and metadata.
        """
        discovered = []
        browser_roots = _get_browser_roots()

        for browser_name, roots in browser_roots.items():
            exe_path = _find_browser_executable(browser_name)

            for root in roots:
                if not root.exists():
                    continue

                local_state_file = root / "Local State"
                info_cache = {}

                if local_state_file.exists():
                    try:
                        data = json.loads(local_state_file.read_text(encoding="utf-8", errors="ignore"))
                        info_cache = data.get("profile", {}).get("info_cache", {})
                    except Exception:
                        pass

                # If info_cache found, parse profiles
                if info_cache:
                    for pdir, pdata in info_cache.items():
                        email = (
                            pdata.get("user_name")
                            or pdata.get("email")
                            or pdata.get("hosted_domain")
                            or ""
                        )
                        display_name = pdata.get("name") or pdir
                        gaia_name = pdata.get("gaia_name") or pdata.get("gaia_given_name") or ""

                        # Try reading profile Preferences if email is missing
                        if not email:
                            pref_file = root / pdir / "Preferences"
                            if pref_file.exists():
                                try:
                                    pref = json.loads(pref_file.read_text(encoding="utf-8", errors="ignore"))
                                    acc_info = pref.get("account_info", [])
                                    if isinstance(acc_info, list) and acc_info:
                                        email = acc_info[0].get("email", "")
                                        if not display_name or display_name == pdir:
                                            display_name = acc_info[0].get("full_name", display_name)
                                    elif isinstance(acc_info, dict):
                                        email = acc_info.get("email", "")
                                except Exception:
                                    pass

                        discovered.append({
                            "browser": browser_name,
                            "profile_dir": pdir,
                            "display_name": display_name,
                            "email": email.strip(),
                            "gaia_name": gaia_name,
                            "user_data_dir": str(root),
                            "executable": exe_path,
                            "installed": exe_path is not None,
                            "id": f"{browser_name.lower().replace(' ', '_')}_{pdir.lower().replace(' ', '_')}",
                        })
                else:
                    # Check for Default directory
                    default_dir = root / "Default"
                    if default_dir.exists():
                        email = ""
                        display_name = "Default Profile"
                        pref_file = default_dir / "Preferences"
                        if pref_file.exists():
                            try:
                                pref = json.loads(pref_file.read_text(encoding="utf-8", errors="ignore"))
                                acc_info = pref.get("account_info", [])
                                if isinstance(acc_info, list) and acc_info:
                                    email = acc_info[0].get("email", "")
                                    display_name = acc_info[0].get("full_name", display_name)
                            except Exception:
                                pass

                        discovered.append({
                            "browser": browser_name,
                            "profile_dir": "Default",
                            "display_name": display_name,
                            "email": email.strip(),
                            "gaia_name": "",
                            "user_data_dir": str(root),
                            "executable": exe_path,
                            "installed": exe_path is not None,
                            "id": f"{browser_name.lower().replace(' ', '_')}_default",
                        })

        return discovered

    @staticmethod
    def launch_with_extension(
        browser_name: str,
        profile_dir: str,
        extension_path: str,
        target_url: str = "http://127.0.0.1:8765/dashboard/index.html",
    ) -> dict[str, Any]:
        """
        Launches the specified browser profile with CryptoVeil extension loaded.
        """
        exe_path = _find_browser_executable(browser_name)
        if not exe_path:
            return {"success": False, "error": f"Executable for {browser_name} not found on system."}

        ext_abs_path = str(Path(extension_path).resolve())
        if not Path(ext_abs_path).exists():
            return {"success": False, "error": f"Extension directory not found at: {ext_abs_path}"}

        args = [
            exe_path,
            f"--profile-directory={profile_dir}",
            f"--load-extension={ext_abs_path}",
            f"--no-first-run",
            target_url,
        ]

        try:
            # Spawn in background detached process
            if sys.platform == "win32":
                subprocess.Popen(
                    args,
                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                    close_fds=True,
                )
            else:
                subprocess.Popen(args, start_new_session=True, close_fds=True)

            return {
                "success": True,
                "browser": browser_name,
                "profile_dir": profile_dir,
                "executable": exe_path,
                "extension_path": ext_abs_path,
                "url": target_url,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


if __name__ == "__main__":
    profiles = BrowserProfileScanner.get_all_profiles()
    print(f"[*] Discovered {len(profiles)} browser profiles on host:")
    for p in profiles:
        print(f"  - [{p['browser']}] {p['display_name']} | Email: {p['email'] or '(None)'} | Profile: {p['profile_dir']}")
