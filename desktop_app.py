"""
desktop_app.py — CryptoVeil v2 Native Desktop Application.

Runs the CryptoVeil cybersecurity and forensics suite inside a native Windows/macOS/Linux
desktop application window using pywebview (Edge WebView2 on Windows) with full native
window controls and zero browser URL bars.
"""
from __future__ import annotations

import asyncio
import multiprocessing
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

# ── PyInstaller Windows Multiprocessing Support ───────────────────────────
multiprocessing.freeze_support()

# ── Ensure Project Root is in sys.path ───────────────────────────────────
PROJECT_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ── Force UTF-8 on Windows console ───────────────────────────────────────
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import uvicorn
from agent.server.main import app

PORT = int(os.environ.get("CRYPTOVEIL_PORT", "8765"))
HOST = os.environ.get("CRYPTOVEIL_HOST", "127.0.0.1")


def get_log_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = PROJECT_ROOT
    return os.path.join(base, "desktop_app.log")


def log_msg(msg: str):
    try:
        with open(get_log_path(), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def is_server_healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


import subprocess

def start_backend():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        config = uvicorn.Config(
            app=app,
            host="127.0.0.1" if HOST in ("127.0.0.1", "localhost") else "0.0.0.0",
            port=PORT,
            reload=False,
            log_level="warning",
            log_config=None,
            loop="asyncio",
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        loop.run_until_complete(server.serve())
    except Exception as e:
        import traceback
        log_msg(f"Background backend error: {e}\n{traceback.format_exc()}")


def wait_for_server(port: int, timeout: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if is_server_healthy(port):
            return True
        time.sleep(0.2)
    return False


def main():
    log_msg("=== CryptoVeil Desktop App Starting ===")
    backend_proc = None

    # If backend not responding, start backend server
    if not is_server_healthy(PORT):
        log_msg(f"Initializing Core Security Engine on port {PORT}...")
        if getattr(sys, "frozen", False):
            server_thread = threading.Thread(target=start_backend, daemon=True)
            server_thread.start()
        else:
            run_py = os.path.join(PROJECT_ROOT, "run.py")
            flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
            try:
                backend_executable = sys.executable.replace("pythonw.exe", "python.exe")
                backend_proc = subprocess.Popen(
                    [backend_executable, run_py, "--server"],
                    cwd=PROJECT_ROOT,
                    creationflags=flags,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                log_msg(f"Backend process spawned (PID: {backend_proc.pid}).")
            except Exception as e:
                log_msg(f"Failed to spawn backend subprocess: {e}. Falling back to thread.")
                server_thread = threading.Thread(target=start_backend, daemon=True)
                server_thread.start()
        
        log_msg(f"Waiting for backend health check on port {PORT}...")
        if not wait_for_server(PORT, timeout=15.0):
            log_msg(f"[ERROR] Server failed to become healthy on port {PORT} within timeout.")
            if not is_port_in_use(PORT):
                log_msg("[FATAL] Port 8765 is not listening.")
    else:
        log_msg(f"Connected to active Core Engine on port {PORT}.")

    app_url = f"http://127.0.0.1:{PORT}/dashboard/index.html"
    log_msg(f"Opening GUI pointing to {app_url}...")

    # Open native pywebview window
    try:
        import webview
        log_msg("Creating pywebview native desktop window...")
        window = webview.create_window(
            title="CryptoVeil — Security Operations Desktop Application",
            url=app_url,
            width=1360,
            height=880,
            min_size=(1024, 680),
            background_color="#050811",
            text_select=True,
        )
        webview.start(debug=False)
        log_msg("Desktop application window closed normally.")
    except Exception as e:
        log_msg(f"Native window GUI error ({e}). Falling back to default browser...")
        webbrowser.open(app_url)
    finally:
        if backend_proc is not None:
            try:
                log_msg("Terminating backend process on desktop app exit...")
                backend_proc.terminate()
            except Exception:
                pass
        log_msg("CryptoVeil exited cleanly.")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
