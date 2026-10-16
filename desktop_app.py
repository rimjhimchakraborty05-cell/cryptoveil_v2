"""Native desktop window with a gracefully stopped, loopback-only backend."""

from __future__ import annotations

import json
import logging
import multiprocessing
import os
import socket
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn

from agent.version import VERSION

log = logging.getLogger("cryptoveil.desktop")


def startup_error_message(exc: Exception, data_dir: str | os.PathLike[str] | None = None) -> str:
    """Plain-language failure report; never touch existing evidence on startup failure."""
    detail = str(exc).strip() or exc.__class__.__name__
    lines = ["CryptoVeil could not start.", "", detail]
    if data_dir:
        lines.extend(
            [
                "",
                f"Diagnostic log: {Path(data_dir) / 'desktop_app.log'}",
                "Existing security evidence was not automatically reset or repaired.",
            ]
        )
    return "\n".join(lines)


def show_startup_error(message: str) -> None:
    log.error("%s", message.replace("\n", " | "))
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(0, message, "CryptoVeil startup problem", 0x10)
            return
        except Exception:
            log.exception("Could not display Windows startup dialog")
    print(message)


def is_server_healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
            data = json.load(response)
            return (
                isinstance(data, dict)
                and data.get("service") == "cryptoveil-agent"
                and data.get("version") == VERSION
            )
    except (OSError, ValueError):
        return False


def main() -> None:
    from agent.server.main import app, default_data_dir

    data_dir = os.environ.get("CRYPTOVEIL_DATA_DIR", str(default_data_dir()))
    os.makedirs(data_dir, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(data_dir, "desktop_app.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    port = int(os.environ.get("CRYPTOVEIL_PORT", "8765"))
    server = None
    thread = None
    if not is_server_healthy(port):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(
                    f"Port {port} is in use by another application or an older CryptoVeil. Close it before starting this version."
                )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                loop="asyncio",
                log_config=None,
                log_level="warning",
            )
        )
        thread = threading.Thread(target=server.run, name="CryptoVeil backend", daemon=False)
        thread.start()
        deadline = time.monotonic() + 30
        while not is_server_healthy(port):
            if not thread.is_alive() or time.monotonic() >= deadline:
                server.should_exit = True
                thread.join(timeout=5)
                raise RuntimeError(
                    f"CryptoVeil could not start. See {data_dir}/desktop_app.log for details."
                )
            time.sleep(0.15)
    app_url = f"http://127.0.0.1:{port}/dashboard/"

    # Packaged smoke mode validates that the frozen application can start its
    # loopback backend and static dashboard without opening a desktop window.
    # It is used only when explicitly enabled by the build pipeline.
    smoke_seconds = float(os.environ.get("CRYPTOVEIL_SMOKE_SECONDS", "0") or 0)
    if smoke_seconds > 0:
        try:
            time.sleep(min(smoke_seconds, 30.0))
            if not is_server_healthy(port):
                raise RuntimeError("CryptoVeil packaged smoke check lost backend health")
            return
        finally:
            if server:
                server.should_exit = True
                if thread:
                    thread.join()

    try:
        try:
            import webview

            webview.settings["ALLOW_DOWNLOADS"] = True
            webview.settings["ALLOW_FILE_URLS"] = False
            webview.create_window(
                "CryptoVeil - Security & Evidence",
                app_url,
                width=1360,
                height=900,
                min_size=(860, 640),
                background_color="#f5f6f3",
                text_select=True,
            )
            webview.start(debug=False)
        except Exception:
            log.exception("Native window unavailable; using the local browser view")
            webbrowser.open(app_url)
            if thread:
                print(
                    f"CryptoVeil is running at {app_url}. Press Ctrl+C to stop after saving reports."
                )
                while thread.is_alive():
                    thread.join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            # Give lifespan shutdown time to drain writes, seal the tail and
            # save the final daily report. Never terminate the writer abruptly.
            server.should_exit = True
            if thread:
                thread.join()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    try:
        main()
    except Exception as exc:
        try:
            from agent.server.main import default_data_dir

            error_dir = os.environ.get("CRYPTOVEIL_DATA_DIR", str(default_data_dir()))
        except Exception:
            error_dir = None
        show_startup_error(startup_error_message(exc, error_dir))
        raise SystemExit(1) from exc
