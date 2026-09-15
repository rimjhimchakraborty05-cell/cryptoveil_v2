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

import uvicorn

log = logging.getLogger("cryptoveil.desktop")


def is_server_healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
            data = json.load(response)
            return (
                isinstance(data, dict)
                and data.get("service") == "cryptoveil-agent"
                and data.get("version") == "2.1.0"
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
    main()
