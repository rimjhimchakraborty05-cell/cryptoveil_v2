"""Exercise streaming through the real ASGI server and authentication middleware."""

import json
import socket
import threading
import time
import uuid

import httpx
import uvicorn

from agent.server.main import Settings, create_app


def test_live_http_stream_notifies_after_a_browser_record_is_saved(tmp_path):
    app = create_app(
        Settings(
            data_dir=tmp_path / "data",
            archive_dir=tmp_path / "archive",
            sensors_enabled=False,
            reports_enabled=False,
            testing=True,
        )
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(32)
        port = listener.getsockname()[1]
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False
            ) as client:
                token = client.get("/api/session").json()["csrf_token"]
                code = client.post(
                    "/api/pairing/code", json={}, headers={"X-CryptoVeil-CSRF": token}
                ).json()["code"]
                origin = "chrome-extension://" + "a" * 32
                pairing = client.post(
                    "/api/pairing/complete", json={"code": code}, headers={"Origin": origin}
                ).json()
                with client.stream("GET", "/api/live") as response:
                    assert response.status_code == 200
                    assert response.headers["content-type"].startswith("text/event-stream")
                    lines = response.iter_lines()

                    def read_change():
                        for line in lines:
                            if line.startswith("data: "):
                                return json.loads(line[6:])
                        raise AssertionError("Stream ended without a notification")

                    initial = read_change()
                    saved = client.post(
                        "/api/browser/telemetry",
                        headers={"Origin": origin, "Authorization": f"Bearer {pairing['token']}"},
                        json={
                            "event_id": str(uuid.uuid4()),
                            "type": "site_visit",
                            "hostname": "example.test",
                            "collected_at_ms": int(time.time() * 1000),
                        },
                    )
                    assert saved.json()["received"]
                    assert read_change()["revision"] > initial["revision"]
                    assert (
                        client.get("/api/events").json()["events"][0]["seq"] == saved.json()["seq"]
                    )
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "Live connection prevented clean server shutdown"
