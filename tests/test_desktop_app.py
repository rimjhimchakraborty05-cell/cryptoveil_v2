import io
import json

import desktop_app
from agent.version import VERSION


def response(version):
    return io.BytesIO(
        json.dumps(
            {
                "status": "ok",
                "service": "cryptoveil-agent",
                "version": version,
            }
        ).encode()
    )


def test_desktop_health_check_accepts_current_shared_version(monkeypatch):
    monkeypatch.setattr(
        desktop_app.urllib.request,
        "urlopen",
        lambda *args, **kwargs: response(VERSION),
    )
    assert desktop_app.is_server_healthy(8765)


def test_desktop_health_check_rejects_stale_backend_version(monkeypatch):
    monkeypatch.setattr(
        desktop_app.urllib.request,
        "urlopen",
        lambda *args, **kwargs: response("0.0.0"),
    )
    assert not desktop_app.is_server_healthy(8765)
