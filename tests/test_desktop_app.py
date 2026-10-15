import io
import json

import desktop_app
from agent.server import main as server_main
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


def test_frozen_runtime_uses_localappdata_for_persistent_data(monkeypatch, tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    executable = install_dir / "CryptoVeil.exe"
    executable.write_bytes(b"placeholder")
    localappdata = tmp_path / "LocalAppData"

    monkeypatch.setattr(server_main.sys, "frozen", True, raising=False)
    monkeypatch.setattr(server_main.sys, "executable", str(executable))
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))

    expected = localappdata / "CryptoVeil" / "data"
    assert server_main.default_data_dir() == expected
    assert "_MEIPASS" not in str(server_main.default_data_dir())


def test_startup_failure_message_preserves_evidence_instructions(tmp_path):
    message = desktop_app.startup_error_message(
        RuntimeError("Port 8765 is already in use"), tmp_path / "data"
    )
    assert "Port 8765 is already in use" in message
    assert "desktop_app.log" in message
    assert "not automatically reset" in message


def test_startup_failure_fallback_is_safe_without_data_path():
    message = desktop_app.startup_error_message(ValueError("Invalid configuration"))
    assert "Invalid configuration" in message
    assert "Diagnostic log" not in message
