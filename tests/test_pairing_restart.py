from __future__ import annotations

from agent.server.security import PairingManager


ORIGIN = "chrome-extension://" + "a" * 32


def test_paired_browser_token_survives_application_restart(tmp_path):
    first = PairingManager(tmp_path)
    code = first.new_code()["code"]
    result = first.complete(code, "Edge profile", ORIGIN)
    token = result["token"]
    client_id = result["client_id"]

    restarted = PairingManager(tmp_path)
    client = restarted.authenticate(token, ORIGIN)

    assert client is not None
    assert client["id"] == client_id
    assert client["name"] == "Edge profile"


def test_persisted_pairing_stays_bound_to_original_extension_origin(tmp_path):
    first = PairingManager(tmp_path)
    code = first.new_code()["code"]
    token = first.complete(code, "Chrome profile", ORIGIN)["token"]

    restarted = PairingManager(tmp_path)
    assert restarted.authenticate(token, ORIGIN) is not None
    assert restarted.authenticate(token, "chrome-extension://" + "b" * 32) is None
