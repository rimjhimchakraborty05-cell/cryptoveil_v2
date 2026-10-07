from fastapi.testclient import TestClient

from agent.server.main import Settings, create_app


def dashboard(client):
    session = client.get("/api/session").json()
    client.headers["X-CryptoVeil-CSRF"] = session["csrf_token"]


def test_real_sensor_tests_refuse_to_fake_results_when_sensors_are_disabled(tmp_path):
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path / "data",
                archive_dir=tmp_path / "archive",
                sensors_enabled=False,
                reports_enabled=False,
                testing=True,
                report_timezone="UTC",
            )
        )
    ) as client:
        dashboard(client)
        response = client.post("/api/sensor-tests/process_start", json={})
        assert response.status_code == 409
        assert "ProcessWatcher is not active" in response.json()["detail"]


def test_real_sensor_test_endpoint_returns_measured_evidence_result(tmp_path):
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path / "data",
                archive_dir=tmp_path / "archive",
                sensors_enabled=False,
                reports_enabled=False,
                testing=True,
                report_timezone="UTC",
            )
        )
    ) as client:
        dashboard(client)

        class FakeRunner:
            async def run(self, test_id):
                assert test_id == "process_start"
                return {
                    "mode": "real_sensor_test",
                    "name": "Process sensor",
                    "passed": True,
                    "expected_detection": "sensor.process.spawned",
                    "actual_detection": "sensor.process.spawned",
                    "latency_ms": 123,
                    "evidence_id": "11111111-1111-4111-8111-111111111111",
                    "seq": 7,
                    "detail": "Detected by the real pipeline.",
                }

        client.app.state.sensor_tests = FakeRunner()
        result = client.post("/api/sensor-tests/process_start", json={})
        assert result.status_code == 200
        body = result.json()
        assert body["mode"] == "real_sensor_test"
        assert body["passed"]
        assert body["actual_detection"] == "sensor.process.spawned"
        assert body["seq"] == 7


def test_isolated_simulation_never_changes_live_evidence(tmp_path):
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path / "data",
                archive_dir=tmp_path / "archive",
                sensors_enabled=False,
                reports_enabled=False,
                testing=True,
                report_timezone="UTC",
            )
        )
    ) as client:
        dashboard(client)
        audit = client.app.state.audit_logger
        before = audit.stats()["total_events"]
        response = client.post("/api/simulations/integrity", json={})
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "isolated_demo"
        assert body["safe"] is True
        assert body["result"]["isolated"] is True
        assert [check["verified"] for check in body["result"]["checks"]] == [
            True,
            False,
            False,
            False,
        ]
        assert audit.stats()["total_events"] == before
