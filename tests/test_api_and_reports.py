import asyncio
import io
import json
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.bus.event_bus import EventBroker
from agent.bus.events import BaseEvent
from agent.forensics.audit_logger import AuditLogger, IntegrityError
from agent.forensics.evidence_archive import EvidenceArchive
from agent.reports.export import safe_cell
from agent.reports.scheduler import ReportScheduler
from agent.reports.store import ReportStore
from agent.server.main import Settings, create_app

EXTENSION = "chrome-extension://" + "a" * 32


@pytest.fixture
def client(tmp_path):
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
        yield client


def dashboard(client):
    session = client.get("/api/session").json()
    client.headers["X-CryptoVeil-CSRF"] = session["csrf_token"]


def pair(client):
    dashboard(client)
    code = client.post("/api/pairing/code", json={}).json()["code"]
    result = client.post(
        "/api/pairing/complete",
        json={"code": code, "name": "Test browser"},
        headers={"Origin": EXTENSION},
    )
    assert result.status_code == 200
    token = result.json()["token"]
    return {"Authorization": f"Bearer {token}", "Origin": EXTENSION}


def telemetry(**changes):
    return {
        "event_id": str(uuid.uuid4()),
        "type": "site_visit",
        "hostname": "example.test",
        "score": 100,
        "collected_at_ms": int(time.time() * 1000),
        **changes,
    }


def test_auth_origin_and_csrf_boundaries(client):
    assert client.get("/api/status").status_code == 401
    assert client.post("/api/browser/telemetry", json=telemetry()).status_code == 401
    assert (
        client.get("/api/session", headers={"Origin": "https://hostile.example"}).status_code == 403
    )
    assert client.get("/api/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/health", headers={"Host": "rebind.example"}).status_code == 400
    dashboard(client)
    assert (
        client.post(
            "/api/pairing/code", json={}, headers={"X-CryptoVeil-CSRF": "wrong"}
        ).status_code
        == 403
    )
    assert client.post("/api/forensics/simulate_tamper/0", json={}).status_code == 404
    assert client.post("/api/simulations/run/sim_all", json={}).status_code == 404
    assert client.get("/dashboard/").headers["x-frame-options"] == "DENY"
    assert (
        client.options(
            "/api/browser/telemetry",
            headers={"Origin": EXTENSION, "Access-Control-Request-Method": "POST"},
        ).status_code
        == 200
    )
    assert client.post("/api/pairing/complete", json={"code": "00000000"}).status_code == 403


def test_pairing_code_is_one_use_and_limited(client):
    dashboard(client)
    code = client.post("/api/pairing/code", json={}).json()["code"]
    payload = {"code": code, "name": "Chrome"}
    assert (
        client.post(
            "/api/pairing/complete", json=payload, headers={"Origin": EXTENSION}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/pairing/complete", json=payload, headers={"Origin": EXTENSION}
        ).status_code
        == 401
    )
    code = client.post("/api/pairing/code", json={}).json()["code"]
    wrong = "00000000" if code != "00000000" else "11111111"
    for _ in range(5):
        assert (
            client.post(
                "/api/pairing/complete", json={"code": wrong}, headers={"Origin": EXTENSION}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/pairing/complete", json={"code": code}, headers={"Origin": EXTENSION}
        ).status_code
        == 401
    )


def test_ack_means_persisted_and_retry_is_idempotent(client):
    headers = pair(client)
    payload = telemetry(type="site_warning", score=25, reasons=["Check spelling"])
    first = client.post("/api/browser/telemetry", json=payload, headers=headers)
    assert first.status_code == 200
    receipt = first.json()
    audit = client.app.state.audit_logger
    assert audit.archive.retrieve_event(receipt["seq"])["hash"] == receipt["hash"]
    assert json.loads(audit._log_path.read_text().splitlines()[0])["event"]["severity"] == "high"
    second = client.post("/api/browser/telemetry", json=payload, headers=headers)
    assert second.json()["duplicate"] and second.json()["seq"] == receipt["seq"]
    assert audit.stats()["total_events"] == 1
    assert (
        client.post(
            "/api/browser/telemetry", json={**payload, "score": 50}, headers=headers
        ).status_code
        == 409
    )
    assert client.get("/api/events?limit=-1").status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"score": 200},
        {"score": True},
        {"type": "fake_block"},
        {"url": "https://example.test/?password=secret"},
        {"password": "secret"},
        {"hostname": "https://example.test/path"},
        {"reasons": ["a" * 251]},
    ],
)
def test_bad_or_sensitive_telemetry_is_rejected(client, change):
    assert (
        client.post(
            "/api/browser/telemetry", json=telemetry(**change), headers=pair(client)
        ).status_code
        == 422
    )
    assert client.app.state.audit_logger.stats()["total_events"] == 0


def test_revocation_and_origin_binding(client):
    headers = pair(client)
    other = {**headers, "Origin": "chrome-extension://" + "b" * 32}
    assert client.post("/api/browser/telemetry", json=telemetry(), headers=other).status_code == 401
    client_id = client.get("/api/status").json()["clients"][0]["id"]
    assert client.post("/api/pairing/revoke/" + client_id, json={}).status_code == 200
    assert (
        client.post("/api/browser/telemetry", json=telemetry(), headers=headers).status_code == 401
    )


def test_tamper_detected_and_new_ingest_is_not_acknowledged(client):
    headers = pair(client)
    assert (
        client.post("/api/browser/telemetry", json=telemetry(), headers=headers).status_code == 200
    )
    audit = client.app.state.audit_logger
    audit._log_path.unlink()
    result = client.post("/api/forensics/verify", json={}).json()
    assert not result["verified"] and result["expected_events"] == 1
    assert (
        client.post("/api/browser/telemetry", json=telemetry(), headers=headers).status_code == 503
    )
    assert client.get("/api/forensics/proof/0").status_code == 409


def test_report_exports_are_saved_signed_and_tamper_checked(client):
    headers = pair(client)
    client.post("/api/browser/telemetry", json=telemetry(), headers=headers)
    generated = client.post("/api/reports/generate", json={})
    assert generated.status_code == 200
    date = generated.json()["date"]
    version = generated.json()["version"]
    for fmt in ("pdf", "csv", "json", "zip"):
        response = client.get(f"/api/reports/{date}/download?format={fmt}")
        assert response.status_code == 200
        if fmt == "pdf":
            assert response.content.startswith(b"%PDF")
        if fmt == "zip":
            with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
                assert set(bundle.namelist()) == {
                    "manifest.json",
                    "report.pdf",
                    "report.csv",
                    "report.json",
                    "evidence.jsonl",
                    "checkpoints.json",
                }
                manifest = json.loads(bundle.read("manifest.json"))
                assert client.app.state.audit_logger.verify_signature(
                    manifest, client.app.state.audit_logger.public_key
                )
    proof = client.get("/api/forensics/proof/0").json()
    assert client.post("/api/forensics/verify_proof", json=proof).json()["valid"]
    store = client.app.state.report_store
    (store.directory / date / version / "report.pdf").write_bytes(b"%PDF altered")
    assert not client.get(f"/api/reports/{date}/verify").json()["verified"]
    assert client.get(f"/api/reports/{date}/download?format=pdf").status_code == 409
    assert client.post("/api/reports/generate", json={}).status_code == 409


def test_report_bundle_rejects_unexpected_files(client):
    pair(client)
    generated = client.post("/api/reports/generate", json={}).json()
    bundle = client.app.state.report_store.directory / generated["date"] / generated["version"]
    (bundle / "unexpected.txt").write_text("not part of the signed bundle")
    result = client.get(f"/api/reports/{generated['date']}/verify").json()
    assert not result["verified"] and any("Unexpected file" in issue for issue in result["issues"])


@pytest.mark.parametrize("payload", [b"null", b"[]", b'"broken"', b'{"x":1,"x":2}'])
def test_malformed_report_manifest_fails_without_crashing(client, payload):
    pair(client)
    generated = client.post("/api/reports/generate", json={}).json()
    store = client.app.state.report_store
    (
        store.audit.archive.reports_dir / generated["date"] / f"{generated['version']}.json"
    ).write_bytes(payload)
    response = client.get(f"/api/reports/{generated['date']}/verify")
    assert response.status_code == 200 and not response.json()["verified"]


def test_download_serves_only_the_bytes_it_verified(client, monkeypatch):
    pair(client)
    generated = client.post("/api/reports/generate", json={}).json()
    store = client.app.state.report_store
    target = store.directory / generated["date"] / generated["version"] / "report.csv"
    original = target.read_bytes()
    read_bytes = Path.read_bytes

    def swap_after_read(path):
        content = read_bytes(path)
        if path == target:
            path.write_bytes(b"changed after verification")
        return content

    monkeypatch.setattr(Path, "read_bytes", swap_after_read)
    response = client.get(f"/api/reports/{generated['date']}/download?format=csv")
    assert response.status_code == 200 and response.content == original
    assert not store.verify(generated["date"])["verified"]


def test_csv_preserves_record_zero_and_neutralises_formulas():
    assert safe_cell(0) == "0"
    assert safe_cell("=1+1") == "'=1+1"
    assert safe_cell("@SUM(1)") == "'@SUM(1)"


def test_reports_keep_versions_and_detect_deleted_snapshot(client):
    pair(client)
    first = client.post("/api/reports/generate", json={}).json()
    second = client.post("/api/reports/generate", json={}).json()
    store = client.app.state.report_store
    assert first["version"] != second["version"]
    assert (store.directory / first["date"] / first["version"] / "report.pdf").exists()
    import shutil

    shutil.rmtree(store.directory / second["date"] / second["version"])
    assert not store.verify(second["date"])["verified"]


def test_safe_demo_does_not_change_live_evidence(client):
    headers = pair(client)
    client.post("/api/browser/telemetry", json=telemetry(), headers=headers)
    audit = client.app.state.audit_logger
    before = audit._log_path.read_bytes()
    demo = client.post("/api/forensics/demo", json={}).json()
    assert demo["isolated"] and [c["verified"] for c in demo["checks"]] == [
        True,
        False,
        False,
        False,
    ]
    assert audit._log_path.read_bytes() == before


def test_catch_up_includes_older_days_and_refreshes_partial_report(tmp_path):
    audit = AuditLogger(EventBroker(), tmp_path / "data", EvidenceArchive(tmp_path / "archive"))
    now = datetime.now(UTC)
    older = now - timedelta(days=10)
    audit.record(
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": older.timestamp(),
            "topic": "browser.telemetry",
            "event_kind": "site_visit",
            "hostname": "old.test",
        }
    )
    store = ReportStore(tmp_path / "reports", audit)
    scheduler = ReportScheduler(audit, store, "UTC")
    scheduler.catch_up()
    assert store.exists(older.strftime("%Y-%m-%d")) and store.exists(now.strftime("%Y-%m-%d"))
    report = store.get(older.strftime("%Y-%m-%d"))
    assert len(report["evidence"]) == 1 and report["forensic_integrity"]["verified"]


def test_audit_failure_propagates_instead_of_acknowledging():
    async def scenario():
        broker = EventBroker()

        async def failing(event):
            raise IntegrityError("disk full")

        broker.subscribe("*", failing, durable=True)
        with pytest.raises(IntegrityError):
            await broker.publish(BaseEvent())

    asyncio.run(scenario())
