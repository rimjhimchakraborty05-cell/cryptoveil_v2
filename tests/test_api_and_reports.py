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
from agent.bus.events import BaseEvent, MitreAlertEvent
from agent.forensics.audit_logger import AuditLogger, IntegrityError
from agent.forensics.evidence_archive import EvidenceArchive
from agent.reports.export import safe_cell
from agent.reports.scheduler import ReportScheduler
from agent.reports.store import ReportStore
from agent.server.main import Settings, create_app
from agent.server.security import PairingManager

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
    assert client.get("/api/live").status_code == 401
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


def test_investigation_api_returns_real_findings_and_mitre_summary(client):
    dashboard(client)
    alert = MitreAlertEvent(
        mitre_id="T1059",
        mitre_name="Command and Scripting Interpreter",
        description="Office launched a shell",
        pid=77,
        process_name="powershell.exe",
        parent_name="winword.exe",
        cmdline="powershell.exe -NoProfile",
        rule_id="office-shell",
    )
    client.app.state.audit_logger.record(alert.model_dump(mode="json"))

    response = client.get("/api/investigation")
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["findings"] == 1
    assert data["summary"]["mitre_alerts"] == 1
    assert data["mitre_techniques"] == [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "count": 1,
        }
    ]
    assert data["recent_findings"][0]["event"]["rule_id"] == "office-shell"
    assert "process_graph" in data


def test_runtime_readiness_reports_persistent_assets_without_exposing_secrets(client):
    dashboard(client)
    response = client.get("/api/runtime/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["version"]
    assert data["loopback_only"] is True
    assert data["checks"]["data_directory"] is True
    assert data["checks"]["archive_directory"] is True
    assert data["checks"]["rules_file"] is True
    assert data["checks"]["dashboard_assets"] is True
    assert data["checks"]["extension_assets"] is True
    assert "csrf_token" not in data
    assert "session_token" not in data
    assert "private_key" not in data


def test_browser_account_context_is_saved_per_event_and_survives_identity_changes(client):
    headers = pair(client)
    profile = {
        "browser_family": "Edge",
        "account_email": "owner@example.test",
        "account_source": "browser_profile",
    }
    body = telemetry(profile_context=profile)
    first = client.post("/api/browser/telemetry", json=body, headers=headers)
    assert first.status_code == 200
    changed = {
        **profile,
        "account_email": "different@example.test",
        "account_source": "user_provided",
    }
    assert (
        client.post(
            "/api/browser/heartbeat", json={"profile_context": changed}, headers=headers
        ).status_code
        == 200
    )
    retry = client.post("/api/browser/telemetry", json=body, headers=headers)
    assert retry.json()["duplicate"]
    assert retry.json()["seq"] == first.json()["seq"]
    event = client.get("/api/events").json()["events"][0]["event"]
    assert event["user_email"] == "owner@example.test"
    assert client.get("/api/status").json()["clients"][0]["profile_context"] == changed


def test_dom_signals_are_validated_and_can_generate_linked_evidence(client):
    headers, page_id = pair(client), str(uuid.uuid4())
    for kind in ("shadow_ai_dom", "sensitive_field_used"):
        result = client.post(
            "/api/browser/telemetry", json=telemetry(type=kind, page_id=page_id), headers=headers
        )
        assert result.status_code == 200
    event = client.get("/api/events").json()["events"][0]["event"]
    assert event["topic"] == "engine.correlation.finding"
    assert len(event["evidence_ids"]) == 2
    for event_id in event["evidence_ids"]:
        related = client.get(f"/api/events/id/{event_id}")
        assert related.status_code == 200
        assert related.json()["event"]["event_id"] == event_id
    assert (
        client.post(
            "/api/browser/telemetry",
            json=telemetry(dom_signal="password_contents"),
            headers=headers,
        ).status_code
        == 422
    )


def test_profile_email_requires_an_explicit_matching_source(client):
    headers = pair(client)
    for context in (
        {"account_email": "person@example.test"},
        {"account_source": "browser_profile"},
        {"account_email": "invalid-email", "account_source": "user_provided"},
    ):
        assert (
            client.post(
                "/api/browser/heartbeat", json={"profile_context": context}, headers=headers
            ).status_code
            == 422
        )


def test_paired_browser_token_survives_application_restart(tmp_path):
    first = PairingManager(tmp_path)
    code = first.new_code()["code"]
    result = first.complete(code, "Edge profile", EXTENSION)
    token = result["token"]
    client_id = result["client_id"]

    restarted = PairingManager(tmp_path)
    client = restarted.authenticate(token, EXTENSION)

    assert client is not None
    assert client["id"] == client_id
    assert client["name"] == "Edge profile"


def test_persisted_pairing_stays_bound_to_original_extension_origin(tmp_path):
    first = PairingManager(tmp_path)
    code = first.new_code()["code"]
    token = first.complete(code, "Chrome profile", EXTENSION)["token"]

    restarted = PairingManager(tmp_path)
    assert restarted.authenticate(token, EXTENSION) is not None
    assert restarted.authenticate(token, "chrome-extension://" + "b" * 32) is None


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


def test_date_wise_evidence_api_lists_verifies_and_downloads(client):
    headers = pair(client)
    client.post("/api/browser/telemetry", json=telemetry(), headers=headers)
    generated = client.post("/api/reports/generate", json={})
    assert generated.status_code == 200
    date = generated.json()["date"]

    listed = client.get("/api/evidence/daily")
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["days"] and payload["days"][0]["date"] == date
    assert "host_separation_verified" in payload["archive"]

    verified = client.get(f"/api/evidence/daily/{date}/verify")
    assert verified.status_code == 200
    assert verified.json()["verified"]
    assert verified.json()["daily_seal_verified"] is True
    assert verified.json()["daily_link_verified"] is True

    verified_all = client.get("/api/evidence/daily/verify-all")
    assert verified_all.status_code == 200
    assert verified_all.json()["verified"] is True
    assert verified_all.json()["dates_checked"] >= 1

    evidence_zip = client.get(f"/api/evidence/daily/{date}/download?format=zip")
    assert evidence_zip.status_code == 200
    assert evidence_zip.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(evidence_zip.content)) as bundle:
        assert "evidence.jsonl" in bundle.namelist()
        assert "checkpoints.json" in bundle.namelist()
        assert "manifest.json" in bundle.namelist()
        assert "daily_seal.json" in bundle.namelist()
        assert "daily_summary.json" in bundle.namelist()

    evidence_json = client.get(f"/api/evidence/daily/{date}/download?format=json")
    assert evidence_json.status_code == 200
    assert evidence_json.headers["content-type"].startswith("application/json")

    events = client.get(f"/api/evidence/daily/{date}/download?format=events")
    assert events.status_code == 200
    assert events.headers["content-type"].startswith("application/x-ndjson")
    assert b'"seq":0' in events.content

    metadata = client.get(f"/api/evidence/daily/{date}/download?format=metadata")
    assert metadata.status_code == 200
    metadata_body = metadata.json()
    assert metadata_body["verification"]["verified"] is True
    assert metadata_body["daily_seal"]["kind"] == "daily_evidence_seal"
    assert metadata_body["manifest"]["kind"] == "daily_evidence_bundle"

    pdf = client.get(f"/api/evidence/daily/{date}/download?format=pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")


def test_daily_seals_link_consecutive_days_and_fail_closed_on_tamper(client):
    pair(client)
    audit = client.app.state.audit_logger
    now = datetime.now(UTC)
    yesterday = now - timedelta(days=1)

    audit.record(
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": yesterday.timestamp(),
            "topic": "sensor.process.spawned",
            "severity": "info",
            "source": "endpoint",
            "name": "yesterday-test.exe",
        }
    )
    audit.record(
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.timestamp(),
            "topic": "sensor.process.spawned",
            "severity": "info",
            "source": "endpoint",
            "name": "today-test.exe",
        }
    )

    yesterday_date = yesterday.strftime("%Y-%m-%d")
    today_date = now.strftime("%Y-%m-%d")
    first = client.post(f"/api/reports/generate?date={yesterday_date}", json={})
    second = client.post(f"/api/reports/generate?date={today_date}", json={})
    assert first.status_code == 200 and second.status_code == 200

    store = client.app.state.report_store
    first_path = store.directory / yesterday_date / first.json()["version"] / "daily_seal.json"
    second_path = store.directory / today_date / second.json()["version"] / "daily_seal.json"
    first_seal = json.loads(first_path.read_text())
    second_seal = json.loads(second_path.read_text())

    assert first_seal["kind"] == "daily_evidence_seal"
    assert second_seal["previous_day_root"] == first_seal["daily_merkle_root"]
    assert client.get("/api/evidence/daily/verify-all").json()["verified"] is True

    first_path.write_text(first_path.read_text().replace('"event_count":1', '"event_count":2'))
    assert client.get(f"/api/evidence/daily/{yesterday_date}/verify").json()["verified"] is False
    assert client.get(f"/api/evidence/daily/{today_date}/verify").json()["verified"] is False
    assert client.get("/api/evidence/daily/verify-all").json()["verified"] is False


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
                    "daily_seal.json",
                    "daily_summary.json",
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
