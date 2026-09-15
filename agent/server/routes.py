"""Small authenticated API for collection, evidence review and daily exports."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..bus.events import BrowserTelemetryEvent, EventSeverity
from ..forensics.audit_logger import AuditLogger, IntegrityError
from ..reports.report_generator import describe_event, next_step
from ..reports.store import valid_date

router = APIRouter()


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


@router.get("/api/health")
def health():
    return {"status": "ok", "service": "cryptoveil-agent", "version": "2.2.0"}


@router.get("/api/session")
def session(request: Request):
    manager = request.app.state.pairing
    response = JSONResponse(
        {
            "csrf_token": manager.csrf_token,
            "today": request.app.state.scheduler.today(),
            "timezone": request.app.state.settings.report_timezone,
        }
    )
    response.set_cookie(
        "cv_session", manager.session_token, httponly=True, samesite="strict", path="/"
    )
    return response


@router.post("/api/pairing/code")
async def pairing_code(request: Request):
    return request.app.state.pairing.new_code()


class PairingPayload(StrictPayload):
    code: str = Field(pattern=r"^\d{8}$")
    name: str = Field(default="My browser", min_length=1, max_length=60)


@router.post("/api/pairing/complete")
async def pairing_complete(payload: PairingPayload, request: Request):
    try:
        return request.app.state.pairing.complete(
            payload.code, payload.name, request.headers.get("origin")
        )
    except ValueError as exc:
        raise HTTPException(401, str(exc)) from exc


@router.post("/api/pairing/revoke/{client_id}")
async def revoke_browser(client_id: str, request: Request):
    if not request.app.state.pairing.revoke(client_id):
        raise HTTPException(404, "Paired browser not found")
    request.app.state.live.notify()
    return {"revoked": True}


class ProfileContext(StrictPayload):
    browser_family: Literal["Chrome", "Edge", "Brave", "Opera", "Chromium", "Unknown"] = "Unknown"
    account_email: str | None = Field(default=None, max_length=254)
    account_source: Literal["not_shared", "browser_profile", "user_provided", "unavailable"] = (
        "not_shared"
    )

    @field_validator("account_email")
    @classmethod
    def valid_email_label(cls, value):
        if value is not None and not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", value):
            raise ValueError("Enter a valid email label")
        return value

    @model_validator(mode="after")
    def consistent_source(self):
        shared = self.account_source in ("browser_profile", "user_provided")
        if shared != bool(self.account_email):
            raise ValueError("The account email and its source must agree")
        return self


class HeartbeatPayload(StrictPayload):
    queued_events: int = Field(default=0, ge=0, le=10000)
    dropped_events: int = Field(default=0, ge=0, le=2**31 - 1)
    profile_context: ProfileContext | None = None


@router.post("/api/browser/heartbeat")
async def heartbeat(payload: HeartbeatPayload, request: Request):
    request.app.state.pairing.heartbeat(
        request.state.browser_client["id"],
        payload.queued_events,
        payload.dropped_events,
        payload.profile_context.model_dump() if payload.profile_context else None,
    )
    request.app.state.live.notify()
    return {
        "received": True,
        "collection_paused": bool(request.app.state.audit_logger.collection_error),
    }


class TelemetryPayload(StrictPayload):
    event_id: uuid.UUID
    type: Literal[
        "site_visit",
        "site_warning",
        "shadow_ai_network",
        "shadow_ai_iframe",
        "shadow_ai_dom",
        "sensitive_field_used",
        "masking_activated",
        "masking_deactivated",
        "collection_gap",
    ]
    hostname: str | None = Field(default=None, max_length=253)
    score: int | None = Field(default=None, ge=0, le=100, strict=True)
    reasons: list[str] = Field(default_factory=list, max_length=10)
    ai_domain: str | None = Field(default=None, max_length=253)
    field_type: str | None = Field(default=None, max_length=30)
    collected_at_ms: int = Field(ge=0, le=32_503_680_000_000, strict=True)
    dropped_count: int = Field(default=0, ge=0, le=2**31 - 1)
    page_id: uuid.UUID | None = None
    profile_context: ProfileContext | None = None
    dom_signal: Literal["ai_script", "ai_component"] | None = None

    @field_validator("reasons")
    @classmethod
    def validate_reasons(cls, values):
        if any(len(value) > 250 for value in values):
            raise ValueError("A reason cannot exceed 250 characters")
        return values

    @field_validator("hostname", "ai_domain")
    @classmethod
    def validate_hostname(cls, value):
        if value is None:
            return None
        value = value.rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{0,252}", value):
            raise ValueError("Send the hostname only, without URL paths or credentials")
        return value


@router.post("/api/browser/telemetry")
async def browser_telemetry(payload: TelemetryPayload, request: Request):
    client = request.state.browser_client
    severity = EventSeverity.INFO
    if payload.type == "site_warning":
        severity = (
            EventSeverity.HIGH
            if payload.score is not None and payload.score < 50
            else EventSeverity.MEDIUM
        )
    elif payload.type.startswith("shadow_ai"):
        severity = EventSeverity.LOW
    elif payload.type == "collection_gap":
        severity = EventSeverity.HIGH
    event = BrowserTelemetryEvent(
        event_id=str(uuid.uuid5(uuid.UUID(client["id"]), str(payload.event_id))),
        severity=severity,
        event_kind=payload.type,
        hostname=payload.hostname,
        trust_score=payload.score,
        browser_name=client["name"],
        user_email=payload.profile_context.account_email if payload.profile_context else None,
        detail={
            "client_id": client["id"],
            "client_event_id": str(payload.event_id),
            **payload.model_dump(
                mode="json", exclude={"event_id", "type", "hostname", "score"}, exclude_none=True
            ),
        },
    )
    try:
        receipt = await request.app.state.broker.publish(event)
    except IntegrityError as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if receipt is None:
        raise HTTPException(503, "Durable evidence storage is not available")
    request.app.state.pairing.clients[client["id"]]["last_seen"] = time.time()
    return {
        "received": True,
        "event_id": str(payload.event_id),
        "evidence_id": event.event_id,
        "seq": receipt["seq"],
        "hash": receipt["hash"],
        "duplicate": receipt.get("duplicate", False),
    }


@router.get("/api/live")
async def live_updates(request: Request):
    live = request.app.state.live
    subscription = live.subscribe()
    try:
        queue = await subscription.__aenter__()
    except RuntimeError as exc:
        raise HTTPException(429, str(exc)) from exc

    async def frames():
        try:
            yield "retry: 2000\n\n" + live.frame()
            while not await request.is_disconnected():
                try:
                    await asyncio.wait_for(queue.get(), timeout=15)
                    # Coalesce a burst into one refresh, keeping a slow browser
                    # from creating a backlog or delaying evidence writes.
                    await asyncio.sleep(0.2)
                    yield live.frame()
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await subscription.__aexit__(None, None, None)

    return StreamingResponse(
        frames(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
    )


def event_view(entry: dict) -> dict:
    ev = entry["event"]
    return {
        "seq": entry.get("seq"),
        "hash": entry.get("hash"),
        "timestamp": ev.get("timestamp"),
        "severity": ev.get("severity", "info"),
        "source": ev.get("source", "unknown"),
        "summary": describe_event(ev),
        "hostname": ev.get("hostname") or ev.get("process_name") or ev.get("name", ""),
        "next_step": next_step(ev),
        "event": ev,
    }


@router.get("/api/events/id/{event_id}")
def event_by_id(event_id: uuid.UUID, request: Request):
    try:
        entry = request.app.state.audit_logger.entry_by_id(str(event_id))
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "The related evidence copy is damaged; run verification") from exc
    if entry is None:
        raise HTTPException(404, "Related evidence is missing or was not collected in this ledger")
    return event_view(entry)


@router.get("/api/events")
def events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    severity: Literal["all", "alerts", "info", "low", "medium", "high", "critical"] = "all",
):
    entries = request.app.state.audit_logger.recent_entries(500)
    if severity == "alerts":
        entries = [
            e for e in entries if e["event"].get("severity") in ("medium", "high", "critical")
        ]
    elif severity != "all":
        entries = [e for e in entries if e["event"].get("severity") == severity]
    return {
        "events": [event_view(e) for e in reversed(entries[-limit:])],
        "window": "Latest 500 stored events",
    }


@router.get("/api/status")
def status(request: Request):
    from .main import BASE_DIR

    state = request.app.state
    recent = state.audit_logger.recent_entries(200)
    alerts = [
        event_view(e)
        for e in recent
        if e["event"].get("severity") in ("medium", "high", "critical")
    ]
    sensors = []
    for sensor in state.sensors:
        task = getattr(sensor, "_task", None)
        health = getattr(sensor, "status", "starting")
        if task and task.done() and health not in ("unavailable", "stopped"):
            health = "unavailable"
        sensors.append(
            {
                "name": type(sensor).__name__,
                "status": health,
                "detail": getattr(sensor, "last_error", None),
                "mode": getattr(
                    sensor,
                    "mode",
                    "filesystem_push" if type(sensor).__name__ == "EntropyWatcher" else "sampled",
                ),
            }
        )
    return {
        "uptime_seconds": round(time.time() - state.start_time),
        **state.audit_logger.stats(),
        "integrity": state.audit_logger.last_verification,
        "clients": state.pairing.public_clients(),
        "sensors": sensors,
        "sensors_enabled": state.settings.sensors_enabled,
        "recent_alert_count": len(alerts),
        "recent_alerts": list(reversed(alerts[-5:])),
        "alert_window": "Latest 200 stored events",
        "report_error": state.scheduler.error,
        "today": state.scheduler.today(),
        "timezone": state.settings.report_timezone,
        "storage_path": str(state.settings.data_dir.resolve()),
        "extension_path": str((BASE_DIR / "extension").resolve()),
        "verification_interval_seconds": state.settings.verification_seconds,
        "delivery_errors": state.broker.stats()["dead_letter_count"],
        "live_revision": state.live.revision,
    }


@router.post("/api/forensics/verify")
def verify(request: Request):
    return request.app.state.audit_logger.verify_chain()


@router.get("/api/forensics/verify_chain")
def verify_compatibility(request: Request):
    return request.app.state.audit_logger.verify_chain()


@router.get("/api/forensics/proof/{seq}")
def proof(seq: int, request: Request):
    if seq < 0:
        raise HTTPException(422, "Evidence number must be non-negative")
    try:
        result = request.app.state.audit_logger.get_proof(seq)
    except IntegrityError as exc:
        raise HTTPException(409, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "Evidence record not found")
    return result


class ProofPayload(StrictPayload):
    seq: int = Field(ge=0)
    checkpoint: dict
    leaf_data: str = Field(max_length=64)
    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    audit_path: list[str] = Field(max_length=63)


@router.post("/api/forensics/verify_proof")
def verify_proof(payload: ProofPayload, request: Request):
    return AuditLogger.verify_proof(payload.model_dump(), request.app.state.audit_logger.public_key)


@router.get("/api/forensics/archive/{seq}")
def archived_evidence(seq: int, request: Request):
    if seq < 0:
        raise HTTPException(422, "Evidence number must be non-negative")
    audit = request.app.state.audit_logger
    try:
        record = audit.archive.retrieve_event(seq)
    except (ValueError, OSError) as exc:
        raise HTTPException(409, "Archived record is damaged") from exc
    if record is None:
        raise HTTPException(404, "Archived record not found")
    return {"record": record, "archive": audit.archive.describe()}


@router.post("/api/forensics/demo")
def integrity_demo():
    from ..forensics.demo import demonstrate_integrity

    return demonstrate_integrity()


@router.get("/api/process/graph")
def process_graph(request: Request):
    return request.app.state.mitre_engine.graph()


@router.get("/api/reports")
def reports(request: Request):
    return {"reports": request.app.state.report_store.list_reports()}


@router.post("/api/reports/generate")
def generate_report(request: Request, date: str | None = None):
    try:
        return request.app.state.scheduler.generate_now(date)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/api/reports/{date}/verify")
def verify_report(date: str, request: Request):
    try:
        return request.app.state.report_store.verify(valid_date(date))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/api/reports/{date}/download")
def download_report(
    date: str, request: Request, format: Literal["pdf", "csv", "json", "zip"] = "pdf"
):
    try:
        data, media_type, filename = request.app.state.report_store.download(
            valid_date(date), format
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(409, str(exc)) from exc
    return Response(
        data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/reports/{date}")
def get_report(date: str, request: Request):
    try:
        result = request.app.state.report_store.get(valid_date(date))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(409, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "No signed report for this day")
    return result
