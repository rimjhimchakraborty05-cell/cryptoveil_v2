"""CryptoVeil local application: durable collection, verification and reports."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..bus.event_bus import EventBroker
from ..engines.mitre_engine import MitreEngine
from ..engines.network_engine import NetworkEngine
from ..forensics.audit_logger import AuditLogger
from ..forensics.evidence_archive import EvidenceArchive
from ..forensics.storage import DataDirectoryLock
from ..reports.scheduler import ReportScheduler
from ..reports.store import ReportStore
from ..sensors.clipboard_watcher import ClipboardWatcher
from ..sensors.entropy_watcher import EntropyWatcher
from ..sensors.process_watcher import ProcessWatcher
from . import routes
from .security import PairingManager, access_guard

log = logging.getLogger("cryptoveil.server")
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))


def default_data_dir() -> Path:
    if getattr(sys, "frozen", False):
        legacy = Path(sys.executable).parent / "data"
        if (legacy / "audit_log.jsonl").exists():
            return legacy
        return (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
            / "CryptoVeil"
            / "data"
        )
    return BASE_DIR / "data"


def default_watch_paths() -> list[str]:
    configured = os.environ.get("CRYPTOVEIL_WATCH_PATHS")
    if configured is not None:
        return [p for p in configured.split(os.pathsep) if p]
    return [str(p) for name in ("Documents", "Downloads") if (p := Path.home() / name).is_dir()]


@dataclass
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("CRYPTOVEIL_DATA_DIR", default_data_dir()))
    )
    archive_dir: Path | None = None
    rules_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("CRYPTOVEIL_RULES_PATH", BASE_DIR / "process_rules.json")
        )
    )
    watch_paths: list[str] = field(default_factory=default_watch_paths)
    sensors_enabled: bool = True
    reports_enabled: bool = True
    testing: bool = False
    report_timezone: str = field(
        default_factory=lambda: os.environ.get("CRYPTOVEIL_REPORT_TIMEZONE", "Asia/Kolkata")
    )
    report_formats: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            os.environ.get("CRYPTOVEIL_REPORT_FORMATS", "pdf,csv,json").split(",")
        )
    )
    verification_seconds: int = 30

    def __post_init__(self):
        self.data_dir = Path(self.data_dir)
        if self.archive_dir is None:
            legacy = self.data_dir.parent / "offhost_evidence"
            legacy_exists = any((legacy / "events").glob("*.json"))
            default = legacy if legacy_exists else self.data_dir / "evidence_archive"
            self.archive_dir = Path(
                os.environ.get(
                    "CRYPTOVEIL_ARCHIVE_DIR", os.environ.get("CRYPTOVEIL_OFFHOST_DIR", default)
                )
            )
        self.archive_dir = Path(self.archive_dir)
        if not self.report_formats or set(self.report_formats) - {"pdf", "csv", "json"}:
            raise ValueError("CRYPTOVEIL_REPORT_FORMATS supports pdf,csv,json")
        if self.verification_seconds < 5:
            raise ValueError("Verification interval must be at least five seconds")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(application):
        directory_lock = DataDirectoryLock(settings.data_dir)
        broker = EventBroker()
        broker.set_loop(asyncio.get_running_loop())
        sensors = []
        verification_task = None
        scheduler = None
        try:
            audit = await asyncio.to_thread(
                AuditLogger, broker, settings.data_dir, EvidenceArchive(settings.archive_dir)
            )
            audit.attach()
            engine = MitreEngine(broker, settings.rules_path)
            engine.attach()
            store = ReportStore(settings.data_dir / "reports", audit)
            scheduler = ReportScheduler(
                audit, store, settings.report_timezone, settings.report_formats
            )
            pairing = PairingManager(settings.data_dir)
            application.state.settings = settings
            application.state.broker = broker
            application.state.audit_logger = audit
            application.state.mitre_engine = engine
            application.state.report_store = store
            application.state.scheduler = scheduler
            application.state.pairing = pairing
            application.state.start_time = time.time()
            application.state.sensors = sensors
            if settings.sensors_enabled:
                sensors.extend(
                    [
                        ProcessWatcher(broker),
                        NetworkEngine(broker),
                        EntropyWatcher(
                            broker,
                            settings.watch_paths,
                            exclude_paths=[str(settings.data_dir), str(settings.archive_dir)],
                        ),
                        ClipboardWatcher(broker),
                    ]
                )
                for sensor in sensors:
                    try:
                        sensor.start()
                    except Exception as exc:
                        sensor.status = "unavailable"
                        sensor.last_error = str(exc)
                        log.exception("Sensor failed to start")

            async def monitor():
                while True:
                    await asyncio.sleep(settings.verification_seconds)
                    try:
                        result = await asyncio.to_thread(audit.verify_chain)
                        if result["verified"] and not audit.collection_error:
                            await asyncio.to_thread(audit.seal)
                    except Exception as exc:
                        audit.collection_error = f"Integrity monitor failed: {exc}"
                        log.exception("Integrity monitor failed")

            verification_task = asyncio.create_task(monitor())
            if settings.reports_enabled:
                scheduler.start()
            yield
        finally:
            for sensor in sensors:
                if isinstance(sensor, EntropyWatcher):
                    await asyncio.to_thread(sensor.stop)
                else:
                    await sensor.stop()
            await broker.drain()
            if verification_task:
                verification_task.cancel()
                with suppress(asyncio.CancelledError):
                    await verification_task
            if scheduler and settings.reports_enabled:
                await scheduler.stop()
            if (
                hasattr(application.state, "audit_logger")
                and not application.state.audit_logger.collection_error
            ):
                await asyncio.to_thread(application.state.audit_logger.seal)
            directory_lock.close()

    application = FastAPI(
        title="CryptoVeil",
        version="2.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.middleware("http")(access_guard)
    application.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"chrome-extension://[a-p]{32}",
        allow_methods=["POST"],
        allow_headers=["Content-Type", "Authorization"],
        allow_credentials=False,
    )
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost"] + (["testserver"] if settings.testing else []),
    )
    application.include_router(routes.router)
    application.mount(
        "/dashboard",
        StaticFiles(directory=str(BASE_DIR / "dashboard"), html=True),
        name="dashboard",
    )

    @application.get("/")
    def root():
        return RedirectResponse("/dashboard/")

    return application


app = create_app()
