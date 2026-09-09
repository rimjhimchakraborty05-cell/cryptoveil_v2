"""
main.py — FastAPI application entry point + lifespan wiring.

Boots the event bus, every sensor, both analysis engines, the forensic audit
logger + off-host store, and the daily report scheduler; wires them all
together through the EventBroker; and exposes the REST API plus two
WebSocket broadcast channels (dashboard, browser extension). Started via
run.py at the project root:

    python run.py
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ..bus.event_bus import EventBroker
from ..engines.mitre_engine import MitreEngine
from ..engines.network_engine import NetworkEngine
from ..forensics.audit_logger import AuditLogger
from ..forensics.off_host_store import OffHostStore
from ..reports.scheduler import ReportScheduler
from ..reports.store import ReportStore
from ..sensors.clipboard_watcher import ClipboardWatcher
from ..sensors.entropy_watcher import EntropyWatcher
from ..sensors.process_watcher import ProcessWatcher
from . import routes
from .ws_manager import WebSocketManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cryptoveil.server")

def _resolve_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and Path(meipass).exists():
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


BASE_DIR = _resolve_base_dir()


def _resolve_data_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return BASE_DIR / "data"


def _resolve_offhost_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "offhost_evidence"
    return BASE_DIR / "offhost_evidence"


def _resolve_rules_path() -> Path:
    p = BASE_DIR / "process_rules.json"
    if p.exists():
        return p
    if getattr(sys, "frozen", False):
        p2 = Path(sys.executable).resolve().parent / "process_rules.json"
        if p2.exists():
            return p2
    return p


def _resolve_dashboard_dir() -> Path:
    d = BASE_DIR / "dashboard"
    if d.exists():
        return d
    if getattr(sys, "frozen", False):
        d2 = Path(sys.executable).resolve().parent / "dashboard"
        if d2.exists():
            return d2
        d3 = Path(sys.executable).resolve().parent / "_internal" / "dashboard"
        if d3.exists():
            return d3
    return d


DATA_DIR = Path(os.environ.get("CRYPTOVEIL_DATA_DIR", _resolve_data_dir()))
OFFHOST_DIR = Path(os.environ.get("CRYPTOVEIL_OFFHOST_DIR", _resolve_offhost_dir()))
RULES_PATH = Path(os.environ.get("CRYPTOVEIL_RULES_PATH", _resolve_rules_path()))
WATCH_PATHS = [p for p in os.environ.get("CRYPTOVEIL_WATCH_PATHS", str(Path.home())).split(os.pathsep) if p]
DASHBOARD_DIR = _resolve_dashboard_dir()


@asynccontextmanager
async def lifespan(app: FastAPI):
    broker = EventBroker()
    broker.set_loop(asyncio.get_running_loop())

    off_host = OffHostStore(OFFHOST_DIR)
    audit_logger = AuditLogger(broker, DATA_DIR, off_host)
    audit_logger.attach()

    mitre_engine = MitreEngine(broker, RULES_PATH)
    mitre_engine.attach()
    network_engine = NetworkEngine(broker)

    process_watcher = ProcessWatcher(broker)
    entropy_watcher = EntropyWatcher(broker, WATCH_PATHS)
    clipboard_watcher = ClipboardWatcher(broker)

    report_store = ReportStore(DATA_DIR / "reports")
    scheduler = ReportScheduler(audit_logger, report_store)

    ws_manager = WebSocketManager()
    broker.subscribe("*", ws_manager.broadcast_event)

    app.state.broker = broker
    app.state.audit_logger = audit_logger
    app.state.off_host = off_host
    app.state.mitre_engine = mitre_engine
    app.state.network_engine = network_engine
    app.state.report_store = report_store
    app.state.scheduler = scheduler
    app.state.ws_manager = ws_manager
    app.state.start_time = time.time()

    process_watcher.start()
    network_engine.start()
    entropy_watcher.start()
    clipboard_watcher.start()
    scheduler.start()

    log.info("CryptoVeil agent fully wired and running")
    try:
        yield
    finally:
        await process_watcher.stop()
        await network_engine.stop()
        entropy_watcher.stop()
        await clipboard_watcher.stop()
        await scheduler.stop()
        log.info("CryptoVeil agent shut down cleanly")


app = FastAPI(title="CryptoVeil Agent", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)

if DASHBOARD_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await app.state.ws_manager.connect("dashboard", websocket)
    try:
        while True:
            await websocket.receive_text()  # dashboard is push-only; drain any pings
    except WebSocketDisconnect:
        app.state.ws_manager.disconnect("dashboard", websocket)


@app.websocket("/ws/extension")
async def ws_extension(websocket: WebSocket):
    await app.state.ws_manager.connect("extension", websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            await routes.handle_extension_ws_message(app, msg)
    except WebSocketDisconnect:
        app.state.ws_manager.disconnect("extension", websocket)
