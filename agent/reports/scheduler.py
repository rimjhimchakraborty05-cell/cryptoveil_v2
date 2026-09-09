"""
scheduler.py — Drives the 24-hour report cycle.

On startup, generates (or catches up on) yesterday's and today's report if
missing, so a restart never loses a day. Then sleeps until the next UTC
midnight, generates the day that just ended, persists it, and repeats — for
as long as the process stays active, matching the "until my application is
active, daily reports must be available" requirement.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..forensics.audit_logger import AuditLogger
from .report_generator import generate_report
from .store import ReportStore

log = logging.getLogger("cryptoveil.reports.scheduler")


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _yesterday_str() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def _seconds_until_next_midnight_utc() -> float:
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return (tomorrow - now).total_seconds()


class ReportScheduler:
    def __init__(self, audit_logger: AuditLogger, store: ReportStore) -> None:
        self._audit_logger = audit_logger
        self._store = store
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._catch_up()
        self._task = asyncio.create_task(self._run())
        log.info("ReportScheduler started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    def _catch_up(self) -> None:
        for date_str in (_yesterday_str(), _today_str()):
            if not self._store.exists(date_str):
                self.generate_now(date_str)

    def generate_now(self, date_str: Optional[str] = None) -> dict:
        date_str = date_str or _today_str()
        report = generate_report(self._audit_logger, date_str)
        self._store.save(report)
        log.info(
            "Generated daily report for %s (%d events)",
            date_str, report["executive_summary"]["total_events"],
        )
        return report

    async def _run(self) -> None:
        while self._running:
            await asyncio.sleep(_seconds_until_next_midnight_utc())
            if not self._running:
                break
            completed_date = (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime("%Y-%m-%d")
            self.generate_now(completed_date)
