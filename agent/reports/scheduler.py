"""Catch up every recorded day, refresh today's report and save on shutdown."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from ..forensics.audit_logger import AuditLogger, IntegrityError
from .report_generator import generate_report
from .store import ReportStore, valid_date

log = logging.getLogger("cryptoveil.reports")


class ReportScheduler:
    def __init__(
        self,
        audit_logger: AuditLogger,
        store: ReportStore,
        timezone_name="Asia/Kolkata",
        formats=("pdf", "csv", "json"),
        refresh_seconds=900,
    ) -> None:
        self.audit = audit_logger
        self.store = store
        self.timezone_name = timezone_name
        self.zone = ZoneInfo(timezone_name)
        self.formats = tuple(formats)
        self.refresh_seconds = max(60, refresh_seconds)
        self._task = None
        self._last_refresh = 0.0
        self._last_count = -1
        self._last_day = None
        self._lock = threading.RLock()
        self.error: str | None = None

    def today(self) -> str:
        return datetime.now(self.zone).strftime("%Y-%m-%d")

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # All ledger publishers have already been drained by app shutdown.
        try:
            await asyncio.to_thread(self.generate_now)
        except Exception as exc:
            self.error = str(exc)
            log.exception("Final daily report could not be saved")

    def generate_now(self, date_str=None) -> dict:
        with self._lock:
            date_str = valid_date(date_str or self.today())
            if date_str > self.today():
                raise ValueError("Cannot report a future day")
            if self.store.exists(date_str) and not self.store.verify(date_str)["verified"]:
                raise IntegrityError(
                    "Existing report was modified or deleted. It will not be silently replaced."
                )
            report = generate_report(self.audit, date_str, self.timezone_name)
            saved = self.store.save(report, self.formats)
            if date_str == self.today():
                self._last_count = report["forensic_integrity"]["total_events"]
                self._last_refresh = time.monotonic()
                self._last_day = date_str
            self.error = None
            return {**saved, "event_count": report["executive_summary"]["total_events"]}

    def catch_up(self) -> None:
        entries, _, _ = self.audit.snapshot()
        dates = set(self.store.dates())
        for entry in entries:
            try:
                dates.add(
                    datetime.fromtimestamp(entry["event"]["timestamp"], self.zone).strftime(
                        "%Y-%m-%d"
                    )
                )
            except (KeyError, TypeError, ValueError, OSError):
                continue
        today = self.today()
        for date in sorted(dates):
            if date < today:
                current = self.store.get(date) if self.store.exists(date) else None
                # Finish a previous day's snapshot which was taken before
                # that day ended; otherwise preserve the completed snapshot.
                ended = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=self.zone).date()
                generated_day = (
                    datetime.fromisoformat(current["generated_at"]).astimezone(self.zone).date()
                    if current
                    else None
                )
                if current is None or generated_day == ended:
                    self.generate_now(date)
        if not self.store.exists(today) or self.audit.stats()["total_events"] != self._last_count:
            self.generate_now(today)

    async def _run(self) -> None:
        while True:
            try:
                today = self.today()
                if self._last_day != today:
                    await asyncio.to_thread(self.catch_up)
                elif (
                    time.monotonic() - self._last_refresh >= self.refresh_seconds
                    and self.audit.stats()["total_events"] != self._last_count
                ):
                    await asyncio.to_thread(self.generate_now)
            except Exception as exc:
                self.error = str(exc)
                log.exception("Daily report generation failed; will retry")
            await asyncio.sleep(60)
