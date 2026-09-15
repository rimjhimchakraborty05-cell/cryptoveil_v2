"""
process_watcher.py — Process spawn/exit sensor + anti-forensic command detection.

Runs as a non-blocking asyncio background task. Polls the OS process table via
psutil at a fixed interval, diffs against the previously seen PID set to
detect spawns and terminations, and publishes ProcessSpawnedEvent /
ProcessTerminatedEvent onto the EventBroker.

Anti-forensic detection (log clearing, shadow-copy deletion, journal wiping,
etc.) is evaluated inline on every spawned process and published as its own
always-critical AntiForensicEvent, so it is never masked by a MITRE rule miss.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import suppress

import psutil

from ..bus.event_bus import EventBroker
from ..bus.events import (
    AntiForensicEvent,
    EventSeverity,
    ProcessSpawnedEvent,
    ProcessTerminatedEvent,
)

log = logging.getLogger("cryptoveil.sensors.process")

# Command-line substrings indicating an attacker is trying to destroy
# evidence of their own activity (log clearing, shadow-copy deletion,
# journal wiping, secure deletion, etc.)
ANTI_FORENSIC_PATTERNS: dict[str, str] = {
    "wevtutil cl": "Windows event log cleared via wevtutil",
    "wevtutil clear-log": "Windows event log cleared via wevtutil",
    "vssadmin delete shadows": "Volume shadow copies deleted (evidence destruction)",
    "fsutil usn deletejournal": "NTFS USN change journal deleted (forensic timeline destroyed)",
    "cipher /w": "Free-space wipe via cipher.exe (secure deletion of recoverable data)",
    "wbadmin delete catalog": "Windows Backup catalog deleted",
    "bcdedit /set bootstatuspolicy ignoreallfailures": "Boot recovery options disabled",
    "clear-eventlog": "PowerShell event-log clearing cmdlet",
    "remove-eventlog": "PowerShell event-log removal cmdlet",
}


class ProcessWatcher:
    """Polls the process table and publishes process lifecycle + anti-forensic events."""

    def __init__(self, broker: EventBroker, poll_interval: float = 1.0) -> None:
        self._broker = broker
        self._interval = poll_interval
        self._known: dict[int, dict] = {}
        self._task: asyncio.Task | None = None
        self._running = False
        self.status, self.last_error = "starting", None

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("ProcessWatcher started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        self.status = "stopped"

    @staticmethod
    def _snapshot() -> dict[int, dict]:
        result = {}
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                result[proc.pid] = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result

    async def _run(self) -> None:
        try:
            snapshot = await asyncio.to_thread(self._snapshot)
            self._known = {
                pid: {"name": info.get("name", ""), "create_time": info.get("create_time")}
                for pid, info in snapshot.items()
            }
            self.status = "active"
        except Exception as exc:  # noqa: BLE001 - sensor failure must not stop monitoring
            self.status, self.last_error = "unavailable", str(exc)
        while self._running:
            try:
                await self._poll_once()
                self.status, self.last_error = "active", None
            except Exception as exc:
                self.status, self.last_error = "unavailable", str(exc)
                log.exception("Process observations unavailable")
            await asyncio.sleep(self._interval)

    async def _poll_once(self) -> None:
        snapshot = await asyncio.to_thread(self._snapshot)
        for pid, info in snapshot.items():
            previous = self._known.get(pid)
            if previous and previous.get("create_time") == info.get("create_time"):
                continue
            if previous:
                await self._broker.publish(
                    ProcessTerminatedEvent(pid=pid, name=previous.get("name", ""))
                )
            name = info.get("name") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            ppid = info.get("ppid") or 0
            parent = snapshot.get(ppid, {})
            await self._broker.publish(
                ProcessSpawnedEvent(
                    pid=pid,
                    name=name,
                    exe=info.get("exe") or "",
                    cmdline=cmdline,
                    ppid=ppid,
                    parent_name=parent.get("name") or "",
                    parent_exe=parent.get("exe") or "",
                    username=info.get("username") or "",
                    create_time=info.get("create_time") or time.time(),
                )
            )
            self._known[pid] = {"name": name, "create_time": info.get("create_time")}
            await self._check_anti_forensic(pid, name, cmdline)
        for pid in set(self._known) - set(snapshot):
            old = self._known.pop(pid)
            await self._broker.publish(ProcessTerminatedEvent(pid=pid, name=old.get("name", "")))

    async def _check_anti_forensic(self, pid: int, name: str, cmdline: str) -> None:
        if name.lower() not in {
            "wevtutil.exe",
            "vssadmin.exe",
            "fsutil.exe",
            "cipher.exe",
            "wbadmin.exe",
            "bcdedit.exe",
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
        }:
            return
        haystack = re.sub(r"\.exe\b", "", cmdline.lower()).replace('"', "")
        haystack = re.sub(r"\s+", " ", haystack)
        for pattern, description in ANTI_FORENSIC_PATTERNS.items():
            if pattern in haystack:
                await self._broker.publish(
                    AntiForensicEvent(
                        severity=EventSeverity.CRITICAL,
                        pid=pid,
                        process_name=name,
                        cmdline=cmdline,
                        matched_pattern=pattern,
                    )
                )
                log.warning("Anti-forensic activity detected: %s (pid=%s)", description, pid)
                return
