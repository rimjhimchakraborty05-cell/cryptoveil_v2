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
import time
from typing import Optional

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
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("ProcessWatcher started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        # Prime the known-process table so already-running processes at
        # startup don't all fire spurious "spawn" events.
        for p in psutil.process_iter(["pid", "name"]):
            self._known[p.pid] = {"name": p.info.get("name", "")}

        while self._running:
            try:
                await self._poll_once()
            except Exception:
                log.exception("ProcessWatcher poll failed")
            await asyncio.sleep(self._interval)

    async def _poll_once(self) -> None:
        current_pids: set[int] = set()

        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            info = proc.info
            pid = info["pid"]
            current_pids.add(pid)

            if pid in self._known:
                continue  # already seen — not a new spawn

            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            ppid = info.get("ppid") or 0

            parent_name, parent_exe = "", ""
            try:
                parent = psutil.Process(ppid)
                parent_name = parent.name()
                parent_exe = parent.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                pass

            self._known[pid] = {"name": name}

            await self._broker.publish(
                ProcessSpawnedEvent(
                    pid=pid,
                    name=name,
                    exe=exe,
                    cmdline=cmdline,
                    ppid=ppid,
                    parent_name=parent_name,
                    parent_exe=parent_exe,
                    username=info.get("username") or "",
                    create_time=info.get("create_time") or time.time(),
                )
            )

            await self._check_anti_forensic(pid, name, cmdline)

        terminated = set(self._known) - current_pids
        for pid in terminated:
            name = self._known.pop(pid, {}).get("name", "")
            await self._broker.publish(ProcessTerminatedEvent(pid=pid, name=name))

    async def _check_anti_forensic(self, pid: int, name: str, cmdline: str) -> None:
        haystack = cmdline.lower()
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
