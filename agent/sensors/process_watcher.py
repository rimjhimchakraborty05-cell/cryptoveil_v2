"""
process_watcher.py — Process spawn/exit sensor + anti-forensic command detection.

On Windows, subscribes to native WMI process-start events. A one-second psutil
snapshot reconciles exits and provides a visible fallback when WMI is unavailable.
OS queries and metadata enrichment run outside the asyncio event loop.

Anti-forensic detection (log clearing, shadow-copy deletion, journal wiping,
etc.) is evaluated inline on every spawned process and published as its own
always-critical AntiForensicEvent, so it is never masked by a MITRE rule miss.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
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
from .windows_process_events import WindowsProcessEvents

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
    """Native Windows starts plus sampled reconciliation, with explicit coverage status."""

    def __init__(self, broker: EventBroker, poll_interval: float = 1.0) -> None:
        self._broker = broker
        self._interval = poll_interval
        self._known: dict[int, dict] = {}
        self._task: asyncio.Task | None = None
        self._running = False
        self.status, self.last_error = "starting", None
        self.mode = "starting"
        self._native = None
        self._lock = asyncio.Lock()

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("ProcessWatcher started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._native:
            await asyncio.to_thread(self._native.stop)
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
            self._known = {pid: dict(info) for pid, info in snapshot.items()}
            self.status = "active"
            if sys.platform == "win32":
                loop = asyncio.get_running_loop()

                def accept(trace):
                    # WMI calls this on its worker thread; capture short-lived
                    # process metadata before queueing the async persistence.
                    info, parent = self._trace_context(trace)
                    return asyncio.run_coroutine_threadsafe(self._on_native(info, parent), loop)

                self._native = WindowsProcessEvents(accept)
                self._native.start()
        except Exception as exc:  # noqa: BLE001 - sensor failure must not stop monitoring
            self.status, self.last_error = "unavailable", str(exc)
        while self._running:
            try:
                await self._poll_once()
                native = self._native.status if self._native else None
                self.mode = (
                    "windows_wmi_push"
                    if native == "active"
                    else "polling_fallback"
                    if self._native
                    else "polling"
                )
                self.status = (
                    "active"
                    if not self._native or native == "active"
                    else "starting"
                    if native == "starting"
                    else "degraded"
                )
                self.last_error = (
                    self._native.last_error
                    if self._native
                    else f"Process table sampled every {self._interval:g} second(s)"
                )
            except Exception as exc:
                self.status, self.last_error = "unavailable", str(exc)
                log.exception("Process observations unavailable")
            await asyncio.sleep(self._interval)

    async def _poll_once(self) -> None:
        snapshot_started = time.time()
        snapshot = await asyncio.to_thread(self._snapshot)
        async with self._lock:
            for pid, info in snapshot.items():
                await self._emit_spawn(info, snapshot.get(info.get("ppid"), {}), "process_snapshot")
            for pid in set(self._known) - set(snapshot):
                if (self._known[pid].get("create_time") or 0) > snapshot_started:
                    continue
                old = self._known.pop(pid)
                await self._broker.publish(
                    ProcessTerminatedEvent(pid=pid, name=old.get("name", ""))
                )

    @staticmethod
    def _read_process(pid):
        try:
            return psutil.Process(pid).as_dict(
                attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"],
                ad_value=None,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}

    @classmethod
    def _trace_context(cls, trace):
        info = cls._read_process(trace["pid"])
        # A recycled PID must not lend its command line to the earlier event.
        if not info or abs((info.get("create_time") or 0) - trace["create_time"]) > 0.05:
            info = dict(trace)
        parent = cls._read_process(trace["ppid"])
        return info, parent

    async def _on_native(self, info, parent):
        async with self._lock:
            if not parent:
                parent = self._known.get(info.get("ppid"), {})
            await self._emit_spawn(info, parent, "windows_wmi_push")

    async def _emit_spawn(self, info, parent, method):
        pid = info["pid"]
        previous = self._known.get(pid)
        if previous and previous.get("create_time") == info.get("create_time"):
            return
        if previous:
            await self._broker.publish(
                ProcessTerminatedEvent(pid=pid, name=previous.get("name", ""))
            )
        if (parent.get("create_time") or 0) > (info.get("create_time") or 0):
            parent = {}
        name = info.get("name") or ""
        cmdline = " ".join(info.get("cmdline") or [])
        await self._broker.publish(
            ProcessSpawnedEvent(
                pid=pid,
                name=name,
                exe=info.get("exe") or "",
                cmdline=cmdline,
                ppid=info.get("ppid") or 0,
                parent_name=parent.get("name") or "",
                parent_exe=parent.get("exe") or "",
                username=info.get("username") or "",
                create_time=info.get("create_time") or time.time(),
                observation_method=method,
                context_complete=bool(info.get("exe") and cmdline and parent.get("name")),
            )
        )
        self._known[pid] = dict(info)
        await self._check_anti_forensic(pid, name, cmdline)

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
