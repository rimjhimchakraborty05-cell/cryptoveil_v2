"""Harmless real-sensor validation used by the CryptoVeil Simulation Lab.

Real sensor tests create ordinary OS activity and wait for the normal sensor,
broker and evidence pipeline to observe it. They never publish synthetic sensor
events directly. Isolated demonstrations live elsewhere and are labelled as
simulations.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from ..forensics.audit_logger import AuditLogger


class SensorTestUnavailable(RuntimeError):
    """Raised when the requested real sensor is not active."""


class SensorTestRunner:
    def __init__(self, audit: AuditLogger, sensors: list, watch_paths: list[str]) -> None:
        self.audit = audit
        self.sensors = sensors
        self.watch_paths = [Path(path) for path in watch_paths if Path(path).is_dir()]
        self._lock = asyncio.Lock()

    def _sensor(self, class_name: str):
        return next((sensor for sensor in self.sensors if type(sensor).__name__ == class_name), None)

    def _require_sensor(self, class_name: str):
        sensor = self._sensor(class_name)
        if sensor is None or getattr(sensor, "status", "unavailable") not in {
            "active",
            "degraded",
        }:
            raise SensorTestUnavailable(
                f"{class_name} is not active; start CryptoVeil with that sensor available."
            )
        return sensor

    def _find_event(self, predicate):
        for entry in reversed(self.audit.recent_entries(500)):
            event = entry.get("event", {})
            if predicate(event):
                return entry
        return None

    async def _wait_for(self, predicate, timeout: float = 8.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            entry = await asyncio.to_thread(self._find_event, predicate)
            if entry is not None:
                return entry
            await asyncio.sleep(0.1)
        return None

    @staticmethod
    def _result(name: str, expected: str, entry: dict | None, started: float, detail: str) -> dict:
        elapsed = round((time.monotonic() - started) * 1000)
        event = entry.get("event", {}) if entry else {}
        return {
            "mode": "real_sensor_test",
            "name": name,
            "passed": entry is not None,
            "expected_detection": expected,
            "actual_detection": event.get("topic") if entry else "not_observed",
            "latency_ms": elapsed,
            "evidence_id": event.get("event_id") if entry else None,
            "seq": entry.get("seq") if entry else None,
            "detail": detail if entry else f"No matching sensor evidence was observed within {elapsed} ms.",
        }

    async def run_process_start(self) -> dict:
        """Start an ordinary short-lived Python process and wait for ProcessWatcher evidence."""
        async with self._lock:
            self._require_sensor("ProcessWatcher")
            marker = f"cryptoveil-safe-process-test-{uuid.uuid4()}"
            started = time.monotonic()
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import time; time.sleep(2.5)",
                marker,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=creationflags,
            )
            try:
                entry = await self._wait_for(
                    lambda event: event.get("topic") == "sensor.process.spawned"
                    and marker in event.get("cmdline", ""),
                    timeout=7.0,
                )
            finally:
                try:
                    await asyncio.wait_for(process.wait(), timeout=4.0)
                except TimeoutError:
                    process.terminate()
                    await process.wait()
            return self._result(
                "Process sensor",
                "sensor.process.spawned",
                entry,
                started,
                "A harmless short-lived process was created and detected by the normal process sensor.",
            )

    async def run_ransomware_indicator(self) -> dict:
        """Create temporary random files in a watched folder and wait for the entropy burst sensor."""
        async with self._lock:
            self._require_sensor("EntropyWatcher")
            if not self.watch_paths:
                raise SensorTestUnavailable("No writable watched folder is configured for the file sensor test.")

            base = next((path for path in self.watch_paths if os.access(path, os.W_OK)), None)
            if base is None:
                raise SensorTestUnavailable("No configured watched folder is writable for the file sensor test.")

            marker = f"CryptoVeil_SensorTest_{uuid.uuid4().hex[:10]}"
            directory = Path(tempfile.mkdtemp(prefix=marker + "_", dir=base))
            started = time.monotonic()
            try:
                for index in range(9):
                    target = directory / f"sample_{index:02d}.bin"
                    await asyncio.to_thread(target.write_bytes, os.urandom(4096))
                    await asyncio.sleep(0.08)

                entry = await self._wait_for(
                    lambda event: event.get("topic") == "sensor.filesystem.entropy"
                    and bool(event.get("burst_triggered"))
                    and str(directory) in event.get("file_path", ""),
                    timeout=8.0,
                )
            finally:
                await asyncio.to_thread(shutil.rmtree, directory, True)

            return self._result(
                "Ransomware behavioral sensor",
                "sensor.filesystem.entropy with burst_triggered=true",
                entry,
                started,
                "Temporary high-entropy files were created in a dedicated test folder and removed after the real sensor check.",
            )

    async def run(self, test_id: str) -> dict:
        if test_id == "process_start":
            return await self.run_process_start()
        if test_id == "ransomware_indicator":
            return await self.run_ransomware_indicator()
        raise ValueError("Unknown real sensor test")
