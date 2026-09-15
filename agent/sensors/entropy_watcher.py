"""
entropy_watcher.py — Filesystem burst-entropy sensor (ransomware indicator).

Uses watchdog's OS-native filesystem push events (no polling) to observe file
creation/modification/moves inside one or more watched directories. Each
touched file's Shannon entropy is sampled; a sustained burst of high-entropy
writes in a short time window is the classic signature of ransomware
encrypting a directory tree in bulk.

Watchdog callbacks run on an OS thread, not the asyncio event loop, so all
publishing goes through EventBroker.publish_threadsafe().
"""

from __future__ import annotations

import logging
import math
import os
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..bus.event_bus import EventBroker
from ..bus.events import EventSeverity, FileEntropyEvent

log = logging.getLogger("cryptoveil.sensors.entropy")

ENTROPY_THRESHOLD = 7.2  # bits/byte — near-random data (encrypted/compressed)
SAMPLE_BYTES = 65536  # read at most this many bytes per file
BURST_WINDOW_SECONDS = 20.0  # sliding window for burst detection
BURST_COUNT_THRESHOLD = 8  # high-entropy writes within window → burst


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte of a byte string. 0.0 for empty input."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: EntropyWatcher) -> None:
        self._watcher = watcher

    def on_created(self, event):
        if not event.is_directory:
            self._watcher.handle(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._watcher.handle(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            self._watcher.handle(event.dest_path, "moved")


class EntropyWatcher:
    """Watches directories for ransomware-style high-entropy write bursts."""

    def __init__(
        self,
        broker: EventBroker,
        watch_paths: list[str],
        entropy_threshold: float = ENTROPY_THRESHOLD,
        burst_window_seconds: float = BURST_WINDOW_SECONDS,
        burst_count_threshold: int = BURST_COUNT_THRESHOLD,
        exclude_paths: list[str] | None = None,
    ) -> None:
        self._broker = broker
        self._watch_paths = [p for p in watch_paths if os.path.isdir(p)]
        self._entropy_threshold = entropy_threshold
        self._burst_window = burst_window_seconds
        self._burst_count_threshold = burst_count_threshold
        self._observer = Observer()
        self._recent_high_entropy: dict[str, float] = {}
        self._excluded = [Path(p).resolve() for p in (exclude_paths or [])]
        self._last_seen: dict[str, float] = {}
        self._last_alert = -100.0
        self.status, self.last_error = "starting", None

    def start(self) -> None:
        if not self._watch_paths:
            self.status, self.last_error = "unavailable", "No valid watched folders configured"
            log.warning(self.last_error)
            return
        handler = _Handler(self)
        for path in self._watch_paths:
            self._observer.schedule(handler, path, recursive=True)
        self._observer.start()
        self.status = "active"
        log.info("EntropyWatcher started on %s", self._watch_paths)

    def stop(self) -> None:
        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
        self.status = "stopped"

    def handle(self, path: str, kind: str) -> None:
        resolved = Path(path).resolve()
        if any(resolved == p or p in resolved.parents for p in self._excluded):
            return
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in resolved.parts):
            return
        now = time.monotonic()
        if now - self._last_seen.get(str(resolved), -100) < 0.5:
            return
        self._last_seen = {p: t for p, t in self._last_seen.items() if now - t < self._burst_window}
        self._last_seen[str(resolved)] = now
        try:
            with resolved.open("rb") as stream:
                data = stream.read(SAMPLE_BYTES)
        except OSError:
            return
        entropy = shannon_entropy(data)
        is_high = len(data) >= 1024 and entropy >= self._entropy_threshold
        self._recent_high_entropy = {
            p: t for p, t in self._recent_high_entropy.items() if now - t < self._burst_window
        }
        if is_high:
            self._recent_high_entropy[str(resolved)] = now
        burst = (
            is_high
            and len(self._recent_high_entropy) >= self._burst_count_threshold
            and now - self._last_alert >= 15
        )
        if burst:
            self._last_alert = now
        self._broker.publish_threadsafe(
            FileEntropyEvent(
                severity=EventSeverity.HIGH if burst else EventSeverity.INFO,
                file_path=str(resolved),
                entropy=round(entropy, 3),
                event_kind=kind,
                burst_count=len(self._recent_high_entropy),
                burst_triggered=burst,
            )
        )
