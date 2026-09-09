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
from collections import deque
from typing import Deque

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..bus.event_bus import EventBroker
from ..bus.events import EventSeverity, FileEntropyEvent

log = logging.getLogger("cryptoveil.sensors.entropy")

ENTROPY_THRESHOLD = 7.2       # bits/byte — near-random data (encrypted/compressed)
SAMPLE_BYTES = 65536          # read at most this many bytes per file
BURST_WINDOW_SECONDS = 20.0   # sliding window for burst detection
BURST_COUNT_THRESHOLD = 8     # high-entropy writes within window → burst


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
    def __init__(self, watcher: "EntropyWatcher") -> None:
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
    ) -> None:
        self._broker = broker
        self._watch_paths = [p for p in watch_paths if os.path.isdir(p)]
        self._entropy_threshold = entropy_threshold
        self._burst_window = burst_window_seconds
        self._burst_count_threshold = burst_count_threshold
        self._observer = Observer()
        self._recent_high_entropy: Deque[float] = deque()

    def start(self) -> None:
        if not self._watch_paths:
            log.warning("EntropyWatcher: no valid watch paths configured, sensor idle")
            return
        handler = _Handler(self)
        for path in self._watch_paths:
            self._observer.schedule(handler, path, recursive=True)
        self._observer.start()
        log.info("EntropyWatcher started on %s", self._watch_paths)

    def stop(self) -> None:
        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=2)

    def handle(self, path: str, kind: str) -> None:
        try:
            with open(path, "rb") as f:
                data = f.read(SAMPLE_BYTES)
        except (OSError, PermissionError):
            return

        entropy = shannon_entropy(data)
        is_high = entropy >= self._entropy_threshold

        burst_triggered = False
        now = time.monotonic()
        if is_high:
            self._recent_high_entropy.append(now)
            while (
                self._recent_high_entropy
                and now - self._recent_high_entropy[0] > self._burst_window
            ):
                self._recent_high_entropy.popleft()
            if len(self._recent_high_entropy) >= self._burst_count_threshold:
                burst_triggered = True

        severity = EventSeverity.INFO
        if is_high:
            severity = EventSeverity.MEDIUM
        if burst_triggered:
            severity = EventSeverity.CRITICAL

        event = FileEntropyEvent(
            severity=severity,
            file_path=path,
            entropy=round(entropy, 3),
            event_kind=kind,
            burst_count=len(self._recent_high_entropy),
            burst_triggered=burst_triggered,
        )
        self._broker.publish_threadsafe(event)
