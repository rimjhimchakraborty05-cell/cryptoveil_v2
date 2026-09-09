"""
network_engine.py — Connection telemetry, C2 beacon detection, DGA classifier.

Polls active outbound connections via psutil at a fixed interval (metadata
only — no deep packet inspection, per README's documented limitations). For
every established connection:

  1. Publishes a NetworkConnectionEvent (raw telemetry).
  2. Tracks per-(pid, remote_addr, remote_port) contact timestamps to detect
     C2 beaconing: regular, low-jitter check-ins are flagged via the
     coefficient of variation (stdev / mean) of inter-contact intervals.
  3. Resolves the remote address via reverse DNS (best-effort, on an
     already-established connection — pre-connection DNS interception would
     need a local resolver hook, out of scope here) and scores the hostname
     label for DGA (Domain Generation Algorithm) characteristics: high
     entropy, low vowel ratio, unusual digit ratio, long random-looking
     labels.
"""
from __future__ import annotations

import asyncio
import logging
import math
import socket
import statistics
from collections import defaultdict, deque
from typing import Deque, Optional

import psutil

from ..bus.event_bus import EventBroker
from ..bus.events import (
    C2BeaconEvent,
    DgaDetectedEvent,
    NetworkConnectionEvent,
)

log = logging.getLogger("cryptoveil.engines.network")

POLL_INTERVAL = 3.0
MIN_BEACON_SAMPLES = 5
MAX_COV_FOR_BEACON = 0.15  # low variance in interval == regular beaconing
DGA_ENTROPY_THRESHOLD = 3.6
VOWELS = set("aeiou")


def _label_entropy(label: str) -> float:
    if not label:
        return 0.0
    freq: dict[str, int] = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    n = len(label)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _dga_score(hostname: str) -> tuple[float, float, float, int]:
    label = hostname.split(".")[0].lower()
    entropy = _label_entropy(label)
    vowel_ratio = sum(1 for c in label if c in VOWELS) / max(len(label), 1)
    digit_ratio = sum(1 for c in label if c.isdigit()) / max(len(label), 1)
    return entropy, vowel_ratio, digit_ratio, len(label)


class NetworkEngine:
    def __init__(self, broker: EventBroker, poll_interval: float = POLL_INTERVAL) -> None:
        self._broker = broker
        self._interval = poll_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._contact_history: dict[tuple, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._dns_cache: dict[str, Optional[str]] = {}
        self._beacon_alerted: set[tuple] = set()

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("NetworkEngine started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        while self._running:
            try:
                await self._poll_once()
            except Exception:
                log.exception("NetworkEngine poll failed")
            await asyncio.sleep(self._interval)

    async def _poll_once(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.warning("NetworkEngine: insufficient privileges to list connections")
            return

        now = loop.time()
        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue

            pid = c.pid or 0
            try:
                pname = psutil.Process(pid).name() if pid else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"

            remote_addr, remote_port = c.raddr.ip, c.raddr.port
            local_addr, local_port = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)

            await self._broker.publish(
                NetworkConnectionEvent(
                    pid=pid,
                    process_name=pname,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    status=c.status,
                )
            )

            key = (pid, remote_addr, remote_port)
            history = self._contact_history[key]
            history.append(now)
            await self._check_beacon(key, pid, pname, remote_addr, remote_port, history)
            await self._check_dga(remote_addr, pid, pname)

    async def _check_beacon(self, key, pid, pname, remote_addr, remote_port, history: Deque[float]) -> None:
        if len(history) < MIN_BEACON_SAMPLES or key in self._beacon_alerted:
            return
        samples = list(history)
        intervals = [b - a for a, b in zip(samples, samples[1:])]
        if len(intervals) < MIN_BEACON_SAMPLES - 1:
            return
        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            return
        cov = statistics.pstdev(intervals) / mean_interval
        if cov <= MAX_COV_FOR_BEACON:
            self._beacon_alerted.add(key)
            await self._broker.publish(
                C2BeaconEvent(
                    pid=pid,
                    process_name=pname,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    beacon_count=len(history),
                    avg_interval_seconds=round(mean_interval, 2),
                    coefficient_of_variation=round(cov, 4),
                )
            )
            log.warning(
                "C2 beacon suspected: %s:%s from pid=%s cov=%.3f", remote_addr, remote_port, pid, cov
            )

    async def _check_dga(self, remote_addr: str, pid: int, pname: str) -> None:
        if remote_addr in self._dns_cache:
            hostname = self._dns_cache[remote_addr]
        else:
            hostname = await self._reverse_dns(remote_addr)
            self._dns_cache[remote_addr] = hostname

        if not hostname:
            return

        entropy, vowel_ratio, digit_ratio, label_len = _dga_score(hostname)
        if entropy >= DGA_ENTROPY_THRESHOLD and label_len >= 8 and vowel_ratio < 0.3:
            await self._broker.publish(
                DgaDetectedEvent(
                    hostname=hostname,
                    entropy_score=round(entropy, 3),
                    vowel_ratio=round(vowel_ratio, 3),
                    digit_ratio=round(digit_ratio, 3),
                    label_length=label_len,
                    pid=pid,
                    process_name=pname,
                )
            )
            log.warning("DGA-like hostname detected: %s (entropy=%.2f)", hostname, entropy)

    @staticmethod
    async def _reverse_dns(ip: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0])
        except (socket.herror, socket.gaierror, OSError):
            return None
