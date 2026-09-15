"""New-connection observations and conservative repetition heuristics.

A socket seen in multiple polls is ONE connection, not repeated beacon traffic.
This sensor cannot see DNS queries or traffic inside an established socket.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import statistics
import time
from collections import OrderedDict, deque
from contextlib import suppress

import psutil

from ..bus.event_bus import EventBroker
from ..bus.events import C2BeaconEvent, EventSeverity, NetworkConnectionEvent

log = logging.getLogger("cryptoveil.network")
POLL_INTERVAL = 3.0
MIN_BEACON_SAMPLES = 6


class NetworkEngine:
    def __init__(self, broker: EventBroker, poll_interval=POLL_INTERVAL) -> None:
        self._broker, self._interval = broker, poll_interval
        self._task = None
        self._running = False
        self._active = set()
        self._contact_history = OrderedDict()
        self._alerted_at = {}
        self.status, self.last_error = "starting", None

    def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        self.status = "stopped"

    async def _run(self):
        while self._running:
            try:
                await self._poll_once()
            except Exception as exc:  # noqa: BLE001 - sensor failure must not stop monitoring
                self.status, self.last_error = "unavailable", str(exc)
                log.warning("Network observations unavailable: %s", exc)
            await asyncio.sleep(self._interval)

    @staticmethod
    def _snapshot():
        observations = []
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            if ipaddress.ip_address(c.raddr.ip).is_loopback:
                continue
            try:
                process = psutil.Process(c.pid) if c.pid else None
                name = process.name() if process else "unknown"
                started = process.create_time() if process else 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name, started = "unknown", 0
            observations.append((c, name, started))
        return observations

    async def _poll_once(self):
        observations = await asyncio.to_thread(self._snapshot)
        now = time.monotonic()
        active, sampled_keys = set(), set()
        for c, name, started in observations:
            identity = (c.pid, started, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
            active.add(identity)
            if identity in self._active:
                continue
            await self._broker.publish(
                NetworkConnectionEvent(
                    pid=c.pid or 0,
                    process_name=name,
                    local_addr=c.laddr.ip,
                    local_port=c.laddr.port,
                    remote_addr=c.raddr.ip,
                    remote_port=c.raddr.port,
                    status=c.status,
                )
            )
            key = (c.pid, started, c.raddr.ip, c.raddr.port)
            if key in sampled_keys:
                continue
            sampled_keys.add(key)
            history = self._contact_history.setdefault(key, deque(maxlen=20))
            self._contact_history.move_to_end(key)
            while history and now - history[0] > 3600:
                history.popleft()
            history.append(now)
            await self._check_pattern(key, name, history, now)
        self._active = active
        while len(self._contact_history) > 1000:
            old, _ = self._contact_history.popitem(last=False)
            self._alerted_at.pop(old, None)
        self.status, self.last_error = "active", None

    async def _check_pattern(self, key, name, history, now):
        if len(history) < MIN_BEACON_SAMPLES or now - self._alerted_at.get(key, -3600) < 3600:
            return
        intervals = [b - a for a, b in zip(history, list(history)[1:])]
        mean = statistics.mean(intervals)
        # Intervals close to the polling cadence are too imprecise to classify.
        if mean < self._interval * 3:
            return
        cov = statistics.pstdev(intervals) / mean
        if cov <= 0.15:
            self._alerted_at[key] = now
            await self._broker.publish(
                C2BeaconEvent(
                    severity=EventSeverity.MEDIUM,
                    pid=key[0] or 0,
                    process_name=name,
                    remote_addr=key[2],
                    remote_port=key[3],
                    beacon_count=len(history),
                    avg_interval_seconds=round(mean, 2),
                    coefficient_of_variation=round(cov, 4),
                )
            )
