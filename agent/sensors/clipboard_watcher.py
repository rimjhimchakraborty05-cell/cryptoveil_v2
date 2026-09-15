"""Observe rapid changes between wallet-shaped clipboard values.

This is a review signal, not attribution of an unauthorised writer. Ordinary
clipboard contents are neither recorded nor hashed into the evidence ledger.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from contextlib import suppress

import pyperclip

from ..bus.events import ClipboardChangedEvent, ClipboardSwapEvent, EventSeverity

WALLET = re.compile(
    r"(?:0x[0-9a-fA-F]{40}|bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\Z"
)


class ClipboardWatcher:
    def __init__(self, broker):
        self._broker = broker
        self._task = None
        self._running = False
        self._last_hash = None
        self._last_change = 0.0
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
                content = (await asyncio.to_thread(pyperclip.paste)).strip()
                await self.observe(content, time.monotonic())
                self.status, self.last_error = "active", None
            except Exception:  # noqa: BLE001 - clipboard APIs differ by host
                self.status, self.last_error = (
                    "unavailable",
                    "Clipboard access is unavailable in this session",
                )
                await asyncio.sleep(10)
            await asyncio.sleep(0.5)

    async def observe(self, content, now):
        if not WALLET.fullmatch(content):
            self._last_hash = None
            return
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        if current_hash == self._last_hash:
            return
        previous_hash = self._last_hash
        previous_time = self._last_change
        self._last_hash, self._last_change = current_hash, now
        await self._broker.publish(
            ClipboardChangedEvent(
                content_hash=current_hash, content_length=len(content), previous_hash=previous_hash
            )
        )
        if previous_hash is not None and now - previous_time <= 2:
            await self._broker.publish(
                ClipboardSwapEvent(
                    severity=EventSeverity.MEDIUM,
                    expected_hash=previous_hash,
                    observed_hash=current_hash,
                )
            )
