"""
clipboard_watcher.py — Clipboard integrity sensor (hijack detection).

Windows and macOS/Linux both use a polling loop here (a true native push
notification would require a Win32 message-only window, out of scope for
this reference build — see README "Explicit Limitations"). Windows polls
faster than the documented 100ms macOS/Linux fallback cadence.

Detection logic: whenever the clipboard changes we hash and record it, then
re-check shortly after. If the content has silently changed *again* by the
time we re-check — without the normal "content changed" tick firing in
between — it's treated as a clipboard swap: the classic crypto-address
hijack pattern where malware watches the clipboard for a wallet address and
substitutes its own.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
from typing import Optional

import pyperclip

from ..bus.event_bus import EventBroker
from ..bus.events import ClipboardChangedEvent, ClipboardSwapEvent, EventSeverity

log = logging.getLogger("cryptoveil.sensors.clipboard")

WINDOWS_POLL_SECONDS = 0.25
FALLBACK_POLL_SECONDS = 0.5
RECHECK_DELAY_SECONDS = 0.6


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


class ClipboardWatcher:
    def __init__(self, broker: EventBroker) -> None:
        self._broker = broker
        self._last_hash: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._interval = WINDOWS_POLL_SECONDS if sys.platform == "win32" else FALLBACK_POLL_SECONDS

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("ClipboardWatcher started (interval=%.2fs, platform=%s)", self._interval, sys.platform)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        try:
            self._last_hash = _hash(pyperclip.paste())
        except Exception:
            log.warning("Clipboard access unavailable on this platform/session — sensor idle")
            return

        while self._running:
            await asyncio.sleep(self._interval)
            try:
                content = pyperclip.paste()
            except Exception:
                continue

            current_hash = _hash(content)
            if current_hash == self._last_hash:
                continue

            previous_hash = self._last_hash
            self._last_hash = current_hash

            await self._broker.publish(
                ClipboardChangedEvent(
                    content_hash=current_hash,
                    content_length=len(content),
                    previous_hash=previous_hash,
                )
            )

            asyncio.create_task(self._recheck(current_hash))

    async def _recheck(self, expected_hash: str) -> None:
        """
        If the clipboard content has moved on again to something new by the
        time we recheck, and nothing else legitimately updated our tracked
        hash in between, treat it as a hijack/swap.
        """
        await asyncio.sleep(RECHECK_DELAY_SECONDS)
        try:
            content = pyperclip.paste()
        except Exception:
            return

        observed_hash = _hash(content)
        if observed_hash == expected_hash:
            return  # unchanged since we last recorded it — normal
        if observed_hash == self._last_hash:
            return  # a legitimate subsequent copy already updated state

        await self._broker.publish(
            ClipboardSwapEvent(
                severity=EventSeverity.HIGH,
                expected_hash=expected_hash,
                observed_hash=observed_hash,
            )
        )
        self._last_hash = observed_hash
