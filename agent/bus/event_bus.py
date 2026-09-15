"""Async pub/sub with durable evidence delivery and bounded caller backpressure.

The audit subscriber must succeed before an event is acknowledged. Optional
subscribers are awaited and isolated; publishers cannot accumulate unlimited
fire-and-forget tasks. Filesystem threads submit work to the owning event loop.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from .events import BaseEvent

log = logging.getLogger("cryptoveil.bus")
Handler = Callable[[BaseEvent], Awaitable[object]]


class EventBroker:
    def __init__(self) -> None:
        self._exact: dict[str, list[Handler]] = defaultdict(list)
        self._wildcard: list[Handler] = []
        self._durable: Handler | None = None
        self._dead_letters: deque[dict] = deque(maxlen=100)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread_futures = set()
        self._closing = False

    def subscribe(self, topic: str, handler: Handler, *, durable: bool = False) -> None:
        if durable:
            if topic != "*" or self._durable is not None:
                raise ValueError("Exactly one durable subscriber is supported, on topic '*'")
            self._durable = handler
        elif topic == "*":
            self._wildcard.append(handler)
        else:
            self._exact[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        handlers = self._wildcard if topic == "*" else self._exact[topic]
        handlers[:] = [h for h in handlers if h != handler]

    async def publish(self, event: BaseEvent) -> dict | None:
        receipt = await self._durable(event) if self._durable else None
        if isinstance(receipt, dict) and receipt.get("duplicate"):
            return receipt
        handlers = self._exact.get(event.topic, []) + self._wildcard
        if handlers:
            await asyncio.gather(*(self._safe_invoke(handler, event) for handler in handlers))
        return receipt

    def publish_threadsafe(self, event: BaseEvent) -> None:
        if self._closing or not self._loop or not self._loop.is_running():
            return
        future = asyncio.run_coroutine_threadsafe(self.publish(event), self._loop)
        self._thread_futures.add(future)
        # The watchdog thread waits for persistence instead of queuing an
        # unbounded number of disk writes. It never blocks the asyncio loop.
        try:
            future.result(timeout=30)
        except Exception as exc:  # noqa: BLE001 - fail-safe boundary for sensor threads
            log.error("Filesystem event delivery failed: %s", exc)
            self._dead_letters.append(
                {"topic": event.topic, "event_id": event.event_id, "error": str(exc)}
            )
        finally:
            self._thread_futures.discard(future)

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def _safe_invoke(self, handler: Handler, event: BaseEvent) -> None:
        try:
            await handler(event)
        except Exception as exc:
            log.exception("Subscriber failed for %s", event.topic)
            self._dead_letters.append(
                {
                    "handler": handler.__qualname__,
                    "topic": event.topic,
                    "event_id": event.event_id,
                    "error": str(exc),
                }
            )

    async def drain(self) -> None:
        self._closing = True
        futures = list(self._thread_futures)
        if futures:
            await asyncio.gather(*(asyncio.wrap_future(f) for f in futures), return_exceptions=True)

    def stats(self) -> dict:
        return {
            "dead_letter_count": len(self._dead_letters),
            "durable_subscriber": self._durable is not None,
        }

    def dead_letters(self) -> list[dict]:
        return list(self._dead_letters)
