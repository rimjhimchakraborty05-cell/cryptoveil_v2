"""
event_bus.py — Asynchronous Pub/Sub Event Broker.

Architectural contract (enforced here, not just documented):
  - ALL inter-module communication MUST flow through this broker.
  - Sensors PUBLISH; Engines SUBSCRIBE and PUBLISH results; Logger SUBSCRIBES to *.
  - publish() spawns handlers as asyncio Tasks — it never blocks the caller.
  - A failing handler is caught, dead-lettered, and never crashes the bus.
  - Thread-safe publish is exposed for sensors that run in OS threads.

Topic wildcards:
  broker.subscribe("*", handler)          → receives every event
  broker.subscribe("engine.*", handler)  → not yet implemented (prefix match)
  broker.subscribe("engine.mitre.alert") → exact topic match
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Awaitable, Callable

from .events import BaseEvent

log = logging.getLogger("cryptoveil.bus")

Handler = Callable[[BaseEvent], Awaitable[None]]


class EventBroker:
    """
    Central asyncio pub/sub broker.  One instance per process; injected
    into every sensor, engine, and the audit logger via their constructors.
    """

    def __init__(self) -> None:
        self._exact: dict[str, list[Handler]] = defaultdict(list)
        self._wildcard: list[Handler] = []
        self._dead_letters: list[dict] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------ #
    # Subscription management
    # ------------------------------------------------------------------ #

    def subscribe(self, topic: str, handler: Handler) -> None:
        """Register *handler* for *topic*.  Use ``"*"`` for all events."""
        if topic == "*":
            self._wildcard.append(handler)
        else:
            self._exact[topic].append(handler)
        log.debug("Subscribed %s → %s", handler.__qualname__, topic)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        if topic == "*":
            self._wildcard = [h for h in self._wildcard if h is not handler]
        else:
            self._exact[topic] = [h for h in self._exact[topic] if h is not handler]

    # ------------------------------------------------------------------ #
    # Publishing — async (call from coroutine context)
    # ------------------------------------------------------------------ #

    async def publish(self, event: BaseEvent) -> None:
        """
        Publish *event* to all matching subscribers.

        Each handler is wrapped in its own asyncio.Task so:
          • The caller is never blocked by subscriber logic.
          • A slow or crashing subscriber cannot affect others.
        """
        for handler in self._exact.get(event.topic, []) + self._wildcard:
            asyncio.create_task(self._safe_invoke(handler, event))

    # ------------------------------------------------------------------ #
    # Thread-safe publishing — for sensors running in OS threads
    # ------------------------------------------------------------------ #

    def publish_threadsafe(self, event: BaseEvent) -> None:
        """
        Schedule *publish(event)* on the running event loop from any thread.
        Call this from background sensor threads that cannot use ``await``.
        """
        loop = self._loop or asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(self.publish(event), loop)

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once at server startup to register the running loop."""
        self._loop = loop

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _safe_invoke(self, handler: Handler, event: BaseEvent) -> None:
        try:
            await handler(event)
        except Exception as exc:
            log.error(
                "Handler %s failed [topic=%s event_id=%s]: %s",
                handler.__qualname__, event.topic, event.event_id, exc,
                exc_info=True,
            )
            self._dead_letters.append({
                "handler": handler.__qualname__,
                "topic":    event.topic,
                "event_id": event.event_id,
                "error":    str(exc),
            })
            if len(self._dead_letters) > 500:
                self._dead_letters = self._dead_letters[-500:]

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #

    def stats(self) -> dict:
        return {
            "exact_subscriptions":    {t: len(h) for t, h in self._exact.items()},
            "wildcard_subscriptions": len(self._wildcard),
            "dead_letter_count":      len(self._dead_letters),
        }

    def dead_letters(self) -> list[dict]:
        return list(self._dead_letters)
