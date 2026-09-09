"""
ws_manager.py — Broadcast fan-out for the two WebSocket channels.

Every bus event (subscribed via topic="*") is pushed to every connected
dashboard client in real time, giving the "browser event appears almost
immediately in the dashboard" real-time bridge described in
docs/PROJECT_VISION.md. High/critical-severity events are additionally
pushed to connected extension clients as "threat_alert" pushes, matching the
shape background.js's handleAgentPush() already expects.
"""
from __future__ import annotations

import json
import logging

from fastapi import WebSocket

from ..bus.events import BaseEvent, EventSeverity

log = logging.getLogger("cryptoveil.server.ws")

ALERT_SEVERITIES = {EventSeverity.HIGH, EventSeverity.CRITICAL}


class WebSocketManager:
    def __init__(self) -> None:
        self._clients: dict[str, set[WebSocket]] = {"dashboard": set(), "extension": set()}

    async def connect(self, channel: str, ws: WebSocket) -> None:
        await ws.accept()
        self._clients[channel].add(ws)
        log.info("WebSocket connected: channel=%s total=%d", channel, len(self._clients[channel]))

    def disconnect(self, channel: str, ws: WebSocket) -> None:
        self._clients[channel].discard(ws)

    def counts(self) -> dict[str, int]:
        return {channel: len(clients) for channel, clients in self._clients.items()}

    async def broadcast_event(self, event: BaseEvent) -> None:
        await self._send_all("dashboard", event.model_dump(mode="json"))

        if event.severity in ALERT_SEVERITIES:
            push = {
                "push_type": "threat_alert",
                "topic": event.topic,
                "description": getattr(event, "description", None) or event.topic,
                "severity": event.severity.value,
            }
            await self._send_all("extension", push)

    async def _send_all(self, channel: str, payload: dict) -> None:
        text = json.dumps(payload)
        dead = []
        for ws in list(self._clients[channel]):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients[channel].discard(ws)
