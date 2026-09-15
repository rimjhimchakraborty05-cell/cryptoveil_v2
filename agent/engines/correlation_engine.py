"""Bounded, time-window correlation. Related observations are not causal proof."""

import time
from collections import deque

from ..bus.events import EventSeverity, ThreatFindingEvent


class CorrelationEngine:
    def __init__(self, broker, *, clock=time.monotonic, window_seconds=120):
        self.broker = broker
        self.clock = clock
        self.window = window_seconds
        self.recent = deque(maxlen=512)
        self.emitted = {}

    def attach(self):
        for topic in (
            "engine.mitre.alert",
            "engine.antiforensic.detected",
            "sensor.filesystem.entropy",
            "browser.telemetry",
        ):
            self.broker.subscribe(topic, self.on_event)

    @staticmethod
    def category(event):
        if event.topic in ("engine.mitre.alert", "engine.antiforensic.detected"):
            return "process"
        if event.topic == "sensor.filesystem.entropy" and event.burst_triggered:
            return "encryption"
        if event.topic == "browser.telemetry":
            if event.event_kind in ("shadow_ai_dom", "shadow_ai_iframe", "shadow_ai_network"):
                return "ai"
            if event.event_kind == "sensitive_field_used":
                return "sensitive"
        return None

    async def on_event(self, event):
        category = self.category(event)
        if category is None:
            return
        now = self.clock()
        while self.recent and now - self.recent[0][0] > self.window:
            self.recent.popleft()
        self.emitted = {key: ts for key, ts in self.emitted.items() if now - ts < self.window}
        # Offline browser observations are retained in the ledger, but must not
        # be joined to current process activity as if they happened now.
        if event.topic == "browser.telemetry":
            collected = event.detail.get("collected_at_ms", 0) / 1000
            if not 0 <= event.timestamp - collected <= self.window:
                return
        self.recent.append((now, category, event))
        matches = []
        for _, other_kind, other in self.recent:
            if other.event_id == event.event_id:
                continue
            kinds = {category, other_kind}
            same_page = (
                event.topic == other.topic == "browser.telemetry"
                and event.detail.get("client_id") == other.detail.get("client_id")
                and event.detail.get("page_id")
                and event.detail.get("page_id") == other.detail.get("page_id")
            )
            if kinds == {"process", "encryption"}:
                matches.append(
                    (
                        "lotl_encryption",
                        other,
                        "Suspicious execution near a file-encryption burst",
                        ["T1059", "T1486"],
                        EventSeverity.CRITICAL,
                        "Review the process and changed files. If unexpected, disconnect the device and preserve evidence.",
                    )
                )
            elif kinds == {"ai", "sensitive"} and same_page:
                matches.append(
                    (
                        "ai_sensitive_page",
                        other,
                        "AI component and sensitive input on the same page",
                        [],
                        EventSeverity.MEDIUM,
                        "Check whether this AI component is approved before entering corporate data. This does not prove the field was read.",
                    )
                )
            elif kinds == {"ai", "process"}:
                matches.append(
                    (
                        "browser_endpoint",
                        other,
                        "Browser AI activity near suspicious endpoint execution",
                        [],
                        EventSeverity.HIGH,
                        "Review both observations together. Timing alone does not establish that the browser caused the process activity.",
                    )
                )
        for rule, other, title, techniques, severity, action in matches:
            # One finding per rule and browser page/process during this window.
            browser = event if event.topic == "browser.telemetry" else other
            scope = (
                browser.detail.get("page_id", "host")
                if browser.topic == "browser.telemetry"
                else "host"
            )
            key = (
                rule,
                browser.detail.get("client_id", "host")
                if browser.topic == "browser.telemetry"
                else "host",
                scope,
            )
            if key in self.emitted:
                continue
            if len(self.emitted) >= 2048:
                self.emitted.pop(next(iter(self.emitted)))
            self.emitted[key] = now
            try:
                await self.broker.publish(
                    ThreatFindingEvent(
                        severity=severity,
                        rule_id=rule,
                        title=title,
                        next_action=action,
                        evidence_ids=[other.event_id, event.event_id],
                        mitre_ids=techniques,
                        window_seconds=self.window,
                        correlation_basis="same_page_and_time"
                        if rule == "ai_sensitive_page"
                        else "same_host_and_time",
                    )
                )
            except Exception:
                self.emitted.pop(key, None)
                raise
