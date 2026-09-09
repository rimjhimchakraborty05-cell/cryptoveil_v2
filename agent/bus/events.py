"""
events.py — Pydantic v2 typed event models for CryptoVeil's pub/sub bus.

All inter-module communication flows exclusively through these models.
Topic naming convention:  <layer>.<category>.<subcategory>

  sensor.*          — raw OS / browser telemetry
  engine.*          — analysis results produced by reasoning engines
  forensics.*       — audit trail checkpoints
  browser.*         — data received from the Chrome extension
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class EventSeverity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseEvent(BaseModel):
    event_id:  str           = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float         = Field(
        default_factory=lambda: datetime.now(timezone.utc).timestamp()
    )
    severity: EventSeverity  = EventSeverity.INFO
    source:   str            = "unknown"
    topic:    str            = "event.base"

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Sensor events
# ---------------------------------------------------------------------------

class ClipboardChangedEvent(BaseEvent):
    topic:          str = "sensor.clipboard.changed"
    source:         str = "clipboard_watcher"
    content_hash:   str
    content_length: int
    was_swapped:    bool          = False
    previous_hash:  Optional[str] = None


class ClipboardSwapEvent(BaseEvent):
    topic:         str = "sensor.clipboard.swap"
    source:        str = "clipboard_watcher"
    severity:      EventSeverity = EventSeverity.HIGH
    expected_hash: str
    observed_hash: str


class FileEntropyEvent(BaseEvent):
    topic:           str = "sensor.filesystem.entropy"
    source:          str = "entropy_watcher"
    file_path:       str
    entropy:         float
    event_kind:      str   # modified | created | moved
    burst_count:     int   = 0
    burst_triggered: bool  = False


class ProcessSpawnedEvent(BaseEvent):
    topic:       str = "sensor.process.spawned"
    source:      str = "process_watcher"
    pid:         int
    name:        str
    exe:         str
    cmdline:     str
    ppid:        int
    parent_name: str
    parent_exe:  str
    username:    str
    create_time: float


class ProcessTerminatedEvent(BaseEvent):
    topic:      str = "sensor.process.terminated"
    source:     str = "process_watcher"
    pid:        int
    name:       str
    returncode: Optional[int] = None


class NetworkConnectionEvent(BaseEvent):
    topic:        str = "sensor.network.connection"
    source:       str = "network_engine"
    pid:          int
    process_name: str
    local_addr:   str
    local_port:   int
    remote_addr:  str
    remote_port:  int
    status:       str


# ---------------------------------------------------------------------------
# Engine events
# ---------------------------------------------------------------------------

class MitreAlertEvent(BaseEvent):
    topic:        str          = "engine.mitre.alert"
    source:       str          = "mitre_engine"
    severity:     EventSeverity = EventSeverity.HIGH
    mitre_id:     str
    mitre_name:   str
    description:  str
    pid:          int
    process_name: str
    parent_name:  str
    cmdline:      str
    rule_id:      str


class C2BeaconEvent(BaseEvent):
    topic:                    str          = "engine.network.c2"
    source:                   str          = "network_engine"
    severity:                 EventSeverity = EventSeverity.CRITICAL
    pid:                      int
    process_name:             str
    remote_addr:              str
    remote_port:              int
    beacon_count:             int
    avg_interval_seconds:     float
    coefficient_of_variation: float


class DgaDetectedEvent(BaseEvent):
    topic:        str          = "engine.network.dga"
    source:       str          = "network_engine"
    severity:     EventSeverity = EventSeverity.HIGH
    hostname:     str
    entropy_score: float
    vowel_ratio:  float
    digit_ratio:  float
    label_length: int
    pid:          Optional[int] = None
    process_name: Optional[str] = None


class AntiForensicEvent(BaseEvent):
    topic:           str          = "engine.antiforensic.detected"
    source:          str          = "process_watcher"
    severity:        EventSeverity = EventSeverity.CRITICAL
    pid:             int
    process_name:    str
    cmdline:         str
    matched_pattern: str


# ---------------------------------------------------------------------------
# Browser events
# ---------------------------------------------------------------------------

class BrowserTelemetryEvent(BaseEvent):
    topic:        str = "browser.telemetry"
    source:       str = "extension"
    event_kind:   str   # site_warning | shadow_ai | obfuscation | interstitial
    hostname:     Optional[str] = None
    trust_score:  Optional[int] = None
    user_email:   Optional[str] = None
    browser_name: Optional[str] = None
    detail:       dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Forensics events
# ---------------------------------------------------------------------------

class AuditCheckpointEvent(BaseEvent):
    topic:            str          = "forensics.checkpoint"
    source:           str          = "audit_logger"
    severity:         EventSeverity = EventSeverity.INFO
    checkpoint_seq:   int
    events_included:  int
    merkle_root:      str
    signature:        str
    public_key:       str


# ---------------------------------------------------------------------------
# Registry  (used for WebSocket deserialisation)
# ---------------------------------------------------------------------------

EVENT_REGISTRY: dict[str, type[BaseEvent]] = {
    "sensor.clipboard.changed":      ClipboardChangedEvent,
    "sensor.clipboard.swap":         ClipboardSwapEvent,
    "sensor.filesystem.entropy":     FileEntropyEvent,
    "sensor.process.spawned":        ProcessSpawnedEvent,
    "sensor.process.terminated":     ProcessTerminatedEvent,
    "sensor.network.connection":     NetworkConnectionEvent,
    "engine.mitre.alert":            MitreAlertEvent,
    "engine.network.c2":             C2BeaconEvent,
    "engine.network.dga":            DgaDetectedEvent,
    "engine.antiforensic.detected":  AntiForensicEvent,
    "browser.telemetry":             BrowserTelemetryEvent,
    "forensics.checkpoint":          AuditCheckpointEvent,
}
