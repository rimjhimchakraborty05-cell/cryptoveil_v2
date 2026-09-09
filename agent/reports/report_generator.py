"""
report_generator.py — Aggregates a day's events into a Daily SOC Report.

Reads directly from the AuditLogger's on-disk hash chain (audit_log.jsonl) so
the report is generated from exactly the same evidence the forensic layer
verifies — the Executive Summary and the Forensic Integrity section of the
report are two views of the same data, not two separate code paths that
could silently drift apart.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ..forensics.audit_logger import AuditLogger

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _day_bounds_utc(date_str: str) -> tuple[float, float]:
    day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return day.timestamp(), (day + timedelta(days=1)).timestamp()


def generate_report(audit_logger: AuditLogger, date_str: str) -> dict[str, Any]:
    start_ts, end_ts = _day_bounds_utc(date_str)
    log_path = audit_logger._log_path  # same file the forensic layer verifies

    events: list[dict] = []
    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ev = entry["event"]
                ts = ev.get("timestamp", 0)
                if start_ts <= ts < end_ts:
                    events.append(ev)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for ev in events:
        sev = ev.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    threats_detected = sum(
        1 for ev in events
        if ev.get("topic", "").startswith("engine.") or ev.get("topic") == "sensor.clipboard.swap"
    )
    threats_blocked = sum(
        1 for ev in events
        if ev.get("topic") == "browser.telemetry"
        and ev.get("event_kind") in ("interstitial", "site_warning")
    )

    browser_events = [ev for ev in events if ev.get("topic", "").startswith("browser.")]
    sites_analyzed = {ev.get("hostname") for ev in browser_events if ev.get("hostname")}
    suspicious_sites = {
        ev.get("hostname") for ev in browser_events
        if ev.get("event_kind") == "site_warning" and ev.get("hostname")
    }
    shadow_ai_events = [ev for ev in browser_events if ev.get("event_kind") == "shadow_ai"]
    obfuscation_events = [ev for ev in browser_events if ev.get("event_kind") == "obfuscation"]

    clipboard_hijacks = [ev for ev in events if ev.get("topic") == "sensor.clipboard.swap"]
    entropy_bursts = [
        ev for ev in events
        if ev.get("topic") == "sensor.filesystem.entropy" and ev.get("burst_triggered")
    ]
    anti_forensic_events = [ev for ev in events if ev.get("topic") == "engine.antiforensic.detected"]
    c2_events = [ev for ev in events if ev.get("topic") == "engine.network.c2"]
    dga_events = [ev for ev in events if ev.get("topic") == "engine.network.dga"]
    network_anomalies = c2_events + dga_events

    mitre_events = [ev for ev in events if ev.get("topic") == "engine.mitre.alert"]
    mitre_techniques = [
        {
            "technique_id": ev.get("mitre_id"),
            "technique_name": ev.get("mitre_name"),
            "detection_time": datetime.fromtimestamp(
                ev.get("timestamp", 0), tz=timezone.utc
            ).isoformat(),
            "source": ev.get("source"),
            "severity": ev.get("severity"),
            "evidence_id": ev.get("event_id"),
        }
        for ev in mitre_events
    ]

    checkpoints_today = [
        cp for cp in audit_logger._checkpoints if start_ts <= cp["timestamp"] < end_ts
    ]

    integrity = audit_logger.verify_chain()

    if not integrity["verified"]:
        overall_status = "COMPROMISED"
    elif counts["critical"] > 0:
        overall_status = "CRITICAL_ALERTS"
    elif counts["high"] > 0:
        overall_status = "ELEVATED"
    else:
        overall_status = "NORMAL"

    return {
        "date": date_str,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "overall_status": overall_status,
            "total_events": len(events),
            "critical_events": counts["critical"],
            "high_events": counts["high"],
            "medium_events": counts["medium"],
            "low_events": counts["low"],
            "info_events": counts["info"],
            "threats_detected": threats_detected,
            "threats_blocked": threats_blocked,
            "protection_actions": len(obfuscation_events) + threats_blocked,
        },
        "browser_security": {
            "sites_analyzed": len(sites_analyzed),
            "suspicious_sites": len(suspicious_sites),
            "blocked_pages": threats_blocked,
            "sensitive_field_protection_events": len(obfuscation_events),
            "shadow_ai_detections": len(shadow_ai_events),
            "total_browser_events": len(browser_events),
        },
        "endpoint_security": {
            "suspicious_processes": len(mitre_events),
            "clipboard_hijack_attempts": len(clipboard_hijacks),
            "file_ransomware_anomalies": len(entropy_bursts),
            "anti_forensic_activity": len(anti_forensic_events),
            "network_anomalies": len(network_anomalies),
            "c2_beacon_detections": len(c2_events),
            "dga_detections": len(dga_events),
        },
        "mitre_attack": mitre_techniques,
        "forensic_integrity": {
            "total_evidence_events": integrity["total_events"],
            "events_this_report": len(events),
            "hash_chain_verified": integrity["verified"],
            "merkle_checkpoints_sealed": len(checkpoints_today),
            "digital_signatures_verified": integrity["verified"],
            "off_host_evidence_available": audit_logger._off_host.available(),
            "integrity_violations": len(integrity["violations"]),
            "violation_details": integrity["violations"],
        },
    }
