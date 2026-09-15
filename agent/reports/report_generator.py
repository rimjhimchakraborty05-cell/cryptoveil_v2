"""Daily reports from a single verified ledger snapshot, grouped by receipt time."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from ..forensics.audit_logger import AuditLogger


def day_bounds(date_str: str, timezone_name: str) -> tuple[float, float]:
    day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=ZoneInfo(timezone_name))
    if day.strftime("%Y-%m-%d") != date_str:
        raise ValueError("Date must use YYYY-MM-DD")
    start = day
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


def describe_event(event: dict) -> str:
    kind = event.get("event_kind")
    names = {
        "site_visit": "Website assessed",
        "site_warning": "Suspicious website warning",
        "shadow_ai_network": "Connection to a known AI service observed",
        "shadow_ai_iframe": "Known AI service embedded in a page",
        "shadow_ai_dom": "AI-related component added to the page",
        "sensitive_field_used": "Sensitive input used",
        "masking_activated": "Visual masking enabled",
        "masking_deactivated": "Visual masking disabled",
        "collection_gap": "Browser queue overflow reported",
        "obfuscation_triggered": "Legacy input hook activity (not a verified block)",
    }
    if kind in names:
        return names[kind]
    topics = {
        "sensor.process.spawned": "Process started",
        "sensor.process.terminated": "Process ended",
        "sensor.clipboard.changed": "Clipboard changed",
        "sensor.clipboard.swap": "Rapid wallet-address change observed",
        "sensor.filesystem.entropy": "File entropy observation",
        "sensor.network.connection": "Network connection observed",
        "engine.network.c2": "Repeated outbound connections (review required)",
        "engine.network.dga": "Unusual reverse-DNS hostname (review required)",
        "engine.antiforensic.detected": "Potential evidence-cleanup command observed",
        "engine.mitre.alert": event.get("description", "Suspicious process behaviour"),
        "engine.correlation.finding": event.get("title", "Related threat observations"),
    }
    return topics.get(event.get("topic"), "Security observation")


def next_step(event: dict) -> str:
    topic, kind = event.get("topic", ""), event.get("event_kind", "")
    if topic == "engine.correlation.finding":
        return event.get("next_action", "Review the linked evidence records.")
    if kind == "site_warning":
        return "Check the address before entering credentials. Close the page if you do not recognise it."
    if kind.startswith("shadow_ai"):
        return "Confirm that this AI service is expected before sharing sensitive information."
    if kind == "collection_gap":
        return "Keep the application running. Some browser events could not be queued; review the collection gap."
    if topic == "engine.antiforensic.detected":
        return "Preserve the report and check whether the cleanup command was authorised."
    if topic in ("engine.network.c2", "engine.network.dga"):
        return (
            "Review the process and destination. This heuristic alone does not establish malware."
        )
    if event.get("burst_triggered"):
        return "Check which application changed these files. If unexpected, disconnect the device and preserve evidence."
    if topic == "sensor.clipboard.swap":
        return "Verify the destination address before pasting or sending funds."
    if event.get("severity") in ("high", "critical"):
        return "Inspect the process details and confirm whether the activity was expected."
    return "No immediate action indicated by this observation."


def generate_report(
    audit_logger: AuditLogger, date_str: str, timezone_name: str = "Asia/Kolkata"
) -> dict:
    start, end = day_bounds(date_str, timezone_name)
    entries, integrity, checkpoints = audit_logger.snapshot()
    selected = []
    for entry in entries:
        event = entry.get("event")
        if not isinstance(event, dict):
            continue
        ts = event.get("timestamp")
        if isinstance(ts, (int, float)) and start <= ts < end:
            selected.append(entry)
    events = [e["event"] for e in selected]
    counts = Counter(e.get("severity", "info") for e in events)
    browser = [e for e in events if e.get("topic") == "browser.telemetry"]
    kinds = Counter(e.get("event_kind") for e in browser)
    alerts = [e for e in events if e.get("severity") in ("medium", "high", "critical")]
    status = (
        "REVIEW_EVIDENCE"
        if not integrity["verified"]
        else "REVIEW_ALERTS"
        if alerts
        else "NO_ALERTS_RECORDED"
    )
    public_events = [
        {
            "seq": e.get("seq"),
            "hash": e.get("hash"),
            "timestamp": e["event"].get("timestamp"),
            "severity": e["event"].get("severity", "info"),
            "summary": describe_event(e["event"]),
            "hostname": e["event"].get("hostname") or e["event"].get("process_name", ""),
            "next_step": next_step(e["event"]),
            "browser_name": e["event"].get("browser_name", ""),
            "account_email": e["event"].get("user_email") or "",
            "account_source": e["event"]
            .get("detail", {})
            .get("profile_context", {})
            .get("account_source", ""),
        }
        for e in selected
    ]
    return {
        "schema_version": 2,
        "date": date_str,
        "timezone": timezone_name,
        "generated_at": datetime.now(UTC).isoformat(),
        "time_basis": "Time received by the application; browser collection time is retained separately when supplied.",
        "executive_summary": {
            "overall_status": status,
            "total_events": len(events),
            "alerts_to_review": len(alerts),
            "critical_events": counts["critical"],
            "high_events": counts["high"],
            "medium_events": counts["medium"],
        },
        "browser_security": {
            "events_received": len(browser),
            "sites_assessed": len({e.get("hostname") for e in browser if e.get("hostname")}),
            "website_warnings": kinds["site_warning"],
            "ai_service_observations": sum(
                kinds[k] for k in ("shadow_ai_network", "shadow_ai_iframe", "shadow_ai_dom")
            ),
            "profiles": list(
                {
                    (e.get("detail", {}).get("client_id"), e.get("user_email")): {
                        "client_id": e.get("detail", {}).get("client_id"),
                        "browser_name": e.get("browser_name"),
                        **e.get("detail", {}).get("profile_context", {}),
                    }
                    for e in browser
                }.values()
            ),
            "visual_masking_events": kinds["masking_activated"],
            "collection_gaps": kinds["collection_gap"],
        },
        "endpoint_security": {
            "suspicious_process_alerts": sum(
                e.get("topic") == "engine.mitre.alert" for e in events
            ),
            "cleanup_command_alerts": sum(
                e.get("topic") == "engine.antiforensic.detected" for e in events
            ),
            "file_burst_alerts": sum(bool(e.get("burst_triggered")) for e in events),
            "network_observations": sum(
                e.get("topic") == "sensor.network.connection" for e in events
            ),
        },
        "forensic_integrity": integrity,
        "linked_findings": [e for e in events if e.get("topic") == "engine.correlation.finding"],
        "evidence_index": public_events,
        "evidence": selected,
        "checkpoints": checkpoints,
        "limitations": [
            "Alerts are behavioural indicators and require investigation; they are not proof of an attack.",
            "Visual masking does not prevent a website or another privileged extension from reading page data.",
            "A local archive does not survive an attacker rewriting all local copies and stealing the signing key.",
            "Integrity results describe the complete ledger at report generation, not continuous protection while the app is closed.",
        ],
    }
