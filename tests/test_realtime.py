import asyncio
import concurrent.futures
import json
import subprocess
import sys
import time

import pytest

from agent.bus.event_bus import EventBroker
from agent.bus.events import BrowserTelemetryEvent, FileEntropyEvent, MitreAlertEvent
from agent.engines.correlation_engine import CorrelationEngine
from agent.engines.mitre_engine import MitreEngine
from agent.forensics.audit_logger import AuditLogger
from agent.forensics.evidence_archive import EvidenceArchive
from agent.sensors.process_watcher import ProcessWatcher
from agent.sensors.windows_process_events import WindowsProcessEvents, is_wmi_timeout
from agent.server.live import LiveUpdates


def process_alert():
    return MitreAlertEvent(
        mitre_id="T1059",
        mitre_name="Command interpreter",
        description="Test execution indicator",
        pid=400,
        process_name="powershell.exe",
        parent_name="chrome.exe",
        cmdline="test metadata only",
        rule_id="test",
    )


def burst():
    return FileEntropyEvent(
        file_path="test-file",
        entropy=7.9,
        event_kind="modified",
        burst_triggered=True,
        burst_count=8,
    )


def browser_event(kind="shadow_ai_dom", page="page-a", client="browser-a", age=0):
    return BrowserTelemetryEvent(
        event_kind=kind,
        hostname="work.example",
        detail={
            "collected_at_ms": int((time.time() - age) * 1000),
            "page_id": page,
            "client_id": client,
        },
    )


def test_related_findings_are_stored_with_verifiable_source_ids(tmp_path):
    async def run():
        broker = EventBroker()
        audit = AuditLogger(broker, tmp_path / "data", EvidenceArchive(tmp_path / "archive"))
        audit.attach()
        CorrelationEngine(broker).attach()
        first, second = process_alert(), burst()
        await broker.publish(first)
        await broker.publish(second)
        entries = audit.recent_entries(10)
        assert len(entries) == 3
        finding = entries[-1]["event"]
        assert finding["evidence_ids"] == [first.event_id, second.event_id]
        assert finding["correlation_basis"] == "same_host_and_time"
        assert finding["confidence"] == "indicator_requires_review"
        assert audit.verify_chain()["verified"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "other",
    [
        browser_event("sensitive_field_used", page="another"),
        browser_event("sensitive_field_used", client="another"),
        browser_event("sensitive_field_used", age=600),
    ],
)
def test_ai_and_sensitive_fields_on_different_pages_profiles_or_times_do_not_correlate(other):
    async def run():
        broker = EventBroker()
        findings = []

        async def capture(event):
            findings.append(event)

        broker.subscribe("engine.correlation.finding", capture)
        CorrelationEngine(broker).attach()
        await broker.publish(browser_event())
        await broker.publish(other)
        assert findings == []

    asyncio.run(run())


def test_same_page_ai_correlates_once_and_never_claims_a_confirmed_leak():
    async def run():
        broker = EventBroker()
        findings = []

        async def capture(event):
            findings.append(event)

        broker.subscribe("engine.correlation.finding", capture)
        CorrelationEngine(broker).attach()
        await broker.publish(browser_event())
        await broker.publish(browser_event("sensitive_field_used"))
        await broker.publish(browser_event("sensitive_field_used"))
        assert len(findings) == 1
        assert findings[0].rule_id == "ai_sensitive_page"
        assert findings[0].correlation_basis == "same_page_and_time"
        assert "does not prove" in findings[0].next_action

    asyncio.run(run())


def test_correlation_window_expires_and_old_browser_queue_is_excluded():
    async def run():
        broker = EventBroker()
        findings, clock = [], [0]

        async def capture(event):
            findings.append(event)

        broker.subscribe("engine.correlation.finding", capture)
        CorrelationEngine(broker, clock=lambda: clock[0]).attach()
        await broker.publish(process_alert())
        clock[0] = 121
        await broker.publish(burst())
        await broker.publish(browser_event(age=3600))
        assert findings == []

    asyncio.run(run())


def test_live_notifications_are_bounded_and_follow_successful_storage():
    async def run():
        broker, live = EventBroker(), LiveUpdates(max_clients=1)

        async def reject(event):
            raise OSError("disk unavailable")

        broker.subscribe("*", reject, durable=True)
        broker.subscribe("*", live.on_event)
        async with live.subscribe() as queue:
            with pytest.raises(OSError):
                await broker.publish(process_alert())
            assert queue.empty()
            for _ in range(1000):
                live.notify()
            assert queue.qsize() == 1
            assert '"revision": 1000' in live.frame()
            with pytest.raises(RuntimeError):
                async with live.subscribe():
                    pass
        async with live.subscribe() as queue:
            assert queue.empty()

    asyncio.run(run())


def test_native_and_sampled_process_observations_deduplicate_and_preserve_lineage():
    async def run():
        broker, events = EventBroker(), []

        async def capture(event):
            events.append(event)

        broker.subscribe("*", capture)
        watcher = ProcessWatcher(broker)
        parent = {"pid": 2, "name": "chrome.exe", "exe": "chrome.exe", "create_time": 90}
        info = {
            "pid": 3,
            "ppid": 2,
            "name": "powershell.exe",
            "exe": "powershell.exe",
            "cmdline": ["powershell.exe", "-NoProfile"],
            "create_time": 100,
        }
        await watcher._on_native(info, parent)
        await watcher._on_native(info, parent)
        async with watcher._lock:
            await watcher._emit_spawn(info, parent, "process_snapshot")
        assert len(events) == 1
        assert events[0].parent_name == "chrome.exe"
        assert events[0].observation_method == "windows_wmi_push"
        assert events[0].context_complete
        await watcher._on_native({**info, "create_time": 200}, {**parent, "create_time": 201})
        assert events[-1].parent_name == ""
        assert not events[-1].context_complete
        assert events[-2].topic == "sensor.process.terminated"

    asyncio.run(run())


def test_recycled_pid_does_not_supply_metadata_to_an_old_native_event(monkeypatch):
    monkeypatch.setattr(
        ProcessWatcher,
        "_read_process",
        staticmethod(lambda pid: {"pid": pid, "create_time": 999, "cmdline": ["unrelated"]}),
    )
    trace = {"pid": 5, "ppid": 4, "create_time": 123, "name": "short-lived.exe"}
    info, _ = ProcessWatcher._trace_context(trace)
    assert info == trace
    assert "cmdline" not in info


def test_only_wmi_timeout_is_treated_as_idle():
    class Error:
        hresult = -2147352567
        excepinfo = (0, None, None, None, 0, -2147209215)

    assert is_wmi_timeout(Error())
    Error.excepinfo = (0, None, None, None, 0, -2147024891)
    assert not is_wmi_timeout(Error())


def test_rule_dsl_rejects_unknown_conditions_instead_of_matching_every_process(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "bad",
                        "mitre_id": "T1059",
                        "mitre_name": "test",
                        "description": "test",
                        "conditions": {"misspelled_process_name": ["x"]},
                    }
                ]
            }
        )
    )
    with pytest.raises(ValueError, match="Unsupported"):
        MitreEngine(EventBroker(), path)


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows WMI")
def test_windows_wmi_observes_an_actual_process_start():
    received = []

    def capture(trace):
        received.append(trace)
        future = concurrent.futures.Future()
        future.set_result(None)
        return future

    source = WindowsProcessEvents(capture)
    source.start()
    child = None
    try:
        deadline = time.monotonic() + 10
        while source.status == "starting" and time.monotonic() < deadline:
            time.sleep(0.05)
        assert source.status == "active", source.last_error
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
        deadline = time.monotonic() + 10
        while (
            not any(event["pid"] == child.pid for event in received) and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert any(event["pid"] == child.pid for event in received)
    finally:
        if child:
            child.wait(timeout=5)
        source.stop()
