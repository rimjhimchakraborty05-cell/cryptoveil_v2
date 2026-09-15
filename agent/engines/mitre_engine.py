"""
mitre_engine.py — MITRE ATT&CK rule DSL evaluator + live process graph.

Subscribes to sensor.process.spawned events, evaluates every spawn against
the rule set loaded from process_rules.json (editable without code changes,
per README), and publishes MitreAlertEvent for any match.

Also maintains an in-memory process ancestry graph (nodes + edges) for the
dashboard's live graph panel and the GET /api/process/graph endpoint.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..bus.event_bus import EventBroker
from ..bus.events import (
    EventSeverity,
    MitreAlertEvent,
    ProcessSpawnedEvent,
    ProcessTerminatedEvent,
)

log = logging.getLogger("cryptoveil.engines.mitre")

SEVERITY_MAP = {
    "critical": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
}


class MitreEngine:
    def __init__(self, broker: EventBroker, rules_path: str | Path) -> None:
        self._broker = broker
        self._rules_path = Path(rules_path)
        self._rules: list[dict[str, Any]] = []
        self._graph_nodes: dict[int, dict] = {}
        self._graph_edges: list[dict] = []
        self.reload_rules()

    def reload_rules(self) -> None:
        with open(self._rules_path, encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        allowed = {
            "process_name_in",
            "parent_name_in",
            "parent_name_not_in",
            "exe_path_not_contains",
            "cmdline_regex",
        }
        seen = set()
        if not isinstance(rules, list) or len(rules) > 128:
            raise ValueError("Rules must be a list containing at most 128 entries")
        for rule in rules:
            if not isinstance(rule, dict) or any(
                not isinstance(rule.get(key), str) or not rule[key]
                for key in ("id", "mitre_id", "mitre_name", "description")
            ):
                raise ValueError("Each rule needs an ID, MITRE technique, name and description")
            if rule["id"] in seen or rule.get("severity", "high") not in SEVERITY_MAP:
                raise ValueError("Rule IDs must be unique and severity must be recognised")
            seen.add(rule["id"])
            conditions = rule.get("conditions")
            if not isinstance(conditions, dict) or not conditions or set(conditions) - allowed:
                raise ValueError(f"Unsupported or empty conditions in {rule['id']}")
            for key, value in conditions.items():
                if key == "cmdline_regex":
                    if not isinstance(value, str) or not 0 < len(value) <= 512:
                        raise ValueError(
                            "Command pattern must be a nonempty string of at most 512 characters"
                        )
                    re.compile(value, re.IGNORECASE)
                elif (
                    not isinstance(value, list)
                    or not value
                    or any(not isinstance(item, str) or not item for item in value)
                ):
                    raise ValueError(f"{key} requires a nonempty list of strings")
        self._rules = rules
        log.info("MitreEngine loaded %d rules from %s", len(self._rules), self._rules_path)

    def attach(self) -> None:
        self._broker.subscribe("sensor.process.spawned", self._on_spawn)
        self._broker.subscribe("sensor.process.terminated", self._on_terminate)

    async def _on_spawn(self, event: ProcessSpawnedEvent) -> None:
        self._graph_nodes[event.pid] = {
            "pid": event.pid,
            "name": event.name,
            "exe": event.exe,
            "ppid": event.ppid,
            "flagged": False,
            "rule_id": None,
        }
        if event.ppid:
            self._graph_edges.append({"from": event.ppid, "to": event.pid})

        for rule in self._rules:
            if self._matches(rule["conditions"], event):
                self._graph_nodes[event.pid]["flagged"] = True
                self._graph_nodes[event.pid]["rule_id"] = rule["id"]
                await self._broker.publish(
                    MitreAlertEvent(
                        severity=SEVERITY_MAP.get(rule.get("severity", "high"), EventSeverity.HIGH),
                        mitre_id=rule["mitre_id"],
                        mitre_name=rule["mitre_name"],
                        description=rule["description"],
                        pid=event.pid,
                        process_name=event.name,
                        parent_name=event.parent_name,
                        cmdline=event.cmdline,
                        rule_id=rule["id"],
                    )
                )
                log.warning("MITRE match %s (%s) pid=%s", rule["id"], rule["mitre_id"], event.pid)
                break  # first matching rule wins; avoids duplicate alerts per spawn

    async def _on_terminate(self, event: ProcessTerminatedEvent) -> None:
        self._graph_nodes.pop(event.pid, None)
        self._graph_edges = [
            e for e in self._graph_edges if e["from"] != event.pid and e["to"] != event.pid
        ]

    @staticmethod
    def _matches(conditions: dict[str, Any], event: ProcessSpawnedEvent) -> bool:
        name = event.name.lower()
        parent = event.parent_name.lower()
        exe_path = event.exe.lower()
        cmdline = event.cmdline

        if "process_name_in" in conditions:
            allowed = {v.lower() for v in conditions["process_name_in"]}
            if name not in allowed:
                return False

        if "parent_name_in" in conditions:
            allowed = {v.lower() for v in conditions["parent_name_in"]}
            if parent not in allowed:
                return False

        if "parent_name_not_in" in conditions:
            excluded = {v.lower() for v in conditions["parent_name_not_in"]}
            if not parent or parent in excluded:
                return False

        if "exe_path_not_contains" in conditions:
            # Masquerading rule: the exe path must NOT contain any of the
            # expected system directories for this to be a match.
            expected_substrings = conditions["exe_path_not_contains"]
            if not exe_path or any(sub.lower() in exe_path for sub in expected_substrings):
                return False

        return (
            "cmdline_regex" not in conditions
            or re.search(conditions["cmdline_regex"], cmdline, re.IGNORECASE) is not None
        )

    def graph(self) -> dict:
        return {"nodes": list(self._graph_nodes.values()), "edges": self._graph_edges}
