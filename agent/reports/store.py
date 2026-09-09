"""
store.py — Persists generated daily reports so they remain accessible after
an application restart, for as long as the local data store exists (per the
requirement: "until my application is active, daily reports must be
available").
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class ReportStore:
    def __init__(self, reports_dir: str | Path) -> None:
        self._dir = Path(reports_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, report: dict[str, Any]) -> None:
        path = self._dir / f"{report['date']}.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, date_str: str) -> Optional[dict[str, Any]]:
        path = self._dir / f"{date_str}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_reports(self) -> list[dict[str, Any]]:
        summaries = []
        for path in sorted(self._dir.glob("*.json"), reverse=True):
            report = json.loads(path.read_text(encoding="utf-8"))
            summary = report["executive_summary"]
            summaries.append({
                "date": report["date"],
                "total_events": summary["total_events"],
                "threats_detected": summary["threats_detected"],
                "overall_status": summary["overall_status"],
                "integrity_verified": report["forensic_integrity"]["hash_chain_verified"],
            })
        return summaries

    def exists(self, date_str: str) -> bool:
        return (self._dir / f"{date_str}.json").exists()
