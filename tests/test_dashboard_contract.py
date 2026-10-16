"""Regression checks preventing duplicated or disconnected dashboard controls."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self.views: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "button" and "data-view" in attrs:
            self.views.append(attrs["data-view"])


def test_dashboard_has_unique_controls_and_distinct_views():
    parser = DashboardParser()
    parser.feed((ROOT / "dashboard" / "index.html").read_text(encoding="utf-8"))
    assert len(parser.ids) == len(set(parser.ids)), "Duplicate dashboard element IDs"
    assert parser.views == [
        "overview",
        "activity",
        "threats",
        "evidence",
        "reports",
        "lab",
    ]
    for removed in ("report-format", "demo-button", "setup-connect-browser", "setup-open-lab"):
        assert removed not in parser.ids
    assert parser.ids.count("run-integrity-simulation") == 1
    assert parser.ids.count("export-dialog") == 1
    assert parser.ids.count("vault-download") == 1


def test_dashboard_javascript_references_only_existing_elements():
    parser = DashboardParser()
    parser.feed((ROOT / "dashboard" / "index.html").read_text(encoding="utf-8"))
    source = (ROOT / "dashboard" / "js" / "dashboard.js").read_text(encoding="utf-8")
    referenced = set(re.findall(r'\$\("([^"]+)"\)', source))
    missing = referenced - set(parser.ids)
    assert not missing, f"Dashboard script references nonexistent controls: {sorted(missing)}"
