"""
export.py — Render a stored report to PDF, CSV, or JSON for download.

PDF is the primary format (panel/management review); CSV flattens the event
counts for spreadsheet analysis; JSON is the raw report for
forensic/technical follow-up.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def to_json_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(report, indent=2, sort_keys=True).encode("utf-8")


def to_csv_bytes(report: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["CryptoVeil Daily SOC Report", report["date"]])
    writer.writerow([])

    for section_title, key in [
        ("Executive Summary", "executive_summary"),
        ("Browser Security", "browser_security"),
        ("Endpoint Security", "endpoint_security"),
    ]:
        writer.writerow([section_title])
        for k, v in report[key].items():
            writer.writerow([k, v])
        writer.writerow([])

    writer.writerow(["MITRE ATT&CK Techniques"])
    writer.writerow(["technique_id", "technique_name", "detection_time", "source", "severity", "evidence_id"])
    for t in report["mitre_attack"]:
        writer.writerow([
            t["technique_id"], t["technique_name"], t["detection_time"],
            t["source"], t["severity"], t["evidence_id"],
        ])
    writer.writerow([])

    writer.writerow(["Forensic Integrity"])
    for k, v in report["forensic_integrity"].items():
        if k != "violation_details":
            writer.writerow([k, v])

    return buf.getvalue().encode("utf-8")


def to_pdf_bytes(report: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CVTitle", parent=styles["Title"], textColor=colors.HexColor("#0d1424"))
    heading_style = ParagraphStyle("CVHeading", parent=styles["Heading2"], textColor=colors.HexColor("#00647a"))

    story = [
        Paragraph("CryptoVeil &mdash; Daily SOC Report", title_style),
        Paragraph(f"Date: {report['date']} | Generated: {report['generated_at']}", styles["Normal"]),
        Spacer(1, 10 * mm),
    ]

    def kv_section(title: str, data: dict[str, Any]) -> None:
        story.append(Paragraph(title, heading_style))
        rows = [[k.replace("_", " ").title(), str(v)] for k, v in data.items() if not isinstance(v, list)]
        table = Table(rows, colWidths=[85 * mm, 85 * mm])
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef6f8")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(table)
        story.append(Spacer(1, 6 * mm))

    kv_section("Executive Summary", report["executive_summary"])
    kv_section("Browser Security", report["browser_security"])
    kv_section("Endpoint Security", report["endpoint_security"])

    story.append(Paragraph("MITRE ATT&CK Techniques Detected", heading_style))
    if report["mitre_attack"]:
        header = ["Technique", "Name", "Detected", "Severity"]
        rows = [header] + [
            [t["technique_id"], t["technique_name"], t["detection_time"][:19], t["severity"]]
            for t in report["mitre_attack"]
        ]
        table = Table(rows, colWidths=[30 * mm, 65 * mm, 45 * mm, 30 * mm])
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1424")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques detected today.", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    fi = {k: v for k, v in report["forensic_integrity"].items() if k != "violation_details"}
    kv_section("Forensic Integrity", fi)

    if report["forensic_integrity"]["violation_details"]:
        story.append(Paragraph("Integrity Violations", heading_style))
        for v in report["forensic_integrity"]["violation_details"]:
            story.append(Paragraph(
                f"seq={v['seq']} event_id={v['event_id']} status={v['status']}", styles["Normal"]
            ))

    doc.build(story)
    return buf.getvalue()


def export(report: dict[str, Any], fmt: str) -> tuple[bytes, str, str]:
    """Returns (bytes, media_type, filename)."""
    fmt = fmt.lower()
    date = report["date"]
    if fmt == "pdf":
        return to_pdf_bytes(report), "application/pdf", f"cryptoveil_report_{date}.pdf"
    if fmt == "csv":
        return to_csv_bytes(report), "text/csv", f"cryptoveil_report_{date}.csv"
    if fmt == "json":
        return to_json_bytes(report), "application/json", f"cryptoveil_report_{date}.json"
    raise ValueError(f"Unsupported export format: {fmt!r} (use pdf, csv, or json)")
