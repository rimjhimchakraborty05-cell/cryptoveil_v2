"""Readable, safely escaped PDF/CSV/JSON exports. JSON retains full evidence."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def to_json_bytes(report: dict) -> bytes:
    return json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode("utf-8")


def safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        "'" + text
        if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n"))
        else text
    )


def to_csv_bytes(report: dict) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "Sequence",
            "Received timestamp",
            "Severity",
            "Observation",
            "Host/process",
            "Original hash",
            "Next step",
            "Browser profile",
            "Account email label",
            "Account label source",
        ]
    )
    for e in report["evidence_index"]:
        writer.writerow(
            [
                safe_cell(e.get(k))
                for k in (
                    "seq",
                    "timestamp",
                    "severity",
                    "summary",
                    "hostname",
                    "hash",
                    "next_step",
                    "browser_name",
                    "account_email",
                    "account_source",
                )
            ]
        )
    return buffer.getvalue().encode("utf-8-sig")


def to_pdf_bytes(report: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="CryptoVeil Daily Evidence Report",
        author="CryptoVeil",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle("CVCell", fontName="Helvetica", fontSize=8, leading=11, splitLongWords=True)
    )
    styles.add(
        ParagraphStyle("CVHash", fontName="Courier", fontSize=7, leading=10, splitLongWords=True)
    )
    styles.add(
        ParagraphStyle(
            "CVHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#235b52"),
            spaceBefore=12,
            spaceAfter=7,
        )
    )

    def para(text: object, style="CVCell"):
        return Paragraph(escape(str(text)), styles[style])

    story = [
        para("CryptoVeil", "Title"),
        para("Daily evidence report", "Heading2"),
        para(
            f"{report['date']} | {report['timezone']} | {report['executive_summary']['overall_status']}"
        ),
        Spacer(1, 4 * mm),
        para(f"Generated: {report['generated_at']}"),
        para(report["time_basis"]),
    ]

    def make_table(rows, widths, header=False):
        t = Table(
            [[para(c) for c in row] for row in rows],
            colWidths=widths,
            repeatRows=1 if header else 0,
            hAlign="LEFT",
        )
        t.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce2df")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf3ef")),
                ]
            )
        )
        return t

    def table(rows, widths, header=False):
        story.append(make_table(rows, widths, header))

    for label, key in (
        ("Daily summary", "executive_summary"),
        ("Browser activity", "browser_security"),
        ("Device activity", "endpoint_security"),
    ):
        story.append(para(label, "CVHeading"))
        table(
            [
                [k.replace("_", " ").capitalize(), v]
                for k, v in report[key].items()
                if not isinstance(v, (list, dict))
            ],
            [doc.width * 0.65, doc.width * 0.35],
        )
    profiles = report["browser_security"].get("profiles", [])
    if profiles:
        story.append(para("Browser profiles observed", "CVHeading"))
        table(
            [["Browser", "Account label", "Source"]]
            + [
                [
                    p.get("browser_name") or p.get("browser_family", "Browser"),
                    p.get("account_email") or "Not shared",
                    {
                        "browser_profile": "Reported by browser",
                        "user_provided": "Manual, unverified",
                        "unavailable": "Unavailable",
                    }.get(p.get("account_source"), "Not shared"),
                ]
                for p in profiles[:50]
            ],
            [doc.width * 0.28, doc.width * 0.47, doc.width * 0.25],
            header=True,
        )
        story.append(
            para(
                "Account labels describe the paired profile and are not authenticated identity claims. Full profile history is retained in JSON."
            )
        )
    integrity = report["forensic_integrity"]
    integrity_block = [
        para("Evidence integrity at generation", "CVHeading"),
        make_table(
            [
                ["Verification", integrity["status"]],
                [
                    "Records found / expected",
                    f"{integrity['total_events']} / {integrity['expected_events']}",
                ],
                ["Signatures verified", integrity["signatures_verified"]],
                ["Violations", integrity["violation_count"]],
            ],
            [doc.width * 0.65, doc.width * 0.35],
        ),
    ]
    for label, key in (
        ("Original Merkle root", "original_root"),
        ("Recomputed Merkle root", "recomputed_root"),
        ("Pinned public key", "public_key"),
    ):
        integrity_block.extend(
            [Spacer(1, 2 * mm), para(label), para(integrity.get(key) or "Unavailable", "CVHash")]
        )
    story.append(KeepTogether(integrity_block))
    if integrity["violations"]:
        story.append(para("Evidence changes requiring investigation", "CVHeading"))
        for violation in integrity["violations"]:
            story.append(
                para(
                    f"{violation['status']} | record {violation.get('seq', '-')} | {violation.get('detail', '')}"
                )
            )
    story.append(para("Evidence index", "CVHeading"))
    selected = report["evidence_index"]
    if selected:
        # The full machine-readable evidence is included in every signed bundle.
        # Keep the PDF usable even on a day with thousands of routine events.
        alerts = [e for e in selected if e["severity"] in ("medium", "high", "critical")]
        shown = alerts[:100] if alerts else selected[-30:]
        story.append(
            para(
                f"Showing {len(shown)} of {len(selected)} events. The JSON/CSV exports contain the full daily evidence index."
            )
        )
        rows = [["Record / time", "Observation", "Severity"]]
        for e in shown:
            ts = datetime.fromtimestamp(e["timestamp"], ZoneInfo(report["timezone"])).strftime(
                "%H:%M:%S"
            )
            rows.append(
                [
                    f"#{e['seq']} / {ts}",
                    f"{e['summary']}\n{e['hostname']}\n{e['next_step']}",
                    e["severity"],
                ]
            )
        table(rows, [doc.width * 0.19, doc.width * 0.67, doc.width * 0.14], header=True)
    else:
        story.append(para("No evidence was received during this reporting day."))
    story.append(para("Scope and interpretation", "CVHeading"))
    for item in report["limitations"]:
        story.append(para(item))
        story.append(Spacer(1, 2 * mm))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#66756d"))
        canvas.drawString(
            18 * mm,
            10 * mm,
            f"CryptoVeil | {report['date']} | Verify with the signed bundle manifest",
        )
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, str(document.page))
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def export(report: dict, fmt: str) -> tuple[bytes, str, str]:
    exporters = {
        "json": (to_json_bytes, "application/json"),
        "csv": (to_csv_bytes, "text/csv"),
        "pdf": (to_pdf_bytes, "application/pdf"),
    }
    if fmt not in exporters:
        raise ValueError("Use pdf, csv or json")
    render, media_type = exporters[fmt]
    return render(report), media_type, f"cryptoveil_{report['date']}.{fmt}"
