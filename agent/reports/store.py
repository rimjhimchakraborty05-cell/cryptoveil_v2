"""Versioned daily files with signed, independently copied manifests.

Previous reports are never overwritten. An export is served only after its
saved bytes verify against the original signed manifest and pinned key.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import secrets
import threading
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from ..forensics.audit_logger import AuditLogger, IntegrityError
from ..forensics.storage import canonical, decode_object, immutable_write
from .export import export
from .report_generator import day_bounds

VERSION = re.compile(r"\d{8}T\d{12}Z-[0-9a-f]{6}\Z")


def valid_date(date: str) -> str:
    day_bounds(date, "UTC")
    return date


class ReportStore:
    def __init__(self, reports_dir: str | Path, audit_logger: AuditLogger) -> None:
        self.directory = Path(reports_dir)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.audit = audit_logger
        self._lock = threading.RLock()

    def _versions(self, date: str) -> list[str]:
        valid_date(date)
        archive_dir = self.audit.archive.reports_dir / date
        versions = {p.stem for p in archive_dir.glob("*.json") if VERSION.fullmatch(p.stem)}
        versions.update(
            p.name
            for p in (self.directory / date).glob("*")
            if p.is_dir() and VERSION.fullmatch(p.name)
        )
        return sorted(versions)

    def dates(self) -> list[str]:
        candidates = {p.name if p.is_dir() else p.stem for p in self.directory.iterdir()}
        candidates.update(p.name for p in self.audit.archive.reports_dir.iterdir())
        dates = []
        for value in candidates:
            try:
                dates.append(valid_date(value))
            except ValueError:
                pass
        return sorted(dates, reverse=True)

    def save(self, report: dict, formats: tuple[str, ...] = ("pdf", "csv", "json")) -> dict:
        with self._lock:
            date = valid_date(report["date"])
            version = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(3)
            directory = self.directory / date / version
            files = {}
            for fmt in dict.fromkeys(("json",) + formats):
                files[f"report.{fmt}"] = export(report, fmt)[0]
            files["evidence.jsonl"] = b"".join(canonical(e) + b"\n" for e in report["evidence"])
            files["checkpoints.json"] = canonical(report["checkpoints"])
            manifest = self.audit.sign(
                {
                    "schema_version": 2,
                    "kind": "daily_evidence_bundle",
                    "date": date,
                    "version": version,
                    "generated_at": report["generated_at"],
                    "timezone": report["timezone"],
                    "event_count": report["executive_summary"]["total_events"],
                    "evidence_verified_at_generation": report["forensic_integrity"]["verified"],
                    "files": {
                        name: hashlib.sha256(data).hexdigest() for name, data in files.items()
                    },
                }
            )
            for name, data in files.items():
                immutable_write(directory / name, data)
            immutable_write(directory / "manifest.json", canonical(manifest))
            immutable_write(
                self.audit.archive.reports_dir / date / f"{version}.json", canonical(manifest)
            )
            return {"date": date, "version": version, "formats": list(formats), "saved": True}

    def verify(self, date: str, version: str | None = None) -> dict:
        with self._lock:
            result, _ = self._verify_snapshot(date, version)
            return result

    def _verify_snapshot(
        self, date: str, version: str | None = None
    ) -> tuple[dict, dict[str, bytes]]:
        """Read each file once; downloads serve exactly the bytes we verified."""
        valid_date(date)
        versions = self._versions(date)
        version = version or (versions[-1] if versions else None)
        if version is None:
            return {
                "verified": False,
                "date": date,
                "status": "NO_SIGNED_REPORT",
                "issues": ["No signed snapshot is available"],
            }, {}
        if not VERSION.fullmatch(version):
            raise ValueError("Invalid report version")
        directory = self.directory / date / version
        archive_path = self.audit.archive.reports_dir / date / f"{version}.json"
        issues = []
        signature_ok = False
        manifest = {}
        files = {}
        try:
            manifest = decode_object(archive_path.read_bytes())
            signature_ok = self.audit.verify_signature(manifest, self.audit.public_key)
            if (
                not signature_ok
                or manifest.get("date") != date
                or manifest.get("version") != version
                or manifest.get("kind") != "daily_evidence_bundle"
            ):
                issues.append("Manifest signature or identity is invalid")
            files["manifest.json"] = (directory / "manifest.json").read_bytes()
            if decode_object(files["manifest.json"]) != manifest:
                issues.append("Report manifest was modified")
        except (OSError, ValueError, TypeError):
            issues.append("Original report manifest is missing or unreadable")
        expected_files = manifest.get("files", {})
        if not isinstance(expected_files, dict) or not expected_files:
            issues.append("Manifest file inventory is invalid")
            expected_files = {}
        try:
            if directory.is_dir():
                actual_files = {p.name for p in directory.iterdir()}
                unexpected = actual_files - set(expected_files) - {"manifest.json"}
                if unexpected:
                    issues.append(
                        "Unexpected file in report bundle: " + ", ".join(sorted(unexpected))
                    )
        except OSError:
            issues.append("Report directory is unreadable")
        for name, expected_hash in expected_files.items():
            if name not in {
                "report.json",
                "report.csv",
                "report.pdf",
                "evidence.jsonl",
                "checkpoints.json",
            }:
                issues.append("Unexpected file in manifest")
                continue
            try:
                files[name] = (directory / name).read_bytes()
                actual = hashlib.sha256(files[name]).hexdigest()
                if actual != expected_hash:
                    issues.append(f"{name} was modified")
            except OSError:
                issues.append(f"{name} is missing")
        return {
            "verified": not issues,
            "signature_verified": signature_ok,
            "date": date,
            "version": version,
            "status": "VERIFIED" if not issues else "MODIFIED_OR_MISSING",
            "issues": issues,
            "evidence_verified_at_generation": manifest.get("evidence_verified_at_generation"),
            "event_count": manifest.get("event_count"),
            "generated_at": manifest.get("generated_at"),
        }, files

    def get(self, date: str) -> dict | None:
        with self._lock:
            if not self._versions(date):
                return None
            result, files = self._verify_snapshot(date)
            if not result["verified"]:
                raise IntegrityError(
                    "Report files were modified or removed: " + "; ".join(result["issues"])
                )
            return json.loads(files["report.json"])

    def list_reports(self) -> list[dict]:
        return [self.verify(date) for date in self.dates()]

    def download(self, date: str, fmt: str) -> tuple[bytes, str, str]:
        with self._lock:
            result, files = self._verify_snapshot(date)
            if not result["verified"]:
                raise IntegrityError(
                    "Report integrity failed; preserve the existing files for investigation"
                )
            if fmt == "zip":
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
                    for name, data in files.items():
                        bundle.writestr(name, data)
                return buffer.getvalue(), "application/zip", f"cryptoveil_evidence_{date}.zip"
            media_types = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}
            if fmt not in media_types:
                raise ValueError("Use pdf, csv, json or zip")
            name = f"report.{fmt}"
            if name not in files:
                raise ValueError("This format was not enabled for the saved snapshot")
            return files[name], media_types[fmt], f"cryptoveil_{date}.{fmt}"

    def exists(self, date: str) -> bool:
        return bool(self._versions(date))
