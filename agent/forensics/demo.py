"""A temporary, isolated integrity demonstration. Never edits live evidence."""

import json
import time
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

from ..bus.event_bus import EventBroker
from .audit_logger import AuditLogger
from .evidence_archive import EvidenceArchive


def demonstrate_integrity() -> dict:
    with TemporaryDirectory(prefix="cryptoveil-demo-") as directory:
        base = Path(directory)
        audit = AuditLogger(EventBroker(), base / "data", EvidenceArchive(base / "archive"), 2)
        for n in range(3):
            audit.record(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": time.time(),
                    "topic": "browser.telemetry",
                    "event_kind": "site_visit",
                    "hostname": f"example{n}.test",
                }
            )
        audit.seal()
        original = audit._log_path.read_bytes()
        clean = audit.verify_chain()
        lines = original.splitlines()
        altered = json.loads(lines[1])
        altered["event"]["hostname"] = "changed.example.test"
        lines[1] = json.dumps(altered).encode()
        audit._log_path.write_bytes(b"\n".join(lines) + b"\n")
        modified = audit.verify_chain()
        audit._log_path.write_bytes(b"\n".join(original.splitlines()[:-1]) + b"\n")
        deleted = audit.verify_chain()
        audit._log_path.unlink()
        cleared = audit.verify_chain()
        return {
            "isolated": True,
            "original_root": clean["original_root"],
            "checks": [
                {
                    "scenario": "Original evidence",
                    "verified": clean["verified"],
                    "recomputed_root": clean["recomputed_root"],
                },
                {
                    "scenario": "One record modified",
                    "verified": modified["verified"],
                    "recomputed_root": modified["recomputed_root"],
                },
                {
                    "scenario": "Last record deleted",
                    "verified": deleted["verified"],
                    "recomputed_root": deleted["recomputed_root"],
                },
                {
                    "scenario": "Whole log removed",
                    "verified": cleared["verified"],
                    "recomputed_root": cleared["recomputed_root"],
                },
            ],
        }
