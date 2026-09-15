"""Durable evidence ledger with signed Merkle checkpoints and a signed head.

The original signed hashes are never recalculated in place. Verification reads
current bytes, recomputes hashes and compares them with the signed baseline.
Missing records, malformed JSON, altered checkpoints and missing tails fail
closed. Local signatures cannot protect against theft of the signing key or
rollback of every local copy; export anchors to an independently managed host.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..bus.event_bus import EventBroker
from ..bus.events import BaseEvent
from .evidence_archive import EvidenceArchive
from .merkle_tree import InclusionProof, MerkleTree
from .storage import atomic_write, canonical, decode_object, sync_directory

log = logging.getLogger("cryptoveil.forensics")
GENESIS_HASH = "0" * 64
CHECKPOINT_INTERVAL = 50


class IntegrityError(RuntimeError):
    """Evidence must be preserved for investigation before collection resumes."""


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def entry_digest(entry: dict) -> str:
    return digest({k: entry[k] for k in ("seq", "event", "prev_hash")})


def merkle_root(hashes: list[str]) -> str:
    tree = MerkleTree()
    for value in hashes:
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("Invalid SHA-256 digest")
        tree.add_leaf(bytes.fromhex(value))
    return tree.root_hex()


class AuditLogger:
    def __init__(
        self,
        broker: EventBroker,
        data_dir: str | Path,
        archive: EvidenceArchive,
        checkpoint_interval: int = CHECKPOINT_INTERVAL,
    ) -> None:
        if checkpoint_interval < 1:
            raise ValueError("checkpoint_interval must be positive")
        self._broker = broker
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._data_dir / "audit_log.jsonl"
        self._checkpoint_path = self._data_dir / "checkpoints.jsonl"
        self._key_path = self._data_dir / "ed25519_key.pem"
        self._public_path = self._data_dir / "ed25519_public_key.hex"
        self._marker_path = self._data_dir / "integrity_v2.marker"
        self.archive = archive
        self._checkpoint_interval = checkpoint_interval
        self._lock = threading.RLock()
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self._pending_batch: list[dict] = []
        self._checkpoints: list[dict] = []
        self._event_ids: dict[str, int] = {}
        self._private_key = None
        self.public_key = ""
        self.collection_error: str | None = None
        self._startup_errors: list[dict] = []
        self.last_verification: dict = {}
        self.migrated_legacy = False
        self._expects_anchor = self._public_path.exists() or self._marker_path.exists()
        self._load_key()
        self._replay()

    def _load_key(self) -> None:
        try:
            existing = (
                self._log_path.exists()
                or self._checkpoint_path.exists()
                or self.archive.head_path.exists()
                or self._marker_path.exists()
                or any(self.archive.events_dir.glob("*.json"))
            )
            if self._public_path.exists():
                self.public_key = self._public_path.read_text().strip()
            if self._key_path.exists():
                key = serialization.load_pem_private_key(self._key_path.read_bytes(), password=None)
                if not isinstance(key, Ed25519PrivateKey):
                    raise ValueError("Signing key is not Ed25519")
            elif existing:
                raise ValueError("Signing key is missing; existing evidence will not be re-keyed")
            else:
                key = Ed25519PrivateKey.generate()
                atomic_write(
                    self._key_path,
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ),
                )
            public = (
                key.public_key()
                .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                .hex()
            )
            pinned = os.environ.get("CRYPTOVEIL_TRUSTED_PUBLIC_KEY", self.public_key or public)
            if public != pinned or (self.public_key and public != self.public_key):
                raise ValueError("Signing key does not match the pinned verification key")
            if not self._public_path.exists():
                if self._marker_path.exists():
                    raise ValueError("Pinned verification key was deleted")
                atomic_write(self._public_path, public.encode())
            self.public_key = public
            self._private_key = key
        except (OSError, ValueError, TypeError) as exc:
            self.collection_error = str(exc)
            self._startup_errors.append({"status": "KEY_ERROR", "detail": str(exc)})

    def sign(self, payload: dict) -> dict:
        if self._private_key is None:
            raise IntegrityError("Signing key unavailable")
        body = {**payload, "public_key": self.public_key}
        return {
            **body,
            "signature": self._private_key.sign(canonical(self.signed_body(body))).hex(),
        }

    @staticmethod
    def signed_body(payload: dict) -> dict:
        # Version 3 authenticates the compact header. Its signed root commits
        # to all leaves; the stored leaf list is checked against that root.
        excluded = {"signature"}
        if payload.get("schema_version") == 3 and payload.get("kind") == "merkle_checkpoint":
            excluded.add("leaves")
        return {k: v for k, v in payload.items() if k not in excluded}

    @staticmethod
    def verify_signature(payload: dict, trusted_key: str) -> bool:
        try:
            if payload["public_key"] != trusted_key:
                return False
            body = AuditLogger.signed_body(payload)
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_key)).verify(
                bytes.fromhex(payload["signature"]), canonical(body)
            )
            return True
        except Exception:  # noqa: BLE001 - malformed/untrusted signatures fail closed
            # InvalidSignature is deliberately treated as failure, never as a
            # reason to recreate the baseline.
            return False

    def _checkpoint_signature_ok(self, cp: dict) -> bool:
        if cp.get("schema_version") in (2, 3):
            return self.verify_signature(cp, self.public_key)
        # Preserve v2.0 logs, whose signatures covered only the root. Their
        # weaker metadata binding is surfaced explicitly in the result.
        try:
            if cp["public_key"] != self.public_key:
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key)).verify(
                bytes.fromhex(cp["signature"]), bytes.fromhex(cp["merkle_root"])
            )
            return True
        except Exception:  # noqa: BLE001 - malformed legacy signatures fail closed
            return False

    @staticmethod
    def _read_jsonl(path: Path, issues: list[dict], label: str) -> list[dict]:
        records = []
        if not path.exists():
            return records
        try:
            with path.open("rb") as stream:
                for line_number, line in enumerate(stream, 1):
                    try:
                        value = decode_object(line)
                        records.append(value)
                    except (TypeError, ValueError, UnicodeError):
                        issues.append(
                            {
                                "status": "MALFORMED_RECORD",
                                "file": label,
                                "line": line_number,
                                "detail": "Evidence could not be decoded",
                            }
                        )
        except OSError as exc:
            issues.append({"status": "UNREADABLE_FILE", "file": label, "detail": str(exc)})
        return records

    def _replay(self) -> None:
        with self._lock:
            had_anchor = self.archive.head_path.exists() or self._marker_path.exists()
            result = self.verify_chain()
            if not result["verified"]:
                return
            issues: list[dict] = []
            entries = self._read_jsonl(self._log_path, issues, "audit_log")
            self._checkpoints = self._read_jsonl(self._checkpoint_path, issues, "checkpoints")
            self._seq = len(entries)
            self._last_hash = entries[-1]["hash"] if entries else GENESIS_HASH
            self._event_ids = {e["event"]["event_id"]: e["seq"] for e in entries}
            sealed = self._checkpoints[-1]["end_seq"] + 1 if self._checkpoints else 0
            self._pending_batch = entries[sealed:]
            if had_anchor:
                self._known_head = self.archive.read_head()
            if not had_anchor:
                self.migrated_legacy = bool(entries)
                try:
                    self.archive.store_batch(entries)
                    for cp in self._checkpoints:
                        self.archive.store_checkpoint(cp)
                    self._write_head()
                    atomic_write(self._marker_path, b"CryptoVeil integrity schema 2\n")
                except (OSError, ValueError) as exc:
                    self.collection_error = f"Archive initialization failed: {exc}"
                    self._startup_errors.append({"status": "ARCHIVE_ERROR", "detail": str(exc)})
            self.verify_chain()

    def attach(self) -> None:
        self._broker.subscribe("*", self._on_event, durable=True)

    async def _on_event(self, event: BaseEvent) -> dict:
        return await asyncio.to_thread(self.record, event.model_dump(mode="json"))

    @staticmethod
    def _append(path: Path, value: dict) -> None:
        with path.open("ab") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(path.parent)

    def _write_head(self) -> None:
        if getattr(self, "_known_head", None) and self.archive.read_head() != self._known_head:
            raise ValueError("Signed head changed outside the evidence writer")
        head = self.sign(
            {
                "schema_version": 2,
                "kind": "evidence_head",
                "total_events": self._seq,
                "last_hash": self._last_hash,
                "checkpoint_count": len(self._checkpoints),
                "last_checkpoint_hash": digest(self._checkpoints[-1])
                if self._checkpoints
                else GENESIS_HASH,
                "pending_hashes": [e["hash"] for e in self._pending_batch],
            }
        )
        self.archive.store_head(head)
        self._known_head = head

    def record(self, event_dict: dict) -> dict:
        with self._lock:
            if self.collection_error:
                raise IntegrityError(self.collection_error)
            event_id = event_dict.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("A stable event_id is required for durable delivery")
            if event_id in self._event_ids:
                original = self.archive.retrieve_event(self._event_ids[event_id])
                if original is None:
                    self.collection_error = "An acknowledged evidence copy is missing"
                    raise IntegrityError(self.collection_error)
                old = {k: v for k, v in original["event"].items() if k != "timestamp"}
                new = {k: v for k, v in event_dict.items() if k != "timestamp"}
                if old != new:
                    raise ValueError("This event_id has already been used for different evidence")
                if (
                    entry_digest(original) != original["hash"]
                    or not self.verify_chain()["verified"]
                ):
                    raise IntegrityError("Previously acknowledged evidence failed verification")
                return {**original, "duplicate": True}
            body = {"seq": self._seq, "event": event_dict, "prev_hash": self._last_hash}
            entry = {**body, "hash": digest(body)}
            try:
                # No ACK is returned until all three writes are durable. If a
                # crash interrupts a write, startup reports the discrepancy;
                # it never quietly accepts a shorter evidence history.
                self.archive.store_batch([entry])
                self._append(self._log_path, entry)
                self._seq += 1
                self._last_hash = entry["hash"]
                self._pending_batch.append(entry)
                self._event_ids[event_id] = entry["seq"]
                if len(self._pending_batch) >= self._checkpoint_interval:
                    self._checkpoint()
                self._write_head()
            except (OSError, ValueError) as exc:
                self.collection_error = f"Evidence persistence failed: {exc}"
                raise IntegrityError(self.collection_error) from exc
            return entry

    def _checkpoint(self) -> None:
        if not self._pending_batch:
            return
        batch = self._pending_batch
        cp = self.sign(
            {
                "schema_version": 3,
                "kind": "merkle_checkpoint",
                "checkpoint_seq": len(self._checkpoints),
                "events_included": len(batch),
                "start_seq": batch[0]["seq"],
                "end_seq": batch[-1]["seq"],
                "merkle_root": merkle_root([e["hash"] for e in batch]),
                "previous_checkpoint_hash": digest(self._checkpoints[-1])
                if self._checkpoints
                else GENESIS_HASH,
                "timestamp": time.time(),
                "leaves": [e["hash"] for e in batch],
            }
        )
        self.archive.store_checkpoint(cp)
        self._append(self._checkpoint_path, cp)
        self._checkpoints.append(cp)
        self._pending_batch = []

    def seal(self) -> None:
        with self._lock:
            if self.collection_error:
                raise IntegrityError(self.collection_error)
            if self._pending_batch:
                try:
                    self._checkpoint()
                    self._write_head()
                except (OSError, ValueError) as exc:
                    self.collection_error = f"Checkpoint persistence failed: {exc}"
                    raise IntegrityError(self.collection_error) from exc

    def entry_by_id(self, event_id: str) -> dict | None:
        with self._lock:
            seq = self._event_ids.get(event_id)
            if seq is None:
                return None
            entry = self.archive.retrieve_event(seq)
            if entry and (
                not isinstance(entry.get("event"), dict)
                or entry["event"].get("event_id") != event_id
            ):
                raise ValueError("The archived evidence identity changed")
            return entry

    def verify_chain(self) -> dict:
        with self._lock:
            issues = list(self._startup_errors)
            entries = self._read_jsonl(self._log_path, issues, "audit_log")
            local_cps = self._read_jsonl(self._checkpoint_path, issues, "checkpoints")
            head = None
            try:
                head = self.archive.read_head()
            except (OSError, ValueError) as exc:
                issues.append({"status": "INVALID_HEAD", "detail": str(exc)})
            anchored = bool(
                head
                or self._marker_path.exists()
                or getattr(self, "_known_head", None)
                or getattr(self, "_expects_anchor", False)
            )
            signatures_ok = True
            if anchored:
                if not head or not self.verify_signature(head, self.public_key):
                    issues.append(
                        {
                            "status": "HEAD_SIGNATURE_FAILED",
                            "detail": "Signed evidence baseline is missing or invalid",
                        }
                    )
                    signatures_ok = False
                try:
                    if not self._public_path.exists():
                        issues.append({"status": "PINNED_KEY_MISSING"})
                    elif self._public_path.read_text().strip() != self.public_key:
                        issues.append({"status": "PINNED_KEY_CHANGED"})
                except (OSError, UnicodeError):
                    issues.append({"status": "PINNED_KEY_UNREADABLE"})
            known_head = getattr(self, "_known_head", None)
            if known_head and head != known_head:
                issues.append(
                    {
                        "status": "SIGNED_HEAD_CHANGED",
                        "detail": "The current baseline differs from the last acknowledged head",
                    }
                )
            reference_head = known_head or head
            expected_hashes: list[str] = []
            cp_checks = []
            previous_cp = GENESIS_HASH
            legacy = 0
            archived_cp_count = len(list(self.archive.checkpoints_dir.glob("*.json")))
            try:
                expected_cp_count = (
                    int(reference_head["checkpoint_count"])
                    if reference_head
                    else max(len(local_cps), archived_cp_count)
                )
                if not 0 <= expected_cp_count <= max(len(local_cps), archived_cp_count) + 1:
                    raise ValueError("Impossible checkpoint count")
            except (KeyError, ValueError, TypeError):
                expected_cp_count = len(local_cps)
                issues.append({"status": "INVALID_CHECKPOINT_COUNT"})
            if len(local_cps) != expected_cp_count:
                issues.append(
                    {
                        "status": "CHECKPOINTS_MISSING_OR_ADDED",
                        "expected": expected_cp_count,
                        "observed": len(local_cps),
                    }
                )
            if anchored and archived_cp_count != expected_cp_count:
                issues.append({"status": "ARCHIVE_CHECKPOINT_COUNT_MISMATCH"})
            for index in range(expected_cp_count):
                local = local_cps[index] if index < len(local_cps) else None
                try:
                    saved = self.archive.retrieve_checkpoint(index)
                    if anchored and saved is None:
                        issues.append(
                            {"status": "ARCHIVE_CHECKPOINT_MISSING", "checkpoint_seq": index}
                        )
                    cp = saved or local
                    if not cp:
                        raise ValueError("Checkpoint is missing")
                    if saved is not None and saved != local:
                        issues.append({"status": "CHECKPOINT_MODIFIED", "checkpoint_seq": index})
                    signature_ok = self._checkpoint_signature_ok(cp)
                    signatures_ok = signatures_ok and signature_ok
                    if not signature_ok:
                        issues.append(
                            {"status": "CHECKPOINT_SIGNATURE_FAILED", "checkpoint_seq": index}
                        )
                    leaves = cp["leaves"]
                    if (
                        not isinstance(leaves, list)
                        or not leaves
                        or any(
                            type(cp[k]) is not int
                            for k in ("checkpoint_seq", "start_seq", "end_seq", "events_included")
                        )
                        or cp["checkpoint_seq"] != index
                        or cp["start_seq"] != len(expected_hashes)
                        or cp["events_included"] != len(leaves)
                        or cp["end_seq"] != cp["start_seq"] + len(leaves) - 1
                        or merkle_root(leaves) != cp["merkle_root"]
                    ):
                        raise ValueError("Checkpoint range, leaves or root is inconsistent")
                    if cp.get("schema_version") in (2, 3):
                        if cp.get("previous_checkpoint_hash") != previous_cp:
                            raise ValueError("Checkpoint chain is broken")
                    else:
                        legacy += 1
                    expected_hashes.extend(leaves)
                    previous_cp = digest(cp)
                    cp_checks.append(
                        {
                            "checkpoint_seq": index,
                            "start_seq": cp["start_seq"],
                            "end_seq": cp["end_seq"],
                            "original_root": cp["merkle_root"],
                            "signature_verified": signature_ok,
                        }
                    )
                except (KeyError, ValueError, TypeError, OSError) as exc:
                    issues.append(
                        {
                            "status": "INVALID_CHECKPOINT",
                            "checkpoint_seq": index,
                            "detail": str(exc),
                        }
                    )
                    signatures_ok = False
            if reference_head:
                try:
                    if reference_head["last_checkpoint_hash"] != previous_cp:
                        issues.append({"status": "CHECKPOINT_HEAD_MISMATCH"})
                    pending = reference_head["pending_hashes"]
                    if not isinstance(pending, list) or any(
                        len(bytes.fromhex(h)) != 32 for h in pending
                    ):
                        raise ValueError("Invalid pending hashes")
                    expected_hashes.extend(pending)
                    expected_count = reference_head["total_events"]
                    if type(expected_count) is not int or expected_count != len(expected_hashes):
                        raise ValueError(
                            "Signed count does not agree with checkpoint and tail hashes"
                        )
                except (KeyError, TypeError, ValueError):
                    issues.append({"status": "INVALID_SIGNED_BASELINE"})
                    expected_count = len(expected_hashes)
            else:
                # One-time legacy import: chain validation plus all available
                # original checkpoint/archive copies. Never used after v2 initialization.
                expected_count = max(
                    len(entries), len(list(self.archive.events_dir.glob("*.json")))
                )
                expected_hashes.extend(
                    e.get("hash", GENESIS_HASH) for e in entries[len(expected_hashes) :]
                )
            event_inventory = self.archive.event_inventory()
            archived_event_count = sum(len(paths) for paths in event_inventory.values())
            if anchored and archived_event_count != expected_count:
                issues.append(
                    {
                        "status": "ARCHIVE_EVIDENCE_COUNT_MISMATCH",
                        "expected": expected_count,
                        "observed": archived_event_count,
                    }
                )
            if len(entries) != expected_count:
                issues.append(
                    {
                        "status": "EVIDENCE_MISSING_OR_ADDED",
                        "expected": expected_count,
                        "observed": len(entries),
                        "detail": "Evidence was removed, truncated or inserted",
                    }
                )
            previous_hash = GENESIS_HASH
            recomputed: list[str] = []
            seen_ids = set()
            for index, entry in enumerate(entries):
                try:
                    if set(entry) != {"seq", "event", "prev_hash", "hash"}:
                        raise ValueError("Unexpected or missing record fields")
                    event = entry["event"]
                    if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
                        raise TypeError("Invalid event object")
                    if event["event_id"] in seen_ids:
                        issues.append({"status": "DUPLICATE_EVENT_ID", "seq": index})
                    seen_ids.add(event["event_id"])
                    calculated = entry_digest(entry)
                    recomputed.append(calculated)
                    original = expected_hashes[index] if index < len(expected_hashes) else None
                    if type(entry["seq"]) is not int or entry["seq"] != index:
                        issues.append(
                            {
                                "status": "SEQUENCE_CHANGED",
                                "seq": index,
                                "observed_seq": entry["seq"],
                            }
                        )
                    if (
                        entry["prev_hash"] != previous_hash
                        or calculated != entry["hash"]
                        or (original and calculated != original)
                    ):
                        issues.append(
                            {
                                "status": "EVIDENCE_MODIFIED",
                                "seq": index,
                                "event_id": event["event_id"],
                                "original_hash": original,
                                "stored_hash": entry["hash"],
                                "recomputed_hash": calculated,
                            }
                        )
                    previous_hash = entry["hash"]
                    saved = self.archive.retrieve_event(index, event_inventory)
                    if anchored and saved is None:
                        issues.append({"status": "ARCHIVE_EVIDENCE_MISSING", "seq": index})
                    if saved is not None:
                        if entry_digest(saved) != saved["hash"] or (
                            original and saved["hash"] != original
                        ):
                            issues.append({"status": "ARCHIVE_EVIDENCE_MODIFIED", "seq": index})
                        if saved != entry:
                            issues.append({"status": "ARCHIVE_CONTENT_MISMATCH", "seq": index})
                except (KeyError, TypeError, ValueError, OSError) as exc:
                    issues.append({"status": "INVALID_EVIDENCE", "seq": index, "detail": str(exc)})
                    if len(recomputed) <= index:
                        recomputed.append(GENESIS_HASH)
            if reference_head and previous_hash != reference_head.get("last_hash"):
                issues.append(
                    {
                        "status": "TAIL_HASH_MISMATCH",
                        "detail": "Last evidence hash differs from signed baseline",
                    }
                )
            for cp in cp_checks:
                actual = recomputed[cp["start_seq"] : cp["end_seq"] + 1]
                cp["recomputed_root"] = merkle_root(actual)
                cp["matches"] = cp["recomputed_root"] == cp["original_root"]
                if not cp["matches"]:
                    issues.append({"status": "MERKLE_ROOT_MISMATCH", **cp})
            try:
                original_root = merkle_root(expected_hashes)
            except (TypeError, ValueError):
                original_root = None
                issues.append({"status": "INVALID_ORIGINAL_HASHES"})
            recomputed_root = merkle_root(recomputed)
            if original_root != recomputed_root:
                issues.append(
                    {
                        "status": "EVIDENCE_ROOT_MISMATCH",
                        "original_root": original_root,
                        "recomputed_root": recomputed_root,
                    }
                )
            verified = not issues
            if not verified:
                self.collection_error = (
                    self.collection_error
                    or "Evidence integrity failed. Preserve the files and investigate before restarting collection."
                )
            result = {
                "verified": verified,
                "status": "VERIFIED" if verified else "MODIFIED_OR_MISSING",
                "total_events": len(entries),
                "expected_events": expected_count,
                "original_root": original_root,
                "recomputed_root": recomputed_root,
                "signatures_verified": signatures_ok and bool(head) and verified,
                "checkpoint_count": expected_cp_count,
                "checkpoint_results": cp_checks[-100:],
                "legacy_checkpoints": legacy,
                "checked_at": time.time(),
                "violation_count": len(issues),
                "violations": issues[:100],
                "collection_paused": bool(self.collection_error),
                "collection_error": self.collection_error,
                "public_key": self.public_key,
                "archive": self.archive.describe(),
            }
            self.last_verification = result
            return result

    def recent_entries(self, limit: int = 100) -> list[dict]:
        with self._lock:
            if not self._log_path.exists():
                return []
            with self._log_path.open("rb") as stream:
                tail = deque(stream, maxlen=limit)
            entries = []
            for line in tail:
                try:
                    entry = json.loads(line)
                    if isinstance(entry.get("event"), dict):
                        entries.append(entry)
                except (ValueError, AttributeError):
                    pass  # The integrity result separately reports damaged records.
            return entries

    def snapshot(self) -> tuple[list[dict], dict, list[dict]]:
        """One consistent evidence/report snapshot under the writer lock."""
        with self._lock:
            integrity = self.verify_chain()
            if integrity["verified"] and not self.collection_error:
                self.seal()
                integrity = self.verify_chain()
            entries = self._read_jsonl(self._log_path, [], "audit_log")
            return entries, integrity, list(self._checkpoints)

    def get_proof(self, seq: int) -> dict | None:
        with self._lock:
            if not self.verify_chain()["verified"]:
                raise IntegrityError("Proof unavailable because the evidence failed verification")
            self.seal()
            for cp in self._checkpoints:
                if cp["start_seq"] <= seq <= cp["end_seq"]:
                    index = seq - cp["start_seq"]
                    tree = MerkleTree()
                    for value in cp["leaves"]:
                        tree.add_leaf(bytes.fromhex(value))
                    proof = tree.inclusion_proof(index)
                    return {
                        "seq": seq,
                        "checkpoint": {k: v for k, v in cp.items() if k != "leaves"}
                        if cp.get("schema_version") == 3
                        else cp,
                        "leaf_data": cp["leaves"][index],
                        "leaf_index": index,
                        "tree_size": proof.tree_size,
                        "audit_path": proof.audit_path,
                    }
            return None

    @staticmethod
    def verify_proof(payload: dict, trusted_public_key: str) -> dict:
        try:
            cp = payload["checkpoint"]
            if not isinstance(cp, dict):
                raise TypeError("Checkpoint must be an object")
            metadata_ok = (
                cp.get("schema_version") in (2, 3)
                and all(
                    type(cp[k]) is int
                    for k in ("start_seq", "end_seq", "events_included", "checkpoint_seq")
                )
                and all(type(payload[k]) is int for k in ("seq", "leaf_index", "tree_size"))
                and cp["start_seq"] >= 0
                and cp["checkpoint_seq"] >= 0
                and payload["seq"] == cp["start_seq"] + payload["leaf_index"]
                and payload["tree_size"] == cp["events_included"]
                and cp["end_seq"] == cp["start_seq"] + cp["events_included"] - 1
                and 0 <= payload["leaf_index"] < cp["events_included"]
            )
            if cp.get("schema_version") == 3:
                metadata_ok = (
                    metadata_ok and cp.get("kind") == "merkle_checkpoint" and "leaves" not in cp
                )
            else:
                metadata_ok = (
                    metadata_ok
                    and payload["tree_size"] == len(cp["leaves"])
                    and payload["leaf_data"] == cp["leaves"][payload["leaf_index"]]
                )
            inclusion_ok = MerkleTree.verify_inclusion_proof(
                bytes.fromhex(payload["leaf_data"]),
                InclusionProof(payload["leaf_index"], payload["tree_size"], payload["audit_path"]),
                cp["merkle_root"],
            )
            signature_ok = AuditLogger.verify_signature(cp, trusted_public_key)
            return {
                "valid": metadata_ok and inclusion_ok and signature_ok,
                "inclusion_verified": inclusion_ok,
                "signature_verified": signature_ok,
                "metadata_verified": metadata_ok,
                "key_trusted": cp["public_key"] == trusted_public_key,
            }
        except (KeyError, IndexError, TypeError, ValueError):
            return {"valid": False, "detail": "Malformed proof"}

    def stats(self) -> dict:
        return {
            "total_events": self._seq,
            "checkpoints": len(self._checkpoints),
            "pending_in_batch": len(self._pending_batch),
            "collection_paused": bool(self.collection_error),
        }
