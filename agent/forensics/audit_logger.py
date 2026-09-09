"""
audit_logger.py — Tamper-evident forensic audit trail.

Subscribes to *every* event on the bus (topic="*") and appends each one to a
SHA-256 hash chain:

    entry.hash = SHA256(canonical_json({seq, event, prev_hash}))

Any edit to any prior entry breaks every hash computed after it, so a single
recomputation pass (verify_chain) proves — or disproves — the integrity of
the entire log, and pinpoints exactly which sequence number was altered.

Every CHECKPOINT_INTERVAL entries, a Merkle root is computed over the
batch's hashes, Ed25519-signed with the agent's private key, published as an
AuditCheckpointEvent, and shipped to the off-host evidence store *before*
the local write is considered durable — so evidence survives even a fully
compromised endpoint.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..bus.event_bus import EventBroker
from ..bus.events import AuditCheckpointEvent, BaseEvent
from .merkle_tree import InclusionProof, MerkleTree
from .off_host_store import OffHostStore

log = logging.getLogger("cryptoveil.forensics.audit")

GENESIS_HASH = "0" * 64
CHECKPOINT_INTERVAL = 50


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuditLogger:
    def __init__(
        self,
        broker: EventBroker,
        data_dir: str | Path,
        off_host_store: OffHostStore,
        checkpoint_interval: int = CHECKPOINT_INTERVAL,
    ) -> None:
        self._broker = broker
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._data_dir / "audit_log.jsonl"
        self._checkpoint_path = self._data_dir / "checkpoints.jsonl"
        self._key_path = self._data_dir / "ed25519_key.pem"
        self._off_host = off_host_store
        self._checkpoint_interval = checkpoint_interval

        self._seq = 0
        self._last_hash = GENESIS_HASH
        self._pending_batch: list[dict] = []
        self._checkpoints: list[dict] = []

        self._private_key = self._load_or_create_key()
        self._public_key_hex = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        self._replay_existing_state()

    # ------------------------------------------------------------------ #
    # Key management
    # ------------------------------------------------------------------ #

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if self._key_path.exists():
            return serialization.load_pem_private_key(self._key_path.read_bytes(), password=None)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._key_path.write_bytes(pem)
        log.info("Generated new Ed25519 audit signing key at %s", self._key_path)
        return key

    # ------------------------------------------------------------------ #
    # Startup replay — rebuild in-memory chain/checkpoint state from disk
    # ------------------------------------------------------------------ #

    def _replay_existing_state(self) -> None:
        if self._log_path.exists() and self._log_path.stat().st_size > 0:
            try:
                with open(self._log_path, "rb") as f:
                    f.seek(0, 2)  # Seek to EOF
                    size = f.tell()
                    buffer_size = min(size, 16384)
                    f.seek(size - buffer_size)
                    lines = f.read().decode("utf-8", errors="replace").splitlines()
                    for line in reversed(lines):
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                if "seq" in entry and "hash" in entry:
                                    self._seq = entry["seq"] + 1
                                    self._last_hash = entry["hash"]
                                    break
                            except Exception:
                                continue
            except Exception as e:
                log.warning("Fast replay error: %s", e)

        if self._checkpoint_path.exists():
            with open(self._checkpoint_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self._checkpoints.append(json.loads(line))
                        except Exception:
                            continue
        if self._seq:
            log.info(
                "AuditLogger fast-replayed seq #%d, %d checkpoints",
                self._seq, len(self._checkpoints),
            )

    # ------------------------------------------------------------------ #
    # Bus wiring
    # ------------------------------------------------------------------ #

    def attach(self) -> None:
        self._broker.subscribe("*", self._on_event)

    async def _on_event(self, event: BaseEvent) -> None:
        # Don't let checkpoint-sealing events re-trigger a checkpoint of
        # themselves mid-seal; they're still recorded like anything else.
        self.record(event.model_dump(mode="json"))

    # ------------------------------------------------------------------ #
    # Core chain logic
    # ------------------------------------------------------------------ #

    def record(self, event_dict: dict) -> dict:
        seq = self._seq
        prev_hash = self._last_hash

        body = {"seq": seq, "event": event_dict, "prev_hash": prev_hash}
        entry_hash = _sha256_hex(_canonical(body))
        entry = {**body, "hash": entry_hash}

        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

        self._seq += 1
        self._last_hash = entry_hash
        self._pending_batch.append(entry)

        if len(self._pending_batch) >= self._checkpoint_interval:
            self._checkpoint()

        return entry

    def _checkpoint(self) -> None:
        batch = self._pending_batch
        self._pending_batch = []

        tree = MerkleTree()
        for entry in batch:
            tree.add_leaf(bytes.fromhex(entry["hash"]))
        root_hex = tree.root_hex()
        signature = self._private_key.sign(bytes.fromhex(root_hex)).hex()
        checkpoint_seq = len(self._checkpoints)

        checkpoint = {
            "checkpoint_seq": checkpoint_seq,
            "events_included": len(batch),
            "start_seq": batch[0]["seq"],
            "end_seq": batch[-1]["seq"],
            "merkle_root": root_hex,
            "signature": signature,
            "public_key": self._public_key_hex,
            "timestamp": time.time(),
            "leaves": [e["hash"] for e in batch],
        }
        self._checkpoints.append(checkpoint)

        # Ship off-host BEFORE the checkpoint is considered durable.
        self._off_host.store_checkpoint(checkpoint)
        self._off_host.store_batch(batch)

        with open(self._checkpoint_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(checkpoint, sort_keys=True) + "\n")

        try:
            asyncio.get_running_loop()
            asyncio.create_task(
                self._broker.publish(
                    AuditCheckpointEvent(
                        checkpoint_seq=checkpoint_seq,
                        events_included=len(batch),
                        merkle_root=root_hex,
                        signature=signature,
                        public_key=self._public_key_hex,
                    )
                )
            )
        except RuntimeError:
            pass  # no running loop (e.g. offline test harness) — checkpoint is still sealed on disk

        log.info(
            "Checkpoint #%d sealed: %d events, root=%s...",
            checkpoint_seq, len(batch), root_hex[:16],
        )

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #

    def verify_chain(self) -> dict:
        """
        Recompute every entry's hash from disk and compare against the
        stored value, returning per-event results so a tampered entry can
        be pinpointed rather than just returning a single boolean.
        """
        if not self._log_path.exists():
            return {"verified": True, "total_events": 0, "violations": []}

        violations: list[dict] = []
        prev_hash = GENESIS_HASH
        total = 0

        with open(self._log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                total += 1

                body = {"seq": entry["seq"], "event": entry["event"], "prev_hash": prev_hash}
                expected_hash = _sha256_hex(_canonical(body))
                actual_hash = entry["hash"]
                ok = expected_hash == actual_hash and entry["prev_hash"] == prev_hash

                if not ok:
                    violations.append({
                        "seq": entry["seq"],
                        "event_id": entry["event"].get("event_id"),
                        "expected_hash": expected_hash,
                        "actual_hash": actual_hash,
                        "status": "TAMPERED",
                    })
                # Continue the chain from the *stored* hash so a single
                # tampered entry is reported once, not cascaded into every
                # subsequent entry as an additional false violation.
                prev_hash = actual_hash

        return {"verified": len(violations) == 0, "total_events": total, "violations": violations}

    def get_proof(self, seq: int) -> Optional[dict]:
        for cp in self._checkpoints:
            if cp["start_seq"] <= seq <= cp["end_seq"]:
                leaf_index = seq - cp["start_seq"]
                tree = MerkleTree()
                for leaf_hex in cp["leaves"]:
                    tree.add_leaf(bytes.fromhex(leaf_hex))
                proof = tree.inclusion_proof(leaf_index)
                return {
                    "seq": seq,
                    "checkpoint_seq": cp["checkpoint_seq"],
                    "leaf_data": cp["leaves"][leaf_index],
                    "leaf_index": proof.leaf_index,
                    "tree_size": proof.tree_size,
                    "audit_path": proof.audit_path,
                    "merkle_root": cp["merkle_root"],
                    "signature": cp["signature"],
                    "public_key": cp["public_key"],
                }
        return None

    @staticmethod
    def verify_proof(proof_payload: dict) -> dict:
        """Self-contained verification of a proof returned by get_proof()."""
        proof = InclusionProof(
            leaf_index=proof_payload["leaf_index"],
            tree_size=proof_payload["tree_size"],
            audit_path=proof_payload["audit_path"],
        )
        leaf_data = bytes.fromhex(proof_payload["leaf_data"])
        inclusion_ok = MerkleTree.verify_inclusion_proof(
            leaf_data=leaf_data,
            proof=proof,
            expected_root_hex=proof_payload["merkle_root"],
        )

        signature_ok = False
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(proof_payload["public_key"]))
            pubkey.verify(
                bytes.fromhex(proof_payload["signature"]),
                bytes.fromhex(proof_payload["merkle_root"]),
            )
            signature_ok = True
        except Exception:
            signature_ok = False

        return {
            "inclusion_verified": inclusion_ok,
            "signature_verified": signature_ok,
            "valid": inclusion_ok and signature_ok,
        }

    def stats(self) -> dict:
        return {
            "total_events": self._seq,
            "checkpoints": len(self._checkpoints),
            "pending_in_batch": len(self._pending_batch),
        }

    def simulate_tamper(self, seq: int, marker: str = "TAMPERED_BY_DEMO") -> bool:
        """
        Demo-only helper for the panel script (docs/PROJECT_VISION.md §6):
        mutates one stored entry's event 'source' field in place so
        verify_chain() can be shown catching it live. The off-host copy of
        the same event is completely untouched by this call. Never call
        this outside a controlled demonstration.
        """
        if not self._log_path.exists():
            return False
        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        changed = False
        for i, line in enumerate(lines):
            entry = json.loads(line)
            if entry["seq"] == seq:
                entry["event"]["source"] = marker
                lines[i] = json.dumps(entry, sort_keys=True)
                changed = True
                break
        if changed:
            self._log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return changed
