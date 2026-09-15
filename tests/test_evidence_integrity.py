import copy
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.bus.event_bus import EventBroker
from agent.forensics.audit_logger import (
    AuditLogger,
    IntegrityError,
    entry_digest,
    merkle_root,
)
from agent.forensics.evidence_archive import EvidenceArchive
from agent.forensics.merkle_tree import InclusionProof, MerkleTree
from agent.forensics.storage import canonical


def event(index=0):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "topic": "browser.telemetry",
        "event_kind": "site_visit",
        "hostname": f"site{index}.example.test",
        "severity": "info",
    }


@pytest.fixture
def audit(tmp_path):
    result = AuditLogger(EventBroker(), tmp_path / "data", EvidenceArchive(tmp_path / "archive"), 3)
    for i in range(5):
        result.record(event(i))
    return result


def rewrite(audit, entries):
    audit._log_path.write_bytes(b"".join(canonical(e) + b"\n" for e in entries))


def read(audit):
    return [json.loads(line) for line in audit._log_path.read_bytes().splitlines()]


@pytest.mark.parametrize(
    "attack",
    [
        "edit",
        "tail",
        "middle",
        "whole",
        "empty",
        "malformed",
        "blank",
        "reorder",
        "rewrite_hashes",
        "duplicate",
        "extra_field",
    ],
)
def test_changed_or_missing_evidence_fails(audit, attack):
    entries = read(audit)
    if attack == "edit":
        entries[1]["event"]["hostname"] = "modified.test"
    elif attack == "tail":
        entries.pop()
    elif attack == "middle":
        entries.pop(2)
    elif attack == "whole":
        audit._log_path.unlink()
    elif attack == "empty":
        entries = []
    elif attack == "malformed":
        audit._log_path.write_bytes(b"{bad evidence\n")
    elif attack == "blank":
        audit._log_path.write_bytes(b"\n")
    elif attack == "reorder":
        entries[1], entries[2] = entries[2], entries[1]
    elif attack == "duplicate":
        entries.append(entries[-1])
    elif attack == "extra_field":
        entries[1]["hidden"] = "inserted data"
    elif attack == "rewrite_hashes":
        entries[1]["event"]["hostname"] = "modified.test"
        for i, e in enumerate(entries):
            e["prev_hash"] = entries[i - 1]["hash"] if i else "0" * 64
            e["hash"] = entry_digest(e)
    if attack not in ("whole", "malformed", "blank"):
        rewrite(audit, entries)
    result = audit.verify_chain()
    assert result["verified"] is False
    assert result["violation_count"] > 0
    assert result["collection_paused"] is True
    with pytest.raises(IntegrityError):
        audit.record(event())


@pytest.mark.parametrize(
    "target",
    [
        "checkpoint_metadata",
        "checkpoint_signature",
        "checkpoint_file",
        "head",
        "archive_event",
        "archive_delete",
        "pinned_key",
    ],
)
def test_baseline_and_archive_attacks_fail(audit, target):
    if target.startswith("checkpoint"):
        cp = json.loads(audit._checkpoint_path.read_text().splitlines()[0])
        if target == "checkpoint_metadata":
            cp["start_seq"] = 99
        elif target == "checkpoint_signature":
            cp["signature"] = "00" * 64
        if target == "checkpoint_file":
            audit._checkpoint_path.unlink()
        else:
            audit._checkpoint_path.write_bytes(canonical(cp) + b"\n")
    elif target == "head":
        audit.archive.head_path.unlink()
    elif target == "pinned_key":
        audit._public_path.unlink()
    elif target == "archive_event":
        path = next(audit.archive.events_dir.glob("000000000001_*.json"))
        e = json.loads(path.read_bytes())
        e["event"]["hostname"] = "forged.test"
        path.write_bytes(canonical(e))
    elif target == "archive_delete":
        next(audit.archive.events_dir.glob("000000000004_*.json")).unlink()
    assert not audit.verify_chain()["verified"]


def test_extra_archived_evidence_fails(audit):
    (audit.archive.events_dir / "999999999999_extra.json").write_bytes(b"{}")
    result = audit.verify_chain()
    assert not result["verified"]
    assert any(v["status"] == "ARCHIVE_EVIDENCE_COUNT_MISMATCH" for v in result["violations"])


@pytest.mark.parametrize("payload", [b"null", b"[]", b'"broken"', b'{"x":1,"x":2}'])
@pytest.mark.parametrize("target", ["head", "checkpoint", "event"])
def test_malformed_archive_objects_fail_closed(audit, payload, target):
    path = (
        audit.archive.head_path
        if target == "head"
        else (
            audit.archive.checkpoints_dir / "00000000.json"
            if target == "checkpoint"
            else next(audit.archive.events_dir.glob("000000000000_*.json"))
        )
    )
    path.write_bytes(payload)
    result = audit.verify_chain()
    assert not result["verified"] and result["collection_paused"]


def test_duplicate_json_keys_in_ledger_are_reported(audit):
    original = audit._log_path.read_bytes()
    audit._log_path.write_bytes(original.replace(b'"seq":0', b'"seq":9,"seq":0', 1))
    assert not audit.verify_chain()["verified"]


def test_signed_head_rollback_is_detected_during_collection(audit):
    old_head = audit.archive.head_path.read_bytes()
    audit.record(event())
    audit.archive.head_path.write_bytes(old_head)
    result = audit.verify_chain()
    assert not result["verified"]
    assert any(v["status"] == "SIGNED_HEAD_CHANGED" for v in result["violations"])


def test_new_write_cannot_silently_replace_a_deleted_head(audit):
    audit.archive.head_path.unlink()
    with pytest.raises(IntegrityError):
        audit.record(event())
    assert not audit.archive.head_path.exists()


def test_extra_archived_fields_are_reported(audit):
    path = next(audit.archive.events_dir.glob("000000000000_*.json"))
    record = json.loads(path.read_bytes())
    path.write_bytes(canonical({**record, "inserted": "unknown evidence"}))
    assert not audit.verify_chain()["verified"]


def test_restart_preserves_unsealed_tail_and_deduplicates(audit):
    original = read(audit)[-1]
    restarted = AuditLogger(EventBroker(), audit._data_dir, audit.archive, 3)
    assert restarted.stats()["pending_in_batch"] == 2
    assert restarted.verify_chain()["verified"]
    same = restarted.record({**original["event"], "timestamp": time.time() + 1})
    assert same["duplicate"] and same["seq"] == original["seq"]
    assert restarted.stats()["total_events"] == 5
    with pytest.raises(ValueError):
        restarted.record({**original["event"], "hostname": "another.test"})
    restarted.seal()
    proof = restarted.get_proof(4)
    assert restarted.verify_proof(proof, restarted.public_key)["valid"]


def test_missing_key_never_creates_new_identity(audit):
    audit._key_path.unlink()
    restarted = AuditLogger(EventBroker(), audit._data_dir, audit.archive)
    assert not restarted.last_verification["verified"]
    assert not audit._key_path.exists()


def test_truncated_file_is_detected_after_restart(audit):
    rewrite(audit, read(audit)[:-1])
    restarted = AuditLogger(EventBroker(), audit._data_dir, audit.archive)
    assert not restarted.last_verification["verified"]


def test_concurrent_recording_has_unique_contiguous_sequences(audit):
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(audit.record, [event(i) for i in range(40)]))
    assert [e["seq"] for e in read(audit)] == list(range(45))
    assert audit.verify_chain()["verified"]


def test_proof_rejects_untrusted_signer_and_metadata_change(audit):
    proof = audit.get_proof(2)
    assert audit.verify_proof(proof, audit.public_key)["valid"]
    forged = copy.deepcopy(proof)
    forged["seq"] = 99
    assert not audit.verify_proof(forged, audit.public_key)["valid"]
    forged = copy.deepcopy(proof)
    key = Ed25519PrivateKey.generate()
    cp = forged["checkpoint"]
    cp["public_key"] = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    cp["signature"] = key.sign(canonical({k: v for k, v in cp.items() if k != "signature"})).hex()
    assert not audit.verify_proof(forged, audit.public_key)["valid"]


@pytest.mark.parametrize(
    "index,size,path",
    [(99, 1, []), (-1, 1, []), (0, 0, []), (0, 1, ["00" * 32]), (0, 2, []), (0, 2, ["zz" * 32])],
)
def test_malformed_merkle_proofs_fail_without_crashing(index, size, path):
    tree = MerkleTree()
    tree.add_leaf(b"x")
    assert not tree.verify_inclusion_proof(b"x", InclusionProof(index, size, path), tree.root_hex())


def test_legacy_logs_are_imported_without_rewriting_evidence(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    archive = EvidenceArchive(tmp_path / "old_archive")
    key = Ed25519PrivateKey.generate()
    pub = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    (data / "ed25519_key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    entries = []
    for i in range(5):
        e = {"seq": i, "event": event(i), "prev_hash": entries[-1]["hash"] if entries else "0" * 64}
        e["hash"] = entry_digest(e)
        entries.append(e)
    raw = b"".join(canonical(e) + b"\n" for e in entries)
    (data / "audit_log.jsonl").write_bytes(raw)
    leaves = [e["hash"] for e in entries[:3]]
    root = merkle_root(leaves)
    cp = {
        "checkpoint_seq": 0,
        "events_included": 3,
        "start_seq": 0,
        "end_seq": 2,
        "merkle_root": root,
        "signature": key.sign(bytes.fromhex(root)).hex(),
        "public_key": pub,
        "timestamp": time.time(),
        "leaves": leaves,
    }
    (data / "checkpoints.jsonl").write_bytes(canonical(cp) + b"\n")
    archive.store_checkpoint(cp)
    archive.store_batch(entries[:3])
    migrated = AuditLogger(EventBroker(), data, archive, 3)
    assert migrated.verify_chain()["verified"]
    assert migrated.verify_chain()["legacy_checkpoints"] == 1
    assert (data / "audit_log.jsonl").read_bytes() == raw
    migrated.record(event(6))
    assert migrated.verify_chain()["verified"]
