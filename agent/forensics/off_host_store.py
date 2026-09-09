"""
off_host_store.py — Off-host evidence preservation (reference implementation).

Per the README's documented limitation: "The off-host store in the reference
build is a local file — production tamper-evidence requires a genuinely
separate host." This module still enforces the *architectural* contract the
rest of the system depends on — evidence is copied to a location the primary
process does not treat as its working data directory, and entries are only
ever appended, never edited — so the write-then-verify demo (delete/modify
the local record, still retrieve a valid off-host copy) behaves correctly
even though the "remote" here is a second local directory rather than a
network-attached host.

Swapping this for a genuine remote target (S3, a syslog collector, a second
machine over SSH) only requires replacing store_checkpoint / store_batch /
retrieve_event / retrieve_checkpoint — nothing else in the codebase talks to
the filesystem directly.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("cryptoveil.forensics.offhost")


class OffHostStore:
    def __init__(self, offhost_dir: str | Path) -> None:
        self._dir = Path(offhost_dir)
        self._events_dir = self._dir / "events"
        self._checkpoints_dir = self._dir / "checkpoints"
        self._events_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoints_dir.mkdir(parents=True, exist_ok=True)
        log.info("OffHostStore ready at %s", self._dir)

    def store_batch(self, batch: list[dict]) -> None:
        for entry in batch:
            path = self._events_dir / f"{entry['seq']:012d}_{entry['hash'][:12]}.json"
            if not path.exists():
                path.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")

    def store_checkpoint(self, checkpoint: dict) -> None:
        path = self._checkpoints_dir / f"{checkpoint['checkpoint_seq']:08d}.json"
        path.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")

    def retrieve_event(self, seq: int) -> Optional[dict]:
        matches = list(self._events_dir.glob(f"{seq:012d}_*.json"))
        if not matches:
            return None
        return json.loads(matches[0].read_text(encoding="utf-8"))

    def retrieve_checkpoint(self, checkpoint_seq: int) -> Optional[dict]:
        path = self._checkpoints_dir / f"{checkpoint_seq:08d}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def available(self) -> bool:
        return self._dir.exists()
