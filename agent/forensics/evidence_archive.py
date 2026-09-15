"""Independent evidence copies. A local directory is NOT an off-host service.

CRYPTOVEIL_ARCHIVE_DIR may point to a separately managed mounted volume.
Host separation and retention must be enforced by that volume's operator.
"""

from __future__ import annotations

from pathlib import Path

from .storage import atomic_write, canonical, decode_object, immutable_write


class EvidenceArchive:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.events_dir = self.directory / "events"
        self.checkpoints_dir = self.directory / "checkpoints"
        self.reports_dir = self.directory / "reports"
        for path in (self.events_dir, self.checkpoints_dir, self.reports_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.head_path = self.directory / "head.json"

    def store_batch(self, batch: list[dict]) -> None:
        for entry in batch:
            seq = entry["seq"]
            existing = self.retrieve_event(seq)
            if existing is not None and existing != entry:
                raise ValueError(f"Archived evidence #{seq} differs; it will not be replaced")
            if existing is None:
                path = self.events_dir / f"{seq:012d}_{entry['hash'][:12]}.json"
                immutable_write(path, canonical(entry))

    def store_checkpoint(self, checkpoint: dict) -> None:
        path = self.checkpoints_dir / f"{checkpoint['checkpoint_seq']:08d}.json"
        if path.exists():
            if decode_object(path.read_bytes()) != checkpoint:
                raise ValueError("Archived checkpoint differs; it will not be replaced")
        else:
            immutable_write(path, canonical(checkpoint))

    def event_inventory(self) -> dict[int, list[Path]]:
        inventory: dict[int, list[Path]] = {}
        for path in self.events_dir.glob("*.json"):
            prefix = path.name.split("_", 1)[0]
            seq = int(prefix) if len(prefix) == 12 and prefix.isdigit() else -1
            inventory.setdefault(seq, []).append(path)
        return inventory

    def retrieve_event(
        self, seq: int, inventory: dict[int, list[Path]] | None = None
    ) -> dict | None:
        matches = (
            inventory.get(seq, [])
            if inventory is not None
            else list(self.events_dir.glob(f"{seq:012d}_*.json"))
        )
        if len(matches) > 1:
            raise ValueError(f"Multiple archived records claim sequence #{seq}")
        return decode_object(matches[0].read_bytes()) if matches else None

    def retrieve_checkpoint(self, seq: int) -> dict | None:
        path = self.checkpoints_dir / f"{seq:08d}.json"
        return decode_object(path.read_bytes()) if path.exists() else None

    def read_head(self) -> dict | None:
        return decode_object(self.head_path.read_bytes()) if self.head_path.exists() else None

    def store_head(self, head: dict) -> None:
        atomic_write(self.head_path, canonical(head))

    def describe(self) -> dict:
        return {
            "mode": "filesystem_archive",
            "path": str(self.directory.resolve()),
            "available": self.directory.is_dir(),
            "host_separation_verified": False,
            "note": "A second local folder is a backup, not protection against full host compromise.",
        }
