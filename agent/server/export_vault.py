"""Local owner step-up authorization for exporting signed forensic evidence.

This is an export gate for a single-user desktop app, not a multi-user RBAC
system and not encryption at rest. It protects download APIs even if the UI
is bypassed. The passphrase is never persisted, and the short-lived token
is only kept in memory.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path

from ..forensics.storage import atomic_write, canonical, decode_object

MIN_LENGTH = 16
MAX_LENGTH = 128
TOKEN_LIFETIME_SECONDS = 300
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


class VaultAccessError(ValueError):
    """A vault setup/unlock attempt could not be authorized."""


class EvidenceExportVault:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "evidence_export_owner.json"
        self._lock = threading.RLock()
        self._record = decode_object(self.path.read_bytes()) if self.path.exists() else None
        if self._record is not None and (
            not isinstance(self._record, dict)
            or self._record.get("scheme") != "scrypt-v1"
            or not isinstance(self._record.get("salt"), str)
            or not isinstance(self._record.get("digest"), str)
            or len(bytes.fromhex(self._record["salt"])) != 16
            or len(bytes.fromhex(self._record["digest"])) != 32
        ):
            raise VaultAccessError("Export authorization record is malformed; preserve it for review")
        self._token_digest: bytes | None = None
        self._expiry = 0.0
        self._failures: list[float] = []

    @property
    def configured(self) -> bool:
        return self._record is not None

    @staticmethod
    def _derive(passphrase: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
        )

    def _issue(self) -> dict:
        token = secrets.token_urlsafe(32)
        self._token_digest = hashlib.sha256(token.encode("utf-8")).digest()
        self._expiry = time.monotonic() + TOKEN_LIFETIME_SECONDS
        return {"token": token, "expires_in_seconds": TOKEN_LIFETIME_SECONDS}

    def configure(self, passphrase: str) -> dict:
        with self._lock:
            if self.configured:
                raise VaultAccessError("An evidence export passphrase is already configured")
            if not MIN_LENGTH <= len(passphrase) <= MAX_LENGTH:
                raise VaultAccessError("Choose an owner passphrase between 16 and 128 characters")
            salt = secrets.token_bytes(16)
            record = {
                "scheme": "scrypt-v1",
                "salt": salt.hex(),
                "digest": self._derive(passphrase, salt).hex(),
            }
            atomic_write(self.path, canonical(record))
            self._record = record
            return self._issue()

    def unlock(self, passphrase: str) -> dict:
        with self._lock:
            if not self.configured:
                raise VaultAccessError("Configure an owner passphrase before exporting evidence")
            now = time.monotonic()
            self._failures = [t for t in self._failures if now - t < LOCKOUT_SECONDS]
            if len(self._failures) >= MAX_ATTEMPTS:
                raise VaultAccessError("Too many attempts. Wait one minute before trying again")
            salt = bytes.fromhex(self._record["salt"])
            derived = self._derive(passphrase, salt)
            if not hmac.compare_digest(derived, bytes.fromhex(self._record["digest"])):
                self._failures.append(now)
                raise VaultAccessError("Incorrect owner passphrase")
            self._failures.clear()
            return self._issue()

    def authorized(self, token: str) -> bool:
        with self._lock:
            if not token or self._token_digest is None or time.monotonic() >= self._expiry:
                return False
            return hmac.compare_digest(
                hashlib.sha256(token.encode("utf-8")).digest(), self._token_digest
            )

    def lock(self) -> None:
        with self._lock:
            self._token_digest = None
            self._expiry = 0.0
