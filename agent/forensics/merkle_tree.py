"""
merkle_tree.py — RFC 6962-style Merkle tree with O(log n) inclusion proofs.

Uses the same domain-separated hashing scheme as Certificate Transparency:

    MTH({})           = SHA-256()                                   (empty tree)
    MTH({d0})         = SHA-256(0x00 || d0)                         (leaf hash)
    MTH(D[0:n])       = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                            where k is the largest power of two < n

Domain separation (the 0x00 / 0x01 prefix byte) prevents an attacker from
crafting a leaf whose hash collides with an internal node's hash — the
classic Merkle "second preimage" forgery that RFC 6962 exists specifically
to close.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1) if n > 1 else 1


@dataclass
class InclusionProof:
    leaf_index: int
    tree_size: int
    audit_path: list[str]  # hex-encoded sibling hashes


class MerkleTree:
    """An append-only Merkle tree of raw leaf byte-strings."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    def add_leaf(self, data: bytes) -> int:
        """Append a leaf, returning its 0-based index."""
        self._leaves.append(data)
        return len(self._leaves) - 1

    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        return self._mth(self._leaves)

    def root_hex(self) -> str:
        return self.root().hex()

    @classmethod
    def _mth(cls, leaves: list[bytes]) -> bytes:
        n = len(leaves)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return leaf_hash(leaves[0])
        k = _largest_power_of_two_less_than(n)
        left = cls._mth(leaves[:k])
        right = cls._mth(leaves[k:])
        return node_hash(left, right)

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if not (0 <= leaf_index < len(self._leaves)):
            raise IndexError("leaf_index out of range")
        path = self._audit_path(self._leaves, leaf_index)
        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=len(self._leaves),
            audit_path=[h.hex() for h in path],
        )

    @classmethod
    def _audit_path(cls, leaves: list[bytes], index: int) -> list[bytes]:
        n = len(leaves)
        if n <= 1:
            return []
        k = _largest_power_of_two_less_than(n)
        if index < k:
            return cls._audit_path(leaves[:k], index) + [cls._mth(leaves[k:])]
        return cls._audit_path(leaves[k:], index - k) + [cls._mth(leaves[:k])]

    @staticmethod
    def verify_inclusion_proof(
        leaf_data: bytes,
        proof: InclusionProof,
        expected_root_hex: str,
    ) -> bool:
        """
        Recompute the root from a leaf + its audit path and compare against
        the expected root. Self-contained — does not need the full tree.
        """
        # Reject impossible positions and both missing and surplus siblings.
        # Otherwise a one-leaf proof can "prove" membership at any index.
        if (
            type(proof.leaf_index) is not int
            or type(proof.tree_size) is not int
            or not isinstance(proof.audit_path, list)
            or not (0 <= proof.leaf_index < proof.tree_size <= 2**63)
        ):
            return False
        index, size, expected_length = proof.leaf_index, proof.tree_size, 0
        while size > 1:
            k = _largest_power_of_two_less_than(size)
            if index < k:
                size = k
            else:
                index, size = index - k, size - k
            expected_length += 1
        if len(proof.audit_path) != expected_length:
            return False
        try:
            path = [bytes.fromhex(h) for h in proof.audit_path]
            if len(bytes.fromhex(expected_root_hex)) != 32 or any(len(h) != 32 for h in path):
                return False
            recomputed = _rebuild_root(
                leaf_hash(leaf_data), proof.leaf_index, proof.tree_size, path
            )
            return recomputed.hex() == expected_root_hex.lower()
        except (ValueError, TypeError, IndexError):
            return False


def _rebuild_root(leaf: bytes, index: int, size: int, path: list[bytes], position=None) -> bytes:
    """
    Reconstructs the Merkle root from a leaf hash and its audit path,
    mirroring MerkleTree._audit_path's exact traversal order: the audit
    path list is built inner-recursion-first, so we must consume it from
    the END (top of the tree) inward to match.
    """
    if size <= 1:
        return leaf
    if position is None:
        position = len(path) - 1
    k = _largest_power_of_two_less_than(size)
    if index < k:
        sub_root = _rebuild_root(leaf, index, k, path, position - 1)
        return node_hash(sub_root, path[position])
    sub_root = _rebuild_root(leaf, index - k, size - k, path, position - 1)
    return node_hash(path[position], sub_root)
