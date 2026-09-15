"""
test_merkle.py — 12 unit tests for agent/forensics/merkle_tree.py

Run directly:
    python tests/test_merkle.py
"""

from __future__ import annotations

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.forensics.merkle_tree import (
    InclusionProof,
    MerkleTree,
    leaf_hash,
    node_hash,
)


class TestMerkleTree(unittest.TestCase):
    # 1
    def test_empty_tree_root_is_sha256_of_empty_string(self):
        tree = MerkleTree()
        self.assertEqual(tree.root(), hashlib.sha256(b"").digest())

    # 2
    def test_single_leaf_root_equals_leaf_hash(self):
        tree = MerkleTree()
        tree.add_leaf(b"event-0")
        self.assertEqual(tree.root(), leaf_hash(b"event-0"))

    # 3
    def test_two_leaf_root_matches_manual_computation(self):
        tree = MerkleTree()
        tree.add_leaf(b"a")
        tree.add_leaf(b"b")
        expected = node_hash(leaf_hash(b"a"), leaf_hash(b"b"))
        self.assertEqual(tree.root(), expected)

    # 4
    def test_add_leaf_returns_sequential_indices(self):
        tree = MerkleTree()
        self.assertEqual(tree.add_leaf(b"x"), 0)
        self.assertEqual(tree.add_leaf(b"y"), 1)
        self.assertEqual(tree.add_leaf(b"z"), 2)

    # 5
    def test_size_reflects_leaf_count(self):
        tree = MerkleTree()
        for i in range(7):
            tree.add_leaf(f"leaf-{i}".encode())
        self.assertEqual(tree.size(), 7)

    # 6
    def test_domain_separation_leaf_vs_node_hash(self):
        # A leaf hash of some bytes must never equal a node hash computed
        # over the same bytes split as two "children" — this is exactly the
        # second-preimage forgery RFC 6962's prefix bytes prevent.
        data = b"\x00" * 32
        left, right = data[:16], data[16:]
        self.assertNotEqual(leaf_hash(data), node_hash(left, right))

    # 7
    def test_root_changes_when_any_leaf_changes(self):
        tree_a = MerkleTree()
        tree_b = MerkleTree()
        for leaf in [b"one", b"two", b"three", b"four", b"five"]:
            tree_a.add_leaf(leaf)
        for leaf in [b"one", b"two", b"THREE-MODIFIED", b"four", b"five"]:
            tree_b.add_leaf(leaf)
        self.assertNotEqual(tree_a.root_hex(), tree_b.root_hex())

    # 8
    def test_single_leaf_inclusion_proof_has_empty_audit_path(self):
        tree = MerkleTree()
        tree.add_leaf(b"only-leaf")
        proof = tree.inclusion_proof(0)
        self.assertEqual(proof.audit_path, [])
        self.assertTrue(MerkleTree.verify_inclusion_proof(b"only-leaf", proof, tree.root_hex()))

    # 9
    def test_inclusion_proof_verifies_for_every_index_pow2_tree(self):
        tree = MerkleTree()
        leaves = [f"evt-{i}".encode() for i in range(8)]  # power-of-two size
        for leaf in leaves:
            tree.add_leaf(leaf)
        root_hex = tree.root_hex()
        for i, leaf in enumerate(leaves):
            proof = tree.inclusion_proof(i)
            self.assertTrue(MerkleTree.verify_inclusion_proof(leaf, proof, root_hex))

    # 10
    def test_inclusion_proof_verifies_for_every_index_non_pow2_tree(self):
        tree = MerkleTree()
        leaves = [f"evt-{i}".encode() for i in range(17)]  # non-power-of-two size
        for leaf in leaves:
            tree.add_leaf(leaf)
        root_hex = tree.root_hex()
        for i, leaf in enumerate(leaves):
            proof = tree.inclusion_proof(i)
            self.assertTrue(
                MerkleTree.verify_inclusion_proof(leaf, proof, root_hex),
                f"proof failed for index {i} of {len(leaves)}",
            )

    # 11
    def test_tampered_leaf_data_fails_verification(self):
        tree = MerkleTree()
        leaves = [f"evt-{i}".encode() for i in range(10)]
        for leaf in leaves:
            tree.add_leaf(leaf)
        root_hex = tree.root_hex()
        proof = tree.inclusion_proof(4)
        self.assertFalse(MerkleTree.verify_inclusion_proof(b"evt-4-TAMPERED", proof, root_hex))

    # 12
    def test_tampered_audit_path_entry_fails_verification(self):
        tree = MerkleTree()
        leaves = [f"evt-{i}".encode() for i in range(10)]
        for leaf in leaves:
            tree.add_leaf(leaf)
        root_hex = tree.root_hex()
        proof = tree.inclusion_proof(4)
        tampered_path = list(proof.audit_path)
        tampered_path[0] = "00" * 32  # corrupt one sibling hash
        bad_proof = InclusionProof(
            leaf_index=proof.leaf_index, tree_size=proof.tree_size, audit_path=tampered_path
        )
        self.assertFalse(MerkleTree.verify_inclusion_proof(leaves[4], bad_proof, root_hex))


if __name__ == "__main__":
    unittest.main(verbosity=2)
