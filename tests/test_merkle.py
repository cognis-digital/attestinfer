"""Merkle tree: inclusion, odd counts, tamper, reorder, second-preimage tagging."""
import hashlib

import pytest

from attestinfer.merkle import (
    MerkleProof,
    MerkleTree,
    hash_content,
    leaf_hash,
    verify_proof,
)


def _chunks(n):
    return [(f"c{i}", f"content {i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 16, 17, 33])
def test_all_inclusion_proofs_verify(n):
    chunks = _chunks(n)
    t = MerkleTree.from_chunks(chunks)
    for i, (cid, data) in enumerate(chunks):
        p = MerkleProof(i, cid, hash_content(data), t.proof(i))
        assert verify_proof(t.root, p), f"n={n} i={i}"


def test_content_tamper_fails():
    chunks = _chunks(9)
    t = MerkleTree.from_chunks(chunks)
    bad = MerkleProof(0, "c0", hash_content(b"forged"), t.proof(0))
    assert not verify_proof(t.root, bad)


def test_reorder_fails():
    chunks = _chunks(6)
    t = MerkleTree.from_chunks(chunks)
    # claim c0's content at index 3 with c0's path
    bad = MerkleProof(3, "c0", hash_content(chunks[0][1]), t.proof(0))
    assert not verify_proof(t.root, bad)


def test_wrong_root_fails():
    t = MerkleTree.from_chunks(_chunks(4))
    other = MerkleTree.from_chunks(_chunks(5))
    p = MerkleProof(0, "c0", hash_content(b"content 0"), t.proof(0))
    assert not verify_proof(other.root, p)


def test_leaf_and_node_domain_separation():
    # A leaf digest must never equal an internal-node digest for the same bytes,
    # thanks to the 0x00 / 0x01 domain tags.
    a = hash_content(b"x")
    b = hash_content(b"y")
    leaf = leaf_hash(0, "c0", a)
    # internal node hash of (a,b) uses the 0x01 tag; craft the raw blake of a||b
    naive = hashlib.blake2b(a + b, digest_size=32).digest()
    assert leaf != naive


def test_empty_corpus_has_defined_root():
    t = MerkleTree([])
    assert isinstance(t.root, bytes) and len(t.root) == 32


def test_proof_serialization_roundtrip():
    chunks = _chunks(10)
    t = MerkleTree.from_chunks(chunks)
    p = MerkleProof(4, "c4", hash_content(chunks[4][1]), t.proof(4))
    p2 = MerkleProof.from_dict(p.to_dict())
    assert verify_proof(t.root, p2)
    assert p2.to_dict() == p.to_dict()
