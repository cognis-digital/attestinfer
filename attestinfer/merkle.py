"""Merkle commitment over a private corpus.

The corpus (the retrievable knowledge an inference is grounded in) is committed
to a single 32-byte root. A verifier who holds only the root can later be shown
*one* chunk plus a short inclusion proof and confirm that chunk was part of the
committed set — without the holder ever revealing the rest of the corpus. This
is the selective-disclosure property attestinfer needs.

Design choices (all matter for security; see THREAT_MODEL.md):

* Leaves and internal nodes use **domain-separated** BLAKE2b so a leaf digest can
  never be reinterpreted as an internal node (second-preimage / node-substitution
  resistance, per RFC 6962-style tagging).
* Odd nodes are **promoted** (not duplicated) up a level. Duplicating the last
  node enables a known forgery (CVE-2012-2459 class); promotion avoids it.
* A leaf commits to ``index || chunk_id || content_hash`` so a proof binds a
  chunk to its *position*, preventing reordering or duplication attacks.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

_LEAF = b"\x00"  # domain separation tags
_NODE = b"\x01"


def _h(*parts: bytes) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    for p in parts:
        d.update(p)
    return d.digest()


def hash_content(data: bytes) -> bytes:
    """Content hash of a raw chunk payload (32 bytes)."""
    return hashlib.blake2b(data, digest_size=32).digest()


def leaf_hash(index: int, chunk_id: str, content_hash: bytes) -> bytes:
    """Position-binding leaf digest. ``content_hash`` is :func:`hash_content`."""
    return _h(_LEAF, index.to_bytes(8, "big"), chunk_id.encode("utf-8"), b"\x00", content_hash)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _h(_NODE, left, right)


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the path to the root. ``is_right`` marks which side it is on."""

    hash: bytes
    is_right: bool


@dataclass(frozen=True)
class MerkleProof:
    index: int
    chunk_id: str
    content_hash: bytes
    steps: tuple[ProofStep, ...]

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "chunk_id": self.chunk_id,
            "content_hash": self.content_hash.hex(),
            "steps": [{"hash": s.hash.hex(), "is_right": s.is_right} for s in self.steps],
        }

    @staticmethod
    def from_dict(d: dict) -> "MerkleProof":
        return MerkleProof(
            index=d["index"],
            chunk_id=d["chunk_id"],
            content_hash=bytes.fromhex(d["content_hash"]),
            steps=tuple(ProofStep(bytes.fromhex(s["hash"]), s["is_right"]) for s in d["steps"]),
        )


class MerkleTree:
    """A Merkle tree over an ordered list of leaves.

    Build with :meth:`from_chunks`, read :attr:`root`, and produce inclusion
    proofs with :meth:`proof`.
    """

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            # Empty corpus: a well-defined sentinel root so the format is total.
            self._levels = [[_h(_LEAF, b"EMPTY")]]
            return
        levels = [list(leaves)]
        while len(levels[-1]) > 1:
            cur = levels[-1]
            nxt = []
            for i in range(0, len(cur), 2):
                if i + 1 < len(cur):
                    nxt.append(_node_hash(cur[i], cur[i + 1]))
                else:
                    nxt.append(cur[i])  # promote odd node unchanged
            levels.append(nxt)
        self._levels = levels

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, index: int) -> tuple[ProofStep, ...]:
        steps: list[ProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                sib = idx + 1
                if sib < len(level):
                    steps.append(ProofStep(level[sib], is_right=True))
                # else: promoted node, no sibling at this level
            else:
                steps.append(ProofStep(level[idx - 1], is_right=False))
            idx //= 2
        return tuple(steps)

    @classmethod
    def from_chunks(cls, chunks: list[tuple[str, bytes]]) -> "MerkleTree":
        """Build from ``(chunk_id, raw_content)`` pairs, preserving order."""
        leaves = [
            leaf_hash(i, cid, hash_content(data)) for i, (cid, data) in enumerate(chunks)
        ]
        return cls(leaves)


def verify_proof(root: bytes, proof: MerkleProof) -> bool:
    """Recompute the root from a proof and compare. Constant-shape, no exceptions."""
    node = leaf_hash(proof.index, proof.chunk_id, proof.content_hash)
    for step in proof.steps:
        node = _node_hash(node, step.hash) if step.is_right else _node_hash(step.hash, node)
    return node == root
