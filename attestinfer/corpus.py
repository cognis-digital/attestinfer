"""Corpus commitment.

A *corpus* is an ordered set of chunks (documents / passages the model may
retrieve from). :func:`commit_corpus` produces a manifest containing the Merkle
root and per-chunk metadata (id + content hash), plus the private mapping needed
later to build inclusion proofs. The manifest's ``root`` is the public commitment;
raw chunk contents never appear in a transcript.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .merkle import MerkleTree, MerkleProof, hash_content


@dataclass
class CorpusManifest:
    root: bytes
    # ordered list of (chunk_id, content_hash-hex); public metadata, no content
    entries: list[tuple[str, str]] = field(default_factory=list)
    # private: id -> raw bytes, kept locally to build proofs. Not serialized publicly.
    _contents: dict[str, bytes] = field(default_factory=dict, repr=False)

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def index_of(self, chunk_id: str) -> int:
        for i, (cid, _) in enumerate(self.entries):
            if cid == chunk_id:
                return i
        raise KeyError(f"unknown chunk_id: {chunk_id}")

    def build_proof(self, chunk_id: str) -> MerkleProof:
        """Build an inclusion proof for ``chunk_id`` (requires local contents)."""
        idx = self.index_of(chunk_id)
        if chunk_id not in self._contents:
            raise KeyError(f"no local content for {chunk_id}; cannot build proof")
        chunks = [(cid, self._contents[cid]) for cid, _ in self.entries]
        tree = MerkleTree.from_chunks(chunks)
        ch = hash_content(self._contents[chunk_id])
        return MerkleProof(idx, chunk_id, ch, tree.proof(idx))

    def content_hash(self, chunk_id: str) -> bytes:
        return bytes.fromhex(self.entries[self.index_of(chunk_id)][1])

    def save_public(self, path: str) -> None:
        """Write the public manifest (root + metadata, NO contents)."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"root": self.root_hex, "entries": self.entries}, f, indent=2)

    def save_private(self, path: str) -> None:
        """Write the full manifest including local contents (keep this secret)."""
        obj = {
            "root": self.root_hex,
            "entries": self.entries,
            "contents": {k: v.decode("utf-8", "surrogateescape") for k, v in self._contents.items()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)

    @staticmethod
    def load(path: str) -> "CorpusManifest":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        contents = {
            k: v.encode("utf-8", "surrogateescape") for k, v in obj.get("contents", {}).items()
        }
        return CorpusManifest(bytes.fromhex(obj["root"]), list(map(tuple, obj["entries"])), contents)


def commit_corpus(chunks: list[tuple[str, bytes]]) -> CorpusManifest:
    """Commit an ordered list of ``(chunk_id, raw_content)`` to a Merkle root."""
    ids = [c[0] for c in chunks]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate chunk_id in corpus")
    tree = MerkleTree.from_chunks(chunks)
    entries = [(cid, hash_content(data).hex()) for cid, data in chunks]
    contents = {cid: data for cid, data in chunks}
    return CorpusManifest(tree.root, entries, contents)


def commit_directory(path: str) -> CorpusManifest:
    """Commit every regular file under ``path`` as a chunk (id = relative path)."""
    chunks: list[tuple[str, bytes]] = []
    for base, _dirs, files in os.walk(path):
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            with open(full, "rb") as f:
                chunks.append((rel, f.read()))
    chunks.sort(key=lambda c: c[0])
    return commit_corpus(chunks)
