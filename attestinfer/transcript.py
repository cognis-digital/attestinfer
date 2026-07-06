"""The attestation transcript — the core data structure.

A transcript commits, in a single signed object, to everything that determines a
grounded inference:

    model_id      commitment to the weights (see model.py)
    corpus_root   Merkle root over the private corpus (see corpus.py)
    prompt        the user/system prompt (hashed; raw prompt optional)
    decoding      sampling params (temperature-as-str, top_p-as-str, seed, max_tokens)
    retrieved     the retrieved chunks, each as (chunk_id, content_hash, merkle-index)
    output        the produced answer (hashed; raw output optional)

Integrity is enforced two ways that must agree:

  * a **hash chain**: each field digest is folded into a running digest, giving a
    single ``chain_head`` — tamper any field and the head changes;
  * an **ed25519 signature** over the canonical bytes of the signed body.

Each retrieved chunk carries its ``content_hash`` and Merkle index but NOT its
content, and the transcript records the ``corpus_root``. A verifier confirms the
answer was grounded in *committed* data (the retrieved hashes are consistent with
the recorded root once a disclosure proof is supplied) without seeing the corpus.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from . import signing
from .canonical import canonical_bytes
from .merkle import MerkleProof, verify_proof

FORMAT = "attestinfer/transcript/v1"


def _digest(*parts: bytes) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    for p in parts:
        d.update(len(p).to_bytes(8, "big"))  # length-prefix -> unambiguous framing
        d.update(p)
    return d.digest()


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    content_hash: str  # hex
    index: int  # position in the committed corpus

    def to_dict(self) -> dict:
        return {"chunk_id": self.chunk_id, "content_hash": self.content_hash, "index": self.index}


@dataclass
class Transcript:
    format: str
    model: dict  # ModelIdentity.to_dict()
    corpus_root: str  # hex
    prompt_hash: str  # hex
    decoding: dict  # canonical params (all values str/int)
    retrieved: list[RetrievedChunk]
    output_hash: str  # hex
    timestamp: int
    chain_head: str  # hex
    public_key: str  # hex
    signature: str  # hex
    # optional cleartext (may be omitted to protect confidentiality)
    prompt: str | None = None
    output: str | None = None
    nonce: str = ""  # hex, replay/domain separation

    # ---- signed body (everything that is authenticated) ----
    def signed_body(self) -> dict:
        return {
            "format": self.format,
            "model_id": self.model["model_id"],
            "model": self.model,
            "corpus_root": self.corpus_root,
            "prompt_hash": self.prompt_hash,
            "decoding": self.decoding,
            "retrieved": [c.to_dict() for c in self.retrieved],
            "output_hash": self.output_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "chain_head": self.chain_head,
        }

    def to_dict(self) -> dict:
        d = dict(self.signed_body())
        d["public_key"] = self.public_key
        d["signature"] = self.signature
        if self.prompt is not None:
            d["prompt"] = self.prompt
        if self.output is not None:
            d["output"] = self.output
        return d

    @staticmethod
    def from_dict(d: dict) -> "Transcript":
        return Transcript(
            format=d["format"],
            model=d["model"],
            corpus_root=d["corpus_root"],
            prompt_hash=d["prompt_hash"],
            decoding=d["decoding"],
            retrieved=[RetrievedChunk(c["chunk_id"], c["content_hash"], c["index"]) for c in d["retrieved"]],
            output_hash=d["output_hash"],
            timestamp=d["timestamp"],
            chain_head=d["chain_head"],
            public_key=d["public_key"],
            signature=d["signature"],
            prompt=d.get("prompt"),
            output=d.get("output"),
            nonce=d.get("nonce", ""),
        )


def _hash_text(s: str) -> str:
    return hashlib.blake2b(s.encode("utf-8"), digest_size=32).digest().hex()


def compute_chain_head(
    model_id: str,
    corpus_root: str,
    prompt_hash: str,
    decoding: dict,
    retrieved: list[RetrievedChunk],
    output_hash: str,
    timestamp: int,
    nonce: str,
) -> str:
    """Fold every committed field into a single ordered hash chain."""
    head = _digest(FORMAT.encode("utf-8"))
    head = _digest(head, bytes.fromhex(model_id))
    head = _digest(head, bytes.fromhex(corpus_root))
    head = _digest(head, bytes.fromhex(prompt_hash))
    head = _digest(head, canonical_bytes(decoding))
    for rc in retrieved:  # order-sensitive by design
        head = _digest(head, rc.chunk_id.encode("utf-8"), bytes.fromhex(rc.content_hash), rc.index.to_bytes(8, "big"))
    head = _digest(head, bytes.fromhex(output_hash))
    head = _digest(head, timestamp.to_bytes(8, "big"))
    head = _digest(head, bytes.fromhex(nonce) if nonce else b"")
    return head.hex()
