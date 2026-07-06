"""attest / verify / disclose — the public API.

``attest`` produces a signed :class:`Transcript` for one inference.
``verify`` checks integrity (hash chain), the signature, and internal
consistency, reporting *exactly which* check failed.
``disclose`` and ``verify_disclosure`` implement selective revelation of a single
retrieved chunk against the committed corpus root.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import signing
from .canonical import canonical_bytes
from .corpus import CorpusManifest
from .merkle import MerkleProof, verify_proof, hash_content
from .model import ModelIdentity, recompute_model_id
from .signing import KeyPair
from .transcript import (
    Transcript,
    RetrievedChunk,
    compute_chain_head,
    _hash_text,
    FORMAT,
)


def _normalize_decoding(decoding: dict) -> dict:
    """Force decoding params into canonical str/int form (no floats in signed body)."""
    out: dict = {}
    for k, v in decoding.items():
        if isinstance(v, float):
            out[k] = repr(v)  # stable textual form, e.g. "0.7"
        elif isinstance(v, bool):
            out[k] = str(v)
        else:
            out[k] = v
    return out


def attest(
    *,
    keypair: KeyPair,
    model: ModelIdentity,
    corpus: CorpusManifest,
    prompt: str,
    decoding: dict,
    retrieved_ids: list[str],
    output: str,
    include_prompt: bool = False,
    include_output: bool = True,
    timestamp: int | None = None,
    nonce: bytes = b"",
) -> Transcript:
    """Produce a signed transcript for an inference.

    ``retrieved_ids`` are the chunk ids the model was grounded in (order matters).
    Their content hashes are pulled from the committed corpus; contents are never
    embedded. Set ``include_prompt`` / ``include_output`` to embed cleartext.
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    retrieved: list[RetrievedChunk] = []
    for cid in retrieved_ids:
        idx = corpus.index_of(cid)
        ch = corpus.content_hash(cid).hex()
        retrieved.append(RetrievedChunk(cid, ch, idx))

    decoding = _normalize_decoding(decoding)
    prompt_hash = _hash_text(prompt)
    output_hash = _hash_text(output)
    nonce_hex = nonce.hex()

    chain_head = compute_chain_head(
        model.model_id_hex,
        corpus.root_hex,
        prompt_hash,
        decoding,
        retrieved,
        output_hash,
        ts,
        nonce_hex,
    )

    t = Transcript(
        format=FORMAT,
        model=model.to_dict(),
        corpus_root=corpus.root_hex,
        prompt_hash=prompt_hash,
        decoding=decoding,
        retrieved=retrieved,
        output_hash=output_hash,
        timestamp=ts,
        chain_head=chain_head,
        public_key=keypair.public_hex,
        signature="",
        prompt=prompt if include_prompt else None,
        output=output if include_output else None,
        nonce=nonce_hex,
    )
    sig = keypair.sign(canonical_bytes(t.signed_body()))
    t.signature = sig.hex()
    return t


@dataclass
class VerifyResult:
    ok: bool
    checks: dict  # check-name -> bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def verify(transcript: Transcript, expected_public_key: str | None = None) -> VerifyResult:
    """Verify a transcript. Returns which checks passed and the first failure."""
    checks: dict = {}

    checks["format"] = transcript.format == FORMAT

    # 1. model_id is consistent with its shard/param commitment
    try:
        recomputed_mid = recompute_model_id(transcript.model).hex()
        checks["model_id_consistent"] = recomputed_mid == transcript.model["model_id"]
    except Exception:
        checks["model_id_consistent"] = False

    # 2. embedded cleartext (if present) matches its hash
    if transcript.prompt is not None:
        checks["prompt_matches_hash"] = _hash_text(transcript.prompt) == transcript.prompt_hash
    if transcript.output is not None:
        checks["output_matches_hash"] = _hash_text(transcript.output) == transcript.output_hash

    # 3. hash chain recomputes to the recorded head (detects ANY field tamper)
    try:
        recomputed_head = compute_chain_head(
            transcript.model["model_id"],
            transcript.corpus_root,
            transcript.prompt_hash,
            transcript.decoding,
            transcript.retrieved,
            transcript.output_hash,
            transcript.timestamp,
            transcript.nonce,
        )
        checks["chain_head"] = recomputed_head == transcript.chain_head
    except Exception:
        checks["chain_head"] = False

    # 4. signature over canonical signed body
    try:
        body = canonical_bytes(transcript.signed_body())
        pub = bytes.fromhex(transcript.public_key)
        sig = bytes.fromhex(transcript.signature)
        checks["signature"] = signing.verify(pub, body, sig)
    except Exception:
        checks["signature"] = False

    # 5. optional pinned-key check
    if expected_public_key is not None:
        checks["expected_public_key"] = transcript.public_key == expected_public_key

    first_fail = next((k for k, v in checks.items() if not v), "")
    ok = first_fail == ""
    reason = "" if ok else f"check failed: {first_fail}"
    return VerifyResult(ok=ok, checks=checks, reason=reason)


@dataclass
class Disclosure:
    chunk_id: str
    content: str  # revealed cleartext
    proof: MerkleProof
    corpus_root: str  # hex, the root the proof is against

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "content": self.content,
            "proof": self.proof.to_dict(),
            "corpus_root": self.corpus_root,
        }

    @staticmethod
    def from_dict(d: dict) -> "Disclosure":
        return Disclosure(
            chunk_id=d["chunk_id"],
            content=d["content"],
            proof=MerkleProof.from_dict(d["proof"]),
            corpus_root=d["corpus_root"],
        )


def disclose(corpus: CorpusManifest, chunk_id: str) -> Disclosure:
    """Reveal one chunk's content + a Merkle inclusion proof against the root."""
    proof = corpus.build_proof(chunk_id)
    content = corpus._contents[chunk_id].decode("utf-8", "surrogateescape")
    return Disclosure(chunk_id, content, proof, corpus.root_hex)


@dataclass
class DisclosureResult:
    ok: bool
    checks: dict
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def verify_disclosure(disclosure: Disclosure, transcript: Transcript) -> DisclosureResult:
    """Verify a disclosed chunk is (a) inside the committed corpus root and
    (b) exactly the chunk the transcript said was retrieved.
    """
    checks: dict = {}

    # the disclosure's root must match the transcript's committed root
    checks["root_matches_transcript"] = disclosure.corpus_root == transcript.corpus_root

    # revealed content must hash to the proof's content hash
    revealed_hash = hash_content(disclosure.content.encode("utf-8", "surrogateescape"))
    checks["content_matches_proof"] = revealed_hash == disclosure.proof.content_hash

    # Merkle inclusion against the committed root
    checks["merkle_inclusion"] = verify_proof(
        bytes.fromhex(disclosure.corpus_root), disclosure.proof
    )

    # the disclosed chunk must be one the transcript claimed to retrieve,
    # with matching content hash and index (binds disclosure to the attestation)
    match = next(
        (
            rc
            for rc in transcript.retrieved
            if rc.chunk_id == disclosure.chunk_id
            and rc.content_hash == disclosure.proof.content_hash.hex()
            and rc.index == disclosure.proof.index
        ),
        None,
    )
    checks["chunk_in_transcript"] = match is not None

    first_fail = next((k for k, v in checks.items() if not v), "")
    ok = first_fail == ""
    reason = "" if ok else f"check failed: {first_fail}"
    return DisclosureResult(ok=ok, checks=checks, reason=reason)
