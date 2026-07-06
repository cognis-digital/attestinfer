"""attestinfer — cryptographic provenance for grounded AI inference.

Prove that an answer was produced by a *specific* local model and grounded in a
*specific* private corpus — verifiable by a third party, without revealing the
corpus or the weights.

See THREAT_MODEL.md for exactly what this proves and, importantly, what it does
not (it is not zkML/TEE proof of execution).
"""
from __future__ import annotations

from .attest import (
    Disclosure,
    DisclosureResult,
    VerifyResult,
    attest,
    disclose,
    verify,
    verify_disclosure,
)
from .corpus import CorpusManifest, commit_corpus, commit_directory
from .model import ModelIdentity, commit_model, commit_model_from_hashes
from .signing import KeyPair
from .transcript import RetrievedChunk, Transcript

__version__ = "0.1.0"

__all__ = [
    "attest",
    "verify",
    "disclose",
    "verify_disclosure",
    "Disclosure",
    "DisclosureResult",
    "VerifyResult",
    "commit_corpus",
    "commit_directory",
    "CorpusManifest",
    "commit_model",
    "commit_model_from_hashes",
    "ModelIdentity",
    "KeyPair",
    "Transcript",
    "RetrievedChunk",
    "__version__",
]
