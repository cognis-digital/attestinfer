"""Model-identity commitment.

An attestation binds an answer to a *specific* model. We commit to the model by
hashing its weight file(s). For large sharded models we hash each shard and then
Merkle/stream-fold the shard hashes into one 32-byte ``model_id`` so re-hashing a
20 GB checkpoint isn't required to *verify* provenance — the verifier only needs
the committed ``model_id`` and (optionally) the shard list to re-derive it.

IMPORTANT (see THREAT_MODEL.md): hashing the weights proves *which* weights the
attester claims to have used. It does NOT prove the model actually executed the
forward pass that produced the output. That gap requires zkML or a TEE and is
explicitly out of scope.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

_CHUNK = 1 << 20  # 1 MiB streaming read


def hash_file(path: str) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            d.update(b)
    return d.digest()


@dataclass(frozen=True)
class ModelIdentity:
    model_id: bytes  # 32-byte commitment folding all shards + params
    name: str
    shards: tuple[tuple[str, str], ...]  # (relative-name, shard-hash-hex), ordered
    params: dict  # architecture/quant metadata folded into the id

    @property
    def model_id_hex(self) -> str:
        return self.model_id.hex()

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id_hex,
            "name": self.name,
            "shards": [list(s) for s in self.shards],
            "params": self.params,
        }


def _fold(name: str, shards: list[tuple[str, str]], params: dict) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    d.update(b"attestinfer/model/v1\x00")
    d.update(name.encode("utf-8"))
    d.update(b"\x00")
    for sname, shex in shards:
        d.update(sname.encode("utf-8"))
        d.update(b"\x00")
        d.update(bytes.fromhex(shex))
    # params folded canonically (sorted keys, str values)
    for k in sorted(params):
        d.update(k.encode("utf-8"))
        d.update(b"=")
        d.update(str(params[k]).encode("utf-8"))
        d.update(b"\x00")
    return d.digest()


def commit_model(name: str, weight_paths: list[str], params: dict | None = None) -> ModelIdentity:
    """Commit a model to a ``model_id`` by hashing each weight file in order."""
    params = dict(params or {})
    shards: list[tuple[str, str]] = []
    for p in weight_paths:
        shards.append((os.path.basename(p), hash_file(p).hex()))
    mid = _fold(name, shards, params)
    return ModelIdentity(mid, name, tuple(shards), params)


def commit_model_from_hashes(
    name: str, shard_hashes: list[tuple[str, str]], params: dict | None = None
) -> ModelIdentity:
    """Commit from precomputed ``(shard_name, hash_hex)`` pairs (no file access)."""
    params = dict(params or {})
    mid = _fold(name, list(shard_hashes), params)
    return ModelIdentity(mid, name, tuple(shard_hashes), params)


def recompute_model_id(d: dict) -> bytes:
    """Recompute a ``model_id`` from a transcript's model dict (for verification)."""
    shards = [(s[0], s[1]) for s in d["shards"]]
    return _fold(d["name"], shards, d.get("params", {}))
