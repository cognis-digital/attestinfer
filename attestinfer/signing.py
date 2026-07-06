"""Signing keys for attestation transcripts.

Ed25519 via the zero-dependency :mod:`attestinfer.ed25519`. If PyNaCl is present
it is used for a redundant self-check at sign time (defense against a bug in the
pure-Python path), but is never required.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from . import ed25519

try:  # optional cross-check only
    from nacl.signing import SigningKey as _NaclSK, VerifyKey as _NaclVK

    _HAVE_NACL = True
except Exception:  # pragma: no cover - environment dependent
    _HAVE_NACL = False


@dataclass(frozen=True)
class KeyPair:
    seed: bytes  # 32-byte private seed
    public: bytes  # 32-byte public key

    @staticmethod
    def generate() -> "KeyPair":
        seed = os.urandom(32)
        return KeyPair(seed, ed25519.publickey_from_seed(seed))

    @staticmethod
    def from_seed(seed: bytes) -> "KeyPair":
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return KeyPair(seed, ed25519.publickey_from_seed(seed))

    @staticmethod
    def from_seed_hex(seed_hex: str) -> "KeyPair":
        return KeyPair.from_seed(bytes.fromhex(seed_hex))

    def sign(self, msg: bytes) -> bytes:
        sig = ed25519.sign(self.seed, msg)
        if _HAVE_NACL:  # redundant self-check
            try:
                _NaclVK(self.public).verify(msg, sig)
            except Exception as exc:  # pragma: no cover
                raise RuntimeError("signature self-check against PyNaCl failed") from exc
        return sig

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    @property
    def seed_hex(self) -> str:
        return self.seed.hex()


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a signature. Uses PyNaCl too when available (both must agree)."""
    ok = ed25519.verify(public, msg, sig)
    if _HAVE_NACL:
        try:
            _NaclVK(public).verify(msg, sig)
            nacl_ok = True
        except Exception:
            nacl_ok = False
        if nacl_ok != ok:  # pragma: no cover - would indicate a real bug
            raise RuntimeError("ed25519 backends disagree on signature validity")
    return ok
