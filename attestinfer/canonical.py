"""Deterministic (canonical) JSON serialization.

Signatures are taken over bytes, so two parties must agree on the *exact* byte
encoding of a transcript's signed content. We use RFC 8785-style canonical JSON:
sorted keys, no insignificant whitespace, UTF-8, and integers/strings only in the
signed payload (no floats — floats have no canonical representation).
"""
from __future__ import annotations

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical JSON bytes suitable for signing/hashing."""
    _reject_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in signed payloads (no canonical form)")
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)
