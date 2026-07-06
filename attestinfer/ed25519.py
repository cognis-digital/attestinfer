"""Pure-Python Ed25519 (RFC 8032) — zero-dependency signatures.

This is a compact, standards-conformant implementation of Ed25519 so that
``attestinfer`` can sign and verify attestation transcripts with *no* native
or third-party dependency. An auditor can therefore verify a transcript on any
machine that has a stock Python interpreter, which matters for reproducibility.

If PyNaCl is installed, :mod:`attestinfer.signing` will cross-check signatures
against it, but this module is always sufficient on its own.

Derived from the reference implementation in RFC 8032, Appendix A (public
domain). It is intentionally straightforward rather than constant-time; see
THREAT_MODEL.md for the (non-)assumptions this places on the signing host.
"""
from __future__ import annotations

import hashlib

# Curve / field constants (Ed25519).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_By = (4 * pow(5, _P - 2, _P)) % _P
_Bx = 0  # recovered below


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def _sha512_int(b: bytes) -> int:
    return int.from_bytes(_sha512(b), "little")


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_Bx = _xrecover(_By)
_B = (_Bx % _P, _By % _P, 1, (_Bx * _By) % _P)  # extended coordinates (X, Y, Z, T)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    x3 = (e * f) % _P
    y3 = (g * h) % _P
    t3 = (e * h) % _P
    z3 = (f * g) % _P
    return (x3, y3, z3, t3)


def _scalarmult(p, e: int):
    q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _encode_point(p) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % _P
    y = (y * zi) % _P
    out = bytearray((y & ((1 << 255) - 1)).to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _decode_point(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _P - x
    p = (x % _P, y % _P, 1, (x * y) % _P)
    if not _on_curve(p):
        raise ValueError("point not on curve")
    return p


def _on_curve(p) -> bool:
    x, y, z, t = p
    zi = _inv(z)
    x = (x * zi) % _P
    y = (y * zi) % _P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _secret_scalar(h: bytes):
    a = bytearray(h[:32])
    a[0] &= 0xF8
    a[31] &= 0x7F
    a[31] |= 0x40
    return int.from_bytes(a, "little")


def publickey_from_seed(seed: bytes) -> bytes:
    """Return the 32-byte public key for a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = _secret_scalar(h)
    return _encode_point(_scalarmult(_B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    """Return a 64-byte Ed25519 signature over ``msg`` using 32-byte ``seed``."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = _secret_scalar(h)
    pub = _encode_point(_scalarmult(_B, a))
    prefix = h[32:]
    r = _sha512_int(prefix + msg) % _L
    rr = _encode_point(_scalarmult(_B, r))
    k = _sha512_int(rr + pub + msg) % _L
    s = (r + k * a) % _L
    return rr + s.to_bytes(32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a 64-byte signature. Returns True/False; never raises on bad input."""
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        rr = sig[:32]
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        a_pt = _decode_point(pub)
        r_pt = _decode_point(rr)
        k = _sha512_int(rr + pub + msg) % _L
        left = _scalarmult(_B, s)
        right = _edwards_add(r_pt, _scalarmult(a_pt, k))
        # Compare in affine coordinates.
        return _encode_point(left) == _encode_point(right)
    except (ValueError, IndexError):
        return False
