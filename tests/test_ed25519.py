"""Ed25519 correctness: RFC 8032 vector, roundtrip, tamper, PyNaCl interop."""
import os

import pytest

from attestinfer import ed25519


def test_rfc8032_vector_2():
    # RFC 8032 Section 7.1, TEST 2 (single-byte message 0x72).
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    msg = bytes.fromhex("72")
    sig = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert ed25519.publickey_from_seed(seed) == pk
    assert ed25519.sign(seed, msg) == sig
    assert ed25519.verify(pk, msg, sig)


def test_roundtrip_random():
    for _ in range(25):
        seed = os.urandom(32)
        msg = os.urandom(64)
        pk = ed25519.publickey_from_seed(seed)
        sig = ed25519.sign(seed, msg)
        assert ed25519.verify(pk, msg, sig)


def test_tamper_rejected():
    seed = os.urandom(32)
    msg = b"attest this"
    pk = ed25519.publickey_from_seed(seed)
    sig = ed25519.sign(seed, msg)
    assert not ed25519.verify(pk, msg + b"!", sig)
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not ed25519.verify(pk, msg, bytes(bad))


def test_malformed_inputs_return_false():
    assert not ed25519.verify(b"short", b"m", b"x" * 64)
    assert not ed25519.verify(b"\x00" * 32, b"m", b"y" * 63)


def test_seed_length_validation():
    with pytest.raises(ValueError):
        ed25519.sign(b"\x00" * 31, b"m")
    with pytest.raises(ValueError):
        ed25519.publickey_from_seed(b"\x00" * 33)


def test_pynacl_interop_if_available():
    try:
        from nacl.signing import SigningKey, VerifyKey
    except Exception:
        pytest.skip("PyNaCl not installed")
    for _ in range(15):
        seed = os.urandom(32)
        msg = os.urandom(40)
        sk = SigningKey(seed)
        assert bytes(sk.verify_key) == ed25519.publickey_from_seed(seed)
        # our sig accepted by nacl
        VerifyKey(bytes(sk.verify_key)).verify(msg, ed25519.sign(seed, msg))
        # nacl sig accepted by us
        assert ed25519.verify(bytes(sk.verify_key), msg, sk.sign(msg).signature)
