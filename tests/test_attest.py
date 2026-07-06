"""End-to-end attest / verify / disclose, including every tamper path."""
import copy

import pytest

import attestinfer as ai
from attestinfer.transcript import Transcript


@pytest.fixture
def setup():
    corpus = ai.commit_corpus([
        ("doc:a", b"Alpha fact: the sky index is 42."),
        ("doc:b", b"Beta fact: the river flows east."),
        ("doc:c", b"Gamma fact: three moons orbit."),
        ("doc:d", b"Delta fact: the vault code is 9981."),
        ("doc:e", b"Epsilon fact: winter lasts 90 days."),
    ])
    model = ai.commit_model_from_hashes(
        "test-model-7b", [("s0", "11" * 32), ("s1", "22" * 32)], {"quant": "Q4", "ctx": "4096"}
    )
    kp = ai.KeyPair.generate()
    t = ai.attest(
        keypair=kp,
        model=model,
        corpus=corpus,
        prompt="What is the sky index and vault code?",
        decoding={"temperature": 0.2, "top_p": 0.9, "seed": 7, "max_tokens": 128},
        retrieved_ids=["doc:a", "doc:d"],
        output="Sky index 42, vault code 9981.",
        include_output=True,
    )
    return corpus, model, kp, t


def test_clean_verify(setup):
    _, _, _, t = setup
    r = ai.verify(t)
    assert r.ok
    assert all(r.checks.values())


def test_expected_key_pin(setup):
    _, _, kp, t = setup
    assert ai.verify(t, expected_public_key=kp.public_hex).ok
    assert not ai.verify(t, expected_public_key="ab" * 32).ok


def _mutate(t: Transcript, **kw) -> Transcript:
    d = copy.deepcopy(t.to_dict())
    for k, v in kw.items():
        d[k] = v
    return Transcript.from_dict(d)


def test_tamper_output_hash(setup):
    _, _, _, t = setup
    bad = _mutate(t, output_hash="00" * 32)
    assert not ai.verify(bad).ok


def test_tamper_output_cleartext(setup):
    _, _, _, t = setup
    bad = _mutate(t, output="A DIFFERENT ANSWER")
    r = ai.verify(bad)
    assert not r.ok
    assert r.checks["output_matches_hash"] is False


def test_tamper_corpus_root(setup):
    _, _, _, t = setup
    bad = _mutate(t, corpus_root="ff" * 32)
    assert not ai.verify(bad).ok


def test_tamper_model_id(setup):
    _, _, _, t = setup
    m = copy.deepcopy(t.model)
    m["model_id"] = "cd" * 32
    bad = _mutate(t, model=m)
    r = ai.verify(bad)
    assert not r.ok
    assert r.checks["model_id_consistent"] is False


def test_tamper_model_shard_detected_by_id(setup):
    _, _, _, t = setup
    m = copy.deepcopy(t.model)
    m["shards"][0][1] = "99" * 32  # swap a shard hash but keep model_id
    bad = _mutate(t, model=m)
    r = ai.verify(bad)
    assert not r.ok
    assert r.checks["model_id_consistent"] is False


def test_tamper_decoding(setup):
    _, _, _, t = setup
    dec = dict(t.decoding)
    dec["temperature"] = "0.99"
    bad = _mutate(t, decoding=dec)
    assert not ai.verify(bad).ok


def test_tamper_retrieved(setup):
    _, _, _, t = setup
    ret = copy.deepcopy([c.to_dict() for c in t.retrieved])
    ret[0]["chunk_id"] = "doc:c"
    bad = _mutate(t, retrieved=ret)
    assert not ai.verify(bad).ok


def test_tamper_signature(setup):
    _, _, _, t = setup
    sig = bytearray(bytes.fromhex(t.signature))
    sig[0] ^= 1
    bad = _mutate(t, signature=bytes(sig).hex())
    r = ai.verify(bad)
    assert not r.ok
    assert r.checks["signature"] is False


def test_swap_signer_key_fails(setup):
    _, _, _, t = setup
    other = ai.KeyPair.generate()
    bad = _mutate(t, public_key=other.public_hex)
    assert not ai.verify(bad).ok


def test_disclosure_valid(setup):
    corpus, _, _, t = setup
    d = ai.disclose(corpus, "doc:a")
    r = ai.verify_disclosure(d, t)
    assert r.ok
    assert d.content == "Alpha fact: the sky index is 42."


def test_disclosure_not_retrieved_fails(setup):
    corpus, _, _, t = setup
    d = ai.disclose(corpus, "doc:c")  # committed but not retrieved
    r = ai.verify_disclosure(d, t)
    assert not r.ok
    assert r.checks["chunk_in_transcript"] is False
    # yet it IS a valid member of the corpus
    assert r.checks["merkle_inclusion"] is True


def test_disclosure_forged_content_fails(setup):
    corpus, _, _, t = setup
    d = ai.disclose(corpus, "doc:a")
    d.content = "the sky index is 999"
    r = ai.verify_disclosure(d, t)
    assert not r.ok
    assert r.checks["content_matches_proof"] is False


def test_disclosure_wrong_root_fails(setup):
    corpus, _, _, t = setup
    d = ai.disclose(corpus, "doc:a")
    d.corpus_root = "ab" * 32
    r = ai.verify_disclosure(d, t)
    assert not r.ok


def test_transcript_serialization_roundtrip(setup):
    _, _, _, t = setup
    t2 = Transcript.from_dict(t.to_dict())
    assert ai.verify(t2).ok
    assert t2.to_dict() == t.to_dict()


def test_no_cleartext_still_verifies(setup):
    corpus, model, kp, _ = setup
    t = ai.attest(
        keypair=kp, model=model, corpus=corpus,
        prompt="secret prompt", decoding={"seed": 1},
        retrieved_ids=["doc:b"], output="secret answer",
        include_prompt=False, include_output=False,
    )
    assert t.prompt is None and t.output is None
    assert ai.verify(t).ok


def test_unknown_chunk_rejected(setup):
    corpus, model, kp, _ = setup
    with pytest.raises(KeyError):
        ai.attest(
            keypair=kp, model=model, corpus=corpus, prompt="p",
            decoding={}, retrieved_ids=["doc:zzz"], output="o",
        )


def test_duplicate_chunk_id_rejected():
    with pytest.raises(ValueError):
        ai.commit_corpus([("dup", b"1"), ("dup", b"2")])


def test_float_in_signed_body_rejected():
    # decoding floats are normalized to strings; a raw float leaking into the
    # canonical body must be rejected rather than silently mis-serialized.
    from attestinfer.canonical import canonical_bytes
    with pytest.raises(ValueError):
        canonical_bytes({"x": 0.1})
