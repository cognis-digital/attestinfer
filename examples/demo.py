#!/usr/bin/env python3
"""Reproducible end-to-end demo for attestinfer.

Scenario: a local model answers a regulated question grounded in a *private*
knowledge base. We produce a signed attestation transcript, an auditor verifies
it WITHOUT the corpus, we tamper with the transcript (verify fails), and finally
we selectively disclose the one chunk the auditor challenges (proof verifies).

Run:  python examples/demo.py
Exit code 0 means every assertion held.
"""
from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attestinfer as ai  # noqa: E402
from attestinfer.transcript import Transcript  # noqa: E402


def line(msg=""):
    print(msg)


def main() -> int:
    line("=" * 68)
    line("attestinfer demo -- provenance + grounding + selective disclosure")
    line("=" * 68)

    # --- 1. The attester's PRIVATE corpus (never shared with the auditor) ---
    corpus = ai.commit_corpus([
        ("policy:kyc",     b"KYC: verify government ID and proof of address within 30 days."),
        ("policy:limits",  b"Daily wire limit for tier-2 accounts is $50,000."),
        ("policy:sanctions", b"Screen all counterparties against the consolidated sanctions list."),
        ("policy:retention", b"Retain transaction records for 7 years."),
        ("policy:reporting", b"File a SAR within 30 days of detecting suspicious activity."),
    ])
    line(f"\n[1] Committed private corpus of 5 chunks.")
    line(f"    corpus_root = {corpus.root_hex}")
    line(f"    (only this 32-byte root is public; contents stay local)")

    # --- 2. Commit the local model identity ---
    model = ai.commit_model_from_hashes(
        "omnicoder-9b",
        [("model-00001-of-00002.safetensors", "3a" * 32),
         ("model-00002-of-00002.safetensors", "7c" * 32)],
        {"quant": "Q5_K_M", "context": "8192", "arch": "qwen2"},
    )
    line(f"\n[2] Committed model identity.")
    line(f"    model_id = {model.model_id_hex}")

    # --- 3. The attester answers, grounded in two policy chunks, and attests ---
    signer = ai.KeyPair.generate()
    prompt = "What is the tier-2 daily wire limit and when must a SAR be filed?"
    output = "Tier-2 daily wire limit is $50,000; a SAR must be filed within 30 days."
    transcript = ai.attest(
        keypair=signer,
        model=model,
        corpus=corpus,
        prompt=prompt,
        decoding={"temperature": 0.1, "top_p": 0.9, "seed": 1234, "max_tokens": 200},
        retrieved_ids=["policy:limits", "policy:reporting"],
        output=output,
        include_prompt=True,
        include_output=True,
    )
    line(f"\n[3] Produced signed transcript.")
    line(f"    signer public key = {signer.public_hex}")
    line(f"    chain_head        = {transcript.chain_head}")
    line(f"    grounded in       = {[c.chunk_id for c in transcript.retrieved]}")

    # --- 4. Auditor verifies WITHOUT the corpus or the weights ---
    r = ai.verify(transcript, expected_public_key=signer.public_hex)
    line(f"\n[4] Auditor verifies (has only the transcript):")
    for name, ok in r.checks.items():
        line(f"      {'PASS' if ok else 'FAIL'}  {name}")
    assert r.ok, "clean transcript must verify"

    # --- 5. Tamper: change the answer text -> verification MUST fail ---
    forged = copy.deepcopy(transcript.to_dict())
    forged["output"] = "Tier-2 daily wire limit is $5,000,000; no SAR needed."
    r_bad = ai.verify(Transcript.from_dict(forged))
    line(f"\n[5] Tamper the answer -> verify: ok={r_bad.ok}  ({r_bad.reason})")
    assert not r_bad.ok, "tampered transcript must fail"

    # --- 5b. Tamper a hidden field: swap a retrieved chunk -> MUST fail ---
    forged2 = copy.deepcopy(transcript.to_dict())
    forged2["retrieved"][0]["chunk_id"] = "policy:sanctions"
    r_bad2 = ai.verify(Transcript.from_dict(forged2))
    line(f"    Tamper a retrieved chunk -> verify: ok={r_bad2.ok}  ({r_bad2.reason})")
    assert not r_bad2.ok

    # --- 6. Selective disclosure: auditor challenges 'policy:limits' ---
    disc = ai.disclose(corpus, "policy:limits")
    dr = ai.verify_disclosure(disc, transcript)
    line(f"\n[6] Auditor challenges chunk 'policy:limits'; attester discloses it:")
    line(f'      revealed content: "{disc.content}"')
    for name, ok in dr.checks.items():
        line(f"      {'PASS' if ok else 'FAIL'}  {name}")
    assert dr.ok, "valid disclosure must verify"

    # --- 6b. Attester cannot fake a chunk it did not commit ---
    forged_disc = ai.disclose(corpus, "policy:limits")
    forged_disc.content = "Daily wire limit is unlimited."
    dr_bad = ai.verify_disclosure(forged_disc, transcript)
    line(f"\n    Attester tries to disclose forged content -> ok={dr_bad.ok} ({dr_bad.reason})")
    assert not dr_bad.ok

    # --- 6c. A chunk that exists but was NOT retrieved is provably not-used ---
    not_used = ai.disclose(corpus, "policy:kyc")
    dr_nu = ai.verify_disclosure(not_used, transcript)
    line(f"    Disclose a committed-but-unretrieved chunk -> ok={dr_nu.ok} ({dr_nu.reason})")
    line(f"      (merkle_inclusion={dr_nu.checks['merkle_inclusion']}, "
         f"chunk_in_transcript={dr_nu.checks['chunk_in_transcript']})")
    assert not dr_nu.ok and dr_nu.checks["merkle_inclusion"]

    line("\n" + "=" * 68)
    line("DEMO OK -- provenance, integrity, grounding, tamper-evidence, and")
    line("selective disclosure all held. See THREAT_MODEL.md for scope limits.")
    line("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
