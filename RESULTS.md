# Results

All numbers below are **measured** on the development machine (Windows, CPython
3.14, pure-Python Ed25519 — no native acceleration). They are cache/crypto
microbenchmarks and small-scale correctness results, not modeled or projected
figures. Reproduce with `python examples/bench.py` and `python -m pytest`.

## Correctness (test suite)

`python -m pytest -q` → **44 tests pass** across:

* `test_ed25519.py` — RFC 8032 test vector, random roundtrips, tamper rejection,
  malformed-input handling, and **byte-for-byte interop with PyNaCl** in both
  directions (our sigs accepted by PyNaCl; PyNaCl sigs accepted by us).
* `test_merkle.py` — inclusion proofs for corpus sizes {1,2,3,4,5,7,8,16,17,33}
  (odd counts included), content-tamper rejection, reorder rejection, wrong-root
  rejection, leaf/node domain-separation, empty-corpus root, proof serialization.
* `test_attest.py` — clean verify; **every field tampered individually fails
  verification** (output hash, output cleartext, corpus root, model id, a single
  model shard, decoding params, retrieved chunk, signature, signer key swap);
  valid/forged/non-retrieved disclosures; no-cleartext transcripts still verify;
  unknown/duplicate chunk rejection; float rejection in signed body.
* `test_cli.py` — full `keygen → commit → hashmodel → attest → verify → disclose →
  verify-disclosure` flow, plus CLI tamper detection (exit code 1).

## Demo (`examples/demo.py`, exit 0 = all assertions held)

A regulated-KYC scenario. Observed outcomes:

| Step | Result |
|---|---|
| Auditor verifies clean transcript (no corpus, no weights) | all 7 checks PASS |
| Tamper the answer text | `verify` FAILS at `output_matches_hash` |
| Tamper a retrieved chunk id | `verify` FAILS at `chain_head` |
| Disclose the challenged chunk (`policy:limits`) | all 4 checks PASS |
| Attester forges disclosed content | FAILS at `content_matches_proof` |
| Disclose a committed-but-unused chunk | `merkle_inclusion`=True, `chunk_in_transcript`=False |

The last row is the key discriminator: the verifier can tell "this chunk is in
the corpus" apart from "this chunk was used in this answer."

## Performance (measured)

Corpus commitment and proof size (256-byte chunks):

| Corpus size | Commit time | Inclusion-proof steps |
|---|---|---|
| 10 | 0.1 ms | 4 |
| 100 | 0.5 ms | 7 |
| 1,000 | 7.7 ms | 10 |
| 10,000 | 52.5 ms | 14 |

Proof size grows as O(log n): a 10,000-chunk corpus discloses one chunk with a
14-step (~0.5 KB) proof.

Attest / verify latency (1,000-chunk corpus, 3 retrieved chunks, avg of 50):

| Operation | Time |
|---|---|
| `attest` (sign, pure-Python Ed25519) | ~4.0 ms |
| `verify` (verify signature + chain) | ~4.1 ms |
| Transcript size (no cleartext) | ~1.0 KB |

Ed25519 is the dominant cost. With PyNaCl installed the signature path is
substantially faster; correctness is identical (interop-tested).

## What the results support

* **Provenance, integrity, and tamper-evidence** are demonstrated exhaustively:
  mutating any signed field fails verification, and the failing check is named.
* **Grounding-in-committed-data with selective disclosure** works end-to-end and
  is confidentiality-preserving (only challenged chunks are revealed, O(log n)).
* Performance is on-device-practical (single-digit ms) even without native crypto.

## What the results do NOT support

They do **not** establish that the model executed the computation — no benchmark
here (or anywhere in this repo) claims that. Proof of execution needs zkML or a
TEE; see [THREAT_MODEL.md](THREAT_MODEL.md).
