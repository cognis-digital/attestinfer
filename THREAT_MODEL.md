# Threat Model & Scope

This document states **precisely** what `attestinfer` proves and, just as
importantly, what it does **not** prove. Read it before relying on a transcript
for anything consequential (audit, compliance, dispute resolution). We do not
overclaim: the honest boundary of this construction is a feature.

## Roles

* **Attester** — runs a local model over a private corpus, produces answers, and
  signs attestation transcripts. Holds the Ed25519 signing seed and the corpus.
* **Verifier / Auditor** — a third party (regulator, customer, court) that holds
  a transcript and the attester's *public* key. Does **not** hold the corpus or
  the model weights.
* **Adversary** — anyone who wants to alter a transcript after the fact, forge a
  transcript in the attester's name, or claim grounding in data that was not
  actually committed.

## What a transcript commits to

A signed transcript binds, in one Ed25519 signature over canonical bytes, and
redundantly in a length-prefixed BLAKE2b hash chain (`chain_head`):

| Field | Commitment |
|---|---|
| `model_id` | BLAKE2b fold of every weight-shard hash + arch/quant params |
| `corpus_root` | Merkle root over the ordered private corpus |
| `prompt_hash` | BLAKE2b of the prompt (cleartext optional) |
| `decoding` | canonical sampling params (temperature, top_p, seed, max_tokens) |
| `retrieved[]` | for each grounding chunk: `chunk_id`, `content_hash`, corpus `index` |
| `output_hash` | BLAKE2b of the answer (cleartext optional) |
| `timestamp`, `nonce` | freshness / domain separation |

## What this PROVES (properties we stand behind)

1. **Provenance / signer authenticity.** A valid signature proves the transcript
   was produced by the holder of the private seed for the stated public key.
   Ed25519 (RFC 8032); verified by a zero-dependency pure-Python implementation
   cross-checked byte-for-byte against PyNaCl (see `tests/test_ed25519.py`).

2. **Integrity / tamper-evidence.** Changing *any* committed field — the answer,
   a decoding parameter, the model id, a retrieved chunk id/hash/index, the
   corpus root, the timestamp — changes `chain_head` **and** invalidates the
   signature. `verify` reports exactly which check failed. Demonstrated for every
   field in `tests/test_attest.py` and `examples/demo.py`.

3. **Model-identity binding.** The transcript names *which* weights the attester
   claims to have used (`model_id`), and `model_id` is recomputed from the shard
   hashes at verify time, so a shard hash cannot be swapped without detection.

4. **Grounding-in-committed-data.** The answer is bound to a specific set of
   retrieved chunks, each committed under a single `corpus_root`. Given a
   disclosure, the verifier confirms a chunk was a member of the *committed*
   corpus (Merkle inclusion) **and** was the exact chunk the transcript claimed
   to retrieve (id + content hash + index match) — **without ever seeing the
   rest of the corpus.**

5. **Selective disclosure / confidentiality of the corpus.** The public artifact
   is a 32-byte root plus per-retrieved-chunk hashes. Contents are revealed only
   on demand, one chunk at a time, each with an O(log n) inclusion proof. The
   attester **cannot** forge a disclosure: revealed content must hash to the
   committed leaf, and leaves are position-bound (index in the leaf preimage), so
   reordering/duplication is rejected. Merkle construction is domain-separated
   (leaf tag `0x00`, node tag `0x01`) and promotes odd nodes rather than
   duplicating them, avoiding the CVE-2012-2459 duplicate-node forgery class.

6. **Non-membership-by-challenge.** If the attester claims an answer used only
   chunks X and Y, a challenged chunk Z (committed but not in `retrieved[]`)
   fails `chunk_in_transcript` while still proving Merkle inclusion — i.e. the
   verifier can tell "in the corpus" from "actually used in this answer."

## What this DOES NOT prove (hard, honest limits)

1. **It is NOT a proof that the model actually executed the computation.**
   This is the big one. `attestinfer` proves the attester *committed to* a model
   id and *claims* the output came from running that model on those chunks. It
   does **not** prove the forward pass happened, that the stated weights produced
   the stated output, or that a different (e.g. larger/cloud) model didn't
   generate the answer. A malicious attester with the signing key can sign a
   transcript for an answer it produced by any means. **Proving faithful
   execution requires zkML (a succinct proof of the inference circuit) or a
   hardware TEE (attested enclave measuring the loaded weights and I/O).** Those
   are complementary and out of scope here; see *Future work*.

2. **It does not prove the corpus is true, complete, or unbiased.** It proves the
   answer was grounded in *committed* data — not that the data is correct or that
   relevant data wasn't withheld. An attester can commit a corpus of falsehoods.

3. **It does not prove the retrieval was faithful.** We prove *which* chunks the
   transcript names as retrieved and that they are committed members. We do not
   prove those were the objectively "most relevant" chunks, nor that the model
   actually attended to them (again a computation-integrity claim → zkML/TEE).

4. **It does not protect a compromised signing key.** Standard PKI assumption:
   whoever holds the seed can sign anything. Key custody (HSM, OS keystore) is
   the operator's responsibility and out of scope. This library's pure-Python
   Ed25519 is **not constant-time** and is intended for signing/verification on a
   trusted host, not as a side-channel-hardened primitive on hostile hardware.

5. **It does not provide confidentiality of the transcript itself**, only of the
   corpus. Prompt/output cleartext is optional; when omitted only their hashes
   are published, but those hashes are guessable for low-entropy text.

6. **No revocation / timestamping authority.** `timestamp` is attester-asserted.
   Binding a transcript to a trusted time requires an external timestamping
   authority or transparency log (future work; the `nonce`/hash-chain design is
   compatible with appending transcripts to an external log like agentledger).

## Cryptographic assumptions

* BLAKE2b is collision- and second-preimage-resistant (Merkle roots, hash chain,
  content hashes, model fold).
* Ed25519 is EUF-CMA secure (transcript signatures).
* `os.urandom` provides a cryptographically secure seed.
* Canonical JSON (sorted keys, no whitespace, no floats) gives a unique byte
  encoding of the signed body, so signer and verifier hash identical bytes.

## Future work (the honest path to "proof of execution")

* **TEE attestation:** run inference inside an SGX/SEV-SNP/TDX enclave; bind the
  enclave measurement (which covers the loaded weights) to `model_id` and have
  the enclave sign the transcript. Upgrades property (1) from *claimed* to
  *hardware-attested* execution.
* **zkML:** emit a succinct proof that `output = model(prompt, retrieved)` for the
  committed weights. Upgrades (1) to *cryptographic* proof of execution, no
  trusted hardware. Currently impractical for 9B-parameter models, but the
  transcript format already isolates exactly the statement such a proof must
  cover.
* **Transparency log:** append `chain_head`s to an external, tamper-evident log
  for independent, trusted timestamping and non-equivocation.
