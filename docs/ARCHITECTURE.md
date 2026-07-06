# Architecture

`attestinfer` produces one signed object — the **attestation transcript** — that
a third party can verify. This document describes the construction; see
[THREAT_MODEL.md](../THREAT_MODEL.md) for what it does and does not prove.

## Data flow

```
                 PRIVATE (attester side)                    PUBLIC / auditor side
   corpus chunks ─┐
                  ▼
   commit_corpus ── Merkle tree ──► corpus_root ─────────────────┐
   (per-chunk hashes kept locally)                               │
                                                                 ▼
   weight shards ── hash_file ──► model_id ──────────────►  ┌─────────────┐
                                                            │ Transcript  │
   prompt ── blake2b ──► prompt_hash ───────────────────►  │  (signed +  │
   decoding params ─────────────────────────────────────► │ hash-chained│──► verify()
   retrieved chunk ids ── (id, content_hash, index) ─────► │   body)     │
   output ── blake2b ──► output_hash ───────────────────►  └─────────────┘
                                                                 │
   disclose(chunk) ── content + Merkle proof ──────────────────►┘  verify_disclosure()
```

## The three commitments

### 1. Corpus commitment (`corpus.py`, `merkle.py`)

The corpus is an *ordered* list of `(chunk_id, content)` pairs. Each leaf is:

```
leaf = BLAKE2b( 0x00 || u64(index) || chunk_id || 0x00 || BLAKE2b(content) )
```

The `0x00` prefix is a domain-separation tag distinct from the internal-node tag
`0x01`, so a leaf digest can never be reinterpreted as a node (second-preimage
resistance). Binding `index` into the leaf makes proofs **position-binding**: you
cannot move a chunk to a different slot or duplicate it. Internal nodes are
`BLAKE2b(0x01 || left || right)`, and odd nodes are **promoted** unchanged rather
than duplicated (avoids the CVE-2012-2459 duplicate-node forgery class).

The public output is `corpus_root` (32 bytes) plus, for auditability, the list of
`(chunk_id, content_hash)`. **Raw contents never leave the attester.**

### 2. Model-identity commitment (`model.py`)

Each weight shard is streamed through BLAKE2b. All shard hashes plus canonical
arch/quant params are folded into a single `model_id`:

```
model_id = BLAKE2b( "attestinfer/model/v1\0" || name || Σ(shard_name || shard_hash) || Σ(k=v) )
```

At verify time `model_id` is recomputed from the shard list in the transcript, so
a shard hash cannot be altered without detection.

### 3. The transcript (`transcript.py`, `attest.py`)

The **signed body** contains `model_id`, `corpus_root`, `prompt_hash`,
`decoding`, `retrieved[]` (each `{chunk_id, content_hash, index}`), `output_hash`,
`timestamp`, `nonce`, and `chain_head`.

Two independent integrity mechanisms cover the same fields:

* **Hash chain** — fields are folded in a fixed order through length-prefixed
  BLAKE2b into `chain_head`. Length-prefixing prevents concatenation ambiguity
  (`"ab"+"c"` vs `"a"+"bc"`). Any change to any committed field changes the head.
* **Ed25519 signature** — over the canonical-JSON encoding of the signed body.

Both must pass. The hash chain gives a compact human-checkable integrity anchor;
the signature gives authenticity. `verify()` returns a per-check dict and names
the first failing check.

### Canonical serialization (`canonical.py`)

Signer and verifier must hash identical bytes. We use sorted keys, no whitespace,
UTF-8, and **reject floats** in the signed body (floats have no canonical binary
form). Decoding params like `temperature=0.1` are normalized to the string
`"0.1"` before signing.

## Selective disclosure (`attest.py::disclose` / `verify_disclosure`)

A disclosure is `{chunk_id, content, merkle_proof, corpus_root}`. Verification:

1. `corpus_root` in the disclosure equals the transcript's `corpus_root`.
2. `BLAKE2b(content)` equals the proof's committed `content_hash`.
3. The Merkle proof re-derives `corpus_root` (inclusion).
4. The disclosed chunk matches an entry in the transcript's `retrieved[]` by
   `chunk_id`, `content_hash`, **and** `index` — binding the disclosure to *this*
   attestation, not merely to corpus membership.

A committed-but-not-retrieved chunk passes (1)-(3) but fails (4), letting a
verifier distinguish "in the corpus" from "used in this answer."

## Why a hash chain *and* a signature?

Redundancy with different failure modes. The signature is the security-bearing
check (authenticity + integrity under Ed25519). The `chain_head` is a
deterministic, dependency-free digest an auditor can recompute and eyeball, and
it is the natural anchor for appending transcripts to an external transparency
log (e.g. agentledger-style) for timestamping/non-equivocation — noted as future
work in the threat model.
