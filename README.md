# attestinfer

**Cryptographically prove that an AI answer was produced by a specific local
model and grounded in a specific private corpus — verifiable by a third party,
without revealing the corpus or the weights.**

When a local model answers a regulated question ("what is our tier-2 wire
limit?", "does this transaction require a SAR?"), an auditor later needs to know
three things: *which model produced this*, *was it grounded in our actual
policy corpus*, and *has the record been altered since*. Answering those without
handing the auditor your private knowledge base or your model weights is the
problem `attestinfer` solves.

It produces a small, signed **attestation transcript** that commits to the model
identity, the prompt, the decoding parameters, the *hashes* of the retrieved
context (under a single Merkle root over the corpus), and the output. A third
party verifies provenance, integrity, and grounding from the transcript alone.
On challenge, the attester can **selectively disclose** one retrieved chunk with
an O(log n) inclusion proof — revealing that chunk and nothing else.

> **Scope, stated honestly:** this proves *provenance, integrity, tamper-evidence,
> and grounding-in-committed-data*. It does **not** prove the model actually ran
> the computation — that requires zkML or a TEE. We do not fake that property;
> see [THREAT_MODEL.md](THREAT_MODEL.md) for the exact boundary and the future-work
> path to execution proofs.

## Why this is hard / novel

Content-addressed corpora (see [aleph-memory](https://github.com/cognis-digital/aleph-memory))
and hash-chained audit logs (see agentledger) each solve part of this. The
missing piece is a **single signed object that binds a model identity to an
answer and to grounding evidence a third party can check without the underlying
data** — with selective disclosure so confidentiality survives the audit.
`attestinfer` is that object, and it runs on-device with **zero required
dependencies** (a pure-Python RFC 8032 Ed25519 is included, cross-checked against
PyNaCl when present).

## Install

```bash
git clone https://github.com/cognis-digital/attestinfer && cd attestinfer
pip install -e .          # or: make install  |  ./install.sh  |  .\install.ps1
```

No third-party packages are required. `pip install -e '.[fast]'` adds PyNaCl as
an optional cross-check.

## Quickstart (library)

```python
import attestinfer as ai

# 1. Commit your private corpus -> a single 32-byte root (contents stay local)
corpus = ai.commit_corpus([
    ("policy:limits",    b"Daily wire limit for tier-2 accounts is $50,000."),
    ("policy:reporting", b"File a SAR within 30 days of detecting suspicious activity."),
])

# 2. Commit the local model's identity (hash of its weight shards)
model = ai.commit_model_from_hashes("omnicoder-9b",
    [("shard0", "3a"*32)], {"quant": "Q5_K_M"})

# 3. Attest an answer grounded in specific chunks
signer = ai.KeyPair.generate()
t = ai.attest(keypair=signer, model=model, corpus=corpus,
    prompt="tier-2 wire limit and SAR window?",
    decoding={"temperature": 0.1, "seed": 1234},
    retrieved_ids=["policy:limits", "policy:reporting"],
    output="Tier-2 limit is $50,000; SAR within 30 days.")

# 4. A third party verifies with only the transcript + public key
print(ai.verify(t, expected_public_key=signer.public_hex).ok)   # True

# 5. On challenge, disclose one chunk + its Merkle proof
d = ai.disclose(corpus, "policy:limits")
print(ai.verify_disclosure(d, t).ok)                            # True
```

## Quickstart (CLI)

```bash
attestinfer keygen --out key.json
attestinfer commit --jsonl corpus.jsonl --private-out corpus.json --out corpus.pub.json
attestinfer hashmodel --name omnicoder-9b --weights model.safetensors --out model.json
attestinfer attest --key key.json --corpus corpus.json --model model.json \
    --prompt-text "..." --output-text "..." --retrieved policy:limits policy:reporting \
    --out transcript.json
attestinfer verify transcript.json
attestinfer disclose --corpus corpus.json --chunk policy:limits --out disclosure.json
attestinfer verify-disclosure --transcript transcript.json --disclosure disclosure.json
```

## Run the demo

```bash
python examples/demo.py      # attest -> verify -> tamper (fails) -> disclose
```

## What's inside

| Module | Role |
|---|---|
| `ed25519.py` | zero-dependency RFC 8032 signatures (interop-tested vs PyNaCl) |
| `merkle.py` | domain-separated, position-binding Merkle tree + inclusion proofs |
| `corpus.py` | corpus commitment (root + per-chunk hashes; contents kept local) |
| `model.py` | model-identity commitment (weight-shard hash fold) |
| `transcript.py` | the signed, hash-chained attestation object |
| `attest.py` | `attest` / `verify` / `disclose` / `verify_disclosure` |
| `canonical.py` | RFC 8785-style canonical JSON for deterministic signing |
| `cli.py` | command-line interface |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the construction,
[THREAT_MODEL.md](THREAT_MODEL.md) for what it proves and does not, and
[RESULTS.md](RESULTS.md) for measured behavior.

## License

COCL — see [LICENSE](LICENSE).
