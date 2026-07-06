#!/usr/bin/env python3
"""Reproduce the microbenchmarks reported in RESULTS.md."""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attestinfer as ai  # noqa: E402
from attestinfer.canonical import canonical_bytes  # noqa: E402


def main() -> int:
    print("corpus commit + proof size (256-byte chunks):")
    print(f"{'size':>8} {'commit_ms':>10} {'proof_steps':>12}")
    for n in (10, 100, 1000, 10000):
        chunks = [(f"c{i}", os.urandom(256)) for i in range(n)]
        t0 = time.perf_counter()
        corpus = ai.commit_corpus(chunks)
        commit_ms = (time.perf_counter() - t0) * 1000
        steps = len(ai.disclose(corpus, "c0").proof.steps)
        print(f"{n:>8} {commit_ms:>10.1f} {steps:>12}")

    corpus = ai.commit_corpus([(f"c{i}", os.urandom(512)) for i in range(1000)])
    model = ai.commit_model_from_hashes("m", [("s0", "aa" * 32)], {})
    kp = ai.KeyPair.generate()
    reps = 50

    t0 = time.perf_counter()
    for _ in range(reps):
        t = ai.attest(keypair=kp, model=model, corpus=corpus, prompt="p",
                      decoding={"seed": 1}, retrieved_ids=["c1", "c2", "c3"], output="o")
    attest_ms = (time.perf_counter() - t0) / reps * 1000

    t0 = time.perf_counter()
    for _ in range(reps):
        ai.verify(t)
    verify_ms = (time.perf_counter() - t0) / reps * 1000

    print(f"\nattest={attest_ms:.1f}ms  verify={verify_ms:.1f}ms "
          f"(1000-chunk corpus, 3 retrieved)")
    print(f"transcript size (no cleartext) = {len(canonical_bytes(t.signed_body()))} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
