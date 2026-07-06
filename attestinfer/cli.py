"""attestinfer command-line interface.

Subcommands:
    keygen     generate an ed25519 keypair
    commit     build a corpus Merkle commitment from a directory or JSONL
    hashmodel  hash weight files into a model_id
    attest     produce a signed transcript for an inference
    verify     verify a transcript (integrity + signature + grounding)
    disclose   emit a chunk + inclusion proof
    verify-disclosure   check a disclosure against a transcript
"""
from __future__ import annotations

import argparse
import json
import sys

from . import (
    CorpusManifest,
    KeyPair,
    Transcript,
    attest,
    commit_corpus,
    commit_directory,
    commit_model,
    disclose,
    verify,
    verify_disclosure,
)
from .attest import Disclosure


def _load_jsonl_corpus(path: str) -> list[tuple[str, bytes]]:
    chunks = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            chunks.append((obj["id"], obj["text"].encode("utf-8")))
    return chunks


def cmd_keygen(args: argparse.Namespace) -> int:
    kp = KeyPair.generate()
    out = {"public_key": kp.public_hex, "seed": kp.seed_hex}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"wrote keypair to {args.out} (KEEP THE SEED SECRET)", file=sys.stderr)
        print(json.dumps({"public_key": kp.public_hex}))
    else:
        print(json.dumps(out))
    return 0


def cmd_commit(args: argparse.Namespace) -> int:
    if args.dir:
        manifest = commit_directory(args.dir)
    elif args.jsonl:
        manifest = commit_corpus(_load_jsonl_corpus(args.jsonl))
    else:
        print("error: provide --dir or --jsonl", file=sys.stderr)
        return 2
    if args.private_out:
        manifest.save_private(args.private_out)
    if args.out:
        manifest.save_public(args.out)
    print(json.dumps({"corpus_root": manifest.root_hex, "chunks": len(manifest.entries)}))
    return 0


def cmd_hashmodel(args: argparse.Namespace) -> int:
    params = json.loads(args.params) if args.params else {}
    model = commit_model(args.name, args.weights, params)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(model.to_dict(), f, indent=2)
    print(json.dumps({"model_id": model.model_id_hex, "shards": len(model.shards)}))
    return 0


def _load_model(path: str):
    from .model import commit_model_from_hashes

    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    return commit_model_from_hashes(d["name"], [tuple(s) for s in d["shards"]], d.get("params", {}))


def cmd_attest(args: argparse.Namespace) -> int:
    with open(args.key, "r", encoding="utf-8") as f:
        kp = KeyPair.from_seed_hex(json.load(f)["seed"])
    manifest = CorpusManifest.load(args.corpus)
    model = _load_model(args.model)
    prompt = _read(args.prompt, args.prompt_text)
    output = _read(args.output, args.output_text)
    decoding = json.loads(args.decoding) if args.decoding else {}
    retrieved = args.retrieved or []
    t = attest(
        keypair=kp,
        model=model,
        corpus=manifest,
        prompt=prompt,
        decoding=decoding,
        retrieved_ids=retrieved,
        output=output,
        include_prompt=args.include_prompt,
        include_output=not args.no_output,
    )
    js = json.dumps(t.to_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(js)
    else:
        print(js)
    return 0


def _read(path: str | None, text: str | None) -> str:
    if text is not None:
        return text
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.transcript, "r", encoding="utf-8") as f:
        t = Transcript.from_dict(json.load(f))
    r = verify(t, expected_public_key=args.expect_key)
    print(json.dumps({"ok": r.ok, "checks": r.checks, "reason": r.reason}, indent=2))
    return 0 if r.ok else 1


def cmd_disclose(args: argparse.Namespace) -> int:
    manifest = CorpusManifest.load(args.corpus)
    d = disclose(manifest, args.chunk)
    js = json.dumps(d.to_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(js)
    else:
        print(js)
    return 0


def cmd_verify_disclosure(args: argparse.Namespace) -> int:
    with open(args.transcript, "r", encoding="utf-8") as f:
        t = Transcript.from_dict(json.load(f))
    with open(args.disclosure, "r", encoding="utf-8") as f:
        d = Disclosure.from_dict(json.load(f))
    r = verify_disclosure(d, t)
    print(json.dumps({"ok": r.ok, "checks": r.checks, "reason": r.reason}, indent=2))
    return 0 if r.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="attestinfer", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an ed25519 keypair")
    g.add_argument("--out", help="write keypair JSON (contains secret seed)")
    g.set_defaults(func=cmd_keygen)

    c = sub.add_parser("commit", help="commit a corpus to a Merkle root")
    c.add_argument("--dir", help="directory of files to commit")
    c.add_argument("--jsonl", help="JSONL with {id,text} per line")
    c.add_argument("--out", help="public manifest output (root + hashes)")
    c.add_argument("--private-out", help="private manifest output (includes contents)")
    c.set_defaults(func=cmd_commit)

    h = sub.add_parser("hashmodel", help="hash weight files to a model_id")
    h.add_argument("--name", required=True)
    h.add_argument("--weights", nargs="+", required=True, help="weight file paths")
    h.add_argument("--params", help="JSON of arch/quant params")
    h.add_argument("--out", help="model identity JSON output")
    h.set_defaults(func=cmd_hashmodel)

    a = sub.add_parser("attest", help="produce a signed transcript")
    a.add_argument("--key", required=True, help="keypair JSON (from keygen)")
    a.add_argument("--corpus", required=True, help="private corpus manifest")
    a.add_argument("--model", required=True, help="model identity JSON")
    a.add_argument("--prompt")
    a.add_argument("--prompt-text")
    a.add_argument("--output")
    a.add_argument("--output-text")
    a.add_argument("--decoding", help="JSON decoding params")
    a.add_argument("--retrieved", nargs="*", help="retrieved chunk ids in order")
    a.add_argument("--include-prompt", action="store_true")
    a.add_argument("--no-output", action="store_true", help="omit cleartext output")
    a.add_argument("--out", help="transcript output path")
    a.set_defaults(func=cmd_attest)

    v = sub.add_parser("verify", help="verify a transcript")
    v.add_argument("transcript")
    v.add_argument("--expect-key", help="pin expected signer public key (hex)")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("disclose", help="emit a chunk + inclusion proof")
    d.add_argument("--corpus", required=True)
    d.add_argument("--chunk", required=True)
    d.add_argument("--out")
    d.set_defaults(func=cmd_disclose)

    vd = sub.add_parser("verify-disclosure", help="verify a disclosure vs a transcript")
    vd.add_argument("--transcript", required=True)
    vd.add_argument("--disclosure", required=True)
    vd.set_defaults(func=cmd_verify_disclosure)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
