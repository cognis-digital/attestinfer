"""CLI smoke tests: full keygen -> commit -> attest -> verify -> disclose flow."""
import json
import os

from attestinfer.cli import main


def _run(argv, capsys):
    code = main(argv)
    out = capsys.readouterr().out
    return code, out


def test_full_cli_flow(tmp_path, capsys):
    key = tmp_path / "key.json"
    corpus_priv = tmp_path / "corpus_priv.json"
    corpus_pub = tmp_path / "corpus_pub.json"
    model = tmp_path / "model.json"
    jsonl = tmp_path / "corpus.jsonl"
    weight = tmp_path / "weights.bin"
    transcript = tmp_path / "t.json"
    disclosure = tmp_path / "d.json"

    weight.write_bytes(os.urandom(4096))
    with open(jsonl, "w", encoding="utf-8") as f:
        for i in range(4):
            f.write(json.dumps({"id": f"k{i}", "text": f"knowledge {i}"}) + "\n")

    assert _run(["keygen", "--out", str(key)], capsys)[0] == 0
    assert _run(["commit", "--jsonl", str(jsonl), "--private-out", str(corpus_priv),
                 "--out", str(corpus_pub)], capsys)[0] == 0
    assert _run(["hashmodel", "--name", "m", "--weights", str(weight),
                 "--params", '{"q":"Q4"}', "--out", str(model)], capsys)[0] == 0

    code, _ = _run([
        "attest", "--key", str(key), "--corpus", str(corpus_priv), "--model", str(model),
        "--prompt-text", "question?", "--output-text", "answer.",
        "--decoding", '{"temperature":0.5,"seed":3}', "--retrieved", "k1", "k2",
        "--out", str(transcript),
    ], capsys)
    assert code == 0

    code, out = _run(["verify", str(transcript)], capsys)
    assert code == 0
    assert json.loads(out)["ok"] is True

    code, _ = _run(["disclose", "--corpus", str(corpus_priv), "--chunk", "k1",
                    "--out", str(disclosure)], capsys)
    assert code == 0

    code, out = _run(["verify-disclosure", "--transcript", str(transcript),
                      "--disclosure", str(disclosure)], capsys)
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_cli_verify_detects_tamper(tmp_path, capsys):
    key = tmp_path / "key.json"
    corpus = tmp_path / "c.json"
    model = tmp_path / "m.json"
    jsonl = tmp_path / "c.jsonl"
    t = tmp_path / "t.json"
    with open(jsonl, "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "x", "text": "data"}) + "\n")
    _run(["keygen", "--out", str(key)], capsys)
    _run(["commit", "--jsonl", str(jsonl), "--private-out", str(corpus)], capsys)
    weight = tmp_path / "w.bin"; weight.write_bytes(b"weights")
    _run(["hashmodel", "--name", "m", "--weights", str(weight), "--out", str(model)], capsys)
    _run(["attest", "--key", str(key), "--corpus", str(corpus), "--model", str(model),
          "--output-text", "ans", "--retrieved", "x", "--out", str(t)], capsys)

    d = json.loads(t.read_text())
    d["output"] = "tampered"
    t.write_text(json.dumps(d))
    code, out = _run(["verify", str(t)], capsys)
    assert code == 1
    assert json.loads(out)["ok"] is False
