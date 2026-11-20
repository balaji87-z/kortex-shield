#!/usr/bin/env python3
"""Step-14 T4: build the frozen encoding-diff-v0 manifest per
docs/plan-encoding-diff.md (preregistered). 12 payloads x 6 encodings x
2 carriers = 144 samples. Writes the manifest and prints SHA-256."""
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kortex_eval.manifest import load as load_samples  # noqa: E402

FAMILIES = ["sqli", "xss", "path-traversal", "command-injection"]


def payload_text(sample):
    q = sample.query or ""
    assert q.startswith("q="), sample.id
    from urllib.parse import unquote

    return unquote(q[2:])


def encodings(text):
    raw = text.encode("utf-8")
    single = "".join(f"%{b:02X}" for b in raw)
    double = single.replace("%", "%25")
    pct_u = "".join(f"%u{ord(c):04X}" for c in text)
    mixed = "".join(
        f"{('%{:02x}' if i % 2 == 0 else '%{:02X}').upper() if i % 2 else '%{:02x}'}".format(b) if False else
        (f"%{b:02x}" if i % 2 == 0 else f"%{b:02X}")
        for i, b in enumerate(raw)
    )
    overlong = "".join(f"{0xC0 | (b >> 6):02X}{0x80 | (b & 0x3F):02X}" for b in raw)
    return {
        "plain": text,
        "single-pct": single,
        "double-pct": double,
        "pct-u": pct_u,
        "mixed-case-hex": mixed,
        "overlong-utf8": overlong,
    }


def main():
    # first 4 payloads (alphabetical) of each family's frozen T2 selection
    rows_t2 = [json.loads(l) for l in open("data/attacks-ct-v0/manifest.jsonl", encoding="utf-8")]
    bases = []
    for fam in FAMILIES:
        ids = sorted({r["id"][r["id"].index(r["family"]):] for r in rows_t2 if r["family"] == fam})
        bases.extend(ids[:4])
    assert len(bases) == 16, bases
    attacks = {}
    for r in load_samples("data/attacks-v0/manifest.jsonl"):
        base = r.id.rsplit("-", 1)[0]
        # prefer the -q (query) variant over the -login variant, as in T2
        if base not in attacks or not r.id.endswith("-login"):
            attacks[base] = r
    out = []
    for base in bases:
        src = attacks[base]
        text = payload_text(src)
        for enc_name, enc in encodings(text).items():
            for carrier in ("query", "urlencoded"):
                if carrier == "query":
                    row = {"id": f"encd-query-{enc_name}-{base}", "label": "attack",
                           "family": src.family, "source": src.source, "method": "GET",
                           "path": "/", "query": f"q={enc}", "body": "", "content_type": ""}
                else:
                    row = {"id": f"encd-urlencoded-{enc_name}-{base}", "label": "attack",
                           "family": src.family, "source": src.source, "method": "POST",
                           "path": "/", "query": "", "body": f"q={enc}",
                           "content_type": "application/x-www-form-urlencoded"}
                out.append(row)
    assert len(out) == 192, len(out)
    assert len({r["id"] for r in out}) == 192
    out_dir = Path("data/encoding-diff-v0")
    out_dir.mkdir(parents=True, exist_ok=True)
    man = out_dir / "manifest.jsonl"
    with open(man, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    digest = hashlib.sha256(man.read_bytes()).hexdigest()
    (out_dir / "MANIFEST.sha256").write_text(digest + "  manifest.jsonl\n")
    print("samples:", len(out))
    print("sha256:", digest)


if __name__ == "__main__":
    main()
