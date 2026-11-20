#!/usr/bin/env python3
"""Step-14 T2: build the frozen attacks-ct-v0 manifest per
docs/plan-attacks-ct-v0.md (preregistered). 40 payloads (seed 0, 10 per
family) x 8 carriers = 320 samples. Writes the manifest and prints SHA-256.
Never edits the manifest after results are seen (rule 10)."""
import hashlib
import json
import random
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kortex_eval.manifest import load as load_samples  # noqa: E402

FAMILIES = ["sqli", "xss", "path-traversal", "command-injection"]
BOUNDARY = "----kortexboundary"
UNKNOWN_CT = "application/x-kortex-probe-unknown"


def pick_payloads():
    rows = load_samples("data/attacks-v0/manifest.jsonl")
    seen = {}
    for r in rows:
        base = r.id.rsplit("-", 1)[0]
        if base not in seen:
            seen[base] = r
    by_family = {}
    for base, r in sorted(seen.items()):
        by_family.setdefault(r.family, []).append(r)
    rnd = random.Random(0)
    picked = []
    for fam in FAMILIES:
        pool = sorted(by_family[fam], key=lambda r: r.id)
        for i in sorted(rnd.sample(range(len(pool)), 10)):
            picked.append(pool[i])
    return picked


def payload_text(sample):
    """Raw payload text from the -q sample: URL-decoded value of q=."""
    q = sample.query or ""
    assert q.startswith("q="), sample.id
    from urllib.parse import unquote

    return unquote(q[2:])


def multipart_body(payload):
    return (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{payload}\r\n"
        f"--{BOUNDARY}--\r\n"
    )


def carriers(p):
    P = payload_text(p)
    U = quote(P, safe="")
    fam = p.family
    base = p.id.rsplit("-", 1)[0]
    src = p.source
    rows = []
    def add(cid, method, query, body, ct):
        rows.append({
            "id": f"actv0-{cid}-{base}",
            "label": "attack",
            "family": fam,
            "source": src,
            "method": method,
            "path": "/",
            "query": query,
            "body": body,
            "content_type": ct,
        })
    add("query", "GET", f"q={U}", "", "")
    add("urlencoded", "POST", "", f"q={U}", "application/x-www-form-urlencoded")
    add("json", "POST", "", json.dumps({"q": P}, ensure_ascii=False), "application/json")
    add("multipart", "POST", "", multipart_body(P), f"multipart/form-data; boundary={BOUNDARY}")
    add("text-plain", "POST", "", P, "text/plain")
    add("octet-stream", "POST", "", P, "application/octet-stream")
    add("unknown-ct", "POST", "", P, UNKNOWN_CT)
    add("no-ct", "POST", "", P, "")
    return rows


def main():
    out_dir = Path("data/attacks-ct-v0")
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for p in pick_payloads():
        rows.extend(carriers(p))
    assert len(rows) == 320, len(rows)
    assert len({r["id"] for r in rows}) == 320
    man = out_dir / "manifest.jsonl"
    with open(man, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    digest = hashlib.sha256(man.read_bytes()).hexdigest()
    (out_dir / "MANIFEST.sha256").write_text(digest + "  manifest.jsonl\n")
    print("samples:", len(rows))
    print("sha256:", digest)


if __name__ == "__main__":
    main()
