#!/usr/bin/env python3
"""Step-22 T5b DIAGNOSTIC (rule 34), cell G: a compressed attack body whose
bytes hold no NUL, CR or LF.

tools/run_step22_t5_encoding_diag.py could not build such a body (its search
only appended spaces; every stream ended in NUL bytes), so cell G was NOT
MEASURED. Here the canary sits between seeded filler words and the stream is
built with Z_HUFFMAN_ONLY; the search is deterministic (seed 1) and the
result is checked to decompress to text that contains the canary unchanged.

  G   canary, clean zlib stream, Content-Encoding: deflate
      -> 200 would be a compressed attack passing; 403 with a 941/942 rule
         would mean the body was decoded; 403 without one means it was
         refused for another reason (the header, 920450)
  K   the same bytes WITHOUT the Content-Encoding header
      -> shows whether the rules see the canary inside the compressed bytes
         at all (rule 47: without this, a G block says nothing about decoding)
  H   the same text uncompressed (control: the canary must be detected)
  G0  benign text, clean zlib stream, Content-Encoding: deflate (control)
  K0  benign text, clean zlib stream, no header (control: must pass)

A stream with no byte below 32 at all (which CRS 920271 would need at PL2 if
the body were an argument) was searched for separately and not found; that
variant is NOT MEASURED. Never produces a baseline or parity number. Local
engine or connector only (rule 6).

Usage: run_step22_t5_cellg.py --engine URL --out FILE
"""
import argparse, json, random, urllib.error, urllib.request, zlib

XSS = '"><script>alert(1)</script>'
SQLI = 'admin" or "1"="1"#'
BENIGN = "the quick brown fox jumps over the lazy dog"
WORDS = ("the quick brown fox jumps over lazy dog note text sample value item "
         "list page form data user name city blue green").split()
FORBIDDEN = (0, 10, 13)


def clean_stream(text, seed=1, tries=20000):
    """(stream, plain text, tries used): first zlib stream without NUL/CR/LF."""
    rng = random.Random(seed)
    for n in range(tries):
        pre = " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 6)))
        suf = " ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 12)))
        plain = pre + " " + text + (" " + suf if suf else "")
        c = zlib.compressobj(6, zlib.DEFLATED, 15, 8, zlib.Z_HUFFMAN_ONLY)
        out = c.compress(plain.encode()) + c.flush()
        if not any(b in FORBIDDEN for b in out):
            assert zlib.decompress(out).decode() == plain and text in plain
            return out, plain, n + 1
    raise SystemExit(f"no clean stream found in {tries} tries")


def send(url, body, headers, sample_id):
    req = urllib.request.Request(url + "/", data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("X-Kortex-Sample-Id", sample_id)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return {"status": r.status}
    except urllib.error.HTTPError as e:
        # the engine's block page lists the matched rule ids; the connector's does not
        return {"status": e.code, "block_page_lists_920450": "920450" in e.read(8000).decode(errors="replace")}
    except Exception as e:
        return {"status": None, "error": str(e)[:120]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", default="", help="made part of every sample id, e.g. pl2")
    args = ap.parse_args()
    rows = []
    ct = {"Content-Type": "text/plain"}
    ce = {**ct, "Content-Encoding": "deflate"}
    tag = f"-{args.tag}" if args.tag else ""

    def rec(sid, cell, payload, variant, r, **extra):
        r.update({"id": sid, "cell": cell, "payload": payload, "ct": "text/plain",
                  "variant": variant, "label": "DIAGNOSTIC", **extra})
        rows.append(r)
        print(json.dumps(r), flush=True)

    for name, text in (("xss", XSS), ("sqli", SQLI), ("benign", BENIGN)):
        body, plain, tries = clean_stream(text)
        meta = {"body_bytes": len(body), "plain_bytes": len(plain), "search_tries": tries,
                "control_bytes_below_32": sum(1 for b in body if b < 32)}
        g, k = ("G0", "K0") if name == "benign" else ("G", "K")
        sid = f"t5g{tag}-{name}-{g}"
        rec(sid, g, name, "clean-deflate+header", send(args.engine, body, ce, sid), **meta)
        sid = f"t5g{tag}-{name}-{k}"
        rec(sid, k, name, "clean-deflate-no-header", send(args.engine, body, ct, sid), **meta)
        if name != "benign":
            sid = f"t5g{tag}-{name}-H"
            rec(sid, "H", name, "raw", send(args.engine, plain.encode(), ct, sid), plain_bytes=len(plain))
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
