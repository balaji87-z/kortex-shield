#!/usr/bin/env python3
"""Step-22 T5b DIAGNOSTIC (rule 34): is a compressed request body inspected?

The preregistered cells A-C (run_step22_t5_encoding.py) are blocked, but only
by byte-level protocol rules (920270 NUL byte, 921150), never by a 941/942
rule. A block that does not come from the payload cannot tell "decoded and
inspected" from "not decoded" (rule 47). These cells separate the two:

  F  benign text, gzip / deflate, Content-Encoding header present
     -> is a compressed body blocked whatever it contains?
  G  the XSS / SQLi canary, zlib-deflated so that the compressed bytes hold
     no NUL, CR or LF, Content-Encoding: deflate present
     -> blocked only if the engine decodes the body (or refuses the header)
  H  the same canary uncompressed (control: detection must fire)
  I  benign text, NOT compressed, with a Content-Encoding: gzip header
     -> blocked only if the header itself is refused (CRS 920450, restricted
        header); this is what a compressed body free of NUL bytes would meet
  J  the same benign text without the header (control: must pass)

Never produces a baseline or parity number. Local engine only (rule 6).

Usage: run_step22_t5_encoding_diag.py --engine URL --out FILE
"""
import argparse, gzip, json, sys, urllib.request, zlib

XSS = '"><script>alert(1)</script>'
SQLI = 'admin" or "1"="1"#'
BENIGN = "note the quick brown fox jumps over the lazy dog"
FORBIDDEN = (0, 10, 13)


def clean_deflate(text):
    """A zlib stream of text (plus trailing spaces if needed) with no NUL/CR/LF
    byte, or None. Deterministic: first hit over level x padding."""
    for pad in range(0, 64):
        raw = (text + " " * pad).encode()
        for level in range(1, 10):
            out = zlib.compress(raw, level)
            if not any(b in FORBIDDEN for b in out):
                return out, pad, level
    return None


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
    args = ap.parse_args()
    rows = []

    def rec(sid, cell, payload, variant, r, **extra):
        r.update({"id": sid, "cell": cell, "payload": payload, "ct": "text/plain",
                  "variant": variant, "label": "DIAGNOSTIC", **extra})
        rows.append(r)
        print(json.dumps(r), flush=True)

    ct = {"Content-Type": "text/plain"}
    rec("t5d-benign-F-gzip", "F", "benign", "gzip+header",
        send(args.engine, gzip.compress(BENIGN.encode(), mtime=0), {**ct, "Content-Encoding": "gzip"}, "t5d-benign-F-gzip"))
    rec("t5d-benign-F-deflate", "F", "benign", "deflate+header",
        send(args.engine, zlib.compress(BENIGN.encode()), {**ct, "Content-Encoding": "deflate"}, "t5d-benign-F-deflate"))
    found = clean_deflate(BENIGN)
    if found:
        body, pad, level = found
        rec("t5d-benign-F-clean", "F", "benign", "clean-deflate+header",
            send(args.engine, body, {**ct, "Content-Encoding": "deflate"}, "t5d-benign-F-clean"),
            pad=pad, level=level, body_bytes=len(body))
    for name, payload in (("xss", XSS), ("sqli", SQLI)):
        text = "note " + payload
        found = clean_deflate(text)
        if found is None:
            rec(f"t5d-{name}-G", "G", name, "clean-deflate+header",
                {"status": None, "error": "no NUL/CR/LF-free stream found; NOT MEASURED"})
        else:
            body, pad, level = found
            assert zlib.decompress(body).decode().rstrip(" ") == text
            rec(f"t5d-{name}-G", "G", name, "clean-deflate+header",
                send(args.engine, body, {**ct, "Content-Encoding": "deflate"}, f"t5d-{name}-G"),
                pad=pad, level=level, body_bytes=len(body))
        rec(f"t5d-{name}-H", "H", name, "raw",
            send(args.engine, text.encode(), ct, f"t5d-{name}-H"))
    rec("t5d-benign-I-header-only", "I", "benign", "ce-header-uncompressed-body",
        send(args.engine, BENIGN.encode(), {**ct, "Content-Encoding": "gzip"}, "t5d-benign-I-header-only"))
    rec("t5d-benign-J-control", "J", "benign", "raw",
        send(args.engine, BENIGN.encode(), ct, "t5d-benign-J-control"))
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
