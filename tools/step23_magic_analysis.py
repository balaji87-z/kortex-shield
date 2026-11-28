#!/usr/bin/env python3
"""Step-23 T3: what are the bodies behind the compressed-body events?

Usage: step23_magic_analysis.py <events.index.jsonl> <manifest.jsonl>

For the samples of one run that wrote a compressed-body event (E40) it
prints COUNTS ONLY (rule 51: nothing of a body is printed or stored): how
many, by event kind, by content type, by method, by the magic pair matched,
the body size range, and how many of the bodies really inflate as a
complete zlib or gzip stream when the bytes the runner sends are handed to
zlib. The manifest is the local, uncommitted one.
"""
import collections
import json
import statistics
import sys
import zlib

PREFIX = "compressed-body-without-content-encoding:"


def inflates(data: bytes) -> str:
    for name, wbits in (("zlib", 15), ("gzip", 31)):
        try:
            d = zlib.decompressobj(wbits)
            d.decompress(data)
            if d.eof:
                return f"complete {name} stream"
        except zlib.error:
            continue
    return "not a complete stream"


def analyse(event_rows, samples):
    """event_rows: events index rows; samples: manifest rows by id. Returns printable lines."""
    flagged = {}
    for ev in event_rows:
        reason = ev.get("reason") or ""
        if ev.get("decision") == "would_reject" and reason.startswith(PREFIX):
            flagged[ev["sample_id"]] = reason[len(PREFIX):]
    kinds = collections.Counter(flagged.values())
    types, methods, pairs, real = (collections.Counter() for _ in range(4))
    sizes, missing = [], 0
    for sid in flagged:
        s = samples.get(sid)
        if s is None:
            missing += 1
            continue
        data = (s.get("body") or "").encode("utf-8", "surrogatepass")
        ctype = (s.get("content_type") or "")
        if not ctype:
            ctype = next((v for k, v in (s.get("headers") or {}).items() if k.lower() == "content-type"), "")
        types[ctype.split(";")[0].strip().lower() or "(none)"] += 1
        methods[s.get("method", "").upper()] += 1
        pairs[data[:3].hex() if flagged[sid] == "gzip" else data[:2].hex()] += 1
        real[inflates(data)] += 1
        sizes.append(len(data))
    out = [f"samples with a compressed-body event: {len(flagged)} {dict(sorted(kinds.items()))}"
           + (f"; not in the manifest: {missing}" if missing else "")]
    if sizes:
        out.append(f"   content types: {dict(sorted(types.items()))}; methods: {dict(sorted(methods.items()))}")
        out.append(f"   magic bytes matched (hex): {dict(sorted(pairs.items()))}")
        out.append(f"   body size in bytes: min {min(sizes)}, median {int(statistics.median(sizes))}, max {max(sizes)}")
        out.append(f"   handed to zlib: {dict(sorted(real.items()))}")
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    events, manifest = argv
    with open(events, encoding="utf-8") as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    want = {r["sample_id"] for r in rows}
    samples = {}
    with open(manifest, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                s = json.loads(line)
                if s["id"] in want:
                    samples[s["id"]] = s
    print("\n".join(analyse(rows, samples)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
